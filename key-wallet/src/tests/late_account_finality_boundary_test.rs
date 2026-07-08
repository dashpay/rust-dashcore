//! Late-added-account interaction with finality-boundary pruning
//! (dashpay/rust-dashcore#649).
//!
//! `synced_height` certifies "every filter at or below this height was matched
//! against the wallet's scripts" — but only for the account set that existed
//! while those filters were scanned. Adding an account grows the script set
//! without invalidating that certificate, so `prune_finalized_observed_spends`
//! could consume a stale certificate and evict the only protection a
//! newly-added account has for a coin spent before it existed.
//!
//! The fix rewinds `synced_height` to just below wallet birth on every account
//! addition, collapsing the prune boundary until the sync layer re-certifies
//! the new account set by backfilling from birth. These tests pin that rewind
//! and the convergence of the backfill replay. A transient window (funding
//! replayed before its spend) is accepted — the same shape as the other
//! documented residuals; the durable resurrection is what is eliminated.

use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::ephemerealdata::chain_lock::ChainLock;

use crate::account::{AccountType, StandardAccountType};
use crate::managed_account::ManagedCoreFundsAccount;
use crate::test_utils::{
    block_ctx, chain_locked_block_ctx, spend_to_external, utxo_tracked, TestWalletContext,
};
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::managed_wallet_info::ManagedAccountOperations;

const BIRTH: u32 = 50;

fn bip44(index: u32) -> AccountType {
    AccountType::Standard {
        index,
        standard_account_type: StandardAccountType::BIP44Account,
    }
}

/// Add BIP44 account `index` to the wallet and derive its first receive address
/// (deterministic, so the funding tx can be built before the managed account is
/// added). Returns `(account_type, receive_address)`.
fn prepare_account(ctx: &mut TestWalletContext, index: u32) -> (AccountType, dashcore::Address) {
    ctx.wallet.add_account(bip44(index), None).expect("add wallet account");
    let account = ctx.wallet.get_bip44_account(index).expect("wallet account");
    let xpub = account.account_xpub;
    let mut detached = ManagedCoreFundsAccount::from_account(account);
    let address = detached.next_receive_address(Some(&xpub), true).expect("receive address");
    (bip44(index), address)
}

/// The certificate is invalidated the moment the account set grows: adding an
/// account rewinds `synced_height` to just below birth, so a later chainlock
/// prunes nothing (the boundary has collapsed).
#[tokio::test]
async fn late_added_account_rewinds_sync_checkpoint() {
    let mut ctx = TestWalletContext::new_random();
    ctx.managed_wallet.metadata.birth_height = BIRTH;

    let (type1, addr1) = prepare_account(&mut ctx, 1);
    let funding_value = 2_500_000u64;
    let funding_tx = Transaction::dummy(&addr1, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 900);

    // Observe the spend and prune, all while account 1 is unknown.
    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    ctx.managed_wallet.update_last_processed_height(200);
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(200));
    ctx.managed_wallet.update_synced_height(200);
    assert!(!ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint));

    // Adding the account rewinds the certificate to birth - 1.
    ctx.managed_wallet.add_managed_account(&ctx.wallet, type1).expect("add managed account 1");
    assert_eq!(
        ctx.managed_wallet.synced_height(),
        BIRTH - 1,
        "adding an account rewinds synced_height to just below birth"
    );

    // A later chainlock now prunes nothing: the boundary is min(cl, synced) and
    // synced has collapsed to birth - 1.
    let stale_outpoint = OutPoint::new(dashcore::Txid::from([0x5A; 32]), 0);
    ctx.managed_wallet.record_observed_spends(&spend_to_external(&[stale_outpoint], 1, 5), 60);
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(250));
    assert!(
        ctx.managed_wallet.observed_spent_outpoints().contains_key(&stale_outpoint),
        "with synced rewound to birth-1, an entry at height 60 is not prunable despite cl=250"
    );
}

/// The rewind drives a backfill (modeled here as a forward replay). Delivering
/// the funding then the spend converges: no live UTXO, zero balance, and the
/// repopulated entry is re-prunable once the checkpoint re-advances.
#[tokio::test]
async fn late_added_account_converges_after_forward_replay() {
    let mut ctx = TestWalletContext::new_random();
    ctx.managed_wallet.metadata.birth_height = BIRTH;

    let (type1, addr1) = prepare_account(&mut ctx, 1);
    let funding_value = 2_500_000u64;
    let funding_tx = Transaction::dummy(&addr1, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 901);

    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    ctx.managed_wallet.update_last_processed_height(200);
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(200));
    ctx.managed_wallet.update_synced_height(200);
    ctx.managed_wallet.add_managed_account(&ctx.wallet, type1).expect("add managed account 1");

    // Forward replay from birth: funding (born-chainlocked, since 100 <= cl 200)
    // then its spend.
    ctx.check_transaction(&funding_tx, chain_locked_block_ctx(100)).await;
    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "after the full replay the coin is reconciled away"
    );
    assert_eq!(ctx.managed_wallet.balance.total(), 0, "no resurrected coin in the balance");
    assert!(
        ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "the spend replay repopulated the wallet-level entry"
    );

    // Re-advancing the checkpoint past the spend re-certifies coverage, so the
    // repopulated entry becomes prunable again.
    ctx.managed_wallet.update_synced_height(200);
    assert!(
        !ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "entry re-prunable once synced_height honestly re-advances past the spend"
    );
    ctx.check_transaction(&funding_tx, chain_locked_block_ctx(100)).await;
    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "the finalized record short-circuits any further funding redelivery"
    );
}

/// Mid-backfill pruning cannot reopen the hole: while the checkpoint has only
/// partially re-advanced (below the spend height), the repopulated entry sits
/// above the boundary and survives pruning, so a redelivered funding stays
/// guarded.
#[tokio::test]
async fn late_added_account_interrupted_replay_entry_not_prunable() {
    let mut ctx = TestWalletContext::new_random();
    ctx.managed_wallet.metadata.birth_height = BIRTH;

    let (type1, addr1) = prepare_account(&mut ctx, 1);
    let funding_value = 2_500_000u64;
    let funding_tx = Transaction::dummy(&addr1, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 902);

    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    ctx.managed_wallet.update_last_processed_height(200);
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(200));
    ctx.managed_wallet.update_synced_height(200);
    ctx.managed_wallet.add_managed_account(&ctx.wallet, type1).expect("add managed account 1");

    // Replay funding + spend; entry (O, 200) repopulated.
    ctx.check_transaction(&funding_tx, chain_locked_block_ctx(100)).await;
    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    assert!(ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint));

    // Partial backfill: checkpoint advances only to 150, below the spend at 200.
    // Pruning must not evict the entry (200 > boundary min(cl 200, 150) = 150).
    ctx.managed_wallet.update_synced_height(150);
    assert!(
        ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "a repopulated entry above the partial-backfill boundary must survive pruning"
    );
    ctx.check_transaction(&funding_tx, chain_locked_block_ctx(100)).await;
    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "mid-backfill funding redelivery stays guarded — the hole cannot reopen"
    );

    // Completing the backfill re-certifies coverage and the entry prunes safely.
    ctx.managed_wallet.update_synced_height(200);
    assert!(!ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint));
    assert_eq!(ctx.managed_wallet.balance.total(), 0, "converged to zero balance");
}

/// Every add variant rewinds the certificate; adding during initial sync is a
/// no-op; `birth_height == 0` does not underflow.
#[tokio::test]
async fn every_add_variant_rewinds_checkpoint() {
    let mut ctx = TestWalletContext::new_random();
    ctx.managed_wallet.metadata.birth_height = BIRTH;

    // Baseline: certify coverage well above birth.
    ctx.managed_wallet.update_synced_height(1_000);
    assert_eq!(ctx.managed_wallet.synced_height(), 1_000);

    // add_managed_account (funds, from wallet).
    ctx.wallet.add_account(bip44(1), None).expect("wallet account 1");
    ctx.managed_wallet.add_managed_account(&ctx.wallet, bip44(1)).expect("add managed 1");
    assert_eq!(ctx.managed_wallet.synced_height(), BIRTH - 1, "add_managed_account rewinds");

    // Re-certify, then add_managed_account_from_xpub.
    ctx.managed_wallet.update_synced_height(1_000);
    ctx.wallet.add_account(bip44(2), None).expect("wallet account 2");
    let xpub2 = ctx.wallet.get_bip44_account(2).expect("account 2").account_xpub;
    ctx.managed_wallet
        .add_managed_account_from_xpub(bip44(2), xpub2)
        .expect("add managed from xpub");
    assert_eq!(
        ctx.managed_wallet.synced_height(),
        BIRTH - 1,
        "add_managed_account_from_xpub rewinds"
    );

    // No-op during initial sync: synced already at/below the floor.
    ctx.managed_wallet.update_synced_height(BIRTH - 1);
    ctx.wallet.add_account(bip44(3), None).expect("wallet account 3");
    ctx.managed_wallet.add_managed_account(&ctx.wallet, bip44(3)).expect("add managed 3");
    assert_eq!(
        ctx.managed_wallet.synced_height(),
        BIRTH - 1,
        "adding during initial sync leaves the checkpoint untouched"
    );

    // birth_height == 0 saturates rather than underflowing.
    let mut ctx0 = TestWalletContext::new_random();
    ctx0.managed_wallet.metadata.birth_height = 0;
    ctx0.managed_wallet.update_synced_height(1_000);
    ctx0.wallet.add_account(bip44(1), None).expect("wallet account 1");
    ctx0.managed_wallet.add_managed_account(&ctx0.wallet, bip44(1)).expect("add managed 1");
    assert_eq!(
        ctx0.managed_wallet.synced_height(),
        0,
        "birth_height == 0 rewinds to 0 without underflow"
    );
}
