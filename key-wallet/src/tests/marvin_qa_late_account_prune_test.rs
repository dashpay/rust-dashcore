//! Marvin (QA) adversarial pin for commit 5d7737b5 ("bound
//! observed_spent_outpoints via finality-boundary pruning").
//!
//! The design doc's own §3 "residual" analysis acknowledges that a coin whose
//! wallet-level guard entry has already been pruned can be resurrected for an
//! account added *after* the prune, unless that account's own catch-up rescan
//! replays the spend block in the same session before anything external
//! observes the coin as spendable. No existing test (including the six new
//! Phase-1 regression tests) combines "prune already ran" with "account added
//! afterward" — `account_created_after_spend_observed_still_rejects_funding`
//! (in `observed_spent_outpoints_tests.rs`) covers the late-account case but
//! never prunes the entry first.
//!
//! This test isolates exactly that gap: it prunes the wallet-level entry via
//! chainlock + synced_height advance, THEN adds a brand-new managed account,
//! THEN delivers the funding tx to that account for the first time ever
//! (no replay of the spend block in between). If the coin becomes live, the
//! finality-boundary pruning has reopened #649 for accounts added after the
//! boundary advances past their coin's spend height.

use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::ephemerealdata::chain_lock::ChainLock;

use crate::account::{AccountType, StandardAccountType};
use crate::managed_account::ManagedCoreFundsAccount;
use crate::test_utils::{block_ctx, spend_to_external, utxo_tracked, TestWalletContext};
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;

#[tokio::test]
async fn late_added_account_after_prune_still_rejects_funding() {
    let mut ctx = TestWalletContext::new_random();

    // Build account 1 off to the side (mirrors
    // `account_created_after_spend_observed_still_rejects_funding`), but do
    // NOT insert it into the managed collection yet — at spend-observation
    // and prune time the wallet still only knows account 0.
    ctx.wallet
        .add_account(
            AccountType::Standard {
                index: 1,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            None,
        )
        .expect("add account 1");
    let acct1 = ctx.wallet.get_bip44_account(1).expect("account 1");
    let xpub1 = acct1.account_xpub;
    let mut managed_acct1 = ManagedCoreFundsAccount::from_account(acct1);
    let addr1 = managed_acct1.next_receive_address(Some(&xpub1), true).expect("addr1");

    let funding_value = 2_500_000u64;
    let funding_tx = Transaction::dummy(&addr1, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 900);

    // Observe the spend at height 200 while account 1 is NOT yet known.
    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    assert!(
        ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "spend recorded at the wallet level before account 1 exists"
    );

    // Advance the finality boundary past the spend height and prune. This is
    // the step the pre-existing test never performs.
    ctx.managed_wallet.update_last_processed_height(200);
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(200));
    ctx.managed_wallet.update_synced_height(200);
    assert!(
        !ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "precondition: entry must actually be pruned before account 1 is added"
    );

    // NOW account 1 appears (gap-limit/lazy discovery), after the guard entry
    // is gone.
    ctx.managed_wallet
        .accounts
        .insert_funds_bearing_account(managed_acct1)
        .expect("insert managed account 1");

    // Deliver the funding tx to account 1 for the very first time — no prior
    // replay of the spend block for this account in this session.
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;

    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "QA-002 (Medium): coin resurrected — account 1's first-ever sighting of the funding tx \
         was not protected because the wallet-level guard entry was pruned before the account \
         existed, and nothing re-delivered the spend block to re-guard it. This is the exact gap \
         flagged in the design doc's own §3 residual, now empirically confirmed rather than \
         theoretical."
    );
    assert_eq!(
        ctx.managed_wallet.balance.total(),
        0,
        "QA-002: balance must not show the resurrected coin either"
    );
}
