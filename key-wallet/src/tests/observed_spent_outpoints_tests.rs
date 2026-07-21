//! Unit-level coverage for the wallet-level observed-spent-outpoint machinery
//! (dashpay/rust-dashcore#649).
//!
//! The manager-level integration tests (`key-wallet-manager/tests/`) drive the
//! *spend-first* ordering end-to-end through the public `WalletManager` surface:
//! a spend delivered before its funding, reconciled at `update_utxos` insert
//! time. That path leaves several branches of the fix unexercised, because they
//! only trigger on orderings or lifecycle events a black-box manager test cannot
//! reach directly:
//!
//! * the serde adapter for `observed_spent_outpoints` (no manager test
//!   serializes a wallet holding entries),
//! * `prune_finalized_observed_spends` and its finality boundary,
//! * the *funding-first* removal guard `remove_spent_from_accounts` /
//!   `finalize_guard_removed_utxo` (the coin is already live and must be dropped
//!   un-gated by classification),
//! * the account-add sync rewind for a standalone (from-xpub) account, and
//! * the account-local vs. wallet-level source-of-truth split across a reload.
//!
//! These white-box tests exercise those branches directly against the
//! `pub(crate)` surface.

use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, TxIn, Txid};

use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext};
use crate::wallet::managed_wallet_info::managed_account_operations::ManagedAccountOperations;
use crate::wallet::ManagedWalletInfo;
use crate::AccountType;

/// A transaction whose inputs spend exactly `spent`, with no outputs. Enough to
/// drive `record_observed_spends` (reads inputs) and the removal guard.
fn spending_tx(spent: &[OutPoint]) -> Transaction {
    Transaction {
        version: 1,
        lock_time: 0,
        input: spent
            .iter()
            .map(|op| TxIn {
                previous_output: *op,
                ..Default::default()
            })
            .collect(),
        output: Vec::new(),
        special_transaction_payload: None,
    }
}

/// A syntactically-valid `ChainLock` at `height`; only `block_height` is read by
/// the prune boundary, the signature is never verified here.
fn dummy_chain_lock(height: u32) -> ChainLock {
    ChainLock {
        block_height: height,
        block_hash: BlockHash::from_slice(&[height as u8; 32]).expect("hash"),
        signature: BLSSignature::from([0u8; 96]),
    }
}

/// The `observed_spent_outpoints` serde adapter round-trips: it encodes the map
/// as a `(OutPoint, height)` sequence (format-agnostic), and reloads it. An
/// account-less wallet serializes cleanly — the populated-account blocker is
/// `AddressPool::script_pubkey_index` (a non-string JSON map key), not this
/// field — so it isolates the adapter under test.
#[cfg(feature = "serde")]
#[test]
fn observed_spent_outpoints_survive_serde_round_trip() {
    let mut info = ManagedWalletInfo::dummy(7);
    let op_a = OutPoint::new(Txid::from([0x11; 32]), 0);
    let op_b = OutPoint::new(Txid::from([0x22; 32]), 3);
    info.record_observed_spends(&spending_tx(&[op_a]), 100);
    info.record_observed_spends(&spending_tx(&[op_b]), 250);
    assert_eq!(info.observed_spent_outpoints().len(), 2);

    let json = serde_json::to_string(&info).expect("serialize");
    let restored: ManagedWalletInfo = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(restored.observed_spent_outpoints().get(&op_a), Some(&100));
    assert_eq!(restored.observed_spent_outpoints().get(&op_b), Some(&250));
    assert_eq!(restored.observed_spent_outpoints().len(), 2);

    // An empty map round-trips through the sequence adapter too (empty-seq
    // serialize + visitor path), and `#[serde(default)]` still yields an empty
    // set rather than erroring.
    let empty = ManagedWalletInfo::dummy(8);
    let json_empty = serde_json::to_string(&empty).expect("serialize empty");
    let restored_empty: ManagedWalletInfo =
        serde_json::from_str(&json_empty).expect("deserialize empty");
    assert!(restored_empty.observed_spent_outpoints().is_empty());
}

/// `prune_finalized_observed_spends` is a no-op without a chainlock, and
/// otherwise evicts exactly the entries at or below
/// `min(chainlock height, synced_height)` — the finality boundary — keeping
/// everything above it.
#[test]
fn prune_finalized_observed_spends_respects_finality_boundary() {
    let mut info = ManagedWalletInfo::dummy(9);
    let op_low = OutPoint::new(Txid::from([0x01; 32]), 0); // height 50
    let op_bnd = OutPoint::new(Txid::from([0x02; 32]), 0); // height 100 (== boundary)
    let op_high = OutPoint::new(Txid::from([0x03; 32]), 0); // height 150
    info.record_observed_spends(&spending_tx(&[op_low]), 50);
    info.record_observed_spends(&spending_tx(&[op_bnd]), 100);
    info.record_observed_spends(&spending_tx(&[op_high]), 150);

    // No chainlock has been applied: there is no provable finality boundary, so
    // nothing may be pruned regardless of how high `synced_height` is.
    info.metadata.synced_height = 1_000_000;
    info.prune_finalized_observed_spends();
    assert_eq!(
        info.observed_spent_outpoints().len(),
        3,
        "no chainlock => nothing is provably final => no eviction"
    );

    // Boundary = min(chainlock height 200, synced_height 100) = 100. The
    // chainlock being higher than the sync checkpoint is the exact case an
    // in-progress rescan produces, and it must not over-prune.
    info.metadata.synced_height = 100;
    info.metadata.last_applied_chain_lock = Some(dummy_chain_lock(200));
    info.prune_finalized_observed_spends();

    let remaining = info.observed_spent_outpoints();
    assert!(!remaining.contains_key(&op_low), "height 50 <= boundary 100: evicted");
    assert!(!remaining.contains_key(&op_bnd), "height 100 == boundary 100: evicted");
    assert!(remaining.contains_key(&op_high), "height 150 > boundary 100: retained");
    assert_eq!(remaining.len(), 1);
}

/// The funding-first guard: a coin that is already live in a funding account,
/// whose spend the matched-account path could not attribute, is dropped
/// un-gated by `remove_spent_from_accounts`, which also marks it spent, releases
/// its build reservation, and compensates the funding record. Idempotent, and a
/// coinbase is skipped.
#[tokio::test]
async fn funding_first_guard_removes_held_coin_and_compensates_record() {
    let (mut ctx, funding_tx) =
        TestWalletContext::new_random().with_mempool_funding(1_000_000).await;
    let funded = OutPoint::new(funding_tx.txid(), 0);

    // Reserve the coin so we can prove the guard frees the reservation too.
    ctx.managed_wallet
        .first_bip44_managed_account()
        .expect("BIP44 account")
        .reservations()
        .reserve(&[funded], 0);
    assert!(ctx
        .managed_wallet
        .first_bip44_managed_account()
        .unwrap()
        .reservations()
        .reserved(0)
        .contains(&funded));

    // The two decomposed steps the checker runs on a block spend it cannot
    // attribute to the owning account (routed away by tx-type narrowing, or the
    // funding lives in another account): record the observed spend, then drop
    // the coin un-gated by classification.
    let spend = spending_tx(&[funded]);
    ctx.managed_wallet.record_observed_spends(&spend, 200);
    let removed = ctx.managed_wallet.remove_spent_from_accounts(&spend);
    assert!(removed, "guard must remove the live coin the matched path missed");

    let account = ctx.managed_wallet.first_bip44_managed_account().unwrap();
    assert!(!account.utxos.contains_key(&funded), "coin dropped from the funding account");
    assert!(
        !account.reservations().reserved(0).contains(&funded),
        "guard releases the build reservation immediately, not at the TTL backstop"
    );
    let record = account.transactions().get(&funding_tx.txid()).expect("funding record kept");
    assert_eq!(record.net_amount, 0, "the spent output is compensated out of net_amount");
    assert!(record.output_details.is_empty(), "the spent Received output is dropped");

    // Idempotent: the coin is already gone, so a second call removes nothing.
    assert!(
        !ctx.managed_wallet.remove_spent_from_accounts(&spend),
        "second call has nothing left to remove"
    );
    // A coinbase's single input is the null prevout and spends nothing real.
    let coinbase = Transaction::dummy_coinbase(&ctx.receive_address, 5_000_000_000);
    assert!(
        !ctx.managed_wallet.remove_spent_from_accounts(&coinbase),
        "coinbase is skipped by the guard"
    );
}

/// After the funding-first guard drops a coin, the account-local `spent_outpoints`
/// set — rebuilt from recorded transactions on reload — forgets the unrecorded
/// spend, but the persisted wallet-level `observed_spent_outpoints` still keeps
/// the coin from being resurrected when the funding is re-delivered. This is the
/// source-of-truth split the fix relies on across a serialize/deserialize.
#[tokio::test]
async fn wallet_level_set_outlives_account_local_reload() {
    let (mut ctx, funding_tx) =
        TestWalletContext::new_random().with_mempool_funding(1_000_000).await;
    let funded = OutPoint::new(funding_tx.txid(), 0);
    let spend = spending_tx(&[funded]);

    // Observe + drop the coin via the funding-first guard.
    ctx.managed_wallet.record_observed_spends(&spend, 200);
    assert!(ctx.managed_wallet.remove_spent_from_accounts(&spend));

    // Simulate a save/reload: the account-local derived set is rebuilt from
    // recorded transactions only. The spend was never recorded as one of our
    // transactions, so the derived set forgets `funded` — exactly what a real
    // `Deserialize` would reconstruct.
    ctx.managed_wallet
        .first_bip44_managed_account_mut()
        .unwrap()
        .simulate_reload_rebuild_spent_outpoints();

    // The persisted wallet-level set is the durable source of truth: re-delivering
    // the funding in a block must NOT resurrect the coin.
    let block = BlockInfo::new(100, BlockHash::from_slice(&[9u8; 32]).unwrap(), 1_700_000_000);
    ctx.check_transaction(&funding_tx, TransactionContext::InBlock(block)).await;

    assert!(
        !ctx.managed_wallet.first_bip44_managed_account().unwrap().utxos.contains_key(&funded),
        "wallet-level observed_spent must keep the coin dropped even after the account-local \
         derived set is rebuilt from recorded transactions"
    );
}

/// Adding a standalone (from-xpub) account rewinds the sync checkpoint below
/// wallet birth, so the new account's coins get filter coverage before pruning
/// can consume the certificate (dashpay/rust-dashcore#649). A wallet still in
/// initial sync (already at/below the floor) is left untouched.
#[test]
fn adding_account_from_xpub_rewinds_sync_checkpoint() {
    let mut ctx = TestWalletContext::new_random();
    ctx.managed_wallet.metadata.birth_height = 1_000;
    ctx.managed_wallet.metadata.synced_height = 5_000;

    ctx.managed_wallet
        .add_managed_account_from_xpub(
            AccountType::IdentityTopUp {
                registration_index: 7,
            },
            ctx.xpub,
        )
        .expect("attach standalone IdentityTopUp account");

    assert_eq!(
        ctx.managed_wallet.metadata.synced_height, 999,
        "synced_height rewound to birth_height - 1 so the new account is re-scanned from birth"
    );

    // A wallet whose sync checkpoint is already below the birth floor is left
    // as-is: the rewind only ever collapses the certificate, never advances it.
    ctx.managed_wallet.metadata.synced_height = 10;
    ctx.managed_wallet
        .add_managed_account_from_xpub(
            AccountType::IdentityTopUp {
                registration_index: 8,
            },
            ctx.xpub,
        )
        .expect("attach second standalone account");
    assert_eq!(
        ctx.managed_wallet.metadata.synced_height, 10,
        "a still-behind sync checkpoint is not advanced by the rewind"
    );
}
