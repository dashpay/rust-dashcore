//! Tests for the `keep_txs_in_memory` Cargo feature.
//!
//! When the feature is enabled (the default), `ManagedCoreKeysAccount` keeps
//! a per-account `transactions` map populated as transactions are processed.
//! When the feature is disabled, the field does not exist and processing a
//! transaction only updates UTXOs and balance — but `processed_txids`
//! still tracks which txids have been seen so `confirm_transaction`
//! continues to deduplicate re-events.

use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext};
use dashcore::{BlockHash, Transaction};
use dashcore_hashes::Hash;

#[tokio::test]
async fn record_transaction_updates_utxos_and_balance() {
    let mut ctx = TestWalletContext::new_random();

    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[200_000]);
    let result = ctx.check_transaction(&tx, TransactionContext::Mempool).await;
    assert!(result.is_relevant);

    let account = ctx.bip44_account();
    assert_eq!(account.utxos.len(), 1, "UTXOs are tracked regardless of feature");
    assert_eq!(account.balance.spendable(), 200_000);
}

#[cfg(feature = "keep_txs_in_memory")]
#[tokio::test]
async fn transactions_are_stored_when_feature_enabled() {
    let mut ctx = TestWalletContext::new_random();

    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[200_000]);
    let _ = ctx.check_transaction(&tx, TransactionContext::Mempool).await;

    let account = ctx.bip44_account();
    assert_eq!(account.transactions().len(), 1);
    assert!(account.has_transaction(&tx.txid()));
    assert!(account.keys().get_transaction(&tx.txid()).is_some());
}

#[cfg(not(feature = "keep_txs_in_memory"))]
#[tokio::test]
async fn transactions_are_not_stored_when_feature_disabled() {
    let mut ctx = TestWalletContext::new_random();

    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[200_000]);
    let _ = ctx.check_transaction(&tx, TransactionContext::Mempool).await;

    let account = ctx.bip44_account();
    // No record is stored, so `get_transaction` returns None ...
    assert!(account.keys().get_transaction(&tx.txid()).is_none());
    // ... but `has_transaction` still returns true so re-events dedupe.
    assert!(account.has_transaction(&tx.txid()));
}

/// Re-processing the same transaction (mempool → block) must not double-count
/// UTXOs or change balance, regardless of whether the `keep_txs_in_memory`
/// feature is enabled. Without the always-present `processed_txids` set this
/// regresses when the feature is off because `confirm_transaction`'s only
/// dedup signal disappears with the `transactions` map.
#[tokio::test]
async fn confirm_transaction_dedupes_repeat_events() {
    let mut ctx = TestWalletContext::new_random();

    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[200_000]);

    // First: mempool
    let r1 = ctx.check_transaction(&tx, TransactionContext::Mempool).await;
    assert!(r1.is_relevant);
    assert!(r1.is_new_transaction);
    let utxo_count_after_mempool = ctx.bip44_account().utxos.len();
    let balance_after_mempool = ctx.bip44_account().balance.spendable();
    let revision_after_mempool = ctx.bip44_account().monitor_revision();

    // Second: same tx confirmed in a block
    let block = TransactionContext::InBlock(BlockInfo::new(
        100,
        BlockHash::from_slice(&[7u8; 32]).unwrap(),
        1_700_000_000,
    ));
    let r2 = ctx.check_transaction(&tx, block).await;
    assert!(r2.is_relevant);
    assert!(!r2.is_new_transaction, "block confirmation must not be flagged as a new tx");

    let account = ctx.bip44_account();
    assert_eq!(
        account.utxos.len(),
        utxo_count_after_mempool,
        "UTXO count must not grow on confirmation"
    );
    assert_eq!(
        account.balance.spendable(),
        balance_after_mempool,
        "spendable balance must not change between mempool and block confirmation"
    );
    // monitor_revision can advance once for the block-context UTXO refresh,
    // but it must not balloon to N per replay.
    let bumped_by = account.monitor_revision().saturating_sub(revision_after_mempool);
    assert!(bumped_by <= 1, "monitor_revision bumped {bumped_by} times on a single confirmation");
}
