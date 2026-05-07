//! Tests for the `keep-finalized-transactions` Cargo feature.
//!
//! These tests assert the dual semantics of the feature:
//!
//! - With the feature ON, every processed transaction stays in the
//!   in-memory `transactions` map for the wallet's lifetime, including
//!   chainlocked ones.
//! - With the feature OFF (the default), records of chainlocked
//!   transactions are dropped from the map and only their txids are kept
//!   for dedup. IS-locked-but-not-yet-chainlocked records still live in
//!   the map so we don't lose the block-confirmation event when it
//!   arrives.
//!
//! "Finalized" in this crate means *chainlocked* — see
//! [`crate::transaction_checking::TransactionContext::is_chain_locked`].
//! IS-lock alone is **not** finality.

use crate::{
    managed_account::managed_account_trait::ManagedAccountTrait,
    test_utils::TestWalletContext,
    transaction_checking::{BlockInfo, TransactionContext},
};
#[cfg(not(feature = "keep-finalized-transactions"))]
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, Transaction};

/// Walks a single transaction through Mempool → InBlock → InChainLockedBlock
/// and asserts that the record survives the chainlock when the feature is ON.
#[cfg(feature = "keep-finalized-transactions")]
#[tokio::test]
async fn test_chainlocked_record_kept_when_feature_on() {
    let mut ctx = TestWalletContext::new_random();
    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[150_000]);
    let txid = tx.txid();

    // Mempool → record exists
    let _ = ctx.check_transaction(&tx, TransactionContext::Mempool).await;
    assert!(ctx.bip44_account().has_transaction(&txid));
    assert!(ctx.bip44_account().transactions().contains_key(&txid));

    // InBlock → record still there, finalization stays false
    let block_hash = BlockHash::from_slice(&[7u8; 32]).expect("hash");
    let _ = ctx
        .check_transaction(
            &tx,
            TransactionContext::InBlock(BlockInfo::new(100, block_hash, 1_700_000_000)),
        )
        .await;
    assert!(ctx.bip44_account().has_transaction(&txid));
    assert!(!ctx.bip44_account().transaction_is_finalized(&txid));

    // InChainLockedBlock → record MUST still live in the map.
    let _ = ctx
        .check_transaction(
            &tx,
            TransactionContext::InChainLockedBlock(BlockInfo::new(100, block_hash, 1_700_000_000)),
        )
        .await;
    assert!(ctx.bip44_account().has_transaction(&txid));
    assert!(ctx.bip44_account().transaction_is_finalized(&txid));
    assert!(
        ctx.bip44_account().transactions().contains_key(&txid),
        "with the feature ON the record must stay in the map after chainlock"
    );
}

/// With the feature OFF (default) a chainlocked transaction's record is
/// dropped from the map; only the txid is retained for dedup. The
/// `has_transaction` / `transaction_is_finalized` queries must keep
/// working off the txid set.
#[cfg(not(feature = "keep-finalized-transactions"))]
#[tokio::test]
async fn test_chainlocked_record_dropped_when_feature_off() {
    let mut ctx = TestWalletContext::new_random();
    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[150_000]);
    let txid = tx.txid();

    // Mempool → record exists in the map.
    let _ = ctx.check_transaction(&tx, TransactionContext::Mempool).await;
    assert!(ctx.bip44_account().transactions().contains_key(&txid));

    // InChainLockedBlock → record dropped, but `has_transaction` and
    // `transaction_is_finalized` still report the tx via the txid set.
    let block_hash = BlockHash::from_slice(&[7u8; 32]).expect("hash");
    let _ = ctx
        .check_transaction(
            &tx,
            TransactionContext::InChainLockedBlock(BlockInfo::new(100, block_hash, 1_700_000_000)),
        )
        .await;
    assert!(
        !ctx.bip44_account().transactions().contains_key(&txid),
        "with the feature OFF the chainlocked record must be dropped"
    );
    assert!(ctx.bip44_account().has_transaction(&txid));
    assert!(ctx.bip44_account().transaction_is_finalized(&txid));
}

/// IS-lock is **not** finalization. The record must NOT be dropped when
/// the feature is OFF because we still need the in-memory record to
/// absorb the eventual block-confirmation event (height / block hash).
/// This guards against the pre-review bug where dropping on IS-lock
/// lost block-confirmation tracking.
#[cfg(not(feature = "keep-finalized-transactions"))]
#[tokio::test]
async fn test_islocked_record_kept_when_feature_off() {
    let mut ctx = TestWalletContext::new_random();
    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[150_000]);
    let txid = tx.txid();

    let _ = ctx.check_transaction(&tx, TransactionContext::Mempool).await;
    let _ =
        ctx.check_transaction(&tx, TransactionContext::InstantSend(InstantLock::default())).await;

    assert!(ctx.bip44_account().has_transaction(&txid));
    assert!(
        !ctx.bip44_account().transaction_is_finalized(&txid),
        "IS-lock alone is not finalization — only a chainlock counts"
    );
    assert!(
        ctx.bip44_account().transactions().contains_key(&txid),
        "IS-locked records must survive so a later InBlock event can populate \
         block-confirmation info"
    );
}

/// IS-lock first, then a chainlocked block: the record must drop only at
/// the chainlock step. We also assert that the chainlock event still
/// "lands" — `transaction_is_finalized` must report `true` when asked
/// via the txid set.
#[cfg(not(feature = "keep-finalized-transactions"))]
#[tokio::test]
async fn test_islocked_then_chainlocked_drops_at_chainlock() {
    let mut ctx = TestWalletContext::new_random();
    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[200_000]);
    let txid = tx.txid();

    let _ = ctx.check_transaction(&tx, TransactionContext::Mempool).await;
    let _ =
        ctx.check_transaction(&tx, TransactionContext::InstantSend(InstantLock::default())).await;
    assert!(ctx.bip44_account().transactions().contains_key(&txid), "still present after IS-lock");

    let block_hash = BlockHash::from_slice(&[3u8; 32]).expect("hash");
    let _ = ctx
        .check_transaction(
            &tx,
            TransactionContext::InChainLockedBlock(BlockInfo::new(42, block_hash, 1_700_000_000)),
        )
        .await;
    assert!(!ctx.bip44_account().transactions().contains_key(&txid), "dropped at chainlock");
    assert!(ctx.bip44_account().has_transaction(&txid));
    assert!(ctx.bip44_account().transaction_is_finalized(&txid));
}
