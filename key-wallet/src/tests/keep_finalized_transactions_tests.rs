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
    account::{AccountType, StandardAccountType},
    managed_account::managed_account_trait::ManagedAccountTrait,
    test_utils::TestWalletContext,
    transaction_checking::{BlockInfo, TransactionContext},
    wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface,
};
use dashcore::ephemerealdata::chain_lock::ChainLock;
#[cfg(not(feature = "keep-finalized-transactions"))]
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, Transaction};

fn bip44_account_type() -> AccountType {
    AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    }
}

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

/// `apply_chain_lock` at a height covering an `InBlock` record
/// promotes its context. With the feature OFF the record is dropped
/// from the map. With the feature ON it stays with the new context.
#[tokio::test]
async fn test_apply_chain_lock_promotes_in_block_records() {
    let mut ctx = TestWalletContext::new_random();
    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[150_000]);
    let txid = tx.txid();
    let block_hash = BlockHash::from_slice(&[9u8; 32]).expect("hash");

    let _ = ctx
        .check_transaction(
            &tx,
            TransactionContext::InBlock(BlockInfo::new(50, block_hash, 1_700_000_000)),
        )
        .await;
    assert!(ctx.bip44_account().transactions().contains_key(&txid));

    ctx.managed_wallet.update_last_processed_height(50);
    let outcome = ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(50));
    assert!(
        outcome.metadata_advanced,
        "first chainlock must advance metadata from None to Some(50)"
    );
    let promoted = outcome
        .locked_transactions
        .get(&bip44_account_type())
        .expect("BIP44 account should have a promotion entry");
    assert_eq!(promoted, &vec![txid]);
    assert!(ctx.bip44_account().transaction_is_finalized(&txid));

    #[cfg(feature = "keep-finalized-transactions")]
    {
        let record = ctx.bip44_account().transactions().get(&txid).expect("record kept");
        assert!(matches!(record.context, TransactionContext::InChainLockedBlock(_)));
    }
    #[cfg(not(feature = "keep-finalized-transactions"))]
    {
        assert!(
            !ctx.bip44_account().transactions().contains_key(&txid),
            "with the feature OFF the record must be dropped after promotion"
        );
    }
}

/// `apply_chain_lock` only promotes records at or below `cl_height` and
/// never touches `Mempool` / `InstantSend` records (those have not been
/// mined yet, and chainlock-finality requires a block).
#[tokio::test]
async fn test_apply_chain_lock_skips_unmined_and_above_height() {
    let mut ctx = TestWalletContext::new_random();
    let mempool_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[120_000]);
    let block_tx = Transaction::dummy(&ctx.receive_address, 1..2, &[150_000]);
    let mempool_txid = mempool_tx.txid();
    let block_txid = block_tx.txid();
    let block_hash = BlockHash::from_slice(&[1u8; 32]).expect("hash");

    let _ = ctx.check_transaction(&mempool_tx, TransactionContext::Mempool).await;
    let _ = ctx
        .check_transaction(
            &block_tx,
            TransactionContext::InBlock(BlockInfo::new(200, block_hash, 1_700_000_000)),
        )
        .await;

    // Chainlock at 100 sits below the InBlock-at-200 record and above
    // the mempool record's (absent) height, so neither promotes.
    ctx.managed_wallet.update_last_processed_height(200);
    let outcome = ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(100));
    assert!(outcome.locked_transactions.is_empty());
    assert!(
        outcome.metadata_advanced,
        "metadata must still advance to the new finality boundary even when no record promotes"
    );
    assert!(!ctx.bip44_account().transaction_is_finalized(&mempool_txid));
    assert!(!ctx.bip44_account().transaction_is_finalized(&block_txid));
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
