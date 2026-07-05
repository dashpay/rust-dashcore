//! Found-021 — `TransactionRecord::update_context` silently drops the
//! `InstantLock` when a transaction is promoted from `InstantSend` to `InBlock`.
//!
//! Defect site: `key-wallet/src/managed_account/transaction_record.rs`
//! (`update_context`: unconditional `self.context = context;`).
//! Tracking issue: https://github.com/dashpay/rust-dashcore/issues/763
//!
//! A transaction first observed with `TransactionContext::InstantSend(lock)`
//! and later promoted with `TransactionContext::InBlock(info)` loses the
//! IS-lock: `update_context` replaces the whole context instead of merging.
//! Any consumer that reads the record after block confirmation to use the
//! lock as proof material (e.g. an `InstantAssetLockProof`) finds no lock.
//!
//! The production call sequence is reconstructed directly through the public
//! `TransactionRecord` API — the same two `update_context` hops the wallet
//! sync path performs (`wallet_checker.rs` promotes IS records on block
//! confirmation). No SPV harness or network is required because the defect
//! is a pure field assignment.
//!
//! Test lifecycle: RED today (lock gone after promotion). GREEN once
//! `update_context` preserves the lock — via a merged context variant or a
//! dedicated field — at which point `context_has_instant_lock` below must be
//! extended to recognise the new representation.

use key_wallet::account::{
    AccountType, StandardAccountType, TransactionDirection, TransactionRecord,
};
use key_wallet::dashcore::blockdata::transaction::Transaction;
use key_wallet::dashcore::ephemerealdata::instant_lock::InstantLock;
use key_wallet::dashcore::hashes::Hash;
use key_wallet::dashcore::BlockHash;
use key_wallet::transaction_checking::{BlockInfo, TransactionContext, TransactionType};

/// Minimal, structurally valid (non-special) transaction fixture. The
/// on-chain shape is irrelevant to this bug pin.
fn dummy_tx() -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![],
        output: vec![],
        special_transaction_payload: None,
    }
}

/// A `TransactionRecord` in the `InstantSend` context — the wallet's first
/// observation of an asset-lock tx after IS-lock receipt.
fn record_with_instant_send(lock: InstantLock) -> TransactionRecord {
    TransactionRecord::new(
        dummy_tx(),
        AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP44Account,
        },
        TransactionContext::InstantSend(lock),
        TransactionType::AssetLock,
        TransactionDirection::Outgoing,
        vec![],
        vec![],
        -100_000,
    )
}

/// `true` when the context carries an `InstantLock` in any form. Today only
/// `InstantSend(lock)` qualifies; once the fix introduces a merged variant
/// (e.g. `InBlockWithInstantLock`) or a dedicated lock field, extend this to
/// match it.
fn context_has_instant_lock(ctx: &TransactionContext) -> bool {
    matches!(ctx, TransactionContext::InstantSend(_))
}

#[test]
fn found_021_instant_lock_dropped_on_context_promotion() {
    // Synthetic IS-lock: all-zero fields are structurally valid for this
    // pin; BLS verification is not exercised.
    let lock = InstantLock::default();

    let mut record = record_with_instant_send(lock);
    assert!(
        context_has_instant_lock(&record.context),
        "pre-condition: record.context must be InstantSend after construction"
    );

    // Promote to InBlock — the call the wallet sync path performs when a
    // block confirmation arrives for an already-IS-locked transaction.
    let block_info = BlockInfo::new(100_000, BlockHash::all_zeros(), 1_700_000_000);
    record.update_context(TransactionContext::InBlock(block_info));

    // (RED-by-design): update_context replaces the context wholesale, so the
    // IS-lock is silently dropped on IS -> InBlock promotion (rust-dashcore#763).
    assert!(
        context_has_instant_lock(&record.context),
        "InstantLock was silently dropped on InBlock promotion: \
         record.context after update_context(InBlock(..)) is {:?}. \
         `update_context` performs `self.context = context;` unconditionally, \
         overwriting InstantSend(lock). Fix: merge the context on IS->InBlock \
         promotion (dedicated lock field or an InBlockWithInstantLock variant), \
         then extend context_has_instant_lock in this test to match it. \
         See https://github.com/dashpay/rust-dashcore/issues/763",
        record.context
    );
}
