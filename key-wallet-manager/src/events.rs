//! Wallet events for notifying consumers of wallet state changes.
//!
//! Each variant is self-contained: it carries the transaction record(s) that
//! triggered it and the wallet's new balance after the change. Consumers can
//! persist the transaction(s) and balance atomically off a single event.

use dashcore::prelude::CoreBlockHeight;
use dashcore::Txid;
use key_wallet::managed_account::transaction_record::TransactionRecord;
use key_wallet::transaction_checking::TransactionContext;
use key_wallet::WalletCoreBalance;

use crate::WalletId;

/// Events emitted by the wallet manager.
///
/// Each event represents a meaningful wallet state change. Events that
/// modify balance carry the wallet's balance *after* the change so
/// consumers can persist the record(s) and balance atomically.
#[derive(Debug, Clone)]
pub enum WalletEvent {
    /// First time the wallet sees an off-chain wallet-relevant transaction
    /// (mempool, or directly via an InstantSend lock — in that case
    /// `record.context` is `InstantSend(..)`).
    TransactionReceived {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// The full transaction record with all details.
        record: Box<TransactionRecord>,
        /// Wallet balance after the transaction was recorded.
        balance: WalletCoreBalance,
    },
    /// A previously-seen off-chain wallet-relevant transaction had its state
    /// changed. Currently fires only for InstantSend locks applied
    /// to a known mempool tx.
    TransactionStatusChanged {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// Transaction ID.
        txid: Txid,
        /// New transaction context.
        status: TransactionContext,
        /// Wallet balance after the status change.
        balance: WalletCoreBalance,
    },
    /// A block was processed for a wallet. Carries records bucketed by what
    /// happened to them in this block, plus the post-block balance.
    /// `inserted` is records first stored in this block, `updated` is
    /// previously-known records that just confirmed, `matured` is older
    /// coinbase records that crossed the maturity threshold as the scanned
    /// height advanced.
    BlockUpdate {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// Height of the block that was processed.
        height: CoreBlockHeight,
        /// Records first stored for this wallet in this block.
        inserted: Vec<TransactionRecord>,
        /// Previously-known records confirmed by this block.
        updated: Vec<TransactionRecord>,
        /// Older coinbase records whose maturity threshold was crossed by
        /// this height advance.
        matured: Vec<TransactionRecord>,
        /// Wallet balance after the block was processed.
        balance: WalletCoreBalance,
    },
    /// The wallet's scan cursor advanced because the filter pipeline
    /// committed a batch covering blocks up to `height`. No records or
    /// balance — consumers persist this as a checkpoint atomically with
    /// any records/balance from prior `BlockUpdate` events in the batch.
    SyncHeightUpdate {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// New scanned height for the wallet.
        height: CoreBlockHeight,
    },
}

impl WalletEvent {
    /// ID of the wallet this event pertains to.
    pub fn wallet_id(&self) -> WalletId {
        match self {
            WalletEvent::TransactionReceived {
                wallet_id,
                ..
            }
            | WalletEvent::TransactionStatusChanged {
                wallet_id,
                ..
            }
            | WalletEvent::BlockUpdate {
                wallet_id,
                ..
            }
            | WalletEvent::SyncHeightUpdate {
                wallet_id,
                ..
            } => *wallet_id,
        }
    }

    /// Short description for logging.
    pub fn description(&self) -> String {
        match self {
            WalletEvent::TransactionReceived {
                record,
                balance,
                ..
            } => {
                format!(
                    "TransactionReceived(txid={}, context={}, balance={})",
                    record.txid, record.context, balance
                )
            }
            WalletEvent::TransactionStatusChanged {
                txid,
                status,
                balance,
                ..
            } => {
                format!(
                    "TransactionStatusChanged(txid={}, status={}, balance={})",
                    txid, status, balance
                )
            }
            WalletEvent::BlockUpdate {
                height,
                inserted,
                updated,
                matured,
                balance,
                ..
            } => {
                format!(
                    "BlockUpdate(height={}, inserted={}, updated={}, matured={}, balance={})",
                    height,
                    inserted.len(),
                    updated.len(),
                    matured.len(),
                    balance
                )
            }
            WalletEvent::SyncHeightUpdate {
                height,
                ..
            } => {
                format!("SyncHeightUpdate(height={})", height)
            }
        }
    }
}
