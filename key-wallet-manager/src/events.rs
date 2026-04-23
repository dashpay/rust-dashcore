//! Wallet events for notifying consumers of wallet state changes.
//!
//! Each variant is self-contained: it carries the transaction record(s) that
//! triggered it and the wallet's new balance after the change. Consumers can
//! persist the transaction(s) and balance atomically off a single event.

use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::prelude::CoreBlockHeight;
use dashcore::Txid;
use key_wallet::managed_account::transaction_record::TransactionRecord;
use key_wallet::WalletCoreBalance;

use crate::WalletId;

/// Events emitted by the wallet manager.
///
/// Each event represents a meaningful wallet state change and carries the
/// wallet's balance *after* the change so consumers can save transactions
/// and balance atomically.
#[derive(Debug, Clone)]
pub enum WalletEvent {
    /// A wallet-relevant transaction was first seen in the mempool
    /// (optionally with an InstantSend lock — in that case the record's
    /// `context` is `InstantSend(..)`).
    MempoolTransactionReceived {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// The full transaction record (context may be Mempool or InstantSend).
        ///
        /// Boxed to keep the enum compact: `TransactionRecord` is ~800 bytes
        /// and would otherwise inflate every variant to that size.
        record: Box<TransactionRecord>,
        /// Wallet balance after the transaction was recorded.
        balance: WalletCoreBalance,
    },
    /// A previously-seen wallet-relevant transaction was InstantSend-locked.
    TransactionInstantSendLocked {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// Transaction ID that was locked.
        txid: Txid,
        /// The InstantSend lock that locked the transaction.
        instant_send_lock: InstantLock,
        /// Wallet balance after the lock was applied.
        balance: WalletCoreBalance,
    },
    /// A block was processed. Carries the wallet's newly-recorded and
    /// state-modified transactions for the block, along with the post-block
    /// balance. `transactions_updated` may be empty when only the balance
    /// shifted (e.g. a coinbase maturing as synced height advanced).
    BlockProcessChange {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// Height of the block that was processed.
        height: CoreBlockHeight,
        /// Transaction records recorded or updated by this block.
        transactions_updated: Vec<TransactionRecord>,
        /// Wallet balance after the block was processed.
        balance: WalletCoreBalance,
    },
}

impl WalletEvent {
    /// ID of the wallet this event pertains to.
    pub fn wallet_id(&self) -> WalletId {
        match self {
            WalletEvent::MempoolTransactionReceived {
                wallet_id,
                ..
            }
            | WalletEvent::TransactionInstantSendLocked {
                wallet_id,
                ..
            }
            | WalletEvent::BlockProcessChange {
                wallet_id,
                ..
            } => *wallet_id,
        }
    }

    /// Wallet balance carried by this event.
    pub fn balance(&self) -> WalletCoreBalance {
        match self {
            WalletEvent::MempoolTransactionReceived {
                balance,
                ..
            }
            | WalletEvent::TransactionInstantSendLocked {
                balance,
                ..
            }
            | WalletEvent::BlockProcessChange {
                balance,
                ..
            } => *balance,
        }
    }

    /// Short description for logging.
    pub fn description(&self) -> String {
        match self {
            WalletEvent::MempoolTransactionReceived {
                record,
                balance,
                ..
            } => {
                format!(
                    "MempoolTransactionReceived(txid={}, context={}, balance={})",
                    record.txid, record.context, balance
                )
            }
            WalletEvent::TransactionInstantSendLocked {
                txid,
                balance,
                ..
            } => {
                format!("TransactionInstantSendLocked(txid={}, balance={})", txid, balance)
            }
            WalletEvent::BlockProcessChange {
                height,
                transactions_updated,
                balance,
                ..
            } => {
                format!(
                    "BlockProcessChange(height={}, tx_count={}, balance={})",
                    height,
                    transactions_updated.len(),
                    balance
                )
            }
        }
    }
}
