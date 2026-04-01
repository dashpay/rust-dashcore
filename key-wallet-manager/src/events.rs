//! Wallet events for notifying consumers of wallet state changes.
//!
//! These events are emitted by the WalletManager when significant wallet
//! operations occur, allowing consumers to receive push-based notifications.

use dashcore::{Amount, SignedAmount, Txid};
use key_wallet::managed_account::transaction_record::TransactionRecord;
use key_wallet::transaction_checking::TransactionContext;

use crate::WalletId;

/// Events emitted by the wallet manager.
///
/// Each event represents a meaningful wallet state change that consumers
/// may want to react to.
#[derive(Debug, Clone)]
pub enum WalletEvent {
    /// A transaction relevant to the wallet was received for the first time.
    TransactionReceived {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// Account index within the wallet.
        account_index: u32,
        /// The full transaction record with all details.
        record: Box<TransactionRecord>,
    },
    /// The confirmation status of a previously seen transaction has changed.
    TransactionStatusChanged {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// Transaction ID.
        txid: Txid,
        /// New transaction context.
        status: TransactionContext,
    },
    /// The wallet balance has changed.
    BalanceUpdated {
        /// ID of the affected wallet.
        wallet_id: WalletId,
        /// New spendable balance in duffs (confirmed and mature).
        spendable: u64,
        /// New unconfirmed balance in duffs.
        unconfirmed: u64,
        /// New immature balance (coinbase UTXOs not yet mature).
        immature: u64,
        /// New locked balance (UTXOs reserved for specific purposes like CoinJoin)
        locked: u64,
    },
}

impl WalletEvent {
    /// Get a short description of this event for logging.
    pub fn description(&self) -> String {
        match self {
            WalletEvent::TransactionReceived {
                record,
                ..
            } => {
                format!(
                    "TransactionReceived(txid={}, amount={}, status={})",
                    record.txid,
                    SignedAmount::from_sat(record.net_amount),
                    record.context
                )
            }
            WalletEvent::TransactionStatusChanged {
                txid,
                status,
                ..
            } => {
                format!("TransactionStatusChanged(txid={}, status={})", txid, status)
            }
            WalletEvent::BalanceUpdated {
                spendable,
                unconfirmed,
                immature,
                locked,
                ..
            } => {
                format!(
                    "BalanceUpdated(spendable={}, unconfirmed={}, immature={}, locked={})",
                    Amount::from_sat(*spendable),
                    Amount::from_sat(*unconfirmed),
                    Amount::from_sat(*immature),
                    Amount::from_sat(*locked)
                )
            }
        }
    }
}
