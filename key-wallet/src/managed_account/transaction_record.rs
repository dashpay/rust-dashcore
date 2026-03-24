//! Transaction record for account management
//!
//! This module contains the transaction record structure used to track
//! transactions associated with accounts.

use crate::transaction_checking::{BlockInfo, TransactionContext};
use dashcore::blockdata::transaction::Transaction;
use dashcore::Txid;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Transaction record with full details
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TransactionRecord {
    /// The transaction
    pub transaction: Transaction,
    /// Transaction ID
    pub txid: Txid,
    /// The context in which this transaction was last seen
    pub context: TransactionContext,
    /// Net amount for this account
    pub net_amount: i64,
    /// Fee paid (if we created it)
    pub fee: Option<u64>,
    /// Transaction label
    pub label: Option<String>,
    /// Whether this is our transaction
    pub is_ours: bool,
}

impl TransactionRecord {
    /// Create a new transaction record with the given context
    pub fn new(
        transaction: Transaction,
        context: TransactionContext,
        net_amount: i64,
        is_ours: bool,
    ) -> Self {
        let txid = transaction.txid();
        Self {
            transaction,
            txid,
            context,
            net_amount,
            fee: None,
            label: None,
            is_ours,
        }
    }

    /// Calculate the number of confirmations based on current chain height
    pub fn confirmations(&self, current_height: u32) -> u32 {
        match self.context.block_info() {
            Some(info) if current_height >= info.height => (current_height - info.height) + 1,
            _ => 0,
        }
    }

    /// Check if the transaction is confirmed (has at least 1 confirmation)
    pub fn is_confirmed(&self) -> bool {
        self.context.confirmed()
    }

    /// Check if the transaction has at least the specified number of confirmations
    pub fn has_confirmations(&self, required: u32, current_height: u32) -> bool {
        self.confirmations(current_height) >= required
    }

    /// Block info if confirmed
    pub fn block_info(&self) -> Option<&BlockInfo> {
        self.context.block_info()
    }

    /// Block height if confirmed
    pub fn height(&self) -> Option<u32> {
        self.context.block_info().map(|info| info.height)
    }

    /// Set the fee for this transaction
    pub fn set_fee(&mut self, fee: u64) {
        self.fee = Some(fee);
    }

    /// Set the label for this transaction
    pub fn set_label(&mut self, label: String) {
        self.label = Some(label);
    }

    /// Update the transaction context
    pub fn update_context(&mut self, context: TransactionContext) {
        self.context = context;
    }

    /// Check if this is an incoming transaction (positive net amount)
    pub fn is_incoming(&self) -> bool {
        self.net_amount > 0
    }

    /// Check if this is an outgoing transaction (negative net amount)
    pub fn is_outgoing(&self) -> bool {
        self.net_amount < 0
    }

    /// Get the absolute value of the net amount
    pub fn amount(&self) -> u64 {
        self.net_amount.unsigned_abs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::hashes::Hash;
    use dashcore::BlockHash;

    fn test_block_context(height: u32) -> TransactionContext {
        TransactionContext::InBlock(BlockInfo::new(height, BlockHash::all_zeros(), 1234567890))
    }

    #[test]
    fn test_transaction_record_creation() {
        let tx = Transaction::dummy_empty();
        let record = TransactionRecord::new(tx.clone(), TransactionContext::Mempool, 50000, true);

        assert_eq!(record.txid, tx.txid());
        assert_eq!(record.net_amount, 50000);
        assert!(record.is_ours);
        assert!(!record.is_confirmed());
    }

    #[test]
    fn test_confirmations_calculation() {
        let tx = Transaction::dummy_empty();
        let mut record = TransactionRecord::new(tx, TransactionContext::Mempool, 50000, true);

        // Unconfirmed transaction
        assert_eq!(record.confirmations(100), 0);
        assert!(!record.is_confirmed());

        // Confirm at height 95
        record.update_context(test_block_context(95));
        assert!(record.is_confirmed());

        // At height 100, should have 6 confirmations (100 - 95 + 1)
        assert_eq!(record.confirmations(100), 6);
        assert!(record.has_confirmations(6, 100));
        assert!(!record.has_confirmations(7, 100));

        // At height 95 (same as tx height), should have 1 confirmation
        assert_eq!(record.confirmations(95), 1);

        // Edge case: current height less than tx height
        assert_eq!(record.confirmations(90), 0);
    }

    #[test]
    fn test_incoming_outgoing() {
        let tx = Transaction::dummy_empty();

        let incoming =
            TransactionRecord::new(tx.clone(), TransactionContext::Mempool, 50000, false);
        assert!(incoming.is_incoming());
        assert!(!incoming.is_outgoing());
        assert_eq!(incoming.amount(), 50000);

        let outgoing =
            TransactionRecord::new(tx.clone(), TransactionContext::Mempool, -50000, true);
        assert!(!outgoing.is_incoming());
        assert!(outgoing.is_outgoing());
        assert_eq!(outgoing.amount(), 50000);
    }

    #[test]
    fn test_confirmed_transaction_creation() {
        let tx = Transaction::dummy_empty();
        let record = TransactionRecord::new(tx.clone(), test_block_context(100), 50000, true);

        assert_eq!(record.height(), Some(100));
        assert!(record.is_confirmed());
    }

    #[test]
    fn test_update_context_reorg() {
        let tx = Transaction::dummy_empty();
        let mut record = TransactionRecord::new(tx, test_block_context(100), 50000, true);

        assert!(record.is_confirmed());

        // Simulate reorg — back to mempool
        record.update_context(TransactionContext::Mempool);
        assert!(!record.is_confirmed());
        assert_eq!(record.block_info(), None);
    }

    #[test]
    fn test_labels_and_fees() {
        let tx = Transaction::dummy_empty();
        let mut record = TransactionRecord::new(tx, TransactionContext::Mempool, -50000, true);

        assert_eq!(record.fee, None);
        assert_eq!(record.label, None);

        record.set_fee(226);
        record.set_label("Payment to Bob".to_string());

        assert_eq!(record.fee, Some(226));
        assert_eq!(record.label, Some("Payment to Bob".to_string()));
    }
}
