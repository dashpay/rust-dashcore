//! Transaction record for account management
//!
//! This module contains the transaction record structure used to track
//! transactions associated with accounts.

use alloc::string::String;
use dashcore::blockdata::transaction::Transaction;
use dashcore::{BlockHash, Txid};
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
    /// Block height (if confirmed)
    pub height: Option<u32>,
    /// Block hash (if confirmed)
    pub block_hash: Option<BlockHash>,
    /// Timestamp
    pub timestamp: u64,
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
    /// Create a new transaction record
    pub fn new(transaction: Transaction, timestamp: u64, net_amount: i64, is_ours: bool) -> Self {
        let txid = transaction.txid();
        Self {
            transaction,
            txid,
            height: None,
            block_hash: None,
            timestamp,
            net_amount,
            fee: None,
            label: None,
            is_ours,
        }
    }

    /// Create a confirmed transaction record
    pub fn new_confirmed(
        transaction: Transaction,
        height: u32,
        block_hash: BlockHash,
        timestamp: u64,
        net_amount: i64,
        is_ours: bool,
    ) -> Self {
        let txid = transaction.txid();
        Self {
            transaction,
            txid,
            height: Some(height),
            block_hash: Some(block_hash),
            timestamp,
            net_amount,
            fee: None,
            label: None,
            is_ours,
        }
    }

    /// Calculate the number of confirmations based on current chain height
    pub fn confirmations(&self, current_height: u32) -> u32 {
        match self.height {
            Some(tx_height) if current_height >= tx_height => {
                // Add 1 because the block itself counts as 1 confirmation
                (current_height - tx_height) + 1
            }
            _ => 0, // Unconfirmed or invalid height
        }
    }

    /// Check if the transaction is confirmed (has at least 1 confirmation)
    pub fn is_confirmed(&self) -> bool {
        self.height.is_some()
    }

    /// Check if the transaction has at least the specified number of confirmations
    pub fn has_confirmations(&self, required: u32, current_height: u32) -> bool {
        self.confirmations(current_height) >= required
    }

    /// Set the fee for this transaction
    pub fn set_fee(&mut self, fee: u64) {
        self.fee = Some(fee);
    }

    /// Set the label for this transaction
    pub fn set_label(&mut self, label: String) {
        self.label = Some(label);
    }

    /// Mark transaction as confirmed
    pub fn mark_confirmed(&mut self, height: u32, block_hash: BlockHash) {
        self.height = Some(height);
        self.block_hash = Some(block_hash);
    }

    /// Mark transaction as unconfirmed (e.g., due to reorg)
    pub fn mark_unconfirmed(&mut self) {
        self.height = None;
        self.block_hash = None;
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

    fn create_test_transaction() -> Transaction {
        // Create a minimal test transaction
        Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        }
    }

    #[test]
    fn test_transaction_record_creation() {
        let tx = create_test_transaction();
        let record = TransactionRecord::new(tx.clone(), 1234567890, 50000, true);

        assert_eq!(record.txid, tx.txid());
        assert_eq!(record.timestamp, 1234567890);
        assert_eq!(record.net_amount, 50000);
        assert!(record.is_ours);
        assert!(!record.is_confirmed());
    }

    #[test]
    fn test_confirmations_calculation() {
        let tx = create_test_transaction();
        let mut record = TransactionRecord::new(tx, 1234567890, 50000, true);

        // Unconfirmed transaction
        assert_eq!(record.confirmations(100), 0);
        assert!(!record.is_confirmed());

        // Mark as confirmed at height 95
        record.mark_confirmed(95, BlockHash::all_zeros());
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
        let tx = create_test_transaction();

        let incoming = TransactionRecord::new(tx.clone(), 1234567890, 50000, false);
        assert!(incoming.is_incoming());
        assert!(!incoming.is_outgoing());
        assert_eq!(incoming.amount(), 50000);

        let outgoing = TransactionRecord::new(tx.clone(), 1234567890, -50000, true);
        assert!(!outgoing.is_incoming());
        assert!(outgoing.is_outgoing());
        assert_eq!(outgoing.amount(), 50000);
    }

    #[test]
    fn test_confirmed_transaction_creation() {
        let tx = create_test_transaction();
        let block_hash = BlockHash::all_zeros();
        let record =
            TransactionRecord::new_confirmed(tx.clone(), 100, block_hash, 1234567890, 50000, true);

        assert_eq!(record.height, Some(100));
        assert_eq!(record.block_hash, Some(block_hash));
        assert!(record.is_confirmed());
    }

    #[test]
    fn test_mark_unconfirmed() {
        let tx = create_test_transaction();
        let block_hash = BlockHash::all_zeros();
        let mut record =
            TransactionRecord::new_confirmed(tx, 100, block_hash, 1234567890, 50000, true);

        assert!(record.is_confirmed());

        // Simulate reorg
        record.mark_unconfirmed();
        assert!(!record.is_confirmed());
        assert_eq!(record.height, None);
        assert_eq!(record.block_hash, None);
    }

    #[test]
    fn test_labels_and_fees() {
        let tx = create_test_transaction();
        let mut record = TransactionRecord::new(tx, 1234567890, -50000, true);

        assert_eq!(record.fee, None);
        assert_eq!(record.label, None);

        record.set_fee(226);
        record.set_label("Payment to Bob".to_string());

        assert_eq!(record.fee, Some(226));
        assert_eq!(record.label, Some("Payment to Bob".to_string()));
    }
}
