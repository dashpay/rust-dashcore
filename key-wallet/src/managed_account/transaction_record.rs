//! Transaction record for account management
//!
//! This module contains the transaction record structure used to track
//! transactions associated with accounts.

use crate::error::Error;
use crate::transaction_checking::transaction_router::TransactionType;
use crate::transaction_checking::{BlockInfo, TransactionContext};
use crate::Address;
use dashcore::blockdata::transaction::Transaction;
use dashcore::Txid;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Maximum length of a transaction label in bytes.
pub const MAX_LABEL_LENGTH: usize = 256;

/// Wallet-context metadata for a transaction input.
/// The index references `transaction.input[index]`.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InputDetail {
    /// Index into the transaction's input array
    pub index: u32,
    /// Value of the UTXO being spent
    pub value: u64,
    /// Address that owned the spent UTXO
    pub address: Address,
}

/// Wallet-context metadata for a transaction output.
/// The index references `transaction.output[index]`.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputDetail {
    /// Index into the transaction's output array
    pub index: u32,
    /// Role of this output from the wallet's perspective
    pub role: OutputRole,
    /// Decoded address (None for non-standard scripts)
    pub address: Option<Address>,
    /// Value in satoshis
    pub value: u64,
}

/// Role of a transaction output from the wallet's perspective
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum OutputRole {
    /// Output to our external/receive address
    Received,
    /// Output to our internal/change address
    Change,
    /// Output to counterparty address
    Sent,
    /// Unspendable output (OP_RETURN, non-standard, bare multisig)
    Unspendable,
}

/// Direction of a transaction from the wallet's perspective
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TransactionDirection {
    /// Received funds from external source
    Incoming,
    /// Sent funds to external address
    Outgoing,
    /// Self-transfer or consolidation (no outputs to external addresses; may include unspendable data outputs)
    Internal,
    /// CoinJoin mixing transaction
    CoinJoin,
}

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
    /// Classification of the transaction type
    pub transaction_type: TransactionType,
    /// Direction of the transaction from the wallet's perspective
    pub direction: TransactionDirection,
    /// Wallet-relevant input details
    pub input_details: Vec<InputDetail>,
    /// Wallet-relevant output details
    pub output_details: Vec<OutputDetail>,
    /// Net amount for this account
    pub net_amount: i64,
    /// Fee paid (if we created it)
    pub fee: Option<u64>,
    /// Transaction label
    pub label: String,
}

impl TransactionRecord {
    /// Create a new transaction record with the given context
    pub fn new(
        transaction: Transaction,
        context: TransactionContext,
        transaction_type: TransactionType,
        direction: TransactionDirection,
        input_details: Vec<InputDetail>,
        output_details: Vec<OutputDetail>,
        net_amount: i64,
    ) -> Self {
        let txid = transaction.txid();
        Self {
            txid,
            transaction,
            context,
            transaction_type,
            direction,
            input_details,
            output_details,
            net_amount,
            fee: None,
            label: String::new(),
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

    /// Set the label for this transaction.
    ///
    /// Returns an error if the label exceeds [`MAX_LABEL_LENGTH`] bytes.
    pub fn set_label(&mut self, label: String) -> Result<(), Error> {
        if label.len() > MAX_LABEL_LENGTH {
            return Err(Error::InvalidParameter(format!(
                "Label exceeds {} bytes",
                MAX_LABEL_LENGTH
            )));
        }
        self.label = label;
        Ok(())
    }

    /// Update the transaction context
    pub fn update_context(&mut self, context: TransactionContext) {
        self.context = context;
    }

    /// Check if this is an incoming transaction
    pub fn is_incoming(&self) -> bool {
        self.direction == TransactionDirection::Incoming
    }

    /// Check if this is an outgoing transaction
    pub fn is_outgoing(&self) -> bool {
        self.direction == TransactionDirection::Outgoing
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

    fn simple_record(
        tx: Transaction,
        context: TransactionContext,
        net_amount: i64,
    ) -> TransactionRecord {
        TransactionRecord::new(
            tx,
            context,
            TransactionType::Standard,
            TransactionDirection::Incoming,
            Vec::new(),
            Vec::new(),
            net_amount,
        )
    }

    #[test]
    fn test_transaction_record_creation() {
        let tx = Transaction::dummy_empty();
        let record = simple_record(tx.clone(), TransactionContext::Mempool, 50000);

        assert_eq!(record.txid, tx.txid());
        assert_eq!(record.net_amount, 50000);
        assert_eq!(record.direction, TransactionDirection::Incoming);
        assert!(!record.is_confirmed());
    }

    #[test]
    fn test_confirmations_calculation() {
        let tx = Transaction::dummy_empty();
        let mut record = simple_record(tx, TransactionContext::Mempool, 50000);

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

        let incoming = simple_record(tx.clone(), TransactionContext::Mempool, 50000);
        assert!(incoming.is_incoming());
        assert!(!incoming.is_outgoing());
        assert_eq!(incoming.amount(), 50000);

        let outgoing = TransactionRecord::new(
            tx.clone(),
            TransactionContext::Mempool,
            TransactionType::Standard,
            TransactionDirection::Outgoing,
            Vec::new(),
            Vec::new(),
            -50000,
        );
        assert!(!outgoing.is_incoming());
        assert!(outgoing.is_outgoing());
        assert_eq!(outgoing.amount(), 50000);

        let internal = TransactionRecord::new(
            tx.clone(),
            TransactionContext::Mempool,
            TransactionType::Standard,
            TransactionDirection::Internal,
            Vec::new(),
            Vec::new(),
            0,
        );
        assert!(!internal.is_incoming());
        assert!(!internal.is_outgoing());

        let coinjoin = TransactionRecord::new(
            tx,
            TransactionContext::Mempool,
            TransactionType::CoinJoin,
            TransactionDirection::CoinJoin,
            Vec::new(),
            Vec::new(),
            0,
        );
        assert!(!coinjoin.is_incoming());
        assert!(!coinjoin.is_outgoing());
    }

    #[test]
    fn test_confirmed_transaction_creation() {
        let tx = Transaction::dummy_empty();
        let record = simple_record(tx.clone(), test_block_context(100), 50000);

        assert_eq!(record.height(), Some(100));
        assert!(record.is_confirmed());
    }

    #[test]
    fn test_update_context_reorg() {
        let tx = Transaction::dummy_empty();
        let mut record = simple_record(tx, test_block_context(100), 50000);

        assert!(record.is_confirmed());

        // Simulate reorg — back to mempool
        record.update_context(TransactionContext::Mempool);
        assert!(!record.is_confirmed());
        assert_eq!(record.block_info(), None);
    }

    #[test]
    fn test_labels_and_fees() {
        let tx = Transaction::dummy_empty();
        let mut record = simple_record(tx, TransactionContext::Mempool, -50000);

        assert_eq!(record.fee, None);
        assert!(record.label.is_empty());

        record.set_fee(226);
        record.set_label("Payment to Bob".to_string()).unwrap();

        assert_eq!(record.fee, Some(226));
        assert_eq!(record.label, "Payment to Bob");

        // Empty string clears the label
        record.set_label(String::new()).unwrap();
        assert!(record.label.is_empty());

        // Exceeding max length returns an error
        let long_label = "x".repeat(MAX_LABEL_LENGTH + 1);
        assert!(record.set_label(long_label).is_err());
        assert!(record.label.is_empty()); // unchanged

        // Exactly max length is fine
        let max_label = "x".repeat(MAX_LABEL_LENGTH);
        record.set_label(max_label.clone()).unwrap();
        assert_eq!(record.label, max_label);
    }
}
