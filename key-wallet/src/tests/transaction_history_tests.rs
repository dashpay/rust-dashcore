//! Tests for transaction history tracking and management
//!
//! Tests transaction recording, confirmation tracking, queries, and metadata.

use dashcore::hashes::Hash;
use dashcore::{BlockHash, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};
use std::collections::{BTreeMap, HashMap};

/// Transaction history entry
#[derive(Clone, Debug)]
struct TransactionHistoryEntry {
    pub tx: Transaction,
    pub txid: Txid,
    pub timestamp: u64,
    pub block_height: Option<u32>,
    pub block_hash: Option<BlockHash>,
    pub confirmations: u32,
    pub fee: Option<u64>,
    pub category: TransactionCategory,
    pub metadata: HashMap<String, String>,
    pub replaced_by: Option<Txid>, // For RBF
}

#[derive(Clone, Debug, PartialEq)]
enum TransactionCategory {
    Received,
    Sent,
    Internal, // Between own accounts
    Coinbase,
    CoinJoin,
    ProviderRegistration,
    ProviderUpdate,
    IdentityRegistration,
    IdentityTopUp,
}

/// Transaction history collection
struct TransactionHistory {
    entries: BTreeMap<Txid, TransactionHistoryEntry>,
    by_height: BTreeMap<u32, Vec<Txid>>,
    unconfirmed: Vec<Txid>,
}

impl TransactionHistory {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            by_height: BTreeMap::new(),
            unconfirmed: Vec::new(),
        }
    }

    fn add_transaction(&mut self, entry: TransactionHistoryEntry) {
        let txid = entry.txid;

        if let Some(height) = entry.block_height {
            self.by_height.entry(height).or_insert_with(Vec::new).push(txid);
        } else {
            self.unconfirmed.push(txid);
        }

        self.entries.insert(txid, entry);
    }

    fn get_transaction(&self, txid: &Txid) -> Option<&TransactionHistoryEntry> {
        self.entries.get(txid)
    }

    fn update_confirmations(&mut self, txid: &Txid, confirmations: u32, height: Option<u32>) {
        if let Some(entry) = self.entries.get_mut(txid) {
            entry.confirmations = confirmations;
            if entry.block_height.is_none() && height.is_some() {
                entry.block_height = height;
                // Move from unconfirmed to confirmed
                self.unconfirmed.retain(|&t| t != *txid);
                if let Some(h) = height {
                    self.by_height.entry(h).or_insert_with(Vec::new).push(*txid);
                }
            }
        }
    }

    fn get_history_range(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> Vec<&TransactionHistoryEntry> {
        let mut result = Vec::new();
        for (height, txids) in self.by_height.range(start_height..=end_height) {
            for txid in txids {
                if let Some(entry) = self.entries.get(txid) {
                    result.push(entry);
                }
            }
        }
        result
    }

    fn mark_replaced(&mut self, original: &Txid, replacement: Txid) {
        if let Some(entry) = self.entries.get_mut(original) {
            entry.replaced_by = Some(replacement);
        }
    }
}

/// Helper to create a test transaction
fn create_test_transaction(value: u64) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: dashcore::Witness::default(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: ScriptBuf::new(),
        }],
        special_transaction_payload: None,
    }
}

#[test]
fn test_transaction_history_recording() {
    let mut history = TransactionHistory::new();

    // Create and add transactions
    let tx1 = create_test_transaction(100000);
    let entry1 = TransactionHistoryEntry {
        tx: tx1.clone(),
        txid: tx1.txid(),
        timestamp: 1234567890,
        block_height: Some(100),
        block_hash: Some(BlockHash::from_slice(&[1u8; 32]).unwrap()),
        confirmations: 6,
        fee: Some(1000),
        category: TransactionCategory::Received,
        metadata: HashMap::new(),
        replaced_by: None,
    };

    history.add_transaction(entry1.clone());

    // Verify it was recorded
    let retrieved = history.get_transaction(&tx1.txid());
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().timestamp, 1234567890);
    assert_eq!(retrieved.unwrap().category, TransactionCategory::Received);
}

#[test]
fn test_transaction_confirmation_tracking() {
    let mut history = TransactionHistory::new();

    // Add unconfirmed transaction
    let tx = create_test_transaction(100000);
    let entry = TransactionHistoryEntry {
        tx: tx.clone(),
        txid: tx.txid(),
        timestamp: 1234567890,
        block_height: None,
        block_hash: None,
        confirmations: 0,
        fee: Some(1000),
        category: TransactionCategory::Sent,
        metadata: HashMap::new(),
        replaced_by: None,
    };

    history.add_transaction(entry);
    assert_eq!(history.unconfirmed.len(), 1);

    // Update to confirmed
    history.update_confirmations(&tx.txid(), 1, Some(100));

    let retrieved = history.get_transaction(&tx.txid()).unwrap();
    assert_eq!(retrieved.confirmations, 1);
    assert_eq!(retrieved.block_height, Some(100));
    assert_eq!(history.unconfirmed.len(), 0);

    // Update confirmations
    for confirms in 2..=6 {
        history.update_confirmations(&tx.txid(), confirms, Some(100));
        let retrieved = history.get_transaction(&tx.txid()).unwrap();
        assert_eq!(retrieved.confirmations, confirms);
    }
}

#[test]
fn test_transaction_replacement_rbf() {
    let mut history = TransactionHistory::new();

    // Add original transaction
    let tx1 = create_test_transaction(100000);
    let entry1 = TransactionHistoryEntry {
        tx: tx1.clone(),
        txid: tx1.txid(),
        timestamp: 1234567890,
        block_height: None,
        block_hash: None,
        confirmations: 0,
        fee: Some(1000),
        category: TransactionCategory::Sent,
        metadata: HashMap::new(),
        replaced_by: None,
    };

    history.add_transaction(entry1);

    // Add replacement transaction
    let tx2 = create_test_transaction(99000); // Less output due to higher fee
    let entry2 = TransactionHistoryEntry {
        tx: tx2.clone(),
        txid: tx2.txid(),
        timestamp: 1234567900,
        block_height: None,
        block_hash: None,
        confirmations: 0,
        fee: Some(2000), // Higher fee
        category: TransactionCategory::Sent,
        metadata: HashMap::new(),
        replaced_by: None,
    };

    history.add_transaction(entry2);

    // Mark original as replaced
    history.mark_replaced(&tx1.txid(), tx2.txid());

    let original = history.get_transaction(&tx1.txid()).unwrap();
    assert_eq!(original.replaced_by, Some(tx2.txid()));
}

#[test]
fn test_transaction_history_queries() {
    let mut history = TransactionHistory::new();

    // Add transactions at different heights
    for i in 0..10 {
        let tx = create_test_transaction(100000 * (i + 1));
        let entry = TransactionHistoryEntry {
            tx: tx.clone(),
            txid: tx.txid(),
            timestamp: 1234567890 + i * 100,
            block_height: Some(100 + i as u32),
            block_hash: Some(BlockHash::from_slice(&[i as u8 + 1; 32]).unwrap()),
            confirmations: 6,
            fee: Some(1000),
            category: if i % 2 == 0 {
                TransactionCategory::Received
            } else {
                TransactionCategory::Sent
            },
            metadata: HashMap::new(),
            replaced_by: None,
        };
        history.add_transaction(entry);
    }

    // Query range
    let range = history.get_history_range(102, 105);
    assert_eq!(range.len(), 4); // Heights 102, 103, 104, 105

    // Verify order
    for i in 0..range.len() - 1 {
        assert!(range[i].block_height <= range[i + 1].block_height);
    }
}

#[test]
fn test_transaction_metadata_storage() {
    let mut history = TransactionHistory::new();

    let tx = create_test_transaction(100000);
    let mut metadata = HashMap::new();
    metadata.insert("label".to_string(), "Payment to Alice".to_string());
    metadata.insert("category".to_string(), "business".to_string());
    metadata.insert("note".to_string(), "Invoice #123".to_string());

    let entry = TransactionHistoryEntry {
        tx: tx.clone(),
        txid: tx.txid(),
        timestamp: 1234567890,
        block_height: Some(100),
        block_hash: Some(BlockHash::from_slice(&[1u8; 32]).unwrap()),
        confirmations: 6,
        fee: Some(1000),
        category: TransactionCategory::Sent,
        metadata: metadata.clone(),
        replaced_by: None,
    };

    history.add_transaction(entry);

    let retrieved = history.get_transaction(&tx.txid()).unwrap();
    assert_eq!(retrieved.metadata.get("label"), Some(&"Payment to Alice".to_string()));
    assert_eq!(retrieved.metadata.get("category"), Some(&"business".to_string()));
    assert_eq!(retrieved.metadata.get("note"), Some(&"Invoice #123".to_string()));
}

#[test]
fn test_transaction_category_classification() {
    let categories = vec![
        TransactionCategory::Received,
        TransactionCategory::Sent,
        TransactionCategory::Internal,
        TransactionCategory::Coinbase,
        TransactionCategory::CoinJoin,
        TransactionCategory::ProviderRegistration,
        TransactionCategory::ProviderUpdate,
        TransactionCategory::IdentityRegistration,
        TransactionCategory::IdentityTopUp,
    ];

    // Verify each category is distinct
    for (i, cat1) in categories.iter().enumerate() {
        for (j, cat2) in categories.iter().enumerate() {
            if i == j {
                assert_eq!(cat1, cat2);
            } else {
                assert_ne!(cat1, cat2);
            }
        }
    }
}

#[test]
fn test_coinbase_transaction_history() {
    let mut history = TransactionHistory::new();

    // Create coinbase transaction
    let height = 100000u32;
    let mut script_sig = vec![];
    script_sig.push(0x03);
    script_sig.extend_from_slice(&height.to_le_bytes()[0..3]);

    let coinbase_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from(script_sig),
            sequence: 0xffffffff,
            witness: dashcore::Witness::default(),
        }],
        output: vec![TxOut {
            value: 5000000000,
            script_pubkey: ScriptBuf::new(),
        }],
        special_transaction_payload: None,
    };

    let entry = TransactionHistoryEntry {
        tx: coinbase_tx.clone(),
        txid: coinbase_tx.txid(),
        timestamp: 1234567890,
        block_height: Some(height),
        block_hash: Some(BlockHash::from_slice(&[1u8; 32]).unwrap()),
        confirmations: 0,
        fee: None, // Coinbase has no fee
        category: TransactionCategory::Coinbase,
        metadata: HashMap::new(),
        replaced_by: None,
    };

    history.add_transaction(entry);

    let retrieved = history.get_transaction(&coinbase_tx.txid()).unwrap();
    assert_eq!(retrieved.category, TransactionCategory::Coinbase);
    assert!(retrieved.fee.is_none());
}

#[test]
fn test_internal_transfer_tracking() {
    let mut history = TransactionHistory::new();

    // Create internal transfer (between own accounts)
    let tx = create_test_transaction(100000);
    let entry = TransactionHistoryEntry {
        tx: tx.clone(),
        txid: tx.txid(),
        timestamp: 1234567890,
        block_height: Some(100),
        block_hash: Some(BlockHash::from_slice(&[1u8; 32]).unwrap()),
        confirmations: 6,
        fee: Some(1000),
        category: TransactionCategory::Internal,
        metadata: HashMap::new(),
        replaced_by: None,
    };

    history.add_transaction(entry);

    let retrieved = history.get_transaction(&tx.txid()).unwrap();
    assert_eq!(retrieved.category, TransactionCategory::Internal);
    // Internal transfers should not affect total balance (only fee is lost)
}

#[test]
fn test_transaction_history_pruning() {
    let mut history = TransactionHistory::new();

    // Add many old transactions
    for i in 0..1000 {
        let tx = create_test_transaction(1000 + i); // Vary the amount to get different txids
        let entry = TransactionHistoryEntry {
            tx: tx.clone(),
            txid: tx.txid(),
            timestamp: 1234567890 + i,
            block_height: Some(i as u32),
            block_hash: Some(BlockHash::from_slice(&[(i % 256) as u8; 32]).unwrap()),
            confirmations: 1000 - i as u32,
            fee: Some(100),
            category: TransactionCategory::Received,
            metadata: HashMap::new(),
            replaced_by: None,
        };
        history.add_transaction(entry);
    }

    // In a real implementation, we would prune old transactions
    // keeping only recent ones and important ones (coinbase, large amounts, etc.)
    assert_eq!(history.entries.len(), 1000);

    // Simulate pruning: keep only last 100 blocks
    let cutoff_height = 900;
    let to_keep: Vec<Txid> =
        history.by_height.range(cutoff_height..).flat_map(|(_, txids)| txids.clone()).collect();

    assert_eq!(to_keep.len(), 100);
}
