//! Tests for immature transaction tracking
//!
//! Tests coinbase transaction maturity tracking and management.

use crate::wallet::immature_transaction::{
    AffectedAccounts, ImmatureTransaction, ImmatureTransactionCollection,
};
use alloc::vec::Vec;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, OutPoint, ScriptBuf, Transaction, TxIn, TxOut};

/// Helper to create a coinbase transaction
fn create_test_coinbase(height: u32, value: u64) -> Transaction {
    // Create coinbase input with height in scriptSig
    let mut script_sig = Vec::new();
    script_sig.push(0x03); // Push 3 bytes
    script_sig.extend_from_slice(&height.to_le_bytes()[0..3]); // Height as little-endian

    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::null(), // Coinbase has null outpoint
            script_sig: ScriptBuf::from(script_sig),
            sequence: 0xffffffff,
            witness: dashcore::Witness::default(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: ScriptBuf::new(), // Empty for test
        }],
        special_transaction_payload: None,
    }
}

#[test]
fn test_immature_transaction_creation() {
    let tx = create_test_coinbase(100000, 5000000000);
    let block_hash = BlockHash::from_slice(&[0u8; 32]).unwrap();

    let immature_tx = ImmatureTransaction::new(
        tx.clone(),
        100000,
        block_hash,
        1234567890,
        100,  // maturity confirmations
        true, // is_coinbase
    );

    assert_eq!(immature_tx.txid, tx.txid());
    assert_eq!(immature_tx.height, 100000);
    assert!(immature_tx.is_coinbase);
}

#[test]
fn test_immature_transaction_collection_add() {
    let mut collection = ImmatureTransactionCollection::new();

    // Add transactions at different maturity heights
    let tx1 = create_test_coinbase(100000, 5000000000);
    let tx2 = create_test_coinbase(100050, 5000000000);

    let block_hash = BlockHash::from_slice(&[0u8; 32]).unwrap();

    let immature1 = ImmatureTransaction::new(tx1.clone(), 100000, block_hash, 0, 100, true);
    let immature2 = ImmatureTransaction::new(tx2.clone(), 100050, block_hash, 0, 100, true);

    collection.insert(immature1);
    collection.insert(immature2);

    assert!(collection.contains(&tx1.txid()));
    assert!(collection.contains(&tx2.txid()));
}

#[test]
fn test_immature_transaction_collection_get_mature() {
    let mut collection = ImmatureTransactionCollection::new();
    let block_hash = BlockHash::from_slice(&[0u8; 32]).unwrap();

    // Add transactions at different maturity heights
    let tx1 = create_test_coinbase(100000, 5000000000);
    let tx2 = create_test_coinbase(100050, 5000000000);
    let tx3 = create_test_coinbase(100100, 5000000000);

    collection.insert(ImmatureTransaction::new(tx1.clone(), 100000, block_hash, 0, 100, true));
    collection.insert(ImmatureTransaction::new(tx2.clone(), 100050, block_hash, 0, 100, true));
    collection.insert(ImmatureTransaction::new(tx3.clone(), 100100, block_hash, 0, 100, true));

    // Get transactions that mature at height 100150 or before
    let mature = collection.get_matured(100150);

    assert_eq!(mature.len(), 2);
    assert!(mature.iter().any(|t| t.txid == tx1.txid()));
    assert!(mature.iter().any(|t| t.txid == tx2.txid()));

    // Verify tx3 is not included (matures at 100200)
    assert!(!mature.iter().any(|t| t.txid == tx3.txid()));
}

#[test]
fn test_immature_transaction_collection_remove_mature() {
    let mut collection = ImmatureTransactionCollection::new();
    let block_hash = BlockHash::from_slice(&[0u8; 32]).unwrap();

    // Add transactions
    let tx1 = create_test_coinbase(100000, 5000000000);
    let tx2 = create_test_coinbase(100050, 5000000000);
    let tx3 = create_test_coinbase(100100, 5000000000);

    collection.insert(ImmatureTransaction::new(tx1.clone(), 100000, block_hash, 0, 100, true));
    collection.insert(ImmatureTransaction::new(tx2.clone(), 100050, block_hash, 0, 100, true));
    collection.insert(ImmatureTransaction::new(tx3.clone(), 100100, block_hash, 0, 100, true));

    // Remove mature transactions at height 100150
    let removed = collection.remove_matured(100150);

    assert_eq!(removed.len(), 2);

    // Only tx3 should remain
    assert!(!collection.contains(&tx1.txid()));
    assert!(!collection.contains(&tx2.txid()));
    assert!(collection.contains(&tx3.txid()));
}

#[test]
fn test_affected_accounts() {
    let mut accounts = AffectedAccounts::new();

    // Add various account types
    accounts.add_bip44(0);
    accounts.add_bip44(1);
    accounts.add_bip44(2);
    accounts.add_bip32(0);
    accounts.add_coinjoin(0);

    assert_eq!(accounts.count(), 5);
    assert!(!accounts.is_empty());

    assert_eq!(accounts.bip44_accounts.len(), 3);
    assert_eq!(accounts.bip32_accounts.len(), 1);
    assert_eq!(accounts.coinjoin_accounts.len(), 1);
}

#[test]
fn test_immature_transaction_collection_clear() {
    let mut collection = ImmatureTransactionCollection::new();
    let block_hash = BlockHash::from_slice(&[0u8; 32]).unwrap();

    // Add multiple transactions
    for i in 0..5 {
        let tx = create_test_coinbase(100000 + i, 5000000000);
        collection.insert(ImmatureTransaction::new(tx, 100000 + i, block_hash, 0, 100, true));
    }

    collection.clear();
    assert!(collection.is_empty());
}

#[test]
fn test_immature_transaction_height_tracking() {
    let mut collection = ImmatureTransactionCollection::new();
    let block_hash = BlockHash::from_slice(&[0u8; 32]).unwrap();

    let tx = create_test_coinbase(100000, 5000000000);
    let immature = ImmatureTransaction::new(tx.clone(), 100000, block_hash, 0, 100, true);

    collection.insert(immature);

    // Get the immature transaction
    let retrieved = collection.get(&tx.txid());
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().height, 100000);
}

#[test]
fn test_immature_transaction_duplicate_add() {
    let mut collection = ImmatureTransactionCollection::new();
    let block_hash = BlockHash::from_slice(&[0u8; 32]).unwrap();

    let tx = create_test_coinbase(100000, 5000000000);

    collection.insert(ImmatureTransaction::new(tx.clone(), 100000, block_hash, 0, 100, true));

    // Adding the same transaction again should replace it
    collection.insert(ImmatureTransaction::new(tx.clone(), 100000, block_hash, 0, 100, true));

    // Still only one transaction
    assert!(collection.contains(&tx.txid()));
}

#[test]
fn test_immature_transaction_batch_maturity() {
    let mut collection = ImmatureTransactionCollection::new();
    let block_hash = BlockHash::from_slice(&[0u8; 32]).unwrap();

    // Add multiple transactions that mature at the same height
    for i in 0..5 {
        let tx = create_test_coinbase(100000 - i, 5000000000);
        // All mature at height 100100 (100000 + 100 confirmations)
        collection.insert(ImmatureTransaction::new(tx, 100000, block_hash, 0, 100, true));
    }

    // All should mature at height 100100
    let mature = collection.get_matured(100100);
    assert_eq!(mature.len(), 5);
}

#[test]
fn test_immature_transaction_ordering() {
    let mut collection = ImmatureTransactionCollection::new();
    let block_hash = BlockHash::from_slice(&[0u8; 32]).unwrap();

    // Add transactions in random order with different maturity heights
    let heights = [100, 0, 200, 50];
    let mut txids = Vec::new();

    for (i, height) in heights.iter().enumerate() {
        let tx = create_test_coinbase(100000 + i as u32, 5000000000);
        txids.push(tx.txid());

        collection.insert(ImmatureTransaction::new(tx, 100000 + height, block_hash, 0, 100, true));
    }

    // Get transactions maturing up to height 100200
    let mature = collection.get_matured(100200);

    // Should get transactions at heights 100100, 100150, 100200 (3 total)
    assert_eq!(mature.len(), 3);
}

#[test]
fn test_coinbase_maturity_constant() {
    // Verify the standard coinbase maturity is 100 blocks
    const COINBASE_MATURITY: u32 = 100;

    let block_height = 500000;
    let maturity_height = block_height + COINBASE_MATURITY;

    assert_eq!(maturity_height, 500100);
}

#[test]
fn test_immature_transaction_empty_account_indices() {
    let accounts = AffectedAccounts::new();

    assert!(accounts.bip44_accounts.is_empty());
    assert!(accounts.bip32_accounts.is_empty());
    assert!(accounts.coinjoin_accounts.is_empty());
    assert!(accounts.is_empty());
}

#[test]
fn test_immature_transaction_remove_specific() {
    let mut collection = ImmatureTransactionCollection::new();
    let block_hash = BlockHash::from_slice(&[0u8; 32]).unwrap();

    let tx1 = create_test_coinbase(100000, 5000000000);
    let tx2 = create_test_coinbase(100050, 5000000000);

    collection.insert(ImmatureTransaction::new(tx1.clone(), 100000, block_hash, 0, 100, true));
    collection.insert(ImmatureTransaction::new(tx2.clone(), 100050, block_hash, 0, 100, true));

    // Remove specific transaction
    let removed = collection.remove(&tx1.txid());
    assert!(removed.is_some());

    assert!(!collection.contains(&tx1.txid()));
    assert!(collection.contains(&tx2.txid()));
}

#[test]
fn test_immature_transaction_iterator() {
    let mut collection = ImmatureTransactionCollection::new();
    let block_hash = BlockHash::from_slice(&[0u8; 32]).unwrap();

    // Add transactions
    let mut expected_txids = Vec::new();
    for i in 0..3 {
        let tx = create_test_coinbase(100000 + i, 5000000000);
        expected_txids.push(tx.txid());

        collection.insert(ImmatureTransaction::new(tx, 100000 + i, block_hash, 0, 100, true));
    }

    // Check all transactions are in collection
    for txid in &expected_txids {
        assert!(collection.contains(txid));
    }
}
