//! Tests for UTXO (Unspent Transaction Output) management
//!
//! Tests UTXO creation, tracking, spending, and balance calculation.

// UTXO types would normally come from wallet module
// For testing, using mock implementations at the bottom of this file
use crate::Network;
use dashcore::{Address, OutPoint, Script, ScriptBuf, Transaction, TxIn, TxOut, Txid, BlockHash};
use dashcore::hashes::Hash;
use std::collections::{BTreeMap, HashMap};

/// Helper to create a test UTXO
fn create_test_utxo(txid: Txid, vout: u32, value: u64, height: Option<u32>) -> UTXO {
    UTXO {
        outpoint: OutPoint { txid, vout },
        value,
        script_pubkey: ScriptBuf::new(),
        address: None,
        is_coinbase: false,
        confirmations: height.map(|h| 6), // Assume 6 confirmations if height provided
        block_height: height,
        account_index: Some(0),
        address_index: Some(0),
        is_change: false,
    }
}

#[test]
fn test_utxo_creation_from_transaction() {
    // Create a transaction with multiple outputs
    let tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: dashcore::Witness::default(),
            }
        ],
        output: vec![
            TxOut {
                value: 100000,
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: 200000,
                script_pubkey: ScriptBuf::new(),
            },
        ],
        special_transaction_payload: None,
    };
    
    let txid = tx.txid();
    
    // Create UTXOs from transaction outputs
    let mut utxos = Vec::new();
    for (vout, output) in tx.output.iter().enumerate() {
        let utxo = UTXO {
            outpoint: OutPoint { 
                txid, 
                vout: vout as u32 
            },
            value: output.value,
            script_pubkey: output.script_pubkey.clone(),
            address: None,
            is_coinbase: false,
            confirmations: Some(0),
            block_height: None,
            account_index: Some(0),
            address_index: Some(vout as u32),
            is_change: false,
        };
        utxos.push(utxo);
    }
    
    assert_eq!(utxos.len(), 2);
    assert_eq!(utxos[0].value, 100000);
    assert_eq!(utxos[1].value, 200000);
}

#[test]
fn test_utxo_spending() {
    let mut collection = UTXOCollection::new();
    
    // Add some UTXOs
    let txid1 = Txid::from_byte_array([1u8; 32]);
    let txid2 = Txid::from_byte_array([2u8; 32]);
    
    let utxo1 = create_test_utxo(txid1, 0, 100000, Some(100));
    let utxo2 = create_test_utxo(txid2, 0, 200000, Some(101));
    
    collection.add(utxo1.clone());
    collection.add(utxo2.clone());
    
    assert_eq!(collection.count(), 2);
    assert_eq!(collection.total_value(), 300000);
    
    // Spend the first UTXO
    let spent = collection.spend(&utxo1.outpoint);
    assert!(spent.is_some());
    assert_eq!(spent.unwrap().value, 100000);
    
    // Check remaining
    assert_eq!(collection.count(), 1);
    assert_eq!(collection.total_value(), 200000);
    
    // Try to spend the same UTXO again
    let spent_again = collection.spend(&utxo1.outpoint);
    assert!(spent_again.is_none());
}

#[test]
fn test_utxo_balance_calculation() {
    let mut collection = UTXOCollection::new();
    
    // Add UTXOs with different confirmation counts
    let txid1 = Txid::from_byte_array([1u8; 32]);
    let txid2 = Txid::from_byte_array([2u8; 32]);
    let txid3 = Txid::from_byte_array([3u8; 32]);
    
    let mut utxo1 = create_test_utxo(txid1, 0, 100000, Some(100));
    utxo1.confirmations = Some(10);
    
    let mut utxo2 = create_test_utxo(txid2, 0, 200000, Some(105));
    utxo2.confirmations = Some(5);
    
    let mut utxo3 = create_test_utxo(txid3, 0, 300000, None);
    utxo3.confirmations = Some(0); // Unconfirmed
    
    collection.add(utxo1);
    collection.add(utxo2);
    collection.add(utxo3);
    
    // Total balance (all UTXOs)
    assert_eq!(collection.total_value(), 600000);
    
    // Confirmed balance (6+ confirmations)
    assert_eq!(collection.confirmed_balance(6), 100000);
    
    // Available balance (1+ confirmations)
    assert_eq!(collection.confirmed_balance(1), 300000);
    
    // Unconfirmed balance
    assert_eq!(collection.unconfirmed_balance(), 300000);
}

#[test]
fn test_utxo_selection_for_spending() {
    let mut collection = UTXOCollection::new();
    
    // Add various UTXOs
    for i in 1..=5 {
        let txid = Txid::from_byte_array([i as u8; 32]);
        let utxo = create_test_utxo(txid, 0, (i as u64) * 100000, Some(100 + i));
        collection.add(utxo);
    }
    
    // Select UTXOs for a specific amount
    let target = 350000; // Should select 100000 + 200000 + 100000 or similar
    let selected = collection.select_utxos(target, 1000); // 1000 sat fee per input
    
    assert!(selected.is_some());
    let (utxos, total) = selected.unwrap();
    assert!(total >= target);
    assert!(utxos.len() <= 3); // Should use at most 3 UTXOs
}

#[test]
fn test_coinbase_utxo_handling() {
    let mut collection = UTXOCollection::new();
    
    // Create a coinbase UTXO
    let txid = Txid::from_byte_array([1u8; 32]);
    let mut coinbase_utxo = create_test_utxo(txid, 0, 5000000000, Some(100));
    coinbase_utxo.is_coinbase = true;
    coinbase_utxo.confirmations = Some(50); // Not yet mature (needs 100)
    
    collection.add(coinbase_utxo.clone());
    
    // Check that immature coinbase is not included in spendable balance
    assert_eq!(collection.spendable_balance(100), 0);
    
    // Update to mature
    coinbase_utxo.confirmations = Some(100);
    collection.update_confirmations(&coinbase_utxo.outpoint, 100);
    
    // Now it should be spendable
    assert_eq!(collection.spendable_balance(100), 5000000000);
}

#[test]
fn test_utxo_tracking_across_accounts() {
    let mut collections: BTreeMap<u32, UTXOCollection> = BTreeMap::new();
    
    // Create UTXOs for different accounts
    for account_idx in 0..3 {
        let mut collection = UTXOCollection::new();
        
        for i in 0..5 {
            let txid = Txid::from_byte_array([(account_idx * 10 + i) as u8; 32]);
            let mut utxo = create_test_utxo(txid, 0, 100000 * (i + 1) as u64, Some(100));
            utxo.account_index = Some(account_idx);
            collection.add(utxo);
        }
        
        collections.insert(account_idx, collection);
    }
    
    // Verify each account has its own UTXOs
    for account_idx in 0..3 {
        let collection = collections.get(&account_idx).unwrap();
        assert_eq!(collection.count(), 5);
        assert_eq!(collection.total_value(), 1500000); // 100k + 200k + 300k + 400k + 500k
    }
    
    // Calculate total across all accounts
    let total_balance: u64 = collections.values()
        .map(|c| c.total_value())
        .sum();
    assert_eq!(total_balance, 4500000); // 1.5M * 3 accounts
}

#[test]
fn test_utxo_replacement_rbf() {
    let mut collection = UTXOCollection::new();
    
    let txid1 = Txid::from_byte_array([1u8; 32]);
    let txid2 = Txid::from_byte_array([2u8; 32]);
    
    // Add original transaction UTXO
    let utxo1 = create_test_utxo(txid1, 0, 100000, None);
    collection.add(utxo1.clone());
    
    // Replace with RBF transaction (same inputs, different txid)
    collection.remove(&utxo1.outpoint);
    let utxo2 = create_test_utxo(txid2, 0, 99000, None); // Lower value due to higher fee
    collection.add(utxo2);
    
    assert_eq!(collection.count(), 1);
    assert_eq!(collection.total_value(), 99000);
}

#[test]
fn test_utxo_confirmation_updates() {
    let mut collection = UTXOCollection::new();
    
    let txid = Txid::from_byte_array([1u8; 32]);
    let mut utxo = create_test_utxo(txid, 0, 100000, None);
    utxo.confirmations = Some(0);
    
    collection.add(utxo.clone());
    
    // Initially unconfirmed
    assert_eq!(collection.confirmed_balance(1), 0);
    
    // Update confirmations
    for confirms in 1..=6 {
        collection.update_confirmations(&utxo.outpoint, confirms);
        if confirms >= 1 {
            assert_eq!(collection.confirmed_balance(1), 100000);
        }
        if confirms >= 6 {
            assert_eq!(collection.confirmed_balance(6), 100000);
        }
    }
}

#[test]
fn test_change_utxo_tracking() {
    let mut collection = UTXOCollection::new();
    
    // Add external UTXOs
    let txid1 = Txid::from_byte_array([1u8; 32]);
    let mut external_utxo = create_test_utxo(txid1, 0, 100000, Some(100));
    external_utxo.is_change = false;
    
    // Add change UTXOs
    let txid2 = Txid::from_byte_array([2u8; 32]);
    let mut change_utxo = create_test_utxo(txid2, 1, 50000, Some(100));
    change_utxo.is_change = true;
    
    collection.add(external_utxo);
    collection.add(change_utxo);
    
    // Get change-only balance
    let change_balance = collection.get_change_balance();
    assert_eq!(change_balance, 50000);
    
    // Get external-only balance
    let external_balance = collection.get_external_balance();
    assert_eq!(external_balance, 100000);
}

#[test]
fn test_utxo_dust_filtering() {
    let mut collection = UTXOCollection::new();
    const DUST_LIMIT: u64 = 546; // Standard dust limit
    
    // Add various UTXOs including dust
    let txid1 = Txid::from_byte_array([1u8; 32]);
    let txid2 = Txid::from_byte_array([2u8; 32]);
    let txid3 = Txid::from_byte_array([3u8; 32]);
    
    collection.add(create_test_utxo(txid1, 0, 100000, Some(100)));
    collection.add(create_test_utxo(txid2, 0, 300, Some(100))); // Dust
    collection.add(create_test_utxo(txid3, 0, 1000, Some(100))); // Not dust
    
    // Filter out dust UTXOs
    let non_dust = collection.get_non_dust_utxos(DUST_LIMIT);
    assert_eq!(non_dust.len(), 2);
    
    // Calculate spendable balance excluding dust
    let spendable_non_dust = collection.spendable_balance_non_dust(DUST_LIMIT, 1);
    assert_eq!(spendable_non_dust, 101000);
}

// Mock structures for testing - in real implementation these would be in the wallet module
mod mock {
    use super::*;
    
    pub struct UTXO {
        pub outpoint: OutPoint,
        pub value: u64,
        pub script_pubkey: ScriptBuf,
        pub address: Option<Address>,
        pub is_coinbase: bool,
        pub confirmations: Option<u32>,
        pub block_height: Option<u32>,
        pub account_index: Option<u32>,
        pub address_index: Option<u32>,
        pub is_change: bool,
    }
    
    pub struct UTXOCollection {
        utxos: HashMap<OutPoint, UTXO>,
    }
    
    impl UTXOCollection {
        pub fn new() -> Self {
            Self {
                utxos: HashMap::new(),
            }
        }
        
        pub fn add(&mut self, utxo: UTXO) {
            self.utxos.insert(utxo.outpoint.clone(), utxo);
        }
        
        pub fn remove(&mut self, outpoint: &OutPoint) -> Option<UTXO> {
            self.utxos.remove(outpoint)
        }
        
        pub fn spend(&mut self, outpoint: &OutPoint) -> Option<UTXO> {
            self.remove(outpoint)
        }
        
        pub fn count(&self) -> usize {
            self.utxos.len()
        }
        
        pub fn total_value(&self) -> u64 {
            self.utxos.values().map(|u| u.value).sum()
        }
        
        pub fn confirmed_balance(&self, min_confirmations: u32) -> u64 {
            self.utxos.values()
                .filter(|u| u.confirmations.unwrap_or(0) >= min_confirmations)
                .map(|u| u.value)
                .sum()
        }
        
        pub fn unconfirmed_balance(&self) -> u64 {
            self.utxos.values()
                .filter(|u| u.confirmations.unwrap_or(0) == 0)
                .map(|u| u.value)
                .sum()
        }
        
        pub fn spendable_balance(&self, coinbase_maturity: u32) -> u64 {
            self.utxos.values()
                .filter(|u| {
                    if u.is_coinbase {
                        u.confirmations.unwrap_or(0) >= coinbase_maturity
                    } else {
                        true
                    }
                })
                .map(|u| u.value)
                .sum()
        }
        
        pub fn update_confirmations(&mut self, outpoint: &OutPoint, confirmations: u32) {
            if let Some(utxo) = self.utxos.get_mut(outpoint) {
                utxo.confirmations = Some(confirmations);
            }
        }
        
        pub fn select_utxos(&self, target: u64, _fee_per_input: u64) -> Option<(Vec<UTXO>, u64)> {
            let mut selected = Vec::new();
            let mut total = 0u64;
            
            for utxo in self.utxos.values() {
                if total >= target {
                    break;
                }
                selected.push(utxo.clone());
                total += utxo.value;
            }
            
            if total >= target {
                Some((selected, total))
            } else {
                None
            }
        }
        
        pub fn get_change_balance(&self) -> u64 {
            self.utxos.values()
                .filter(|u| u.is_change)
                .map(|u| u.value)
                .sum()
        }
        
        pub fn get_external_balance(&self) -> u64 {
            self.utxos.values()
                .filter(|u| !u.is_change)
                .map(|u| u.value)
                .sum()
        }
        
        pub fn get_non_dust_utxos(&self, dust_limit: u64) -> Vec<&UTXO> {
            self.utxos.values()
                .filter(|u| u.value >= dust_limit)
                .collect()
        }
        
        pub fn spendable_balance_non_dust(&self, dust_limit: u64, min_confirmations: u32) -> u64 {
            self.utxos.values()
                .filter(|u| u.value >= dust_limit && u.confirmations.unwrap_or(0) >= min_confirmations)
                .map(|u| u.value)
                .sum()
        }
    }
    
    impl Clone for UTXO {
        fn clone(&self) -> Self {
            Self {
                outpoint: self.outpoint.clone(),
                value: self.value,
                script_pubkey: self.script_pubkey.clone(),
                address: self.address.clone(),
                is_coinbase: self.is_coinbase,
                confirmations: self.confirmations,
                block_height: self.block_height,
                account_index: self.account_index,
                address_index: self.address_index,
                is_change: self.is_change,
            }
        }
    }
}

// Use the mock structures for testing
use mock::{UTXO, UTXOCollection};