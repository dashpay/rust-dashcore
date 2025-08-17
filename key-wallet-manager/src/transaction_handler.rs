//! Transaction reception and handling
//!
//! This module provides functionality for receiving transactions,
//! matching them against wallet addresses, and updating wallet state.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::Transaction;
use dashcore::OutPoint;
use dashcore::{Address as DashAddress, Txid};
use key_wallet::{Address, Network};

use crate::wallet_manager::WalletId;
use key_wallet::{Utxo, UtxoSet};

/// Transaction handler for processing incoming transactions
pub struct TransactionHandler {
    /// Network we're operating on
    _network: Network,
    /// Address to wallet mapping for quick lookups
    address_index: BTreeMap<Address, WalletId>,
    /// Script to address mapping
    script_index: BTreeMap<ScriptBuf, Address>,
    /// Pending transactions (unconfirmed)
    pending_txs: BTreeMap<Txid, PendingTransaction>,
}

/// A pending (unconfirmed) transaction
#[derive(Debug, Clone)]
pub struct PendingTransaction {
    /// The transaction
    pub transaction: Transaction,
    /// When we first saw this transaction
    pub first_seen: u64,
    /// Fee paid (if we can calculate it)
    pub fee: Option<u64>,
    /// Whether this transaction is ours (we created it)
    pub is_ours: bool,
}

/// Result of processing a transaction
#[derive(Debug, Clone)]
pub struct TransactionProcessResult {
    /// Wallet IDs that were affected
    pub affected_wallets: Vec<WalletId>,
    /// New UTXOs created
    pub new_utxos: Vec<Utxo>,
    /// UTXOs that were spent
    pub spent_utxos: Vec<OutPoint>,
    /// Net balance change per wallet
    pub balance_changes: BTreeMap<WalletId, i64>,
    /// Whether this transaction is relevant to any wallet
    pub is_relevant: bool,
}

/// Address usage tracker
#[derive(Debug, Clone)]
pub struct AddressTracker {
    /// Used receive addresses by wallet and account
    used_receive_addresses: BTreeMap<(WalletId, u32), BTreeSet<u32>>,
    /// Used change addresses by wallet and account
    used_change_addresses: BTreeMap<(WalletId, u32), BTreeSet<u32>>,
    /// Current receive index for each account
    receive_indices: BTreeMap<(WalletId, u32), u32>,
    /// Current change index for each account
    change_indices: BTreeMap<(WalletId, u32), u32>,
    /// Gap limit for address generation
    gap_limit: u32,
}

impl TransactionHandler {
    /// Create a new transaction handler
    pub fn new(network: Network) -> Self {
        Self {
            _network: network,
            address_index: BTreeMap::new(),
            script_index: BTreeMap::new(),
            pending_txs: BTreeMap::new(),
        }
    }

    /// Register a wallet's addresses for monitoring
    pub fn register_wallet_addresses(&mut self, wallet_id: WalletId, addresses: Vec<Address>) {
        for address in addresses {
            self.address_index.insert(address.clone(), wallet_id.clone());
            let script = address.script_pubkey();
            self.script_index.insert(script, address);
        }
    }

    /// Unregister a wallet's addresses
    pub fn unregister_wallet(&mut self, wallet_id: &WalletId) {
        self.address_index.retain(|_, wid| wid != wallet_id);
        // Also clean up script index
        let addresses_to_remove: Vec<Address> = self
            .address_index
            .iter()
            .filter(|(_, wid)| *wid == wallet_id)
            .map(|(addr, _)| addr.clone())
            .collect();

        for address in addresses_to_remove {
            let script = address.script_pubkey();
            self.script_index.remove(&script);
        }
    }

    /// Process an incoming transaction
    pub fn process_transaction(
        &mut self,
        tx: &Transaction,
        height: Option<u32>,
        timestamp: u64,
    ) -> TransactionProcessResult {
        let txid = tx.txid();
        let mut result = TransactionProcessResult {
            affected_wallets: Vec::new(),
            new_utxos: Vec::new(),
            spent_utxos: Vec::new(),
            balance_changes: BTreeMap::new(),
            is_relevant: false,
        };

        // Check outputs for addresses we control
        for (vout, output) in tx.output.iter().enumerate() {
            if let Some(address) = self.script_index.get(&output.script_pubkey) {
                if let Some(wallet_id) = self.address_index.get(address) {
                    result.is_relevant = true;
                    result.affected_wallets.push(wallet_id.clone());

                    // Create UTXO
                    let outpoint = OutPoint {
                        txid,
                        vout: vout as u32,
                    };

                    let utxo = Utxo::new(
                        outpoint,
                        output.clone(),
                        address.clone(),
                        height.unwrap_or(0),
                        false, // Not coinbase (we should check this properly)
                    );

                    result.new_utxos.push(utxo);

                    // Update balance change
                    *result.balance_changes.entry(wallet_id.clone()).or_insert(0) +=
                        output.value as i64;
                }
            }
        }

        // Check inputs for UTXOs we're spending
        for input in &tx.input {
            // We need to look up the previous output to see if it's ours
            // This requires access to previous transactions or a UTXO set
            // For now, we'll just record the spent outpoint
            result.spent_utxos.push(input.previous_output);
        }

        // Store as pending if unconfirmed
        if height.is_none() && result.is_relevant {
            self.pending_txs.insert(
                txid,
                PendingTransaction {
                    transaction: tx.clone(),
                    first_seen: timestamp,
                    fee: None,      // Calculate if possible
                    is_ours: false, // Determine based on inputs
                },
            );
        }

        result
    }

    /// Confirm a pending transaction
    pub fn confirm_transaction(&mut self, txid: &Txid, _height: u32) -> Option<PendingTransaction> {
        self.pending_txs.remove(txid)
    }

    /// Remove a transaction (due to reorg or expiry)
    pub fn remove_transaction(&mut self, txid: &Txid) -> Option<PendingTransaction> {
        self.pending_txs.remove(txid)
    }

    /// Get all pending transactions
    pub fn pending_transactions(&self) -> &BTreeMap<Txid, PendingTransaction> {
        &self.pending_txs
    }

    /// Check if a script is relevant to any wallet
    pub fn is_script_relevant(&self, script: &ScriptBuf) -> bool {
        self.script_index.contains_key(script)
    }

    /// Get wallet ID for an address
    pub fn get_wallet_for_address(&self, address: &Address) -> Option<&WalletId> {
        self.address_index.get(address)
    }
}

impl AddressTracker {
    /// Create a new address tracker
    pub fn new(gap_limit: u32) -> Self {
        Self {
            used_receive_addresses: BTreeMap::new(),
            used_change_addresses: BTreeMap::new(),
            receive_indices: BTreeMap::new(),
            change_indices: BTreeMap::new(),
            gap_limit,
        }
    }

    /// Mark an address as used
    pub fn mark_address_used(
        &mut self,
        wallet_id: WalletId,
        account_index: u32,
        is_change: bool,
        address_index: u32,
    ) {
        let key = (wallet_id, account_index);

        if is_change {
            self.used_change_addresses.entry(key.clone()).or_default().insert(address_index);

            // Update index if needed
            let current = self.change_indices.entry(key).or_insert(0);
            if address_index >= *current {
                *current = address_index + 1;
            }
        } else {
            self.used_receive_addresses.entry(key.clone()).or_default().insert(address_index);

            // Update index if needed
            let current = self.receive_indices.entry(key).or_insert(0);
            if address_index >= *current {
                *current = address_index + 1;
            }
        }
    }

    /// Get the next receive address index
    pub fn next_receive_index(&self, wallet_id: &WalletId, account_index: u32) -> u32 {
        *self.receive_indices.get(&(wallet_id.clone(), account_index)).unwrap_or(&0)
    }

    /// Get the next change address index
    pub fn next_change_index(&self, wallet_id: &WalletId, account_index: u32) -> u32 {
        *self.change_indices.get(&(wallet_id.clone(), account_index)).unwrap_or(&0)
    }

    /// Check if we need to generate more addresses based on gap limit
    pub fn should_generate_addresses(
        &self,
        wallet_id: &WalletId,
        account_index: u32,
        is_change: bool,
    ) -> bool {
        let key = (wallet_id.clone(), account_index);

        let (used_set, current_index) = if is_change {
            (
                self.used_change_addresses.get(&key),
                self.change_indices.get(&key).copied().unwrap_or(0),
            )
        } else {
            (
                self.used_receive_addresses.get(&key),
                self.receive_indices.get(&key).copied().unwrap_or(0),
            )
        };

        // Find the highest used index
        let highest_used = used_set.and_then(|set| set.iter().max().copied()).unwrap_or(0);

        // Check if we have enough gap
        current_index < highest_used + self.gap_limit
    }

    /// Get unused address indices within the current range
    pub fn get_unused_indices(
        &self,
        wallet_id: &WalletId,
        account_index: u32,
        is_change: bool,
    ) -> Vec<u32> {
        let key = (wallet_id.clone(), account_index);

        let (used_set, current_index) = if is_change {
            (
                self.used_change_addresses.get(&key),
                self.change_indices.get(&key).copied().unwrap_or(0),
            )
        } else {
            (
                self.used_receive_addresses.get(&key),
                self.receive_indices.get(&key).copied().unwrap_or(0),
            )
        };

        let used_set = used_set.cloned().unwrap_or_default();

        (0..current_index).filter(|i| !used_set.contains(i)).collect()
    }
}

/// Transaction matching result
#[derive(Debug, Clone)]
pub struct TransactionMatch {
    /// Transaction ID
    pub txid: Txid,
    /// Matching inputs (our UTXOs being spent)
    pub matching_inputs: Vec<(usize, OutPoint)>,
    /// Matching outputs (new UTXOs for us)
    pub matching_outputs: Vec<(usize, Address, u64)>,
    /// Net value change (positive = receiving, negative = spending)
    pub net_value: i64,
    /// Whether all inputs are ours (likely our own transaction)
    pub is_internal: bool,
}

/// Match a transaction against a set of addresses
pub fn match_transaction(
    tx: &Transaction,
    addresses: &BTreeSet<Address>,
    our_utxos: &UtxoSet,
) -> Option<TransactionMatch> {
    let mut matching_inputs = Vec::new();
    let mut matching_outputs = Vec::new();
    let mut input_value = 0u64;
    let mut output_value = 0u64;

    // Check inputs
    for (idx, input) in tx.input.iter().enumerate() {
        if let Some(utxo) = our_utxos.get(&input.previous_output) {
            matching_inputs.push((idx, input.previous_output));
            input_value += utxo.value();
        }
    }

    // Check outputs
    for (idx, output) in tx.output.iter().enumerate() {
        // Convert to our Address type (this needs proper implementation)
        // For now, check if script matches any of our addresses
        for addr in addresses {
            if addr.script_pubkey() == output.script_pubkey {
                matching_outputs.push((idx, addr.clone(), output.value));
                output_value += output.value;
                break;
            }
        }
    }

    // If no matches, return None
    if matching_inputs.is_empty() && matching_outputs.is_empty() {
        return None;
    }

    let net_value = output_value as i64 - input_value as i64;
    let is_internal = !matching_inputs.is_empty() && matching_inputs.len() == tx.input.len();

    Some(TransactionMatch {
        txid: tx.txid(),
        matching_inputs,
        matching_outputs,
        net_value,
        is_internal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_tracker() {
        let mut tracker = AddressTracker::new(20);
        let wallet_id = [1u8; 32]; // Use byte array for wallet ID

        // Mark some addresses as used
        tracker.mark_address_used(wallet_id, 0, false, 0);
        tracker.mark_address_used(wallet_id, 0, false, 2);
        tracker.mark_address_used(wallet_id, 0, false, 5);

        // Check next index
        assert_eq!(tracker.next_receive_index(&wallet_id, 0), 6);

        // Check unused indices
        let unused = tracker.get_unused_indices(&wallet_id, 0, false);
        assert!(unused.contains(&1));
        assert!(unused.contains(&3));
        assert!(unused.contains(&4));
        assert!(!unused.contains(&0));
        assert!(!unused.contains(&2));
        assert!(!unused.contains(&5));
    }
}
