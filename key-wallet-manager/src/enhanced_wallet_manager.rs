//! Enhanced wallet manager with SPV integration
//!
//! This module extends the basic wallet manager with SPV client integration,
//! compact block filter support, and advanced transaction processing.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use dashcore::blockdata::block::Block;
use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::{Address as DashAddress, BlockHash, Network as DashNetwork, Txid};
use dashcore_hashes::Hash;
use key_wallet::transaction_checking::wallet_checker::WalletTransactionChecker;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::{Address, Network, Wallet};

use crate::compact_filter::{CompactFilter, FilterType};
use crate::utxo::Utxo;
use crate::wallet_manager::{WalletError, WalletId, WalletManager};

/// Enhanced wallet manager with SPV support
pub struct EnhancedWalletManager {
    /// Base wallet manager
    base: WalletManager,
    /// Scripts we're watching for all wallets
    watched_scripts: BTreeSet<ScriptBuf>,
    /// Outpoints we're watching (our UTXOs that might be spent)
    watched_outpoints: BTreeSet<OutPoint>,
    /// Script to wallet mapping for quick lookups
    script_to_wallet: BTreeMap<ScriptBuf, WalletId>,
    /// Outpoint to wallet mapping
    outpoint_to_wallet: BTreeMap<OutPoint, WalletId>,
    /// Current sync height
    sync_height: u32,
    /// Network
    network: Network,
}

impl EnhancedWalletManager {
    /// Create a new enhanced wallet manager
    pub fn new(network: Network) -> Self {
        Self {
            base: WalletManager::new(network),
            watched_scripts: BTreeSet::new(),
            watched_outpoints: BTreeSet::new(),
            script_to_wallet: BTreeMap::new(),
            outpoint_to_wallet: BTreeMap::new(),
            sync_height: 0,
            network,
        }
    }

    /// Add a wallet and start watching its addresses
    pub fn add_wallet(
        &mut self,
        wallet_id: WalletId,
        wallet: Wallet,
        info: ManagedWalletInfo,
    ) -> Result<(), WalletError> {
        // Add to base manager
        self.base.wallets.insert(wallet_id.clone(), wallet);
        self.base.wallet_infos.insert(wallet_id.clone(), info);

        // Update watched scripts for this wallet
        self.update_watched_scripts_for_wallet(&wallet_id)?;

        Ok(())
    }

    /// Update watched scripts for a specific wallet
    pub fn update_watched_scripts_for_wallet(
        &mut self,
        wallet_id: &WalletId,
    ) -> Result<(), WalletError> {
        let info = self
            .base
            .wallet_infos
            .get(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        // Add monitored addresses' scripts
        let monitored_addresses = self.base.get_monitored_addresses(wallet_id);
        for address in monitored_addresses {
            let script = address.script_pubkey();
            self.watched_scripts.insert(script.clone());
            self.script_to_wallet.insert(script, wallet_id.clone());
        }

        // Add UTXO outpoints for watching spends
        // Get UTXOs from our temporary storage since ManagedWalletInfo doesn't store them directly
        let wallet_utxos = self.base.get_wallet_utxos_temp(wallet_id);
        for utxo in wallet_utxos {
            self.watched_outpoints.insert(utxo.outpoint.clone());
            self.outpoint_to_wallet.insert(utxo.outpoint.clone(), wallet_id.clone());
        }

        Ok(())
    }

    /// Add a watched script for a wallet
    pub fn add_watched_script(&mut self, wallet_id: &WalletId, script: ScriptBuf) {
        self.watched_scripts.insert(script.clone());
        self.script_to_wallet.insert(script, wallet_id.clone());
    }

    /// Check if a compact filter matches any of our watched items
    pub fn check_filter(&self, filter: &CompactFilter, block_hash: &BlockHash) -> bool {
        // Get filter key from block hash
        let key = derive_filter_key(block_hash);

        // Check if any of our watched scripts match
        for script in &self.watched_scripts {
            if filter.contains(&script.to_bytes(), &key) {
                return true;
            }
        }

        // Check if any of our watched outpoints match
        for outpoint in &self.watched_outpoints {
            let outpoint_bytes = serialize_outpoint(outpoint);
            if filter.contains(&outpoint_bytes, &key) {
                return true;
            }
        }

        false
    }

    /// Process a block that matched our filter
    pub fn process_block(&mut self, block: &Block, height: u32) -> BlockProcessResult {
        let mut result = BlockProcessResult {
            relevant_transactions: Vec::new(),
            new_utxos: Vec::new(),
            spent_utxos: Vec::new(),
            affected_wallets: BTreeSet::new(),
            balance_changes: BTreeMap::new(),
        };

        let block_hash = block.block_hash();
        let timestamp = block.header.time as u64;

        // Process each transaction in the block
        for tx in &block.txdata {
            let tx_result = self.process_transaction(tx, Some(height), Some(block_hash), timestamp);

            if tx_result.is_relevant {
                result.relevant_transactions.push(tx.clone());
                result.new_utxos.extend(tx_result.new_utxos);
                result.spent_utxos.extend(tx_result.spent_utxos);
                result.affected_wallets.extend(tx_result.affected_wallets);

                // Merge balance changes
                for (wallet_id, change) in tx_result.balance_changes {
                    *result.balance_changes.entry(wallet_id).or_insert(0) += change;
                }
            }
        }

        // Update sync height
        self.sync_height = height;
        self.base.update_height(height);

        result
    }

    /// Process a single transaction
    pub fn process_transaction(
        &mut self,
        tx: &Transaction,
        height: Option<u32>,
        block_hash: Option<BlockHash>,
        timestamp: u64,
    ) -> TransactionProcessResult {
        let mut result = TransactionProcessResult {
            is_relevant: false,
            affected_wallets: Vec::new(),
            new_utxos: Vec::new(),
            spent_utxos: Vec::new(),
            balance_changes: BTreeMap::new(),
        };

        // Check transaction against each wallet
        let wallet_ids: Vec<WalletId> = self.base.wallet_infos.keys().cloned().collect();
        for wallet_id in wallet_ids {
            // Check if any outputs match our watched scripts
            let mut is_wallet_relevant = false;
            let mut wallet_received = 0u64;

            // Check outputs
            for output in &tx.output {
                if self.script_to_wallet.contains_key(&output.script_pubkey) {
                    is_wallet_relevant = true;
                    wallet_received += output.value;
                }
            }

            // Check inputs (for spending detection)
            let mut wallet_spent = 0u64;
            for input in &tx.input {
                if self.outpoint_to_wallet.contains_key(&input.previous_output) {
                    is_wallet_relevant = true;
                    // We'd need to look up the value of the spent UTXO
                    // For now, we'll just mark it as spent
                }
            }

            // If not relevant using simple checks, try the more complex wallet transaction checker
            let wallet_info = match self.base.wallet_infos.get_mut(&wallet_id) {
                Some(info) => info,
                None => continue,
            };
            let check_result = wallet_info.check_transaction(tx, self.network, true);

            // Process inputs for this specific wallet
            for input in &tx.input {
                if let Some(owning_wallet) = self.outpoint_to_wallet.get(&input.previous_output) {
                    if owning_wallet == &wallet_id {
                        is_wallet_relevant = true; // Transaction is relevant if it spends our UTXOs
                        if !result.spent_utxos.contains(&input.previous_output) {
                            result.spent_utxos.push(input.previous_output.clone());
                        }
                    }
                }
            }

            // Consider relevant if either our simple check or the wallet's check says so
            if is_wallet_relevant || check_result.is_relevant {
                result.is_relevant = true;
                result.affected_wallets.push(wallet_id.clone());

                // Process outputs - create UTXOs for outputs that belong to THIS wallet
                for (vout, output) in tx.output.iter().enumerate() {
                    let script = &output.script_pubkey;
                    if let Some(owning_wallet) = self.script_to_wallet.get(script) {
                        if owning_wallet == &wallet_id {
                            // This output belongs to us - create UTXO
                            let outpoint = OutPoint {
                                txid: tx.txid(),
                                vout: vout as u32,
                            };

                            // Try to create an address from the script
                            // For P2PKH scripts, we can extract the address
                            let address = if let Ok(addr) =
                                Address::from_script(&output.script_pubkey, self.network.into())
                            {
                                addr
                            } else {
                                // Fallback to a dummy address if we can't parse the script
                                // This should not happen for standard scripts
                                Address::p2pkh(
                                    &dashcore::PublicKey::from_slice(&[
                                        0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f,
                                        0xe8, 0x3c, 0x1a, 0xf1, 0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53,
                                        0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04, 0x88, 0x7e,
                                        0x5b, 0x23, 0x52,
                                    ])
                                    .unwrap(),
                                    self.network.into(),
                                )
                            };

                            let utxo = Utxo {
                                outpoint: outpoint.clone(),
                                txout: output.clone(),
                                address,
                                height: height.unwrap_or(0),
                                is_coinbase: tx.is_coin_base(),
                                is_confirmed: height.is_some(),
                                is_instantlocked: false,
                                is_locked: false,
                                label: None,
                            };

                            result.new_utxos.push(utxo.clone());

                            // Add UTXO to result
                            // Note: Would need to add to wallet manager outside the loop
                        }
                    }
                }

                // Note: Spent outpoints are removed after processing all wallets

                // Calculate balance change for this wallet
                let received =
                    check_result.affected_accounts.iter().map(|a| a.received).sum::<u64>();
                let sent = check_result.affected_accounts.iter().map(|a| a.sent).sum::<u64>();
                let balance_change = received as i64 - sent as i64;

                result.balance_changes.insert(wallet_id.clone(), balance_change);

                // Add transaction record to wallet
                // Note: ManagedWalletInfo's transaction tracking would be through
                // the accounts, not directly on the info

                // Handle immature transactions (like coinbase)
                if tx.is_coin_base() && height.is_some() {
                    let maturity_confirmations = 100; // Dash coinbase maturity
                    wallet_info.check_immature_transaction(
                        tx,
                        self.network,
                        height.unwrap(),
                        block_hash.unwrap_or(BlockHash::all_zeros()),
                        timestamp,
                        maturity_confirmations,
                    );
                }

                // Update wallet balance
                wallet_info.update_balance();
            }
        }

        // Add new UTXOs to wallet manager
        for utxo in &result.new_utxos {
            // Find which wallet this UTXO belongs to
            if let Some(wallet_id) = self.script_to_wallet.get(&utxo.txout.script_pubkey) {
                let _ = self.base.add_utxo(wallet_id, utxo.clone());
            }
        }

        // Remove spent outpoints from watched sets (do this globally, not per-wallet)
        for spent_outpoint in &result.spent_utxos {
            self.watched_outpoints.remove(spent_outpoint);

            // Find which wallet owned this outpoint and remove from storage
            if let Some(wallet_id) = self.outpoint_to_wallet.remove(spent_outpoint) {
                self.base.remove_spent_utxo(&wallet_id, spent_outpoint);
            }
        }

        // Update watched scripts for affected wallets to add new UTXOs
        // But don't re-add spent ones since we removed them above
        for wallet_id in &result.affected_wallets {
            let _ = self.update_watched_scripts_for_wallet(wallet_id);
        }

        result
    }

    /// Get all watched scripts
    pub fn get_watched_scripts(&self) -> &BTreeSet<ScriptBuf> {
        &self.watched_scripts
    }

    /// Get count of watched scripts
    pub fn watched_scripts_count(&self) -> usize {
        self.watched_scripts.len()
    }

    /// Get count of watched outpoints
    pub fn watched_outpoints_count(&self) -> usize {
        self.watched_outpoints.len()
    }

    /// Get all watched outpoints
    pub fn get_watched_outpoints(&self) -> &BTreeSet<OutPoint> {
        &self.watched_outpoints
    }

    /// Check if we should download a block based on its filter
    pub fn should_download_block(&self, filter: &CompactFilter, block_hash: &BlockHash) -> bool {
        self.check_filter(filter, block_hash)
    }

    /// Get current sync height
    pub fn sync_height(&self) -> u32 {
        self.sync_height
    }

    /// Update sync height
    pub fn update_sync_height(&mut self, height: u32) {
        self.sync_height = height;
        self.base.update_height(height);
    }

    /// Get a reference to the base wallet manager
    pub fn base(&self) -> &WalletManager {
        &self.base
    }

    /// Get a mutable reference to the base wallet manager
    pub fn base_mut(&mut self) -> &mut WalletManager {
        &mut self.base
    }

    /// Get the network
    pub fn network(&self) -> Network {
        self.network
    }
}

/// Result of processing a block
pub struct BlockProcessResult {
    /// Transactions that are relevant to our wallets
    pub relevant_transactions: Vec<Transaction>,
    /// New UTXOs created
    pub new_utxos: Vec<Utxo>,
    /// UTXOs that were spent
    pub spent_utxos: Vec<OutPoint>,
    /// Wallet IDs that were affected
    pub affected_wallets: BTreeSet<WalletId>,
    /// Net balance change per wallet
    pub balance_changes: BTreeMap<WalletId, i64>,
}

/// Result of processing a transaction
pub struct TransactionProcessResult {
    /// Whether this transaction is relevant to any wallet
    pub is_relevant: bool,
    /// Wallet IDs that were affected
    pub affected_wallets: Vec<WalletId>,
    /// New UTXOs created
    pub new_utxos: Vec<Utxo>,
    /// UTXOs that were spent
    pub spent_utxos: Vec<OutPoint>,
    /// Net balance change per wallet
    pub balance_changes: BTreeMap<WalletId, i64>,
}

/// Derive a filter key from a block hash (BIP 158)
fn derive_filter_key(block_hash: &BlockHash) -> [u8; 16] {
    let mut key = [0u8; 16];
    key.copy_from_slice(&block_hash.to_byte_array()[0..16]);
    key
}

/// Serialize an outpoint for filter matching
fn serialize_outpoint(outpoint: &OutPoint) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&outpoint.txid.to_byte_array());
    bytes.extend_from_slice(&outpoint.vout.to_le_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enhanced_manager_creation() {
        let manager = EnhancedWalletManager::new(Network::Testnet);
        assert_eq!(manager.sync_height(), 0);
        assert!(manager.get_watched_scripts().is_empty());
    }
}
