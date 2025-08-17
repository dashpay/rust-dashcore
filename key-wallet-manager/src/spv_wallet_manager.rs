//! SPV Wallet Manager
//!
//! This module provides a comprehensive wallet manager that combines wallet management
//! with SPV client integration. It handles:
//! - Multiple wallet management
//! - Compact block filter checking
//! - Transaction processing and UTXO tracking
//! - SPV synchronization state
//! - Block download queue management

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

use dashcore::blockdata::block::Block;
use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::{BlockHash, Txid};
use key_wallet::{Address, Network};

use crate::compact_filter::CompactFilter;
use crate::wallet_manager::{WalletError, WalletId, WalletManager};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::{Utxo, Wallet};

/// SPV Wallet Manager
///
/// This struct combines wallet management with SPV client integration.
/// It manages multiple wallets, tracks UTXOs, checks compact filters,
/// and handles SPV synchronization state.
pub struct SPVWalletManager {
    /// Base wallet manager
    base: WalletManager,
    /// UTXO cache for quick lookups
    utxo_cache: UtxoCache,
    /// Set of all watched scripts across all wallets
    watched_scripts: BTreeSet<ScriptBuf>,
    /// Set of all watched outpoints
    watched_outpoints: BTreeSet<OutPoint>,
    /// Map from script to wallet ID
    script_to_wallet: BTreeMap<ScriptBuf, WalletId>,
    /// Map from outpoint to wallet ID
    outpoint_to_wallet: BTreeMap<OutPoint, WalletId>,
    /// Current sync height
    sync_height: u32,
    /// Network
    network: Network,

    // SPV-specific fields (from SPVWalletIntegration)
    /// Block download queue
    download_queue: VecDeque<BlockHash>,
    /// Pending blocks waiting for dependencies
    pub(crate) pending_blocks: BTreeMap<u32, (Block, BlockHash)>,
    /// Filter match cache
    filter_matches: BTreeMap<BlockHash, bool>,
    /// Maximum blocks to queue for download
    max_download_queue: usize,
    /// Statistics
    stats: SPVStats,
}

/// UTXO cache for efficient lookups
#[derive(Debug, Clone, Default)]
pub struct UtxoCache {
    /// UTXOs by outpoint
    utxos_by_outpoint: BTreeMap<OutPoint, Utxo>,
    /// UTXOs by address
    utxos_by_address: BTreeMap<Address, Vec<OutPoint>>,
    /// Total balance
    total_balance: u64,
}

impl UtxoCache {
    /// Create a new UTXO cache
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a UTXO to the cache
    pub fn add_utxo(&mut self, utxo: Utxo) {
        let outpoint = utxo.outpoint;
        let address = utxo.address.clone();
        let value = utxo.value();

        // Add to outpoint index
        self.utxos_by_outpoint.insert(outpoint, utxo);

        // Add to address index
        self.utxos_by_address.entry(address).or_insert_with(Vec::new).push(outpoint);

        // Update balance
        self.total_balance += value;
    }

    /// Remove a UTXO from the cache
    pub fn remove_utxo(&mut self, outpoint: &OutPoint) -> Option<Utxo> {
        if let Some(utxo) = self.utxos_by_outpoint.remove(outpoint) {
            // Remove from address index
            if let Some(outpoints) = self.utxos_by_address.get_mut(&utxo.address) {
                outpoints.retain(|op| op != outpoint);
                if outpoints.is_empty() {
                    self.utxos_by_address.remove(&utxo.address);
                }
            }

            // Update balance
            self.total_balance = self.total_balance.saturating_sub(utxo.value());

            Some(utxo)
        } else {
            None
        }
    }

    /// Get a UTXO by outpoint
    pub fn get_utxo(&self, outpoint: &OutPoint) -> Option<&Utxo> {
        self.utxos_by_outpoint.get(outpoint)
    }

    /// Get UTXOs for an address
    pub fn get_utxos_for_address(&self, address: &Address) -> Vec<&Utxo> {
        self.utxos_by_address
            .get(address)
            .map(|outpoints| {
                outpoints.iter().filter_map(|op| self.utxos_by_outpoint.get(op)).collect()
            })
            .unwrap_or_default()
    }

    /// Get all UTXOs
    pub fn get_all_utxos(&self) -> Vec<&Utxo> {
        self.utxos_by_outpoint.values().collect()
    }

    /// Get total balance
    pub fn total_balance(&self) -> u64 {
        self.total_balance
    }

    /// Clear the cache
    pub fn clear(&mut self) {
        self.utxos_by_outpoint.clear();
        self.utxos_by_address.clear();
        self.total_balance = 0;
    }
}

/// SPV synchronization statistics
#[derive(Debug, Clone, Default)]
pub struct SPVStats {
    /// Total filters checked
    pub filters_checked: u64,
    /// Filters that matched
    pub filters_matched: u64,
    /// Blocks downloaded
    pub blocks_downloaded: u64,
    /// Relevant transactions found
    pub transactions_found: u64,
    /// Current sync height
    pub sync_height: u32,
    /// Target height
    pub target_height: u32,
}

/// SPV sync status
#[derive(Debug, Clone, PartialEq)]
pub enum SPVSyncStatus {
    /// Not syncing
    Idle,
    /// Checking filters
    CheckingFilters {
        current: u32,
        target: u32,
    },
    /// Downloading blocks
    DownloadingBlocks {
        pending: usize,
    },
    /// Processing blocks
    ProcessingBlocks,
    /// Synced
    Synced,
    /// Error occurred
    Error(String),
}

/// Result of processing a block
#[derive(Debug, Clone)]
pub struct BlockProcessResult {
    /// Transactions relevant to our wallets
    pub relevant_transactions: Vec<Transaction>,
    /// Number of new UTXOs added
    pub utxos_added: usize,
    /// Number of UTXOs spent
    pub utxos_spent: usize,
    /// Total value received
    pub value_received: u64,
    /// Total value spent
    pub value_spent: u64,
}

/// Result of processing a transaction
#[derive(Debug, Clone)]
pub struct TransactionProcessResult {
    /// Whether the transaction is relevant to any wallet
    pub is_relevant: bool,
    /// Wallets affected by this transaction
    pub affected_wallets: Vec<WalletId>,
    /// Number of inputs from our wallets
    pub inputs_from_wallets: usize,
    /// Number of outputs to our wallets
    pub outputs_to_wallets: usize,
    /// Total value sent (from our wallets)
    pub value_sent: u64,
    /// Total value received (to our wallets)
    pub value_received: u64,
}

impl SPVWalletManager {
    /// Create a new SPV wallet manager
    pub fn new(network: Network) -> Self {
        Self {
            base: WalletManager::new(network),
            utxo_cache: UtxoCache::new(),
            watched_scripts: BTreeSet::new(),
            watched_outpoints: BTreeSet::new(),
            script_to_wallet: BTreeMap::new(),
            outpoint_to_wallet: BTreeMap::new(),
            sync_height: 0,
            network,
            download_queue: VecDeque::new(),
            pending_blocks: BTreeMap::new(),
            filter_matches: BTreeMap::new(),
            max_download_queue: 100,
            stats: SPVStats::default(),
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
        let _info = self
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

        // Add wallet's own addresses
        let wallet = self
            .base
            .wallets
            .get(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.clone()))?;

        // Add receiving addresses (default gap limit of 20)
        let gap_limit = 20u32;

        // Get the first account (account 0) for the wallet's network
        if let Some(collection) = wallet.accounts.get(&self.network) {
            if let Some(account) = collection.standard_bip44_accounts.get(&0) {
                use dashcore::secp256k1::Secp256k1;
                use key_wallet::{ChildNumber, DerivationPath};

                let secp = Secp256k1::new();
                let account_xpub = account.extended_public_key();

                // Add receiving addresses (m/0/i)
                for i in 0..gap_limit {
                    let path = DerivationPath::from(vec![
                        ChildNumber::from_normal_idx(0).unwrap(), // receiving
                        ChildNumber::from_normal_idx(i).unwrap(),
                    ]);

                    if let Ok(address_xpub) = account_xpub.derive_pub(&secp, &path) {
                        let pubkey =
                            dashcore::PublicKey::from_slice(&address_xpub.public_key.serialize())
                                .unwrap();
                        let address = Address::p2pkh(&pubkey, self.network);
                        let script = address.script_pubkey();
                        self.watched_scripts.insert(script.clone());
                        self.script_to_wallet.insert(script, wallet_id.clone());
                    }
                }

                // Add change addresses (m/1/i)
                for i in 0..gap_limit {
                    let path = DerivationPath::from(vec![
                        ChildNumber::from_normal_idx(1).unwrap(), // change
                        ChildNumber::from_normal_idx(i).unwrap(),
                    ]);

                    if let Ok(address_xpub) = account_xpub.derive_pub(&secp, &path) {
                        let pubkey =
                            dashcore::PublicKey::from_slice(&address_xpub.public_key.serialize())
                                .unwrap();
                        let address = Address::p2pkh(&pubkey, self.network);
                        let script = address.script_pubkey();
                        self.watched_scripts.insert(script.clone());
                        self.script_to_wallet.insert(script, wallet_id.clone());
                    }
                }
            }
        }

        Ok(())
    }

    /// Get all watched scripts
    pub fn get_watched_scripts(&self) -> &BTreeSet<ScriptBuf> {
        &self.watched_scripts
    }

    /// Get all watched outpoints
    pub fn get_watched_outpoints(&self) -> &BTreeSet<OutPoint> {
        &self.watched_outpoints
    }

    /// Check if we should download a block based on its compact filter
    pub fn should_download_block(&self, filter: &CompactFilter, _block_hash: &BlockHash) -> bool {
        // Collect all scripts to check
        let mut scripts_to_check: Vec<ScriptBuf> = self.watched_scripts.iter().cloned().collect();

        // Add scripts from watched UTXOs
        for outpoint in &self.watched_outpoints {
            if let Some(utxo) = self.utxo_cache.get_utxo(outpoint) {
                scripts_to_check.push(utxo.address.script_pubkey());
            }
        }

        // Check if any scripts match
        if scripts_to_check.is_empty() {
            return false;
        }

        filter.match_any_script(&scripts_to_check)
    }

    /// Process a block and extract relevant transactions
    pub fn process_block(&mut self, block: &Block, height: u32) -> BlockProcessResult {
        let mut result = BlockProcessResult {
            relevant_transactions: Vec::new(),
            utxos_added: 0,
            utxos_spent: 0,
            value_received: 0,
            value_spent: 0,
        };

        // Process each transaction in the block
        for tx in &block.txdata {
            let tx_result = self.process_transaction(
                tx,
                Some(height),
                Some(block.block_hash()),
                block.header.time as u64,
            );

            if tx_result.is_relevant {
                result.relevant_transactions.push(tx.clone());
                result.utxos_added += tx_result.outputs_to_wallets;
                result.utxos_spent += tx_result.inputs_from_wallets;
                result.value_received += tx_result.value_received;
                result.value_spent += tx_result.value_sent;
            }
        }

        // Update sync height
        self.sync_height = height;

        result
    }

    /// Process a transaction and update wallet state
    pub fn process_transaction(
        &mut self,
        tx: &Transaction,
        height: Option<u32>,
        _block_hash: Option<BlockHash>,
        _timestamp: u64,
    ) -> TransactionProcessResult {
        let mut result = TransactionProcessResult {
            is_relevant: false,
            affected_wallets: Vec::new(),
            inputs_from_wallets: 0,
            outputs_to_wallets: 0,
            value_sent: 0,
            value_received: 0,
        };

        let txid = tx.txid();

        // Check inputs - are we spending any of our UTXOs?
        for input in &tx.input {
            let outpoint = input.previous_output;
            if let Some(utxo) = self.utxo_cache.remove_utxo(&outpoint) {
                result.is_relevant = true;
                result.inputs_from_wallets += 1;
                result.value_sent += utxo.value();

                // Find which wallet this belongs to
                if let Some(wallet_id) = self.outpoint_to_wallet.remove(&outpoint) {
                    if !result.affected_wallets.contains(&wallet_id) {
                        result.affected_wallets.push(wallet_id.clone());
                    }

                    // TODO: Track transaction history separately
                    // ManagedWalletInfo doesn't have a simple transaction history field
                }

                // Remove from watched outpoints
                self.watched_outpoints.remove(&outpoint);
            }
        }

        // Check outputs - are we receiving any funds?
        for (vout, output) in tx.output.iter().enumerate() {
            let script = &output.script_pubkey;

            // Check if this output is for one of our watched scripts
            if let Some(wallet_id) = self.script_to_wallet.get(script) {
                result.is_relevant = true;
                result.outputs_to_wallets += 1;
                result.value_received += output.value;

                if !result.affected_wallets.contains(wallet_id) {
                    result.affected_wallets.push(wallet_id.clone());
                }

                // Create UTXO
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };

                // Try to get address from script
                if let Ok(address) = Address::from_script(script, self.network) {
                    let utxo = Utxo::new(
                        outpoint,
                        output.clone(),
                        address.clone(),
                        height.unwrap_or(0),
                        false, // is_coinbase - we could check this from tx.input[0]
                    );

                    // Add to cache
                    self.utxo_cache.add_utxo(utxo.clone());

                    // Add to watched outpoints
                    self.watched_outpoints.insert(outpoint);
                    self.outpoint_to_wallet.insert(outpoint, wallet_id.clone());

                    // Update balance in wallet info
                    if let Some(info) = self.base.wallet_infos.get_mut(wallet_id) {
                        // Update balance - add to unconfirmed if height is None, confirmed otherwise
                        if height.is_some() {
                            info.balance.confirmed += output.value;
                        } else {
                            info.balance.unconfirmed += output.value;
                        }

                        // TODO: Track transaction history separately
                        // ManagedWalletInfo doesn't have a simple transaction history field
                    }
                }
            }
        }

        result
    }

    /// Update sync height
    pub fn update_sync_height(&mut self, height: u32) {
        self.sync_height = height;
    }

    /// Get current sync height
    pub fn get_sync_height(&self) -> u32 {
        self.sync_height
    }

    /// Get wallet balance
    pub fn get_wallet_balance(&self, wallet_id: &WalletId) -> u64 {
        self.base.wallet_infos.get(wallet_id).map(|info| info.balance.confirmed).unwrap_or(0)
    }

    /// Get all UTXOs for a wallet
    pub fn get_wallet_utxos(&self, wallet_id: &WalletId) -> Vec<&Utxo> {
        let mut utxos = Vec::new();

        // Get all UTXOs that belong to this wallet
        for (outpoint, utxo) in &self.utxo_cache.utxos_by_outpoint {
            if let Some(owner_wallet) = self.outpoint_to_wallet.get(outpoint) {
                if owner_wallet == wallet_id {
                    utxos.push(utxo);
                }
            }
        }

        utxos
    }

    /// Get total balance across all wallets
    pub fn get_total_balance(&self) -> u64 {
        self.utxo_cache.total_balance()
    }

    // SPV-specific methods (from SPVWalletIntegration)

    /// Check if a compact filter matches our wallets
    ///
    /// This is the main entry point for the SPV client to check filters.
    /// Returns true if the block should be downloaded.
    pub fn check_filter(&mut self, filter: &CompactFilter, block_hash: &BlockHash) -> bool {
        self.stats.filters_checked += 1;

        let matches = self.should_download_block(filter, block_hash);

        if matches {
            self.stats.filters_matched += 1;
            self.filter_matches.insert(*block_hash, true);

            // Add to download queue if not already there
            if !self.download_queue.contains(block_hash)
                && self.download_queue.len() < self.max_download_queue
            {
                self.download_queue.push_back(*block_hash);
            }
        } else {
            self.filter_matches.insert(*block_hash, false);
        }

        matches
    }

    /// Process a downloaded block (SPV interface)
    ///
    /// This should be called by the SPV client when a block has been downloaded.
    pub fn process_spv_block(&mut self, block: Block, height: u32) -> BlockProcessResult {
        self.stats.blocks_downloaded += 1;

        // Remove from download queue if present
        let block_hash = block.block_hash();
        self.download_queue.retain(|h| h != &block_hash);

        // Process the block
        let result = self.process_block(&block, height);

        // Update statistics
        self.stats.transactions_found += result.relevant_transactions.len() as u64;
        self.stats.sync_height = height;

        // Clear filter match cache for this block
        self.filter_matches.remove(&block_hash);

        result
    }

    /// Process a mempool transaction
    ///
    /// This can be called for unconfirmed transactions from the mempool.
    pub fn process_mempool_transaction(&mut self, tx: &Transaction) -> TransactionProcessResult {
        let timestamp = current_timestamp();
        self.process_transaction(tx, None, None, timestamp)
    }

    /// Queue a block for processing later
    ///
    /// This is useful when blocks arrive out of order.
    pub fn queue_block(&mut self, block: Block, height: u32) {
        let block_hash = block.block_hash();
        self.pending_blocks.insert(height, (block, block_hash));
    }

    /// Process any queued blocks that are now ready
    pub fn process_queued_blocks(&mut self, current_height: u32) -> Vec<BlockProcessResult> {
        let mut results = Vec::new();

        // Process all blocks up to current height
        let heights_to_process: Vec<u32> =
            self.pending_blocks.keys().filter(|&&h| h <= current_height).cloned().collect();

        for height in heights_to_process {
            if let Some((block, _hash)) = self.pending_blocks.remove(&height) {
                let result = self.process_spv_block(block, height);
                results.push(result);
            }
        }

        results
    }

    /// Get blocks that need to be downloaded
    pub fn get_download_queue(&self) -> Vec<BlockHash> {
        self.download_queue.iter().cloned().collect()
    }

    /// Clear the download queue
    pub fn clear_download_queue(&mut self) {
        self.download_queue.clear()
    }

    /// Get current sync status
    pub fn sync_status(&self) -> SPVSyncStatus {
        if self.stats.sync_height >= self.stats.target_height && self.stats.target_height > 0 {
            SPVSyncStatus::Synced
        } else if !self.download_queue.is_empty() {
            SPVSyncStatus::DownloadingBlocks {
                pending: self.download_queue.len(),
            }
        } else if self.stats.sync_height < self.stats.target_height {
            SPVSyncStatus::CheckingFilters {
                current: self.stats.sync_height,
                target: self.stats.target_height,
            }
        } else {
            SPVSyncStatus::Idle
        }
    }

    /// Set target sync height
    pub fn set_target_height(&mut self, height: u32) {
        self.stats.target_height = height;
    }

    /// Get sync statistics
    pub fn stats(&self) -> &SPVStats {
        &self.stats
    }

    /// Reset sync statistics
    pub fn reset_stats(&mut self) {
        self.stats = SPVStats::default();
    }

    /// Handle a reorg by rolling back to a specific height
    pub fn handle_reorg(&mut self, rollback_height: u32) -> Result<(), WalletError> {
        // Clear any pending blocks above rollback height
        self.pending_blocks.retain(|&height, _| height <= rollback_height);

        // Clear download queue as it may contain invalidated blocks
        self.download_queue.clear();

        // Update sync height
        self.stats.sync_height = rollback_height;
        self.update_sync_height(rollback_height);

        // TODO: Rollback wallet state (remove transactions above rollback height)
        // This would require tracking transaction heights in wallet info

        Ok(())
    }

    /// Check if we're synced
    pub fn is_synced(&self) -> bool {
        self.stats.sync_height >= self.stats.target_height && self.stats.target_height > 0
    }

    /// Get sync progress as a percentage
    pub fn sync_progress(&self) -> f32 {
        if self.stats.target_height == 0 {
            return 0.0;
        }
        (self.stats.sync_height as f32 / self.stats.target_height as f32) * 100.0
    }

    /// Set maximum download queue size
    pub fn set_max_download_queue(&mut self, max: usize) {
        self.max_download_queue = max;
    }

    /// Get pending blocks count
    pub fn pending_blocks_count(&self) -> usize {
        self.pending_blocks.len()
    }

    /// Check if a block height is pending
    pub fn has_pending_block(&self, height: u32) -> bool {
        self.pending_blocks.contains_key(&height)
    }

    /// Get download queue size
    pub fn download_queue_size(&self) -> usize {
        self.download_queue.len()
    }

    /// Check if download queue is empty
    pub fn is_download_queue_empty(&self) -> bool {
        self.download_queue.is_empty()
    }
}

/// Helper function for getting current timestamp
fn current_timestamp() -> u64 {
    #[cfg(feature = "std")]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    #[cfg(not(feature = "std"))]
    {
        0 // In no_std environment, timestamp would need to be provided externally
    }
}

// Implementation of WalletInterface for SPVWalletManager
#[cfg(feature = "std")]
#[async_trait::async_trait]
impl crate::wallet_interface::WalletInterface for SPVWalletManager {
    /// Process a block and return relevant transaction IDs
    async fn process_block(&mut self, block: &Block, height: u32) -> Vec<Txid> {
        let result = self.process_spv_block(block.clone(), height);
        result.relevant_transactions.iter().map(|tx| tx.txid()).collect()
    }

    /// Process a mempool transaction
    async fn process_mempool_transaction(&mut self, tx: &Transaction) {
        self.process_mempool_transaction(tx);
    }

    /// Handle a reorg by rolling back to a specific height
    async fn handle_reorg(&mut self, from_height: u32, to_height: u32) {
        // Roll back from from_height to to_height
        if let Err(e) = self.handle_reorg(to_height) {
            // Log error but don't panic
            // In production, you'd want proper error handling here
            eprintln!("Error handling reorg from {} to {}: {:?}", from_height, to_height, e);
        }
    }

    /// Check if a compact filter matches any watched items
    async fn check_compact_filter(
        &self,
        filter_data: &[u8],
        block_hash: &dashcore::BlockHash,
    ) -> bool {
        use dashcore::bip158::BlockFilter;

        // Get all watched scripts
        let scripts = self.get_watched_scripts();
        if scripts.is_empty() {
            return false;
        }

        // Create a BlockFilter from the raw data
        let filter = BlockFilter::new(filter_data);

        // Check if any of our watched scripts match the filter
        // The match_any method takes an iterator of byte slices
        match filter.match_any(block_hash, scripts.iter().map(|s| s.as_bytes())) {
            Ok(matches) => matches,
            Err(e) => {
                // Log error and return false if matching fails
                eprintln!("Failed to match compact filter: {:?}", e);
                false
            }
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spv_wallet_manager_creation() {
        let manager = SPVWalletManager::new(Network::Testnet);
        assert_eq!(manager.sync_status(), SPVSyncStatus::Idle);
        assert_eq!(manager.sync_progress(), 0.0);
    }

    #[test]
    fn test_sync_progress() {
        let mut manager = SPVWalletManager::new(Network::Testnet);
        manager.set_target_height(1000);
        manager.stats.sync_height = 500;
        assert_eq!(manager.sync_progress(), 50.0);
    }

    #[test]
    fn test_sync_status_transitions() {
        let mut manager = SPVWalletManager::new(Network::Testnet);

        // Initially idle
        assert_eq!(manager.sync_status(), SPVSyncStatus::Idle);

        // Set target height - now checking filters
        manager.set_target_height(100);
        assert_eq!(
            manager.sync_status(),
            SPVSyncStatus::CheckingFilters {
                current: 0,
                target: 100
            }
        );

        // Add to download queue - now downloading
        manager.download_queue.push_back(BlockHash::from_byte_array([0u8; 32]));
        assert_eq!(
            manager.sync_status(),
            SPVSyncStatus::DownloadingBlocks {
                pending: 1
            }
        );

        // Clear queue and sync to target - now synced
        manager.download_queue.clear();
        manager.stats.sync_height = 100;
        assert_eq!(manager.sync_status(), SPVSyncStatus::Synced);
        assert!(manager.is_synced());
    }
}
