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
use alloc::string::{String, ToString};
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
/// and handles SPV synchronization state. It is network-agnostic and can
/// manage wallets across multiple networks simultaneously.
#[derive(Debug)]
pub struct SPVWalletManager {
    /// Base wallet manager
    base: WalletManager,
    /// UTXO cache for quick lookups (per network)
    utxo_cache: BTreeMap<Network, UtxoCache>,
    /// Set of all watched scripts across all wallets (per network)
    watched_scripts: BTreeMap<Network, BTreeSet<ScriptBuf>>,
    /// Set of all watched outpoints (per network)
    watched_outpoints: BTreeMap<Network, BTreeSet<OutPoint>>,
    /// Map from script to wallet ID (per network)
    script_to_wallet: BTreeMap<Network, BTreeMap<ScriptBuf, WalletId>>,
    /// Map from outpoint to wallet ID (per network)
    outpoint_to_wallet: BTreeMap<Network, BTreeMap<OutPoint, WalletId>>,
    /// Current sync height (per network)
    sync_heights: BTreeMap<Network, u32>,

    // SPV-specific fields (from SPVWalletIntegration)
    /// Block download queue (per network)
    download_queues: BTreeMap<Network, VecDeque<BlockHash>>,
    /// Pending blocks waiting for dependencies (per network)
    pub(crate) pending_blocks: BTreeMap<Network, BTreeMap<u32, (Block, BlockHash)>>,
    /// Filter match cache (per network)
    filter_matches: BTreeMap<Network, BTreeMap<BlockHash, bool>>,
    /// Maximum blocks to queue for download
    max_download_queue: usize,
    /// Statistics (per network)
    stats: BTreeMap<Network, SPVStats>,
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
    pub fn new() -> Self {
        Self {
            base: WalletManager::new(),
            utxo_cache: BTreeMap::new(),
            watched_scripts: BTreeMap::new(),
            watched_outpoints: BTreeMap::new(),
            script_to_wallet: BTreeMap::new(),
            outpoint_to_wallet: BTreeMap::new(),
            sync_heights: BTreeMap::new(),
            download_queues: BTreeMap::new(),
            pending_blocks: BTreeMap::new(),
            filter_matches: BTreeMap::new(),
            max_download_queue: 100,
            stats: BTreeMap::new(),
        }
    }

    /// Add a new wallet to the manager
    ///
    /// This method takes a newly created wallet and adds it to the manager.
    /// The wallet ID is derived from the wallet itself.
    pub fn add_new_wallet(
        &mut self,
        wallet: Wallet,
        birth_height: Option<u32>,
    ) -> Result<(), WalletError> {
        // Create managed wallet info
        let mut info = ManagedWalletInfo::from_wallet(&wallet);
        info.metadata.birth_height = birth_height;

        // Add to manager using the internal add_wallet method
        self.add_wallet(wallet, info)
    }

    /// Add an existing wallet to the manager
    ///
    /// This method takes an existing wallet (restored from backup) and adds it to the manager.
    /// The wallet ID is derived from the wallet itself.
    pub fn add_existing_wallet(
        &mut self,
        wallet: Wallet,
        name: String,
        birth_height: Option<u32>,
    ) -> Result<(), WalletError> {
        // Get wallet ID from the wallet itself
        let wallet_id = wallet.wallet_id;

        // Create managed wallet info
        let mut info = ManagedWalletInfo::with_name(wallet.wallet_id, name);
        info.metadata.birth_height = birth_height;

        // For existing wallets, we might want to mark them as restored
        info.metadata.first_loaded_at = current_timestamp();

        // Add to manager using the internal add_wallet method
        self.add_wallet(wallet, info)
    }

    /// Add a wallet and start watching its addresses (internal method)
    ///
    /// This is the base method used by both add_new_wallet and add_existing_wallet.
    /// You can also use this directly if you've already created a Wallet instance.
    pub fn add_wallet(
        &mut self,
        wallet: Wallet,
        info: ManagedWalletInfo,
    ) -> Result<(), WalletError> {
        let wallet_id = wallet.wallet_id;
        // Add to base manager
        self.base.wallets.insert(wallet_id, wallet);
        self.base.wallet_infos.insert(wallet_id, info);

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
            .ok_or_else(|| WalletError::WalletNotFound(*wallet_id))?;

        // Add monitored addresses' scripts for all networks
        // We need to iterate over all networks since we don't know which one is needed
        for network in &[
            Network::Mainnet,
            Network::Testnet,
            Network::Regtest,
            Network::Devnet,
            Network::Evonet,
        ] {
            // Get monitored addresses for this specific wallet and network
            if let Some(info) = self.base.wallet_infos.get(wallet_id) {
                let monitored_addresses = info.monitored_addresses(*network);
                for address in monitored_addresses {
                    let script = address.script_pubkey();
                    self.watched_scripts
                        .entry(*network)
                        .or_insert_with(BTreeSet::new)
                        .insert(script.clone());
                    self.script_to_wallet
                        .entry(*network)
                        .or_insert_with(BTreeMap::new)
                        .insert(script, *wallet_id);
                }
            }
        }

        // Add wallet's own addresses
        let wallet = self
            .base
            .wallets
            .get(wallet_id)
            .ok_or_else(|| WalletError::WalletNotFound(*wallet_id))?;

        // Add receiving addresses (default gap limit of 20)
        let gap_limit = 20u32;

        // Iterate over all networks in the wallet
        for (network, collection) in &wallet.accounts {
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
                        let address = Address::p2pkh(&pubkey, *network);
                        let script = address.script_pubkey();
                        self.watched_scripts
                            .entry(*network)
                            .or_insert_with(BTreeSet::new)
                            .insert(script.clone());
                        self.script_to_wallet
                            .entry(*network)
                            .or_insert_with(BTreeMap::new)
                            .insert(script, *wallet_id);
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
                        let address = Address::p2pkh(&pubkey, *network);
                        let script = address.script_pubkey();
                        self.watched_scripts
                            .entry(*network)
                            .or_insert_with(BTreeSet::new)
                            .insert(script.clone());
                        self.script_to_wallet
                            .entry(*network)
                            .or_insert_with(BTreeMap::new)
                            .insert(script, *wallet_id);
                    }
                }
            }
        }

        Ok(())
    }

    /// Get all watched scripts for a specific network
    pub fn get_watched_scripts(&self, network: Network) -> Option<&BTreeSet<ScriptBuf>> {
        self.watched_scripts.get(&network)
    }

    /// Get all watched outpoints for a specific network
    pub fn get_watched_outpoints(&self, network: Network) -> Option<&BTreeSet<OutPoint>> {
        self.watched_outpoints.get(&network)
    }

    /// Check if we should download a block based on its compact filter
    pub fn should_download_block(
        &self,
        filter: &CompactFilter,
        _block_hash: &BlockHash,
        network: Network,
    ) -> bool {
        // Collect all scripts to check for this network
        let mut scripts_to_check: Vec<ScriptBuf> = Vec::new();

        if let Some(watched_scripts) = self.watched_scripts.get(&network) {
            scripts_to_check.extend(watched_scripts.iter().cloned());
        }

        // Add scripts from watched UTXOs for this network
        if let Some(watched_outpoints) = self.watched_outpoints.get(&network) {
            if let Some(network_cache) = self.utxo_cache.get(&network) {
                for outpoint in watched_outpoints {
                    if let Some(utxo) = network_cache.get_utxo(outpoint) {
                        scripts_to_check.push(utxo.address.script_pubkey());
                    }
                }
            }
        }

        // Check if any scripts match
        if scripts_to_check.is_empty() {
            return false;
        }

        filter.match_any_script(&scripts_to_check)
    }

    /// Process a block and extract relevant transactions
    pub fn process_block(
        &mut self,
        block: &Block,
        height: u32,
        network: Network,
    ) -> BlockProcessResult {
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
                network,
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
        self.update_sync_height(network, height);

        result
    }

    /// Process a transaction and update wallet state
    pub fn process_transaction(
        &mut self,
        tx: &Transaction,
        network: Network,
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
            let utxo =
                self.utxo_cache.get_mut(&network).and_then(|cache| cache.remove_utxo(&outpoint));
            if let Some(utxo) = utxo {
                result.is_relevant = true;
                result.inputs_from_wallets += 1;
                result.value_sent += utxo.value();

                // Find which wallet this belongs to
                if let Some(network_map) = self.outpoint_to_wallet.get_mut(&network) {
                    if let Some(wallet_id) = network_map.remove(&outpoint) {
                        if !result.affected_wallets.contains(&wallet_id) {
                            result.affected_wallets.push(wallet_id);
                        }
                    }
                    // TODO: Track transaction history separately
                    // ManagedWalletInfo doesn't have a simple transaction history field
                }

                // Remove from watched outpoints
                if let Some(network_outpoints) = self.watched_outpoints.get_mut(&network) {
                    network_outpoints.remove(&outpoint);
                }
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
                    result.affected_wallets.push(*wallet_id);
                }

                // Create UTXO
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };

                // Try to get address from script
                if let Ok(address) = Address::from_script(script, dashcore::Network::from(network))
                {
                    let utxo = Utxo::new(
                        outpoint,
                        output.clone(),
                        address.clone(),
                        height.unwrap_or(0),
                        false, // is_coinbase - we could check this from tx.input[0]
                    );

                    // Add to cache
                    self.utxo_cache
                        .entry(network)
                        .or_insert_with(UtxoCache::new)
                        .add_utxo(utxo.clone());

                    // Add to watched outpoints
                    self.watched_outpoints
                        .entry(network)
                        .or_insert_with(BTreeSet::new)
                        .insert(outpoint);
                    self.outpoint_to_wallet
                        .entry(network)
                        .or_insert_with(BTreeMap::new)
                        .insert(outpoint, *wallet_id);

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

    /// Update sync height for a specific network
    pub fn update_sync_height(&mut self, network: Network, height: u32) {
        self.sync_heights.insert(network, height);
    }

    /// Get current sync height for a specific network
    pub fn sync_height(&self, network: Network) -> u32 {
        self.sync_heights.get(&network).copied().unwrap_or(0)
    }

    /// Get wallet balance
    pub fn wallet_balance(&self, wallet_id: &WalletId) -> u64 {
        self.base.wallet_infos.get(wallet_id).map(|info| info.balance.confirmed).unwrap_or(0)
    }

    pub fn wallet_count(&self) -> usize {
        self.base.wallet_count()
    }

    /// Get all UTXOs for a wallet across all networks
    pub fn wallet_utxos(&self, wallet_id: &WalletId) -> Vec<&Utxo> {
        let mut utxos = Vec::new();

        // Get all UTXOs that belong to this wallet from all networks
        for (network, cache) in &self.utxo_cache {
            // Get the outpoint_to_wallet map for this network
            if let Some(outpoint_map) = self.outpoint_to_wallet.get(network) {
                // Iterate through all UTXOs in this network's cache
                for utxo in cache.get_all_utxos() {
                    if let Some(owner_wallet) = outpoint_map.get(&utxo.outpoint) {
                        if owner_wallet == wallet_id {
                            utxos.push(utxo);
                        }
                    }
                }
            }
        }

        utxos
    }

    /// Get total balance across all wallets and networks
    pub fn total_balance(&self) -> u64 {
        self.utxo_cache.values().map(|cache| cache.total_balance()).sum()
    }

    // SPV-specific methods (from SPVWalletIntegration)

    /// Check if a compact filter matches our wallets
    ///
    /// This is the main entry point for the SPV client to check filters.
    /// Returns true if the block should be downloaded.
    pub fn check_filter(
        &mut self,
        filter: &CompactFilter,
        block_hash: &BlockHash,
        network: Network,
    ) -> bool {
        if let Some(stats) = self.stats.get_mut(&network) {
            stats.filters_checked += 1;
        }

        let matches = self.should_download_block(filter, block_hash, network);

        if matches {
            if let Some(stats) = self.stats.get_mut(&network) {
                stats.filters_matched += 1;
            }
            self.filter_matches
                .entry(network)
                .or_insert_with(BTreeMap::new)
                .insert(*block_hash, true);

            // Add to download queue if not already there
            let download_queue = self.download_queues.entry(network).or_insert_with(VecDeque::new);

            if !download_queue.contains(block_hash)
                && download_queue.len() < self.max_download_queue
            {
                download_queue.push_back(*block_hash);
            }
        } else {
            self.filter_matches
                .entry(network)
                .or_insert_with(BTreeMap::new)
                .insert(*block_hash, false);
        }

        matches
    }

    /// Process a downloaded block (SPV interface)
    ///
    /// This should be called by the SPV client when a block has been downloaded.
    pub fn process_spv_block(
        &mut self,
        block: Block,
        height: u32,
        network: Network,
    ) -> BlockProcessResult {
        if let Some(stats) = self.stats.get_mut(&network) {
            stats.blocks_downloaded += 1;
        }

        // Remove from download queue if present
        let block_hash = block.block_hash();
        if let Some(download_queue) = self.download_queues.get_mut(&network) {
            download_queue.retain(|h| h != &block_hash);
        }

        // Process the block
        let result = self.process_block(&block, height, network);

        // Update statistics
        if let Some(stats) = self.stats.get_mut(&network) {
            stats.transactions_found += result.relevant_transactions.len() as u64;
            stats.sync_height = height;
        }

        // Clear filter match cache for this block
        if let Some(filter_matches) = self.filter_matches.get_mut(&network) {
            filter_matches.remove(&block_hash);
        }

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

    /// Get blocks that need to be downloaded for a specific network
    pub fn get_download_queue(&self, network: Network) -> Vec<BlockHash> {
        self.download_queues
            .get(&network)
            .map(|queue| queue.iter().cloned().collect())
            .unwrap_or_else(Vec::new)
    }

    /// Clear the download queue for a specific network
    pub fn clear_download_queue(&mut self, network: Network) {
        if let Some(queue) = self.download_queues.get_mut(&network) {
            queue.clear();
        }
    }

    /// Get current sync status for a specific network
    pub fn sync_status(&self, network: Network) -> SPVSyncStatus {
        let stats = match self.stats.get(&network) {
            Some(s) => s,
            None => return SPVSyncStatus::Idle,
        };

        if stats.sync_height >= stats.target_height && stats.target_height > 0 {
            SPVSyncStatus::Synced
        } else if let Some(queue) = self.download_queues.get(&network) {
            if !queue.is_empty() {
                SPVSyncStatus::DownloadingBlocks {
                    pending: queue.len(),
                }
            } else if stats.sync_height < stats.target_height {
                SPVSyncStatus::CheckingFilters {
                    current: stats.sync_height,
                    target: stats.target_height,
                }
            } else {
                SPVSyncStatus::Idle
            }
        } else {
            SPVSyncStatus::Idle
        }
    }

    /// Set target sync height for a specific network
    pub fn set_target_height(&mut self, network: Network, height: u32) {
        self.stats.entry(network).or_insert_with(SPVStats::default).target_height = height;
    }

    /// Get sync statistics for a specific network
    pub fn stats(&self, network: Network) -> Option<&SPVStats> {
        self.stats.get(&network)
    }

    /// Reset sync statistics for a specific network
    pub fn reset_stats(&mut self, network: Network) {
        if let Some(stats) = self.stats.get_mut(&network) {
            *stats = SPVStats::default();
        }
    }

    /// Handle a reorg by rolling back to a specific height
    pub fn handle_reorg(
        &mut self,
        rollback_height: u32,
        network: Network,
    ) -> Result<(), WalletError> {
        // Clear any pending blocks above rollback height for this network
        if let Some(pending) = self.pending_blocks.get_mut(&network) {
            pending.retain(|&height, _| height <= rollback_height);
        }

        // Clear download queue as it may contain invalidated blocks
        if let Some(queue) = self.download_queues.get_mut(&network) {
            queue.clear();
        }

        // Update sync height
        if let Some(stats) = self.stats.get_mut(&network) {
            stats.sync_height = rollback_height;
        }
        self.update_sync_height(network, rollback_height);

        // TODO: Rollback wallet state (remove transactions above rollback height)
        // This would require tracking transaction heights in wallet info

        Ok(())
    }

    /// Check if we're synced for a specific network
    pub fn is_synced(&self, network: Network) -> bool {
        match self.stats.get(&network) {
            Some(stats) => stats.sync_height >= stats.target_height && stats.target_height > 0,
            None => false,
        }
    }

    /// Get sync progress as a percentage for a specific network
    pub fn sync_progress(&self, network: Network) -> f32 {
        match self.stats.get(&network) {
            Some(stats) => {
                if stats.target_height == 0 {
                    return 0.0;
                }
                (stats.sync_height as f32 / stats.target_height as f32) * 100.0
            }
            None => 0.0,
        }
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

    /// Get download queue size for a specific network
    pub fn download_queue_size(&self, network: Network) -> usize {
        self.download_queues.get(&network).map(|queue| queue.len()).unwrap_or(0)
    }

    /// Check if download queue is empty for a specific network
    pub fn is_download_queue_empty(&self, network: Network) -> bool {
        self.download_queues.get(&network).map(|queue| queue.is_empty()).unwrap_or(true)
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
    use dashcore::hashes::Hash;

    #[test]
    fn test_spv_wallet_manager_creation() {
        let manager = SPVWalletManager::new();
        assert_eq!(manager.sync_status(), SPVSyncStatus::Idle);
        assert_eq!(manager.sync_progress(), 0.0);
    }

    #[test]
    fn test_sync_progress() {
        let mut manager = SPVWalletManager::new();
        manager.set_target_height(1000);
        manager.stats.sync_height = 500;
        assert_eq!(manager.sync_progress(), 50.0);
    }

    #[test]
    fn test_sync_status_transitions() {
        let mut manager = SPVWalletManager::new();

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

    #[test]
    fn test_add_new_wallet() {
        use key_wallet::mnemonic::{Language, Mnemonic};

        let mut manager = SPVWalletManager::new();

        // Create a wallet to add
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(test_mnemonic, Language::English).unwrap();
        let wallet = Wallet::from_mnemonic(
            mnemonic,
            Default::default(),
            Network::Testnet,
            key_wallet::wallet::initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        let wallet_id = wallet.wallet_id;

        // Add the new wallet
        let result = manager.add_new_wallet(wallet, Some(100));

        // Should succeed
        assert!(result.is_ok());

        // Wallet should exist in the manager
        assert!(manager.base.wallets.contains_key(&wallet_id));
        assert!(manager.base.wallet_infos.contains_key(&wallet_id));

        // Check wallet info
        let info = manager.base.wallet_infos.get(&wallet_id).unwrap();
        assert_eq!(info.name, None); // from_wallet creates with no name
        assert_eq!(info.metadata.birth_height, Some(100));
    }

    #[test]
    fn test_add_existing_wallet() {
        use key_wallet::mnemonic::{Language, Mnemonic};

        let mut manager = SPVWalletManager::new();

        // Create an "existing" wallet (simulating restoration from backup)
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(test_mnemonic, Language::English).unwrap();
        let wallet = Wallet::from_mnemonic(
            mnemonic,
            Default::default(),
            Network::Testnet,
            key_wallet::wallet::initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        let wallet_id = wallet.wallet_id;

        // Add the existing wallet
        let result = manager.add_existing_wallet(wallet, "Restored Wallet".to_string(), Some(200));

        // Should succeed
        assert!(result.is_ok());

        // Wallet should exist in the manager
        assert!(manager.base.wallets.contains_key(&wallet_id));
        assert!(manager.base.wallet_infos.contains_key(&wallet_id));

        // Check wallet info
        let info = manager.base.wallet_infos.get(&wallet_id).unwrap();
        assert_eq!(info.name, Some("Restored Wallet".to_string()));
        assert_eq!(info.metadata.birth_height, Some(200));
    }
}
