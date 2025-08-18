//! Simplified SPV Wallet Manager
//!
//! This module provides a thin wrapper around WalletManager that adds
//! SPV-specific functionality without duplicating wallet management logic.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

use async_trait::async_trait;
use dashcore::bip158::BlockFilter;
use dashcore::blockdata::block::Block;
use dashcore::blockdata::transaction::Transaction;
use dashcore::prelude::CoreBlockHeight;
use dashcore::{BlockHash, Txid};
use key_wallet::Network;

use crate::wallet_interface::WalletInterface;
use crate::wallet_manager::{WalletId, WalletManager};
use key_wallet::transaction_checking::TransactionContext;

/// SPV Wallet Manager
///
/// A thin wrapper around WalletManager that adds SPV-specific functionality:
/// - Compact filter checking
/// - Block download queue management
/// - SPV synchronization statistics
///
/// All wallet state, UTXO tracking, and transaction processing is delegated
/// to the underlying WalletManager.
#[derive(Debug)]
pub struct SPVWalletManager {
    /// Base wallet manager (handles all wallet state)
    pub base: WalletManager,

    // SPV-specific fields only
    /// Block download queue (per network)
    download_queues: BTreeMap<Network, VecDeque<BlockHash>>,
    /// Pending blocks waiting for dependencies (per network)
    pending_blocks: BTreeMap<Network, BTreeMap<u32, (Block, BlockHash)>>,
    /// Filter match cache (per network) - caches whether a filter matched
    filter_matches: BTreeMap<Network, BTreeMap<BlockHash, bool>>,
    /// Maximum blocks to queue for download
    max_download_queue: usize,
    /// SPV statistics (per network)
    stats: BTreeMap<Network, SPVStats>,
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

impl SPVWalletManager {
    /// Create a new SPV wallet manager
    pub fn new() -> Self {
        Self {
            base: WalletManager::new(),
            download_queues: BTreeMap::new(),
            pending_blocks: BTreeMap::new(),
            filter_matches: BTreeMap::new(),
            max_download_queue: 100,
            stats: BTreeMap::new(),
        }
    }

    /// Check if a compact filter matches any of our wallets
    ///
    /// This checks the filter against all watched addresses from all wallets
    /// for the specified network.
    pub fn check_filter(
        &self,
        filter: &BlockFilter,
        block_hash: &BlockHash,
        network: Network,
    ) -> bool {
        // Check if we've already evaluated this filter
        if let Some(network_cache) = self.filter_matches.get(&network) {
            if let Some(&matched) = network_cache.get(block_hash) {
                return matched;
            }
        }

        // Collect all scripts we're watching from all wallets for this network
        let mut script_bytes = Vec::new();

        // Get all wallet addresses for this network
        for (wallet_id, info) in &self.base.wallet_infos {
            // Get monitored addresses for this wallet and network
            let monitored = info.monitored_addresses(network);
            for address in monitored {
                script_bytes.push(address.script_pubkey().as_bytes().to_vec());
            }

            // Also check wallet's own addresses if available
            if let Some(wallet) = self.base.wallets.get(wallet_id) {
                // Get addresses from the wallet's accounts
                if let Some(collection) = wallet.accounts.get(&network) {
                    // Check BIP44 accounts
                    for account in collection.standard_bip44_accounts.values() {
                        // You would need to derive addresses here based on the account
                        // This is simplified - in practice you'd derive up to the gap limit
                    }
                }
            }
        }

        // Check if any of our scripts match the filter
        filter
            .match_any(block_hash, &mut script_bytes.iter().map(|s| s.as_slice()))
            .unwrap_or(false)
    }

    /// Process a block and its transactions
    ///
    /// Delegates transaction processing to the base WalletManager
    pub fn process_block(
        &mut self,
        block: &Block,
        height: u32,
        network: Network,
    ) -> ProcessBlockResult {
        let mut result = ProcessBlockResult::default();
        let block_hash = Some(block.block_hash());
        let timestamp = block.header.time;

        // Process each transaction using the base manager
        for tx in &block.txdata {
            let context = TransactionContext::InBlock {
                height,
                block_hash,
                timestamp: Some(timestamp),
            };

            let affected_wallets = self.base.check_transaction_in_all_wallets(
                tx, network, context, true, // update state
            );

            if !affected_wallets.is_empty() {
                result.relevant_transactions += 1;
                result.affected_wallets.extend(affected_wallets);
            }
        }

        // Update statistics
        if let Some(stats) = self.stats.get_mut(&network) {
            stats.blocks_downloaded += 1;
            stats.transactions_found += result.relevant_transactions as u64;
            stats.sync_height = height;
        }

        // Update network state height in base manager
        if let Some(state) = self.base.get_network_state_mut(network) {
            state.current_height = height;
        }

        result
    }

    /// Queue a block for download
    pub fn queue_block_download(&mut self, network: Network, block_hash: BlockHash) -> bool {
        let queue = self.download_queues.entry(network).or_insert_with(VecDeque::new);

        if queue.len() >= self.max_download_queue {
            return false;
        }

        if !queue.contains(&block_hash) {
            queue.push_back(block_hash);
        }

        true
    }

    /// Get next block to download
    pub fn next_block_to_download(&mut self, network: Network) -> Option<BlockHash> {
        self.download_queues.get_mut(&network)?.pop_front()
    }

    /// Add a pending block (waiting for dependencies)
    pub fn add_pending_block(
        &mut self,
        network: Network,
        height: u32,
        block: Block,
        hash: BlockHash,
    ) {
        self.pending_blocks
            .entry(network)
            .or_insert_with(BTreeMap::new)
            .insert(height, (block, hash));
    }

    /// Get and remove a pending block
    pub fn take_pending_block(
        &mut self,
        network: Network,
        height: u32,
    ) -> Option<(Block, BlockHash)> {
        self.pending_blocks.get_mut(&network)?.remove(&height)
    }

    /// Get SPV sync status for a network
    pub fn sync_status(&self, network: Network) -> SPVSyncStatus {
        let stats = self.stats.get(&network);
        let queue_size = self.download_queues.get(&network).map(|q| q.len()).unwrap_or(0);

        if let Some(stats) = stats {
            if stats.sync_height >= stats.target_height {
                SPVSyncStatus::Synced
            } else if queue_size > 0 {
                SPVSyncStatus::DownloadingBlocks {
                    pending: queue_size,
                }
            } else {
                SPVSyncStatus::CheckingFilters {
                    current: stats.sync_height,
                    target: stats.target_height,
                }
            }
        } else {
            SPVSyncStatus::Idle
        }
    }

    /// Update sync statistics
    pub fn update_stats<F>(&mut self, network: Network, update: F)
    where
        F: FnOnce(&mut SPVStats),
    {
        let stats = self.stats.entry(network).or_insert_with(SPVStats::default);
        update(stats);
    }

    /// Get current sync height for a network
    pub fn sync_height(&self, network: Network) -> u32 {
        self.base.get_network_state(network).map(|state| state.current_height).unwrap_or(0)
    }

    /// Set target sync height
    pub fn set_target_height(&mut self, network: Network, height: u32) {
        self.stats.entry(network).or_insert_with(SPVStats::default).target_height = height;
    }
}

/// Result of processing a block
#[derive(Debug, Default)]
pub struct ProcessBlockResult {
    /// Number of relevant transactions found
    pub relevant_transactions: usize,
    /// Wallets that were affected
    pub affected_wallets: Vec<WalletId>,
}

impl Default for SPVWalletManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WalletInterface for SPVWalletManager {
    /// Process a block and return relevant transaction IDs
    async fn process_block(
        &mut self,
        block: &Block,
        height: CoreBlockHeight,
        network: Network,
    ) -> Vec<Txid> {
        let relevant_tx_ids = self.base.process_block(block, height, network);

        // Update statistics
        if let Some(stats) = self.stats.get_mut(&network) {
            stats.blocks_downloaded += 1;
            stats.transactions_found += relevant_tx_ids.len() as u64;
            stats.sync_height = height;
        }

        relevant_tx_ids
    }

    /// Process a mempool transaction
    async fn process_mempool_transaction(&mut self, tx: &Transaction, network: Network) {
        let context = TransactionContext::Mempool;

        // Check transaction against all wallets
        self.base.check_transaction_in_all_wallets(
            tx, network, context, true, // update state
        );
    }

    /// Handle a blockchain reorganization
    async fn handle_reorg(
        &mut self,
        from_height: CoreBlockHeight,
        to_height: CoreBlockHeight,
        network: Network,
    ) {
        self.base.handle_reorg(from_height, to_height, network);

        // Update SPV stats
        if let Some(stats) = self.stats.get_mut(&network) {
            if stats.sync_height >= from_height {
                stats.sync_height = to_height;
            }
        }
    }

    /// Check if a compact filter matches any watched addresses
    async fn check_compact_filter(
        &self,
        filter: &BlockFilter,
        block_hash: &BlockHash,
        network: Network,
    ) -> bool {
        // Check if we've already evaluated this filter
        if let Some(network_cache) = self.filter_matches.get(&network) {
            if let Some(&matched) = network_cache.get(block_hash) {
                return matched;
            }
        }

        self.base.check_compact_filter(filter, block_hash, network)
    }

    /// Get a reference to self as Any for downcasting in tests
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
