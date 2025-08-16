//! SPV Client Integration Module
//!
//! This module provides the integration layer between the SPV client and wallet manager.
//! It handles compact block filters, transaction checking, and wallet state updates.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use dashcore::blockdata::block::Block;
use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::{BlockHash, Network as DashNetwork, Txid};
use dashcore_hashes::Hash;
use key_wallet::{Address, Network};

use crate::compact_filter::CompactFilter;
use crate::enhanced_wallet_manager::{
    BlockProcessResult, EnhancedWalletManager, TransactionProcessResult,
};
use crate::wallet_manager::WalletError;

/// SPV client integration for wallet management
///
/// This struct provides the main interface for SPV clients to interact with
/// the wallet manager. It handles:
/// - Compact block filter checking
/// - Block download decisions
/// - Transaction processing and wallet updates
/// - UTXO tracking
pub struct SPVWalletIntegration {
    /// Enhanced wallet manager
    manager: EnhancedWalletManager,
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

impl SPVWalletIntegration {
    /// Create a new SPV wallet integration
    pub fn new(network: Network) -> Self {
        Self {
            manager: EnhancedWalletManager::new(network),
            download_queue: VecDeque::new(),
            pending_blocks: BTreeMap::new(),
            filter_matches: BTreeMap::new(),
            max_download_queue: 100,
            stats: SPVStats::default(),
        }
    }

    /// Get a reference to the wallet manager
    pub fn wallet_manager(&self) -> &EnhancedWalletManager {
        &self.manager
    }

    /// Get a mutable reference to the wallet manager
    pub fn wallet_manager_mut(&mut self) -> &mut EnhancedWalletManager {
        &mut self.manager
    }

    /// Check if a compact filter matches our wallets
    ///
    /// This is the main entry point for the SPV client to check filters.
    /// Returns true if the block should be downloaded.
    pub fn check_filter(&mut self, filter: &CompactFilter, block_hash: &BlockHash) -> bool {
        self.stats.filters_checked += 1;

        let matches = self.manager.should_download_block(filter, block_hash);

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

    /// Process a downloaded block
    ///
    /// This should be called by the SPV client when a block has been downloaded.
    /// The block will be processed to find relevant transactions and update wallet state.
    pub fn process_block(&mut self, block: Block, height: u32) -> BlockProcessResult {
        self.stats.blocks_downloaded += 1;

        // Remove from download queue if present
        let block_hash = block.block_hash();
        self.download_queue.retain(|h| h != &block_hash);

        // Process the block with the wallet manager
        let result = self.manager.process_block(&block, height);

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
        self.manager.process_transaction(tx, None, None, timestamp)
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
                let result = self.process_block(block, height);
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

    /// Get all watched scripts for filter construction
    pub fn get_watched_scripts(&self) -> Vec<ScriptBuf> {
        self.manager.get_watched_scripts().iter().cloned().collect()
    }

    /// Get all watched outpoints
    pub fn get_watched_outpoints(&self) -> Vec<OutPoint> {
        self.manager.get_watched_outpoints().iter().cloned().collect()
    }

    /// Handle a reorg by rolling back to a specific height
    pub fn handle_reorg(&mut self, rollback_height: u32) -> Result<(), WalletError> {
        // Clear any pending blocks above rollback height
        self.pending_blocks.retain(|&height, _| height <= rollback_height);

        // Clear download queue as it may contain invalidated blocks
        self.download_queue.clear();

        // Update sync height
        self.stats.sync_height = rollback_height;
        self.manager.update_sync_height(rollback_height);

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

    /// Add block to download queue (for testing)
    pub fn test_add_to_download_queue(&mut self, block_hash: BlockHash) {
        self.download_queue.push_back(block_hash);
    }

    /// Set sync height (for testing)
    pub fn test_set_sync_height(&mut self, height: u32) {
        self.stats.sync_height = height;
    }
}

/// Callbacks for SPV client events
///
/// Implement this trait to receive notifications from the SPV integration.
pub trait SPVCallbacks: Send + Sync {
    /// Called when a filter matches and a block should be downloaded
    fn on_filter_match(&self, block_hash: &BlockHash);

    /// Called when a relevant transaction is found
    fn on_transaction_found(&self, tx: &Transaction, height: Option<u32>);

    /// Called when sync status changes
    fn on_sync_status_change(&self, status: SPVSyncStatus);

    /// Called when a reorg is detected
    fn on_reorg_detected(&self, from_height: u32, to_height: u32);

    /// Called when sync completes
    fn on_sync_complete(&self);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spv_integration_creation() {
        let spv = SPVWalletIntegration::new(Network::Testnet);
        assert_eq!(spv.sync_status(), SPVSyncStatus::Idle);
        assert_eq!(spv.sync_progress(), 0.0);
    }

    #[test]
    fn test_sync_progress() {
        let mut spv = SPVWalletIntegration::new(Network::Testnet);
        spv.set_target_height(1000);
        spv.stats.sync_height = 500;
        assert_eq!(spv.sync_progress(), 50.0);
    }

    #[test]
    fn test_sync_status_transitions() {
        let mut spv = SPVWalletIntegration::new(Network::Testnet);

        // Initially idle
        assert_eq!(spv.sync_status(), SPVSyncStatus::Idle);

        // Set target height - now checking filters
        spv.set_target_height(100);
        assert_eq!(
            spv.sync_status(),
            SPVSyncStatus::CheckingFilters {
                current: 0,
                target: 100
            }
        );

        // Add to download queue - now downloading
        spv.download_queue.push_back(BlockHash::from_byte_array([0u8; 32]));
        assert_eq!(
            spv.sync_status(),
            SPVSyncStatus::DownloadingBlocks {
                pending: 1
            }
        );

        // Clear queue and sync to target - now synced
        spv.download_queue.clear();
        spv.stats.sync_height = 100;
        assert_eq!(spv.sync_status(), SPVSyncStatus::Synced);
        assert!(spv.is_synced());
    }
}
