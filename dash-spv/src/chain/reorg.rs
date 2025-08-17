//! Chain reorganization handling
//!
//! This module implements the core logic for handling blockchain reorganizations,
//! including finding common ancestors, rolling back transactions, and switching chains.

use super::chainlock_manager::ChainLockManager;
use super::{ChainTip, Fork};
use crate::storage::ChainStorage;
use crate::types::ChainState;
use dashcore::{BlockHash, Header as BlockHeader, Transaction, Txid};
use std::sync::Arc;
use tracing;

/// Event emitted when a reorganization occurs
#[derive(Debug, Clone)]
pub struct ReorgEvent {
    /// The common ancestor where chains diverged
    pub common_ancestor: BlockHash,
    /// Height of the common ancestor
    pub common_height: u32,
    /// Headers that were removed from the main chain
    pub disconnected_headers: Vec<BlockHeader>,
    /// Headers that were added to the main chain
    pub connected_headers: Vec<BlockHeader>,
    /// Transactions that may have changed confirmation status
    pub affected_transactions: Vec<Transaction>,
}

/// Data collected during the read phase of reorganization
#[allow(dead_code)]
#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub(crate) struct ReorgData {
    /// The common ancestor where chains diverged
    pub(crate) common_ancestor: BlockHash,
    /// Height of the common ancestor
    pub(crate) common_height: u32,
    /// Headers that need to be disconnected from the main chain
    disconnected_headers: Vec<BlockHeader>,
    /// Block hashes and heights for disconnected blocks
    disconnected_blocks: Vec<(BlockHash, u32)>,
    /// Transaction IDs from disconnected blocks that affect the wallet
    affected_tx_ids: Vec<Txid>,
    /// Actual transactions that were affected (if available)
    affected_transactions: Vec<Transaction>,
}

/// Manages chain reorganizations
pub struct ReorgManager {
    /// Maximum depth of reorganization to handle
    max_reorg_depth: u32,
    /// Whether to allow reorgs past chain-locked blocks
    respect_chain_locks: bool,
    /// Chain lock manager for checking locked blocks
    chain_lock_manager: Option<Arc<ChainLockManager>>,
}

impl ReorgManager {
    /// Create a new reorganization manager
    pub fn new(max_reorg_depth: u32, respect_chain_locks: bool) -> Self {
        Self {
            max_reorg_depth,
            respect_chain_locks,
            chain_lock_manager: None,
        }
    }

    /// Create a new reorganization manager with chain lock support
    pub fn new_with_chain_locks(
        max_reorg_depth: u32,
        chain_lock_manager: Arc<ChainLockManager>,
    ) -> Self {
        Self {
            max_reorg_depth,
            respect_chain_locks: true,
            chain_lock_manager: Some(chain_lock_manager),
        }
    }

    /// Check if a fork has more work than the current chain and should trigger a reorg
    pub fn should_reorganize(
        &self,
        current_tip: &ChainTip,
        fork: &Fork,
        storage: &dyn ChainStorage,
    ) -> Result<bool, String> {
        self.should_reorganize_with_chain_state(current_tip, fork, storage, None)
    }

    /// Check if a fork has more work than the current chain and should trigger a reorg
    /// This version is checkpoint-aware when chain_state is provided
    pub fn should_reorganize_with_chain_state(
        &self,
        current_tip: &ChainTip,
        fork: &Fork,
        storage: &dyn ChainStorage,
        chain_state: Option<&ChainState>,
    ) -> Result<bool, String> {
        // Check if fork has more work
        if fork.chain_work <= current_tip.chain_work {
            return Ok(false);
        }

        // Check reorg depth - account for checkpoint sync
        let reorg_depth = if let Some(state) = chain_state {
            if state.synced_from_checkpoint && state.sync_base_height > 0 {
                // During checkpoint sync, both current_tip.height and fork.fork_height
                // should be interpreted relative to sync_base_height

                // For checkpoint sync:
                // - current_tip.height is absolute blockchain height
                // - fork.fork_height might be from genesis-based headers
                // We need to compare relative depths only

                // If the fork is from headers that started at genesis,
                // we shouldn't compare against the full checkpoint height
                if fork.fork_height < state.sync_base_height {
                    // This fork is from before our checkpoint - likely from genesis-based headers
                    // This scenario should be rejected at header validation level, not here
                    tracing::warn!(
                        "Fork detected from height {} which is before checkpoint base height {}. \
                        This suggests headers from genesis were received during checkpoint sync.",
                        fork.fork_height,
                        state.sync_base_height
                    );

                    // For now, reject forks that would reorg past the checkpoint
                    return Err(format!(
                        "Cannot reorg past checkpoint: fork height {} < checkpoint base {}",
                        fork.fork_height, state.sync_base_height
                    ));
                } else {
                    // Normal case: both heights are relative to checkpoint
                    current_tip.height.saturating_sub(fork.fork_height)
                }
            } else {
                // Normal sync mode
                current_tip.height.saturating_sub(fork.fork_height)
            }
        } else {
            // Fallback to original logic when no chain state provided
            current_tip.height.saturating_sub(fork.fork_height)
        };

        if reorg_depth > self.max_reorg_depth {
            return Err(format!(
                "Reorg depth {} exceeds maximum {}",
                reorg_depth, self.max_reorg_depth
            ));
        }

        // Check for chain locks if enabled
        if self.respect_chain_locks {
            if let Some(ref chain_lock_mgr) = self.chain_lock_manager {
                // Check if reorg would violate chain locks
                if chain_lock_mgr.would_violate_chain_lock(fork.fork_height, current_tip.height) {
                    return Err(format!(
                        "Cannot reorg: would violate chain lock between heights {} and {}",
                        fork.fork_height, current_tip.height
                    ));
                }
            } else {
                // Fall back to checking individual blocks
                for height in (fork.fork_height + 1)..=current_tip.height {
                    if let Ok(Some(header)) = storage.get_header_by_height(height) {
                        if self.is_chain_locked(&header, storage)? {
                            return Err(format!(
                                "Cannot reorg past chain-locked block at height {}",
                                height
                            ));
                        }
                    }
                }
            }
        }

        Ok(true)
    }

    /// Check if a block is chain-locked
    pub fn is_chain_locked(
        &self,
        header: &BlockHeader,
        storage: &dyn ChainStorage,
    ) -> Result<bool, String> {
        if let Some(ref chain_lock_mgr) = self.chain_lock_manager {
            // Get the height of this header
            if let Ok(Some(height)) = storage.get_header_height(&header.block_hash()) {
                return Ok(chain_lock_mgr.is_block_chain_locked(&header.block_hash(), height));
            }
        }
        // If no chain lock manager or height not found, assume not locked
        Ok(false)
    }
}

// WalletState removed - reorganization should be handled by external wallet
/*
impl ReorgManager {
    /// Perform a chain reorganization using a phased approach
    pub async fn reorganize<S: StorageManager>(
        &self,
        chain_state: &mut ChainState,
        wallet_state: &mut WalletState,
        fork: &Fork,
        storage_manager: &mut S,
    ) -> Result<ReorgEvent, String> {
        // Phase 1: Collect all necessary data (read-only)
        let reorg_data = self.collect_reorg_data(chain_state, fork, storage_manager).await?;

        // Phase 2: Apply the reorganization (write-only)
        self.apply_reorg_with_data(chain_state, wallet_state, fork, reorg_data, storage_manager)
            .await
    }

    /// Collect all data needed for reorganization (read-only phase)
    #[cfg(test)]
    pub async fn collect_reorg_data<S: StorageManager>(
        &self,
        chain_state: &ChainState,
        fork: &Fork,
        storage_manager: &S,
    ) -> Result<ReorgData, String> {
        self.collect_reorg_data_internal(chain_state, fork, storage_manager).await
    }

    #[cfg(not(test))]
    async fn collect_reorg_data<S: StorageManager>(
        &self,
        chain_state: &ChainState,
        fork: &Fork,
        storage_manager: &S,
    ) -> Result<ReorgData, String> {
        self.collect_reorg_data_internal(chain_state, fork, storage_manager).await
    }

    async fn collect_reorg_data_internal<S: StorageManager>(
        &self,
        chain_state: &ChainState,
        fork: &Fork,
        storage: &S,
    ) -> Result<ReorgData, String> {
        // Find the common ancestor
        let (common_ancestor, common_height) =
            self.find_common_ancestor_with_fork(fork, storage).await?;

        // Collect headers to disconnect
        let current_height = chain_state.get_height();
        let mut disconnected_headers = Vec::new();
        let mut disconnected_blocks = Vec::new();

        // Walk back from current tip to common ancestor
        for height in ((common_height + 1)..=current_height).rev() {
            if let Ok(Some(header)) = storage.get_header(height).await {
                let block_hash = header.block_hash();
                disconnected_blocks.push((block_hash, height));
                disconnected_headers.push(header);
            } else {
                return Err(format!("Missing header at height {}", height));
            }
        }

        // Collect affected transaction IDs
        let affected_tx_ids = Vec::new(); // Will be populated when we have transaction storage
        let affected_transactions = Vec::new(); // Will be populated when we have transaction storage

        Ok(ReorgData {
            common_ancestor,
            common_height,
            disconnected_headers,
            disconnected_blocks,
            affected_tx_ids,
            affected_transactions,
        })
    }

    /// Apply reorganization using collected data (write-only phase)
    async fn apply_reorg_with_data<S: StorageManager>(
        &self,
        chain_state: &mut ChainState,
        wallet_state: &mut WalletState,
        fork: &Fork,
        reorg_data: ReorgData,
        storage_manager: &mut S,
    ) -> Result<ReorgEvent, String> {
        // Create a checkpoint of the current chain state before making any changes
        let chain_state_checkpoint = chain_state.clone();

        // Track headers that were successfully stored for potential rollback
        let mut stored_headers: Vec<BlockHeader> = Vec::new();

        // Perform all operations in a single atomic-like block
        let result = async {
            // Step 1: Rollback wallet state if UTXO rollback is available
            if wallet_state.rollback_manager().is_some() {
                wallet_state
                    .rollback_to_height(reorg_data.common_height, storage_manager)
                    .await
                    .map_err(|e| format!("Failed to rollback wallet state: {:?}", e))?;
            }

            // Step 2: Disconnect blocks from the old chain
            for header in &reorg_data.disconnected_headers {
                // Mark transactions as unconfirmed if rollback manager not available
                if wallet_state.rollback_manager().is_none() {
                    for txid in &reorg_data.affected_tx_ids {
                        wallet_state.mark_transaction_unconfirmed(txid);
                    }
                }

                // Remove header from chain state
                chain_state.remove_tip();
            }

            // Step 3: Connect blocks from the new chain and store them
            let mut current_height = reorg_data.common_height;
            for header in &fork.headers {
                current_height += 1;

                // Add header to chain state
                chain_state.add_header(*header);

                // Store the header - if this fails, we need to rollback everything
                storage_manager.store_headers(&[*header]).await.map_err(|e| {
                    format!("Failed to store header at height {}: {:?}", current_height, e)
                })?;

                // Only record successfully stored headers
                stored_headers.push(*header);
            }

            Ok::<ReorgEvent, String>(ReorgEvent {
                common_ancestor: reorg_data.common_ancestor,
                common_height: reorg_data.common_height,
                disconnected_headers: reorg_data.disconnected_headers,
                connected_headers: fork.headers.clone(),
                affected_transactions: reorg_data.affected_transactions,
            })
        }
        .await;

        // If any operation failed, attempt to restore the chain state
        match result {
            Ok(event) => Ok(event),
            Err(e) => {
                // Restore the chain state to its original state
                *chain_state = chain_state_checkpoint;

                // Log the rollback attempt
                tracing::error!(
                    "Reorg failed, restored chain state. Error: {}. \
                    Successfully stored {} headers before failure.",
                    e,
                    stored_headers.len()
                );

                // Note: We cannot easily rollback the wallet state or storage operations
                // that have already been committed. This is a limitation of not having
                // true database transactions. The error message will indicate this partial
                // state to the caller.
                Err(format!(
                    "Reorg failed after partial application. Chain state restored, \
                    but wallet/storage may be in inconsistent state. Error: {}. \
                    Consider resyncing from a checkpoint.",
                    e
                ))
            }
        }
    }

    /// Find the common ancestor between current chain and a fork
    async fn find_common_ancestor_with_fork(
        &self,
        fork: &Fork,
        storage: &dyn StorageManager,
    ) -> Result<(BlockHash, u32), String> {
        // First check if the fork point itself is in our chain
        if let Ok(Some(height)) = storage.get_header_height_by_hash(&fork.fork_point).await {
            // The fork point is already in our chain, so it's the common ancestor
            return Ok((fork.fork_point, height));
        }

        // If we have fork headers, check their parent blocks
        if !fork.headers.is_empty() {
            // Start from the first header in the fork and walk backwards
            let first_fork_header = &fork.headers[0];
            let mut current_hash = first_fork_header.prev_blockhash;

            // Check if the parent of the first fork header is in our chain
            if let Ok(Some(height)) = storage.get_header_height_by_hash(&current_hash).await {
                return Ok((current_hash, height));
            }
        }

        // As a fallback, the fork should specify where it diverged from
        // In a properly constructed Fork, fork_height should indicate where the split occurred
        if fork.fork_height > 0 {
            // Get the header at fork_height - 1 which should be the common ancestor
            if let Ok(Some(header)) = storage.get_header(fork.fork_height.saturating_sub(1)).await {
                let hash = header.block_hash();
                return Ok((hash, fork.fork_height.saturating_sub(1)));
            }
        }

        Err("Cannot find common ancestor between fork and main chain".to_string())
    }

    /// Find the common ancestor between current chain and a fork point (sync version for ChainStorage)
    fn find_common_ancestor(
        &self,
        _chain_state: &ChainState,
        fork_point: &BlockHash,
        storage: &dyn ChainStorage,
    ) -> Result<(BlockHash, u32), String> {
        // Start from the fork point and walk back until we find a block in our chain
        let mut current_hash = *fork_point;
        let mut iterations = 0;
        const MAX_ITERATIONS: u32 = 1_000_000; // Reasonable limit for chain traversal

        loop {
            if let Ok(Some(height)) = storage.get_header_height(&current_hash) {
                // Found it in our chain
                return Ok((current_hash, height));
            }

            // Get the previous block
            if let Ok(Some(header)) = storage.get_header(&current_hash) {
                current_hash = header.prev_blockhash;

                // Safety check: don't go back too far
                if current_hash == BlockHash::from([0u8; 32]) {
                    return Err("Reached genesis without finding common ancestor".to_string());
                }

                // Prevent infinite loops in case of corrupted chain
                iterations += 1;
                if iterations > MAX_ITERATIONS {
                    return Err(format!("Exceeded maximum iterations ({}) while searching for common ancestor - possible corrupted chain", MAX_ITERATIONS));
                }
            } else {
                return Err("Failed to find common ancestor".to_string());
            }
        }
    }

    /// Collect headers that need to be disconnected
    fn collect_headers_to_disconnect(
        &self,
        chain_state: &ChainState,
        common_height: u32,
        storage: &dyn ChainStorage,
    ) -> Result<Vec<BlockHeader>, String> {
        let current_height = chain_state.get_height();
        let mut headers = Vec::new();

        // Walk back from current tip to common ancestor
        for height in ((common_height + 1)..=current_height).rev() {
            if let Ok(Some(header)) = storage.get_header_by_height(height) {
                headers.push(header);
            } else {
                return Err(format!("Missing header at height {}", height));
            }
        }

        Ok(headers)
    }

    /// Collect transactions affected by the reorganization
    fn collect_affected_transactions(
        &self,
        disconnected_headers: &[BlockHeader],
        _connected_headers: &[BlockHeader],
        wallet_state: &WalletState,
        storage: &dyn ChainStorage,
    ) -> Result<Vec<Transaction>, String> {
        let mut affected = Vec::new();

        // Collect transactions from disconnected blocks
        for header in disconnected_headers {
            let block_hash = header.block_hash();
            if let Ok(Some(txids)) = storage.get_block_transactions(&block_hash) {
                for txid in txids {
                    if wallet_state.is_wallet_transaction(&txid) {
                        if let Ok(Some(tx)) = storage.get_transaction(&txid) {
                            affected.push(tx);
                        }
                    }
                }
            }
        }

        // Note: We don't have transactions from connected headers yet,
        // they would need to be downloaded after the reorg

        Ok(affected)
    }

    /// Check if a block is chain-locked
    pub fn is_chain_locked(
        &self,
        header: &BlockHeader,
        storage: &dyn ChainStorage,
    ) -> Result<bool, String> {
        if let Some(ref chain_lock_mgr) = self.chain_lock_manager {
            // Get the height of this header
            if let Ok(Some(height)) = storage.get_header_height(&header.block_hash()) {
                return Ok(chain_lock_mgr.is_block_chain_locked(&header.block_hash(), height));
            }
        }
        // If no chain lock manager or height not found, assume not locked
        Ok(false)
    }

    /// Validate that a reorganization is safe to perform
    pub fn validate_reorg(&self, current_tip: &ChainTip, fork: &Fork) -> Result<(), String> {
        // Check maximum reorg depth
        let reorg_depth = current_tip.height.saturating_sub(fork.fork_height);
        if reorg_depth > self.max_reorg_depth {
            return Err(format!(
                "Reorg depth {} exceeds maximum allowed {}",
                reorg_depth, self.max_reorg_depth
            ));
        }

        // Check that fork actually has more work
        if fork.chain_work <= current_tip.chain_work {
            return Err("Fork does not have more work than current chain".to_string());
        }

        // Additional validation could go here

        Ok(())
    }
}
*/

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainWork;
    use crate::storage::{MemoryStorage, MemoryStorageManager};
    use dashcore::blockdata::constants::genesis_block;
    use dashcore::Network;

    fn create_test_header(prev: &BlockHeader, nonce: u32) -> BlockHeader {
        let mut header = prev.clone();
        header.prev_blockhash = prev.block_hash();
        header.nonce = nonce;
        header.time = prev.time + 600; // 10 minutes later
        header
    }

    #[tokio::test]
    async fn test_reorg_validation() {
        let reorg_mgr = ReorgManager::new(100, false);

        let genesis = genesis_block(Network::Dash).header;
        let tip = ChainTip::new(genesis.clone(), 0, ChainWork::from_header(&genesis));

        // Create a fork with less work - should not reorg
        let fork = Fork {
            fork_point: BlockHash::from(dashcore_hashes::hash_x11::Hash::all_zeros()),
            fork_height: 0,
            tip_hash: genesis.block_hash(),
            tip_height: 1,
            headers: vec![genesis.clone()],
            chain_work: ChainWork::zero(), // Less work
        };

        let result = reorg_mgr.validate_reorg(&tip, &fork);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not have more work"));
    }

    #[tokio::test]
    async fn test_max_reorg_depth() {
        let reorg_mgr = ReorgManager::new(10, false);

        let genesis = genesis_block(Network::Dash).header;
        let tip = ChainTip::new(genesis.clone(), 100, ChainWork::from_header(&genesis));

        // Create a fork that would require deep reorg
        let fork = Fork {
            fork_point: genesis.block_hash(),
            fork_height: 0, // Fork from genesis
            tip_hash: BlockHash::from(dashcore_hashes::hash_x11::Hash::all_zeros()),
            tip_height: 101,
            headers: vec![],
            chain_work: ChainWork::from_bytes([255u8; 32]), // Max work
        };

        let result = reorg_mgr.validate_reorg(&tip, &fork);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum allowed"));
    }
}
