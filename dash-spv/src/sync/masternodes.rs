//! Masternode synchronization functionality.

use dashcore::{
    address::{Address, Payload},
    bls_sig_utils::BLSPublicKey,
    hash_types::MerkleRootMasternodeList,
    network::constants::NetworkExt,
    network::message::NetworkMessage,
    network::message_sml::{GetMnListDiff, MnListDiff},
    network::message_qrinfo::{QRInfo, GetQRInfo},
    sml::{
        llmq_type::{LLMQType, DKGWindow},
        masternode_list::MasternodeList,
        masternode_list_engine::MasternodeListEngine,
        masternode_list_entry::{
            qualified_masternode_list_entry::QualifiedMasternodeListEntry, EntryMasternodeType,
            MasternodeListEntry,
        },
        quorum_validation_error::ClientDataRetrievalError,
    },
    BlockHash, ProTxHash, PubkeyHash,
};
use dashcore_hashes::Hash;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::SocketAddr;
use std::str::FromStr;

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::{MasternodeState, StorageManager};
use crate::sync::terminal_blocks::TerminalBlockManager;
use crate::sync::discovery::{MasternodeDiscoveryService, DiscoveryResult, QRInfoRequest};
use crate::sync::batching::{QRInfoBatchingStrategy, NetworkConditions};
use crate::sync::validation::{ValidationEngine, ValidationConfig, ValidationResult, ValidationSummary};
use crate::sync::chainlock_validation::{ChainLockValidator, ChainLockValidationConfig};
use crate::sync::validation_state::{ValidationStateManager, ValidationType};
use std::time::Duration;

/// Number of recent masternode lists to maintain individually.
/// Set to 40,000 to ensure we have lists for Platform queries going back ~40 days.
/// This is a temporary solution until we implement on-demand fetching.
const MASTERNODE_LIST_BUFFER_SIZE: u32 = 40_000;

/// Tracks the state of smart DKG-based masternode diff fetching
#[derive(Debug, Clone)]
struct DKGFetchState {
    /// DKG windows we haven't started checking yet
    /// Grouped by mining_start height for efficient processing
    pending_windows: BTreeMap<u32, Vec<DKGWindow>>,
    
    /// Windows we're currently checking
    /// Each entry is (window, current_height_to_check)
    active_windows: Vec<(DKGWindow, u32)>,
    
    /// Cycles we've finished checking (either found quorum or exhausted window)
    /// Key is (quorum_type, cycle_start) to uniquely identify each DKG cycle
    completed_cycles: BTreeSet<(LLMQType, u32)>,
    
    /// Heights we've already requested MnListDiffs for to avoid duplicates
    requested_blocks: BTreeSet<u32>,
    
    /// Track if we found expected quorums for reporting
    quorums_found: usize,
    windows_exhausted: usize,
}

/// Actions to take on a DKG window after processing a diff
enum WindowAction {
    /// Continue checking at the specified next block
    Advance(u32),
    /// Window is complete - quorum was found
    Complete,
    /// Window exhausted without finding quorum (reached end of mining window)
    Exhaust,
}

/// Manages masternode list synchronization.
pub struct MasternodeSyncManager {
    config: ClientConfig,
    sync_in_progress: bool,
    engine: Option<MasternodeListEngine>,
    /// Last time sync progress was made (for timeout detection)
    last_sync_progress: std::time::Instant,
    /// Terminal block manager for optimized sync
    terminal_block_manager: TerminalBlockManager,
    /// Number of diffs we're expecting to receive
    expected_diffs_count: u32,
    /// Number of diffs we've received so far
    received_diffs_count: u32,
    /// The height up to which we need the bulk diff before requesting individual diffs
    bulk_diff_target_height: Option<u32>,
    /// Whether we should request individual diffs after bulk diff completes
    pending_individual_diffs: Option<(u32, u32)>,
    /// Sync base height (when syncing from checkpoint)
    sync_base_height: u32,
    /// Range for smart fetch after bulk completes
    smart_fetch_range: Option<(u32, u32)>,
    /// DKG-based fetch state
    dkg_fetch_state: Option<DKGFetchState>,
    /// Map of requested heights to track which blocks we're expecting
    /// This helps us identify when server returns a different height than requested
    smart_requested_heights: HashSet<u32>,
    /// QRInfo timeout duration
    qr_info_timeout: Duration,
    /// Validation engine for comprehensive validation
    validation_engine: Option<ValidationEngine>,
    /// Chain lock validator
    chain_lock_validator: Option<ChainLockValidator>,
    /// Validation state manager
    validation_state: ValidationStateManager,
}

impl MasternodeSyncManager {
    /// Create a new masternode sync manager.
    pub fn new(config: &ClientConfig) -> Self {
        let engine = if config.enable_masternodes {
            let mut engine = MasternodeListEngine::default_for_network(config.network);
            // Feed genesis block hash at height 0
            if let Some(genesis_hash) = config.network.known_genesis_block_hash() {
                engine.feed_block_height(0, genesis_hash);
            }
            Some(engine)
        } else {
            None
        };

        // Create validation components if validation is enabled
        let (validation_engine, chain_lock_validator) = if config.validation_mode != crate::types::ValidationMode::None {
            let validation_config = ValidationConfig::default();
            let chain_lock_config = ChainLockValidationConfig::default();
            
            (
                Some(ValidationEngine::new(validation_config)),
                Some(ChainLockValidator::new(chain_lock_config)),
            )
        } else {
            (None, None)
        };
        
        Self {
            config: config.clone(),
            sync_in_progress: false,
            engine,
            last_sync_progress: std::time::Instant::now(),
            terminal_block_manager: TerminalBlockManager::new(config.network),
            expected_diffs_count: 0,
            received_diffs_count: 0,
            bulk_diff_target_height: None,
            pending_individual_diffs: None,
            sync_base_height: 0,
            smart_fetch_range: None,
            dkg_fetch_state: None,
            smart_requested_heights: HashSet::new(),
            qr_info_timeout: Duration::from_secs(30),
            validation_engine,
            chain_lock_validator,
            validation_state: ValidationStateManager::new(),
        }
    }

    /// Validate a terminal block against the chain and return its height if valid.
    /// Returns 0 if the block is not valid or not yet synced.
    async fn validate_terminal_block(
        &self,
        storage: &dyn StorageManager,
        terminal_height: u32,
        expected_hash: BlockHash,
        has_precalculated_data: bool,
    ) -> SyncResult<u32> {
        // Check if the terminal block exists in our chain
        match storage.get_header(terminal_height).await {
            Ok(Some(header)) => {
                if header.block_hash() == expected_hash {
                    if has_precalculated_data {
                        tracing::info!(
                            "Using terminal block at height {} with pre-calculated masternode data as base for sync",
                            terminal_height
                        );
                    } else {
                        tracing::info!(
                            "Using terminal block at height {} as base for masternode sync (no pre-calculated data)",
                            terminal_height
                        );
                    }
                    Ok(terminal_height)
                } else {
                    let msg = if has_precalculated_data {
                        "Terminal block hash mismatch at height {} (with pre-calculated data) - falling back to genesis"
                    } else {
                        "Terminal block hash mismatch at height {} (without pre-calculated data) - falling back to genesis"
                    };
                    tracing::warn!(msg, terminal_height);
                    Ok(0)
                }
            }
            Ok(None) => {
                tracing::info!(
                    "Terminal block at height {} not yet synced - starting from genesis",
                    terminal_height
                );
                Ok(0)
            }
            Err(e) => {
                Err(SyncError::Storage(format!("Failed to get terminal block header: {}", e)))
            }
        }
    }

    /// Validate a terminal block against the chain and return its height if valid.
    /// This version accounts for sync base height when querying storage.
    /// Returns 0 if the block is not valid or not yet synced.
    async fn validate_terminal_block_with_base(
        &self,
        storage: &dyn StorageManager,
        terminal_height: u32,
        expected_hash: BlockHash,
        has_precalculated_data: bool,
        sync_base_height: u32,
    ) -> SyncResult<u32> {
        // Skip terminal blocks that are before our sync base
        if terminal_height < sync_base_height {
            tracing::info!(
                "Terminal block at height {} is before sync base height {}, skipping",
                terminal_height,
                sync_base_height
            );
            return Ok(0);
        }

        // Convert blockchain height to storage height
        let storage_height = terminal_height - sync_base_height;

        // Check if the terminal block exists in our chain
        match storage.get_header(storage_height).await {
            Ok(Some(header)) => {
                if header.block_hash() == expected_hash {
                    if has_precalculated_data {
                        tracing::info!(
                            "Using terminal block at blockchain height {} (storage height {}) with pre-calculated masternode data as base for sync",
                            terminal_height,
                            storage_height
                        );
                    } else {
                        tracing::info!(
                            "Using terminal block at blockchain height {} (storage height {}) as base for masternode sync (no pre-calculated data)",
                            terminal_height,
                            storage_height
                        );
                    }
                    Ok(terminal_height)
                } else {
                    let msg = if has_precalculated_data {
                        "Terminal block hash mismatch at blockchain height {} (storage height {}) (with pre-calculated data) - falling back to genesis"
                    } else {
                        "Terminal block hash mismatch at blockchain height {} (storage height {}) (without pre-calculated data) - falling back to genesis"
                    };
                    tracing::warn!(msg, terminal_height, storage_height);
                    Ok(0)
                }
            }
            Ok(None) => {
                tracing::info!(
                    "Terminal block at blockchain height {} (storage height {}) not yet synced - starting from genesis",
                    terminal_height,
                    storage_height
                );
                Ok(0)
            }
            Err(e) => {
                Err(SyncError::Storage(format!("Failed to get terminal block header at storage height {}: {}", storage_height, e)))
            }
        }
    }

    /// Handle an MnListDiff message during masternode synchronization.
    /// Returns true if the message was processed and sync should continue, false if sync is complete.
    pub async fn handle_mnlistdiff_message(
        &mut self,
        diff: MnListDiff,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<bool> {
        if !self.sync_in_progress {
            tracing::warn!(
                "📨 Received MnListDiff but masternode sync is not in progress - ignoring message"
            );
            return Ok(true);
        }

        self.last_sync_progress = std::time::Instant::now();
        
        // Store diff data before moving diff
        let diff_block_hash = diff.block_hash;
        let (diff_height, new_quorums) = {
            let storage_height = storage
                .get_header_height_by_hash(&diff_block_hash)
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get diff height: {}", e)))?
                .ok_or_else(|| SyncError::Storage("Diff block not found".to_string()))?;
            
            // The height from storage is already the absolute blockchain height
            let blockchain_height = storage_height;
            
            tracing::debug!(
                "MnListDiff height: blockchain_height={} (from storage)",
                blockchain_height
            );
            
            let quorums: Vec<LLMQType> = diff.new_quorums.iter()
                .map(|q| q.llmq_type)
                .collect();
            
            (blockchain_height, quorums)
        };

        // Process the diff with fallback to genesis if incremental diff fails
        match self.process_masternode_diff(diff, storage).await {
            Ok(()) => {
                // Success - diff applied
                // Handle smart fetch processing if needed
                if self.dkg_fetch_state.is_some() {
                    if let Some((start, end)) = self.smart_fetch_range {
                        if diff_height >= start && diff_height <= end {
                            // Check if this diff is for a height we specifically requested
                            if self.smart_requested_heights.contains(&diff_height) {
                                tracing::debug!("Received expected smart fetch diff for height {}", diff_height);
                                // Remove from requested set
                                self.smart_requested_heights.remove(&diff_height);
                                // Update smart fetch state based on quorums found
                                self.update_smart_fetch_state(diff_height, &new_quorums, storage, network).await?;
                            } else {
                                tracing::warn!(
                                    "Received diff for height {} but we didn't request it (requested: {:?})",
                                    diff_height,
                                    self.smart_requested_heights
                                );
                                // Don't update smart fetch state for unrequested diffs
                                // This prevents the loop where we keep getting the same bulk height
                            }
                        }
                    }
                }
            }
            Err(e) if e.to_string().contains("MissingStartMasternodeList") => {
                tracing::warn!("Incremental masternode diff failed with MissingStartMasternodeList, retrying from genesis");

                // Reset sync state but keep in progress
                self.last_sync_progress = std::time::Instant::now();
                // Reset counters since we're starting over
                self.expected_diffs_count = 0;
                self.received_diffs_count = 0;
                self.bulk_diff_target_height = None;
                self.pending_individual_diffs = None;
                // Reset smart fetch state to prevent infinite loop
                self.smart_fetch_range = None;
                self.dkg_fetch_state = None;
                self.smart_requested_heights.clear();

                // Get current height again - storage returns storage height, need blockchain height
                let storage_height = storage
                    .get_tip_height()
                    .await
                    .map_err(|e| {
                        SyncError::Storage(format!(
                            "Failed to get current height for fallback: {}",
                            e
                        ))
                    })?
                    .unwrap_or(0);
                
                // The height from storage is already the absolute blockchain height
                let current_height = storage_height;

                // Request full diffs from genesis with last 8 blocks individually
                tracing::info!(
                    "Requesting fallback masternode diffs from genesis to height {} (storage height {} + sync base {})",
                    current_height,
                    storage_height,
                    self.sync_base_height
                );
                self.request_masternode_diffs_for_chainlock_validation(network, storage, 0, current_height).await?;

                // Return true to continue waiting for the new response
                return Ok(true);
            }
            Err(e) => {
                // Other error - propagate it
                return Err(e);
            }
        }

        // Increment received diffs count
        self.received_diffs_count += 1;
        
        // Check if we've received all expected diffs
        if self.expected_diffs_count > 0 && self.received_diffs_count >= self.expected_diffs_count {
            // If we're in smart fetch mode, don't complete sync here - let smart fetch handle its own completion
            if self.dkg_fetch_state.is_some() {
                tracing::debug!(
                    "In smart fetch mode - received {}/{} expected diffs, continuing with DKG-based fetch",
                    self.received_diffs_count, self.expected_diffs_count
                );
                // Reset counters for next batch but keep sync in progress
                self.expected_diffs_count = 0;
                self.received_diffs_count = 0;
                return Ok(true); // Continue with smart fetch
            }
            
            // Handle transition from bulk to smart fetch
            if let Some(bulk_target) = self.bulk_diff_target_height {
                if diff_height == bulk_target {
                    // Bulk fetch complete, start smart fetch
                    if let Some((start, end)) = self.smart_fetch_range {
                        tracing::info!("Bulk fetch complete at height {}, starting smart fetch for range {}-{}", 
                            diff_height, start, end);
                        
                        // Log engine state before transitioning to smart fetch
                        if let Some(engine) = &self.engine {
                            tracing::info!("Engine state before smart fetch transition:");
                            tracing::info!("  - Block container size: {}", engine.block_container.known_block_count());
                            tracing::info!("  - Masternode lists count: {}", engine.masternode_lists.len());
                            if let Some(latest_list) = engine.latest_masternode_list() {
                                tracing::info!("  - Latest masternode list height: {}", 
                                    engine.masternode_lists.last_key_value()
                                        .map(|(h, _)| *h)
                                        .unwrap_or(0)
                                );
                            }
                            
                            // Check if the bulk fetch target height is in the engine
                            // diff_height is already the blockchain height, get_header expects storage index
                            let storage_index = if diff_height >= self.sync_base_height {
                                diff_height - self.sync_base_height
                            } else {
                                0
                            };
                            if let Some(header) = storage.get_header(storage_index).await
                                .map_err(|e| SyncError::Storage(format!("Failed to get bulk header: {}", e)))? 
                            {
                                let bulk_hash = header.block_hash();
                                if let Some(engine_height) = engine.block_container.get_height(&bulk_hash) {
                                    tracing::info!("  - Bulk target hash {} found at engine height {}", bulk_hash, engine_height);
                                } else {
                                    tracing::warn!("  - Bulk target hash {} NOT found in engine block container!", bulk_hash);
                                }
                            }
                        }
                        
                        use dashcore::sml::llmq_type::network::NetworkLLMQExt;
                        tracing::debug!("Calculating DKG windows for blockchain height range {}-{} (sync base: {})", 
                            start, end, self.sync_base_height);
                        let mut all_windows = self.config.network.get_all_dkg_windows(start, end);
                        
                        // Filter out windows that would require masternode lists from before the bulk endpoint
                        let original_window_count: usize = all_windows.values().map(|v| v.len()).sum();
                        
                        // Remove windows where any block in the mining range is below start
                        all_windows.retain(|mining_start, windows| {
                            // Keep only if the mining_start is at or after our bulk endpoint
                            let keep = *mining_start >= start;
                            if !keep {
                                tracing::debug!(
                                    "Filtering out {} DKG windows at mining_start {} (before bulk endpoint {})",
                                    windows.len(), mining_start, start
                                );
                            }
                            keep
                        });
                        
                        // Also filter individual windows within each group
                        for windows in all_windows.values_mut() {
                            windows.retain(|window| {
                                // Keep only if all blocks in the mining window are >= start
                                let keep = window.mining_start >= start;
                                if !keep {
                                    tracing::debug!(
                                        "Filtering out {} DKG window with mining range {}-{} (before bulk endpoint {})",
                                        window.llmq_type, window.mining_start, window.mining_end, start
                                    );
                                }
                                keep
                            });
                        }
                        
                        let filtered_window_count: usize = all_windows.values().map(|v| v.len()).sum();
                        if filtered_window_count < original_window_count {
                            tracing::info!(
                                "Filtered DKG windows from {} to {} (removed {} that would require pre-bulk data)",
                                original_window_count, filtered_window_count, 
                                original_window_count - filtered_window_count
                            );
                        }
                        
                        tracing::info!("Calculated {} DKG windows for smart fetch range {}-{}", 
                            filtered_window_count, start, end);
                        
                        self.dkg_fetch_state = Some(DKGFetchState {
                            pending_windows: all_windows,
                            active_windows: Vec::new(),
                            completed_cycles: BTreeSet::new(),
                            requested_blocks: BTreeSet::new(),
                            quorums_found: 0,
                            windows_exhausted: 0,
                        });
                        self.fetch_next_dkg_blocks(network, storage).await?;
                        
                        // Reset counters for smart fetch
                        self.expected_diffs_count = 0;
                        self.received_diffs_count = 0;
                        return Ok(true); // Continue with smart fetch
                    }
                    self.bulk_diff_target_height = None;
                }
            }
            
            // With smart algorithm, pending_individual_diffs is no longer used
            // The smart fetch will be handled in smart_fetch_range
            {
                tracing::info!("Received all expected masternode diffs ({}/{}), completing sync", 
                    self.received_diffs_count, self.expected_diffs_count);
                self.sync_in_progress = false;
                self.expected_diffs_count = 0;
                self.received_diffs_count = 0;
                self.bulk_diff_target_height = None;
                Ok(false)  // Sync complete
            }
        } else if self.expected_diffs_count > 0 {
            tracing::debug!("Received masternode diff {}/{}, waiting for more", 
                self.received_diffs_count, self.expected_diffs_count);
            Ok(true)  // Continue waiting for more diffs
        } else {
            // Check if smart fetch is active before completing sync
            if self.dkg_fetch_state.is_some() {
                // Smart fetch is active, don't complete sync yet
                tracing::debug!("Smart fetch active, continuing sync");
                Ok(true)
            } else {
                // Legacy behavior: single diff completes sync
                tracing::info!("Masternode sync complete (single diff mode)");
                self.sync_in_progress = false;
                Ok(false)
            }
        }
    }

    /// Check if a sync timeout has occurred and handle recovery.
    pub async fn check_sync_timeout(
        &mut self,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<bool> {
        if !self.sync_in_progress {
            return Ok(false);
        }

        if self.last_sync_progress.elapsed() > std::time::Duration::from_secs(10) {
            tracing::warn!("📊 No masternode sync progress for 10+ seconds, re-sending request");

            // Get current storage height
            let storage_height = storage
                .get_tip_height()
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get current height: {}", e)))?
                .unwrap_or(0);

            // The height from storage is already the absolute blockchain height
            let current_blockchain_height = storage_height;
            
            tracing::debug!(
                "Timeout recovery: blockchain_height={} (from storage)",
                current_blockchain_height
            );

            let last_masternode_height =
                match storage.load_masternode_state().await.map_err(|e| {
                    SyncError::Storage(format!("Failed to load masternode state: {}", e))
                })? {
                    Some(state) => state.last_height,
                    None => 0,
                };

            self.request_masternode_diffs_for_chainlock_validation(network, storage, last_masternode_height, current_blockchain_height)
                .await?;
            self.last_sync_progress = std::time::Instant::now();

            return Ok(true);
        }

        Ok(false)
    }

    /// Start synchronizing masternodes with the effective chain height.
    /// This is used when syncing from a checkpoint where storage height != blockchain height.
    pub async fn start_sync_with_height(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
        effective_height: u32,
        sync_base_height: u32,
    ) -> SyncResult<bool> {
        if self.sync_in_progress {
            return Err(SyncError::SyncInProgress);
        }

        // Skip if masternodes are disabled
        if !self.config.enable_masternodes || self.engine.is_none() {
            return Ok(false);
        }

        tracing::info!("Starting masternode list synchronization with effective height {}", effective_height);

        // Store the sync base height for later use
        self.sync_base_height = sync_base_height;

        // Use the provided effective height instead of storage height
        let current_height = effective_height;

        // Get last known masternode height
        let last_masternode_height =
            match storage.load_masternode_state().await.map_err(|e| {
                SyncError::Storage(format!("Failed to load masternode state: {}", e))
            })? {
                Some(state) => state.last_height,
                None => 0,
            };

        // If we're already up to date, no need to sync
        if last_masternode_height >= current_height {
            tracing::info!(
                "Masternode list already synced to current height (last: {}, current: {})",
                last_masternode_height,
                current_height
            );
            return Ok(false);
        }

        tracing::info!(
            "Starting masternode sync: last_height={}, current_height={}",
            last_masternode_height,
            current_height
        );

        // Set sync state
        self.sync_in_progress = true;
        self.last_sync_progress = std::time::Instant::now();
        self.expected_diffs_count = 0;
        self.received_diffs_count = 0;
        self.bulk_diff_target_height = None;
        self.pending_individual_diffs = None;

        // Check if we can use a terminal block as a base for optimization
        let base_height = if last_masternode_height > 0 {
            // We have a previous state, try incremental sync
            tracing::info!(
                "Attempting incremental masternode diff from height {} to {}",
                last_masternode_height,
                current_height
            );
            last_masternode_height
        } else {
            // No previous state - check if we can start from a terminal block with pre-calculated data
            if let Some(terminal_data) = self
                .terminal_block_manager
                .find_best_terminal_block_with_data(current_height)
                .cloned()
            {
                // We have pre-calculated masternode data for this terminal block!
                self.load_precalculated_masternode_data(&terminal_data, storage).await?
            } else if let Some(terminal_block) =
                self.terminal_block_manager.find_best_base_terminal_block(current_height)
            {
                // No pre-calculated data, but we have a terminal block reference
                self.validate_terminal_block_with_base(
                    storage,
                    terminal_block.height,
                    terminal_block.block_hash,
                    false,
                    sync_base_height,
                )
                .await?
            } else {
                tracing::info!(
                    "No suitable terminal block found - requesting full diff from genesis to height {}",
                    current_height
                );
                0
            }
        };

        // Request masternode list diffs to ensure we have lists for ChainLock validation
        self.request_masternode_diffs_for_chainlock_validation_with_base(network, storage, base_height, current_height, sync_base_height).await?;

        Ok(true) // Sync started
    }

    /// Start synchronizing masternodes (initialize the sync state).
    /// This replaces the old sync method but doesn't loop for messages.
    pub async fn start_sync(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<bool> {
        if self.sync_in_progress {
            return Err(SyncError::SyncInProgress);
        }

        // Skip if masternodes are disabled
        if !self.config.enable_masternodes || self.engine.is_none() {
            return Ok(false);
        }

        tracing::info!("Starting masternode list synchronization");

        // Get current header height
        let current_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get current height: {}", e)))?
            .unwrap_or(0);

        // Get last known masternode height
        let last_masternode_height =
            match storage.load_masternode_state().await.map_err(|e| {
                SyncError::Storage(format!("Failed to load masternode state: {}", e))
            })? {
                Some(state) => state.last_height,
                None => 0,
            };

        // If we're already up to date, no need to sync
        if last_masternode_height >= current_height {
            tracing::info!(
                "Masternode list already synced to current height (last: {}, current: {})",
                last_masternode_height,
                current_height
            );
            return Ok(false);
        }

        tracing::info!(
            "Starting masternode sync: last_height={}, current_height={}",
            last_masternode_height,
            current_height
        );

        // Set sync state
        self.sync_in_progress = true;
        self.last_sync_progress = std::time::Instant::now();
        self.expected_diffs_count = 0;
        self.received_diffs_count = 0;
        self.bulk_diff_target_height = None;
        self.pending_individual_diffs = None;

        // Check if we can use a terminal block as a base for optimization
        let base_height = if last_masternode_height > 0 {
            // We have a previous state, try incremental sync
            tracing::info!(
                "Attempting incremental masternode diff from height {} to {}",
                last_masternode_height,
                current_height
            );
            last_masternode_height
        } else {
            // No previous state - check if we can start from a terminal block with pre-calculated data
            if let Some(terminal_data) = self
                .terminal_block_manager
                .find_best_terminal_block_with_data(current_height)
                .cloned()
            {
                // We have pre-calculated masternode data for this terminal block!
                self.load_precalculated_masternode_data(&terminal_data, storage).await?
            } else if let Some(terminal_block) =
                self.terminal_block_manager.find_best_base_terminal_block(current_height)
            {
                // No pre-calculated data, but we have a terminal block reference
                self.validate_terminal_block_with_base(
                    storage,
                    terminal_block.height,
                    terminal_block.block_hash,
                    false,
                    self.sync_base_height,
                )
                .await?
            } else {
                tracing::info!(
                    "No suitable terminal block found - requesting full diff from genesis to height {}",
                    current_height
                );
                0
            }
        };

        // Request masternode list diffs to ensure we have lists for ChainLock validation
        self.request_masternode_diffs_for_chainlock_validation(network, storage, base_height, current_height).await?;

        Ok(true) // Sync started
    }

    /// Load pre-calculated masternode data from a terminal block into the engine
    async fn load_precalculated_masternode_data(
        &mut self,
        terminal_data: &crate::sync::terminal_block_data::TerminalBlockMasternodeState,
        storage: &dyn StorageManager,
    ) -> SyncResult<u32> {
        if let Ok(terminal_block_hash) = terminal_data.get_block_hash() {
            let validated_height = self
                .validate_terminal_block(storage, terminal_data.height, terminal_block_hash, true)
                .await?;

            if validated_height > 0 {
                tracing::info!(
                    "Terminal block has {} masternodes in pre-calculated data",
                    terminal_data.masternode_count
                );

                // Load the pre-calculated masternode list into the engine
                if let Some(engine) = &mut self.engine {
                    // Convert stored masternode entries to MasternodeListEntry
                    let mut masternodes = BTreeMap::new();

                    for stored_mn in &terminal_data.masternode_list {
                        // Parse ProTxHash
                        let pro_tx_hash_bytes = match hex::decode(&stored_mn.pro_tx_hash) {
                            Ok(bytes) if bytes.len() == 32 => {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&bytes);
                                arr
                            }
                            _ => {
                                tracing::warn!(
                                    "Invalid ProTxHash for masternode: {}",
                                    stored_mn.pro_tx_hash
                                );
                                continue;
                            }
                        };
                        let pro_tx_hash = ProTxHash::from_byte_array(pro_tx_hash_bytes);

                        // Parse service address
                        let service_address = match SocketAddr::from_str(&stored_mn.service) {
                            Ok(addr) => addr,
                            Err(e) => {
                                tracing::warn!(
                                    "Invalid service address for masternode {}: {}",
                                    stored_mn.pro_tx_hash,
                                    e
                                );
                                continue;
                            }
                        };

                        // Parse BLS public key
                        let operator_public_key_bytes =
                            match hex::decode(&stored_mn.pub_key_operator) {
                                Ok(bytes) if bytes.len() == 48 => bytes,
                                _ => {
                                    tracing::warn!(
                                        "Invalid BLS public key for masternode: {}",
                                        stored_mn.pro_tx_hash
                                    );
                                    continue;
                                }
                            };
                        let operator_public_key =
                            match BLSPublicKey::try_from(operator_public_key_bytes.as_slice()) {
                                Ok(key) => key,
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to parse BLS public key for masternode {}: {:?}",
                                        stored_mn.pro_tx_hash,
                                        e
                                    );
                                    continue;
                                }
                            };

                        // Parse voting key hash from the voting address
                        let key_id_voting = match Address::from_str(&stored_mn.voting_address) {
                            Ok(addr) => match addr.payload() {
                                Payload::PubkeyHash(hash) => *hash,
                                _ => {
                                    tracing::warn!("Voting address is not a P2PKH address for masternode {}: {}", stored_mn.pro_tx_hash, stored_mn.voting_address);
                                    continue;
                                }
                            },
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to parse voting address for masternode {}: {:?}",
                                    stored_mn.pro_tx_hash,
                                    e
                                );
                                continue;
                            }
                        };

                        // Determine masternode type
                        let mn_type = match stored_mn.n_type {
                            0 => EntryMasternodeType::Regular,
                            1 => EntryMasternodeType::HighPerformance {
                                platform_http_port: 0,                     // Not available in stored data
                                platform_node_id: PubkeyHash::all_zeros(), // Not available in stored data
                            },
                            _ => {
                                tracing::warn!(
                                    "Unknown masternode type {} for masternode: {}",
                                    stored_mn.n_type,
                                    stored_mn.pro_tx_hash
                                );
                                continue;
                            }
                        };

                        // Create MasternodeListEntry
                        let entry = MasternodeListEntry {
                            version: 2, // Latest version
                            pro_reg_tx_hash: pro_tx_hash,
                            confirmed_hash: None, // Not available in stored data
                            service_address,
                            operator_public_key,
                            key_id_voting,
                            is_valid: stored_mn.is_valid,
                            mn_type,
                        };

                        // Convert to qualified entry
                        let qualified_entry = QualifiedMasternodeListEntry::from(entry);
                        masternodes.insert(pro_tx_hash, qualified_entry);
                    }

                    // Parse merkle root
                    let merkle_root_bytes = match hex::decode(&terminal_data.merkle_root_mn_list) {
                        Ok(bytes) if bytes.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            arr
                        }
                        _ => {
                            tracing::warn!("Invalid merkle root in terminal data");
                            [0u8; 32]
                        }
                    };
                    let merkle_root = MerkleRootMasternodeList::from_byte_array(merkle_root_bytes);

                    // Build masternode list
                    let masternode_list = MasternodeList::build(
                        masternodes,
                        BTreeMap::new(), // No quorum data in terminal blocks
                        terminal_block_hash,
                        terminal_data.height,
                    )
                    .with_merkle_roots(merkle_root, None)
                    .build();

                    // Insert into engine
                    engine.masternode_lists.insert(terminal_data.height, masternode_list);
                    engine.feed_block_height(terminal_data.height, terminal_block_hash);

                    tracing::info!(
                        "Successfully loaded {} masternodes from terminal block at height {}",
                        terminal_data.masternode_list.len(),
                        terminal_data.height
                    );
                }
            }
            Ok(validated_height)
        } else {
            tracing::warn!(
                "Failed to get terminal block hash at height {} - falling back to genesis",
                terminal_data.height
            );
            Ok(0)
        }
    }

    /// Request masternode list diff.
    async fn request_masternode_diff(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &dyn StorageManager,
        base_height: u32,
        current_height: u32,
    ) -> SyncResult<()> {
        // When syncing from a checkpoint, we need to convert blockchain heights to storage heights
        let sync_base = self.sync_base_height;
        
        // Get base block hash
        let base_block_hash = if base_height == 0 {
            // Always use genesis hash for height 0, regardless of sync base
            self.config
                .network
                .known_genesis_block_hash()
                .ok_or_else(|| SyncError::Network("No genesis hash for network".to_string()))?
        } else if base_height < sync_base {
            // Base height is before our sync checkpoint - we can't fetch it from storage
            return Err(SyncError::Storage(format!(
                "Cannot request diff with base height {} - it's before sync checkpoint {}",
                base_height, sync_base
            )));
        } else {
            // Convert blockchain height to storage height
            let storage_base_height = base_height - sync_base;
            storage
                .get_header(storage_base_height)
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get base header at blockchain height {} (storage height {}): {}", base_height, storage_base_height, e)))?
                .ok_or_else(|| SyncError::Storage(format!("Base header not found at blockchain height {} (storage height {})", base_height, storage_base_height)))?
                .block_hash()
        };

        // Get current block hash
        if current_height < sync_base {
            return Err(SyncError::Storage(format!(
                "Cannot request diff with current height {} - it's before sync checkpoint {}",
                current_height, sync_base
            )));
        }
        
        let storage_current_height = current_height - sync_base;
        let current_block_hash = storage
            .get_header(storage_current_height)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get current header at blockchain height {} (storage height {}): {}", current_height, storage_current_height, e)))?
            .ok_or_else(|| SyncError::Storage(format!("Current header not found at blockchain height {} (storage height {})", current_height, storage_current_height)))?
            .block_hash();

        let get_mn_list_diff = GetMnListDiff {
            base_block_hash,
            block_hash: current_block_hash,
        };

        network
            .send_message(NetworkMessage::GetMnListD(get_mn_list_diff))
            .await
            .map_err(|e| SyncError::Network(format!("Failed to send GetMnListDiff: {}", e)))?;

        tracing::debug!(
            "Requested masternode list diff from {} to {}",
            base_height,
            current_height
        );

        Ok(())
    }

    /// Request masternode diffs to ensure we have lists needed for ChainLock validation.
    /// This requests multiple diffs to populate masternode lists at recent heights.
    /// 
    /// # Arguments
    /// * `base_height` - Starting blockchain height (not storage height)
    /// * `target_height` - Target blockchain height (not storage height)
    async fn request_masternode_diffs_for_chainlock_validation(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &dyn StorageManager,
        base_height: u32,
        target_height: u32,
    ) -> SyncResult<()> {
        // Now uses smart algorithm for ALL ranges
        self.request_masternode_diffs_smart(network, storage, base_height, target_height).await
    }

    /// Request masternode list diff with checkpoint base height support.
    async fn request_masternode_diff_with_base(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &dyn StorageManager,
        base_height: u32,
        current_height: u32,
        sync_base_height: u32,
    ) -> SyncResult<()> {
        // Convert blockchain heights to storage heights
        let storage_base_height = if base_height >= sync_base_height {
            base_height - sync_base_height
        } else {
            0
        };
        
        let storage_current_height = if current_height >= sync_base_height {
            current_height - sync_base_height
        } else {
            return Err(SyncError::InvalidState(format!(
                "Current height {} is less than sync base height {}",
                current_height, sync_base_height
            )));
        };
        
        // Verify the storage height actually exists
        let storage_tip = storage.get_tip_height().await
            .map_err(|e| SyncError::Storage(format!("Failed to get storage tip: {}", e)))?
            .unwrap_or(0);
        
        if storage_current_height > storage_tip {
            return Err(SyncError::InvalidState(format!(
                "Requested storage height {} exceeds storage tip {} (blockchain height {} with sync base {})",
                storage_current_height, storage_tip, current_height, sync_base_height
            )));
        }
        
        tracing::debug!(
            "MnListDiff request heights - blockchain: {}-{}, storage: {}-{}, tip: {}",
            base_height, current_height, storage_base_height, storage_current_height, storage_tip
        );

        // Get base block hash
        let base_block_hash = if base_height == 0 {
            self.config
                .network
                .known_genesis_block_hash()
                .ok_or_else(|| SyncError::Network("No genesis hash for network".to_string()))?
        } else {
            storage
                .get_header(storage_base_height)
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get base header at storage height {}: {}", storage_base_height, e)))?
                .ok_or_else(|| SyncError::Storage(format!("Base header not found at storage height {}", storage_base_height)))?
                .block_hash()
        };

        // Get current block hash
        let current_block_hash = storage
            .get_header(storage_current_height)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get current header at storage height {}: {}", storage_current_height, e)))?
            .ok_or_else(|| SyncError::Storage(format!("Current header not found at storage height {}", storage_current_height)))?
            .block_hash();

        let get_mn_list_diff = GetMnListDiff {
            base_block_hash,
            block_hash: current_block_hash,
        };

        network
            .send_message(NetworkMessage::GetMnListD(get_mn_list_diff))
            .await
            .map_err(|e| SyncError::Network(format!("Failed to send GetMnListDiff: {}", e)))?;

        tracing::info!(
            "Requested masternode list diff from blockchain height {} (storage {}) to {} (storage {})",
            base_height,
            storage_base_height,
            current_height,
            storage_current_height
        );

        Ok(())
    }

    /// Request masternode diffs with checkpoint base height support.
    async fn request_masternode_diffs_for_chainlock_validation_with_base(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &dyn StorageManager,
        base_height: u32,
        target_height: u32,
        sync_base_height: u32,
    ) -> SyncResult<()> {
        // Store sync base height for later use
        self.sync_base_height = sync_base_height;
        
        // Use the smart algorithm for all ranges
        self.request_masternode_diffs_smart(network, storage, base_height, target_height).await
    }

    /// Process received masternode list diff.
    async fn process_masternode_diff(
        &mut self,
        diff: MnListDiff,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
        // Log what diff we received
        tracing::info!(
            "Processing masternode diff: base_block_hash={}, block_hash={}, new_masternodes={}, deleted_masternodes={}",
            diff.base_block_hash,
            diff.block_hash,
            diff.new_masternodes.len(),
            diff.deleted_masternodes.len()
        );
        
        // Additional logging for smart fetch debugging
        if self.dkg_fetch_state.is_some() && self.smart_fetch_range.is_some() {
            tracing::debug!("Smart fetch diff processing - checking engine state for base hash");
            if let Some(engine) = &self.engine {
                if let Some(base_height) = engine.block_container.get_height(&diff.base_block_hash) {
                    tracing::debug!("  - Base block hash {} found in engine at height {}", diff.base_block_hash, base_height);
                    if engine.masternode_lists.contains_key(&base_height) {
                        tracing::debug!("  - Masternode list exists at base height {}", base_height);
                    } else {
                        tracing::warn!("  - Masternode list NOT found at base height {}!", base_height);
                    }
                } else {
                    tracing::warn!("  - Base block hash {} NOT found in engine block container!", diff.base_block_hash);
                }
            }
        }
        
        let engine = self.engine.as_mut().ok_or_else(|| {
            SyncError::Validation("Masternode engine not initialized".to_string())
        })?;

        let _target_block_hash = diff.block_hash;

        // Get tip height first as it's needed later
        let tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?
            .unwrap_or(0);

        // Only feed the block headers that are actually needed by the masternode engine
        let target_block_hash = diff.block_hash;
        let base_block_hash = diff.base_block_hash;

        // Special case: Zero hash indicates empty masternode list (common in regtest)
        let zero_hash = BlockHash::all_zeros();
        let is_zero_hash = target_block_hash == zero_hash;

        if is_zero_hash {
            tracing::debug!("Target block hash is zero - likely empty masternode list in regtest");
        } else {
            // Feed target block hash
            if let Some(storage_height) = storage
                .get_header_height_by_hash(&target_block_hash)
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to lookup target hash: {}", e)))?
            {
                // The height from storage is already the absolute blockchain height
                let blockchain_height = storage_height;
                engine.feed_block_height(blockchain_height, target_block_hash);
                tracing::debug!(
                    "Fed target block hash {} at blockchain height {} (storage height {})",
                    target_block_hash,
                    blockchain_height,
                    storage_height
                );
            } else {
                return Err(SyncError::Storage(format!(
                    "Target block hash {} not found in storage",
                    target_block_hash
                )));
            }

            // Feed base block hash
            // Special case for genesis block to avoid checkpoint-related lookup issues
            if base_block_hash == self.config.network.known_genesis_block_hash().ok_or_else(|| {
                SyncError::Network("No genesis hash for network".to_string())
            })? {
                // Genesis is always at height 0
                engine.feed_block_height(0, base_block_hash);
                tracing::debug!("Fed genesis block hash {} at height 0", base_block_hash);
            } else {
                // For non-genesis blocks, look up the height
                if let Some(storage_height) = storage
                    .get_header_height_by_hash(&base_block_hash)
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to lookup base hash: {}", e)))?
                {
                    // The height from storage is already the absolute blockchain height
                    let blockchain_height = storage_height;
                    engine.feed_block_height(blockchain_height, base_block_hash);
                    tracing::debug!(
                        "Fed base block hash {} at blockchain height {} (storage height {})",
                        base_block_hash,
                        blockchain_height,
                        storage_height
                    );
                }
            }

            // Calculate start_height for filtering redundant submissions
            // Feed last 1000 headers or from base height, whichever is more recent
            let start_height = if base_block_hash == self.config.network.known_genesis_block_hash().ok_or_else(|| {
                SyncError::Network("No genesis hash for network".to_string())
            })? {
                // For genesis, start from 0 (but limited by what's in storage)
                0
            } else if let Some(storage_base_height) = storage
                .get_header_height_by_hash(&base_block_hash)
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to lookup base hash: {}", e)))?
            {
                storage_base_height.saturating_sub(100) // Include some headers before base (storage height)
            } else {
                tip_height.saturating_sub(1000)
            };

            // Feed any quorum hashes from new_quorums that are block hashes
            for quorum in &diff.new_quorums {
                // Note: quorum_hash is not necessarily a block hash, so we check if it exists
                if let Some(storage_quorum_height) =
                    storage.get_header_height_by_hash(&quorum.quorum_hash).await.map_err(|e| {
                        SyncError::Storage(format!("Failed to lookup quorum hash: {}", e))
                    })?
                {
                    // Only feed blocks at or after start_height to avoid redundant submissions
                    if storage_quorum_height >= start_height {
                        // The height from storage is already the absolute blockchain height
                        let blockchain_quorum_height = storage_quorum_height;
                        engine.feed_block_height(blockchain_quorum_height, quorum.quorum_hash);
                        tracing::debug!(
                            "Fed quorum hash {} at blockchain height {} (storage height {})",
                            quorum.quorum_hash,
                            blockchain_quorum_height,
                            storage_quorum_height
                        );
                    } else {
                        tracing::trace!(
                            "Skipping quorum hash {} at storage height {} (before start_height {})",
                            quorum.quorum_hash,
                            storage_quorum_height,
                            start_height
                        );
                    }
                }
            }

            // Feed a reasonable range of recent headers for validation purposes
            // The engine may need recent headers for various validations

            if start_height < tip_height {
                tracing::debug!(
                    "Feeding headers from {} to {} to masternode engine",
                    start_height,
                    tip_height
                );
                let headers =
                    storage.get_headers_batch(start_height, tip_height).await.map_err(|e| {
                        SyncError::Storage(format!("Failed to batch load headers: {}", e))
                    })?;

                for (storage_height, header) in headers {
                    // The height from storage is already the absolute blockchain height
                    let blockchain_height = storage_height;
                    engine.feed_block_height(blockchain_height, header.block_hash());
                }
            }
        }

        // Special handling for regtest: skip empty diffs
        if self.config.network == dashcore::Network::Regtest {
            // In regtest, masternode diffs might be empty, which is normal
            if is_zero_hash || (diff.merkle_hashes.is_empty() && diff.new_masternodes.is_empty()) {
                tracing::info!(
                    "Skipping empty masternode diff in regtest - no masternodes configured"
                );

                // Store empty masternode state to mark sync as complete
                let masternode_state = MasternodeState {
                    last_height: tip_height,
                    engine_state: Vec::new(), // Empty state for regtest
                    last_update: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    terminal_block_hash: None,
                };

                storage.store_masternode_state(&masternode_state).await.map_err(|e| {
                    SyncError::Storage(format!("Failed to store masternode state: {}", e))
                })?;

                tracing::info!("Masternode synchronization completed (empty in regtest)");
                return Ok(());
            }
        }

        // Calculate the target blockchain height before applying the diff
        let target_blockchain_height = if let Some(height) = storage
            .get_header_height_by_hash(&diff.block_hash)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to lookup target block height: {}", e)))?
        {
            height
        } else {
            return Err(SyncError::Storage(format!(
                "Target block hash {} not found in storage before applying diff",
                diff.block_hash
            )));
        };

        tracing::debug!(
            "Applying masternode diff with explicit target height: blockchain_height={}, block_hash={}",
            target_blockchain_height,
            diff.block_hash
        );

        // Store the diff block hash for later use
        let diff_block_hash = diff.block_hash;

        // Apply the diff to our engine with explicit height
        engine.apply_diff(diff, Some(target_blockchain_height), true, None)
            .map_err(|e| {
                // Provide more context for IncompleteMnListDiff in regtest
                if self.config.network == dashcore::Network::Regtest && e.to_string().contains("IncompleteMnListDiff") {
                    SyncError::Validation(format!(
                        "Failed to apply masternode diff in regtest (this is normal if no masternodes are configured): {:?}", e
                    ))
                } else {
                    SyncError::Validation(format!("Failed to apply masternode diff: {:?}", e))
                }
            })?;

        // Ensure the target block hash is registered in the engine's block container
        // This is critical for smart fetch to find the base masternode list
        engine.feed_block_height(target_blockchain_height, diff_block_hash);
        tracing::debug!(
            "Ensured target block hash {} is registered at blockchain height {} for future lookups",
            diff_block_hash,
            target_blockchain_height
        );

        tracing::info!("Successfully applied masternode list diff");

        // Validate terminal block if this is one (use blockchain height for terminal block check)
        if self.terminal_block_manager.is_terminal_block_height(target_blockchain_height) {
            // Use blockchain height for validation since terminal blocks are defined by blockchain height
            let is_valid = self
                .terminal_block_manager
                .validate_terminal_block(target_blockchain_height, &diff_block_hash, storage)
                .await?;

            if !is_valid {
                return Err(SyncError::Validation(format!(
                    "Terminal block validation failed at blockchain height {}",
                    target_blockchain_height
                )));
            }

            tracing::info!("✅ Terminal block validated at blockchain height {}", 
                target_blockchain_height);
        }

        // Store the updated masternode state
        let terminal_block_hash =
            if self.terminal_block_manager.is_terminal_block_height(target_blockchain_height) {
                Some(diff_block_hash.to_byte_array())
            } else {
                None
            };

        // Store the blockchain height (not storage height) in the masternode state
        let masternode_state = MasternodeState {
            last_height: target_blockchain_height,
            engine_state: Vec::new(), // TODO: Serialize engine state
            last_update: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| SyncError::InvalidState(format!("System time error: {}", e)))?
                .as_secs(),
            terminal_block_hash,
        };

        storage
            .store_masternode_state(&masternode_state)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to store masternode state: {}", e)))?;

        tracing::info!(
            "Updated masternode list sync height to {}", 
            target_blockchain_height
        );

        Ok(())
    }

    /// Request masternode diffs using smart DKG window-based algorithm
    /// 
    /// The algorithm works as follows:
    /// 1. For large ranges, do a bulk fetch first to get close to target
    /// 2. For the recent blocks, calculate DKG windows for all active quorum types
    /// 3. Start checking the first block of each mining window
    /// 4. If quorum not found, check next block in window (adaptive search)
    /// 5. Stop checking a window once quorum is found or window is exhausted
    ///
    /// # Arguments
    /// * `base_height` - Starting blockchain height (not storage height)
    /// * `target_height` - Target blockchain height (not storage height)
    async fn request_masternode_diffs_smart(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &dyn StorageManager,
        base_height: u32,
        target_height: u32,
    ) -> SyncResult<()> {
        use dashcore::sml::llmq_type::network::NetworkLLMQExt;
        
        if target_height <= base_height {
            return Ok(());
        }
        
        // Step 1: For very large ranges, do bulk fetch to get most of the way
        // This avoids checking thousands of DKG windows
        let bulk_end = target_height.saturating_sub(MASTERNODE_LIST_BUFFER_SIZE);
        if bulk_end > base_height {
                tracing::info!(
                    "Large range detected: bulk fetching {} to {}, then smart fetch {} to {}",
                    base_height, bulk_end, bulk_end, target_height
                );
                
                self.request_masternode_diff(network, storage, base_height, bulk_end).await?;
                self.expected_diffs_count = 1;
                self.bulk_diff_target_height = Some(bulk_end);
                self.smart_fetch_range = Some((bulk_end, target_height));
                
                // Don't initialize dkg_fetch_state here - wait until bulk completes
                // to avoid premature completion in update_smart_fetch_state
                
                return Ok(());
            }
        
        // Step 2: Calculate all DKG windows for the range
        tracing::debug!("Direct smart fetch: calculating DKG windows for blockchain height range {}-{} (sync base: {})", 
            base_height, target_height, self.sync_base_height);
        let all_windows = self.config.network.get_all_dkg_windows(base_height, target_height);
        
        // Initialize fetch state
        let fetch_state = DKGFetchState {
            pending_windows: all_windows,
            active_windows: Vec::new(),
            completed_cycles: BTreeSet::new(),
            requested_blocks: BTreeSet::new(),
            quorums_found: 0,
            windows_exhausted: 0,
        };
        
        // Calculate estimates for logging
        let total_windows: usize = fetch_state.pending_windows.values()
            .map(|v| v.len())
            .sum();
        let total_possible_blocks: usize = fetch_state.pending_windows.values()
            .flat_map(|windows| windows.iter())
            .map(|w| (w.mining_end - w.mining_start + 1) as usize)
            .sum();
        
        tracing::info!(
            "Smart masternode sync: checking {} DKG windows ({} possible blocks) out of {} total blocks",
            total_windows,
            total_possible_blocks,
            target_height - base_height
        );
        
        if total_windows == 0 {
            tracing::error!(
                "No DKG windows calculated for range {}-{}! This suggests an issue with window calculation.",
                base_height, target_height
            );
            // Log some debug info
            tracing::debug!("Network: {:?}", self.config.network);
            tracing::debug!("Base height: {}, Target height: {}", base_height, target_height);
        }
        
        self.dkg_fetch_state = Some(fetch_state);
        
        // Step 3: Start fetching
        self.fetch_next_dkg_blocks(network, storage).await?;
        
        Ok(())
    }
    
    /// Fetch the next batch of blocks based on DKG window state
    /// 
    /// This function:
    /// 1. Moves pending windows to active (up to MAX_ACTIVE_WINDOWS)
    /// 2. For each active window, requests the current block being checked
    /// 3. Batches requests for efficiency (up to MAX_REQUESTS_PER_BATCH)
    /// 
    /// Note: We await here because we're making network requests
    async fn fetch_next_dkg_blocks(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &dyn StorageManager,
    ) -> SyncResult<()> {
        // Early return if no state
        if self.dkg_fetch_state.is_none() {
            return Ok(());
        }
        
        // Now we can safely borrow state
        let state = self.dkg_fetch_state.as_mut().unwrap();
        
        tracing::debug!(
            "fetch_next_dkg_blocks: pending_windows={}, active_windows={}, completed_cycles={}, quorums_found={}",
            state.pending_windows.len(),
            state.active_windows.len(),
            state.completed_cycles.len(),
            state.quorums_found
        );
        
        // Step 1: Activate pending windows if we have capacity
        // MAX_ACTIVE_WINDOWS: Limits how many DKG windows we're tracking simultaneously
        // This prevents memory bloat and helps us focus on completing windows before starting new ones
        const MAX_ACTIVE_WINDOWS: usize = 10;
        let mut activated = 0;
        while state.active_windows.len() < MAX_ACTIVE_WINDOWS {
            if let Some((mining_start, windows)) = state.pending_windows.pop_first() {
                // Start each window at its mining_start block
                for window in windows {
                    tracing::debug!(
                        "Activating {} window: cycle {} (mining {}-{})",
                        window.llmq_type,
                        window.cycle_start,
                        window.mining_start,
                        window.mining_end
                    );
                    state.active_windows.push((window, mining_start));
                    activated += 1;
                }
            } else {
                if activated == 0 && state.active_windows.is_empty() {
                    tracing::warn!("No windows to activate! pending={}, active={}", 
                        state.pending_windows.len(), state.active_windows.len());
                }
                break; // No more pending windows
            }
        }
        
        if activated > 0 {
            tracing::info!("Activated {} DKG windows, now tracking {} active windows",
                activated, state.active_windows.len());
        }
        
        // Step 2: Request blocks for active windows
        let mut requests_made = 0;
        // MAX_REQUESTS_PER_BATCH: Limits network requests per call to avoid overwhelming peers
        // Different from MAX_ACTIVE_WINDOWS - we may have 10 active windows but only request 5 blocks at once
        const MAX_REQUESTS_PER_BATCH: usize = 5;
        
        // Collect blocks to request first to avoid borrow issues
        // Use a set to track heights we're already planning to request in this batch
        let mut blocks_to_request = Vec::new();
        let mut heights_in_batch = std::collections::HashSet::new();
        
        for (window, current_block) in &state.active_windows {
            if blocks_to_request.len() >= MAX_REQUESTS_PER_BATCH {
                break;
            }
            
            // Only request if:
            // 1. We're still within the mining window
            // 2. We haven't already requested this height
            // 3. We're not already requesting this height in this batch
            if *current_block <= window.mining_end 
                && !state.requested_blocks.contains(current_block)
                && !heights_in_batch.contains(current_block) {
                
                blocks_to_request.push((*current_block, window.llmq_type, window.cycle_start, window.mining_start, window.mining_end));
                heights_in_batch.insert(*current_block);
            } else if *current_block <= window.mining_end && heights_in_batch.contains(current_block) {
                tracing::debug!(
                    "Skipping duplicate request for height {} (already in batch for another quorum)",
                    current_block
                );
            }
        }
        
        // Get the last synced masternode height to use as base for diffs
        let last_masternode_height = match storage.load_masternode_state().await
            .map_err(|e| SyncError::Storage(format!("Failed to load masternode state: {}", e)))? {
            Some(state) => state.last_height,
            None => 0,
        };
        
        // Now make the actual requests - request MnListDiffs instead of blocks
        for (block_height, llmq_type, cycle_start, mining_start, mining_end) in blocks_to_request {
            // Skip DKG windows that are at or below our last synced masternode height
            // We can't request diffs for heights we already have or that would require
            // base masternode lists we don't possess
            if block_height <= last_masternode_height {
                tracing::debug!(
                    "Skipping DKG window at height {} (at or below last masternode height {})",
                    block_height,
                    last_masternode_height
                );
                
                // Still mark as requested to avoid re-processing
                if let Some(state) = &mut self.dkg_fetch_state {
                    state.requested_blocks.insert(block_height);
                }
                continue;
            }
            
            tracing::info!(
                "Requesting MnListDiff at height {} for {} quorum (cycle {}, window {}-{})",
                block_height,
                llmq_type,
                cycle_start,
                mining_start,
                mining_end
            );
            
            // For smart fetch, we request MnListDiff from the last known height to this DKG window height
            // This will give us any masternode/quorum changes up to this point
            let base_height = last_masternode_height;
            
            tracing::debug!(
                "Smart fetch diff request: base_height={} -> target_height={} (last_masternode_height={})",
                base_height, block_height, last_masternode_height
            );
            
            // Request the MnListDiff
            self.request_masternode_diff(network, storage, base_height, block_height).await?;
            
            // Mark height as requested
            if let Some(state) = &mut self.dkg_fetch_state {
                state.requested_blocks.insert(block_height);
            }
            
            // Track this as a smart fetch request
            self.smart_requested_heights.insert(block_height);
            requests_made += 1;
        }
        
        if requests_made > 0 {
            tracing::info!("Requested {} MnListDiffs for DKG window checking", requests_made);
        } else {
            tracing::debug!("No MnListDiffs to request in this batch");
        }
        
        self.expected_diffs_count += requests_made as u32;
        
        Ok(())
    }
    
    /// Update smart fetch state based on quorums found in a diff
    async fn update_smart_fetch_state(
        &mut self,
        diff_height: u32,
        new_quorums: &[LLMQType],
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<()> {
        // Early return if no state
        if self.dkg_fetch_state.is_none() {
            return Ok(());
        }
        
        // Check which windows are affected by this diff
        let mut windows_to_update = Vec::new();
        {
            let state = self.dkg_fetch_state.as_ref().unwrap();
            // Find windows that were waiting for this block
            for (i, (window, current_block)) in state.active_windows.iter().enumerate() {
                if *current_block == diff_height {
                    // This is a block we were checking
                    let found_quorum = new_quorums.contains(&window.llmq_type);
                    
                    if found_quorum {
                        windows_to_update.push((i, WindowAction::Complete));
                    } else if diff_height < window.mining_end {
                        windows_to_update.push((i, WindowAction::Advance(diff_height + 1)));
                    } else {
                        windows_to_update.push((i, WindowAction::Exhaust));
                    }
                }
            }
        }
        
        // Apply updates
        let state = self.dkg_fetch_state.as_mut().unwrap();
        Self::apply_window_updates(windows_to_update, state);
        
        // Continue fetching if we have more work
        let has_more_work = !state.pending_windows.is_empty() || !state.active_windows.is_empty();
        
        // Safety check: Don't complete if we haven't requested any heights yet
        // This prevents premature completion when update is called before windows are activated
        let heights_requested = state.requested_blocks.len();
        if has_more_work || heights_requested == 0 {
            self.fetch_next_dkg_blocks(network, storage).await?;
        } else {
            // All done! Log summary
            tracing::info!(
                "Smart masternode sync complete: found {} quorums, exhausted {} windows, requested {} MnListDiffs",
                state.quorums_found,
                state.windows_exhausted,
                heights_requested
            );
            self.dkg_fetch_state = None;
            // Mark sync as complete since smart fetch is done
            self.sync_in_progress = false;
            self.smart_requested_heights.clear();
        }
        
        Ok(())
    }
    
    /// Apply window updates from check_diff_against_active_windows
    fn apply_window_updates(
        updates: Vec<(usize, WindowAction)>,
        state: &mut DKGFetchState,
    ) {
        // Process in reverse order to maintain indices
        for (i, action) in updates.iter().rev() {
            match action {
                WindowAction::Advance(next_block) => {
                    // Update to check next block
                    state.active_windows[*i].1 = *next_block;
                }
                WindowAction::Complete => {
                    // Remove from active and mark as complete
                    let (window, _) = state.active_windows.remove(*i);
                    state.completed_cycles.insert((window.llmq_type, window.cycle_start));
                    state.quorums_found += 1;
                    
                    tracing::debug!(
                        "Found {} quorum at cycle {} after checking {} blocks",
                        window.llmq_type,
                        window.cycle_start,
                        state.requested_blocks.iter()
                            .filter(|&&b| b >= window.mining_start && b <= window.mining_end)
                            .count()
                    );
                }
                WindowAction::Exhaust => {
                    // Remove from active, window exhausted
                    let (window, _) = state.active_windows.remove(*i);
                    state.completed_cycles.insert((window.llmq_type, window.cycle_start));
                    state.windows_exhausted += 1;
                    
                    tracing::debug!(
                        "No {} quorum found in cycle {} mining window ({}-{})",
                        window.llmq_type,
                        window.cycle_start,
                        window.mining_start,
                        window.mining_end
                    );
                }
            }
        }
    }

    /// Reset sync state.
    pub fn reset(&mut self) {
        self.sync_in_progress = false;
        self.expected_diffs_count = 0;
        self.received_diffs_count = 0;
        self.bulk_diff_target_height = None;
        self.pending_individual_diffs = None;
        self.smart_fetch_range = None;
        self.dkg_fetch_state = None;
        self.smart_requested_heights.clear();
        if let Some(_engine) = &mut self.engine {
            // TODO: Reset engine state if needed
        }
    }

    /// Get a reference to the masternode engine for validation.
    pub fn engine(&self) -> Option<&MasternodeListEngine> {
        self.engine.as_ref()
    }

    /// Set the masternode engine (for testing)
    #[cfg(test)]
    pub fn set_engine(&mut self, engine: Option<MasternodeListEngine>) {
        self.engine = engine;
    }

    /// Get a reference to the terminal block manager.
    pub fn terminal_block_manager(&self) -> &TerminalBlockManager {
        &self.terminal_block_manager
    }

    /// Get the next terminal block after the current masternode sync height.
    pub async fn get_next_terminal_block(
        &self,
        storage: &dyn StorageManager,
    ) -> SyncResult<Option<&crate::sync::terminal_blocks::TerminalBlock>> {
        let current_height =
            match storage.load_masternode_state().await.map_err(|e| {
                SyncError::Storage(format!("Failed to load masternode state: {}", e))
            })? {
                Some(state) => state.last_height,
                None => 0,
            };

        Ok(self.terminal_block_manager.get_next_terminal_block(current_height))
    }

    /// Process a block received during smart DKG fetch
    /// 
    /// This checks if the block contains quorum commitments for active DKG windows
    pub async fn process_dkg_block(
        &mut self,
        block: &dashcore::Block,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<()> {
        // Only process if we're in smart fetch mode
        if self.dkg_fetch_state.is_none() {
            return Ok(());
        }

        // Get block height from storage
        let block_height = storage
            .get_header_height_by_hash(&block.block_hash())
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get block height: {}", e)))?
            .ok_or_else(|| SyncError::InvalidState("Block height not found in storage".to_string()))?;

        // Check if this was a requested block
        if !self.smart_requested_heights.contains(&block_height) {
            tracing::debug!("Received unrequested block {} - ignoring", block_height);
            return Ok(());
        }

        tracing::info!("Processing block {} for DKG window checking", block_height);

        // Extract quorum commitments from the block
        let mut found_quorums = Vec::new();
        for tx in &block.txdata {
            // Check if transaction is a special transaction
            if tx.tx_type() != dashcore::blockdata::transaction::special_transaction::TransactionType::Classic {
                // Check for quorum commitment (type 6)
                if let Some(payload) = &tx.special_transaction_payload {
                    if payload.get_type() == dashcore::blockdata::transaction::special_transaction::TransactionType::QuorumCommitment {
                        // This is a quorum commitment
                        // Extract LLMQ type from the payload
                        // Note: This is simplified - actual implementation would parse the commitment
                        tracing::info!("Found quorum commitment in block {}", block_height);
                        // For now, assume it's a valid quorum - in production this would parse the commitment
                        found_quorums.push(dashcore::sml::llmq_type::LLMQType::Llmqtype50_60);
                    }
                }
            }
        }

        // Update smart fetch state based on found quorums
        if !found_quorums.is_empty() || self.dkg_fetch_state.is_some() {
            self.update_smart_fetch_state(block_height, &found_quorums, storage, network).await?;
        }

        // Remove from requested heights
        self.smart_requested_heights.remove(&block_height);

        Ok(())
    }

    /// Process received QRInfo message.
    pub async fn handle_qr_info(
        &mut self,
        qr_info: QRInfo,
        storage: &dyn StorageManager,
    ) -> SyncResult<()> {
        tracing::info!(
            "Received QRInfo with {} diffs and {} snapshots",
            qr_info.mn_list_diff_list.len(),
            qr_info.quorum_snapshot_list.len()
        );
        
        // Create a snapshot before processing for potential rollback
        let snapshot_id = Some(self.validation_state.create_snapshot("Before QRInfo processing"));
        
        // Perform comprehensive validation if enabled
        if let Some(validation_engine) = &mut self.validation_engine {
            // Get engine for validation
            let engine = self.engine.as_ref().ok_or_else(|| {
                SyncError::InvalidState("Masternode engine not initialized".to_string())
            })?;
            
            let validation_result = validation_engine.validate_qr_info(&qr_info, engine)?;
            
            if !validation_result.success {
                tracing::error!(
                    "QRInfo validation failed with {} errors",
                    validation_result.errors.len()
                );
                
                // Record validation failures
                for error in &validation_result.errors {
                    self.validation_state.record_validation_failure(
                        0, // Use 0 as we don't have a specific height
                        ValidationType::QRInfo,
                        error.to_string(),
                        true, // QRInfo failures are recoverable
                    );
                }
                
                // Rollback state
                if let Some(snap_id) = snapshot_id {
                    self.validation_state.rollback_to_snapshot(snap_id)?;
                }
                
                return Err(SyncError::Validation(format!(
                    "QRInfo validation failed: {} errors",
                    validation_result.errors.len()
                )));
            }
            
            tracing::info!(
                "QRInfo validation successful: {} items validated in {:?}",
                validation_result.items_validated,
                validation_result.duration
            );
        }
        
        // Get engine or return early
        let engine = self.engine.as_mut().ok_or_else(|| {
            SyncError::InvalidState("Masternode engine not initialized".to_string())
        })?;
        
        // We can't provide a block height fetcher that borrows self while engine is mutably borrowed
        // The engine should have the necessary block heights already in its block container
        // Process QRInfo through engine without block height fetcher
        engine.feed_qr_info::<fn(&BlockHash) -> Result<u32, ClientDataRetrievalError>>(
            qr_info,
            true,  // verify_tip_non_rotated_quorums
            true,  // verify_rotated_quorums  
            None   // No block height fetcher - engine should have the heights it needs
        ).map_err(|e| SyncError::Validation(format!("QRInfo processing failed: {}", e)))?;
        
        // Mark validation as complete
        if self.validation_engine.is_some() {
            self.validation_state.complete_validation(0);
        }
        
        tracing::info!("Successfully processed QRInfo");
        Ok(())
    }

    /// Request QRInfo from the network.
    pub async fn request_qr_info(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &dyn StorageManager,
        base_block_hashes: Vec<BlockHash>,
        block_request_hash: BlockHash,
        extra_share: bool,
    ) -> SyncResult<()> {
        network
            .request_qr_info(base_block_hashes.clone(), block_request_hash, extra_share)
            .await
            .map_err(|e| SyncError::Network(format!("Failed to send GetQRInfo: {}", e)))?;

        tracing::debug!(
            "Requested QRInfo with {} base hashes for block {}, extra_share={}",
            base_block_hashes.len(),
            block_request_hash,
            extra_share
        );

        Ok(())
    }
    
    // =====================================================================
    // Engine-Driven Discovery Methods (Phase 2)
    // =====================================================================
    //
    // These methods implement Phase 2 of the QRInfo support plan, replacing
    // manual height tracking with intelligent discovery using the masternode
    // list engine's built-in methods. Instead of dash-spv deciding what to
    // request next, the engine tells us exactly which masternode lists are
    // missing and needed for validation.
    //
    // Key improvements:
    // - No more hardcoded height progression
    // - Engine-driven discovery of missing data
    // - Intelligent batching based on network conditions
    // - Automatic fallback to MnListDiff when QRInfo fails
    // - Demand-driven sync that only requests data that's actually needed
    
    /// Perform engine-driven discovery of missing data.
    ///
    /// This replaces manual height tracking with intelligent discovery using
    /// the masternode list engine's built-in methods.
    pub async fn discover_sync_needs(&mut self) -> SyncResult<SyncPlan> {
        let engine = self.engine.as_ref().ok_or_else(|| {
            SyncError::InvalidState("Masternode engine not initialized".to_string())
        })?;
        
        let discovery_service = MasternodeDiscoveryService::new();
        
        // Discover missing masternode lists
        let missing_lists = discovery_service.discover_missing_masternode_lists(engine);
        
        // Discover rotating quorum needs
        let rotating_needs = discovery_service.discover_rotating_quorum_needs(engine);
        
        // Plan QRInfo requests
        let qr_info_requests = discovery_service.plan_qr_info_requests(
            &missing_lists,
            24 * 2 // Default max span (24 blocks is typical masternode list diff interval)
        );
        
        let plan = SyncPlan {
            qr_info_requests,
            rotating_validation_needed: !rotating_needs.needs_validation.is_empty(),
            estimated_completion_time: self.estimate_sync_time(&missing_lists),
            fallback_to_mn_diff: missing_lists.total_discovered > 1000, // Large gaps
        };
        
        tracing::info!(
            "Sync plan: {} QRInfo requests, rotating_validation={}, fallback={}",
            plan.qr_info_requests.len(),
            plan.rotating_validation_needed,
            plan.fallback_to_mn_diff
        );
        
        Ok(plan)
    }
    
    /// Execute the sync plan using engine discovery.
    ///
    /// This method executes QRInfo requests in priority order and handles
    /// failures with fallback to MnListDiff when necessary.
    pub async fn execute_engine_driven_sync(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
        plan: SyncPlan,
    ) -> SyncResult<()> {
        if plan.qr_info_requests.is_empty() {
            tracing::info!("No sync needed - engine has all required data");
            return Ok(());
        }
        
        // Detect network conditions for batching optimization
        let network_conditions = NetworkConditions::good(); // TODO: Implement actual detection
        let batching_strategy = QRInfoBatchingStrategy::new();
        let optimized_batches = batching_strategy.optimize_requests(
            plan.qr_info_requests.clone(),
            &network_conditions
        );
        
        // Execute batches
        for (i, batch) in optimized_batches.iter().enumerate() {
            tracing::info!(
                "Executing batch {}/{} with {} QRInfo requests",
                i + 1,
                optimized_batches.len(),
                batch.requests.len()
            );
            
            // Execute requests in the batch (potentially in parallel if supported)
            for request in &batch.requests {
                tracing::info!(
                    "Executing QRInfo request: heights {}-{}",
                    request.base_height,
                    request.tip_height
                );
                
                // Request QRInfo
                self.request_qr_info(
                    network,
                    storage,
                    vec![request.base_hash], // TODO: Add multiple base hashes for efficiency
                    request.tip_hash,
                    request.extra_share
                ).await.map_err(|e| {
                    SyncError::Network(format!("Failed to request QRInfo: {}", e))
                })?;
                
                // Wait for response with timeout
                let timeout = batching_strategy.calculate_timeout(&batch);
                let timeout_result = tokio::time::timeout(
                    timeout,
                    self.wait_for_qr_info_response(network, storage)
                ).await;
                
                match timeout_result {
                    Ok(Ok(qr_info)) => {
                        self.process_qr_info_response(qr_info, storage).await?;
                        tracing::info!("Successfully processed QRInfo response");
                    }
                    Ok(Err(e)) => {
                        if plan.fallback_to_mn_diff && batching_strategy.should_use_fallback(&batch, 1) {
                            tracing::warn!("QRInfo failed, falling back to MnListDiff: {}", e);
                            self.fallback_to_mn_diff_sync(request, network, storage).await?;
                        } else {
                            return Err(e);
                        }
                    }
                    Err(_) => {
                        tracing::error!("QRInfo request timed out for heights {}-{}", request.base_height, request.tip_height);
                        if plan.fallback_to_mn_diff && batching_strategy.should_use_fallback(&batch, 1) {
                            self.fallback_to_mn_diff_sync(request, network, storage).await?;
                        } else {
                            return Err(SyncError::Network("QRInfo request timeout".to_string()));
                        }
                    }
                }
                
                // Brief pause between requests to be network-friendly
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        
        // Perform any additional rotating quorum validation if needed
        if plan.rotating_validation_needed {
            self.validate_rotating_quorums(storage).await?;
        }
        
        tracing::info!("Engine-driven sync completed successfully");
        Ok(())
    }
    
    /// Process QRInfo response using engine.
    async fn process_qr_info_response(
        &mut self,
        qr_info: QRInfo,
        storage: &dyn StorageManager,
    ) -> SyncResult<()> {
        let engine = self.engine.as_mut().ok_or_else(|| {
            SyncError::InvalidState("Masternode engine not initialized".to_string())
        })?;
        
        // Create a copy of the block container to avoid borrow issues
        let block_container = engine.block_container.clone();
        
        // Create block height fetcher for engine
        let block_height_fetcher = move |block_hash: &BlockHash| -> Result<u32, ClientDataRetrievalError> {
            if let Some(height) = block_container.get_height(block_hash) {
                Ok(height)
            } else {
                Err(ClientDataRetrievalError::RequiredBlockNotPresent(*block_hash))
            }
        };
        
        // Process through engine
        engine.feed_qr_info(
            qr_info,
            true,  // verify_tip_non_rotated_quorums
            true,  // verify_rotated_quorums
            Some(block_height_fetcher)
        ).map_err(|e| SyncError::Validation(format!("Engine QRInfo processing failed: {}", e)))?;
        
        // Update sync progress
        self.update_sync_progress_from_engine();
        
        Ok(())
    }
    
    /// Wait for QRInfo response from the network.
    ///
    /// This is a placeholder - actual implementation would integrate with
    /// the network manager's message handling.
    async fn wait_for_qr_info_response(
        &mut self,
        network: &dyn NetworkManager,
        storage: &dyn StorageManager,
    ) -> SyncResult<QRInfo> {
        // TODO: Implement actual waiting for QRInfo response
        // This would typically involve:
        // 1. Registering interest in QRInfo messages
        // 2. Waiting for the specific response
        // 3. Handling the response when it arrives
        
        Err(SyncError::InvalidState("QRInfo waiting not yet implemented".to_string()))
    }
    
    /// Fallback to individual MnListDiff requests if QRInfo fails.
    async fn fallback_to_mn_diff_sync(
        &mut self,
        request: &QRInfoRequest,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
        tracing::info!(
            "Falling back to MnListDiff sync for heights {}-{}",
            request.base_height,
            request.tip_height
        );
        
        // Request individual diffs for the range
        for height in request.base_height..=request.tip_height {
            let base_height = height.saturating_sub(1);
            self.request_masternode_diff(network, storage, base_height, height).await?;
            
            // TODO: Wait for response and process
            // This would need proper integration with message handling
        }
        
        Ok(())
    }
    
    /// Validate rotating quorums that need validation.
    async fn validate_rotating_quorums(&mut self, storage: &dyn StorageManager) -> SyncResult<()> {
        // TODO: Implement rotating quorum validation
        // This would involve checking quorum signatures and updating verification status
        tracing::info!("Rotating quorum validation not yet implemented");
        Ok(())
    }
    
    /// Update sync progress based on engine state.
    fn update_sync_progress_from_engine(&mut self) {
        if let Some(engine) = &self.engine {
            let total_lists = engine.masternode_lists.len();
            let latest_height = engine.masternode_lists.keys().max().copied().unwrap_or(0);
            
            tracing::debug!(
                "Engine sync progress: {} masternode lists, latest height {}",
                total_lists,
                latest_height
            );
        }
    }
    
    /// Estimate sync time based on discovery results.
    fn estimate_sync_time(&self, discovery: &DiscoveryResult) -> Duration {
        // Estimate based on number of QRInfo requests and network latency
        let base_time_per_request = Duration::from_secs(2); // Conservative estimate
        let total_requests = (discovery.total_discovered / 100).max(1); // ~100 blocks per request
        base_time_per_request * total_requests as u32
    }
    
    /// Check if sync is complete based on engine state.
    pub fn is_sync_complete(&self) -> bool {
        if let Some(engine) = &self.engine {
            // Check if we have all required masternode lists
            let discovery_service = MasternodeDiscoveryService::new();
            let missing = discovery_service.discover_missing_masternode_lists(engine);
            
            missing.total_discovered == 0
        } else {
            false
        }
    }
    
    /// Get sync progress based on engine analysis.
    pub fn get_sync_progress(&self) -> MasternodeSyncProgress {
        if let Some(engine) = &self.engine {
            let discovery_service = MasternodeDiscoveryService::new();
            let missing = discovery_service.discover_missing_masternode_lists(engine);
            
            let total_known = engine.masternode_lists.len();
            let total_needed = total_known + missing.total_discovered;
            let completion_percentage = if total_needed > 0 {
                (total_known as f32 / total_needed as f32) * 100.0
            } else {
                100.0
            };
            
            MasternodeSyncProgress {
                total_lists: total_known,
                latest_height: engine.masternode_lists.keys().max().copied().unwrap_or(0),
                quorum_validation_complete: self.check_quorum_validation_complete(engine),
                completion_percentage,
                estimated_remaining_time: self.estimate_remaining_time_from_missing(&missing),
            }
        } else {
            MasternodeSyncProgress::default()
        }
    }
    
    fn check_quorum_validation_complete(&self, engine: &MasternodeListEngine) -> bool {
        // Check if all quorums have been validated
        // This is a simplified check - actual implementation would be more thorough
        !engine.masternode_lists.is_empty()
    }
    
    fn estimate_remaining_time_from_missing(&self, missing: &DiscoveryResult) -> Duration {
        if missing.total_discovered == 0 {
            Duration::ZERO
        } else {
            self.estimate_sync_time(missing)
        }
    }
    
    /// Get validation summary for reporting.
    pub fn get_validation_summary(&self) -> Option<ValidationSummary> {
        self.validation_engine.as_ref().map(|engine| ValidationSummary::from_engine(engine))
    }
    
    /// Enable or disable validation.
    pub fn set_validation_enabled(&mut self, enabled: bool) {
        if enabled && self.validation_engine.is_none() {
            // Create validation components
            let validation_config = ValidationConfig::default();
            let chain_lock_config = ChainLockValidationConfig::default();
            
            self.validation_engine = Some(ValidationEngine::new(validation_config));
            self.chain_lock_validator = Some(ChainLockValidator::new(chain_lock_config));
        } else if !enabled {
            // Disable validation
            self.validation_engine = None;
            self.chain_lock_validator = None;
        }
    }
    
    /// Validate chain locks for a range of heights.
    pub async fn validate_chain_locks(
        &mut self,
        start_height: u32,
        end_height: u32,
        storage: &dyn StorageManager,
    ) -> SyncResult<Vec<crate::sync::chainlock_validation::ChainLockValidationResult>> {
        if let Some(validator) = &mut self.chain_lock_validator {
            let engine = self.engine.as_ref().ok_or_else(|| {
                SyncError::InvalidState("Masternode engine not initialized".to_string())
            })?;
            
            validator.validate_historical_chain_locks(start_height, end_height, engine, storage).await
        } else {
            Ok(Vec::new())
        }
    }
    
    /// Reset validation state and error counts.
    pub fn reset_validation_state(&mut self) {
        if let Some(engine) = &mut self.validation_engine {
            engine.reset_error_count();
        }
        self.validation_state = ValidationStateManager::new();
    }
}

/// Sync plan for engine-driven masternode sync
#[derive(Debug)]
pub struct SyncPlan {
    /// QRInfo requests to execute
    pub qr_info_requests: Vec<QRInfoRequest>,
    /// Whether rotating quorum validation is needed
    pub rotating_validation_needed: bool,
    /// Estimated time to complete sync
    pub estimated_completion_time: Duration,
    /// Whether to fallback to MnListDiff on QRInfo failures
    pub fallback_to_mn_diff: bool,
}

/// Masternode sync progress information
#[derive(Debug, Default)]
pub struct MasternodeSyncProgress {
    /// Total masternode lists in engine
    pub total_lists: usize,
    /// Latest masternode list height
    pub latest_height: u32,
    /// Whether quorum validation is complete
    pub quorum_validation_complete: bool,
    /// Completion percentage (0-100)
    pub completion_percentage: f32,
    /// Estimated remaining time
    pub estimated_remaining_time: Duration,
}
