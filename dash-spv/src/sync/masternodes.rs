//! Masternode synchronization functionality.

use dashcore::{
    address::{Address, Payload},
    bls_sig_utils::BLSPublicKey,
    hash_types::MerkleRootMasternodeList,
    network::constants::NetworkExt,
    network::message::NetworkMessage,
    network::message_sml::{GetMnListDiff, MnListDiff},
    sml::{
        masternode_list::MasternodeList,
        masternode_list_engine::MasternodeListEngine,
        masternode_list_entry::{
            qualified_masternode_list_entry::QualifiedMasternodeListEntry, EntryMasternodeType,
            MasternodeListEntry,
        },
    },
    BlockHash, ProTxHash, PubkeyHash,
};
use dashcore_hashes::Hash;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str::FromStr;

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::{MasternodeState, StorageManager};
use crate::sync::terminal_blocks::TerminalBlockManager;

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
    /// Track if we're retrying from genesis to ignore stale diffs
    retrying_from_genesis: bool,
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
            retrying_from_genesis: false,
        }
    }
    
    /// Restore the engine state from storage if available.
    pub async fn restore_engine_state(&mut self, storage: &dyn StorageManager) -> SyncResult<()> {
        if !self.config.enable_masternodes {
            return Ok(());
        }
        
        // Load masternode state from storage
        if let Some(state) = storage.load_masternode_state().await.map_err(|e| {
            SyncError::Storage(format!("Failed to load masternode state: {}", e))
        })? {
            if !state.engine_state.is_empty() {
                // Deserialize the engine state
                match bincode::deserialize::<MasternodeListEngine>(&state.engine_state) {
                    Ok(engine) => {
                        tracing::info!(
                            "Restored masternode engine state from storage (last_height: {}, {} masternode lists)",
                            state.last_height,
                            engine.masternode_lists.len()
                        );
                        self.engine = Some(engine);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to deserialize engine state: {}. Starting with fresh engine.",
                            e
                        );
                        // Keep the default engine we created in new()
                    }
                }
            } else {
                tracing::debug!("Masternode state exists but engine state is empty");
            }
        }
        
        Ok(())
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
        
        // Check if we should ignore this diff due to retry
        if self.retrying_from_genesis {
            // Only process genesis diffs when retrying
            let genesis_hash = self.config.network.known_genesis_block_hash()
                .unwrap_or_else(BlockHash::all_zeros);
            if diff.base_block_hash != genesis_hash {
                tracing::debug!(
                    "Ignoring non-genesis diff while retrying from genesis: base_block_hash={}",
                    diff.base_block_hash
                );
                return Ok(true);
            }
            // This is the genesis diff we're waiting for
            self.retrying_from_genesis = false;
        }

        self.last_sync_progress = std::time::Instant::now();

        // Process the diff with fallback to genesis if incremental diff fails
        match self.process_masternode_diff(diff, storage).await {
            Ok(()) => {
                // Success - diff applied
                // Increment received diffs count
                self.received_diffs_count += 1;
                tracing::debug!(
                    "After processing diff: received_diffs_count={}, expected_diffs_count={}, pending_individual_diffs={:?}",
                    self.received_diffs_count,
                    self.expected_diffs_count,
                    self.pending_individual_diffs
                );
            }
            Err(e) if e.to_string().contains("MissingStartMasternodeList") => {
                tracing::warn!("Incremental masternode diff failed with MissingStartMasternodeList, retrying from genesis");

                // Reset sync state but keep in progress
                self.last_sync_progress = std::time::Instant::now();
                // Reset counters since we're starting over
                self.received_diffs_count = 0;
                self.bulk_diff_target_height = None;
                // IMPORTANT: Preserve pending_individual_diffs so we still request them after genesis sync
                // self.pending_individual_diffs = None;  // Don't clear this!
                // Mark that we're retrying from genesis
                self.retrying_from_genesis = true;

                // Get current height again
                let current_height = storage
                    .get_tip_height()
                    .await
                    .map_err(|e| {
                        SyncError::Storage(format!(
                            "Failed to get current height for fallback: {}",
                            e
                        ))
                    })?
                    .unwrap_or(0);

                // Request full diffs from genesis with last 8 blocks individually
                tracing::info!(
                    "Requesting fallback masternode diffs from genesis to height {}",
                    current_height
                );
                self.request_masternode_diffs_for_chainlock_validation_with_base(network, storage, 0, current_height, self.sync_base_height).await?;

                // Return true to continue waiting for the new response
                return Ok(true);
            }
            Err(e) => {
                // Other error - propagate it
                return Err(e);
            }
        }
        
        // Check if we've received all expected diffs
        tracing::info!(
            "Checking diff completion: received={}, expected={}, pending_individual_diffs={:?}",
            self.received_diffs_count,
            self.expected_diffs_count,
            self.pending_individual_diffs
        );
        
        if self.expected_diffs_count > 0 && self.received_diffs_count >= self.expected_diffs_count {
            // Check if this was the bulk diff and we have pending individual diffs
            if let Some((start_height, end_height)) = self.pending_individual_diffs.take() {
                // Reset counters for individual diffs
                self.received_diffs_count = 0;
                self.expected_diffs_count = end_height - start_height;
                self.bulk_diff_target_height = None;
                
                // Request the individual diffs now that bulk is complete
                // Note: start_height and end_height are blockchain heights, not storage heights
                // Each iteration requests diff from height to height+1
                if self.sync_base_height > 0 {
                    // Using checkpoint-based sync - heights are blockchain heights
                    for blockchain_height in start_height..end_height {
                        tracing::debug!(
                            "Requesting individual diff {} of {}: from {} to {}",
                            blockchain_height - start_height + 1,
                            end_height - start_height,
                            blockchain_height,
                            blockchain_height + 1
                        );
                        self.request_masternode_diff_with_base(network, storage, blockchain_height, blockchain_height + 1, self.sync_base_height).await?;
                    }
                } else {
                    // Normal sync - heights are storage heights (same as blockchain heights when sync_base_height = 0)
                    for height in start_height..end_height {
                        self.request_masternode_diff(network, storage, height, height + 1).await?;
                    }
                }
                
                tracing::info!(
                    "✅ Bulk diff complete, now requesting {} individual masternode diffs from blockchain heights {} to {}",
                    self.expected_diffs_count,
                    start_height,
                    end_height
                );
                
                Ok(true)  // Continue waiting for individual diffs
            } else {
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
            // Legacy behavior: single diff completes sync
            tracing::info!("Masternode sync complete (single diff mode)");
            self.sync_in_progress = false;
            Ok(false)
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

            // Get current header height for recovery request
            let current_height = storage
                .get_tip_height()
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get current height: {}", e)))?
                .unwrap_or(0);

            let last_masternode_height =
                match storage.load_masternode_state().await.map_err(|e| {
                    SyncError::Storage(format!("Failed to load masternode state: {}", e))
                })? {
                    Some(state) => state.last_height,
                    None => 0,
                };

            self.request_masternode_diffs_for_chainlock_validation_with_base(network, storage, last_masternode_height, current_height, self.sync_base_height)
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

        tracing::debug!("About to load masternode state from storage");
        
        // Get last known masternode height
        let last_masternode_height =
            match storage.load_masternode_state().await.map_err(|e| {
                SyncError::Storage(format!("Failed to load masternode state: {}", e))
            })? {
                Some(state) => {
                    tracing::info!(
                        "Found existing masternode state: last_height={}, has_engine_state={}, terminal_block={:?}",
                        state.last_height,
                        !state.engine_state.is_empty(),
                        state.terminal_block_hash.is_some()
                    );
                    state.last_height
                },
                None => {
                    tracing::info!("No existing masternode state found, starting from height 0");
                    0
                },
            };

        // If we're already up to date, no need to sync
        if last_masternode_height >= current_height {
            tracing::warn!(
                "⚠️ Masternode list already synced to current height (last: {}, current: {}) - THIS WILL SKIP MASTERNODE SYNC!",
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
        self.retrying_from_genesis = false;

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
                Some(state) => {
                    tracing::info!(
                        "Found existing masternode state: last_height={}, has_engine_state={}, terminal_block={:?}",
                        state.last_height,
                        !state.engine_state.is_empty(),
                        state.terminal_block_hash.is_some()
                    );
                    state.last_height
                },
                None => {
                    tracing::info!("No existing masternode state found, starting from height 0");
                    0
                },
            };

        // If we're already up to date, no need to sync
        if last_masternode_height >= current_height {
            tracing::warn!(
                "⚠️ Masternode list already synced to current height (last: {}, current: {}) - THIS WILL SKIP MASTERNODE SYNC!",
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
        self.retrying_from_genesis = false;

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
                self.validate_terminal_block(
                    storage,
                    terminal_block.height,
                    terminal_block.block_hash,
                    false,
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
        self.request_masternode_diffs_for_chainlock_validation_with_base(network, storage, base_height, current_height, self.sync_base_height).await?;

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
        // Get base block hash
        let base_block_hash = if base_height == 0 {
            self.config
                .network
                .known_genesis_block_hash()
                .ok_or_else(|| SyncError::Network("No genesis hash for network".to_string()))?
        } else {
            storage
                .get_header(base_height)
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get base header: {}", e)))?
                .ok_or_else(|| SyncError::Storage("Base header not found".to_string()))?
                .block_hash()
        };

        // Get current block hash
        let current_block_hash = storage
            .get_header(current_height)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get current header at height {}: {}", current_height, e)))?
            .ok_or_else(|| SyncError::Storage(format!("Current header not found at height {}", current_height)))?
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
    /// This requests multiple diffs to populate masternode lists at the last 8 heights.
    async fn request_masternode_diffs_for_chainlock_validation(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &dyn StorageManager,
        base_height: u32,
        target_height: u32,
    ) -> SyncResult<()> {
        // ChainLocks need masternode lists at (block_height - 8)
        // To ensure we can validate any recent ChainLock, we need lists for the last 8 blocks
        
        if target_height <= base_height {
            return Ok(());
        }
        
        // Reset diff counters
        self.received_diffs_count = 0;
        
        // If the range is small (8 or fewer blocks), request individual diffs for each block
        let blocks_to_sync = target_height - base_height;
        if blocks_to_sync <= 8 {
            // Set expected count
            self.expected_diffs_count = blocks_to_sync;
            
            // Request a diff for each block individually
            for height in base_height..target_height {
                self.request_masternode_diff(network, storage, height, height + 1).await?;
            }
            tracing::info!(
                "Requested {} individual masternode diffs from {} to {}",
                blocks_to_sync,
                base_height,
                target_height
            );
        } else {
            // For larger ranges, optimize by:
            // 1. Request bulk diff to (target_height - 8) first
            // 2. Request individual diffs for the last 8 blocks AFTER bulk completes
            
            let bulk_end_height = target_height.saturating_sub(8);
            
            // Only request bulk if there's something to sync
            if bulk_end_height > base_height {
                self.request_masternode_diff(network, storage, base_height, bulk_end_height).await?;
                self.expected_diffs_count = 1; // Only expecting the bulk diff initially
                self.bulk_diff_target_height = Some(bulk_end_height);
                tracing::debug!(
                    "Set expected_diffs_count=1 for bulk diff, bulk_diff_target_height={}",
                    bulk_end_height
                );
                
                // Store the individual diff request for later (using blockchain heights)
                // Individual diffs should start after the bulk diff ends
                let individual_start = bulk_end_height; // Bulk ends at this height
                if target_height > individual_start {
                    // Store range for individual diffs  
                    // We'll request diffs FROM bulk_end_height TO bulk_end_height+1, etc.
                    self.pending_individual_diffs = Some((individual_start, target_height));
                    tracing::debug!(
                        "Setting pending_individual_diffs: start={}, end={}",
                        individual_start,
                        target_height
                    );
                }
                
                tracing::info!(
                    "Requested bulk masternode diff from {} to {}",
                    base_height,
                    bulk_end_height
                );
                let individual_count = if target_height > bulk_end_height {
                    target_height - bulk_end_height
                } else {
                    0
                };
                tracing::info!(
                    "Will request {} individual diffs after bulk completes (heights {} to {})",
                    individual_count,
                    bulk_end_height + 1,
                    target_height
                );
            } else {
                // No bulk needed, just individual diffs
                let individual_count = target_height - base_height;
                self.expected_diffs_count = individual_count;
                
                for height in base_height..target_height {
                    self.request_masternode_diff(network, storage, height, height + 1).await?;
                }
                
                if individual_count > 0 {
                    tracing::info!(
                        "Requested {} individual masternode diffs from {} to {}",
                        individual_count,
                        base_height,
                        target_height
                    );
                }
            }
        }
        
        Ok(())
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
            // This can happen during phase transitions or when headers are still being stored
            // Instead of failing, adjust to use the storage tip
            tracing::warn!(
                "Requested storage height {} exceeds storage tip {} (blockchain height {} with sync base {}). Using storage tip instead.",
                storage_current_height, storage_tip, current_height, sync_base_height
            );
            
            // Use the storage tip as the current height
            let adjusted_storage_height = storage_tip;
            let adjusted_blockchain_height = storage_tip + sync_base_height;
            
            // Update the heights to use what's actually available
            // Don't recurse - just continue with adjusted values
            if adjusted_storage_height <= storage_base_height {
                // Nothing to sync
                return Ok(());
            }
            
            // Log the adjustment
            tracing::debug!(
                "Adjusted MnListDiff request heights - blockchain: {}-{}, storage: {}-{}",
                base_height, adjusted_blockchain_height, storage_base_height, adjusted_storage_height
            );
            
            // Get current block hash at the adjusted height
            let adjusted_current_hash = storage
                .get_header(adjusted_storage_height)
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get header at adjusted storage height {}: {}", adjusted_storage_height, e)))?
                .ok_or_else(|| SyncError::Storage(format!("Header not found at adjusted storage height {}", adjusted_storage_height)))?
                .block_hash();
            
            // Continue with the request using adjusted values
            let get_mn_list_diff = GetMnListDiff {
                base_block_hash: if base_height == 0 {
                    self.config.network.known_genesis_block_hash()
                        .ok_or_else(|| SyncError::Network("No genesis hash for network".to_string()))?
                } else {
                    storage.get_header(storage_base_height).await
                        .map_err(|e| SyncError::Storage(format!("Failed to get base header: {}", e)))?
                        .ok_or_else(|| SyncError::Storage(format!("Base header not found at storage height {}", storage_base_height)))?
                        .block_hash()
                },
                block_hash: adjusted_current_hash,
            };
            
            network.send_message(NetworkMessage::GetMnListD(get_mn_list_diff)).await
                .map_err(|e| SyncError::Network(format!("Failed to send adjusted GetMnListDiff: {}", e)))?;
            
            tracing::info!(
                "Requested masternode list diff from blockchain height {} (storage {}) to {} (storage {}) [adjusted from {}]",
                base_height, storage_base_height, adjusted_blockchain_height, adjusted_storage_height, current_height
            );
            
            return Ok(());
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
        // ChainLocks need masternode lists at (block_height - 8)
        // To ensure we can validate any recent ChainLock, we need lists for the last 8 blocks
        
        if target_height <= base_height {
            return Ok(());
        }
        
        // Reset diff counters
        self.received_diffs_count = 0;
        
        // If the range is small (8 or fewer blocks), request individual diffs for each block
        let blocks_to_sync = target_height - base_height;
        if blocks_to_sync <= 8 {
            // Set expected count
            self.expected_diffs_count = blocks_to_sync;
            
            // Request a diff for each block individually
            for height in base_height..target_height {
                self.request_masternode_diff_with_base(network, storage, height, height + 1, sync_base_height).await?;
            }
            tracing::info!(
                "Requested {} individual masternode diffs from {} to {}",
                blocks_to_sync,
                base_height,
                target_height
            );
        } else {
            // For larger ranges, optimize by:
            // 1. Request bulk diff to (target_height - 8) first
            // 2. Request individual diffs for the last 8 blocks AFTER bulk completes
            
            let bulk_end_height = target_height.saturating_sub(8);
            
            // Only request bulk if there's something to sync
            if bulk_end_height > base_height {
                self.request_masternode_diff_with_base(network, storage, base_height, bulk_end_height, sync_base_height).await?;
                self.expected_diffs_count = 1; // Only expecting the bulk diff initially
                self.bulk_diff_target_height = Some(bulk_end_height);
                tracing::debug!(
                    "Set expected_diffs_count=1 for bulk diff, bulk_diff_target_height={}",
                    bulk_end_height
                );
                
                // Store the individual diff request for later (using blockchain heights)
                // Individual diffs should start after the bulk diff ends
                let individual_start = bulk_end_height; // Bulk ends at this height
                if target_height > individual_start {
                    // Store range for individual diffs  
                    // We'll request diffs FROM bulk_end_height TO bulk_end_height+1, etc.
                    self.pending_individual_diffs = Some((individual_start, target_height));
                    tracing::debug!(
                        "Setting pending_individual_diffs: start={}, end={}",
                        individual_start,
                        target_height
                    );
                }
                
                tracing::info!(
                    "Requested bulk masternode diff from {} to {}",
                    base_height,
                    bulk_end_height
                );
                let individual_count = if target_height > bulk_end_height {
                    target_height - bulk_end_height
                } else {
                    0
                };
                tracing::info!(
                    "Will request {} individual diffs after bulk completes (heights {} to {})",
                    individual_count,
                    bulk_end_height + 1,
                    target_height
                );
            } else {
                // No bulk needed, just individual diffs
                let individual_count = target_height - base_height;
                self.expected_diffs_count = individual_count;
                
                for height in base_height..target_height {
                    self.request_masternode_diff_with_base(network, storage, height, height + 1, sync_base_height).await?;
                }
                
                if individual_count > 0 {
                    tracing::info!(
                        "Requested {} individual masternode diffs from {} to {}",
                        individual_count,
                        base_height,
                        target_height
                    );
                }
            }
        }
        
        Ok(())
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
            if let Some(storage_target_height) = storage
                .get_header_height_by_hash(&target_block_hash)
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to lookup target hash: {}", e)))?
            {
                // Convert storage height to blockchain height
                let blockchain_target_height = storage_target_height + self.sync_base_height;
                engine.feed_block_height(blockchain_target_height, target_block_hash);
                tracing::debug!(
                    "Fed target block hash {} at blockchain height {} (storage height {})",
                    target_block_hash,
                    blockchain_target_height,
                    storage_target_height
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
                if let Some(storage_base_height) = storage
                    .get_header_height_by_hash(&base_block_hash)
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to lookup base hash: {}", e)))?
                {
                    // Convert storage height to blockchain height
                    let blockchain_base_height = storage_base_height + self.sync_base_height;
                    engine.feed_block_height(blockchain_base_height, base_block_hash);
                    tracing::debug!(
                        "Fed base block hash {} at blockchain height {} (storage height {})",
                        base_block_hash,
                        blockchain_base_height,
                        storage_base_height
                    );
                }
            }

            // Calculate start_height for filtering redundant submissions
            // Feed last 1000 headers or from base height, whichever is more recent
            let storage_start_height = if base_block_hash == self.config.network.known_genesis_block_hash().ok_or_else(|| {
                SyncError::Network("No genesis hash for network".to_string())
            })? {
                // For genesis, start from 0 (but limited by what's in storage)
                0
            } else if let Some(storage_base_height) = storage
                .get_header_height_by_hash(&base_block_hash)
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to lookup base hash: {}", e)))?
            {
                storage_base_height.saturating_sub(100) // Include some headers before base
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
                    if storage_quorum_height >= storage_start_height {
                        // Convert storage height to blockchain height
                        let blockchain_quorum_height = storage_quorum_height + self.sync_base_height;
                        
                        // Check if this block hash is already known to avoid duplicate feeds
                        if !engine.block_container.contains_hash(&quorum.quorum_hash) {
                            engine.feed_block_height(blockchain_quorum_height, quorum.quorum_hash);
                            tracing::debug!(
                                "Fed quorum hash {} at blockchain height {} (storage height {})",
                                quorum.quorum_hash,
                                blockchain_quorum_height,
                                storage_quorum_height
                            );
                        } else {
                            tracing::trace!(
                                "Skipping already known quorum hash {} at blockchain height {}",
                                quorum.quorum_hash,
                                blockchain_quorum_height
                            );
                        }
                    } else {
                        tracing::trace!(
                            "Skipping quorum hash {} at storage height {} (before start_height {})",
                            quorum.quorum_hash,
                            storage_quorum_height,
                            storage_start_height
                        );
                    }
                }
            }

            // Feed a reasonable range of recent headers for validation purposes
            // The engine may need recent headers for various validations

            if storage_start_height < tip_height {
                tracing::debug!(
                    "Feeding headers from storage height {} to {} to masternode engine",
                    storage_start_height,
                    tip_height
                );
                let headers =
                    storage.get_headers_batch(storage_start_height, tip_height).await.map_err(|e| {
                        SyncError::Storage(format!("Failed to batch load headers: {}", e))
                    })?;

                for (storage_height, header) in headers {
                    // Convert storage height to blockchain height
                    let blockchain_height = storage_height + self.sync_base_height;
                    let block_hash = header.block_hash();
                    
                    // Only feed if not already known
                    if !engine.block_container.contains_hash(&block_hash) {
                        engine.feed_block_height(blockchain_height, block_hash);
                    }
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
                // Serialize the engine state even for regtest
                let engine_state = if let Some(engine) = &self.engine {
                    bincode::serialize(engine).unwrap_or_default()
                } else {
                    Vec::new()
                };
                
                let masternode_state = MasternodeState {
                    last_height: tip_height,
                    engine_state,
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

        // Apply the diff to our engine
        let apply_result = engine.apply_diff(diff.clone(), None, true, None);
        
        // Handle specific error cases
        match apply_result {
            Ok(_) => {
                // Success - diff applied
            }
            Err(e) if e.to_string().contains("MissingStartMasternodeList") => {
                // If this is a genesis diff and we still get MissingStartMasternodeList,
                // it means the engine needs to be reset
                if diff.base_block_hash == self.config.network.known_genesis_block_hash().ok_or_else(|| {
                    SyncError::Network("No genesis hash for network".to_string())
                })? {
                    tracing::warn!("Genesis diff failed with MissingStartMasternodeList - resetting engine state");
                    
                    // Reset the engine to a clean state
                    engine.masternode_lists.clear();
                    engine.known_snapshots.clear();
                    engine.rotated_quorums_per_cycle.clear();
                    engine.quorum_statuses.clear();
                    
                    // Re-feed genesis block
                    if let Some(genesis_hash) = self.config.network.known_genesis_block_hash() {
                        engine.feed_block_height(0, genesis_hash);
                    }
                    
                    // Try applying the diff again
                    engine.apply_diff(diff, None, true, None)
                        .map_err(|e| SyncError::Validation(format!("Failed to apply genesis masternode diff after reset: {:?}", e)))?;
                    
                    tracing::info!("Successfully applied genesis masternode diff after engine reset");
                } else {
                    // Non-genesis diff failed - this will trigger a retry from genesis
                    return Err(SyncError::Validation(format!("Failed to apply masternode diff: {:?}", e)));
                }
            }
            Err(e) => {
                // Other errors
                if self.config.network == dashcore::Network::Regtest && e.to_string().contains("IncompleteMnListDiff") {
                    return Err(SyncError::SyncFailed(format!(
                        "Failed to apply masternode diff in regtest (this is normal if no masternodes are configured): {:?}", e
                    )));
                } else {
                    return Err(SyncError::Validation(format!("Failed to apply masternode diff: {:?}", e)));
                }
            }
        }

        tracing::info!("Successfully applied masternode list diff");
        
        // Log the current masternode engine state after applying diff
        if let Some(engine) = &self.engine {
            let current_ml_height = engine.masternode_lists.keys().max().copied().unwrap_or(0);
            tracing::info!(
                "Masternode engine state after diff: highest ML height = {}, total MLs = {}, known snapshots = {}",
                current_ml_height,
                engine.masternode_lists.len(),
                engine.known_snapshots.len()
            );
        }

        // Find the height of the target block
        let target_height = if let Some(height) =
            storage.get_header_height_by_hash(&target_block_hash).await.map_err(|e| {
                SyncError::Storage(format!("Failed to lookup target block height: {}", e))
            })? {
            height
        } else {
            // Fallback to tip height if we can't find the specific block
            storage
                .get_tip_height()
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?
                .unwrap_or(0)
        };

        // Validate terminal block if this is one
        if self.terminal_block_manager.is_terminal_block_height(target_height) {
            let is_valid = self
                .terminal_block_manager
                .validate_terminal_block(target_height, &target_block_hash, storage)
                .await?;

            if !is_valid {
                return Err(SyncError::Validation(format!(
                    "Terminal block validation failed at height {}",
                    target_height
                )));
            }

            tracing::info!("✅ Terminal block validated at height {}", target_height);
        }

        // Store the updated masternode state
        let terminal_block_hash =
            if self.terminal_block_manager.is_terminal_block_height(target_height) {
                Some(target_block_hash.to_byte_array())
            } else {
                None
            };

        // Convert storage height back to blockchain height for masternode state
        let blockchain_height = if self.sync_base_height > 0 {
            target_height + self.sync_base_height
        } else {
            target_height
        };

        // Serialize the engine state
        let engine_state = if let Some(engine) = &self.engine {
            bincode::serialize(engine)
                .map_err(|e| SyncError::Storage(format!("Failed to serialize engine state: {}", e)))?
        } else {
            Vec::new()
        };
        
        let masternode_state = MasternodeState {
            last_height: blockchain_height,
            engine_state,
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

        tracing::info!("Updated masternode list sync height to {}", blockchain_height);

        Ok(())
    }

    /// Reset sync state.
    pub fn reset(&mut self) {
        self.sync_in_progress = false;
        self.expected_diffs_count = 0;
        self.received_diffs_count = 0;
        self.bulk_diff_target_height = None;
        self.pending_individual_diffs = None;
        self.retrying_from_genesis = false;
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
}
