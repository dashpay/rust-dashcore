//! Masternode synchronization functionality.

use dashcore::{
    network::constants::NetworkExt,
    network::message::NetworkMessage,
    network::message_sml::{GetMnListDiff, MnListDiff},
    sml::masternode_list_engine::MasternodeListEngine,
    BlockHash,
};
use dashcore_hashes::Hash;

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::{MasternodeState, StorageManager};

/// Manages masternode list synchronization.
pub struct MasternodeSyncManager {
    config: ClientConfig,
    sync_in_progress: bool,
    engine: Option<MasternodeListEngine>,
    /// Last time sync progress was made (for timeout detection)
    last_sync_progress: std::time::Instant,
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

        // Process the diff with fallback to genesis if incremental diff fails
        match self.process_masternode_diff(diff, storage).await {
            Ok(()) => {
                // Success - diff applied
            }
            Err(e) if e.to_string().contains("MissingStartMasternodeList") => {
                tracing::warn!("Incremental masternode diff failed with MissingStartMasternodeList, retrying from genesis");

                // Reset sync state but keep in progress
                self.last_sync_progress = std::time::Instant::now();

                // Get current height again
                let current_height = storage
                    .get_tip_height()
                    .await
                    .map_err(|e| {
                        SyncError::SyncFailed(format!(
                            "Failed to get current height for fallback: {}",
                            e
                        ))
                    })?
                    .unwrap_or(0);

                // Request full diff from genesis
                tracing::info!(
                    "Requesting fallback masternode diff from genesis to height {}",
                    current_height
                );
                self.request_masternode_diff(network, storage, 0, current_height).await?;

                // Return true to continue waiting for the new response
                return Ok(true);
            }
            Err(e) => {
                // Other error - propagate it
                return Err(e);
            }
        }

        // Masternode sync typically completes after processing one diff
        self.sync_in_progress = false;
        Ok(false)
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
                .map_err(|e| SyncError::SyncFailed(format!("Failed to get current height: {}", e)))?
                .unwrap_or(0);

            let last_masternode_height =
                match storage.load_masternode_state().await.map_err(|e| {
                    SyncError::SyncFailed(format!("Failed to load masternode state: {}", e))
                })? {
                    Some(state) => state.last_height,
                    None => 0,
                };

            self.request_masternode_diff(network, storage, last_masternode_height, current_height)
                .await?;
            self.last_sync_progress = std::time::Instant::now();

            return Ok(true);
        }

        Ok(false)
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
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get current height: {}", e)))?
            .unwrap_or(0);

        // Get last known masternode height
        let last_masternode_height =
            match storage.load_masternode_state().await.map_err(|e| {
                SyncError::SyncFailed(format!("Failed to load masternode state: {}", e))
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

        // Try incremental diff first if we have previous state, fallback to genesis if needed
        let base_height = if last_masternode_height > 0 {
            tracing::info!(
                "Attempting incremental masternode diff from height {} to {}",
                last_masternode_height,
                current_height
            );
            last_masternode_height
        } else {
            tracing::info!(
                "No previous masternode state, requesting full diff from genesis to height {}",
                current_height
            );
            0
        };

        // Request masternode list diff
        self.request_masternode_diff(network, storage, base_height, current_height).await?;

        Ok(true) // Sync started
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
                .ok_or_else(|| SyncError::SyncFailed("No genesis hash for network".to_string()))?
        } else {
            storage
                .get_header(base_height)
                .await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to get base header: {}", e)))?
                .ok_or_else(|| SyncError::SyncFailed("Base header not found".to_string()))?
                .block_hash()
        };

        // Get current block hash
        let current_block_hash = storage
            .get_header(current_height)
            .await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get current header: {}", e)))?
            .ok_or_else(|| SyncError::SyncFailed("Current header not found".to_string()))?
            .block_hash();

        let get_mn_list_diff = GetMnListDiff {
            base_block_hash,
            block_hash: current_block_hash,
        };

        network
            .send_message(NetworkMessage::GetMnListD(get_mn_list_diff))
            .await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to send GetMnListDiff: {}", e)))?;

        tracing::debug!(
            "Requested masternode list diff from {} to {}",
            base_height,
            current_height
        );

        Ok(())
    }

    /// Process received masternode list diff.
    async fn process_masternode_diff(
        &mut self,
        diff: MnListDiff,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
        let engine = self.engine.as_mut().ok_or_else(|| {
            SyncError::SyncFailed("Masternode engine not initialized".to_string())
        })?;

        let _target_block_hash = diff.block_hash;

        // Get tip height first as it's needed later
        let tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip height: {}", e)))?
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
            if let Some(target_height) =
                storage.get_header_height_by_hash(&target_block_hash).await.map_err(|e| {
                    SyncError::SyncFailed(format!("Failed to lookup target hash: {}", e))
                })?
            {
                engine.feed_block_height(target_height, target_block_hash);
                tracing::debug!(
                    "Fed target block hash {} at height {}",
                    target_block_hash,
                    target_height
                );
            } else {
                return Err(SyncError::SyncFailed(format!(
                    "Target block hash {} not found in storage",
                    target_block_hash
                )));
            }

            // Feed base block hash
            if let Some(base_height) = storage
                .get_header_height_by_hash(&base_block_hash)
                .await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to lookup base hash: {}", e)))?
            {
                engine.feed_block_height(base_height, base_block_hash);
                tracing::debug!(
                    "Fed base block hash {} at height {}",
                    base_block_hash,
                    base_height
                );
            }

            // Calculate start_height for filtering redundant submissions
            // Feed last 1000 headers or from base height, whichever is more recent
            let start_height = if let Some(base_height) = storage
                .get_header_height_by_hash(&base_block_hash)
                .await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to lookup base hash: {}", e)))?
            {
                base_height.saturating_sub(100) // Include some headers before base
            } else {
                tip_height.saturating_sub(1000)
            };

            // Feed any quorum hashes from new_quorums that are block hashes
            for quorum in &diff.new_quorums {
                // Note: quorum_hash is not necessarily a block hash, so we check if it exists
                if let Some(quorum_height) =
                    storage.get_header_height_by_hash(&quorum.quorum_hash).await.map_err(|e| {
                        SyncError::SyncFailed(format!("Failed to lookup quorum hash: {}", e))
                    })?
                {
                    // Only feed blocks at or after start_height to avoid redundant submissions
                    if quorum_height >= start_height {
                        engine.feed_block_height(quorum_height, quorum.quorum_hash);
                        tracing::debug!(
                            "Fed quorum hash {} at height {}",
                            quorum.quorum_hash,
                            quorum_height
                        );
                    } else {
                        tracing::trace!(
                            "Skipping quorum hash {} at height {} (before start_height {})",
                            quorum.quorum_hash,
                            quorum_height,
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
                        SyncError::SyncFailed(format!("Failed to batch load headers: {}", e))
                    })?;

                for (height, header) in headers {
                    engine.feed_block_height(height, header.block_hash());
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
                };

                storage.store_masternode_state(&masternode_state).await.map_err(|e| {
                    SyncError::SyncFailed(format!("Failed to store masternode state: {}", e))
                })?;

                tracing::info!("Masternode synchronization completed (empty in regtest)");
                return Ok(());
            }
        }

        // Apply the diff to our engine
        engine.apply_diff(diff, None, true, None)
            .map_err(|e| {
                // Provide more context for IncompleteMnListDiff in regtest
                if self.config.network == dashcore::Network::Regtest && e.to_string().contains("IncompleteMnListDiff") {
                    SyncError::SyncFailed(format!(
                        "Failed to apply masternode diff in regtest (this is normal if no masternodes are configured): {:?}", e
                    ))
                } else {
                    SyncError::SyncFailed(format!("Failed to apply masternode diff: {:?}", e))
                }
            })?;

        tracing::info!("Successfully applied masternode list diff");

        // Find the height of the target block
        // TODO: This is inefficient - we should maintain a hash->height mapping
        let target_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip height: {}", e)))?
            .unwrap_or(0);

        // Store the updated masternode state
        let masternode_state = MasternodeState {
            last_height: target_height,
            engine_state: Vec::new(), // TODO: Serialize engine state
            last_update: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        storage.store_masternode_state(&masternode_state).await.map_err(|e| {
            SyncError::SyncFailed(format!("Failed to store masternode state: {}", e))
        })?;

        tracing::info!("Updated masternode list sync height to {}", target_height);

        Ok(())
    }

    /// Reset sync state.
    pub fn reset(&mut self) {
        self.sync_in_progress = false;
        if let Some(_engine) = &mut self.engine {
            // TODO: Reset engine state if needed
        }
    }

    /// Get a reference to the masternode engine for validation.
    pub fn engine(&self) -> Option<&MasternodeListEngine> {
        self.engine.as_ref()
    }
}
