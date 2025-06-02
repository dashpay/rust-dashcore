//! Masternode synchronization functionality.

use dashcore::{
    network::message::NetworkMessage,
    network::message_sml::{GetMnListDiff, MnListDiff},
    sml::masternode_list_engine::MasternodeListEngine,
    BlockHash,
};
use dashcore_hashes::Hash;

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::{StorageManager, MasternodeState};
use crate::types::SyncProgress;

/// Manages masternode list synchronization.
pub struct MasternodeSyncManager {
    config: ClientConfig,
    sync_in_progress: bool,
    engine: Option<MasternodeListEngine>,
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
        }
    }
    
    /// Synchronize masternode list.
    pub async fn sync(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<SyncProgress> {
        if self.sync_in_progress {
            return Err(SyncError::SyncInProgress);
        }
        
        let _engine = self.engine.as_mut()
            .ok_or_else(|| SyncError::SyncFailed("Masternode engine not initialized".to_string()))?;
        
        self.sync_in_progress = true;
        
        tracing::info!("Starting masternode list synchronization");
        
        // Load existing masternode state
        if let Some(state) = storage.load_masternode_state().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to load masternode state: {}", e)))? {
            
            // TODO: Restore engine state from serialized data
            tracing::info!("Loaded existing masternode state from height {}", state.last_height);
        }
        
        // Get current header height
        let current_height = storage.get_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get current height: {}", e)))?
            .unwrap_or(0);
        
        // Get last synced masternode height
        let mut last_masternode_height = storage.load_masternode_state().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to load masternode state: {}", e)))?
            .map(|s| s.last_height)
            .unwrap_or(0);
        
        // Check if we need to reset masternode engine due to inconsistent state
        if last_masternode_height > 0 {
            // If we have a stored masternode height but no engine state for it,
            // we need to start fresh from genesis
            tracing::warn!("Detected potential masternode state inconsistency. Starting fresh from genesis.");
            tracing::warn!("Last masternode height: {}, Current height: {}", last_masternode_height, current_height);
            
            // Reset the masternode engine
            if let Some(engine) = &mut self.engine {
                *engine = MasternodeListEngine::default_for_network(self.config.network);
                // Feed genesis block hash at height 0
                if let Some(genesis_hash) = self.config.network.known_genesis_block_hash() {
                    engine.feed_block_height(0, genesis_hash);
                }
            }
            
            // Clear stored masternode state to start fresh
            // Note: For now we just reset the height, but ideally we'd have a clear_masternode_state method
            tracing::info!("Masternode engine reset to start from genesis");
            
            // Start from height 0
            last_masternode_height = 0;
        }
        
        if current_height <= last_masternode_height {
            tracing::info!("Masternode list already synced to current height");
            self.sync_in_progress = false;
            return Ok(SyncProgress {
                masternode_height: last_masternode_height,
                masternodes_synced: true,
                ..SyncProgress::default()
            });
        }
        
        // Request masternode list diff
        self.request_masternode_diff(network, storage, last_masternode_height, current_height).await?;
        
        // Process response
        let mut timeout_count = 0;
        let max_timeouts = 10;
        
        loop {
            match network.receive_message().await {
                Ok(Some(NetworkMessage::MnListDiff(diff))) => {
                    // Process the diff
                    self.process_masternode_diff(diff, storage).await?;
                    break;
                }
                Ok(Some(_)) => {
                    // Ignore other messages
                    continue;
                }
                Ok(None) => {
                    timeout_count += 1;
                    if timeout_count >= max_timeouts {
                        self.sync_in_progress = false;
                        return Err(SyncError::SyncTimeout);
                    }
                    
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                Err(e) => {
                    self.sync_in_progress = false;
                    return Err(SyncError::SyncFailed(format!("Network error during masternode sync: {}", e)));
                }
            }
        }
        
        self.sync_in_progress = false;
        
        let final_masternode_height = storage.load_masternode_state().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to load final masternode state: {}", e)))?
            .map(|s| s.last_height)
            .unwrap_or(0);
        
        tracing::info!("Masternode list synchronization completed. New height: {}", final_masternode_height);
        
        Ok(SyncProgress {
            masternode_height: final_masternode_height,
            masternodes_synced: final_masternode_height >= current_height,
            ..SyncProgress::default()
        })
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
            self.config.network.known_genesis_block_hash()
                .ok_or_else(|| SyncError::SyncFailed("No genesis hash for network".to_string()))?
        } else {
            storage.get_header(base_height).await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to get base header: {}", e)))?
                .ok_or_else(|| SyncError::SyncFailed("Base header not found".to_string()))?
                .block_hash()
        };
        
        // Get current block hash
        let current_block_hash = storage.get_header(current_height).await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get current header: {}", e)))?
            .ok_or_else(|| SyncError::SyncFailed("Current header not found".to_string()))?
            .block_hash();
        
        let get_mn_list_diff = GetMnListDiff {
            base_block_hash,
            block_hash: current_block_hash,
        };
        
        network.send_message(NetworkMessage::GetMnListD(get_mn_list_diff)).await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to send GetMnListDiff: {}", e)))?;
        
        tracing::debug!("Requested masternode list diff from {} to {}", base_height, current_height);
        
        Ok(())
    }
    
    /// Process received masternode list diff.
    async fn process_masternode_diff(
        &mut self,
        diff: MnListDiff,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
        let engine = self.engine.as_mut()
            .ok_or_else(|| SyncError::SyncFailed("Masternode engine not initialized".to_string()))?;
        
        let _target_block_hash = diff.block_hash;
        
        // Get tip height first as it's needed later
        let tip_height = storage.get_tip_height().await
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
            if let Some(target_height) = storage.get_header_height_by_hash(&target_block_hash).await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to lookup target hash: {}", e)))? {
                engine.feed_block_height(target_height, target_block_hash);
                tracing::debug!("Fed target block hash {} at height {}", target_block_hash, target_height);
            } else {
                return Err(SyncError::SyncFailed(format!("Target block hash {} not found in storage", target_block_hash)));
            }
            
            // Feed base block hash
            if let Some(base_height) = storage.get_header_height_by_hash(&base_block_hash).await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to lookup base hash: {}", e)))? {
                engine.feed_block_height(base_height, base_block_hash);
                tracing::debug!("Fed base block hash {} at height {}", base_block_hash, base_height);
            }
            
            // Calculate start_height for filtering redundant submissions
            // Feed last 1000 headers or from base height, whichever is more recent
            let start_height = if let Some(base_height) = storage.get_header_height_by_hash(&base_block_hash).await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to lookup base hash: {}", e)))? {
                base_height.saturating_sub(100) // Include some headers before base
            } else {
                tip_height.saturating_sub(1000)
            };
            
            // Feed any quorum hashes from new_quorums that are block hashes
            for quorum in &diff.new_quorums {
                // Note: quorum_hash is not necessarily a block hash, so we check if it exists
                if let Some(quorum_height) = storage.get_header_height_by_hash(&quorum.quorum_hash).await
                    .map_err(|e| SyncError::SyncFailed(format!("Failed to lookup quorum hash: {}", e)))? {
                    // Only feed blocks at or after start_height to avoid redundant submissions
                    if quorum_height >= start_height {
                        engine.feed_block_height(quorum_height, quorum.quorum_hash);
                        tracing::debug!("Fed quorum hash {} at height {}", quorum.quorum_hash, quorum_height);
                    } else {
                        tracing::trace!("Skipping quorum hash {} at height {} (before start_height {})",
                                      quorum.quorum_hash, quorum_height, start_height);
                    }
                }
            }
            
            // Feed a reasonable range of recent headers for validation purposes
            // The engine may need recent headers for various validations
            
            if start_height < tip_height {
                tracing::debug!("Feeding headers from {} to {} to masternode engine", start_height, tip_height);
                let headers = storage.get_headers_batch(start_height, tip_height).await
                    .map_err(|e| SyncError::SyncFailed(format!("Failed to batch load headers: {}", e)))?;
                
                for (height, header) in headers {
                    engine.feed_block_height(height, header.block_hash());
                }
            }
        }
        
        // Special handling for regtest: skip empty diffs
        if self.config.network == dashcore::Network::Regtest {
            // In regtest, masternode diffs might be empty, which is normal
            if is_zero_hash || (diff.merkle_hashes.is_empty() && diff.new_masternodes.is_empty()) {
                tracing::info!("Skipping empty masternode diff in regtest - no masternodes configured");
                
                // Store empty masternode state to mark sync as complete
                let masternode_state = MasternodeState {
                    last_height: tip_height,
                    engine_state: Vec::new(), // Empty state for regtest
                    last_update: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                };
                
                storage.store_masternode_state(&masternode_state).await
                    .map_err(|e| SyncError::SyncFailed(format!("Failed to store masternode state: {}", e)))?;
                
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
        let target_height = storage.get_tip_height().await
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
        
        storage.store_masternode_state(&masternode_state).await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to store masternode state: {}", e)))?;
        
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