//! Header synchronization functionality.

use dashcore::{
    block::Header as BlockHeader,
    network::message::NetworkMessage,
    network::message_blockdata::GetHeadersMessage,
    BlockHash,
    network::constants::NetworkExt
};
use dashcore_hashes::Hash;

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::validation::ValidationManager;

/// Manages header synchronization.
pub struct HeaderSyncManager {
    config: ClientConfig,
    validation: ValidationManager,
    total_headers_synced: u32,
    last_progress_log: Option<std::time::Instant>,
    /// Whether header sync is currently in progress
    syncing_headers: bool,
    /// Last time sync progress was made (for timeout detection)
    last_sync_progress: std::time::Instant,
}

impl HeaderSyncManager {
    /// Create a new header sync manager.
    pub fn new(config: &ClientConfig) -> Self {
        Self {
            config: config.clone(),
            validation: ValidationManager::new(config.validation_mode),
            total_headers_synced: 0,
            last_progress_log: None,
            syncing_headers: false,
            last_sync_progress: std::time::Instant::now(),
        }
    }
    
    /// Handle a Headers message during header synchronization or for new blocks received post-sync.
    /// Returns true if the message was processed and sync should continue, false if sync is complete.
    pub async fn handle_headers_message(
        &mut self,
        headers: Vec<BlockHeader>,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<bool> {
        tracing::info!("🔍 Handle headers message called with {} headers, syncing_headers: {}", 
                       headers.len(), self.syncing_headers);
        
        if headers.is_empty() {
            if self.syncing_headers {
                // No more headers available during sync
                tracing::info!("Received empty headers response, sync complete");
                self.syncing_headers = false;
                return Ok(false);
            } else {
                // Empty headers outside of sync - just ignore
                tracing::debug!("Received empty headers response outside of sync");
                return Ok(true);
            }
        }

        if self.syncing_headers {
            self.last_sync_progress = std::time::Instant::now();
        }
        
        // Update progress tracking
        self.total_headers_synced += headers.len() as u32;
        
        // Log progress periodically (every 10,000 headers or every 30 seconds)
        let should_log = match self.last_progress_log {
            None => true,
            Some(last_time) => {
                last_time.elapsed() >= std::time::Duration::from_secs(30) || 
                self.total_headers_synced % 10000 == 0
            }
        };
        
        if should_log {
            let current_tip_height = storage.get_tip_height().await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip height: {}", e)))?
                .unwrap_or(0);
            
            tracing::info!("📊 Header sync progress: {} headers synced (current tip: height {})", 
                         self.total_headers_synced, current_tip_height + headers.len() as u32);
            tracing::debug!("Latest batch: {} headers, range {} → {}", 
                          headers.len(), headers[0].block_hash(), headers.last().unwrap().block_hash());
            self.last_progress_log = Some(std::time::Instant::now());
        } else {
            // Just a brief debug message for each batch
            tracing::debug!("Received {} headers (total synced: {})", headers.len(), self.total_headers_synced);
        }
        
        // Validate headers
        let validated_headers = self.validate_headers(&headers, storage).await?;
        
        // Store headers
        storage.store_headers(&validated_headers).await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to store headers: {}", e)))?;
        
        if self.syncing_headers {
            // During sync mode - request next batch
            let last_header = headers.last().unwrap();
            self.request_headers(network, Some(last_header.block_hash())).await?;
        } else {
            // Post-sync mode - new blocks received dynamically
            tracing::info!("📋 Processed {} new headers post-sync", headers.len());
            
            // For post-sync headers, we return true to indicate successful processing
            // The caller can then request filter headers and filters for these new blocks
        }
        
        Ok(true)
    }

    /// Check if a sync timeout has occurred and handle recovery.
    pub async fn check_sync_timeout(
        &mut self,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<bool> {
        if !self.syncing_headers {
            return Ok(false);
        }

        let timeout_duration = if network.peer_count() == 0 {
            // More aggressive timeout when no peers
            std::time::Duration::from_secs(5)
        } else {
            std::time::Duration::from_secs(10)
        };

        if self.last_sync_progress.elapsed() > timeout_duration {
            if network.peer_count() == 0 {
                tracing::warn!("📊 Header sync stalled - no connected peers");
                self.syncing_headers = false; // Reset state to allow restart
                return Err(SyncError::SyncFailed("No connected peers for header sync".to_string()));
            }
            
            tracing::warn!("📊 No header sync progress for {}+ seconds, re-sending header request", 
                          timeout_duration.as_secs());
            
            // Get current tip for recovery
            let current_tip_height = storage.get_tip_height().await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip height: {}", e)))?;
            
            let recovery_base_hash = match current_tip_height {
                None => None, // Genesis
                Some(height) => {
                    // Get the current tip hash
                    storage.get_header(height).await
                        .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip header for recovery: {}", e)))?
                        .map(|h| h.block_hash())
                }
            };
            
            self.request_headers(network, recovery_base_hash).await?;
            self.last_sync_progress = std::time::Instant::now();
            
            return Ok(true);
        }

        Ok(false)
    }

    /// Prepare sync state without sending network requests.
    /// This allows monitoring to be set up before requests are sent.
    pub async fn prepare_sync(
        &mut self,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<Option<dashcore::BlockHash>> {
        if self.syncing_headers {
            return Err(SyncError::SyncInProgress);
        }

        tracing::info!("Preparing header synchronization");
        
        // Get current tip from storage
        let current_tip_height = storage.get_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip height: {}", e)))?;
        
        let base_hash = match current_tip_height {
            None => None, // Start from genesis
            Some(height) => {
                // Get the current tip hash
                let tip_header = storage.get_header(height).await
                    .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip header: {}", e)))?;
                tip_header.map(|h| h.block_hash())
            }
        };
        
        // Set sync state but don't send requests yet
        self.syncing_headers = true;
        self.last_sync_progress = std::time::Instant::now();
        tracing::info!("✅ Prepared header sync state, ready to request headers from {:?}", base_hash);
        
        Ok(base_hash)
    }
    
    /// Start synchronizing headers (initialize the sync state).
    /// This replaces the old sync method but doesn't loop for messages.
    pub async fn start_sync(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<bool> {
        if self.syncing_headers {
            return Err(SyncError::SyncInProgress);
        }

        tracing::info!("Starting header synchronization");
        
        // Get current tip from storage
        let current_tip_height = storage.get_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip height: {}", e)))?;
        
        let base_hash = match current_tip_height {
            None => None, // Start from genesis
            Some(height) => {
                // Get the current tip hash
                let tip_header = storage.get_header(height).await
                    .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip header: {}", e)))?;
                tip_header.map(|h| h.block_hash())
            }
        };
        
        // Set sync state
        self.syncing_headers = true;
        self.last_sync_progress = std::time::Instant::now();
        tracing::info!("✅ Set syncing_headers = true, requesting headers from {:?}", base_hash);
        
        // Request headers starting from our current tip
        self.request_headers(network, base_hash).await?;
        
        Ok(true) // Sync started
    }

    
    /// Request headers from the network.
    pub async fn request_headers(
        &mut self,
        network: &mut dyn NetworkManager,
        base_hash: Option<BlockHash>,
    ) -> SyncResult<()> {
        // Note: Removed broken in-flight check that was preventing subsequent requests
        // The loop in sync() already handles request pacing properly
        
        // Build block locator - use slices where possible to reduce allocations
        let block_locator = match base_hash {
            Some(hash) => vec![hash],  // Need vec here for GetHeadersMessage
            None => Vec::new(),        // Empty locator to request headers from genesis
        };
        
        // No specific stop hash (all zeros means sync to tip)
        let stop_hash = BlockHash::from_byte_array([0; 32]);
        
        // Create GetHeaders message
        let getheaders_msg = GetHeadersMessage::new(block_locator, stop_hash);
        
        // Send the message
        network.send_message(NetworkMessage::GetHeaders(getheaders_msg)).await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to send GetHeaders: {}", e)))?;
        
        // Headers request sent successfully
        
        if self.total_headers_synced % 10000 == 0 {
            tracing::debug!("Requested headers starting from {:?}", base_hash);
        }
        
        Ok(())
    }
    
    /// Validate a batch of headers.
    pub async fn validate_headers(
        &self,
        headers: &[BlockHeader],
        storage: &dyn StorageManager,
    ) -> SyncResult<Vec<BlockHeader>> {
        if headers.is_empty() {
            return Ok(Vec::new());
        }
        
        let mut validated = Vec::with_capacity(headers.len());
        
        for (i, header) in headers.iter().enumerate() {
            // Get the previous header for validation
            let prev_header = if i == 0 {
                // First header in batch - get from storage
                let current_tip_height = storage.get_tip_height().await
                    .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip height: {}", e)))?;
                
                if let Some(height) = current_tip_height {
                    storage.get_header(height).await
                        .map_err(|e| SyncError::SyncFailed(format!("Failed to get previous header: {}", e)))?
                } else {
                    None
                }
            } else {
                Some(headers[i - 1])
            };
            
            // Validate the header
            // tracing::trace!("Validating header {} at index {}", header.block_hash(), i);
            // if let Some(prev) = prev_header.as_ref() {
            //     tracing::trace!("Previous header: {}", prev.block_hash());
            // }
            
            self.validation.validate_header(header, prev_header.as_ref())
                .map_err(|e| SyncError::SyncFailed(format!("Header validation failed for block {}: {}", header.block_hash(), e)))?;
            
            validated.push(*header);
        }
        
        Ok(validated)
    }
    
    /// Download and validate a single header for a specific block hash.
    pub async fn download_single_header(
        &mut self,
        block_hash: BlockHash,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
        // Check if we already have this header using the efficient reverse index
        if let Some(height) = storage.get_header_height_by_hash(&block_hash).await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to check header existence: {}", e)))? {
            tracing::debug!("Header for block {} already exists at height {}", block_hash, height);
            return Ok(());
        }
        
        tracing::info!("📥 Requesting header for block {}", block_hash);
        
        // Get current tip hash to use as locator
        let current_tip = if let Some(tip_height) = storage.get_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip height: {}", e)))? {
            
            storage.get_header(tip_height).await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip header: {}", e)))?
                .map(|h| h.block_hash())
                .unwrap_or_else(|| self.config.network.known_genesis_block_hash().expect("unable to get genesis block hash"))
        } else {
            self.config.network.known_genesis_block_hash().expect("unable to get genesis block hash")
        };
        
        // Create GetHeaders message with specific stop hash
        let getheaders_msg = GetHeadersMessage {
            version: 70214, // Dash protocol version
            locator_hashes: vec![current_tip],
            stop_hash: block_hash,
        };
        
        // Send the message
        network.send_message(NetworkMessage::GetHeaders(getheaders_msg)).await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to send GetHeaders: {}", e)))?;
        
        tracing::debug!("Sent getheaders request for block {}", block_hash);
        
        // Note: The header will be processed when we receive the headers response
        // in the normal message handling flow in sync/mod.rs
        
        Ok(())
    }
    
    /// Reset sync state.
    pub fn reset(&mut self) {
        self.total_headers_synced = 0;
        self.last_progress_log = None;
    }
    
    /// Check if header sync is currently in progress.
    pub fn is_syncing(&self) -> bool {
        self.syncing_headers
    }
}