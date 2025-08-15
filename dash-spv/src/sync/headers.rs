//! Header synchronization functionality.

use dashcore::{
    block::Header as BlockHeader, network::constants::NetworkExt, network::message::NetworkMessage,
    network::message_blockdata::GetHeadersMessage, network::message_headers2::Headers2Message,
    BlockHash,
};
use dashcore_hashes::Hash;

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::headers2_state::Headers2StateManager;
use crate::validation::ValidationManager;

/// Manages header synchronization.
pub struct HeaderSyncManager {
    config: ClientConfig,
    validation: ValidationManager,
    headers2_state: Headers2StateManager,
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
            headers2_state: Headers2StateManager::new(),
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
        tracing::info!(
            "🔍 Handle headers message called with {} headers, syncing_headers: {}",
            headers.len(),
            self.syncing_headers
        );

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

        // Log the first and last header received
        tracing::info!(
            "📥 Processing headers: first={} last={}",
            headers[0].block_hash(),
            headers[headers.len() - 1].block_hash()
        );

        // Get the current tip before processing
        let tip_before = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?;
        tracing::info!("📊 Current tip height before processing: {:?}", tip_before);

        if self.syncing_headers {
            self.last_sync_progress = std::time::Instant::now();
        }

        // Update progress tracking
        self.total_headers_synced += headers.len() as u32;

        // Log progress periodically (every 10,000 headers or every 30 seconds)
        let should_log = match self.last_progress_log {
            None => true,
            Some(last_time) => {
                last_time.elapsed() >= std::time::Duration::from_secs(30)
                    || self.total_headers_synced % 10000 == 0
            }
        };

        if should_log {
            let current_tip_height = storage
                .get_tip_height()
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?
                .unwrap_or(0);

            tracing::info!(
                "📊 Header sync progress: {} headers synced (current tip: height {})",
                self.total_headers_synced,
                current_tip_height + headers.len() as u32
            );
            tracing::debug!(
                "Latest batch: {} headers, range {} → {}",
                headers.len(),
                headers[0].block_hash(),
                headers.last().map(|h| h.block_hash()).unwrap_or_else(|| headers[0].block_hash())
            );
            self.last_progress_log = Some(std::time::Instant::now());
        } else {
            // Just a brief debug message for each batch
            tracing::debug!(
                "Received {} headers (total synced: {})",
                headers.len(),
                self.total_headers_synced
            );
        }

        // Validate headers
        let validated_headers = self.validate_headers(&headers, storage).await?;

        // Store headers
        storage
            .store_headers(&validated_headers)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to store headers: {}", e)))?;

        // Get the current tip after processing
        let tip_after = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?;
        tracing::info!("📊 Current tip height after processing: {:?}", tip_after);

        // Log if headers were actually stored
        if tip_before != tip_after {
            tracing::info!(
                "✅ Successfully stored {} headers, tip advanced from {:?} to {:?}",
                validated_headers.len(),
                tip_before,
                tip_after
            );
        } else {
            tracing::warn!("⚠️ Headers validated but tip height unchanged! Validated {} headers but tip remains at {:?}", 
                validated_headers.len(), tip_before);
        }

        if self.syncing_headers {
            // During sync mode - request next batch
            if let Some(last_header) = headers.last() {
                self.request_headers(network, Some(last_header.block_hash())).await?;
            } else {
                return Err(SyncError::InvalidState(
                    "Headers array empty when expected".to_string(),
                ));
            }
        } else {
            // Post-sync mode - new blocks received dynamically
            tracing::info!("📋 Processed {} new headers post-sync", headers.len());

            // For post-sync headers, we return true to indicate successful processing
            // The caller can then request filter headers and filters for these new blocks
        }

        Ok(true)
    }

    /// Handle a Headers2 message with compressed headers.
    /// Returns true if the message was processed and sync should continue, false if sync is complete.
    pub async fn handle_headers2_message(
        &mut self,
        headers2: Headers2Message,
        peer_id: crate::types::PeerId,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<bool> {
        tracing::info!(
            "🔍 Handle headers2 message called with {} compressed headers from peer {}",
            headers2.headers.len(),
            peer_id
        );

        // Decompress headers using the peer's compression state
        let headers = self
            .headers2_state
            .process_headers(peer_id, headers2.headers)
            .map_err(|e| SyncError::Validation(format!("Failed to decompress headers: {}", e)))?;

        // Log compression statistics
        let stats = self.headers2_state.get_stats();
        tracing::info!(
            "📊 Headers2 compression stats: {:.1}% bandwidth saved, {:.1}% compression ratio",
            stats.bandwidth_savings,
            stats.compression_ratio * 100.0
        );

        // Process decompressed headers through the normal flow
        self.handle_headers_message(headers, storage, network).await
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
            std::time::Duration::from_secs(10)
        } else {
            std::time::Duration::from_secs(5)
        };

        if self.last_sync_progress.elapsed() > timeout_duration {
            if network.peer_count() == 0 {
                tracing::warn!("📊 Header sync stalled - no connected peers");
                self.syncing_headers = false; // Reset state to allow restart
                return Err(SyncError::Network("No connected peers for header sync".to_string()));
            }

            tracing::warn!(
                "📊 No header sync progress for {}+ seconds, re-sending header request",
                timeout_duration.as_secs()
            );

            // Get current tip for recovery
            let current_tip_height = storage
                .get_tip_height()
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?;

            let recovery_base_hash = match current_tip_height {
                None => None, // Genesis
                Some(height) => {
                    // Get the current tip hash
                    storage
                        .get_header(height)
                        .await
                        .map_err(|e| {
                            SyncError::Storage(format!(
                                "Failed to get tip header for recovery: {}",
                                e
                            ))
                        })?
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
        let current_tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?;

        let base_hash = match current_tip_height {
            None => {
                tracing::info!("No tip height found, will start from genesis");
                None // Start from genesis
            }
            Some(height) => {
                tracing::info!("Current tip height: {}", height);
                // Get the current tip hash
                let tip_header = storage
                    .get_header(height)
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to get tip header: {}", e)))?;
                let hash = tip_header.map(|h| h.block_hash());
                tracing::info!("Current tip hash: {:?}", hash);
                hash
            }
        };

        // Set sync state but don't send requests yet
        self.syncing_headers = true;
        self.last_sync_progress = std::time::Instant::now();
        tracing::info!(
            "✅ Prepared header sync state, ready to request headers from {:?}",
            base_hash
        );

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
        let current_tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?;

        let base_hash = match current_tip_height {
            None => None, // Start from genesis
            Some(height) => {
                // Get the current tip hash
                let tip_header = storage
                    .get_header(height)
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to get tip header: {}", e)))?;
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
            Some(hash) => {
                log::info!("📍 Requesting headers starting from hash: {}", hash);
                vec![hash] // Need vec here for GetHeadersMessage
            }
            None => {
                // Empty locator for initial sync - some peers expect this
                log::info!("📍 Requesting headers from genesis with empty locator");
                Vec::new()
            }
        };

        // No specific stop hash (all zeros means sync to tip)
        let stop_hash = BlockHash::from_byte_array([0; 32]);

        // Create GetHeaders message
        let getheaders_msg = GetHeadersMessage::new(block_locator.clone(), stop_hash);

        // Check if we have a peer that supports headers2
        let use_headers2 = network.has_headers2_peer().await;

        if use_headers2 {
            tracing::info!("📤 Sending GetHeaders2 message (compressed headers)");
            // Send GetHeaders2 message for compressed headers
            network
                .send_message(NetworkMessage::GetHeaders2(getheaders_msg))
                .await
                .map_err(|e| SyncError::Network(format!("Failed to send GetHeaders2: {}", e)))?;
        } else {
            tracing::info!("📤 Sending GetHeaders message (uncompressed headers)");
            // Send regular GetHeaders message
            network
                .send_message(NetworkMessage::GetHeaders(getheaders_msg))
                .await
                .map_err(|e| SyncError::Network(format!("Failed to send GetHeaders: {}", e)))?;
        }

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
                let current_tip_height = storage
                    .get_tip_height()
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?;

                if let Some(height) = current_tip_height {
                    storage.get_header(height).await.map_err(|e| {
                        SyncError::Storage(format!("Failed to get previous header: {}", e))
                    })?
                } else {
                    None
                }
            } else {
                Some(headers[i - 1])
            };

            // Check if this header already exists in storage
            let already_exists = storage
                .get_header_height_by_hash(&header.block_hash())
                .await
                .map_err(|e| {
                    SyncError::Storage(format!("Failed to check header existence: {}", e))
                })?
                .is_some();

            if already_exists {
                tracing::info!(
                    "⚠️ Header {} already exists in storage, skipping validation",
                    header.block_hash()
                );
                // Add the existing header to validated vector so subsequent headers
                // can reference it correctly
                validated.push(*header);
                continue;
            }

            // Validate the header
            tracing::info!("Validating new header {} at index {}", header.block_hash(), i);
            if let Some(prev) = prev_header.as_ref() {
                tracing::debug!("Previous header: {}", prev.block_hash());
            }

            self.validation.validate_header(header, prev_header.as_ref()).map_err(|e| {
                SyncError::Validation(format!(
                    "Header validation failed for block {}: {}",
                    header.block_hash(),
                    e
                ))
            })?;

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
        if let Some(height) = storage
            .get_header_height_by_hash(&block_hash)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to check header existence: {}", e)))?
        {
            tracing::debug!("Header for block {} already exists at height {}", block_hash, height);
            return Ok(());
        }

        tracing::info!("📥 Requesting header for block {}", block_hash);

        // Get current tip hash to use as locator
        let current_tip = if let Some(tip_height) = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?
        {
            storage
                .get_header(tip_height)
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get tip header: {}", e)))?
                .map(|h| h.block_hash())
                .unwrap_or_else(|| {
                    self.config
                        .network
                        .known_genesis_block_hash()
                        .ok_or_else(|| {
                            SyncError::InvalidState(
                                "Unable to get genesis block hash for network".to_string(),
                            )
                        })
                        .unwrap_or_else(|e| {
                            tracing::error!("Failed to get genesis block hash: {}", e);
                            dashcore::BlockHash::from([0u8; 32])
                        })
                })
        } else {
            self.config
                .network
                .known_genesis_block_hash()
                .ok_or_else(|| {
                    SyncError::InvalidState(
                        "Unable to get genesis block hash for network".to_string(),
                    )
                })
                .unwrap_or_else(|e| {
                    tracing::error!("Failed to get genesis block hash: {}", e);
                    dashcore::BlockHash::from([0u8; 32])
                })
        };

        tracing::info!(
            "📍 Using tip at height {:?} as locator: {}",
            storage.get_tip_height().await.ok().flatten(),
            current_tip
        );

        // Create GetHeaders message requesting headers up to and including the specific block
        // The peer will send headers starting after our current tip up to the requested block
        let getheaders_msg = GetHeadersMessage {
            version: 70214, // Dash protocol version
            locator_hashes: vec![current_tip],
            stop_hash: block_hash, // Request headers up to this specific block
        };

        tracing::info!("📤 Requesting headers from {} up to block {}", current_tip, block_hash);

        // Send the message
        network
            .send_message(NetworkMessage::GetHeaders(getheaders_msg))
            .await
            .map_err(|e| SyncError::Network(format!("Failed to send GetHeaders: {}", e)))?;

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

    /// Reset any pending requests after restart.
    pub fn reset_pending_requests(&mut self) {
        // Headers sync doesn't track individual pending requests
        // Just reset the sync state
        self.syncing_headers = false;
        self.last_sync_progress = std::time::Instant::now();
        tracing::debug!("Reset header sync pending requests");
    }

    /// Get headers2 compression statistics.
    pub fn headers2_stats(&self) -> crate::sync::headers2_state::Headers2Stats {
        self.headers2_state.get_stats()
    }

    /// Reset headers2 state for a peer (e.g., on disconnect).
    pub fn reset_headers2_peer(&mut self, peer_id: crate::types::PeerId) {
        self.headers2_state.reset_peer(peer_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{client::ClientConfig, storage::MemoryStorageManager, types::ValidationMode};
    use dashcore::{block::Header as BlockHeader, block::Version, Network};
    use dashcore_hashes::Hash;

    fn create_test_header(height: u32, prev_hash: BlockHash) -> BlockHeader {
        BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: prev_hash,
            merkle_root: dashcore::TxMerkleNode::from_byte_array([height as u8; 32]),
            time: 1234567890 + height,
            bits: dashcore::CompactTarget::from_consensus(0x1d00ffff),
            nonce: height,
        }
    }

    #[tokio::test]
    async fn test_validate_headers_includes_existing_headers() {
        // Create storage with some existing headers
        let mut storage = MemoryStorageManager::new().await.unwrap();

        // Store the genesis header
        let genesis = create_test_header(0, BlockHash::from([0u8; 32]));
        storage.store_headers(&[genesis]).await.unwrap();

        // Store header at height 1
        let header1 = create_test_header(1, genesis.block_hash());
        storage.store_headers(&[header1]).await.unwrap();

        // Create a config and sync manager
        let config = ClientConfig::new(Network::Dash).with_validation_mode(ValidationMode::Basic);
        let sync_manager = HeaderSyncManager::new(&config);

        // Create a batch of headers where the first two already exist
        let headers = vec![
            genesis,                                     // Already exists
            header1,                                     // Already exists
            create_test_header(2, header1.block_hash()), // New
            create_test_header(3, create_test_header(2, header1.block_hash()).block_hash()), // New
        ];

        // Validate headers
        let validated = sync_manager.validate_headers(&headers, &storage).await.unwrap();

        // All headers should be in the validated vector, including existing ones
        assert_eq!(validated.len(), 4, "All headers should be included in validated vector");

        // Verify the headers are in correct order
        assert_eq!(validated[0].block_hash(), genesis.block_hash());
        assert_eq!(validated[1].block_hash(), header1.block_hash());
        assert_eq!(validated[2].prev_blockhash, header1.block_hash());
        assert_eq!(validated[3].prev_blockhash, validated[2].block_hash());
    }

    #[tokio::test]
    async fn test_validate_headers_with_gaps() {
        // Create storage with a header at height 0
        let mut storage = MemoryStorageManager::new().await.unwrap();
        let genesis = create_test_header(0, BlockHash::from([0u8; 32]));
        storage.store_headers(&[genesis]).await.unwrap();

        // Create config and sync manager
        let config = ClientConfig::new(Network::Dash).with_validation_mode(ValidationMode::Basic);
        let sync_manager = HeaderSyncManager::new(&config);

        // Create headers with a gap - header at height 2 is missing from storage
        let header1 = create_test_header(1, genesis.block_hash());
        let header2 = create_test_header(2, header1.block_hash());
        let header3 = create_test_header(3, header2.block_hash());

        // Store only header1, skip header2
        storage.store_headers(&[header1]).await.unwrap();

        // Try to validate a batch that includes the existing header1, new header2, and new header3
        let headers = vec![header1, header2, header3];

        let validated = sync_manager.validate_headers(&headers, &storage).await.unwrap();

        // All headers should be validated successfully
        assert_eq!(validated.len(), 3, "All headers should be validated");

        // The existing header1 should be included so header2 can reference it
        assert_eq!(validated[0].block_hash(), header1.block_hash());
        assert_eq!(validated[1].prev_blockhash, header1.block_hash());
        assert_eq!(validated[2].prev_blockhash, header2.block_hash());
    }
}
