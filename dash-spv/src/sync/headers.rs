//! Header synchronization functionality.

use dashcore::{
    block::Header as BlockHeader,
    network::message::NetworkMessage,
    network::message_blockdata::GetHeadersMessage,
    BlockHash,
};
use dashcore_hashes::Hash;

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::types::SyncProgress;
use crate::validation::ValidationManager;

/// Manages header synchronization.
pub struct HeaderSyncManager {
    config: ClientConfig,
    validation: ValidationManager,
}

impl HeaderSyncManager {
    /// Create a new header sync manager.
    pub fn new(config: &ClientConfig) -> Self {
        Self {
            config: config.clone(),
            validation: ValidationManager::new(config.validation_mode),
        }
    }
    
    /// Synchronize headers with the network.
    pub async fn sync(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<SyncProgress> {
        tracing::info!("Starting header synchronization");
        
        // Get current tip from storage
        let current_tip_height = storage.get_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip height: {}", e)))?;
        
        let base_hash = match current_tip_height {
            None => {
                // No headers in storage yet - start from genesis
                // Use genesis block hash to request headers starting from block 1
                let genesis_hash = self.config.network.known_genesis_block_hash().expect("unable to get genesis block hash");
                Some(genesis_hash)
            }
            Some(height) => {
                // Get the tip hash - request headers after this one
                let tip_header = storage.get_header(height).await
                    .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip header: {}", e)))?
                    .ok_or_else(|| SyncError::SyncFailed("Tip header not found".to_string()))?;
                Some(tip_header.block_hash())
            }
        };
        
        // Request headers starting from our tip
        self.request_headers(network, base_hash).await?;
        
        // Process incoming headers
        let mut new_headers = Vec::new();
        let mut timeout_count = 0;
        let max_timeouts = 10;
        
        loop {
            match network.receive_message().await {
                Ok(Some(NetworkMessage::Headers(headers))) => {
                    timeout_count = 0;
                    
                    if headers.is_empty() {
                        // No more headers available
                        break;
                    }
                    
                    tracing::debug!("Received {} headers starting at {}", headers.len(), headers[0].block_hash());
                    if !headers.is_empty() {
                        tracing::trace!("First header: {:?}", headers[0].block_hash());
                        tracing::trace!("Last header: {:?}", headers.last().unwrap().block_hash());
                    }
                    
                    // Validate headers
                    let validated_headers = self.validate_headers(&headers, storage).await?;
                    
                    // Store validated headers
                    storage.store_headers(&validated_headers).await
                        .map_err(|e| SyncError::SyncFailed(format!("Failed to store headers: {}", e)))?;
                    
                    new_headers.extend(validated_headers);
                    
                    // If we got a full batch, request more
                    if headers.len() == self.config.max_headers_per_message as usize {
                        let last_hash = headers.last().unwrap().block_hash();
                        self.request_headers(network, Some(last_hash)).await?;
                    } else {
                        // Partial batch means we're at the tip
                        break;
                    }
                }
                Ok(Some(_)) => {
                    // Ignore other messages during header sync
                    continue;
                }
                Ok(None) => {
                    // No message available, check timeout
                    timeout_count += 1;
                    if timeout_count >= max_timeouts {
                        return Err(SyncError::SyncTimeout);
                    }
                    
                    // Small delay before trying again
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                Err(e) => {
                    return Err(SyncError::SyncFailed(format!("Network error during header sync: {}", e)));
                }
            }
        }
        
        let final_height = storage.get_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get final tip height: {}", e)))?
            .unwrap_or(0);
        
        tracing::info!("Header synchronization completed. New tip height: {}", final_height);
        
        Ok(SyncProgress {
            header_height: final_height,
            headers_synced: true,
            ..SyncProgress::default()
        })
    }
    
    /// Request headers from the network.
    async fn request_headers(
        &mut self,
        network: &mut dyn NetworkManager,
        base_hash: Option<BlockHash>,
    ) -> SyncResult<()> {
        // Note: Removed broken in-flight check that was preventing subsequent requests
        // The loop in sync() already handles request pacing properly
        
        // Build block locator 
        let block_locator = match base_hash {
            Some(hash) => vec![hash],  // Include our tip hash to request headers after it
            None => vec![],            // Empty locator to request headers from genesis
        };
        
        // No specific stop hash (all zeros means sync to tip)
        let stop_hash = BlockHash::from_byte_array([0; 32]);
        
        // Create GetHeaders message
        let getheaders_msg = GetHeadersMessage::new(block_locator, stop_hash);
        
        // Send the message
        network.send_message(NetworkMessage::GetHeaders(getheaders_msg)).await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to send GetHeaders: {}", e)))?;
        
        // Headers request sent successfully
        
        tracing::debug!("Requested headers starting from {:?}", base_hash);
        
        Ok(())
    }
    
    /// Validate a batch of headers.
    async fn validate_headers(
        &self,
        headers: &[BlockHeader],
        storage: &dyn StorageManager,
    ) -> SyncResult<Vec<BlockHeader>> {
        if headers.is_empty() {
            return Ok(Vec::new());
        }
        
        let mut validated = Vec::new();
        
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
        // No state to reset currently
    }
}