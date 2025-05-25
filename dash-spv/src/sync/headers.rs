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
    headers_in_flight_to: i32,
    validation: ValidationManager,
}

impl HeaderSyncManager {
    /// Create a new header sync manager.
    pub fn new(config: &ClientConfig) -> Self {
        Self {
            config: config.clone(),
            headers_in_flight_to: 0,
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
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip height: {}", e)))?
            .unwrap_or(0);
        
        let base_hash = if current_tip_height == 0 {
            // Start from genesis
            self.config.network.known_genesis_block_hash()
                .ok_or_else(|| SyncError::SyncFailed("No genesis hash for network".to_string()))?
        } else {
            // Get the tip hash
            storage.get_header(current_tip_height).await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip header: {}", e)))?
                .ok_or_else(|| SyncError::SyncFailed("Tip header not found".to_string()))?
                .block_hash()
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
                    
                    // Validate headers
                    let validated_headers = self.validate_headers(&headers, storage).await?;
                    
                    // Store validated headers
                    storage.store_headers(&validated_headers).await
                        .map_err(|e| SyncError::SyncFailed(format!("Failed to store headers: {}", e)))?;
                    
                    new_headers.extend(validated_headers);
                    
                    // If we got a full batch, request more
                    if headers.len() == self.config.max_headers_per_message as usize {
                        let last_hash = headers.last().unwrap().block_hash();
                        self.request_headers(network, last_hash).await?;
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
        base_hash: BlockHash,
    ) -> SyncResult<()> {
        // Don't request if we already have headers in flight
        let current_height = 0; // TODO: Get from storage
        if current_height < self.headers_in_flight_to as u32 {
            return Ok(());
        }
        
        // Build block locator (simplified - just use the base hash)
        let block_locator = vec![base_hash];
        
        // No specific stop hash (all zeros means sync to tip)
        let stop_hash = BlockHash::from_byte_array([0; 32]);
        
        // Create GetHeaders message
        let getheaders_msg = GetHeadersMessage::new(block_locator, stop_hash);
        
        // Send the message
        network.send_message(NetworkMessage::GetHeaders(getheaders_msg)).await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to send GetHeaders: {}", e)))?;
        
        // Track headers in flight
        self.headers_in_flight_to += self.config.max_headers_per_message as i32;
        
        tracing::debug!("Requested headers starting from {}", base_hash);
        
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
            self.validation.validate_header(header, prev_header.as_ref())
                .map_err(|e| SyncError::SyncFailed(format!("Header validation failed: {}", e)))?;
            
            validated.push(*header);
        }
        
        Ok(validated)
    }
    
    /// Reset sync state.
    pub fn reset(&mut self) {
        self.headers_in_flight_to = 0;
    }
}