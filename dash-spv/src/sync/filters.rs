//! Filter synchronization functionality.

use dashcore::{
    hash_types::FilterHeader,
    network::message::NetworkMessage,
    network::message_filter::{CFHeaders, GetCFHeaders, CFilter, GetCFilters},
    BlockHash,
};
use dashcore_hashes::{sha256d, Hash};

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::types::SyncProgress;

/// Manages BIP157 filter synchronization.
pub struct FilterSyncManager {
    config: ClientConfig,
    syncing_filter_headers: bool,
    syncing_filters: bool,
}

impl FilterSyncManager {
    /// Create a new filter sync manager.
    pub fn new(config: &ClientConfig) -> Self {
        Self {
            config: config.clone(),
            syncing_filter_headers: false,
            syncing_filters: false,
        }
    }
    
    /// Synchronize filter headers.
    pub async fn sync_headers(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<SyncProgress> {
        if self.syncing_filter_headers {
            return Err(SyncError::SyncInProgress);
        }
        
        self.syncing_filter_headers = true;
        
        tracing::info!("Starting filter header synchronization");
        
        // Get current filter tip
        let current_filter_height = storage.get_filter_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get filter tip: {}", e)))?
            .unwrap_or(0);
        
        // Get current header tip to know how far to sync
        let header_tip_height = storage.get_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get header tip: {}", e)))?
            .unwrap_or(0);
        
        if current_filter_height >= header_tip_height {
            tracing::info!("Filter headers already synced to header tip");
            self.syncing_filter_headers = false;
            return Ok(SyncProgress {
                filter_header_height: current_filter_height,
                filter_headers_synced: true,
                ..SyncProgress::default()
            });
        }
        
        // Get the stop hash (tip of headers)
        let stop_hash = if header_tip_height > 0 {
            storage.get_header(header_tip_height).await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to get stop header: {}", e)))?
                .ok_or_else(|| SyncError::SyncFailed("Stop header not found".to_string()))?
                .block_hash()
        } else {
            return Err(SyncError::SyncFailed("No headers available for filter sync".to_string()));
        };
        
        // Request filter headers
        self.request_filter_headers(network, current_filter_height + 1, stop_hash).await?;
        
        // Process incoming filter headers
        let mut timeout_count = 0;
        let max_timeouts = 10;
        
        loop {
            match network.receive_message().await {
                Ok(Some(NetworkMessage::CFHeaders(cf_headers))) => {
                    timeout_count = 0;
                    
                    if cf_headers.filter_hashes.is_empty() {
                        break;
                    }
                    
                    // Verify and process filter headers
                    let new_filter_headers = self.process_filter_headers(&cf_headers, current_filter_height, storage).await?;
                    
                    if !new_filter_headers.is_empty() {
                        // Store the new filter headers
                        storage.store_filter_headers(&new_filter_headers).await
                            .map_err(|e| SyncError::SyncFailed(format!("Failed to store filter headers: {}", e)))?;
                        
                        tracing::info!("Stored {} filter headers", new_filter_headers.len());
                    }
                    
                    // Check if we need to request more
                    let new_filter_height = storage.get_filter_tip_height().await
                        .map_err(|e| SyncError::SyncFailed(format!("Failed to get new filter tip: {}", e)))?
                        .unwrap_or(0);
                    
                    if new_filter_height >= header_tip_height {
                        break;
                    }
                }
                Ok(Some(_)) => {
                    // Ignore other messages
                    continue;
                }
                Ok(None) => {
                    timeout_count += 1;
                    if timeout_count >= max_timeouts {
                        self.syncing_filter_headers = false;
                        return Err(SyncError::SyncTimeout);
                    }
                    
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                Err(e) => {
                    self.syncing_filter_headers = false;
                    return Err(SyncError::SyncFailed(format!("Network error during filter header sync: {}", e)));
                }
            }
        }
        
        let final_filter_height = storage.get_filter_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get final filter tip: {}", e)))?
            .unwrap_or(0);
        
        self.syncing_filter_headers = false;
        
        tracing::info!("Filter header synchronization completed. New tip height: {}", final_filter_height);
        
        Ok(SyncProgress {
            filter_header_height: final_filter_height,
            filter_headers_synced: final_filter_height >= header_tip_height,
            ..SyncProgress::default()
        })
    }
    
    /// Request filter headers from the network.
    async fn request_filter_headers(
        &mut self,
        network: &mut dyn NetworkManager,
        start_height: u32,
        stop_hash: BlockHash,
    ) -> SyncResult<()> {
        let get_cf_headers = GetCFHeaders {
            filter_type: 0, // Basic filter type
            start_height,
            stop_hash,
        };
        
        network.send_message(NetworkMessage::GetCFHeaders(get_cf_headers)).await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to send GetCFHeaders: {}", e)))?;
        
        tracing::debug!("Requested filter headers from height {} to {}", start_height, stop_hash);
        
        Ok(())
    }
    
    /// Process received filter headers and verify chain.
    async fn process_filter_headers(
        &self,
        cf_headers: &CFHeaders,
        start_height: u32,
        storage: &dyn StorageManager,
    ) -> SyncResult<Vec<FilterHeader>> {
        if cf_headers.filter_hashes.is_empty() {
            return Ok(Vec::new());
        }
        
        // Verify filter header chain
        if !self.verify_filter_header_chain(cf_headers, start_height, storage).await? {
            return Err(SyncError::SyncFailed("Filter header chain verification failed".to_string()));
        }
        
        // Convert filter hashes to filter headers
        let mut new_filter_headers = Vec::new();
        let mut prev_header = cf_headers.previous_filter_header;
        
        for filter_hash in &cf_headers.filter_hashes {
            // According to BIP157: filter_header = double_sha256(filter_hash || prev_filter_header)
            let mut data = filter_hash.as_byte_array().to_vec();
            data.extend_from_slice(prev_header.as_byte_array());
            
            let filter_header = FilterHeader::from_byte_array(sha256d::Hash::hash(&data).to_byte_array());
            
            new_filter_headers.push(filter_header);
            prev_header = filter_header;
        }
        
        Ok(new_filter_headers)
    }
    
    /// Verify filter header chain connects to our local chain.
    async fn verify_filter_header_chain(
        &self,
        cf_headers: &CFHeaders,
        start_height: u32,
        storage: &dyn StorageManager,
    ) -> SyncResult<bool> {
        if cf_headers.filter_hashes.is_empty() {
            return Ok(true);
        }
        
        // Get the expected previous filter header from our local chain
        let expected_prev_header = if start_height == 0 {
            FilterHeader::from_byte_array([0; 32]) // Genesis filter header is all zeros
        } else {
            storage.get_filter_header(start_height - 1).await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to get previous filter header: {}", e)))?
                .ok_or_else(|| SyncError::SyncFailed(format!("Missing previous filter header at height {}", start_height - 1)))?
        };
        
        // Verify that the previous_filter_header from the message matches our local chain
        if cf_headers.previous_filter_header != expected_prev_header {
            tracing::error!(
                "Filter header chain doesn't connect to local chain. Expected: {:?}, Received: {:?}",
                expected_prev_header,
                cf_headers.previous_filter_header
            );
            return Ok(false);
        }
        
        tracing::debug!("Filter header chain verification passed for {} headers", cf_headers.filter_hashes.len());
        Ok(true)
    }
    
    /// Reset sync state.
    pub fn reset(&mut self) {
        self.syncing_filter_headers = false;
        self.syncing_filters = false;
    }
}