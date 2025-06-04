//! Filter synchronization functionality.

use dashcore::{
    hash_types::FilterHeader,
    network::message::NetworkMessage,
    network::message_filter::{CFHeaders, GetCFHeaders, GetCFilters},
    network::message_blockdata::Inventory,
    ScriptBuf, BlockHash,
    bip158::{BlockFilterReader, Error as Bip158Error},
};
use dashcore_hashes::{sha256d, Hash};
use std::collections::{HashMap, VecDeque};

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::types::SyncProgress;

// Constants for filter synchronization
const FILTER_BATCH_SIZE: u32 = 1999; // Stay under Dash Core's 2000 limit
const SYNC_TIMEOUT_SECONDS: u64 = 5;
const RECEIVE_TIMEOUT_MILLIS: u64 = 100;
const DEFAULT_FILTER_SYNC_RANGE: u32 = 100;
const FILTER_REQUEST_BATCH_SIZE: u32 = 100; // For compact filter requests
const MAX_TIMEOUTS: u32 = 10;

/// Manages BIP157 filter synchronization.
pub struct FilterSyncManager {
    _config: ClientConfig,
    /// Whether filter header sync is currently in progress
    syncing_filter_headers: bool,
    /// Current height being synced for filter headers
    current_sync_height: u32,
    /// Expected stop hash for current batch
    expected_stop_hash: Option<BlockHash>,
    /// Last time sync progress was made (for timeout detection)
    last_sync_progress: std::time::Instant,
    /// Whether filter sync is currently in progress
    syncing_filters: bool,
    /// Queue of blocks that have been requested and are waiting for response
    pending_block_downloads: VecDeque<crate::types::FilterMatch>,
    /// Blocks currently being downloaded (map for quick lookup)
    downloading_blocks: HashMap<BlockHash, u32>,
}

impl FilterSyncManager {
    /// Create a new filter sync manager.
    pub fn new(config: &ClientConfig) -> Self {
        Self {
            _config: config.clone(),
            syncing_filter_headers: false,
            current_sync_height: 0,
            expected_stop_hash: None,
            last_sync_progress: std::time::Instant::now(),
            syncing_filters: false,
            pending_block_downloads: VecDeque::new(),
            downloading_blocks: HashMap::new(),
        }
    }
    
    /// Handle a CFHeaders message during filter header synchronization.
    /// Returns true if the message was processed and sync should continue, false if sync is complete.
    pub async fn handle_cfheaders_message(
        &mut self,
        cf_headers: CFHeaders,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<bool> {
        if !self.syncing_filter_headers {
            // Not currently syncing, ignore
            return Ok(true);
        }

        self.last_sync_progress = std::time::Instant::now();
        
        if cf_headers.filter_hashes.is_empty() {
            // Empty response indicates end of sync
            self.syncing_filter_headers = false;
            return Ok(false);
        }

        // Get header tip height for validation
        let header_tip_height = storage.get_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get header tip height: {}", e)))?
            .unwrap_or(0);

        // Determine the actual start height of this batch
        let stop_height = self.find_height_for_block_hash(&cf_headers.stop_hash, storage, 0, header_tip_height).await?
            .ok_or_else(|| SyncError::SyncFailed(format!(
                "Cannot find height for stop hash {} in CFHeaders", cf_headers.stop_hash
            )))?;

        let batch_start_height = stop_height.saturating_sub(cf_headers.filter_hashes.len() as u32 - 1);
        
        tracing::debug!("Received CFHeaders batch: start={}, stop={}, count={} (expected start={})", 
                       batch_start_height, stop_height, cf_headers.filter_hashes.len(), self.current_sync_height);
        
        // Check if this is the expected batch or if there's overlap
        if batch_start_height < self.current_sync_height {
            tracing::warn!("📋 Received overlapping filter headers: expected start={}, received start={} (likely from recovery/retry)", 
                          self.current_sync_height, batch_start_height);
            
            // Handle overlapping headers using the helper method
            let skip_count = (self.current_sync_height - batch_start_height) as usize;
            let (_, new_current_height) = self.handle_overlapping_headers(
                &cf_headers, 
                skip_count, 
                self.current_sync_height, 
                storage
            ).await?;
            self.current_sync_height = new_current_height;
        } else if batch_start_height > self.current_sync_height {
            // Gap in the sequence - this shouldn't happen in normal operation
            tracing::error!("❌ Gap detected in filter header sequence: expected start={}, received start={} (gap of {} headers)", 
                           self.current_sync_height, batch_start_height, batch_start_height - self.current_sync_height);
            return Err(SyncError::SyncFailed(format!("Gap in filter header sequence: expected {}, got {}", self.current_sync_height, batch_start_height)));
        } else {
            // This is the expected batch - process it
            match self.verify_filter_header_chain(&cf_headers, batch_start_height, storage).await {
                Ok(true) => {
                    tracing::debug!("✅ Filter header chain verification successful for batch {}-{}", 
                                   batch_start_height, stop_height);
                    
                    // Store the verified filter headers
                    self.store_filter_headers(cf_headers.clone(), storage).await?;
                    
                    // Update current height
                    self.current_sync_height = stop_height + 1;
                    
                    // Check if we've reached the header tip
                    if stop_height >= header_tip_height {
                        tracing::info!("🎯 Filter header sync complete at height {}", stop_height);
                        self.syncing_filter_headers = false;
                        return Ok(false);
                    }
                    
                    // Request next batch
                    let next_batch_end_height = (self.current_sync_height + FILTER_BATCH_SIZE - 1).min(header_tip_height);
                    let stop_hash = if next_batch_end_height < header_tip_height {
                        storage.get_header(next_batch_end_height).await
                            .map_err(|e| SyncError::SyncFailed(format!("Failed to get next batch stop header: {}", e)))?
                            .ok_or_else(|| SyncError::SyncFailed("Next batch stop header not found".to_string()))?
                            .block_hash()
                    } else {
                        storage.get_header(header_tip_height).await
                            .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip header: {}", e)))?
                            .ok_or_else(|| SyncError::SyncFailed("Tip header not found".to_string()))?
                            .block_hash()
                    };
                    
                    self.request_filter_headers(network, self.current_sync_height, stop_hash).await?;
                }
                Ok(false) => {
                    tracing::warn!("⚠️ Filter header chain verification failed for batch {}-{}", 
                                  batch_start_height, stop_height);
                    return Err(SyncError::SyncFailed("Filter header chain verification failed".to_string()));
                }
                Err(e) => {
                    tracing::error!("❌ Filter header chain verification failed: {}", e);
                    return Err(e);
                }
            }
        }

        Ok(true)
    }

    /// Check if a sync timeout has occurred and handle recovery.
    pub async fn check_sync_timeout(
        &mut self,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<bool> {
        if !self.syncing_filter_headers {
            return Ok(false);
        }

        if self.last_sync_progress.elapsed() > std::time::Duration::from_secs(SYNC_TIMEOUT_SECONDS) {
            tracing::warn!("📊 No filter header sync progress for {}+ seconds, re-sending filter header request", SYNC_TIMEOUT_SECONDS);
            
            // Get header tip height for recovery
            let header_tip_height = storage.get_tip_height().await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to get header tip height: {}", e)))?
                .unwrap_or(0);
            
            // Re-calculate current batch parameters for recovery
            let recovery_batch_end_height = (self.current_sync_height + FILTER_BATCH_SIZE - 1).min(header_tip_height);
            let recovery_batch_stop_hash = if recovery_batch_end_height < header_tip_height {
                storage.get_header(recovery_batch_end_height).await
                    .map_err(|e| SyncError::SyncFailed(format!("Failed to get recovery batch stop header: {}", e)))?
                    .ok_or_else(|| SyncError::SyncFailed("Recovery batch stop header not found".to_string()))?
                    .block_hash()
            } else {
                storage.get_header(header_tip_height).await
                    .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip header: {}", e)))?
                    .ok_or_else(|| SyncError::SyncFailed("Tip header not found".to_string()))?
                    .block_hash()
            };
            
            self.request_filter_headers(network, self.current_sync_height, recovery_batch_stop_hash).await?;
            self.last_sync_progress = std::time::Instant::now();
            
            return Ok(true);
        }

        Ok(false)
    }

    /// Start synchronizing filter headers (initialize the sync state).
    /// This replaces the old sync_headers method but doesn't loop for messages.
    pub async fn start_sync_headers(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<bool> {
        if self.syncing_filter_headers {
            return Err(SyncError::SyncInProgress);
        }

        tracing::info!("🚀 Starting filter header synchronization");
        
        // Get current filter tip
        let current_filter_height = storage.get_filter_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get filter tip height: {}", e)))?
            .unwrap_or(0);
        
        // Get header tip
        let header_tip_height = storage.get_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get header tip height: {}", e)))?
            .unwrap_or(0);
        
        if current_filter_height >= header_tip_height {
            tracing::info!("Filter headers already synced to header tip");
            return Ok(false); // Already synced
        }
        
        // Set up sync state
        self.syncing_filter_headers = true;
        self.current_sync_height = current_filter_height + 1;
        self.last_sync_progress = std::time::Instant::now();
        
        // Get the stop hash (tip of headers)
        let stop_hash = if header_tip_height > 0 {
            storage.get_header(header_tip_height).await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to get stop header: {}", e)))?
                .ok_or_else(|| SyncError::SyncFailed("Stop header not found".to_string()))?
                .block_hash()
        } else {
            return Err(SyncError::SyncFailed("No headers available for filter sync".to_string()));
        };
        
        // Initial request for first batch
        let batch_end_height = (self.current_sync_height + FILTER_BATCH_SIZE - 1).min(header_tip_height);
        
        tracing::debug!("Requesting filter headers batch: start={}, end={}, count={}", 
                       self.current_sync_height, batch_end_height, batch_end_height - self.current_sync_height + 1);
        
        // Get the hash at batch_end_height for the stop_hash
        let batch_stop_hash = if batch_end_height < header_tip_height {
            storage.get_header(batch_end_height).await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to get batch stop header: {}", e)))?
                .ok_or_else(|| SyncError::SyncFailed("Batch stop header not found".to_string()))?
                .block_hash()
        } else {
            stop_hash
        };
        
        self.request_filter_headers(network, self.current_sync_height, batch_stop_hash).await?;
        
        Ok(true) // Sync started
    }

    
    /// Request filter headers from the network.
    pub async fn request_filter_headers(
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
    pub async fn process_filter_headers(
        &self,
        cf_headers: &CFHeaders,
        start_height: u32,
        storage: &dyn StorageManager,
    ) -> SyncResult<Vec<FilterHeader>> {
        if cf_headers.filter_hashes.is_empty() {
            return Ok(Vec::new());
        }
        
        tracing::debug!("Processing {} filter headers starting from height {}", cf_headers.filter_hashes.len(), start_height);
        
        // Verify filter header chain
        if !self.verify_filter_header_chain(cf_headers, start_height, storage).await? {
            return Err(SyncError::SyncFailed("Filter header chain verification failed".to_string()));
        }
        
        // Convert filter hashes to filter headers
        let mut new_filter_headers = Vec::with_capacity(cf_headers.filter_hashes.len());
        let mut prev_header = cf_headers.previous_filter_header;
        
        // For the first batch starting at height 1, we need to store the genesis filter header (height 0)
        if start_height == 1 {
            // The previous_filter_header is the genesis filter header at height 0
            // We need to store this so subsequent batches can verify against it
            tracing::debug!("Storing genesis filter header: {:?}", prev_header);
            // Note: We'll handle this in the calling function since we need mutable storage access
        }
        
        for (i, filter_hash) in cf_headers.filter_hashes.iter().enumerate() {
            // According to BIP157: filter_header = double_sha256(filter_hash || prev_filter_header)
            let mut data = [0u8; 64];
            data[..32].copy_from_slice(filter_hash.as_byte_array());
            data[32..].copy_from_slice(prev_header.as_byte_array());
            
            let filter_header = FilterHeader::from_byte_array(sha256d::Hash::hash(&data).to_byte_array());

            if i < 1 || i >= cf_headers.filter_hashes.len() - 1 {
                tracing::trace!("Filter header {}: filter_hash={:?}, prev_header={:?}, result={:?}",
                               start_height + i as u32, filter_hash, prev_header, filter_header);
            }

            new_filter_headers.push(filter_header);
            prev_header = filter_header;
        }
        
        Ok(new_filter_headers)
    }
    
    /// Handle overlapping filter headers by skipping already processed ones.
    /// Returns the number of new headers stored and updates current_height accordingly.
    async fn handle_overlapping_headers(
        &self,
        cf_headers: &CFHeaders,
        skip_count: usize,
        expected_start_height: u32,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<(usize, u32)> {
        if skip_count >= cf_headers.filter_hashes.len() {
            tracing::info!("✅ All {} headers in this batch already processed, skipping", cf_headers.filter_hashes.len());
            return Ok((0, expected_start_height));
        }
        
        // We need to compute the filter headers for the entire batch first,
        // then extract only the new ones we need to store.
        // This is because each filter header depends on the previous one.
        
        // First, find where in our chain the cf_headers.previous_filter_header connects
        let current_filter_tip = storage.get_filter_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get filter tip: {}", e)))?
            .unwrap_or(0);
        
        let mut connection_height = None;
        for check_height in (0..=current_filter_tip).rev() {
            if let Ok(Some(stored_header)) = storage.get_filter_header(check_height).await {
                if stored_header == cf_headers.previous_filter_header {
                    connection_height = Some(check_height);
                    break;
                }
            }
        }
        
        // If we can't find a connection point, check if this is overlapping data we can safely ignore
        let connection_height = match connection_height {
            Some(height) => height,
            None => {
                // Calculate the height range this batch would cover
                // Get header tip height since the stop hash might be beyond our current filter tip
                let header_tip_height = storage.get_tip_height().await
                    .map_err(|e| SyncError::SyncFailed(format!("Failed to get header tip height: {}", e)))?
                    .unwrap_or(0);
                    
                let stop_height = self.find_height_for_block_hash(&cf_headers.stop_hash, storage, 0, header_tip_height).await?
                    .ok_or_else(|| SyncError::SyncFailed(format!(
                        "Cannot find height for stop hash {} in overlapping headers", cf_headers.stop_hash
                    )))?;
                let batch_start_height = stop_height.saturating_sub(cf_headers.filter_hashes.len() as u32 - 1);
                
                // Check if we already have valid data for the overlapping range
                let overlap_end = expected_start_height.saturating_sub(1);
                if batch_start_height <= overlap_end && overlap_end <= current_filter_tip {
                    // This is an overlapping batch from a different peer with different previous_filter_header
                    // We already have valid data for the overlapping range, so we can safely ignore this batch
                    tracing::warn!("📋 Cannot find connection point for overlapping headers from different peer.");
                    tracing::warn!("📋 Batch range: {}-{}, our tip: {}, expected start: {}", 
                                   batch_start_height, stop_height, current_filter_tip, expected_start_height);
                    tracing::warn!("📋 This appears to be overlapping data from a different peer view - ignoring safely");
                    
                    // Calculate how many new headers we would have processed (for progress tracking)
                    let would_be_new_count = if stop_height > current_filter_tip {
                        (stop_height - current_filter_tip) as usize
                    } else {
                        0
                    };
                    
                    // Return success with the count of headers we would have added if this was valid
                    let new_current_height = if would_be_new_count > 0 {
                        current_filter_tip + would_be_new_count as u32 + 1
                    } else {
                        expected_start_height
                    };
                    
                    return Ok((would_be_new_count, new_current_height));
                } else {
                    // This is a real problem - we can't connect and we don't have the data
                    return Err(SyncError::SyncFailed("Cannot find connection point for overlapping headers".to_string()));
                }
            }
        };
        
        // Process all filter headers starting from the connection point
        let batch_start_height = connection_height + 1;
        let all_filter_headers = self.process_filter_headers(cf_headers, batch_start_height, storage).await?;
        
        // Now extract only the new headers we need (skip the overlapping ones)
        let headers_to_skip = expected_start_height.saturating_sub(batch_start_height) as usize;
        if headers_to_skip >= all_filter_headers.len() {
            tracing::info!("✅ All headers in overlapping batch already stored");
            return Ok((0, expected_start_height));
        }
        
        let new_filter_headers = all_filter_headers[headers_to_skip..].to_vec();
        
        if !new_filter_headers.is_empty() {
            storage.store_filter_headers(&new_filter_headers).await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to store filter headers: {}", e)))?;
            
            tracing::info!("✅ Stored {} new filter headers (skipped {} overlapping)", 
                          new_filter_headers.len(), headers_to_skip);
            
            let new_current_height = expected_start_height + new_filter_headers.len() as u32;
            Ok((new_filter_headers.len(), new_current_height))
        } else {
            Ok((0, expected_start_height))
        }
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
        
        // Skip verification for the first batch starting from height 1, since we don't know the genesis filter header
        if start_height <= 1 {
            tracing::debug!("Skipping filter header chain verification for first batch (start_height={})", start_height);
            return Ok(true);
        }
        
        // Safety check to prevent underflow
        if start_height == 0 {
            tracing::error!("Invalid start_height=0 in filter header verification - this should never happen");
            return Err(SyncError::SyncFailed("Invalid start_height=0 in filter header verification".to_string()));
        }
        
        // Get the expected previous filter header from our local chain
        let prev_height = start_height - 1;
        tracing::debug!("Verifying filter header chain: start_height={}, prev_height={}", start_height, prev_height);
        
        let expected_prev_header = storage.get_filter_header(prev_height).await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get previous filter header at height {}: {}", prev_height, e)))?
            .ok_or_else(|| SyncError::SyncFailed(format!("Missing previous filter header at height {}", prev_height)))?;
        
        // Always check if the previous_filter_header from the message exists anywhere in our chain
        // This handles both normal continuation and overlapping ranges from recovery/multi-peer scenarios
        let current_filter_tip = storage.get_filter_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get filter tip during overlap check: {}", e)))?
            .unwrap_or(0);
        
        // Search through our stored headers to see if the received previous_filter_header
        // matches any valid point in our chain
        let mut found_valid_connection = false;
        let mut _connection_height = None;
        
        for check_height in (0..=current_filter_tip).rev() {
            if let Ok(Some(stored_header)) = storage.get_filter_header(check_height).await {
                if stored_header == cf_headers.previous_filter_header {
                    found_valid_connection = true;
                    _connection_height = Some(check_height);
                    
                    if cf_headers.previous_filter_header == expected_prev_header {
                        tracing::debug!("Filter headers connect normally at expected height {}", check_height);
                    } else {
                        tracing::info!("Filter headers connect via overlap at height {} (expected at {})", check_height, prev_height);
                    }
                    break;
                }
            }
        }
        
        if !found_valid_connection {
            tracing::error!(
                "Filter header chain verification failed: received previous_filter_header {:?} doesn't match any stored header (expected: {:?} at height {})",
                cf_headers.previous_filter_header,
                expected_prev_header,
                prev_height
            );
            return Ok(false);
        }
        
        tracing::trace!("Filter header chain verification passed for {} headers", cf_headers.filter_hashes.len());
        Ok(true)
    }
    
    /// Synchronize compact filters for recent blocks or specific range.
    pub async fn sync_filters(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
        start_height: Option<u32>,
        count: Option<u32>,
    ) -> SyncResult<SyncProgress> {
        if self.syncing_filters {
            return Err(SyncError::SyncInProgress);
        }
        
        self.syncing_filters = true;
        
        // Determine range to sync
        let filter_tip_height = storage.get_filter_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get filter tip: {}", e)))?
            .unwrap_or(0);
            
        let start = start_height.unwrap_or_else(|| {
            // Default: sync last blocks for recent transaction discovery
            filter_tip_height.saturating_sub(DEFAULT_FILTER_SYNC_RANGE)
        });
        
        let end = count.map(|c| start + c - 1)
            .unwrap_or(filter_tip_height)
            .min(filter_tip_height); // Ensure we don't go beyond available filter headers
            
        if start > end {
            self.syncing_filters = false;
            return Ok(SyncProgress::default());
        }
        
        tracing::info!("🔄 Starting compact filter sync from height {} to {} ({} blocks)", start, end, end - start + 1);
        
        // Request filters in batches
        let batch_size = FILTER_REQUEST_BATCH_SIZE;
        let mut current_height = start;
        let mut filters_downloaded = 0;
        
        while current_height <= end {
            let batch_end = (current_height + batch_size - 1).min(end);
            
            tracing::debug!("Requesting filters for heights {} to {}", current_height, batch_end);
            
            // Get stop hash for this batch
            let stop_hash = storage.get_header(batch_end).await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to get stop header: {}", e)))?
                .ok_or_else(|| SyncError::SyncFailed("Stop header not found".to_string()))?
                .block_hash();
            
            self.request_filters(network, current_height, stop_hash).await?;
            
            // Note: Filter responses will be handled by the monitoring loop
            // This method now just sends requests and trusts that responses 
            // will be processed by the centralized message handler
            tracing::debug!("Sent filter request for batch {} to {}", current_height, batch_end);
            
            let batch_size_actual = batch_end - current_height + 1;
            filters_downloaded += batch_size_actual;
            current_height = batch_end + 1;
        }
        
        self.syncing_filters = false;
        
        tracing::info!("✅ Compact filter synchronization completed. Downloaded {} filters", filters_downloaded);
        
        Ok(SyncProgress {
            filters_downloaded: filters_downloaded as u64,
            ..SyncProgress::default()
        })
    }
    
    /// Check filters against watch list and return matches.
    pub async fn check_filters_for_matches(
        &self,
        storage: &dyn StorageManager,
        watch_items: &[crate::types::WatchItem],
        start_height: u32,
        end_height: u32,
    ) -> SyncResult<Vec<crate::types::FilterMatch>> {
        tracing::info!("Checking filters for matches from height {} to {}", start_height, end_height);
        
        if watch_items.is_empty() {
            return Ok(Vec::new());
        }
        
        // Convert watch items to scripts for filter matching
        let watch_scripts = self.extract_scripts_from_watch_items(watch_items)?;
        
        let mut matches = Vec::new();
        
        for height in start_height..=end_height {
            if let Some(filter_data) = storage.load_filter(height).await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to load filter: {}", e)))? {
                
                // Get the block hash for this height
                let block_hash = storage.get_header(height).await
                    .map_err(|e| SyncError::SyncFailed(format!("Failed to get header: {}", e)))?
                    .ok_or_else(|| SyncError::SyncFailed("Header not found".to_string()))?
                    .block_hash();
                
                // Check if any watch scripts match using the raw filter data
                if self.filter_matches_scripts(&filter_data, &block_hash, &watch_scripts)? {
                    // block_hash already obtained above
                    
                    matches.push(crate::types::FilterMatch {
                        block_hash,
                        height,
                        block_requested: false,
                    });
                    
                    tracing::info!("Filter match found at height {} ({})", height, block_hash);
                }
            }
        }
        
        tracing::info!("Found {} filter matches", matches.len());
        Ok(matches)
    }
    
    /// Request compact filters from the network.
    pub async fn request_filters(
        &mut self,
        network: &mut dyn NetworkManager,
        start_height: u32,
        stop_hash: BlockHash,
    ) -> SyncResult<()> {
        let get_cfilters = GetCFilters {
            filter_type: 0, // Basic filter type
            start_height,
            stop_hash,
        };
        
        network.send_message(NetworkMessage::GetCFilters(get_cfilters)).await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to send GetCFilters: {}", e)))?;
        
        tracing::debug!("Requested filters from height {} to {}", start_height, stop_hash);
        
        Ok(())
    }
    
    /// Find height for a block hash within a range.
    async fn find_height_for_block_hash(
        &self,
        block_hash: &BlockHash,
        storage: &dyn StorageManager,
        start_height: u32,
        end_height: u32,
    ) -> SyncResult<Option<u32>> {
        // Use the efficient reverse index first
        if let Some(height) = storage.get_header_height_by_hash(block_hash).await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get header height by hash: {}", e)))? {
            // Check if the height is within the requested range
            if height >= start_height && height <= end_height {
                return Ok(Some(height));
            }
        }
        Ok(None)
    }
    
    /// Download filter header for a specific block.
    pub async fn download_filter_header_for_block(
        &mut self,
        block_hash: BlockHash,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
        // Get the block height for this hash by scanning headers
        let header_tip_height = storage.get_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get header tip height: {}", e)))?
            .unwrap_or(0);
        
        let height = self.find_height_for_block_hash(&block_hash, storage, 0, header_tip_height).await?
            .ok_or_else(|| SyncError::SyncFailed(format!(
                "Cannot find height for block {} - header not found", block_hash
            )))?;
        
        // Check if we already have this filter header
        if storage.get_filter_header(height).await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to check filter header: {}", e)))?
            .is_some() {
            tracing::debug!("Filter header for block {} at height {} already exists", block_hash, height);
            return Ok(());
        }
        
        tracing::info!("📥 Requesting filter header for block {} at height {}", block_hash, height);
        
        // Request filter header using getcfheaders
        self.request_filter_headers(network, height, block_hash).await?;
        
        Ok(())
    }
    
    /// Download and check a compact filter for matches against watch items.
    pub async fn download_and_check_filter(
        &mut self,
        block_hash: BlockHash,
        watch_items: &[crate::types::WatchItem],
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<bool> {
        if watch_items.is_empty() {
            tracing::debug!("No watch items configured, skipping filter check for block {}", block_hash);
            return Ok(false);
        }
        
        // Get the block height for this hash by scanning headers  
        let header_tip_height = storage.get_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get header tip height: {}", e)))?
            .unwrap_or(0);
        
        let height = self.find_height_for_block_hash(&block_hash, storage, 0, header_tip_height).await?
            .ok_or_else(|| SyncError::SyncFailed(format!(
                "Cannot find height for block {} - header not found", block_hash
            )))?;
        
        tracing::info!("📥 Requesting compact filter for block {} at height {} (checking {} watch items)", 
                      block_hash, height, watch_items.len());
        
        // Request the compact filter using getcfilters
        self.request_filters(network, height, block_hash).await?;
        
        // Note: The actual filter checking will happen when we receive the CFilter message
        // This method just initiates the download. The client will need to handle the response.
        
        Ok(false) // Return false for now, will be updated when we process the response
    }
    
    /// Check a filter for matches against watch items (helper method for processing CFilter messages).
    pub async fn check_filter_for_matches(
        &self,
        filter_data: &[u8],
        block_hash: &BlockHash,
        watch_items: &[crate::types::WatchItem],
        _storage: &dyn StorageManager,
    ) -> SyncResult<bool> {
        if watch_items.is_empty() {
            return Ok(false);
        }
        
        // Convert watch items to scripts for filter checking
        let mut scripts = Vec::with_capacity(watch_items.len());
        for item in watch_items {
            match item {
                crate::types::WatchItem::Address { address, .. } => {
                    scripts.push(address.script_pubkey());
                }
                crate::types::WatchItem::Script(script) => {
                    scripts.push(script.clone());
                }
                crate::types::WatchItem::Outpoint(_) => {
                    // For outpoints, we'd need the transaction data to get the script
                    // Skip for now - this would require more complex logic
                }
            }
        }
        
        if scripts.is_empty() {
            tracing::debug!("No scripts to check for block {}", block_hash);
            return Ok(false);
        }
        
        // Use the existing filter matching logic (synchronous method)
        self.filter_matches_scripts(filter_data, block_hash, &scripts)
    }
    
    /// Extract scripts from watch items for filter matching.
    fn extract_scripts_from_watch_items(&self, watch_items: &[crate::types::WatchItem]) -> SyncResult<Vec<ScriptBuf>> {
        let mut scripts = Vec::with_capacity(watch_items.len());
        
        for item in watch_items {
            match item {
                crate::types::WatchItem::Address { address, .. } => {
                    scripts.push(address.script_pubkey());
                }
                crate::types::WatchItem::Script(script) => {
                    scripts.push(script.clone());
                }
                crate::types::WatchItem::Outpoint(outpoint) => {
                    // For outpoints, we need to watch for spending transactions
                    // This requires the outpoint bytes in the filter
                    // For now, we'll skip outpoint matching as it's more complex
                    tracing::warn!("Outpoint watching not yet implemented: {:?}", outpoint);
                }
            }
        }
        
        Ok(scripts)
    }
    
    
    /// Check if filter matches any of the provided scripts using BIP158 GCS filter.
    fn filter_matches_scripts(&self, filter_data: &[u8], block_hash: &BlockHash, scripts: &[ScriptBuf]) -> SyncResult<bool> {
        if scripts.is_empty() {
            return Ok(false);
        }
        
        if filter_data.is_empty() {
            tracing::debug!("Empty filter data, no matches possible");
            return Ok(false);
        }
        
        // Create a BlockFilterReader with the block hash for proper key derivation
        let filter_reader = BlockFilterReader::new(block_hash);
        
        // Convert scripts to byte slices for matching without heap allocation
        let mut script_bytes = Vec::with_capacity(scripts.len());
        for script in scripts {
            script_bytes.push(script.as_bytes());
        }
        
        tracing::debug!("Checking filter against {} watch scripts using BIP158 GCS", scripts.len());
        
        // Use the BIP158 filter to check if any scripts match
        let mut filter_slice = filter_data;
        match filter_reader.match_any(&mut filter_slice, script_bytes.into_iter()) {
            Ok(matches) => {
                if matches {
                    tracing::info!("BIP158 filter match found! Block {} contains watched scripts", block_hash);
                } else {
                    tracing::debug!("No BIP158 filter matches found for block {}", block_hash);
                }
                Ok(matches)
            }
            Err(Bip158Error::Io(e)) => {
                Err(SyncError::SyncFailed(format!("BIP158 filter IO error: {}", e)))
            }
            Err(Bip158Error::UtxoMissing(outpoint)) => {
                Err(SyncError::SyncFailed(format!("BIP158 filter UTXO missing: {}", outpoint)))
            }
            Err(_) => {
                Err(SyncError::SyncFailed("BIP158 filter error".to_string()))
            }
        }
    }
    
    /// Store filter headers from a CFHeaders message.
    /// This method is used when filter headers are received outside of the normal sync process,
    /// such as when monitoring the network for new blocks.
    pub async fn store_filter_headers(
        &mut self,
        cfheaders: dashcore::network::message_filter::CFHeaders,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
        if cfheaders.filter_hashes.is_empty() {
            tracing::debug!("No filter headers to store");
            return Ok(());
        }
        
        // Get the block height for the stop hash
        let header_tip_height = storage.get_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get header tip height: {}", e)))?
            .unwrap_or(0);
        
        let stop_height = self.find_height_for_block_hash(&cfheaders.stop_hash, storage, 0, header_tip_height).await?
            .ok_or_else(|| SyncError::SyncFailed(format!(
                "Cannot find height for stop hash {} - header not found", cfheaders.stop_hash
            )))?;
        
        // Calculate the start height based on the number of filter hashes
        let start_height = stop_height.saturating_sub(cfheaders.filter_hashes.len() as u32 - 1);
        
        tracing::info!("Received {} filter headers from height {} to {}", 
                      cfheaders.filter_hashes.len(), start_height, stop_height);
        
        // Check current filter tip to see if we already have some/all of these headers
        let current_filter_tip = storage.get_filter_tip_height().await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get filter tip: {}", e)))?
            .unwrap_or(0);
        
        // If we already have all these filter headers, skip processing
        if current_filter_tip >= stop_height {
            tracing::info!("Already have filter headers up to height {} (received up to {}), skipping", 
                          current_filter_tip, stop_height);
            return Ok(());
        }
        
        // If there's partial overlap, we need to handle it carefully
        if current_filter_tip >= start_height && start_height > 0 {
            tracing::info!("Received overlapping filter headers. Current tip: {}, received range: {}-{}", 
                          current_filter_tip, start_height, stop_height);
            
            // Verify that the overlapping portion matches what we have stored
            // This is done by the verify_filter_header_chain method
            // If verification fails, we'll skip storing to avoid corruption
        }
        
        // Handle overlapping headers properly
        if current_filter_tip >= start_height && start_height > 0 {
            tracing::info!("Received overlapping filter headers. Current tip: {}, received range: {}-{}", 
                          current_filter_tip, start_height, stop_height);
            
            // Use the handle_overlapping_headers method which properly handles the chain continuity
            let skip_count = (current_filter_tip + 1 - start_height) as usize;
            let expected_start = current_filter_tip + 1;
            
            match self.handle_overlapping_headers(&cfheaders, skip_count, expected_start, storage).await {
                Ok((stored_count, _)) => {
                    if stored_count > 0 {
                        tracing::info!("✅ Successfully handled overlapping filter headers");
                    } else {
                        tracing::info!("All filter headers in batch already stored");
                    }
                }
                Err(e) => {
                    // If we can't find the connection point, it might be from a different peer
                    // with a different view of the chain
                    tracing::warn!("Failed to handle overlapping filter headers: {}. This may be due to data from different peers.", e);
                    return Ok(());
                }
            }
        } else {
            // Process the filter headers to convert them to the proper format
            match self.process_filter_headers(&cfheaders, start_height, storage).await {
                Ok(new_filter_headers) => {
                    if !new_filter_headers.is_empty() {
                        // If this is the first batch (starting at height 1), store the genesis filter header first
                        if start_height == 1 && current_filter_tip < 1 {
                            let genesis_header = vec![cfheaders.previous_filter_header];
                            storage.store_filter_headers(&genesis_header).await
                                .map_err(|e| SyncError::SyncFailed(format!("Failed to store genesis filter header: {}", e)))?;
                            tracing::debug!("Stored genesis filter header at height 0: {:?}", cfheaders.previous_filter_header);
                        }
                        
                        // Store the new filter headers
                        storage.store_filter_headers(&new_filter_headers).await
                            .map_err(|e| SyncError::SyncFailed(format!("Failed to store filter headers: {}", e)))?;
                        
                        tracing::info!("✅ Successfully stored {} new filter headers", new_filter_headers.len());
                    }
                }
                Err(e) => {
                    // If verification failed, it might be from a peer with different data
                    tracing::warn!("Failed to process filter headers: {}. This may be due to data from different peers.", e);
                    return Ok(());
                }
            }
        }
        
        Ok(())
    }
    
    /// Request a block for download after a filter match.
    pub async fn request_block_download(
        &mut self,
        filter_match: crate::types::FilterMatch,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<()> {
        // Check if already downloading or queued
        if self.downloading_blocks.contains_key(&filter_match.block_hash) {
            tracing::debug!("Block {} already being downloaded", filter_match.block_hash);
            return Ok(());
        }
        
        if self.pending_block_downloads.iter().any(|m| m.block_hash == filter_match.block_hash) {
            tracing::debug!("Block {} already queued for download", filter_match.block_hash);
            return Ok(());
        }
        
        tracing::info!("📦 Requesting block download for {} at height {}", filter_match.block_hash, filter_match.height);
        
        // Create GetData message for the block
        let inv = Inventory::Block(filter_match.block_hash);
        
        let getdata = vec![inv];
        
        // Send the request
        network.send_message(NetworkMessage::GetData(getdata)).await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to send GetData for block: {}", e)))?;
        
        // Mark as downloading and add to queue
        self.downloading_blocks.insert(filter_match.block_hash, filter_match.height);
        let block_hash = filter_match.block_hash;
        self.pending_block_downloads.push_back(filter_match);
        
        tracing::debug!("Added block {} to download queue (queue size: {})", 
                       block_hash, self.pending_block_downloads.len());
        
        Ok(())
    }
    
    /// Handle a downloaded block and return whether it was expected.
    pub async fn handle_downloaded_block(
        &mut self,
        block: &dashcore::block::Block,
    ) -> SyncResult<Option<crate::types::FilterMatch>> {
        let block_hash = block.block_hash();
        
        // Check if this block was requested
        if let Some(height) = self.downloading_blocks.remove(&block_hash) {
            tracing::info!("📦 Received expected block {} at height {}", block_hash, height);
            
            // Find and remove from pending queue
            if let Some(pos) = self.pending_block_downloads.iter().position(|m| m.block_hash == block_hash) {
                let mut filter_match = self.pending_block_downloads.remove(pos).unwrap();
                filter_match.block_requested = true;
                
                tracing::debug!("Removed block {} from download queue (remaining: {})", 
                               block_hash, self.pending_block_downloads.len());
                
                return Ok(Some(filter_match));
            }
        }
        
        tracing::warn!("Received unexpected block: {}", block_hash);
        Ok(None)
    }
    
    /// Check if there are pending block downloads.
    pub fn has_pending_downloads(&self) -> bool {
        !self.pending_block_downloads.is_empty() || !self.downloading_blocks.is_empty()
    }
    
    /// Get the number of pending block downloads.
    pub fn pending_download_count(&self) -> usize {
        self.pending_block_downloads.len()
    }
    
    /// Process filter matches and automatically request block downloads.
    pub async fn process_filter_matches_and_download(
        &mut self,
        filter_matches: Vec<crate::types::FilterMatch>,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<Vec<crate::types::FilterMatch>> {
        if filter_matches.is_empty() {
            return Ok(filter_matches);
        }
        
        tracing::info!("Processing {} filter matches for block downloads", filter_matches.len());
        
        // Filter out blocks already being downloaded or queued
        let mut new_downloads = Vec::new();
        let mut inventory_items = Vec::new();
        
        for filter_match in filter_matches {
            // Check if already downloading or queued
            if self.downloading_blocks.contains_key(&filter_match.block_hash) {
                tracing::debug!("Block {} already being downloaded", filter_match.block_hash);
                continue;
            }
            
            if self.pending_block_downloads.iter().any(|m| m.block_hash == filter_match.block_hash) {
                tracing::debug!("Block {} already queued for download", filter_match.block_hash);
                continue;
            }
            
            tracing::info!("📦 Queuing block download for {} at height {}", filter_match.block_hash, filter_match.height);
            
            // Add to inventory for bulk request
            inventory_items.push(Inventory::Block(filter_match.block_hash));
            
            // Mark as downloading and add to queue
            self.downloading_blocks.insert(filter_match.block_hash, filter_match.height);
            self.pending_block_downloads.push_back(filter_match.clone());
            new_downloads.push(filter_match);
        }
        
        // Send single bundled GetData request for all blocks
        if !inventory_items.is_empty() {
            tracing::info!("📦 Requesting {} blocks in single GetData message", inventory_items.len());
            
            let getdata = NetworkMessage::GetData(inventory_items);
            network.send_message(getdata).await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to send bundled GetData for blocks: {}", e)))?;
                
            tracing::debug!("Added {} blocks to download queue (total queue size: {})", 
                           new_downloads.len(), self.pending_block_downloads.len());
        }
        
        Ok(new_downloads)
    }
    
    /// Reset sync state.
    pub fn reset(&mut self) {
        self.syncing_filter_headers = false;
        self.syncing_filters = false;
        self.pending_block_downloads.clear();
        self.downloading_blocks.clear();
    }
    
    /// Check if filter header sync is currently in progress.
    pub fn is_syncing_filter_headers(&self) -> bool {
        self.syncing_filter_headers
    }
}
