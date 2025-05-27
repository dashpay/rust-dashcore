//! Filter synchronization functionality.

use dashcore::{
    hash_types::FilterHeader,
    network::message::NetworkMessage,
    network::message_filter::{CFHeaders, GetCFHeaders, GetCFilters},
    ScriptBuf, BlockHash,
    bip158::{BlockFilterReader, Error as Bip158Error},
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
            
        tracing::debug!("Current filter tip height: {:?}", current_filter_height);
        
        // Since filter header sync completed successfully, we can remove the clearing logic
        // let current_filter_height = 0;
        
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
        
        // Sync filter headers in batches
        let mut current_height = current_filter_height + 1;
        let mut timeout_count = 0;
        let max_timeouts = 10;
        
        // Initial request for first batch - limit to 1999 to stay under 2000 limit
        let batch_size = 1999; // Dash Core has a hard limit of 2000, so use 1999 to be safe
        let batch_end_height = (current_height + batch_size - 1).min(header_tip_height);
        
        tracing::debug!("Requesting filter headers batch: start={}, end={}, count={}", 
                       current_height, batch_end_height, batch_end_height - current_height + 1);
        
        // Get the hash at batch_end_height for the stop_hash
        let batch_stop_hash = if batch_end_height < header_tip_height {
            storage.get_header(batch_end_height).await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to get batch stop header: {}", e)))?
                .ok_or_else(|| SyncError::SyncFailed("Batch stop header not found".to_string()))?
                .block_hash()
        } else {
            stop_hash
        };
        
        self.request_filter_headers(network, current_height, batch_stop_hash).await?;
        
        loop {
            match network.receive_message().await {
                Ok(Some(NetworkMessage::CFHeaders(cf_headers))) => {
                    timeout_count = 0;
                    
                    if cf_headers.filter_hashes.is_empty() {
                        break;
                    }
                    
                    // Verify and process filter headers  
                    let new_filter_headers = self.process_filter_headers(&cf_headers, current_height, storage).await?;
                    
                    if !new_filter_headers.is_empty() {
                        // For the first batch, we need to store the genesis filter header first
                        if current_height == 1 {
                            // Store the genesis filter header at height 0
                            let genesis_header = vec![cf_headers.previous_filter_header];
                            storage.store_filter_headers(&genesis_header).await
                                .map_err(|e| SyncError::SyncFailed(format!("Failed to store genesis filter header: {}", e)))?;
                            tracing::debug!("Stored genesis filter header at height 0: {:?}", cf_headers.previous_filter_header);
                        }
                        
                        // Store the new filter headers
                        storage.store_filter_headers(&new_filter_headers).await
                            .map_err(|e| SyncError::SyncFailed(format!("Failed to store filter headers: {}", e)))?;
                        
                        tracing::info!("Stored {} filter headers starting from height {}", new_filter_headers.len(), current_height);
                        
                        // Update current height to the next unprocessed height
                        current_height += new_filter_headers.len() as u32;
                        
                        tracing::debug!("Updated current_height to {}", current_height);
                    }
                    
                    // Check if we need to request more
                    if current_height > header_tip_height {
                        break;
                    }
                    
                    // If we got a full batch, request the next one  
                    if cf_headers.filter_hashes.len() >= 1999 { // Check for near-full batch
                        let next_batch_end_height = (current_height + batch_size - 1).min(header_tip_height);
                        
                        tracing::debug!("Requesting next filter headers batch: start={}, end={}, count={}", 
                                       current_height, next_batch_end_height, next_batch_end_height - current_height + 1);
                        
                        let next_batch_stop_hash = if next_batch_end_height < header_tip_height {
                            storage.get_header(next_batch_end_height).await
                                .map_err(|e| SyncError::SyncFailed(format!("Failed to get next batch stop header: {}", e)))?
                                .ok_or_else(|| SyncError::SyncFailed("Next batch stop header not found".to_string()))?
                                .block_hash()
                        } else {
                            stop_hash
                        };
                        
                        self.request_filter_headers(network, current_height, next_batch_stop_hash).await?;
                    } else {
                        // Partial batch means we're done
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
        
        tracing::debug!("Processing {} filter headers starting from height {}", cf_headers.filter_hashes.len(), start_height);
        
        // Verify filter header chain
        if !self.verify_filter_header_chain(cf_headers, start_height, storage).await? {
            return Err(SyncError::SyncFailed("Filter header chain verification failed".to_string()));
        }
        
        // Convert filter hashes to filter headers
        let mut new_filter_headers = Vec::new();
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
            let mut data = filter_hash.as_byte_array().to_vec();
            data.extend_from_slice(prev_header.as_byte_array());
            
            let filter_header = FilterHeader::from_byte_array(sha256d::Hash::hash(&data).to_byte_array());
            
            if i < 3 || i >= cf_headers.filter_hashes.len() - 3 {
                tracing::debug!("Filter header {}: filter_hash={:?}, prev_header={:?}, result={:?}", 
                               start_height + i as u32, filter_hash, prev_header, filter_header);
            }
            
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
        
        // Skip verification for the first batch starting from height 1, since we don't know the genesis filter header
        if start_height <= 1 {
            tracing::debug!("Skipping filter header chain verification for first batch (start_height={})", start_height);
            return Ok(true);
        }
        
        // Safety check to prevent underflow
        if start_height == 0 {
            tracing::error!("Invalid start_height=0 in filter header verification");
            return Err(SyncError::SyncFailed("Invalid start_height=0".to_string()));
        }
        
        // Get the expected previous filter header from our local chain
        let prev_height = start_height - 1;
        tracing::debug!("Verifying filter header chain: start_height={}, prev_height={}", start_height, prev_height);
        
        let expected_prev_header = storage.get_filter_header(prev_height).await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get previous filter header at height {}: {}", prev_height, e)))?
            .ok_or_else(|| SyncError::SyncFailed(format!("Missing previous filter header at height {}", prev_height)))?;
        
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
            // Default: sync last 100 blocks for recent transaction discovery
            filter_tip_height.saturating_sub(100)
        });
        
        let end = count.map(|c| start + c - 1)
            .unwrap_or(filter_tip_height)
            .min(filter_tip_height); // Ensure we don't go beyond available filter headers
            
        if start > end {
            self.syncing_filters = false;
            return Ok(SyncProgress::default());
        }
        
        tracing::info!("Starting compact filter sync from height {} to {}", start, end);
        
        // Request filters in batches
        let batch_size = 100;
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
            
            // Collect filter responses for this batch
            let mut timeout_count = 0;
            let max_timeouts = 10;
            let mut received_filters = 0;
            let expected_filters = batch_end - current_height + 1;
            
            while received_filters < expected_filters {
                match network.receive_message().await {
                    Ok(Some(NetworkMessage::CFilter(cfilter))) => {
                        timeout_count = 0;
                        
                        // Find the height for this filter by matching block hash
                        if let Some(height) = self.find_height_for_block_hash(&cfilter.block_hash, storage, current_height, batch_end).await? {
                            // Store the filter
                            storage.store_filter(height, &cfilter.filter).await
                                .map_err(|e| SyncError::SyncFailed(format!("Failed to store filter: {}", e)))?;
                            
                            received_filters += 1;
                            filters_downloaded += 1;
                            
                            tracing::debug!("Stored filter for height {} (hash: {})", height, cfilter.block_hash);
                        } else {
                            tracing::warn!("Received filter for unknown block hash: {}", cfilter.block_hash);
                        }
                    }
                    Ok(Some(_)) => {
                        // Ignore other messages
                        continue;
                    }
                    Ok(None) => {
                        timeout_count += 1;
                        if timeout_count >= max_timeouts {
                            self.syncing_filters = false;
                            return Err(SyncError::SyncTimeout);
                        }
                        
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                    Err(e) => {
                        self.syncing_filters = false;
                        return Err(SyncError::SyncFailed(format!("Network error during filter sync: {}", e)));
                    }
                }
            }
            
            current_height = batch_end + 1;
        }
        
        self.syncing_filters = false;
        
        tracing::info!("Compact filter synchronization completed. Downloaded {} filters", filters_downloaded);
        
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
    async fn request_filters(
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
        let height = self.find_height_for_block_hash(&block_hash, storage, 0, 10000).await?
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
        let height = self.find_height_for_block_hash(&block_hash, storage, 0, 10000).await?
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
        storage: &dyn StorageManager,
    ) -> SyncResult<bool> {
        if watch_items.is_empty() {
            return Ok(false);
        }
        
        // Convert watch items to scripts for filter checking
        let scripts: Vec<dashcore::ScriptBuf> = watch_items.iter()
            .filter_map(|item| {
                match item {
                    crate::types::WatchItem::Address(addr) => {
                        Some(addr.script_pubkey())
                    }
                    crate::types::WatchItem::Script(script) => {
                        Some(script.clone())
                    }
                    crate::types::WatchItem::Outpoint(_) => {
                        // For outpoints, we'd need the transaction data to get the script
                        // Skip for now - this would require more complex logic
                        None
                    }
                }
            })
            .collect();
        
        if scripts.is_empty() {
            tracing::debug!("No scripts to check for block {}", block_hash);
            return Ok(false);
        }
        
        // Use the existing filter matching logic (synchronous method)
        self.filter_matches_scripts(filter_data, block_hash, &scripts)
    }
    
    /// Extract scripts from watch items for filter matching.
    fn extract_scripts_from_watch_items(&self, watch_items: &[crate::types::WatchItem]) -> SyncResult<Vec<ScriptBuf>> {
        let mut scripts = Vec::new();
        
        for item in watch_items {
            match item {
                crate::types::WatchItem::Address(addr) => {
                    scripts.push(addr.script_pubkey());
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
        
        // Convert scripts to byte slices for matching
        let script_bytes: Vec<&[u8]> = scripts.iter().map(|s| s.as_bytes()).collect();
        
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
        let stop_height = self.find_height_for_block_hash(&cfheaders.stop_hash, storage, 0, 10000).await?
            .ok_or_else(|| SyncError::SyncFailed(format!(
                "Cannot find height for stop hash {} - header not found", cfheaders.stop_hash
            )))?;
        
        // Calculate the start height based on the number of filter hashes
        let start_height = stop_height.saturating_sub(cfheaders.filter_hashes.len() as u32 - 1);
        
        tracing::info!("Storing {} filter headers from height {} to {}", 
                      cfheaders.filter_hashes.len(), start_height, stop_height);
        
        // Process the filter headers to convert them to the proper format
        let new_filter_headers = self.process_filter_headers(&cfheaders, start_height, storage).await?;
        
        if !new_filter_headers.is_empty() {
            // If this is the first batch (starting at height 1), store the genesis filter header first
            if start_height == 1 {
                let genesis_header = vec![cfheaders.previous_filter_header];
                storage.store_filter_headers(&genesis_header).await
                    .map_err(|e| SyncError::SyncFailed(format!("Failed to store genesis filter header: {}", e)))?;
                tracing::debug!("Stored genesis filter header at height 0: {:?}", cfheaders.previous_filter_header);
            }
            
            // Store the new filter headers
            storage.store_filter_headers(&new_filter_headers).await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to store filter headers: {}", e)))?;
            
            tracing::info!("✅ Successfully stored {} filter headers", new_filter_headers.len());
        }
        
        Ok(())
    }
    
    /// Reset sync state.
    pub fn reset(&mut self) {
        self.syncing_filter_headers = false;
        self.syncing_filters = false;
    }
}
