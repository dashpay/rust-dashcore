//! CFilter download and verification logic.
//!
//! This module handles downloading individual compact block filters and verifying
//! them against their corresponding filter headers.
//!
//! ## Key Features
//!
//! - Filter request queue management with flow control
//! - Parallel filter downloads with concurrency limits
//! - Filter verification against CFHeaders
//! - Individual filter header downloads for blocks
//! - Progress tracking and gap detection

use dashcore::{
    bip158::BlockFilter, network::message::NetworkMessage, network::message_filter::GetCFilters,
    BlockHash,
};

use super::manager::TrustedCheckpointFilterHeader;
use super::types::*;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::types::SyncProgress;

impl<S: StorageManager + Send + Sync + 'static, N: NetworkManager + Send + Sync + 'static>
    super::manager::FilterSyncManager<S, N>
{
    pub async fn verify_cfilter_against_headers(
        &self,
        filter_data: &[u8],
        height: u32,
        storage: &S,
    ) -> SyncResult<bool> {
        // We expect filter headers to be synced before requesting filters.
        // If we're at height 0 (genesis), skip verification because there is no previous header.
        if height == 0 {
            tracing::debug!("Skipping cfilter verification at genesis height 0");
            return Ok(true);
        }

        let prev_height = height - 1;
        let prev_header = match storage.get_filter_header(prev_height).await.map_err(|e| {
            SyncError::Storage(format!(
                "Failed to load previous filter header at height {}: {}",
                prev_height, e
            ))
        })? {
            Some(header) => header,
            None if self.sync_base_height > 0 && height == self.sync_base_height => {
                match self.load_checkpoint_prev_filter_header(storage).await? {
                    Some(trusted) if trusted.height == prev_height => trusted.header,
                    Some(trusted) => {
                        tracing::error!(
                            "Checkpoint predecessor header height mismatch: expected {}, stored {}",
                            prev_height,
                            trusted.height
                        );
                        return Ok(false);
                    }
                    None => {
                        tracing::warn!(
                            "Missing trusted checkpoint predecessor filter header at height {}",
                            prev_height
                        );
                        return Ok(false);
                    }
                }
            }
            None => {
                tracing::warn!(
                    "Missing filter header at height {} required for verifying cfilter at {}",
                    prev_height,
                    height
                );
                return Ok(false);
            }
        };

        let expected_header = storage.get_filter_header(height).await.map_err(|e| {
            SyncError::Storage(format!("Failed to load expected filter header: {}", e))
        })?;

        let Some(expected_header) = expected_header else {
            tracing::warn!("Missing filter headers in storage for height {}", height);
            return Ok(false);
        };

        // Compute the header from the received filter bytes and compare
        let filter = BlockFilter::new(filter_data);
        let computed_header = filter.filter_header(&prev_header);

        let matches = computed_header == expected_header;
        if !matches {
            tracing::error!(
                "CFilter header mismatch at height {}: computed={:?}, expected={:?}",
                height,
                computed_header,
                expected_header
            );
        }

        Ok(matches)
    }
    /// Scan backward from `abs_height` down to `min_abs_height` (inclusive)
    /// to find the nearest available block header stored in `storage`.
    pub async fn sync_filters(
        &mut self,
        network: &mut N,
        storage: &mut S,
        start_height: Option<u32>,
        count: Option<u32>,
    ) -> SyncResult<SyncProgress> {
        if self.syncing_filters {
            return Err(SyncError::SyncInProgress);
        }

        self.syncing_filters = true;

        // Determine range to sync
        let filter_tip_height = storage
            .get_filter_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get filter tip: {}", e)))?
            .unwrap_or(0);

        let start = start_height.unwrap_or_else(|| {
            // Default: sync last blocks for recent transaction discovery
            filter_tip_height.saturating_sub(DEFAULT_FILTER_SYNC_RANGE)
        });

        let end = count.map(|c| start + c - 1).unwrap_or(filter_tip_height).min(filter_tip_height); // Ensure we don't go beyond available filter headers

        let base_height = self.sync_base_height;
        let clamped_start = start.max(base_height);

        if clamped_start > end {
            self.syncing_filters = false;
            return Ok(SyncProgress::default());
        }

        tracing::info!(
            "🔄 Starting compact filter sync from height {} to {} ({} blocks)",
            clamped_start,
            end,
            end - clamped_start + 1
        );

        // Request filters in batches
        let batch_size = FILTER_REQUEST_BATCH_SIZE;
        let mut current_height = clamped_start;
        let mut filters_downloaded = 0;

        while current_height <= end {
            let batch_end = (current_height + batch_size - 1).min(end);

            tracing::debug!("Requesting filters for heights {} to {}", current_height, batch_end);

            let stop_hash = storage
                .get_header(batch_end)
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get stop header: {}", e)))?
                .ok_or_else(|| SyncError::Storage("Stop header not found".to_string()))?
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

        tracing::info!(
            "✅ Compact filter synchronization completed. Downloaded {} filters",
            filters_downloaded
        );

        Ok(SyncProgress {
            filters_downloaded: filters_downloaded as u64,
            ..SyncProgress::default()
        })
    }

    pub async fn sync_filters_with_flow_control(
        &mut self,
        network: &mut N,
        storage: &mut S,
        start_height: Option<u32>,
        count: Option<u32>,
    ) -> SyncResult<SyncProgress> {
        if !self.flow_control_enabled {
            // Fall back to original method if flow control is disabled
            return self.sync_filters(network, storage, start_height, count).await;
        }

        if self.syncing_filters {
            return Err(SyncError::SyncInProgress);
        }

        self.syncing_filters = true;

        // Clear any stale state from previous attempts
        self.clear_filter_sync_state();

        // Build the queue of filter requests
        self.build_filter_request_queue(storage, start_height, count).await?;

        // Start processing the queue with flow control
        self.process_filter_request_queue(network, storage).await?;

        // Note: Actual completion will be tracked by the monitoring loop
        // This method just queues up requests and starts the flow control process
        tracing::info!(
            "✅ Filter sync with flow control initiated ({} requests queued, {} active)",
            self.pending_filter_requests.len(),
            self.active_filter_requests.len()
        );

        // Don't set syncing_filters to false here - it should remain true during download
        // It will be cleared when sync completes or fails

        Ok(SyncProgress {
            filters_downloaded: 0, // Will be updated by monitoring loop
            ..SyncProgress::default()
        })
    }

    /// Mark a filter as received and check for batch completion.
    pub async fn mark_filter_received(
        &mut self,
        block_hash: BlockHash,
        storage: &S,
    ) -> SyncResult<Vec<(u32, u32)>> {
        if !self.flow_control_enabled {
            return Ok(Vec::new());
        }

        // Record the received filter
        self.record_individual_filter_received(block_hash, storage).await?;

        // Check which active requests are now complete
        let mut completed_requests = Vec::new();

        for (start, end) in self.active_filter_requests.keys() {
            if self.is_request_complete(*start, *end).await? {
                completed_requests.push((*start, *end));
            }
        }

        // Remove completed requests from active tracking
        for range in &completed_requests {
            self.active_filter_requests.remove(range);
            tracing::debug!("✅ Filter request range {}-{} completed", range.0, range.1);
        }

        // Log current state periodically
        {
            let guard = self.received_filter_heights.lock().await;
            if guard.len() % 1000 == 0 {
                tracing::info!(
                    "Filter sync state: {} filters received, {} active requests, {} pending requests",
                    guard.len(),
                    self.active_filter_requests.len(),
                    self.pending_filter_requests.len()
                );
            }
        }

        // Always return at least one "completion" to trigger queue processing
        // This ensures we continuously utilize available slots instead of waiting for 100% completion
        if completed_requests.is_empty() && !self.pending_filter_requests.is_empty() {
            // If we have available slots and pending requests, trigger processing
            let available_slots =
                MAX_CONCURRENT_FILTER_REQUESTS.saturating_sub(self.active_filter_requests.len());
            if available_slots > 0 {
                completed_requests.push((0, 0)); // Dummy completion to trigger processing
            }
        }

        Ok(completed_requests)
    }

    async fn is_request_complete(&self, start: u32, end: u32) -> SyncResult<bool> {
        let received_heights = self.received_filter_heights.lock().await;
        for height in start..=end {
            if !received_heights.contains(&height) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn record_individual_filter_received(
        &mut self,
        block_hash: BlockHash,
        storage: &S,
    ) -> SyncResult<()> {
        // Look up height for the block hash
        if let Some(height) = storage.get_header_height_by_hash(&block_hash).await.map_err(|e| {
            SyncError::Storage(format!("Failed to get header height by hash: {}", e))
        })? {
            // Record in received filter heights
            let mut heights = self.received_filter_heights.lock().await;
            heights.insert(height);
            tracing::trace!(
                "📊 Recorded filter received at height {} for block {}",
                height,
                block_hash
            );
        } else {
            tracing::warn!("Could not find height for filter block hash {}", block_hash);
        }

        Ok(())
    }

    pub async fn request_filters(
        &mut self,
        network: &mut N,
        start_height: u32,
        stop_hash: BlockHash,
    ) -> SyncResult<()> {
        let get_cfilters = GetCFilters {
            filter_type: 0, // Basic filter type
            start_height,
            stop_hash,
        };

        // Log with peer if available
        let peer_addr = network.get_last_message_peer_addr().await;
        match peer_addr {
            Some(addr) => tracing::debug!(
                "Sending GetCFilters: start_height={}, stop_hash={}, to {}",
                start_height,
                stop_hash,
                addr
            ),
            None => tracing::debug!(
                "Sending GetCFilters: start_height={}, stop_hash={}",
                start_height,
                stop_hash
            ),
        }

        network
            .send_message(NetworkMessage::GetCFilters(get_cfilters))
            .await
            .map_err(|e| SyncError::Network(format!("Failed to send GetCFilters: {}", e)))?;

        tracing::trace!("Requested filters from height {} to {}", start_height, stop_hash);

        Ok(())
    }

    pub async fn request_filters_with_tracking(
        &mut self,
        network: &mut N,
        storage: &S,
        start_height: u32,
        stop_hash: BlockHash,
    ) -> SyncResult<()> {
        // Find the end height for the stop hash
        let header_tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get header tip height: {}", e)))?
            .ok_or_else(|| {
                SyncError::Storage("No headers available for filter sync".to_string())
            })?;

        let end_height = self
            .find_height_for_block_hash(&stop_hash, storage, start_height, header_tip_height)
            .await?
            .ok_or_else(|| {
                SyncError::Validation(format!(
                    "Cannot find height for stop hash {} in range {}-{}",
                    stop_hash, start_height, header_tip_height
                ))
            })?;

        // Safety check: ensure we don't request more than the Dash Core limit
        let range_size = end_height.saturating_sub(start_height) + 1;
        if range_size > MAX_FILTER_REQUEST_SIZE {
            return Err(SyncError::Validation(format!(
                "Filter request range {}-{} ({} filters) exceeds maximum allowed size of {}",
                start_height, end_height, range_size, MAX_FILTER_REQUEST_SIZE
            )));
        }

        // Record this request for tracking
        self.record_filter_request(start_height, end_height);

        // Send the actual request
        self.request_filters(network, start_height, stop_hash).await
    }

    pub(super) async fn find_height_for_block_hash(
        &self,
        block_hash: &BlockHash,
        storage: &S,
        start_height: u32,
        end_height: u32,
    ) -> SyncResult<Option<u32>> {
        // Use the efficient reverse index first.
        // Contract: StorageManager::get_header_height_by_hash returns ABSOLUTE blockchain height.
        if let Some(abs_height) =
            storage.get_header_height_by_hash(block_hash).await.map_err(|e| {
                SyncError::Storage(format!("Failed to get header height by hash: {}", e))
            })?
        {
            // Check if the absolute height is within the requested range
            if abs_height >= start_height && abs_height <= end_height {
                return Ok(Some(abs_height));
            }
        }

        Ok(None)
    }

    pub async fn download_filter_header_for_block(
        &mut self,
        block_hash: BlockHash,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        // Get the block height for this hash by scanning headers
        let header_tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get header tip height: {}", e)))?
            .ok_or_else(|| {
                SyncError::Storage("No headers available for filter sync".to_string())
            })?;

        let height = self
            .find_height_for_block_hash(&block_hash, storage, 0, header_tip_height)
            .await?
            .ok_or_else(|| {
                SyncError::Validation(format!(
                    "Cannot find height for block {} - header not found",
                    block_hash
                ))
            })?;

        // Check if we already have this filter header
        if storage
            .get_filter_header(height)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to check filter header: {}", e)))?
            .is_some()
        {
            tracing::debug!(
                "Filter header for block {} at height {} already exists",
                block_hash,
                height
            );
            return Ok(());
        }

        tracing::info!("📥 Requesting filter header for block {} at height {}", block_hash, height);

        // Request filter header using getcfheaders
        self.request_filter_headers(network, height, block_hash).await?;

        Ok(())
    }

    pub async fn download_and_check_filter(
        &mut self,
        block_hash: BlockHash,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<bool> {
        // TODO: Will check with wallet once integrated

        // Get the block height for this hash by scanning headers
        let header_tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get header tip height: {}", e)))?
            .unwrap_or(0);

        let height = self
            .find_height_for_block_hash(&block_hash, storage, 0, header_tip_height)
            .await?
            .ok_or_else(|| {
                SyncError::Validation(format!(
                    "Cannot find height for block {} - header not found",
                    block_hash
                ))
            })?;

        tracing::info!(
            "📥 Requesting compact filter for block {} at height {}",
            block_hash,
            height
        );

        // Request the compact filter using getcfilters
        self.request_filters(network, height, block_hash).await?;

        // Note: The actual filter checking will happen when we receive the CFilter message
        // This method just initiates the download. The client will need to handle the response.

        Ok(false) // Return false for now, will be updated when we process the response
    }

    pub async fn store_filter_headers(
        &mut self,
        cfheaders: dashcore::network::message_filter::CFHeaders,
        storage: &mut S,
    ) -> SyncResult<()> {
        if cfheaders.filter_hashes.is_empty() {
            tracing::debug!("No filter headers to store");
            return Ok(());
        }

        // Get the height range for this batch
        let (start_height, stop_height, _header_tip_height) =
            self.get_batch_height_range(&cfheaders, storage).await?;

        tracing::info!(
            "Received {} filter headers from height {} to {}",
            cfheaders.filter_hashes.len(),
            start_height,
            stop_height
        );

        // Check current filter tip to see if we already have some/all of these headers
        let current_filter_tip = storage
            .get_filter_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get filter tip: {}", e)))?
            .unwrap_or(0);

        // If we already have all these filter headers, skip processing
        if current_filter_tip >= stop_height {
            tracing::info!(
                "Already have filter headers up to height {} (received up to {}), skipping",
                current_filter_tip,
                stop_height
            );
            return Ok(());
        }

        // If there's partial overlap, we need to handle it carefully
        if current_filter_tip >= start_height && start_height > 0 {
            tracing::info!(
                "Received overlapping filter headers. Current tip: {}, received range: {}-{}",
                current_filter_tip,
                start_height,
                stop_height
            );

            // Verify that the overlapping portion matches what we have stored
            // This is done by the verify_filter_header_chain method
            // If verification fails, we'll skip storing to avoid corruption
        }

        // Handle overlapping headers properly
        if current_filter_tip >= start_height && start_height > 0 {
            tracing::info!(
                "Received overlapping filter headers. Current tip: {}, received range: {}-{}",
                current_filter_tip,
                start_height,
                stop_height
            );

            // Use the handle_overlapping_headers method which properly handles the chain continuity
            let expected_start = current_filter_tip + 1;

            match self.handle_overlapping_headers(&cfheaders, expected_start, storage).await {
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
                    tracing::warn!(
                        "Failed to handle overlapping filter headers: {}. This may be due to data from different peers.",
                        e
                    );
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
                            storage.store_filter_headers(&genesis_header).await.map_err(|e| {
                                SyncError::Storage(format!(
                                    "Failed to store genesis filter header: {}",
                                    e
                                ))
                            })?;
                            tracing::debug!(
                                "Stored genesis filter header at height 0: {:?}",
                                cfheaders.previous_filter_header
                            );
                        }

                        // If this is the first batch that begins at the checkpoint base, persist the
                        // trusted predecessor filter header so we can verify the checkpoint filter.
                        if self.sync_base_height > 0 && start_height == self.sync_base_height {
                            if let Some(prev_height) = self.sync_base_height.checked_sub(1) {
                                let record = TrustedCheckpointFilterHeader {
                                    height: prev_height,
                                    header: cfheaders.previous_filter_header,
                                };
                                self.persist_checkpoint_prev_filter_header(storage, record).await?;
                                tracing::info!(
                                    "Stored trusted checkpoint predecessor filter header at height {}",
                                    prev_height
                                );
                            }
                        } else if self.sync_base_height > 0
                            && start_height == self.sync_base_height + 1
                            && current_filter_tip < self.sync_base_height
                        {
                            // Store the previous_filter_header as the filter header for the checkpoint block
                            let checkpoint_header = vec![cfheaders.previous_filter_header];
                            storage.store_filter_headers(&checkpoint_header).await.map_err(
                                |e| {
                                    SyncError::Storage(format!(
                                        "Failed to store checkpoint filter header: {}",
                                        e
                                    ))
                                },
                            )?;
                            tracing::info!(
                                "Stored checkpoint filter header at height {}: {:?}",
                                self.sync_base_height,
                                cfheaders.previous_filter_header
                            );
                        }

                        // Store the new filter headers
                        storage.store_filter_headers(&new_filter_headers).await.map_err(|e| {
                            SyncError::Storage(format!("Failed to store filter headers: {}", e))
                        })?;

                        tracing::info!(
                            "✅ Successfully stored {} new filter headers",
                            new_filter_headers.len()
                        );
                    }
                }
                Err(e) => {
                    // If verification failed, it might be from a peer with different data
                    tracing::warn!(
                        "Failed to process filter headers: {}. This may be due to data from different peers.",
                        e
                    );
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    pub async fn send_next_filter_batch(&mut self, network: &mut N) -> SyncResult<()> {
        let available_slots = self.get_available_request_slots();
        let requests_to_send = available_slots.min(self.pending_filter_requests.len());

        if requests_to_send > 0 {
            tracing::debug!(
                "Sending {} more filter requests ({} queued, {} active)",
                requests_to_send,
                self.pending_filter_requests.len() - requests_to_send,
                self.active_filter_requests.len() + requests_to_send
            );

            for _ in 0..requests_to_send {
                if let Some(request) = self.pending_filter_requests.pop_front() {
                    self.send_filter_request(network, request).await?;
                }
            }
        }

        Ok(())
    }
}
