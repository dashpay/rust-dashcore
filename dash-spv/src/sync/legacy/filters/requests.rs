//! Request queue management and flow control.
//!
//! This module handles:
//! - Building request queues for CFHeaders and CFilters
//! - Processing queues with concurrency limits (flow control)
//! - Tracking active requests and managing completion
//! - Sending individual requests to the network

use super::types::*;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;

impl<S: StorageManager, N: NetworkManager> super::manager::FilterSyncManager<S, N> {
    /// Build a queue of filter requests covering the specified range.
    ///
    /// If start_height is None, defaults to (filter_header_tip - DEFAULT_FILTER_SYNC_RANGE).
    /// If count is None, syncs to filter_header_tip.
    /// Splits the range into batches of FILTER_REQUEST_BATCH_SIZE.
    pub(super) async fn build_filter_request_queue(
        &mut self,
        storage: &S,
        start_height: Option<u32>,
        count: Option<u32>,
    ) -> SyncResult<()> {
        // Clear any existing queue
        self.pending_filter_requests.clear();

        // Determine range to sync
        // Note: get_filter_tip_height() returns the highest filter HEADER height, not filter height
        let filter_header_tip_height = storage
            .get_filter_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get filter header tip: {}", e)))?
            .unwrap_or(0);

        let start = start_height
            .unwrap_or_else(|| filter_header_tip_height.saturating_sub(DEFAULT_FILTER_SYNC_RANGE));

        // Calculate the end height based on the requested count
        // Do NOT cap at the current filter position - we want to sync UP TO the filter header tip
        let end = if let Some(c) = count {
            (start + c - 1).min(filter_header_tip_height)
        } else {
            filter_header_tip_height
        };

        let base_height = self.sync_base_height;
        let clamped_start = start.max(base_height);

        if clamped_start > end {
            tracing::warn!(
                "⚠️ Filter sync requested from height {} but end height is {} - no filters to sync",
                start,
                end
            );
            return Ok(());
        }

        tracing::info!(
            "🔄 Building filter request queue from height {} to {} ({} blocks, filter headers available up to {})",
            clamped_start,
            end,
            end - clamped_start + 1,
            filter_header_tip_height
        );

        // Build requests in batches
        let batch_size = FILTER_REQUEST_BATCH_SIZE;
        let mut current_height = clamped_start;

        while current_height <= end {
            let batch_end = (current_height + batch_size - 1).min(end);

            // Ensure the batch end height is within the stored header range
            let stop_hash = storage
                .get_header(batch_end)
                .await
                .map_err(|e| {
                    SyncError::Storage(format!(
                        "Failed to get stop header at height {}: {}",
                        batch_end, e
                    ))
                })?
                .ok_or_else(|| {
                    SyncError::Storage(format!("Stop header not found at height {}", batch_end))
                })?
                .block_hash();

            // Create filter request and add to queue
            let request = FilterRequest {
                start_height: current_height,
                end_height: batch_end,
                stop_hash,
                is_retry: false,
            };

            self.pending_filter_requests.push_back(request);

            tracing::debug!(
                "Queued filter request for heights {} to {}",
                current_height,
                batch_end
            );

            current_height = batch_end + 1;
        }

        tracing::info!(
            "📋 Filter request queue built with {} batches",
            self.pending_filter_requests.len()
        );

        // Log the first few batches for debugging
        for (i, request) in self.pending_filter_requests.iter().take(3).enumerate() {
            tracing::debug!(
                "  Batch {}: heights {}-{} (stop hash: {})",
                i + 1,
                request.start_height,
                request.end_height,
                request.stop_hash
            );
        }
        if self.pending_filter_requests.len() > 3 {
            tracing::debug!("  ... and {} more batches", self.pending_filter_requests.len() - 3);
        }

        Ok(())
    }

    /// Process the filter request queue.
    ///
    /// Sends an initial batch of requests up to MAX_CONCURRENT_FILTER_REQUESTS.
    /// Additional requests are sent as active requests complete.
    pub(super) async fn process_filter_request_queue(
        &mut self,
        network: &mut N,
        _storage: &S,
    ) -> SyncResult<()> {
        // Send initial batch up to MAX_CONCURRENT_FILTER_REQUESTS
        let initial_send_count =
            MAX_CONCURRENT_FILTER_REQUESTS.min(self.pending_filter_requests.len());

        for _ in 0..initial_send_count {
            if let Some(request) = self.pending_filter_requests.pop_front() {
                self.send_filter_request(network, request).await?;
            }
        }

        tracing::info!(
            "🚀 Sent initial batch of {} filter requests ({} queued, {} active)",
            initial_send_count,
            self.pending_filter_requests.len(),
            self.active_filter_requests.len()
        );

        Ok(())
    }

    /// Send a single filter request and track it as active.
    pub(super) async fn send_filter_request(
        &mut self,
        network: &mut N,
        request: FilterRequest,
    ) -> SyncResult<()> {
        // Send the actual network request
        self.request_filters(network, request.start_height, request.stop_hash).await?;

        // Track this request as active
        let range = (request.start_height, request.end_height);
        let active_request = ActiveRequest {
            sent_time: std::time::Instant::now(),
        };

        self.active_filter_requests.insert(range, active_request);

        // Include peer info when available
        let peer_addr = network.get_last_message_peer_addr().await;
        match peer_addr {
            Some(addr) => {
                tracing::debug!(
                    "📡 Sent filter request for range {}-{} to {} (now {} active)",
                    request.start_height,
                    request.end_height,
                    addr,
                    self.active_filter_requests.len()
                );
            }
            None => {
                tracing::debug!(
                    "📡 Sent filter request for range {}-{} (now {} active)",
                    request.start_height,
                    request.end_height,
                    self.active_filter_requests.len()
                );
            }
        }

        // Apply delay only for retry requests to avoid hammering peers
        if request.is_retry && FILTER_RETRY_DELAY_MS > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(FILTER_RETRY_DELAY_MS)).await;
        }

        Ok(())
    }

    /// Mark a filter as received and check for batch completion.
    ///
    /// Returns list of completed request ranges (start_height, end_height).
    /// Process next requests from the queue when active requests complete.
    ///
    /// Called after filter requests complete to send more from the queue.
    pub async fn process_next_queued_requests(&mut self, network: &mut N) -> SyncResult<()> {
        let available_slots =
            MAX_CONCURRENT_FILTER_REQUESTS.saturating_sub(self.active_filter_requests.len());
        let mut sent_count = 0;

        for _ in 0..available_slots {
            if let Some(request) = self.pending_filter_requests.pop_front() {
                self.send_filter_request(network, request).await?;
                sent_count += 1;
            } else {
                break;
            }
        }

        if sent_count > 0 {
            tracing::debug!(
                "🚀 Sent {} additional filter requests from queue ({} queued, {} active)",
                sent_count,
                self.pending_filter_requests.len(),
                self.active_filter_requests.len()
            );
        }

        Ok(())
    }
}
