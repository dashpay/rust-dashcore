//! Timeout and retry logic for filter synchronization.
//!
//! This module handles:
//! - Detecting timed-out filter and CFHeader requests
//! - Retrying failed requests with exponential backoff
//! - Managing retry counts and giving up after max attempts
//! - Sync progress timeout detection

use super::types::*;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use dashcore::BlockHash;

impl<S: StorageManager, N: NetworkManager> super::manager::FilterSyncManager<S, N> {
    /// Check if filter header sync has timed out (no progress for SYNC_TIMEOUT_SECONDS).
    ///
    /// If timeout is detected, attempts recovery by re-sending the current batch request.
    pub async fn check_sync_timeout(
        &mut self,
        storage: &mut S,
        network: &mut N,
    ) -> SyncResult<bool> {
        if !self.syncing_filter_headers {
            return Ok(false);
        }

        if self.last_sync_progress.elapsed() > std::time::Duration::from_secs(SYNC_TIMEOUT_SECONDS)
        {
            tracing::warn!(
                "📊 No filter header sync progress for {}+ seconds, re-sending filter header request",
                SYNC_TIMEOUT_SECONDS
            );

            // Get header tip height for recovery
            let header_tip_height = storage.get_tip_height().await.ok_or_else(|| {
                SyncError::Storage("No headers available for filter sync".to_string())
            })?;

            // Re-calculate current batch parameters for recovery
            let recovery_batch_end_height =
                (self.current_sync_height + FILTER_BATCH_SIZE - 1).min(header_tip_height);
            let recovery_batch_stop_hash = if recovery_batch_end_height < header_tip_height {
                // Try to get the header at the calculated height with backward scanning
                match storage.get_header(recovery_batch_end_height).await {
                    Ok(Some(header)) => header.block_hash(),
                    Ok(None) => {
                        tracing::warn!(
                            "Recovery header not found at blockchain height {}, scanning backwards",
                            recovery_batch_end_height
                        );

                        let min_height = self.current_sync_height;
                        match self
                            .find_available_header_at_or_before(
                                recovery_batch_end_height.saturating_sub(1),
                                min_height,
                                storage,
                            )
                            .await
                        {
                            Some((hash, height)) => {
                                if height < self.current_sync_height {
                                    tracing::warn!(
                                        "Recovery: Found header at height {} which is less than current sync height {}. This indicates we already have filter headers up to {}. Marking sync as complete.",
                                        height,
                                        self.current_sync_height,
                                        self.current_sync_height - 1
                                    );
                                    self.syncing_filter_headers = false;
                                    return Ok(false);
                                }
                                hash
                            }
                            None => {
                                tracing::error!(
                                    "No headers available for recovery between {} and {}",
                                    min_height,
                                    recovery_batch_end_height
                                );
                                return Err(SyncError::Storage(
                                    "No headers available for recovery".to_string(),
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        return Err(SyncError::Storage(format!(
                            "Failed to get recovery batch stop header at height {}: {}",
                            recovery_batch_end_height, e
                        )));
                    }
                }
            } else {
                // Special handling for chain tip: if we can't find the exact tip header,
                // try the previous header as we might be at the actual chain tip
                match storage.get_header(header_tip_height).await {
                    Ok(Some(header)) => header.block_hash(),
                    Ok(None) if header_tip_height > 0 => {
                        tracing::debug!(
                            "Tip header not found at blockchain height {} during recovery, trying previous header",
                            header_tip_height
                        );
                        // Try previous header when at chain tip
                        storage
                            .get_header(header_tip_height - 1)
                            .await
                            .map_err(|e| {
                                SyncError::Storage(format!(
                                    "Failed to get previous header during recovery: {}",
                                    e
                                ))
                            })?
                            .ok_or_else(|| {
                                SyncError::Storage(format!(
                                    "Neither tip ({}) nor previous header found during recovery",
                                    header_tip_height
                                ))
                            })?
                            .block_hash()
                    }
                    Ok(None) => {
                        return Err(SyncError::Validation(format!(
                            "Tip header not found at height {} (genesis) during recovery",
                            header_tip_height
                        )));
                    }
                    Err(e) => {
                        return Err(SyncError::Validation(format!(
                            "Failed to get tip header during recovery: {}",
                            e
                        )));
                    }
                }
            };

            self.request_filter_headers(
                network,
                self.current_sync_height,
                recovery_batch_stop_hash,
            )
            .await?;
            self.last_sync_progress = std::time::Instant::now();

            return Ok(true);
        }

        Ok(false)
    }

    /// Check for timed out CFHeader requests and retry them.
    ///
    /// Called periodically to detect and recover from requests that never received responses.
    pub async fn check_cfheader_request_timeouts(
        &mut self,
        network: &mut N,
        storage: &S,
    ) -> SyncResult<()> {
        if !self.syncing_filter_headers {
            return Ok(());
        }

        let now = std::time::Instant::now();
        let mut timed_out_requests = Vec::new();

        // Check for timed out active requests
        for (start_height, active_req) in &self.active_cfheader_requests {
            if now.duration_since(active_req.sent_time) > self.cfheader_request_timeout {
                timed_out_requests.push((*start_height, active_req.stop_hash));
            }
        }

        // Handle timeouts: remove from active, retry or give up based on retry count
        for (start_height, stop_hash) in timed_out_requests {
            self.handle_cfheader_request_timeout(start_height, stop_hash, network, storage).await?;
        }

        // Check queue status and send next batch if needed
        self.process_next_queued_cfheader_requests(network).await?;

        Ok(())
    }

    /// Handle a specific CFHeaders request timeout.
    async fn handle_cfheader_request_timeout(
        &mut self,
        start_height: u32,
        stop_hash: BlockHash,
        _network: &mut N,
        _storage: &S,
    ) -> SyncResult<()> {
        let retry_count = self.cfheader_retry_counts.get(&start_height).copied().unwrap_or(0);

        // Remove from active requests
        self.active_cfheader_requests.remove(&start_height);

        if retry_count >= self.max_cfheader_retries {
            tracing::error!(
                "❌ CFHeaders request for height {} failed after {} retries, giving up",
                start_height,
                retry_count
            );
            return Ok(());
        }

        tracing::info!(
            "🔄 Retrying timed out CFHeaders request for height {} (attempt {}/{})",
            start_height,
            retry_count + 1,
            self.max_cfheader_retries
        );

        // Create new request and add back to queue for retry
        let retry_request = CFHeaderRequest {
            start_height,
            stop_hash,
            is_retry: true,
        };

        // Update retry count
        self.cfheader_retry_counts.insert(start_height, retry_count + 1);

        // Add to front of queue for priority retry
        self.pending_cfheader_requests.push_front(retry_request);

        Ok(())
    }

    /// Check for timed out filter requests and retry them.
    pub async fn check_filter_request_timeouts(
        &mut self,
        network: &mut N,
        storage: &S,
    ) -> SyncResult<()> {
        let now = std::time::Instant::now();
        let timeout_duration = std::time::Duration::from_secs(REQUEST_TIMEOUT_SECONDS);

        // Check for timed out active requests
        let mut timed_out_requests = Vec::new();
        for ((start, end), active_req) in &self.active_filter_requests {
            if now.duration_since(active_req.sent_time) > timeout_duration {
                timed_out_requests.push((*start, *end));
            }
        }

        // Handle timeouts: remove from active, retry or give up based on retry count
        for range in timed_out_requests {
            self.handle_request_timeout(range, network, storage).await?;
        }

        // Check queue status and send next batch if needed
        self.process_next_queued_requests(network).await?;

        Ok(())
    }

    /// Handle a specific filter request timeout.
    async fn handle_request_timeout(
        &mut self,
        range: (u32, u32),
        _network: &mut N,
        storage: &S,
    ) -> SyncResult<()> {
        let (start, end) = range;
        let retry_count = self.filter_retry_counts.get(&range).copied().unwrap_or(0);

        // Remove from active requests
        self.active_filter_requests.remove(&range);

        if retry_count >= self.max_filter_retries {
            tracing::error!(
                "❌ Filter range {}-{} failed after {} retries, giving up",
                start,
                end,
                retry_count
            );
            return Ok(());
        }

        // Calculate stop hash for retry; ensure height is within the stored window
        if self.header_abs_to_storage_index(end).is_none() {
            tracing::debug!(
                "Skipping retry for range {}-{} because end is below checkpoint base {}",
                start,
                end,
                self.sync_base_height
            );
            return Ok(());
        }

        match storage.get_header(end).await {
            Ok(Some(header)) => {
                let stop_hash = header.block_hash();

                tracing::info!(
                    "🔄 Retrying timed out filter range {}-{} (attempt {}/{})",
                    start,
                    end,
                    retry_count + 1,
                    self.max_filter_retries
                );

                // Create new request and add back to queue for retry
                let retry_request = FilterRequest {
                    start_height: start,
                    end_height: end,
                    stop_hash,
                    is_retry: true,
                };

                // Update retry count
                self.filter_retry_counts.insert(range, retry_count + 1);

                // Add to front of queue for priority retry
                self.pending_filter_requests.push_front(retry_request);

                Ok(())
            }
            Ok(None) => {
                tracing::error!(
                    "Cannot retry filter range {}-{}: header not found at height {}",
                    start,
                    end,
                    end
                );
                Ok(())
            }
            Err(e) => {
                tracing::error!("Failed to get header at height {} for retry: {}", end, e);
                Ok(())
            }
        }
    }
}
