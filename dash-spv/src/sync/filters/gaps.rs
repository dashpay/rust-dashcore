//! Gap detection and recovery logic.
//!
//! This module handles:
//! - Detecting gaps between headers and filter headers
//! - Detecting gaps between filter headers and downloaded filters
//! - Finding missing filter ranges within requested ranges
//! - Retrying missing or timed-out filter requests
//! - Auto-restarting filter header sync when gaps are detected

use super::types::*;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use std::collections::HashSet;

impl<S: StorageManager + Send + Sync + 'static, N: NetworkManager + Send + Sync + 'static>
    super::manager::FilterSyncManager<S, N>
{
    /// Record a filter request for a height range.
    ///
    /// Tracks when the request was made for timeout detection.
    pub fn record_filter_request(&mut self, start_height: u32, end_height: u32) {
        self.requested_filter_ranges.insert((start_height, end_height), std::time::Instant::now());
        tracing::debug!("📊 Recorded filter request for range {}-{}", start_height, end_height);
    }

    /// Record receipt of a filter at a specific height.
    pub fn record_filter_received(&mut self, height: u32) {
        if let Ok(mut heights) = self.received_filter_heights.try_lock() {
            heights.insert(height);
            tracing::trace!("📊 Recorded filter received at height {}", height);
        }
    }

    /// Find missing filter ranges within the requested ranges.
    ///
    /// Returns a list of (start_height, end_height) tuples for ranges where
    /// filters were requested but not all filters have been received.
    pub fn find_missing_ranges(&self) -> Vec<(u32, u32)> {
        let mut missing_ranges = Vec::new();

        let heights = match self.received_filter_heights.try_lock() {
            Ok(heights) => heights.clone(),
            Err(_) => return missing_ranges,
        };

        // For each requested range
        for (start, end) in self.requested_filter_ranges.keys() {
            let mut current = *start;

            // Find gaps within this range
            while current <= *end {
                if !heights.contains(&current) {
                    // Start of a gap
                    let gap_start = current;

                    // Find end of gap
                    while current <= *end && !heights.contains(&current) {
                        current += 1;
                    }

                    missing_ranges.push((gap_start, current - 1));
                } else {
                    current += 1;
                }
            }
        }

        // Merge adjacent ranges for efficiency
        Self::merge_adjacent_ranges(&mut missing_ranges);
        missing_ranges
    }

    /// Check if a filter range is complete (all heights received).
    pub fn is_range_complete(&self, start_height: u32, end_height: u32) -> bool {
        let heights = match self.received_filter_heights.try_lock() {
            Ok(heights) => heights,
            Err(_) => return false,
        };

        for height in start_height..=end_height {
            if !heights.contains(&height) {
                return false;
            }
        }
        true
    }

    /// Get total number of missing filters across all ranges.
    pub fn get_total_missing_filters(&self) -> u32 {
        let missing_ranges = self.find_missing_ranges();
        missing_ranges.iter().map(|(start, end)| end - start + 1).sum()
    }

    /// Get actual coverage percentage (considering gaps).
    ///
    /// Returns percentage of requested filters that have been received.
    pub fn get_actual_coverage_percentage(&self) -> f64 {
        if self.requested_filter_ranges.is_empty() {
            return 0.0;
        }

        let total_requested: u32 =
            self.requested_filter_ranges.iter().map(|((start, end), _)| end - start + 1).sum();

        if total_requested == 0 {
            return 0.0;
        }

        let total_missing = self.get_total_missing_filters();
        let received = total_requested - total_missing;

        (received as f64 / total_requested as f64) * 100.0
    }

    /// Check if there's a gap between block headers and filter headers.
    ///
    /// Returns (has_gap, block_height, filter_height, gap_size).
    /// A gap of <= 1 block is considered normal (edge case at tip).
    pub async fn check_cfheader_gap(&self, storage: &S) -> SyncResult<(bool, u32, u32, u32)> {
        let block_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get block tip: {}", e)))?
            .unwrap_or(0);

        let filter_height = storage
            .get_filter_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get filter tip: {}", e)))?
            .unwrap_or(0);

        let gap_size = block_height.saturating_sub(filter_height);

        // Consider within 1 block as "no gap" to handle edge cases at the tip
        let has_gap = gap_size > 1;

        tracing::debug!(
            "CFHeader gap check: block_height={}, filter_height={}, gap={}",
            block_height,
            filter_height,
            gap_size
        );

        Ok((has_gap, block_height, filter_height, gap_size))
    }

    /// Check if there's a gap between synced filters and filter headers.
    ///
    /// Returns (has_gap, filter_header_height, last_synced_filter, gap_size).
    pub async fn check_filter_gap(
        &self,
        storage: &S,
        progress: &crate::types::SyncProgress,
    ) -> SyncResult<(bool, u32, u32, u32)> {
        // Get filter header tip height
        let filter_header_height = storage
            .get_filter_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get filter tip height: {}", e)))?
            .unwrap_or(0);

        // Get last synced filter height from progress tracking
        let last_synced_filter = progress.last_synced_filter_height.unwrap_or(0);

        // Calculate gap
        let gap_size = filter_header_height.saturating_sub(last_synced_filter);
        let has_gap = gap_size > 0;

        tracing::debug!(
            "Filter gap check: filter_header_height={}, last_synced_filter={}, gap={}",
            filter_header_height,
            last_synced_filter,
            gap_size
        );

        Ok((has_gap, filter_header_height, last_synced_filter, gap_size))
    }

    /// Attempt to restart filter header sync if there's a gap and conditions are met.
    ///
    /// Returns true if sync was restarted, false otherwise.
    /// Respects cooldown period and max retry attempts to prevent spam.
    pub async fn maybe_restart_cfheader_sync_for_gap(
        &mut self,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<bool> {
        // Check if we're already syncing
        if self.syncing_filter_headers {
            return Ok(false);
        }

        // Check gap detection cooldown
        if let Some(last_attempt) = self.last_gap_restart_attempt {
            if last_attempt.elapsed() < self.gap_restart_cooldown {
                return Ok(false); // Too soon since last attempt
            }
        }

        // Check if we've exceeded max attempts
        if self.gap_restart_failure_count >= self.max_gap_restart_attempts {
            tracing::warn!(
                "⚠️  CFHeader gap restart disabled after {} failed attempts",
                self.max_gap_restart_attempts
            );
            return Ok(false);
        }

        // Check for gap
        let (has_gap, block_height, filter_height, gap_size) =
            self.check_cfheader_gap(storage).await?;

        if !has_gap {
            // Reset failure count if no gap
            if self.gap_restart_failure_count > 0 {
                tracing::debug!("✅ CFHeader gap resolved, resetting failure count");
                self.gap_restart_failure_count = 0;
            }
            return Ok(false);
        }

        // Gap detected - attempt restart
        tracing::info!(
            "🔄 CFHeader gap detected: {} block headers vs {} filter headers (gap: {})",
            block_height,
            filter_height,
            gap_size
        );
        tracing::info!("🚀 Auto-restarting filter header sync to close gap...");

        self.last_gap_restart_attempt = Some(std::time::Instant::now());

        match self.start_sync_headers(network, storage).await {
            Ok(started) => {
                if started {
                    tracing::info!("✅ CFHeader sync restarted successfully");
                    self.gap_restart_failure_count = 0; // Reset on success
                    Ok(true)
                } else {
                    tracing::warn!(
                        "⚠️  CFHeader sync restart returned false (already up to date?)"
                    );
                    self.gap_restart_failure_count += 1;
                    Ok(false)
                }
            }
            Err(e) => {
                tracing::error!("❌ Failed to restart CFHeader sync: {}", e);
                self.gap_restart_failure_count += 1;
                Err(e)
            }
        }
    }

    /// Retry missing or timed out filter ranges.
    ///
    /// Finds missing and timed-out ranges, deduplicates them, and re-requests.
    /// Respects max retry count and batch size limits.
    /// Returns number of ranges retried.
    pub async fn retry_missing_filters(&mut self, network: &mut N, storage: &S) -> SyncResult<u32> {
        let missing = self.find_missing_ranges();
        let timed_out = self.get_timed_out_ranges(std::time::Duration::from_secs(30));

        // Combine and deduplicate
        let mut ranges_to_retry: HashSet<(u32, u32)> = missing.into_iter().collect();
        ranges_to_retry.extend(timed_out);

        if ranges_to_retry.is_empty() {
            return Ok(0);
        }

        let mut retried_count = 0;

        for (start, end) in ranges_to_retry {
            let retry_count = self.filter_retry_counts.get(&(start, end)).copied().unwrap_or(0);

            if retry_count >= self.max_filter_retries {
                tracing::error!(
                    "❌ Filter range {}-{} failed after {} retries, giving up",
                    start,
                    end,
                    retry_count
                );
                continue;
            }

            // Ensure retry end height is within the stored header window
            if self.header_abs_to_storage_index(end).is_none() {
                tracing::debug!(
                    "Skipping retry for range {}-{} because end is below checkpoint base {}",
                    start,
                    end,
                    self.sync_base_height
                );
                continue;
            }

            match storage.get_header(end).await {
                Ok(Some(header)) => {
                    let stop_hash = header.block_hash();

                    tracing::info!(
                        "🔄 Retrying filter range {}-{} (attempt {}/{})",
                        start,
                        end,
                        retry_count + 1,
                        self.max_filter_retries
                    );

                    // Re-request the range, but respect batch size limits
                    let range_size = end - start + 1;
                    if range_size <= MAX_FILTER_REQUEST_SIZE {
                        // Range is within limits, request directly
                        self.request_filters(network, start, stop_hash).await?;
                        self.filter_retry_counts.insert((start, end), retry_count + 1);
                        retried_count += 1;
                    } else {
                        // Range is too large, split into smaller batches
                        tracing::warn!(
                            "Filter range {}-{} ({} filters) exceeds Dash Core's 1000 filter limit, splitting into batches",
                            start,
                            end,
                            range_size
                        );

                        let max_batch_size = MAX_FILTER_REQUEST_SIZE;
                        let mut current_start = start;

                        while current_start <= end {
                            let batch_end = (current_start + max_batch_size - 1).min(end);

                            if self.header_abs_to_storage_index(batch_end).is_none() {
                                tracing::debug!(
                                    "Skipping retry batch {}-{} because batch end is below checkpoint base {}",
                                    current_start,
                                    batch_end,
                                    self.sync_base_height
                                );
                                current_start = batch_end + 1;
                                continue;
                            }

                            match storage.get_header(batch_end).await {
                                Ok(Some(batch_header)) => {
                                    let batch_stop_hash = batch_header.block_hash();

                                    tracing::info!(
                                        "🔄 Retrying filter batch {}-{} (part of range {}-{}, attempt {}/{})",
                                        current_start,
                                        batch_end,
                                        start,
                                        end,
                                        retry_count + 1,
                                        self.max_filter_retries
                                    );

                                    self.request_filters(network, current_start, batch_stop_hash)
                                        .await?;
                                    current_start = batch_end + 1;
                                }
                                Ok(None) => {
                                    tracing::warn!(
                                        "Missing header at height {} for batch retry, continuing to next batch",
                                        batch_end
                                    );
                                    current_start = batch_end + 1;
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "Error retrieving header at height {}: {:?}, continuing to next batch",
                                        batch_end,
                                        e
                                    );
                                    current_start = batch_end + 1;
                                }
                            }
                        }

                        // Update retry count for the original range
                        self.filter_retry_counts.insert((start, end), retry_count + 1);
                        retried_count += 1;
                    }
                }
                Ok(None) => {
                    tracing::error!(
                        "Cannot retry filter range {}-{}: header not found at height {}",
                        start,
                        end,
                        end
                    );
                }
                Err(e) => {
                    tracing::error!("Failed to get header at height {} for retry: {}", end, e);
                }
            }
        }

        if retried_count > 0 {
            tracing::info!("📡 Retried {} filter ranges", retried_count);
        }

        Ok(retried_count)
    }

    /// Check and retry missing filters (main entry point for monitoring loop).
    ///
    /// Logs diagnostic information about missing ranges before retrying.
    pub async fn check_and_retry_missing_filters(
        &mut self,
        network: &mut N,
        storage: &S,
    ) -> SyncResult<()> {
        let missing_ranges = self.find_missing_ranges();
        let total_missing = self.get_total_missing_filters();

        if total_missing > 0 {
            tracing::info!(
                "📊 Filter gap check: {} missing ranges covering {} filters",
                missing_ranges.len(),
                total_missing
            );

            // Show first few missing ranges for debugging
            for (i, (start, end)) in missing_ranges.iter().enumerate() {
                if i >= 5 {
                    tracing::info!("  ... and {} more missing ranges", missing_ranges.len() - 5);
                    break;
                }
                tracing::info!("  Missing range: {}-{} ({} filters)", start, end, end - start + 1);
            }

            let retried = self.retry_missing_filters(network, storage).await?;
            if retried > 0 {
                tracing::info!("✅ Initiated retry for {} filter ranges", retried);
            }
        }

        Ok(())
    }

    /// Merge adjacent ranges for efficiency, but respect the maximum filter request size.
    ///
    /// Sorts ranges, merges adjacent ones if they don't exceed MAX_FILTER_REQUEST_SIZE,
    /// and splits any ranges that exceed the limit.
    fn merge_adjacent_ranges(ranges: &mut Vec<(u32, u32)>) {
        if ranges.is_empty() {
            return;
        }

        ranges.sort_by_key(|(start, _)| *start);

        let mut merged = Vec::new();
        let mut current = ranges[0];

        for &(start, end) in ranges.iter().skip(1) {
            let potential_merged_size = end.saturating_sub(current.0) + 1;

            if start <= current.1 + 1 && potential_merged_size <= MAX_FILTER_REQUEST_SIZE {
                // Merge ranges only if the result doesn't exceed the limit
                current.1 = current.1.max(end);
            } else {
                // Non-adjacent or would exceed limit, push current and start new
                merged.push(current);
                current = (start, end);
            }
        }

        merged.push(current);

        // Final pass: split any ranges that still exceed the limit
        let mut final_ranges = Vec::new();
        for (start, end) in merged {
            let range_size = end.saturating_sub(start) + 1;
            if range_size <= MAX_FILTER_REQUEST_SIZE {
                final_ranges.push((start, end));
            } else {
                // Split large range into smaller chunks
                let mut chunk_start = start;
                while chunk_start <= end {
                    let chunk_end = (chunk_start + MAX_FILTER_REQUEST_SIZE - 1).min(end);
                    final_ranges.push((chunk_start, chunk_end));
                    chunk_start = chunk_end + 1;
                }
            }
        }

        *ranges = final_ranges;
    }
}
