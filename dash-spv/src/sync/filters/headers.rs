//! CFHeaders (filter header) synchronization logic.
//!
//! This module handles the synchronization of compact block filter headers (CFHeaders)
//! which are used to efficiently determine which blocks might contain transactions
//! relevant to watched addresses.
//!
//! ## Key Features
//!
//! - Sequential and flow-controlled CFHeaders synchronization
//! - Batch processing with configurable concurrency
//! - Timeout detection and automatic recovery
//! - Gap detection and overlap handling
//! - Filter header chain verification
//! - Stability checking before declaring sync complete

use dashcore::{
    network::message::NetworkMessage,
    network::message_filter::{CFHeaders, GetCFHeaders},
    BlockHash,
};

use super::types::*;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;

impl<S: StorageManager + Send + Sync + 'static, N: NetworkManager + Send + Sync + 'static>
    super::manager::FilterSyncManager<S, N>
{
    pub(super) async fn find_available_header_at_or_before(
        &self,
        abs_height: u32,
        min_abs_height: u32,
        storage: &S,
    ) -> Option<(BlockHash, u32)> {
        if abs_height < min_abs_height {
            return None;
        }

        let mut scan_height = abs_height;
        loop {
            match storage.get_header(scan_height).await {
                Ok(Some(header)) => {
                    tracing::info!("Found available header at blockchain height {}", scan_height);
                    return Some((header.block_hash(), scan_height));
                }
                Ok(None) => {
                    tracing::debug!(
                        "Header missing at blockchain height {}, scanning back",
                        scan_height
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "Error reading header at blockchain height {}: {}",
                        scan_height,
                        e
                    );
                }
            }

            if scan_height == min_abs_height {
                break;
            }
            scan_height = scan_height.saturating_sub(1);
        }

        None
    }
    /// Calculate the start height of a CFHeaders batch.
    fn calculate_batch_start_height(cf_headers: &CFHeaders, stop_height: u32) -> u32 {
        let count = cf_headers.filter_hashes.len() as u32;
        let offset = count.saturating_sub(1);
        stop_height.saturating_sub(offset)
    }

    /// Get the height range for a CFHeaders batch.
    pub(super) async fn get_batch_height_range(
        &self,
        cf_headers: &CFHeaders,
        storage: &S,
    ) -> SyncResult<(u32, u32, u32)> {
        let header_tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get header tip height: {}", e)))?
            .ok_or_else(|| {
                SyncError::Storage("No headers available for filter sync".to_string())
            })?;

        let stop_height = self
            .find_height_for_block_hash(&cf_headers.stop_hash, storage, 0, header_tip_height)
            .await?
            .ok_or_else(|| {
                SyncError::Validation(format!(
                    "Cannot find height for stop hash {} in CFHeaders",
                    cf_headers.stop_hash
                ))
            })?;

        let start_height = Self::calculate_batch_start_height(cf_headers, stop_height);

        // Best-effort: resolve the start block hash for additional diagnostics from headers storage
        let start_hash_opt =
            storage.get_header(start_height).await.ok().flatten().map(|h| h.block_hash());

        // Always try to resolve the expected/requested start as well (current_sync_height)
        // We don't have access to current_sync_height here, so we'll log both the batch
        // start and a best-effort expected start in the caller. For this analysis log,
        // avoid placeholder labels and prefer concrete values when known.
        let prev_height = start_height.saturating_sub(1);
        match start_hash_opt {
            Some(h) => {
                tracing::debug!(
                    "CFHeaders batch analysis: batch_start_hash={}, msg_prev_filter_header={}, msg_prev_height={}, stop_hash={}, stop_height={}, start_height={}, count={}, header_tip_height={}",
                    h,
                    cf_headers.previous_filter_header,
                    prev_height,
                    cf_headers.stop_hash,
                    stop_height,
                    start_height,
                    cf_headers.filter_hashes.len(),
                    header_tip_height
                );
            }
            None => {
                tracing::debug!(
                    "CFHeaders batch analysis: batch_start_hash=<not stored>, msg_prev_filter_header={}, msg_prev_height={}, stop_hash={}, stop_height={}, start_height={}, count={}, header_tip_height={}",
                    cf_headers.previous_filter_header,
                    prev_height,
                    cf_headers.stop_hash,
                    stop_height,
                    start_height,
                    cf_headers.filter_hashes.len(),
                    header_tip_height
                );
            }
        }
        Ok((start_height, stop_height, header_tip_height))
    }

    pub async fn handle_cfheaders_message(
        &mut self,
        cf_headers: CFHeaders,
        storage: &mut S,
        network: &mut N,
    ) -> SyncResult<bool> {
        if !self.syncing_filter_headers {
            // Not currently syncing, ignore
            return Ok(true);
        }

        // Check if we're using flow control
        if self.cfheaders_flow_control_enabled {
            return self.handle_cfheaders_with_flow_control(cf_headers, storage, network).await;
        }

        // Don't update last_sync_progress here - only update when we actually make progress

        if cf_headers.filter_hashes.is_empty() {
            // Empty response indicates end of sync
            self.syncing_filter_headers = false;
            return Ok(false);
        }

        // Get the height range for this batch
        let (batch_start_height, stop_height, header_tip_height) =
            self.get_batch_height_range(&cf_headers, storage).await?;

        // Best-effort: resolve start hash for this batch for better diagnostics
        let recv_start_hash_opt =
            storage.get_header(batch_start_height).await.ok().flatten().map(|h| h.block_hash());

        // Resolve expected start hash (what we asked for), for clarity
        let expected_start_hash_opt = storage
            .get_header(self.current_sync_height)
            .await
            .ok()
            .flatten()
            .map(|h| h.block_hash());

        let prev_height = batch_start_height.saturating_sub(1);
        let effective_prev_height = self.current_sync_height.saturating_sub(1);
        match (recv_start_hash_opt, expected_start_hash_opt) {
            (Some(batch_hash), Some(expected_hash)) => {
                tracing::debug!(
                    "Received CFHeaders batch: batch_start={} (hash={}), msg_prev_header={} at {}, expected_start={} (hash={}), effective_prev_height={}, stop={}, count={}",
                    batch_start_height,
                    batch_hash,
                    cf_headers.previous_filter_header,
                    prev_height,
                    self.current_sync_height,
                    expected_hash,
                    effective_prev_height,
                    stop_height,
                    cf_headers.filter_hashes.len()
                );
            }
            (None, Some(expected_hash)) => {
                tracing::debug!(
                    "Received CFHeaders batch: batch_start={} (hash=<not stored>), msg_prev_header={} at {}, expected_start={} (hash={}), effective_prev_height={}, stop={}, count={}",
                    batch_start_height,
                    cf_headers.previous_filter_header,
                    prev_height,
                    self.current_sync_height,
                    expected_hash,
                    effective_prev_height,
                    stop_height,
                    cf_headers.filter_hashes.len()
                );
            }
            (Some(batch_hash), None) => {
                tracing::debug!(
                    "Received CFHeaders batch: batch_start={} (hash={}), msg_prev_header={} at {}, expected_start={} (hash=<unknown>), effective_prev_height={}, stop={}, count={}",
                    batch_start_height,
                    batch_hash,
                    cf_headers.previous_filter_header,
                    prev_height,
                    self.current_sync_height,
                    effective_prev_height,
                    stop_height,
                    cf_headers.filter_hashes.len()
                );
            }
            (None, None) => {
                tracing::debug!(
                    "Received CFHeaders batch: batch_start={} (hash=<not stored>), msg_prev_header={} at {}, expected_start={} (hash=<unknown>), effective_prev_height={}, stop={}, count={}",
                    batch_start_height,
                    cf_headers.previous_filter_header,
                    prev_height,
                    self.current_sync_height,
                    effective_prev_height,
                    stop_height,
                    cf_headers.filter_hashes.len()
                );
            }
        }

        // Check if this is the expected batch or if there's overlap
        if batch_start_height < self.current_sync_height {
            // Special-case benign overlaps around checkpoint boundaries; log at debug level
            let benign_checkpoint_overlap = self.sync_base_height > 0
                && ((batch_start_height + 1 == self.sync_base_height
                    && self.current_sync_height == self.sync_base_height)
                    || (batch_start_height == self.sync_base_height
                        && self.current_sync_height == self.sync_base_height + 1));

            // Try to include the peer address for diagnostics
            let peer_addr = network.get_last_message_peer_addr().await;
            if benign_checkpoint_overlap {
                match peer_addr {
                    Some(addr) => {
                        tracing::debug!(
                            "📋 Benign checkpoint overlap from {}: expected start={}, received start={}",
                            addr,
                            self.current_sync_height,
                            batch_start_height
                        );
                    }
                    None => {
                        tracing::debug!(
                            "📋 Benign checkpoint overlap: expected start={}, received start={}",
                            self.current_sync_height,
                            batch_start_height
                        );
                    }
                }
            } else {
                match peer_addr {
                    Some(addr) => {
                        tracing::warn!(
                            "📋 Received overlapping filter headers from {}: expected start={}, received start={} (likely from recovery/retry)",
                            addr,
                            self.current_sync_height,
                            batch_start_height
                        );
                    }
                    None => {
                        tracing::warn!(
                            "📋 Received overlapping filter headers: expected start={}, received start={} (likely from recovery/retry)",
                            self.current_sync_height,
                            batch_start_height
                        );
                    }
                }
            }

            // Handle overlapping headers using the helper method
            let (new_headers_stored, new_current_height) = self
                .handle_overlapping_headers(&cf_headers, self.current_sync_height, storage)
                .await?;
            self.current_sync_height = new_current_height;

            // Only record progress if we actually stored new headers
            if new_headers_stored > 0 {
                self.last_sync_progress = std::time::Instant::now();
            }
        } else if batch_start_height > self.current_sync_height {
            // Gap in the sequence - this shouldn't happen in normal operation
            tracing::error!(
                "❌ Gap detected in filter header sequence: expected start={}, received start={} (gap of {} headers)",
                self.current_sync_height,
                batch_start_height,
                batch_start_height - self.current_sync_height
            );
            return Err(SyncError::Validation(format!(
                "Gap in filter header sequence: expected {}, got {}",
                self.current_sync_height, batch_start_height
            )));
        } else {
            // This is the expected batch - process it
            match self.verify_filter_header_chain(&cf_headers, batch_start_height, storage).await {
                Ok(true) => {
                    tracing::debug!(
                        "✅ Filter header chain verification successful for batch {}-{}",
                        batch_start_height,
                        stop_height
                    );

                    // Store the verified filter headers
                    self.store_filter_headers(cf_headers.clone(), storage).await?;

                    // Update current height and record progress
                    self.current_sync_height = stop_height + 1;
                    self.last_sync_progress = std::time::Instant::now();

                    // Check if we've reached the header tip
                    if stop_height >= header_tip_height {
                        // Perform stability check before declaring completion
                        if let Ok(is_stable) = self.check_filter_header_stability(storage).await {
                            if is_stable {
                                tracing::info!(
                                    "🎯 Filter header sync complete at height {} (stability confirmed)",
                                    stop_height
                                );
                                self.syncing_filter_headers = false;
                                return Ok(false);
                            } else {
                                tracing::debug!(
                                    "Filter header sync reached tip at height {} but stability check failed, continuing sync",
                                    stop_height
                                );
                            }
                        } else {
                            tracing::debug!(
                                "Filter header sync reached tip at height {} but stability check errored, continuing sync",
                                stop_height
                            );
                        }
                    }

                    // Check if our next sync height would exceed the header tip
                    if self.current_sync_height > header_tip_height {
                        tracing::info!(
                            "Filter header sync complete - current sync height {} exceeds header tip {}",
                            self.current_sync_height,
                            header_tip_height
                        );
                        self.syncing_filter_headers = false;
                        return Ok(false);
                    }

                    // Request next batch
                    let next_batch_end_height =
                        (self.current_sync_height + FILTER_BATCH_SIZE - 1).min(header_tip_height);
                    tracing::debug!(
                        "Calculated next batch end height: {} (current: {}, tip: {})",
                        next_batch_end_height,
                        self.current_sync_height,
                        header_tip_height
                    );

                    let stop_hash = if next_batch_end_height < header_tip_height {
                        // Try to get the header at the calculated height
                        match storage.get_header(next_batch_end_height).await {
                            Ok(Some(header)) => header.block_hash(),
                            Ok(None) => {
                                tracing::warn!(
                                    "Header not found at blockchain height {}, scanning backwards to find actual available height",
                                    next_batch_end_height
                                );

                                let min_height = self.current_sync_height; // Don't go below where we are
                                match self
                                    .find_available_header_at_or_before(
                                        next_batch_end_height.saturating_sub(1),
                                        min_height,
                                        storage,
                                    )
                                    .await
                                {
                                    Some((hash, height)) => {
                                        if height < self.current_sync_height {
                                            tracing::warn!(
                                                "Found header at height {} which is less than current sync height {}. This means we already have filter headers up to {}. Marking sync as complete.",
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
                                            "No available headers found between {} and {} - storage appears to have gaps",
                                            min_height,
                                            next_batch_end_height
                                        );
                                        tracing::error!(
                                            "This indicates a serious storage inconsistency. Stopping filter header sync."
                                        );
                                        self.syncing_filter_headers = false;
                                        return Err(SyncError::Storage(format!(
                                            "No available headers found between {} and {} while selecting next batch stop hash",
                                            min_height,
                                            next_batch_end_height
                                        )));
                                    }
                                }
                            }
                            Err(e) => {
                                return Err(SyncError::Storage(format!(
                                    "Failed to get next batch stop header at height {}: {}",
                                    next_batch_end_height, e
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
                                    "Tip header not found at blockchain height {}, trying previous header",
                                    header_tip_height
                                );
                                // Try previous header when at chain tip
                                match storage.get_header(header_tip_height - 1).await {
                                    Ok(Some(header)) => header.block_hash(),
                                    _ => {
                                        tracing::warn!(
                                            "⚠️ No header found at tip or tip-1 during CFHeaders handling"
                                        );
                                        return Err(SyncError::Validation(
                                            "No header found at tip or tip-1".to_string(),
                                        ));
                                    }
                                }
                            }
                            _ => {
                                return Err(SyncError::Validation(
                                    "No header found at computed end height".to_string(),
                                ));
                            }
                        }
                    };

                    self.request_filter_headers(network, self.current_sync_height, stop_hash)
                        .await?;
                }
                Ok(false) => {
                    tracing::warn!(
                        "⚠️ Filter header chain verification failed for batch {}-{}",
                        batch_start_height,
                        stop_height
                    );
                    return Err(SyncError::Validation(
                        "Filter header chain verification failed".to_string(),
                    ));
                }
                Err(e) => {
                    tracing::error!("❌ Filter header chain verification failed: {}", e);
                    return Err(e);
                }
            }
        }

        Ok(true)
    }
    pub async fn start_sync_headers(
        &mut self,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<bool> {
        if self.syncing_filter_headers {
            return Err(SyncError::SyncInProgress);
        }

        // Check if any connected peer supports compact filters
        if !network
            .has_peer_with_service(dashcore::network::constants::ServiceFlags::COMPACT_FILTERS)
            .await
        {
            tracing::warn!(
                "⚠️  No connected peers support compact filters (BIP 157/158). Skipping filter synchronization."
            );
            tracing::warn!(
                "⚠️  To enable filter sync, connect to peers that advertise NODE_COMPACT_FILTERS service bit."
            );
            return Ok(false); // No sync started
        }

        tracing::info!("🚀 Starting filter header synchronization");
        tracing::debug!("FilterSync start: sync_base_height={}", self.sync_base_height);

        // Get current filter tip
        let current_filter_height = storage
            .get_filter_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get filter tip height: {}", e)))?
            .unwrap_or(0);

        // Get header tip (absolute blockchain height)
        let header_tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get header tip height: {}", e)))?
            .ok_or_else(|| {
                SyncError::Storage("No headers available for filter sync".to_string())
            })?;
        tracing::debug!(
            "FilterSync context: header_tip_height={} (base={})",
            header_tip_height,
            self.sync_base_height
        );

        if current_filter_height >= header_tip_height {
            tracing::info!("Filter headers already synced to header tip");
            return Ok(false); // Already synced
        }

        // Determine next height to request
        // In checkpoint sync, request from the checkpoint height itself. CFHeaders includes
        // previous_filter_header for (start_height - 1), so we can compute the chain from the
        // checkpoint and store its filter header as the first element.
        let next_height =
            if self.sync_base_height > 0 && current_filter_height < self.sync_base_height {
                tracing::info!(
                    "Starting filter sync from checkpoint base {} (current filter height: {})",
                    self.sync_base_height,
                    current_filter_height
                );
                self.sync_base_height
            } else {
                current_filter_height + 1
            };
        tracing::debug!(
            "FilterSync plan: next_height={}, current_filter_height={}, header_tip_height={}",
            next_height,
            current_filter_height,
            header_tip_height
        );

        if next_height > header_tip_height {
            tracing::warn!(
                "Filter sync requested but next height {} > header tip {}, nothing to sync",
                next_height,
                header_tip_height
            );
            return Ok(false);
        }

        // Set up sync state
        self.syncing_filter_headers = true;
        self.current_sync_height = next_height;
        self.last_sync_progress = std::time::Instant::now();

        // Get the stop hash (tip of headers)
        let stop_hash = storage
            .get_header(header_tip_height)
            .await
            .map_err(|e| {
                SyncError::Storage(format!(
                    "Failed to get stop header at blockchain height {}: {}",
                    header_tip_height, e
                ))
            })?
            .ok_or_else(|| {
                SyncError::Storage(format!(
                    "Stop header not found at blockchain height {}",
                    header_tip_height
                ))
            })?
            .block_hash();

        // Initial request for first batch
        let batch_end_height =
            (self.current_sync_height + FILTER_BATCH_SIZE - 1).min(header_tip_height);

        tracing::debug!(
            "Requesting filter headers batch: start={}, end={}, count={} (base={})",
            self.current_sync_height,
            batch_end_height,
            batch_end_height - self.current_sync_height + 1,
            self.sync_base_height
        );

        // Get the hash at batch_end_height for the stop_hash
        let batch_stop_hash = if batch_end_height < header_tip_height {
            // Try to get the header at the calculated height with fallback
            match storage.get_header(batch_end_height).await {
                Ok(Some(header)) => {
                    tracing::debug!(
                        "Found header for batch stop at blockchain height {}, hash={}",
                        batch_end_height,
                        header.block_hash()
                    );
                    header.block_hash()
                }
                Ok(None) => {
                    tracing::warn!(
                        "Initial batch header not found at blockchain height {}, scanning for available header",
                        batch_end_height
                    );

                    match self
                        .find_available_header_at_or_before(
                            batch_end_height,
                            self.current_sync_height,
                            storage,
                        )
                        .await
                    {
                        Some((hash, _height)) => hash,
                        None => {
                            // If we can't find any headers in the batch range, something is wrong
                            // Don't fall back to tip as that would create an oversized request
                            let start_idx =
                                self.header_abs_to_storage_index(self.current_sync_height);
                            let end_idx = self.header_abs_to_storage_index(batch_end_height);
                            return Err(SyncError::Storage(format!(
                                "No headers found in batch range {} to {} (header storage idx {:?} to {:?})",
                                self.current_sync_height,
                                batch_end_height,
                                start_idx,
                                end_idx
                            )));
                        }
                    }
                }
                Err(e) => {
                    return Err(SyncError::Validation(format!(
                        "Failed to get initial batch stop header at height {}: {}",
                        batch_end_height, e
                    )));
                }
            }
        } else {
            stop_hash
        };

        self.request_filter_headers(network, self.current_sync_height, batch_stop_hash).await?;

        Ok(true) // Sync started
    }

    pub async fn request_filter_headers(
        &mut self,
        network: &mut N,
        start_height: u32,
        stop_hash: BlockHash,
    ) -> SyncResult<()> {
        // Validation: ensure this is a valid request
        // Note: We can't easily get the stop height here without storage access,
        // but we can at least check obvious invalid cases
        if start_height == 0 {
            tracing::error!("Invalid filter header request: start_height cannot be 0");
            return Err(SyncError::Validation(
                "Invalid start_height 0 for filter headers".to_string(),
            ));
        }

        tracing::debug!(
            "Sending GetCFHeaders: start_height={}, stop_hash={}, base_height={} (header storage idx {:?}, filter storage idx {:?})",
            start_height,
            stop_hash,
            self.sync_base_height,
            self.header_abs_to_storage_index(start_height),
            self.filter_abs_to_storage_index(start_height)
        );

        let get_cf_headers = GetCFHeaders {
            filter_type: 0, // Basic filter type
            start_height,
            stop_hash,
        };

        network
            .send_message(NetworkMessage::GetCFHeaders(get_cf_headers))
            .await
            .map_err(|e| SyncError::Network(format!("Failed to send GetCFHeaders: {}", e)))?;

        tracing::debug!("Requested filter headers from height {} to {}", start_height, stop_hash);

        Ok(())
    }

    /// Start synchronizing filter headers with flow control for parallel requests.
    pub async fn start_sync_headers_with_flow_control(
        &mut self,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<bool> {
        if self.syncing_filter_headers {
            return Err(SyncError::SyncInProgress);
        }

        // Check if any connected peer supports compact filters
        if !network
            .has_peer_with_service(dashcore::network::constants::ServiceFlags::COMPACT_FILTERS)
            .await
        {
            tracing::warn!(
                "⚠️  No connected peers support compact filters (BIP 157/158). Skipping filter synchronization."
            );
            return Ok(false); // No sync started
        }

        tracing::info!("🚀 Starting filter header synchronization with flow control");

        // Get current filter tip
        let current_filter_height = storage
            .get_filter_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get filter tip height: {}", e)))?
            .unwrap_or(0);

        // Get header tip (absolute blockchain height)
        let header_tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get header tip height: {}", e)))?
            .ok_or_else(|| {
                SyncError::Storage("No headers available for filter sync".to_string())
            })?;

        if current_filter_height >= header_tip_height {
            tracing::info!("Filter headers already synced to header tip");
            return Ok(false); // Already synced
        }

        // Determine next height to request
        let next_height =
            if self.sync_base_height > 0 && current_filter_height < self.sync_base_height {
                tracing::info!(
                    "Starting filter sync from checkpoint base {} (current filter height: {})",
                    self.sync_base_height,
                    current_filter_height
                );
                self.sync_base_height
            } else {
                current_filter_height + 1
            };

        if next_height > header_tip_height {
            tracing::warn!(
                "Filter sync requested but next height {} > header tip {}, nothing to sync",
                next_height,
                header_tip_height
            );
            return Ok(false);
        }

        // Set up flow control state
        self.syncing_filter_headers = true;
        self.current_sync_height = next_height;
        self.next_cfheader_height_to_process = next_height;
        self.last_sync_progress = std::time::Instant::now();

        // Build request queue
        self.build_cfheader_request_queue(storage, next_height, header_tip_height).await?;

        // Send initial batch of requests
        self.process_cfheader_request_queue(network).await?;

        tracing::info!(
            "✅ CFHeaders flow control initiated ({} requests queued, {} active)",
            self.pending_cfheader_requests.len(),
            self.active_cfheader_requests.len()
        );

        Ok(true)
    }

    /// Build queue of CFHeaders requests from the specified range.
    async fn build_cfheader_request_queue(
        &mut self,
        storage: &S,
        start_height: u32,
        end_height: u32,
    ) -> SyncResult<()> {
        // Clear any existing queue
        self.pending_cfheader_requests.clear();
        self.active_cfheader_requests.clear();
        self.cfheader_retry_counts.clear();
        self.received_cfheader_batches.clear();

        tracing::info!(
            "🔄 Building CFHeaders request queue from height {} to {} ({} blocks)",
            start_height,
            end_height,
            end_height - start_height + 1
        );

        // Build requests in batches of FILTER_BATCH_SIZE (1999)
        let mut current_height = start_height;

        while current_height <= end_height {
            let batch_end = (current_height + FILTER_BATCH_SIZE - 1).min(end_height);

            // Get stop_hash for this batch
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

            // Create CFHeaders request and add to queue
            let request = CFHeaderRequest {
                start_height: current_height,
                stop_hash,
                is_retry: false,
            };

            self.pending_cfheader_requests.push_back(request);

            tracing::debug!(
                "Queued CFHeaders request for heights {} to {} (stop_hash: {})",
                current_height,
                batch_end,
                stop_hash
            );

            current_height = batch_end + 1;
        }

        tracing::info!(
            "📋 CFHeaders request queue built with {} batches",
            self.pending_cfheader_requests.len()
        );

        Ok(())
    }

    /// Process the CFHeaders request queue with flow control.
    async fn process_cfheader_request_queue(&mut self, network: &mut N) -> SyncResult<()> {
        // Send initial batch up to max_concurrent_cfheader_requests
        let initial_send_count =
            self.max_concurrent_cfheader_requests.min(self.pending_cfheader_requests.len());

        for _ in 0..initial_send_count {
            if let Some(request) = self.pending_cfheader_requests.pop_front() {
                self.send_cfheader_request(network, request).await?;
            }
        }

        tracing::info!(
            "🚀 Sent initial batch of {} CFHeaders requests ({} queued, {} active)",
            initial_send_count,
            self.pending_cfheader_requests.len(),
            self.active_cfheader_requests.len()
        );

        Ok(())
    }

    /// Send a single CFHeaders request and track it as active.
    async fn send_cfheader_request(
        &mut self,
        network: &mut N,
        request: CFHeaderRequest,
    ) -> SyncResult<()> {
        // Send the actual network request
        self.request_filter_headers(network, request.start_height, request.stop_hash).await?;

        // Track this request as active
        let active_request = ActiveCFHeaderRequest {
            sent_time: std::time::Instant::now(),
            stop_hash: request.stop_hash,
        };

        self.active_cfheader_requests.insert(request.start_height, active_request);

        tracing::debug!(
            "📡 Sent CFHeaders request for height {} (stop_hash: {}, now {} active)",
            request.start_height,
            request.stop_hash,
            self.active_cfheader_requests.len()
        );

        Ok(())
    }

    /// Handle CFHeaders message with flow control (buffering and sequential processing).
    async fn handle_cfheaders_with_flow_control(
        &mut self,
        cf_headers: CFHeaders,
        storage: &mut S,
        network: &mut N,
    ) -> SyncResult<bool> {
        // Handle empty response - indicates end of sync
        if cf_headers.filter_hashes.is_empty() {
            tracing::info!("Received empty CFHeaders response - sync complete");
            self.syncing_filter_headers = false;
            self.clear_cfheader_flow_control_state();
            return Ok(false);
        }

        // Get the height range for this batch
        let (batch_start_height, stop_height, _header_tip_height) =
            self.get_batch_height_range(&cf_headers, storage).await?;

        tracing::debug!(
            "Received CFHeaders batch: start={}, stop={}, count={}, next_expected={}",
            batch_start_height,
            stop_height,
            cf_headers.filter_hashes.len(),
            self.next_cfheader_height_to_process
        );

        // Mark this request as complete in active tracking
        self.active_cfheader_requests.remove(&batch_start_height);

        // Check if this is the next expected batch
        if batch_start_height == self.next_cfheader_height_to_process {
            // Process this batch immediately
            tracing::debug!("Processing expected batch at height {}", batch_start_height);
            self.process_cfheader_batch(cf_headers, storage, network).await?;

            // Try to process any buffered batches that are now in sequence
            self.process_buffered_cfheader_batches(storage, network).await?;
        } else if batch_start_height > self.next_cfheader_height_to_process {
            // Out of order - buffer for later
            tracing::debug!(
                "Buffering out-of-order batch at height {} (expected {})",
                batch_start_height,
                self.next_cfheader_height_to_process
            );

            let batch = ReceivedCFHeaderBatch {
                cfheaders: cf_headers,
                received_at: std::time::Instant::now(),
            };

            self.received_cfheader_batches.insert(batch_start_height, batch);
        } else {
            // Already processed - likely a duplicate or retry
            tracing::debug!(
                "Ignoring already-processed batch at height {} (current expected: {})",
                batch_start_height,
                self.next_cfheader_height_to_process
            );
        }

        // Send next queued requests to fill available slots
        self.process_next_queued_cfheader_requests(network).await?;

        // Check if sync is complete
        if self.is_cfheader_sync_complete(storage).await? {
            tracing::info!("✅ CFHeaders sync complete!");
            self.syncing_filter_headers = false;
            self.clear_cfheader_flow_control_state();
            return Ok(false);
        }

        Ok(true)
    }

    /// Process a single CFHeaders batch (extracted from original handle_cfheaders logic).
    async fn process_cfheader_batch(
        &mut self,
        cf_headers: CFHeaders,
        storage: &mut S,
        _network: &mut N,
    ) -> SyncResult<()> {
        let (batch_start_height, stop_height, _header_tip_height) =
            self.get_batch_height_range(&cf_headers, storage).await?;

        // Verify and process the batch
        match self.verify_filter_header_chain(&cf_headers, batch_start_height, storage).await {
            Ok(true) => {
                tracing::debug!(
                    "✅ Filter header chain verification successful for batch {}-{}",
                    batch_start_height,
                    stop_height
                );

                // Store the verified filter headers
                self.store_filter_headers(cf_headers.clone(), storage).await?;

                // Update next expected height
                self.next_cfheader_height_to_process = stop_height + 1;
                self.current_sync_height = stop_height + 1;
                self.last_sync_progress = std::time::Instant::now();

                tracing::debug!(
                    "Updated next expected height to {}, batch processed successfully",
                    self.next_cfheader_height_to_process
                );
            }
            Ok(false) => {
                tracing::warn!(
                    "⚠️ Filter header chain verification failed for batch {}-{}",
                    batch_start_height,
                    stop_height
                );
                return Err(SyncError::Validation(
                    "Filter header chain verification failed".to_string(),
                ));
            }
            Err(e) => {
                tracing::error!("❌ Filter header chain verification failed: {}", e);
                return Err(e);
            }
        }

        Ok(())
    }

    /// Process buffered CFHeaders batches that are now in sequence.
    async fn process_buffered_cfheader_batches(
        &mut self,
        storage: &mut S,
        network: &mut N,
    ) -> SyncResult<()> {
        while let Some(batch) =
            self.received_cfheader_batches.remove(&self.next_cfheader_height_to_process)
        {
            tracing::debug!(
                "Processing buffered batch at height {}",
                self.next_cfheader_height_to_process
            );

            self.process_cfheader_batch(batch.cfheaders, storage, network).await?;
        }

        Ok(())
    }

    /// Process next requests from the queue when active requests complete.
    pub(super) async fn process_next_queued_cfheader_requests(
        &mut self,
        network: &mut N,
    ) -> SyncResult<()> {
        let available_slots = self
            .max_concurrent_cfheader_requests
            .saturating_sub(self.active_cfheader_requests.len());

        let mut sent_count = 0;
        for _ in 0..available_slots {
            if let Some(request) = self.pending_cfheader_requests.pop_front() {
                self.send_cfheader_request(network, request).await?;
                sent_count += 1;
            } else {
                break;
            }
        }

        if sent_count > 0 {
            tracing::debug!(
                "🚀 Sent {} additional CFHeaders requests from queue ({} queued, {} active)",
                sent_count,
                self.pending_cfheader_requests.len(),
                self.active_cfheader_requests.len()
            );
        }

        Ok(())
    }

    /// Check if CFHeaders sync is complete.
    async fn is_cfheader_sync_complete(&self, storage: &S) -> SyncResult<bool> {
        // Sync is complete if:
        // 1. No pending requests
        // 2. No active requests
        // 3. No buffered batches
        // 4. Current height >= header tip

        if !self.pending_cfheader_requests.is_empty() {
            return Ok(false);
        }

        if !self.active_cfheader_requests.is_empty() {
            return Ok(false);
        }

        if !self.received_cfheader_batches.is_empty() {
            return Ok(false);
        }

        let header_tip = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get header tip: {}", e)))?
            .unwrap_or(0);

        Ok(self.next_cfheader_height_to_process > header_tip)
    }

    /// Clear flow control state.
    fn clear_cfheader_flow_control_state(&mut self) {
        self.pending_cfheader_requests.clear();
        self.active_cfheader_requests.clear();
        self.cfheader_retry_counts.clear();
        self.received_cfheader_batches.clear();
    }

    pub(super) async fn handle_overlapping_headers(
        &self,
        cf_headers: &CFHeaders,
        expected_start_height: u32,
        storage: &mut S,
    ) -> SyncResult<(usize, u32)> {
        // Get the height range for this batch
        let (batch_start_height, stop_height, _header_tip_height) =
            self.get_batch_height_range(cf_headers, storage).await?;
        let skip_count = expected_start_height.saturating_sub(batch_start_height) as usize;

        // Complete overlap case - all headers already processed
        if skip_count >= cf_headers.filter_hashes.len() {
            tracing::info!(
                "✅ All {} headers in batch already processed, skipping",
                cf_headers.filter_hashes.len()
            );
            return Ok((0, expected_start_height));
        }

        // Find connection point in our chain
        let current_filter_tip = storage
            .get_filter_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get filter tip: {}", e)))?
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

        let connection_height = match connection_height {
            Some(height) => height,
            None => {
                // Special-case: checkpoint overlap where peer starts at checkpoint height
                // and we expect to start at checkpoint+1. We don't store the checkpoint's
                // filter header in storage, but CFHeaders provides previous_filter_header
                // for (checkpoint-1), allowing us to compute from checkpoint onward and skip one.
                if self.sync_base_height > 0
                    && (
                        // Case A: peer starts at checkpoint, we expect checkpoint+1
                        (batch_start_height == self.sync_base_height
                            && expected_start_height == self.sync_base_height + 1)
                            ||
                        // Case B: peer starts one before checkpoint, we expect checkpoint
                        (batch_start_height + 1 == self.sync_base_height
                            && expected_start_height == self.sync_base_height)
                    )
                {
                    tracing::debug!(
                        "Overlap at checkpoint: synthesizing connection at height {}",
                        self.sync_base_height - 1
                    );
                    self.sync_base_height - 1
                } else {
                    // No connection found - check if this is overlapping data we can safely ignore
                    let overlap_end = expected_start_height.saturating_sub(1);
                    if batch_start_height <= overlap_end && overlap_end <= current_filter_tip {
                        tracing::warn!(
                            "📋 Ignoring overlapping headers from different peer view (range {}-{})",
                            batch_start_height,
                            stop_height
                        );
                        return Ok((0, expected_start_height));
                    } else {
                        return Err(SyncError::Validation(
                            "Cannot find connection point for overlapping headers".to_string(),
                        ));
                    }
                }
            }
        };

        // Process all filter headers from the connection point
        let batch_start_height = connection_height + 1;
        let all_filter_headers =
            self.process_filter_headers(cf_headers, batch_start_height, storage).await?;

        // Extract only the new headers we need
        let headers_to_skip = expected_start_height.saturating_sub(batch_start_height) as usize;
        if headers_to_skip >= all_filter_headers.len() {
            return Ok((0, expected_start_height));
        }

        let new_filter_headers = all_filter_headers[headers_to_skip..].to_vec();

        if !new_filter_headers.is_empty() {
            storage.store_filter_headers(&new_filter_headers).await.map_err(|e| {
                SyncError::Storage(format!("Failed to store filter headers: {}", e))
            })?;

            tracing::info!(
                "✅ Stored {} new filter headers (skipped {} overlapping)",
                new_filter_headers.len(),
                headers_to_skip
            );

            let new_current_height = expected_start_height + new_filter_headers.len() as u32;
            Ok((new_filter_headers.len(), new_current_height))
        } else {
            Ok((0, expected_start_height))
        }
    }

    /// Verify filter header chain connects to our local chain.
    /// This is a simplified version focused only on cryptographic chain verification,
    /// with overlap detection handled by the dedicated overlap resolution system.
    pub(super) async fn verify_filter_header_chain(
        &self,
        cf_headers: &CFHeaders,
        start_height: u32,
        storage: &S,
    ) -> SyncResult<bool> {
        if cf_headers.filter_hashes.is_empty() {
            return Ok(true);
        }

        // Skip verification for the first batch when starting from genesis or around checkpoint
        // - Genesis sync: start_height == 1 (we don't have genesis filter header)
        // - Checkpoint sync (expected first batch): start_height == sync_base_height + 1
        // - Checkpoint overlap batch: start_height == sync_base_height (peer included one extra)
        if start_height <= 1
            || (self.sync_base_height > 0
                && (start_height == self.sync_base_height
                    || start_height == self.sync_base_height + 1))
        {
            tracing::debug!(
                "Skipping filter header chain verification for first batch (start_height={}, sync_base_height={})",
                start_height,
                self.sync_base_height
            );
            return Ok(true);
        }

        // Safety check to prevent underflow
        if start_height == 0 {
            tracing::error!(
                "Invalid start_height=0 in filter header verification - this should never happen"
            );
            return Err(SyncError::Validation(
                "Invalid start_height=0 in filter header verification".to_string(),
            ));
        }

        // Get the expected previous filter header from our local chain
        let prev_height = start_height - 1;
        tracing::debug!(
            "Verifying filter header chain: start_height={}, prev_height={}",
            start_height,
            prev_height
        );

        let expected_prev_header = storage
            .get_filter_header(prev_height)
            .await
            .map_err(|e| {
                SyncError::Storage(format!(
                    "Failed to get previous filter header at height {}: {}",
                    prev_height, e
                ))
            })?
            .ok_or_else(|| {
                SyncError::Storage(format!(
                    "Missing previous filter header at height {}",
                    prev_height
                ))
            })?;

        // Simple chain continuity check - the received headers should connect to our expected previous header
        if cf_headers.previous_filter_header != expected_prev_header {
            tracing::error!(
                "Filter header chain verification failed: received previous_filter_header {:?} doesn't match expected header {:?} at height {}",
                cf_headers.previous_filter_header,
                expected_prev_header,
                prev_height
            );
            return Ok(false);
        }

        tracing::trace!(
            "Filter header chain verification passed for {} headers",
            cf_headers.filter_hashes.len()
        );
        Ok(true)
    }

    async fn check_filter_header_stability(&mut self, storage: &S) -> SyncResult<bool> {
        let current_filter_tip = storage
            .get_filter_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get filter tip height: {}", e)))?;

        let now = std::time::Instant::now();

        // Check if the tip height has changed since last check
        if self.last_filter_tip_height != current_filter_tip {
            // Tip height changed, reset stability timer
            self.last_filter_tip_height = current_filter_tip;
            self.last_stability_check = now;
            tracing::debug!(
                "Filter tip height changed to {:?}, resetting stability timer",
                current_filter_tip
            );
            return Ok(false);
        }

        // Check if enough time has passed since last change
        const STABILITY_DURATION: std::time::Duration = std::time::Duration::from_secs(3);
        if now.duration_since(self.last_stability_check) >= STABILITY_DURATION {
            tracing::debug!(
                "Filter header sync stability confirmed (tip height {:?} stable for 3+ seconds)",
                current_filter_tip
            );
            return Ok(true);
        }

        tracing::debug!(
            "Filter header sync stability check: waiting for tip height {:?} to stabilize",
            current_filter_tip
        );
        Ok(false)
    }
}
