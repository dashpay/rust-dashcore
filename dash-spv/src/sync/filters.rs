//! Filter synchronization functionality.

use dashcore::{
    bip158::{BlockFilter, BlockFilterReader, Error as Bip158Error},
    hash_types::FilterHeader,
    network::message::NetworkMessage,
    network::message_blockdata::Inventory,
    network::message_filter::{CFHeaders, GetCFHeaders, GetCFilters},
    BlockHash, ScriptBuf,
};
use dashcore_hashes::{sha256d, Hash};
use std::collections::{HashMap, HashSet, VecDeque};
use tokio::sync::mpsc;

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::types::{SharedFilterHeights, SyncProgress};

// Constants for filter synchronization
// Stay under Dash Core's 2000 limit (for CFHeaders). Using 1999 helps reduce accidental overlaps.
const FILTER_BATCH_SIZE: u32 = 1999;
const SYNC_TIMEOUT_SECONDS: u64 = 5;
const DEFAULT_FILTER_SYNC_RANGE: u32 = 100;
const FILTER_REQUEST_BATCH_SIZE: u32 = 100; // For compact filter requests (CFilters)
const MAX_FILTER_REQUEST_SIZE: u32 = 1000; // Maximum filters per CFilter request (Dash Core limit)

// Flow control constants
const MAX_CONCURRENT_FILTER_REQUESTS: usize = 50; // Maximum concurrent filter batches (increased for better performance)
const FILTER_RETRY_DELAY_MS: u64 = 100; // Delay for retry requests to avoid hammering peers
const REQUEST_TIMEOUT_SECONDS: u64 = 30; // Timeout for individual requests

/// Handle for sending CFilter messages to the processing thread.
pub type FilterNotificationSender =
    mpsc::UnboundedSender<dashcore::network::message_filter::CFilter>;

/// Represents a filter request to be sent or queued.
#[derive(Debug, Clone)]
struct FilterRequest {
    start_height: u32,
    end_height: u32,
    stop_hash: BlockHash,
    is_retry: bool,
}

/// Represents an active filter request that has been sent and is awaiting response.
#[derive(Debug)]
struct ActiveRequest {
    sent_time: std::time::Instant,
}

/// Manages BIP157 filter synchronization.
pub struct FilterSyncManager<S: StorageManager, N: NetworkManager> {
    _phantom_s: std::marker::PhantomData<S>,
    _phantom_n: std::marker::PhantomData<N>,
    _config: ClientConfig,
    /// Whether filter header sync is currently in progress
    syncing_filter_headers: bool,
    /// Current height being synced for filter headers
    current_sync_height: u32,
    /// Base height for sync (typically from checkpoint)
    sync_base_height: u32,
    /// Last time sync progress was made (for timeout detection)
    last_sync_progress: std::time::Instant,
    /// Last time filter header tip height was checked for stability
    last_stability_check: std::time::Instant,
    /// Filter tip height from last stability check
    last_filter_tip_height: Option<u32>,
    /// Whether filter sync is currently in progress
    pub syncing_filters: bool,
    /// Queue of blocks that have been requested and are waiting for response
    pending_block_downloads: VecDeque<crate::types::FilterMatch>,
    /// Blocks currently being downloaded (map for quick lookup)
    downloading_blocks: HashMap<BlockHash, u32>,
    /// Blocks requested by the filter processing thread
    pub processing_thread_requests: std::sync::Arc<tokio::sync::Mutex<HashSet<BlockHash>>>,
    /// Track requested filter ranges: (start_height, end_height) -> request_time
    requested_filter_ranges: HashMap<(u32, u32), std::time::Instant>,
    /// Track individual filter heights that have been received (shared with stats)
    received_filter_heights: SharedFilterHeights,
    /// Maximum retries for a filter range
    max_filter_retries: u32,
    /// Retry attempts per range
    filter_retry_counts: HashMap<(u32, u32), u32>,
    /// Queue of pending filter requests
    pending_filter_requests: VecDeque<FilterRequest>,
    /// Currently active filter requests (limited by MAX_CONCURRENT_FILTER_REQUESTS)
    active_filter_requests: HashMap<(u32, u32), ActiveRequest>,
    /// Whether flow control is enabled
    flow_control_enabled: bool,
    /// Last time we detected a gap and attempted restart
    last_gap_restart_attempt: Option<std::time::Instant>,
    /// Minimum time between gap restart attempts (to prevent spam)
    gap_restart_cooldown: std::time::Duration,
    /// Number of consecutive gap restart failures
    gap_restart_failure_count: u32,
    /// Maximum gap restart attempts before giving up
    max_gap_restart_attempts: u32,
}

impl<S: StorageManager + Send + Sync + 'static, N: NetworkManager + Send + Sync + 'static>
    FilterSyncManager<S, N>
{
    /// Verify that the received compact filter hashes to the expected filter header
    /// based on previously synchronized CFHeaders.
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

        // Load previous and expected headers
        let prev_header = storage.get_filter_header(height - 1).await.map_err(|e| {
            SyncError::Storage(format!("Failed to load previous filter header: {}", e))
        })?;
        let expected_header = storage.get_filter_header(height).await.map_err(|e| {
            SyncError::Storage(format!("Failed to load expected filter header: {}", e))
        })?;

        let (Some(prev_header), Some(expected_header)) = (prev_header, expected_header) else {
            tracing::warn!(
                "Missing filter headers in storage for height {} (prev and/or expected)",
                height
            );
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
    /// Returns the found `(BlockHash, height)` or `None` if none available.
    async fn find_available_header_at_or_before(
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
            let Some(scan_storage_height) = self.header_abs_to_storage_index(scan_height) else {
                tracing::debug!(
                    "Storage index not available for blockchain height {} while scanning (min={})",
                    scan_height,
                    min_abs_height
                );
                break;
            };

            match storage.get_header(scan_storage_height).await {
                Ok(Some(header)) => {
                    tracing::info!(
                        "Found available header at blockchain height {} / storage height {}",
                        scan_height,
                        scan_storage_height
                    );
                    return Some((header.block_hash(), scan_height));
                }
                Ok(None) => {
                    tracing::debug!(
                        "Header missing at blockchain height {} / storage height {}, scanning back",
                        scan_height,
                        scan_storage_height
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "Error reading header at blockchain height {} / storage height {}: {}",
                        scan_height,
                        scan_storage_height,
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
        stop_height.saturating_sub(cf_headers.filter_hashes.len() as u32 - 1)
    }

    /// Get the height range for a CFHeaders batch.
    async fn get_batch_height_range(
        &self,
        cf_headers: &CFHeaders,
        storage: &S,
    ) -> SyncResult<(u32, u32, u32)> {
        let storage_tip_index = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get header tip height: {}", e)))?
            .unwrap_or(0);

        // Convert block header storage index to absolute blockchain height
        let header_tip_height = self.header_storage_to_abs_height(storage_tip_index);

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
        let start_hash_opt = match self.header_abs_to_storage_index(start_height) {
            Some(idx) => storage.get_header(idx).await.ok().flatten().map(|h| h.block_hash()),
            None => None,
        };

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

    /// Create a new filter sync manager.
    pub fn new(config: &ClientConfig, received_filter_heights: SharedFilterHeights) -> Self {
        Self {
            _config: config.clone(),
            syncing_filter_headers: false,
            current_sync_height: 0,
            sync_base_height: 0,
            last_sync_progress: std::time::Instant::now(),
            last_stability_check: std::time::Instant::now(),
            last_filter_tip_height: None,
            syncing_filters: false,
            pending_block_downloads: VecDeque::new(),
            downloading_blocks: HashMap::new(),
            processing_thread_requests: std::sync::Arc::new(tokio::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
            requested_filter_ranges: HashMap::new(),
            received_filter_heights,
            max_filter_retries: 3,
            filter_retry_counts: HashMap::new(),
            pending_filter_requests: VecDeque::new(),
            active_filter_requests: HashMap::new(),
            flow_control_enabled: true,
            last_gap_restart_attempt: None,
            gap_restart_cooldown: std::time::Duration::from_secs(
                config.cfheader_gap_restart_cooldown_secs,
            ),
            gap_restart_failure_count: 0,
            max_gap_restart_attempts: config.max_cfheader_gap_restart_attempts,
            _phantom_s: std::marker::PhantomData,
            _phantom_n: std::marker::PhantomData,
        }
    }

    /// Set the base height for sync (typically from checkpoint)
    pub fn set_sync_base_height(&mut self, height: u32) {
        self.sync_base_height = height;
    }

    /// Convert absolute blockchain height to block header storage index.
    /// Storage indexing is base-inclusive: at checkpoint base B, storage index 0 == absolute height B.
    fn header_abs_to_storage_index(&self, height: u32) -> Option<u32> {
        if self.sync_base_height > 0 {
            height.checked_sub(self.sync_base_height)
        } else {
            Some(height)
        }
    }

    /// Convert block header storage index to absolute blockchain height.
    /// Storage indexing is base-inclusive: at checkpoint base B, absolute height == B + index.
    fn header_storage_to_abs_height(&self, index: u32) -> u32 {
        if self.sync_base_height > 0 {
            self.sync_base_height + index
        } else {
            index
        }
    }

    /// Convert absolute blockchain height to filter header storage index.
    /// Storage indexing is base-inclusive for filter headers as well.
    fn filter_abs_to_storage_index(&self, height: u32) -> Option<u32> {
        if self.sync_base_height > 0 {
            height.checked_sub(self.sync_base_height)
        } else {
            Some(height)
        }
    }

    // Note: previously had filter_storage_to_abs_height, but it was unused and removed for clarity.

    /// Enable flow control for filter downloads.
    pub fn enable_flow_control(&mut self) {
        self.flow_control_enabled = true;
    }

    /// Disable flow control for filter downloads.
    pub fn disable_flow_control(&mut self) {
        self.flow_control_enabled = false;
    }

    /// Check if filter sync is available (any peer supports compact filters).
    pub async fn is_filter_sync_available(&self, network: &N) -> bool {
        network
            .has_peer_with_service(dashcore::network::constants::ServiceFlags::COMPACT_FILTERS)
            .await
    }

    /// Handle a CFHeaders message during filter header synchronization.
    /// Returns true if the message was processed and sync should continue, false if sync is complete.
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
        let recv_start_hash_opt = match self.header_abs_to_storage_index(batch_start_height) {
            Some(idx) => storage.get_header(idx).await.ok().flatten().map(|h| h.block_hash()),
            None => None,
        };

        // Resolve expected start hash (what we asked for), for clarity
        let expected_start_hash_opt =
            match self.header_abs_to_storage_index(self.current_sync_height) {
                Some(idx) => storage.get_header(idx).await.ok().flatten().map(|h| h.block_hash()),
                None => None,
            };

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
                        // Convert blockchain height to storage height
                        let storage_height = self
                            .header_abs_to_storage_index(next_batch_end_height)
                            .ok_or_else(|| {
                                SyncError::Validation(format!(
                                    "next_batch_end_height {} is at or before checkpoint base {}",
                                    next_batch_end_height, self.sync_base_height
                                ))
                            })?;
                        match storage.get_header(storage_height).await {
                            Ok(Some(header)) => header.block_hash(),
                            Ok(None) => {
                                tracing::warn!(
                                    "Header not found at storage height {} (blockchain height {}), scanning backwards to find actual available height",
                                    storage_height,
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
                        let tip_storage_height = self
                            .header_abs_to_storage_index(header_tip_height)
                            .ok_or_else(|| {
                                SyncError::Validation(format!(
                                    "header_tip_height {} below checkpoint base {}",
                                    header_tip_height, self.sync_base_height
                                ))
                            })?;
                        match storage.get_header(tip_storage_height).await {
                            Ok(Some(header)) => header.block_hash(),
                            Ok(None) if header_tip_height > 0 => {
                                tracing::debug!(
                                    "Tip header not found at storage height {} (blockchain height {}), trying previous header",
                                    tip_storage_height,
                                    header_tip_height
                                );
                                // Try previous header when at chain tip
                                let prev_storage_height = self
                                    .header_abs_to_storage_index(header_tip_height - 1)
                                    .ok_or_else(|| {
                                        SyncError::Validation(format!(
                                            "prev header height {} below checkpoint base {}",
                                            header_tip_height - 1,
                                            self.sync_base_height
                                        ))
                                    })?;
                                storage
                                    .get_header(prev_storage_height)
                                    .await
                                    .map_err(|e| {
                                        SyncError::Storage(format!(
                                            "Failed to get previous header: {}",
                                            e
                                        ))
                                    })?
                                    .ok_or_else(|| {
                                        SyncError::Storage(format!(
                                            "Neither tip ({}) nor previous header found",
                                            header_tip_height
                                        ))
                                    })?
                                    .block_hash()
                            }
                            Ok(None) => {
                                return Err(SyncError::Validation(format!(
                                    "Tip header not found at height {} (genesis)",
                                    header_tip_height
                                )));
                            }
                            Err(e) => {
                                return Err(SyncError::Validation(format!(
                                    "Failed to get tip header: {}",
                                    e
                                )));
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

    /// Check if a sync timeout has occurred and handle recovery.
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
            let storage_tip_index = storage
                .get_tip_height()
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get header tip height: {}", e)))?
                .unwrap_or(0);

            // Convert storage index to blockchain height
            let header_tip_height = self.header_storage_to_abs_height(storage_tip_index);

            // Re-calculate current batch parameters for recovery
            let recovery_batch_end_height =
                (self.current_sync_height + FILTER_BATCH_SIZE - 1).min(header_tip_height);
            let recovery_batch_stop_hash = if recovery_batch_end_height < header_tip_height {
                // Try to get the header at the calculated height with backward scanning
                // Convert blockchain height to storage height
                let storage_height =
                    self.header_abs_to_storage_index(recovery_batch_end_height).ok_or_else(
                        || SyncError::Storage("recovery end below checkpoint base".to_string()),
                    )?;
                match storage.get_header(storage_height).await {
                    Ok(Some(header)) => header.block_hash(),
                    Ok(None) => {
                        tracing::warn!(
                            "Recovery header not found at storage height {} (blockchain height {}), scanning backwards",
                            storage_height,
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
                // Use storage tip index directly since get_header expects header storage index
                match storage.get_header(storage_tip_index).await {
                    Ok(Some(header)) => header.block_hash(),
                    Ok(None) if storage_tip_index > 0 => {
                        tracing::debug!(
                            "Tip header not found at storage height {} (blockchain height {}) during recovery, trying previous header",
                            storage_tip_index,
                            header_tip_height
                        );
                        // Try previous header when at chain tip
                        storage
                            .get_header(storage_tip_index - 1)
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

    /// Start synchronizing filter headers (initialize the sync state).
    /// This replaces the old sync_headers method but doesn't loop for messages.
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

        // Get header tip (storage index of block headers)
        let storage_tip_index = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get header tip height: {}", e)))?
            .unwrap_or(0);

        // Convert storage height to blockchain height for comparisons
        let header_tip_height = self.header_storage_to_abs_height(storage_tip_index);
        tracing::debug!(
            "FilterSync context: header_storage_tip_index={}, header_tip_height={} (base={})",
            storage_tip_index,
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
        let stop_hash = if storage_tip_index > 0 {
            // Use storage_tip_height directly since get_header expects storage height
            storage
                .get_header(storage_tip_index)
                .await
                .map_err(|e| {
                    SyncError::Storage(format!(
                        "Failed to get stop header at storage height {} (blockchain height {}): {}",
                        storage_tip_index, header_tip_height, e
                    ))
                })?
                .ok_or_else(|| {
                    SyncError::Storage(format!(
                        "Stop header not found at storage height {} (blockchain height {})",
                        storage_tip_index, header_tip_height
                    ))
                })?
                .block_hash()
        } else {
            return Err(SyncError::Storage("No headers available for filter sync".to_string()));
        };

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
            // Convert blockchain height to storage height
            let storage_height = self
                .header_abs_to_storage_index(batch_end_height)
                .ok_or_else(|| SyncError::Storage("batch_end below checkpoint base".to_string()))?;
            tracing::debug!(
                "Trying to get header at blockchain height {} -> storage height {}",
                batch_end_height,
                storage_height
            );
            match storage.get_header(storage_height).await {
                Ok(Some(header)) => {
                    tracing::debug!(
                        "Found header for batch stop at blockchain height {} (storage height {}), hash={}",
                        batch_end_height,
                        storage_height,
                        header.block_hash()
                    );
                    header.block_hash()
                }
                Ok(None) => {
                    tracing::warn!(
                        "Initial batch header not found at storage height {} (blockchain height {}), scanning for available header",
                        storage_height,
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

    /// Request filter headers from the network.
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

    /// Process received filter headers and verify chain.
    pub async fn process_filter_headers(
        &self,
        cf_headers: &CFHeaders,
        start_height: u32,
        storage: &S,
    ) -> SyncResult<Vec<FilterHeader>> {
        if cf_headers.filter_hashes.is_empty() {
            return Ok(Vec::new());
        }

        tracing::debug!(
            "Processing {} filter headers starting from height {}",
            cf_headers.filter_hashes.len(),
            start_height
        );

        // Verify filter header chain
        if !self.verify_filter_header_chain(cf_headers, start_height, storage).await? {
            return Err(SyncError::Validation(
                "Filter header chain verification failed".to_string(),
            ));
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

            let filter_header =
                FilterHeader::from_byte_array(sha256d::Hash::hash(&data).to_byte_array());

            if i < 1 || i >= cf_headers.filter_hashes.len() - 1 {
                tracing::trace!(
                    "Filter header {}: filter_hash={:?}, prev_header={:?}, result={:?}",
                    start_height + i as u32,
                    filter_hash,
                    prev_header,
                    filter_header
                );
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
    async fn verify_filter_header_chain(
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

    /// Synchronize compact filters for recent blocks or specific range.
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

        if start > end {
            self.syncing_filters = false;
            return Ok(SyncProgress::default());
        }

        tracing::info!(
            "🔄 Starting compact filter sync from height {} to {} ({} blocks)",
            start,
            end,
            end - start + 1
        );

        // Request filters in batches
        let batch_size = FILTER_REQUEST_BATCH_SIZE;
        let mut current_height = start;
        let mut filters_downloaded = 0;

        while current_height <= end {
            let batch_end = (current_height + batch_size - 1).min(end);

            tracing::debug!("Requesting filters for heights {} to {}", current_height, batch_end);

            // Get stop hash for this batch
            let stop_hash = match self.header_abs_to_storage_index(batch_end) {
                Some(idx) => storage
                    .get_header(idx)
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to get stop header: {}", e)))?
                    .ok_or_else(|| SyncError::Storage("Stop header not found".to_string()))?
                    .block_hash(),
                None => {
                    return Err(SyncError::Storage("batch_end below checkpoint base".to_string()))
                }
            };

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

    /// Synchronize compact filters with flow control to prevent overwhelming peers.
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

    /// Build queue of filter requests from the specified range.
    async fn build_filter_request_queue(
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

        if start > end {
            tracing::warn!(
                "⚠️ Filter sync requested from height {} but end height is {} - no filters to sync",
                start,
                end
            );
            return Ok(());
        }

        tracing::info!(
            "🔄 Building filter request queue from height {} to {} ({} blocks, filter headers available up to {})",
            start,
            end,
            end - start + 1,
            filter_header_tip_height
        );

        // Build requests in batches
        let batch_size = FILTER_REQUEST_BATCH_SIZE;
        let mut current_height = start;

        while current_height <= end {
            let batch_end = (current_height + batch_size - 1).min(end);

            // Get stop hash for this batch - convert blockchain height to storage index
            let storage_height = self.header_abs_to_storage_index(batch_end).ok_or_else(|| {
                SyncError::Validation(format!(
                    "batch_end {} is at or before checkpoint base {}",
                    batch_end, self.sync_base_height
                ))
            })?;
            let stop_hash = storage
                .get_header(storage_height)
                .await
                .map_err(|e| {
                    SyncError::Storage(format!(
                        "Failed to get stop header at height {} (storage index {}): {}",
                        batch_end, storage_height, e
                    ))
                })?
                .ok_or_else(|| {
                    SyncError::Storage(format!(
                        "Stop header not found at height {} (storage index {})",
                        batch_end, storage_height
                    ))
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

    /// Process the filter request queue with flow control.
    async fn process_filter_request_queue(
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
    async fn send_filter_request(
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

        // Also record in the existing tracking system
        self.record_filter_request(request.start_height, request.end_height);

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
    /// Returns list of completed request ranges.
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

    /// Check if a filter request range is complete (all filters received).
    async fn is_request_complete(&self, start: u32, end: u32) -> SyncResult<bool> {
        let received_heights = self.received_filter_heights.lock().await;
        for height in start..=end {
            if !received_heights.contains(&height) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Record that a filter was received at a specific height.
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

    /// Process next requests from the queue when active requests complete.
    pub async fn process_next_queued_requests(&mut self, network: &mut N) -> SyncResult<()> {
        if !self.flow_control_enabled {
            return Ok(());
        }

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

    /// Get status of flow control system.
    pub fn get_flow_control_status(&self) -> (usize, usize, bool) {
        (
            self.pending_filter_requests.len(),
            self.active_filter_requests.len(),
            self.flow_control_enabled,
        )
    }

    /// Check for timed out filter requests and handle recovery.
    pub async fn check_filter_request_timeouts(
        &mut self,
        network: &mut N,
        storage: &S,
    ) -> SyncResult<()> {
        if !self.flow_control_enabled {
            // Fall back to original timeout checking
            return self.check_and_retry_missing_filters(network, storage).await;
        }

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
        _network: &mut dyn NetworkManager,
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

        // Calculate stop hash for retry - convert blockchain height to storage index
        let storage_height = self.header_abs_to_storage_index(end).ok_or_else(|| {
            SyncError::Validation(format!(
                "retry end {} is at or before checkpoint base {}",
                end, self.sync_base_height
            ))
        })?;
        match storage.get_header(storage_height).await {
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

    /// Check filters against wallet and return matches.
    pub async fn check_filters_for_matches(
        &self,
        _storage: &S,
        start_height: u32,
        end_height: u32,
    ) -> SyncResult<Vec<crate::types::FilterMatch>> {
        tracing::info!(
            "Checking filters for matches from height {} to {}",
            start_height,
            end_height
        );

        // TODO: This will be integrated with wallet's check_compact_filter
        // For now, return empty matches
        Ok(Vec::new())
    }

    /// Request compact filters from the network.
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

    /// Request compact filters with range tracking.
    pub async fn request_filters_with_tracking(
        &mut self,
        network: &mut N,
        storage: &S,
        start_height: u32,
        stop_hash: BlockHash,
    ) -> SyncResult<()> {
        // Find the end height for the stop hash
        let header_tip_index = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get header tip height: {}", e)))?
            .unwrap_or(0);

        let header_tip_height = self.header_storage_to_abs_height(header_tip_index);

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

    /// Find height for a block hash within a range.
    async fn find_height_for_block_hash(
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

    /// Download filter header for a specific block.
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

    /// Download and check a compact filter for matches.
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

    /// Check a filter for matches using the wallet.
    pub async fn check_filter_for_matches<
        W: key_wallet_manager::wallet_interface::WalletInterface,
    >(
        &self,
        filter_data: &[u8],
        block_hash: &BlockHash,
        wallet: &mut W,
        network: dashcore::Network,
    ) -> SyncResult<bool> {
        // Create the BlockFilter from the raw data
        let filter = dashcore::bip158::BlockFilter::new(filter_data);

        // Use wallet's check_compact_filter method
        let matches = wallet.check_compact_filter(&filter, block_hash, network).await;
        if matches {
            tracing::info!("🎯 Filter match found for block {}", block_hash);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check if filter matches any of the provided scripts using BIP158 GCS filter.
    #[allow(dead_code)]
    fn filter_matches_scripts(
        &self,
        filter_data: &[u8],
        block_hash: &BlockHash,
        scripts: &[ScriptBuf],
    ) -> SyncResult<bool> {
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

        // tracing::debug!("Checking filter against {} watch scripts using BIP158 GCS", scripts.len());

        // Use the BIP158 filter to check if any scripts match
        let mut filter_slice = filter_data;
        match filter_reader.match_any(&mut filter_slice, script_bytes.into_iter()) {
            Ok(matches) => {
                if matches {
                    tracing::info!(
                        "BIP158 filter match found! Block {} contains watched scripts",
                        block_hash
                    );
                } else {
                    tracing::trace!("No BIP158 filter matches found for block {}", block_hash);
                }
                Ok(matches)
            }
            Err(Bip158Error::Io(e)) => {
                Err(SyncError::Storage(format!("BIP158 filter IO error: {}", e)))
            }
            Err(Bip158Error::UtxoMissing(outpoint)) => {
                Err(SyncError::Validation(format!("BIP158 filter UTXO missing: {}", outpoint)))
            }
            Err(_) => Err(SyncError::Validation("BIP158 filter error".to_string())),
        }
    }

    /// Store filter headers from a CFHeaders message.
    /// This method is used when filter headers are received outside of the normal sync process,
    /// such as when monitoring the network for new blocks.
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

                        // If this is the first batch after a checkpoint, store the checkpoint filter header
                        if self.sync_base_height > 0
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

    /// Request a block for download after a filter match.
    pub async fn request_block_download(
        &mut self,
        filter_match: crate::types::FilterMatch,
        network: &mut N,
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

        tracing::info!(
            "📦 Requesting block download for {} at height {}",
            filter_match.block_hash,
            filter_match.height
        );

        // Create GetData message for the block
        let inv = Inventory::Block(filter_match.block_hash);

        let getdata = vec![inv];

        // Send the request
        network
            .send_message(NetworkMessage::GetData(getdata))
            .await
            .map_err(|e| SyncError::Network(format!("Failed to send GetData for block: {}", e)))?;

        // Mark as downloading and add to queue
        self.downloading_blocks.insert(filter_match.block_hash, filter_match.height);
        let block_hash = filter_match.block_hash;
        self.pending_block_downloads.push_back(filter_match);

        tracing::debug!(
            "Added block {} to download queue (queue size: {})",
            block_hash,
            self.pending_block_downloads.len()
        );

        Ok(())
    }

    /// Handle a downloaded block and return whether it was expected.
    pub async fn handle_downloaded_block(
        &mut self,
        block: &dashcore::block::Block,
    ) -> SyncResult<Option<crate::types::FilterMatch>> {
        let block_hash = block.block_hash();

        // Check if this block was requested by the sync manager
        if let Some(height) = self.downloading_blocks.remove(&block_hash) {
            tracing::info!("📦 Received expected block {} at height {}", block_hash, height);

            // Find and remove from pending queue
            if let Some(pos) =
                self.pending_block_downloads.iter().position(|m| m.block_hash == block_hash)
            {
                let mut filter_match =
                    self.pending_block_downloads.remove(pos).ok_or_else(|| {
                        SyncError::InvalidState("filter match should exist at position".to_string())
                    })?;
                filter_match.block_requested = true;

                tracing::debug!(
                    "Removed block {} from download queue (remaining: {})",
                    block_hash,
                    self.pending_block_downloads.len()
                );

                return Ok(Some(filter_match));
            }
        }

        // Check if this block was requested by the filter processing thread
        {
            let mut processing_requests = self.processing_thread_requests.lock().await;
            if processing_requests.remove(&block_hash) {
                tracing::info!(
                    "📦 Received block {} requested by filter processing thread",
                    block_hash
                );

                // We don't have height information for processing thread requests,
                // so we'll need to look it up
                // Create a minimal FilterMatch to indicate this was a processing thread request
                let filter_match = crate::types::FilterMatch {
                    block_hash,
                    height: 0, // Height unknown for processing thread requests
                    block_requested: true,
                };

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

    /// Get the number of active filter requests (for flow control).
    pub fn active_request_count(&self) -> usize {
        self.active_filter_requests.len()
    }

    /// Check if there are pending filter requests in the queue.
    pub fn has_pending_filter_requests(&self) -> bool {
        !self.pending_filter_requests.is_empty()
    }

    /// Get the number of available request slots.
    pub fn get_available_request_slots(&self) -> usize {
        MAX_CONCURRENT_FILTER_REQUESTS.saturating_sub(self.active_filter_requests.len())
    }

    /// Send the next batch of filter requests from the queue.
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

    /// Process filter matches and automatically request block downloads.
    pub async fn process_filter_matches_and_download(
        &mut self,
        filter_matches: Vec<crate::types::FilterMatch>,
        network: &mut N,
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

            if self.pending_block_downloads.iter().any(|m| m.block_hash == filter_match.block_hash)
            {
                tracing::debug!("Block {} already queued for download", filter_match.block_hash);
                continue;
            }

            tracing::info!(
                "📦 Queuing block download for {} at height {}",
                filter_match.block_hash,
                filter_match.height
            );

            // Add to inventory for bulk request
            inventory_items.push(Inventory::Block(filter_match.block_hash));

            // Mark as downloading and add to queue
            self.downloading_blocks.insert(filter_match.block_hash, filter_match.height);
            self.pending_block_downloads.push_back(filter_match.clone());
            new_downloads.push(filter_match);
        }

        // Send single bundled GetData request for all blocks
        if !inventory_items.is_empty() {
            tracing::info!(
                "📦 Requesting {} blocks in single GetData message",
                inventory_items.len()
            );

            let getdata = NetworkMessage::GetData(inventory_items);
            network.send_message(getdata).await.map_err(|e| {
                SyncError::Network(format!("Failed to send bundled GetData for blocks: {}", e))
            })?;

            tracing::debug!(
                "Added {} blocks to download queue (total queue size: {})",
                new_downloads.len(),
                self.pending_block_downloads.len()
            );
        }

        Ok(new_downloads)
    }

    /// Reset sync state.
    pub fn reset(&mut self) {
        self.syncing_filter_headers = false;
        self.syncing_filters = false;
        self.pending_block_downloads.clear();
        self.downloading_blocks.clear();
        self.clear_filter_sync_state();
    }

    /// Clear filter sync state (for retries and recovery).
    fn clear_filter_sync_state(&mut self) {
        // Clear request tracking
        self.requested_filter_ranges.clear();
        self.active_filter_requests.clear();
        self.pending_filter_requests.clear();

        // Clear retry counts for fresh start
        self.filter_retry_counts.clear();

        // Note: We don't clear received_filter_heights as those are actually received

        tracing::debug!("Cleared filter sync state for retry/recovery");
    }

    /// Check if filter header sync is currently in progress.
    pub fn is_syncing_filter_headers(&self) -> bool {
        self.syncing_filter_headers
    }

    /// Check if filter sync is currently in progress.
    pub fn is_syncing_filters(&self) -> bool {
        self.syncing_filters
            || !self.active_filter_requests.is_empty()
            || !self.pending_filter_requests.is_empty()
    }

    /// Get the number of filters that have been received.
    pub fn get_received_filter_count(&self) -> u32 {
        match self.received_filter_heights.try_lock() {
            Ok(heights) => heights.len() as u32,
            Err(_) => 0,
        }
    }

    /// Create a filter processing task that runs in a separate thread.
    /// Returns a sender channel that the networking thread can use to send CFilter messages
    /// for processing.
    /// TODO: Integrate with wallet for filter checking
    pub fn spawn_filter_processor(
        _network_message_sender: mpsc::Sender<NetworkMessage>,
        _processing_thread_requests: std::sync::Arc<
            tokio::sync::Mutex<std::collections::HashSet<BlockHash>>,
        >,
        stats: std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
    ) -> FilterNotificationSender {
        let (filter_tx, mut filter_rx) =
            mpsc::unbounded_channel::<dashcore::network::message_filter::CFilter>();

        tokio::spawn(async move {
            tracing::info!("🔄 Filter processing thread started (wallet integration pending)");

            loop {
                tokio::select! {
                    // Handle CFilter messages
                    Some(cfilter) = filter_rx.recv() => {
                        // TODO: Process filter with wallet
                        tracing::debug!("Received CFilter for block {} (wallet integration pending)", cfilter.block_hash);
                        // Update stats
                        Self::update_filter_received(&stats).await;
                    }

                    // Exit when channel is closed
                    else => {
                        tracing::info!("🔄 Filter processing thread stopped");
                        break;
                    }
                }
            }
        });

        filter_tx
    }

    /* TODO: Re-implement with wallet integration
    /// Process a single filter notification by checking for matches and requesting blocks.
    async fn process_filter_notification(
        cfilter: dashcore::network::message_filter::CFilter,
        network_message_sender: &mpsc::Sender<NetworkMessage>,
        processing_thread_requests: &std::sync::Arc<
            tokio::sync::Mutex<std::collections::HashSet<BlockHash>>,
        >,
        stats: &std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
    ) -> SyncResult<()> {
        // Update filter reception tracking
        Self::update_filter_received(stats).await;

        if watch_items.is_empty() {
            return Ok(());
        }

        // Convert watch items to scripts for filter checking
        let mut scripts = Vec::with_capacity(watch_items.len());
        for item in watch_items {
            match item {
                crate::types::WatchItem::Address {
                    address,
                    ..
                } => {
                    scripts.push(address.script_pubkey());
                }
                crate::types::WatchItem::Script(script) => {
                    scripts.push(script.clone());
                }
                crate::types::WatchItem::Outpoint(_) => {
                    // Skip outpoints for now
                }
            }
        }

        if scripts.is_empty() {
            return Ok(());
        }

        // Check if the filter matches any of our scripts
        let matches = Self::check_filter_matches(&cfilter.filter, &cfilter.block_hash, &scripts)?;

        if matches {
            tracing::info!(
                "🎯 Filter match found in processing thread for block {}",
                cfilter.block_hash
            );

            // Update filter match statistics
            {
                let mut stats_lock = stats.write().await;
                stats_lock.filters_matched += 1;
            }

            // Register this request in the processing thread tracking
            {
                let mut requests = processing_thread_requests.lock().await;
                requests.insert(cfilter.block_hash);
                tracing::debug!(
                    "Registered block {} in processing thread requests",
                    cfilter.block_hash
                );
            }

            // Request the full block download
            let inv = dashcore::network::message_blockdata::Inventory::Block(cfilter.block_hash);
            let getdata = dashcore::network::message::NetworkMessage::GetData(vec![inv]);

            if let Err(e) = network_message_sender.send(getdata).await {
                tracing::error!("Failed to request block download for match: {}", e);
                // Remove from tracking if request failed
                {
                    let mut requests = processing_thread_requests.lock().await;
                    requests.remove(&cfilter.block_hash);
                }
            } else {
                tracing::info!(
                    "📦 Requested block download for filter match: {}",
                    cfilter.block_hash
                );
            }
        }

        Ok(())
    }
    */

    /* TODO: Re-implement with wallet integration
    /// Static method to check if a filter matches any scripts (used by the processing thread).
    fn check_filter_matches(
        filter_data: &[u8],
        block_hash: &BlockHash,
        scripts: &[ScriptBuf],
    ) -> SyncResult<bool> {
        if scripts.is_empty() || filter_data.is_empty() {
            return Ok(false);
        }

        // Create a BlockFilterReader with the block hash for proper key derivation
        let filter_reader = BlockFilterReader::new(block_hash);

        // Convert scripts to byte slices for matching
        let mut script_bytes = Vec::with_capacity(scripts.len());
        for script in scripts {
            script_bytes.push(script.as_bytes());
        }

        // Use the BIP158 filter to check if any scripts match
        let mut filter_slice = filter_data;
        match filter_reader.match_any(&mut filter_slice, script_bytes.into_iter()) {
            Ok(matches) => {
                if matches {
                    tracing::info!(
                        "BIP158 filter match found! Block {} contains watched scripts",
                        block_hash
                    );
                }
                Ok(matches)
            }
            Err(Bip158Error::Io(e)) => {
                Err(SyncError::Storage(format!("BIP158 filter IO error: {}", e)))
            }
            Err(Bip158Error::UtxoMissing(outpoint)) => {
                Err(SyncError::Validation(format!("BIP158 filter UTXO missing: {}", outpoint)))
            }
            Err(_) => Err(SyncError::Validation("BIP158 filter error".to_string())),
        }
    }
    */

    /// Check if filter header sync is stable (tip height hasn't changed for 3+ seconds).
    /// This prevents premature completion detection when filter headers are still arriving.
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

    /// Start tracking filter sync progress.
    pub async fn start_filter_sync_tracking(
        stats: &std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
        total_filters_requested: u64,
    ) {
        let mut stats_lock = stats.write().await;

        // If we're starting a new sync session while one is already in progress,
        // add to the existing count instead of resetting
        if stats_lock.filter_sync_start_time.is_some() {
            // Accumulate the new request count
            stats_lock.filters_requested += total_filters_requested;
            tracing::info!(
                "📊 Added {} filters to existing sync tracking (total: {} filters requested)",
                total_filters_requested,
                stats_lock.filters_requested
            );
        } else {
            // Fresh start - reset everything
            stats_lock.filters_requested = total_filters_requested;
            stats_lock.filters_received = 0;
            stats_lock.filter_sync_start_time = Some(std::time::Instant::now());
            stats_lock.last_filter_received_time = None;
            // Clear the received heights tracking for a fresh start
            let received_filter_heights = stats_lock.received_filter_heights.clone();
            drop(stats_lock); // Release the RwLock before awaiting the mutex
            let mut heights = received_filter_heights.lock().await;
            heights.clear();
            tracing::info!(
                "📊 Started new filter sync tracking: {} filters requested",
                total_filters_requested
            );
        }
    }

    /// Complete filter sync tracking (marks the sync session as complete).
    pub async fn complete_filter_sync_tracking(
        stats: &std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
    ) {
        let mut stats_lock = stats.write().await;
        stats_lock.filter_sync_start_time = None;
        tracing::info!("📊 Completed filter sync tracking");
    }

    /// Update filter reception tracking.
    pub async fn update_filter_received(
        stats: &std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
    ) {
        let mut stats_lock = stats.write().await;
        stats_lock.filters_received += 1;
        stats_lock.last_filter_received_time = Some(std::time::Instant::now());
    }

    /// Record filter received at specific height (used by processing thread).
    pub async fn record_filter_received_at_height(
        stats: &std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
        storage: &S,
        block_hash: &BlockHash,
    ) {
        // Look up height for the block hash
        if let Ok(Some(height)) = storage.get_header_height_by_hash(block_hash).await {
            // Get the shared filter heights arc from stats
            let stats_lock = stats.read().await;
            let received_filter_heights = stats_lock.received_filter_heights.clone();
            drop(stats_lock); // Release the stats lock before acquiring the mutex

            // Now lock the heights and insert
            let mut heights = received_filter_heights.lock().await;
            heights.insert(height);
            tracing::trace!(
                "📊 Recorded filter received at height {} for block {}",
                height,
                block_hash
            );
        } else {
            tracing::warn!("Could not find height for filter block hash {}", block_hash);
        }
    }

    /// Get filter sync progress as percentage.
    pub async fn get_filter_sync_progress(
        stats: &std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
    ) -> f64 {
        let stats_lock = stats.read().await;
        if stats_lock.filters_requested == 0 {
            return 0.0;
        }
        (stats_lock.filters_received as f64 / stats_lock.filters_requested as f64) * 100.0
    }

    /// Check if filter sync has timed out (no filters received for 30+ seconds).
    pub async fn check_filter_sync_timeout(
        stats: &std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
    ) -> bool {
        let stats_lock = stats.read().await;
        if let Some(last_received) = stats_lock.last_filter_received_time {
            last_received.elapsed() > std::time::Duration::from_secs(30)
        } else if let Some(sync_start) = stats_lock.filter_sync_start_time {
            // No filters received yet, check if we've been waiting too long
            sync_start.elapsed() > std::time::Duration::from_secs(30)
        } else {
            false
        }
    }

    /// Get filter sync status information.
    pub async fn get_filter_sync_status(
        stats: &std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
    ) -> (u64, u64, f64, bool) {
        let stats_lock = stats.read().await;
        let progress = if stats_lock.filters_requested == 0 {
            0.0
        } else {
            (stats_lock.filters_received as f64 / stats_lock.filters_requested as f64) * 100.0
        };

        let timeout = if let Some(last_received) = stats_lock.last_filter_received_time {
            last_received.elapsed() > std::time::Duration::from_secs(30)
        } else if let Some(sync_start) = stats_lock.filter_sync_start_time {
            sync_start.elapsed() > std::time::Duration::from_secs(30)
        } else {
            false
        };

        (stats_lock.filters_requested, stats_lock.filters_received, progress, timeout)
    }

    /// Get enhanced filter sync status with gap information.
    ///
    /// This function provides comprehensive filter sync status by combining:
    /// 1. Basic progress tracking (filters_received vs filters_requested)
    /// 2. Gap analysis of active filter requests
    /// 3. Correction logic for tracking inconsistencies
    ///
    /// The function addresses a bug where completion could be incorrectly reported
    /// when active request tracking (requested_filter_ranges) was empty but
    /// basic progress indicated incomplete sync. This could happen when filter
    /// range requests were marked complete but individual filters within those
    /// ranges were never actually received.
    ///
    /// Returns: (filters_requested, filters_received, basic_progress, timeout, total_missing, actual_coverage, missing_ranges)
    pub async fn get_filter_sync_status_with_gaps(
        stats: &std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
        filter_sync: &FilterSyncManager<S, N>,
    ) -> (u64, u64, f64, bool, u32, f64, Vec<(u32, u32)>) {
        let stats_lock = stats.read().await;
        let basic_progress = if stats_lock.filters_requested == 0 {
            0.0
        } else {
            (stats_lock.filters_received as f64 / stats_lock.filters_requested as f64) * 100.0
        };

        let timeout = if let Some(last_received) = stats_lock.last_filter_received_time {
            last_received.elapsed() > std::time::Duration::from_secs(30)
        } else if let Some(sync_start) = stats_lock.filter_sync_start_time {
            sync_start.elapsed() > std::time::Duration::from_secs(30)
        } else {
            false
        };

        // Get gap information from active requests
        let missing_ranges = filter_sync.find_missing_ranges();
        let total_missing = filter_sync.get_total_missing_filters();
        let actual_coverage = filter_sync.get_actual_coverage_percentage();

        // If active request tracking shows no gaps but basic progress indicates incomplete sync,
        // we may have a tracking inconsistency. In this case, trust the basic progress calculation.
        let corrected_total_missing = if total_missing == 0
            && stats_lock.filters_received < stats_lock.filters_requested
        {
            // Gap detection failed, but basic stats show incomplete sync
            tracing::debug!(
                "Gap detection shows complete ({}), but basic progress shows {}/{} - treating as incomplete",
                total_missing,
                stats_lock.filters_received,
                stats_lock.filters_requested
            );
            (stats_lock.filters_requested - stats_lock.filters_received) as u32
        } else {
            total_missing
        };

        (
            stats_lock.filters_requested,
            stats_lock.filters_received,
            basic_progress,
            timeout,
            corrected_total_missing,
            actual_coverage,
            missing_ranges,
        )
    }

    /// Record a filter range request for tracking.
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

    /// Get filter ranges that have timed out (no response after 30+ seconds).
    pub fn get_timed_out_ranges(&self, timeout_duration: std::time::Duration) -> Vec<(u32, u32)> {
        let now = std::time::Instant::now();
        let mut timed_out = Vec::new();

        let heights = match self.received_filter_heights.try_lock() {
            Ok(heights) => heights.clone(),
            Err(_) => return timed_out,
        };

        for ((start, end), request_time) in &self.requested_filter_ranges {
            if now.duration_since(*request_time) > timeout_duration {
                // Check if this range is incomplete
                let mut is_incomplete = false;
                for height in *start..=*end {
                    if !heights.contains(&height) {
                        is_incomplete = true;
                        break;
                    }
                }

                if is_incomplete {
                    timed_out.push((*start, *end));
                }
            }
        }

        timed_out
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

    /// Check if there's a gap between block headers and filter headers
    /// Returns (has_gap, block_height, filter_height, gap_size)
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

    /// Attempt to restart filter header sync if there's a gap and conditions are met
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

            // Calculate stop hash for this range - convert blockchain height to storage index
            let storage_height = self.header_abs_to_storage_index(end).ok_or_else(|| {
                SyncError::Validation(format!(
                    "retry range end {} is at or before checkpoint base {}",
                    end, self.sync_base_height
                ))
            })?;
            match storage.get_header(storage_height).await {
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

                            // Get stop hash for this batch - convert blockchain height to storage index
                            let batch_storage_height =
                                self.header_abs_to_storage_index(batch_end).ok_or_else(|| {
                                    SyncError::Validation(format!(
                                        "retry batch_end {} is at or before checkpoint base {}",
                                        batch_end, self.sync_base_height
                                    ))
                                })?;
                            match storage.get_header(batch_storage_height).await {
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
                                        "Missing header at storage height {} (batch end height {}) for batch retry, continuing to next batch",
                                        batch_storage_height,
                                        batch_end
                                    );
                                    current_start = batch_end + 1;
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "Error retrieving header at storage height {} (batch end height {}): {:?}, continuing to next batch",
                                        batch_storage_height,
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

    /// Reset filter range tracking (useful for testing or restart scenarios).
    pub fn reset_filter_tracking(&mut self) {
        self.requested_filter_ranges.clear();
        if let Ok(mut heights) = self.received_filter_heights.try_lock() {
            heights.clear();
        }
        self.filter_retry_counts.clear();
        tracing::info!("🔄 Reset filter range tracking");
    }

    /// Merge adjacent ranges for efficiency, but respect the maximum filter request size.
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

    /// Reset any pending requests after restart.
    pub fn reset_pending_requests(&mut self) {
        // Clear all request tracking state
        self.syncing_filter_headers = false;
        self.syncing_filters = false;
        self.requested_filter_ranges.clear();
        self.pending_filter_requests.clear();
        self.active_filter_requests.clear();
        self.filter_retry_counts.clear();
        self.pending_block_downloads.clear();
        self.downloading_blocks.clear();
        self.last_sync_progress = std::time::Instant::now();
        tracing::debug!("Reset filter sync pending requests");
    }
}
