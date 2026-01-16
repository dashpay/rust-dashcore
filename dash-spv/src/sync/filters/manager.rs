//! Filter synchronization manager - main coordinator.
//!
//! This module contains the FilterSyncManager struct and high-level coordination logic
//! that delegates to specialized sub-modules for headers, downloads, matching, etc.

use crate::client::Config;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::types::SharedFilterHeights;
use dashcore::{hash_types::FilterHeader, network::message_filter::CFHeaders, BlockHash};
use dashcore_hashes::{sha256d, Hash};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

// Import types and constants from the types module
use super::types::*;

/// Manages BIP157 compact block filter synchronization.
///
/// # Generic Parameters
///
/// - `S: StorageManager` - Storage backend for filter headers and filters
/// - `N: NetworkManager` - Network for requesting filters from peers
///
/// ## Why Generics?
///
/// Filter synchronization involves:
/// - Downloading thousands of filter headers and filters
/// - Complex flow control with parallel requests
/// - Retry logic
/// - Storage operations for persistence
///
/// Generic design enables:
/// - **Testing** without real network or disk I/O
/// - **Performance** through monomorphization (no vtable overhead)
/// - **Flexibility** for custom storage backends
///
/// Production uses concrete types; tests use mocks. Both compile to efficient,
/// specialized code without runtime abstraction costs.
pub struct FilterSyncManager<S: StorageManager, N: NetworkManager> {
    pub(super) _phantom_s: std::marker::PhantomData<S>,
    pub(super) _phantom_n: std::marker::PhantomData<N>,
    pub(super) _config: Config,
    /// Whether filter header sync is currently in progress
    pub(super) syncing_filter_headers: bool,
    /// Current height being synced for filter headers
    pub(super) current_sync_height: u32,
    /// Base height for sync (typically from checkpoint)
    pub(super) sync_base_height: u32,
    /// Last time sync progress was made (for timeout detection)
    pub(super) last_sync_progress: std::time::Instant,
    /// Whether filter sync is currently in progress
    pub(super) syncing_filters: bool,
    /// Queue of blocks that have been requested and are waiting for response
    pub(super) pending_block_downloads: VecDeque<crate::types::FilterMatch>,
    /// Blocks currently being downloaded (map for quick lookup)
    pub(super) downloading_blocks: HashMap<BlockHash, u32>,
    /// Blocks requested by the filter processing thread
    pub(super) processing_thread_requests: std::sync::Arc<tokio::sync::Mutex<HashSet<BlockHash>>>,
    /// Track individual filter heights that have been received (shared with stats)
    pub(super) received_filter_heights: SharedFilterHeights,
    /// Maximum retries for a filter range
    pub(super) max_filter_retries: u32,
    /// Retry attempts per range
    pub(super) filter_retry_counts: HashMap<(u32, u32), u32>,
    /// Queue of pending filter requests
    pub(super) pending_filter_requests: VecDeque<FilterRequest>,
    /// Currently active filter requests (limited by MAX_CONCURRENT_FILTER_REQUESTS)
    pub(super) active_filter_requests: HashMap<(u32, u32), ActiveRequest>,
    /// Queue of pending CFHeaders requests
    pub(super) pending_cfheader_requests: VecDeque<CFHeaderRequest>,
    /// Currently active CFHeaders requests: (start_height, stop_height) -> ActiveCFHeaderRequest
    pub(super) active_cfheader_requests: HashMap<u32, ActiveCFHeaderRequest>,
    /// Retry counts per CFHeaders range: start_height -> retry_count
    pub(super) cfheader_retry_counts: HashMap<u32, u32>,
    /// Maximum retries for CFHeaders
    pub(super) max_cfheader_retries: u32,
    /// Received CFHeaders batches waiting for sequential processing: start_height -> batch
    pub(super) received_cfheader_batches: HashMap<u32, ReceivedCFHeaderBatch>,
    /// Next expected height for sequential processing
    pub(super) next_cfheader_height_to_process: u32,
    /// Maximum concurrent CFHeaders requests
    pub(super) max_concurrent_cfheader_requests: usize,
    /// Timeout for CFHeaders requests
    pub(super) cfheader_request_timeout: std::time::Duration,
}

impl<S: StorageManager, N: NetworkManager> FilterSyncManager<S, N> {
    /// Verify that the received compact filter hashes to the expected filter header
    pub fn new(config: &Config, received_filter_heights: SharedFilterHeights) -> Self {
        Self {
            _config: config.clone(),
            syncing_filter_headers: false,
            current_sync_height: 0,
            sync_base_height: 0,
            last_sync_progress: std::time::Instant::now(),
            syncing_filters: false,
            pending_block_downloads: VecDeque::new(),
            downloading_blocks: HashMap::new(),
            processing_thread_requests: std::sync::Arc::new(tokio::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
            received_filter_heights,
            max_filter_retries: 3,
            filter_retry_counts: HashMap::new(),
            pending_filter_requests: VecDeque::new(),
            active_filter_requests: HashMap::new(),
            // CFHeaders fields
            pending_cfheader_requests: VecDeque::new(),
            active_cfheader_requests: HashMap::new(),
            cfheader_retry_counts: HashMap::new(),
            max_cfheader_retries: 3,
            received_cfheader_batches: HashMap::new(),
            next_cfheader_height_to_process: 0,
            max_concurrent_cfheader_requests: 50,
            _phantom_s: std::marker::PhantomData,
            _phantom_n: std::marker::PhantomData,
            cfheader_request_timeout: Duration::from_secs(30),
        }
    }

    /// Set the base height for sync (typically from checkpoint)
    pub fn set_sync_base_height(&mut self, height: u32) {
        self.sync_base_height = height;
    }

    /// Convert absolute blockchain height to block header storage index.
    /// Storage indexing is base-inclusive: at checkpoint base B, storage index 0 == absolute height B.
    pub(super) fn header_abs_to_storage_index(&self, height: u32) -> Option<u32> {
        if self.sync_base_height > 0 {
            height.checked_sub(self.sync_base_height)
        } else {
            Some(height)
        }
    }

    /// Convert absolute blockchain height to filter header storage index.
    /// Storage indexing is base-inclusive for filter headers as well.
    pub(super) fn filter_abs_to_storage_index(&self, height: u32) -> Option<u32> {
        if self.sync_base_height > 0 {
            height.checked_sub(self.sync_base_height)
        } else {
            Some(height)
        }
    }

    // Note: previously had filter_storage_to_abs_height, but it was unused and removed for clarity.

    /// Set syncing filters state.
    pub fn set_syncing_filters(&mut self, syncing: bool) {
        self.syncing_filters = syncing;
    }

    /// Check if filter sync is available (any peer supports compact filters).
    pub async fn is_filter_sync_available(&self, network: &N) -> bool {
        network
            .has_peer_with_service(dashcore::network::constants::ServiceFlags::COMPACT_FILTERS)
            .await
    }

    /// Handle a CFHeaders message during filter header synchronization.
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

    pub fn reset(&mut self) {
        self.syncing_filter_headers = false;
        self.syncing_filters = false;
        self.pending_block_downloads.clear();
        self.downloading_blocks.clear();
        self.clear_filter_sync_state();
    }

    /// Clear filter sync state (for retries and recovery).
    pub(super) fn clear_filter_sync_state(&mut self) {
        // Clear request tracking
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

    pub fn reset_pending_requests(&mut self) {
        // Clear all request tracking state
        self.syncing_filter_headers = false;
        self.syncing_filters = false;
        self.pending_filter_requests.clear();
        self.active_filter_requests.clear();
        self.filter_retry_counts.clear();
        self.pending_block_downloads.clear();
        self.downloading_blocks.clear();
        self.last_sync_progress = std::time::Instant::now();
        tracing::debug!("Reset filter sync pending requests");
    }

    /// Fully clear filter tracking state, including received heights.
    pub async fn clear_filter_state(&mut self) {
        self.reset_pending_requests();
        let mut heights = self.received_filter_heights.lock().await;
        heights.clear();
        tracing::info!("Cleared filter sync state and received heights");
    }
}
