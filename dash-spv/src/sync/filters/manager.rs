//! Filters manager for parallel sync.
//!
//! Downloads compact block filters (BIP 157/158), verifies them against headers,
//! and matches against wallet to identify blocks for download.
//! Emits FiltersStored, FiltersSyncComplete and BlocksNeeded events.

use std::collections::{btree_map, BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use dashcore::bip158::BlockFilter;
use dashcore::{Address, BlockHash};

use super::batch::FiltersBatch;
use super::pipeline::FiltersPipeline;
use crate::error::SyncResult;
use crate::network::RequestSender;
use crate::storage::{BlockHeaderStorage, FilterHeaderStorage, FilterStorage};
use crate::sync::filters::util::get_prev_filter_header;
use crate::sync::{FiltersProgress, SyncEvent, SyncManager, SyncState};
use crate::validation::{FilterValidationInput, FilterValidator, Validator};

use crate::sync::progress::ProgressPercentage;
use dashcore::hash_types::FilterHeader;
use key_wallet::manager::WalletInterface;
use key_wallet::manager::{check_compact_filters_for_addresses, FilterMatchKey};
use tokio::sync::RwLock;

/// Batch size for processing filters.
const BATCH_PROCESSING_SIZE: u32 = 5000;

/// Maximum number of batches to scan ahead while waiting for blocks.
const MAX_LOOKAHEAD_BATCHES: usize = 3;

/// Filters manager for downloading and matching compact block filters.
///
/// Generic over:
/// - `H: BlockHeaderStorage` for block hash lookups
/// - `FH: FilterHeaderStorage` for filter header verification
/// - `F: FilterStorage` for storing and loading filters
/// - `W: WalletInterface` for wallet operations
pub struct FiltersManager<
    H: BlockHeaderStorage,
    FH: FilterHeaderStorage,
    F: FilterStorage,
    W: WalletInterface,
> {
    /// Current progress of the manager.
    pub(super) progress: FiltersProgress,
    /// Block header storage (for block hash lookups).
    pub(super) header_storage: Arc<RwLock<H>>,
    /// Filter header storage (for verification).
    filter_header_storage: Arc<RwLock<FH>>,
    /// Filter storage (for storing filters).
    pub(super) filter_storage: Arc<RwLock<F>>,
    /// Wallet for matching filters.
    pub(super) wallet: Arc<RwLock<W>>,
    /// Pipeline for downloading filters.
    pub(super) filter_pipeline: FiltersPipeline,
    /// Completed batches waiting for verification and storage.
    pub(super) pending_batches: BTreeSet<FiltersBatch>,
    /// Next batch start height to store (for filter verification/storage).
    next_batch_to_store: u32,

    // === Multi-batch processing state ===
    /// Active batches being processed (keyed by start_height).
    pub(super) active_batches: BTreeMap<u32, FiltersBatch>,
    /// Current block height being processed (for progress tracking).
    processing_height: u32,
    /// Blocks remaining that need to be processed.
    /// Maps block_hash -> (height, batch_start) for batch association.
    pub(super) blocks_remaining: BTreeMap<BlockHash, (u32, u32)>,
    /// Block hashes that have been matched and queued for download.
    pub(super) filters_matched: HashSet<BlockHash>,
}

impl<H: BlockHeaderStorage, FH: FilterHeaderStorage, F: FilterStorage, W: WalletInterface>
    FiltersManager<H, FH, F, W>
{
    /// Create a new filters manager with the given storage references.
    pub async fn new(
        wallet: Arc<RwLock<W>>,
        header_storage: Arc<RwLock<H>>,
        filter_header_storage: Arc<RwLock<FH>>,
        filter_storage: Arc<RwLock<F>>,
    ) -> Self {
        let committed_height = wallet.read().await.filter_committed_height();

        // Load block header tip for target display
        let header_tip =
            header_storage.read().await.get_tip().await.map(|t| t.height()).unwrap_or(0);

        let mut initial_progress = FiltersProgress::default();
        initial_progress.update_committed_height(committed_height);
        initial_progress.update_target_height(header_tip);

        Self {
            progress: initial_progress,
            header_storage,
            filter_header_storage,
            filter_storage,
            wallet,
            filter_pipeline: FiltersPipeline::new(),
            pending_batches: BTreeSet::new(),
            next_batch_to_store: 0,
            // Multi-batch processing
            active_batches: BTreeMap::new(),
            processing_height: 0,
            blocks_remaining: BTreeMap::new(),
            filters_matched: HashSet::new(),
        }
    }

    /// Returns true if there is no in-flight processing state.
    fn is_idle(&self) -> bool {
        self.active_batches.is_empty()
            && self.blocks_remaining.is_empty()
            && self.filters_matched.is_empty()
            && self.pending_batches.is_empty()
            && self.filter_pipeline.is_idle()
    }

    async fn load_filters(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> SyncResult<HashMap<FilterMatchKey, BlockFilter>> {
        let loaded_filters =
            self.filter_storage.read().await.load_filters(start_height..end_height + 1).await?;

        let loaded_headers =
            self.header_storage.read().await.load_headers(start_height..end_height + 1).await?;

        let mut filters = HashMap::new();
        for (idx, (filter_data, header)) in
            loaded_filters.iter().zip(loaded_headers.iter()).enumerate()
        {
            let height = start_height + idx as u32;
            let key = FilterMatchKey::new(height, header.block_hash());
            let filter = BlockFilter::new(filter_data);
            filters.insert(key, filter);
        }
        Ok(filters)
    }

    /// Initialize the filter download state and begin downloading from the current position.
    pub(super) async fn start_download(
        &mut self,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        debug_assert!(self.is_idle(), "manager should have no in-flight state on start");

        // Use filter_committed_height for restart recovery instead of
        // synced_height, which advances per-block and may exceed committed scan progress.
        let (wallet_birth_height, wallet_committed_height) = {
            let wallet = self.wallet.read().await;
            (wallet.earliest_required_height().await, wallet.filter_committed_height())
        };

        // Get stored filters tip
        let stored_filters_tip = self.filter_storage.read().await.filter_tip_height().await?;

        // Get header start height (for checkpoint sync)
        let header_start_height =
            self.header_storage.read().await.get_start_height().await.unwrap_or(0);

        // Calculate scan start (where we need to start processing)
        // Must be at least header_start_height for checkpoint-based sync
        let scan_start = if wallet_committed_height > 0 {
            wallet_birth_height.max(wallet_committed_height + 1)
        } else {
            wallet_birth_height
        }
        .max(header_start_height);

        // Check if already at target (nothing to download)
        if scan_start > self.progress.filter_header_tip_height() {
            // Only emit FiltersSyncComplete if we've also reached the chain tip
            // This prevents premature sync complete while filter headers are still syncing
            if self.progress.committed_height() >= self.progress.target_height() {
                self.set_state(SyncState::Synced);
                tracing::info!("Filters already synced to {}", self.progress.target_height());
                return Ok(vec![SyncEvent::FiltersSyncComplete {
                    tip_height: self.progress.committed_height(),
                }]);
            }
            // Not enough filter headers yet to start scanning. Go back to waiting
            // so the next FilterHeadersStored event triggers start_download again
            // with proper batch processing initialization.
            self.set_state(SyncState::WaitForEvents);
            return Ok(vec![]);
        }

        // Determine download start (where we need to download from)
        // Must be at least header_start_height for checkpoint-based sync
        let download_start = if stored_filters_tip > 0 {
            (stored_filters_tip + 1).max(header_start_height)
        } else {
            scan_start
        };

        self.next_batch_to_store = download_start;
        self.processing_height = scan_start;

        tracing::info!(
            "Starting filter download (scan_start={}, download_start={}, stored_filters_tip={}, target={})",
            scan_start,
            download_start,
            stored_filters_tip,
            self.progress.filter_header_tip_height()
        );

        self.set_state(SyncState::Syncing);

        // Initialize download pipeline for remaining filters
        if download_start <= self.progress.filter_header_tip_height() {
            self.filter_pipeline.init(download_start, self.progress.filter_header_tip_height());
            let header_storage = self.header_storage.read().await;
            self.filter_pipeline.send_pending(requests, &*header_storage).await?;
            drop(header_storage);
        } else {
            // No new filters to download, scanning stored filters only
            self.filter_pipeline.init(download_start, download_start.saturating_sub(1));
        }

        // Initialize the first processing batch
        let batch_end =
            (scan_start + BATCH_PROCESSING_SIZE - 1).min(self.progress.filter_header_tip_height());

        // Load any already-stored filters into the current batch, or create empty batch
        let filters = if stored_filters_tip > 0 && scan_start <= stored_filters_tip {
            let end_height = stored_filters_tip.min(batch_end);
            tracing::info!(
                "Loading stored filters {} to {} into current batch",
                scan_start,
                end_height
            );
            // Update stored_height to reflect stored filters are available
            self.progress.update_stored_height(stored_filters_tip);
            self.load_filters(scan_start, end_height).await?
        } else {
            HashMap::new()
        };

        let mut batch = FiltersBatch::new(scan_start, batch_end, filters);
        if stored_filters_tip >= batch_end {
            batch.mark_verified();
        }
        self.active_batches.insert(scan_start, batch);
        self.progress.update_committed_height(scan_start.saturating_sub(1));

        // Only scan if all filters for the batch are already loaded
        if self.progress.stored_height() >= batch_end {
            self.scan_batch(scan_start).await
        } else {
            tracing::debug!(
                "Initial batch {}-{}: waiting for filters (stored_height={})",
                scan_start,
                batch_end,
                self.progress.stored_height()
            );
            Ok(vec![])
        }
    }

    /// Store completed filter batches to disk and do speculative matching.
    /// This is decoupled from block processing - we store and match as fast as possible.
    pub(super) async fn store_and_match_batches(&mut self) -> SyncResult<Vec<SyncEvent>> {
        // Collect newly completed batches from pipeline
        let completed = self.filter_pipeline.take_completed_batches();
        // Filter out batches that have already been stored (can happen with retries)
        for batch in completed {
            if batch.start_height() < self.next_batch_to_store {
                tracing::debug!(
                    "Discarding duplicate batch {}-{} (already stored, next_batch_to_store={})",
                    batch.start_height(),
                    batch.end_height(),
                    self.next_batch_to_store
                );
                continue;
            }
            self.pending_batches.insert(batch);
        }

        let mut events = Vec::new();

        // Store batches in order (for filter verification chain)
        while let Some(batch) = self.pending_batches.first() {
            if batch.start_height() != self.next_batch_to_store {
                tracing::trace!(
                    "Waiting for batch {}, first pending is {} ({} pending)",
                    self.next_batch_to_store,
                    batch.start_height(),
                    self.pending_batches.len()
                );
                break;
            }

            let mut batch = self.pending_batches.pop_first().unwrap();

            tracing::debug!(
                "Storing filter batch {} to {} ({} filters)",
                batch.start_height(),
                batch.end_height(),
                batch.filters().len()
            );

            // Verify and store filters
            if !batch.verified() {
                // Load filter headers for verification
                let filter_headers = self
                    .filter_header_storage
                    .read()
                    .await
                    .load_filter_headers(batch.start_height()..batch.end_height() + 1)
                    .await?;

                let filter_headers_map: HashMap<u32, FilterHeader> = filter_headers
                    .into_iter()
                    .enumerate()
                    .map(|(idx, header)| (batch.start_height() + idx as u32, header))
                    .collect();

                let filter_header_storage = self.filter_header_storage.read().await;
                let prev_filter_header =
                    get_prev_filter_header(&*filter_header_storage, batch.start_height()).await?;
                drop(filter_header_storage);

                let validator = FilterValidator::new();
                let validation_input = FilterValidationInput {
                    filters: batch.filters(),
                    expected_headers: &filter_headers_map,
                    prev_filter_header,
                };
                validator.validate(validation_input)?;

                // Store verified filters to disk
                let mut filter_storage = self.filter_storage.write().await;
                for (key, filter) in batch.filters() {
                    filter_storage.store_filter(key.height(), &filter.content).await?;
                }
                drop(filter_storage);

                events.push(SyncEvent::FiltersStored {
                    start_height: batch.start_height(),
                    end_height: batch.end_height(),
                });
            }

            // === Load filters into all active batches that overlap ===
            for active_batch in self.active_batches.values_mut() {
                if batch.start_height() <= active_batch.end_height()
                    && batch.end_height() >= active_batch.start_height()
                {
                    // This batch overlaps with active batch, load into memory
                    let load_start = batch.start_height().max(active_batch.start_height());
                    let load_end = batch.end_height().min(active_batch.end_height());

                    let mut loaded_count = 0;
                    for (key, filter) in batch.filters_mut() {
                        if key.height() >= load_start && key.height() <= load_end {
                            active_batch.filters_mut().insert(key.clone(), filter.clone());
                            loaded_count += 1;
                        }
                    }
                    tracing::debug!(
                        "Loaded {} filters from batch {}-{} into active_batch {}-{} (active_batch now has {} filters)",
                        loaded_count,
                        batch.start_height(),
                        batch.end_height(),
                        active_batch.start_height(),
                        active_batch.end_height(),
                        active_batch.filters().len()
                    );
                }
            }

            self.progress.add_processed(batch.end_height() - batch.start_height() + 1);
            self.progress.update_stored_height(batch.end_height());
            self.next_batch_to_store = batch.end_height() + 1;
        }

        // If we stored any batches, try to process the batch containing the current processing height.
        // This is called only when batches complete, not on every filter
        if !events.is_empty() {
            tracing::debug!(
                "Calling try_process_batch after storing batches (stored_height={}, target_height={})",
                self.progress.stored_height(),
                self.progress.target_height()
            );
            events.extend(self.try_process_batch().await?);
        }

        Ok(events)
    }

    /// Try to process batches - commit completed, scan ready, create lookahead.
    /// Returns events for blocks that need to be downloaded.
    pub(super) async fn try_process_batch(&mut self) -> SyncResult<Vec<SyncEvent>> {
        let mut events = Vec::new();

        // Phase 1: Commit completed batches in order
        events.extend(self.try_commit_batches().await?);

        // Phase 2: Scan any ready batches where filters are available
        events.extend(self.scan_ready_batches().await?);

        // Phase 3: Create lookahead batches up to MAX_LOOKAHEAD_BATCHES
        events.extend(self.try_create_lookahead_batches().await?);

        // If no active batches and all filters downloaded, emit FiltersSyncComplete.
        // This handles both initial sync (Syncing → Synced transition) and incremental
        // updates (already Synced, signal BlocksManager that no more blocks are coming).
        if self.active_batches.is_empty()
            && matches!(self.state(), SyncState::Syncing | SyncState::Synced)
            && self.progress.committed_height() >= self.progress.filter_header_tip_height()
            && self.progress.committed_height() >= self.progress.target_height()
        {
            if self.state() == SyncState::Syncing {
                self.set_state(SyncState::Synced);
            }
            tracing::info!("Filter sync complete at height {}", self.progress.committed_height());
            events.push(SyncEvent::FiltersSyncComplete {
                tip_height: self.progress.committed_height(),
            });
        }

        Ok(events)
    }

    /// Commit completed batches in order (lowest batch_start first).
    async fn try_commit_batches(&mut self) -> SyncResult<Vec<SyncEvent>> {
        let mut events = Vec::new();

        loop {
            // Get the lowest batch
            let Some((&batch_start, batch)) = self.active_batches.first_key_value() else {
                break;
            };

            // Check if batch was scanned - can't commit until scanned
            if !batch.scanned() {
                break;
            }

            // Check if batch has pending blocks
            if batch.pending_blocks() > 0 {
                break;
            }

            // Check if rescan is needed and not done
            if !batch.rescan_complete() {
                // Take collected addresses from the batch
                let addresses = self
                    .active_batches
                    .get_mut(&batch_start)
                    .map(|b| b.take_collected_addresses())
                    .unwrap_or_default();

                if !addresses.is_empty() {
                    // Rescan current batch
                    events.extend(self.rescan_batch(batch_start, addresses.clone()).await?);

                    // Also rescan later batches that are already scanned
                    let later_batches: Vec<u32> = self
                        .active_batches
                        .iter()
                        .filter(|(&start, batch)| start > batch_start && batch.scanned())
                        .map(|(&start, _)| start)
                        .collect();

                    for later_start in later_batches {
                        events.extend(self.rescan_batch(later_start, addresses.clone()).await?);
                    }

                    // Check if rescan found more blocks
                    if let Some(batch) = self.active_batches.get(&batch_start) {
                        if batch.pending_blocks() > 0 {
                            // Found more blocks, can't commit yet
                            break;
                        }
                    }
                }
                // Mark rescan as complete
                if let Some(batch) = self.active_batches.get_mut(&batch_start) {
                    batch.mark_rescan_complete();
                }
            }

            // Commit this batch
            let batch = self.active_batches.remove(&batch_start).unwrap();
            let end = batch.end_height();
            if end > self.progress.committed_height() {
                self.progress.update_committed_height(end);
                self.wallet.write().await.update_filter_committed_height(end);
            }
            self.processing_height = end + 1;

            tracing::info!(
                "Committed batch {}-{}, committed_height now {}",
                batch.start_height(),
                batch.end_height(),
                self.progress.committed_height()
            );
        }

        Ok(events)
    }

    /// Scan any active batches where filters are available but not yet scanned.
    async fn scan_ready_batches(&mut self) -> SyncResult<Vec<SyncEvent>> {
        let mut events = Vec::new();

        // Collect batch starts that need scanning
        let batch_starts: Vec<u32> = self
            .active_batches
            .iter()
            .filter(|(_, batch)| {
                !batch.scanned() && self.progress.stored_height() >= batch.end_height()
            })
            .map(|(&start, _)| start)
            .collect();

        for batch_start in batch_starts {
            events.extend(self.scan_batch(batch_start).await?);
        }

        Ok(events)
    }

    /// Create lookahead batches up to MAX_LOOKAHEAD_BATCHES.
    async fn try_create_lookahead_batches(&mut self) -> SyncResult<Vec<SyncEvent>> {
        let mut events = Vec::new();

        while self.active_batches.len() < MAX_LOOKAHEAD_BATCHES {
            // Find where next batch should start
            let next_start = if let Some((&_, last_batch)) = self.active_batches.last_key_value() {
                last_batch.end_height() + 1
            } else {
                self.processing_height
            };

            // Check if we've reached the target
            if next_start > self.progress.filter_header_tip_height() {
                break;
            }

            let next_end = (next_start + BATCH_PROCESSING_SIZE - 1)
                .min(self.progress.filter_header_tip_height());

            tracing::info!(
                "Creating lookahead batch {}-{} (active_batches={})",
                next_start,
                next_end,
                self.active_batches.len()
            );

            // Load available filters into the new batch
            let available_end = self.progress.stored_height().min(next_end);
            let filters = if next_start <= available_end {
                self.load_filters(next_start, available_end).await?
            } else {
                HashMap::new()
            };

            let mut batch = FiltersBatch::new(next_start, next_end, filters);
            if self.progress.stored_height() >= next_end {
                batch.mark_verified();
            }
            self.active_batches.insert(next_start, batch);

            // Scan immediately if filters are available
            if self.progress.stored_height() >= next_end {
                events.extend(self.scan_batch(next_start).await?);
            }
        }

        Ok(events)
    }

    /// Rescan a specific batch for newly discovered addresses.
    pub(super) async fn rescan_batch(
        &mut self,
        batch_start: u32,
        new_addresses: HashSet<Address>,
    ) -> SyncResult<Vec<SyncEvent>> {
        if new_addresses.is_empty() {
            return Ok(vec![]);
        }

        let Some(batch) = self.active_batches.get_mut(&batch_start) else {
            return Ok(vec![]);
        };

        tracing::info!(
            "Rescan filters ({}-{}) for {} new addresses",
            batch.start_height(),
            batch.end_height(),
            new_addresses.len()
        );

        if batch.filters().is_empty() {
            return Ok(vec![]);
        }

        // Match filters against new addresses only
        let addresses_vec: Vec<_> = new_addresses.into_iter().collect();
        let matches = check_compact_filters_for_addresses(batch.filters(), addresses_vec);
        let mut events = Vec::new();
        let mut blocks_needed = BTreeSet::new();
        let mut new_blocks_count = 0;

        if !matches.is_empty() {
            self.progress.add_matched(matches.len() as u32);
        }
        for key in matches {
            // Skip blocks that were already matched (even if already processed)
            if self.filters_matched.contains(key.hash()) {
                continue;
            }
            // Queue blocks discovered by rescan for download
            if let btree_map::Entry::Vacant(e) = self.blocks_remaining.entry(*key.hash()) {
                e.insert((key.height(), batch_start));
                self.filters_matched.insert(*key.hash());
                blocks_needed.insert(key);
                new_blocks_count += 1;
            }
        }

        // Update batch pending_blocks count
        if new_blocks_count > 0 {
            if let Some(batch) = self.active_batches.get_mut(&batch_start) {
                batch.set_pending_blocks(batch.pending_blocks() + new_blocks_count);
            }
            tracing::info!("Rescan found {} additional blocks", new_blocks_count);
            events.push(SyncEvent::BlocksNeeded {
                blocks: blocks_needed,
            });
        }

        Ok(events)
    }

    /// Scan a specific batch with wallet's current addresses.
    async fn scan_batch(&mut self, batch_start: u32) -> SyncResult<Vec<SyncEvent>> {
        let mut events = Vec::new();

        let Some(batch) = self.active_batches.get_mut(&batch_start) else {
            tracing::debug!("scan_batch: batch {} not found", batch_start);
            return Ok(events);
        };

        tracing::debug!(
            "scan_batch: batch {}-{} has {} filters",
            batch.start_height(),
            batch.end_height(),
            batch.filters().len()
        );

        batch.mark_scanned();

        // Get all filters in the batch
        if batch.filters().is_empty() {
            tracing::debug!("scan_batch: batch filters are empty, returning early");
            return Ok(events);
        }

        // Match against wallet's current addresses
        let wallet = self.wallet.read().await;
        let addresses = wallet.monitored_addresses();
        let matches = check_compact_filters_for_addresses(batch.filters(), addresses);
        drop(wallet);

        tracing::info!(
            "Batch {}-{}: found {} matching blocks",
            batch.start_height(),
            batch.end_height(),
            matches.len()
        );

        if matches.is_empty() {
            return Ok(events);
        }

        self.progress.add_matched(matches.len() as u32);

        // Filter out already-processed blocks and track the new ones
        let mut blocks_needed = BTreeSet::new();
        let mut new_blocks_count = 0;
        for key in matches {
            if self.filters_matched.contains(key.hash()) {
                continue;
            }
            if self.blocks_remaining.contains_key(key.hash()) {
                continue;
            }
            self.blocks_remaining.insert(*key.hash(), (key.height(), batch_start));
            self.filters_matched.insert(*key.hash());
            blocks_needed.insert(key);
            new_blocks_count += 1;
        }

        // Update batch pending_blocks count
        if let Some(batch) = self.active_batches.get_mut(&batch_start) {
            batch.set_pending_blocks(batch.pending_blocks() + new_blocks_count);
        }

        if !blocks_needed.is_empty() {
            events.push(SyncEvent::BlocksNeeded {
                blocks: blocks_needed,
            });
        }

        Ok(events)
    }

    /// Handle notification that new filter headers are available.
    /// Used by both FilterHeadersSyncComplete and FilterHeadersStored events.
    pub(super) async fn handle_new_filter_headers(
        &mut self,
        tip_height: u32,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        self.progress.update_filter_header_tip_height(tip_height);
        self.update_target_height(tip_height);

        match self.state() {
            SyncState::Syncing | SyncState::Synced
                if self.progress.stored_height() < self.progress.filter_header_tip_height() =>
            {
                // Transition back to Syncing so is_synced() returns false
                // until all new filters and matched blocks are fully processed.
                if self.state() == SyncState::Synced {
                    self.set_state(SyncState::Syncing);
                }

                self.filter_pipeline.extend_target(tip_height);
                {
                    let header_storage = self.header_storage.read().await;
                    self.filter_pipeline.send_pending(requests, &*header_storage).await?;
                }

                if self.active_batches.is_empty() {
                    tracing::debug!("Processing new filter (target: {})", tip_height);
                    return self.try_create_lookahead_batches().await;
                }
            }
            SyncState::WaitingForConnections | SyncState::WaitForEvents
                if self.progress.stored_height() < self.progress.filter_header_tip_height() =>
            {
                return self.start_download(requests).await;
            }
            _ => {}
        }
        Ok(vec![])
    }
}

impl<H: BlockHeaderStorage, FH: FilterHeaderStorage, F: FilterStorage, W: WalletInterface>
    std::fmt::Debug for FiltersManager<H, FH, F, W>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FiltersManager").field("progress", &self.progress).finish()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{MessageType, RequestSender};
    use crate::storage::{
        DiskStorageManager, PersistentBlockHeaderStorage, PersistentFilterHeaderStorage,
        PersistentFilterStorage, StorageManager,
    };
    use crate::sync::{ManagerIdentifier, SyncManagerProgress};
    use key_wallet::test_utils::MockWallet;
    use tokio::sync::mpsc::unbounded_channel;

    type TestFiltersManager = FiltersManager<
        PersistentBlockHeaderStorage,
        PersistentFilterHeaderStorage,
        PersistentFilterStorage,
        MockWallet,
    >;
    type TestSyncManager = dyn SyncManager;

    async fn create_test_manager() -> TestFiltersManager {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        FiltersManager::new(
            wallet,
            storage.block_headers(),
            storage.filter_headers(),
            storage.filters(),
        )
        .await
    }

    #[tokio::test]
    async fn test_filters_manager_new() {
        let manager = create_test_manager().await;
        assert_eq!(manager.identifier(), ManagerIdentifier::Filter);
        assert_eq!(manager.state(), SyncState::WaitForEvents);
        assert_eq!(manager.wanted_message_types(), vec![MessageType::CFilter]);
    }

    #[tokio::test]
    async fn test_filters_manager_progress() {
        let mut manager = create_test_manager().await;
        manager.set_state(SyncState::Syncing);
        manager.progress.update_stored_height(500);
        manager.progress.update_target_height(1000);
        manager.progress.add_processed(350);
        manager.progress.add_downloaded(250);
        manager.progress.add_matched(150);

        let manager_ref: &TestSyncManager = &manager;
        let progress = manager_ref.progress();
        if let SyncManagerProgress::Filters(progress) = progress {
            assert_eq!(progress.state(), SyncState::Syncing);
            assert_eq!(progress.stored_height(), 500);
            assert_eq!(progress.target_height(), 1000);
            assert_eq!(progress.processed(), 350);
            assert_eq!(progress.downloaded(), 250);
            assert_eq!(progress.matched(), 150);
            assert!(progress.last_activity().elapsed().as_secs() < 1);
        } else {
            panic!("Expected SyncManagerProgress::Filters");
        }
    }

    #[tokio::test]
    async fn test_max_lookahead_constant() {
        // Verify the constant is set to expected value
        assert_eq!(MAX_LOOKAHEAD_BATCHES, 3);
    }

    #[tokio::test]
    async fn test_batch_commit_blocks_on_pending() {
        let mut manager = create_test_manager().await;
        manager.set_state(SyncState::Syncing);

        // Manually create two batches
        let mut batch1 = FiltersBatch::new(0, 4999, HashMap::new());
        let batch2 = FiltersBatch::new(5000, 9999, HashMap::new());

        // batch1 has pending blocks, batch2 does not
        batch1.set_pending_blocks(1);

        manager.active_batches.insert(0, batch1);
        manager.active_batches.insert(5000, batch2);

        // Try to commit - should not commit anything since batch1 has pending blocks
        manager.try_commit_batches().await.unwrap();
        assert_eq!(manager.active_batches.len(), 2);
        // committed_height stays at initial value since nothing was committed
        assert!(manager.active_batches.contains_key(&0));
    }

    #[tokio::test]
    async fn test_batch_commit_succeeds_when_ready() {
        let mut manager = create_test_manager().await;
        manager.set_state(SyncState::Syncing);

        // Create a batch with no pending blocks, scanned, and rescan complete
        let mut batch1 = FiltersBatch::new(0, 4999, HashMap::new());
        batch1.set_pending_blocks(0);
        batch1.mark_scanned();
        batch1.mark_rescan_complete();

        manager.active_batches.insert(0, batch1);

        // Commit should work
        manager.try_commit_batches().await.unwrap();
        assert_eq!(manager.active_batches.len(), 0);
        assert_eq!(manager.progress.committed_height(), 4999);
    }

    #[tokio::test]
    async fn test_batch_commit_order_preserved() {
        let mut manager = create_test_manager().await;
        manager.set_state(SyncState::Syncing);

        // Create two batches, both ready to commit
        let mut batch1 = FiltersBatch::new(0, 4999, HashMap::new());
        batch1.set_pending_blocks(0);
        batch1.mark_scanned();
        batch1.mark_rescan_complete();

        let mut batch2 = FiltersBatch::new(5000, 9999, HashMap::new());
        batch2.set_pending_blocks(0);
        batch2.mark_scanned();
        batch2.mark_rescan_complete();

        manager.active_batches.insert(5000, batch2); // Insert higher one first
        manager.active_batches.insert(0, batch1);

        // Commit should commit both in order
        manager.try_commit_batches().await.unwrap();
        assert_eq!(manager.active_batches.len(), 0);
        assert_eq!(manager.progress.committed_height(), 9999); // Both committed
    }

    #[tokio::test]
    async fn test_blocks_remaining_tracks_batch() {
        let mut manager = create_test_manager().await;
        manager.set_state(SyncState::Syncing);

        // Add blocks from different batches
        let hash1 = dashcore::block::Header::dummy(0).block_hash();
        let hash2 = dashcore::block::Header::dummy(1).block_hash();

        manager.blocks_remaining.insert(hash1, (100, 0)); // batch 0
        manager.blocks_remaining.insert(hash2, (5100, 5000)); // batch 5000

        // Verify batch association
        assert_eq!(manager.blocks_remaining.get(&hash1), Some(&(100, 0)));
        assert_eq!(manager.blocks_remaining.get(&hash2), Some(&(5100, 5000)));
    }

    #[tokio::test]
    async fn test_is_idle() {
        let mut manager = create_test_manager().await;
        let hash = dashcore::block::Header::dummy(0).block_hash();

        // Fresh manager is idle
        assert!(manager.is_idle());

        // Test each involved field separately
        manager.active_batches.insert(0, FiltersBatch::new(0, 999, HashMap::new()));
        assert!(!manager.is_idle());
        manager.active_batches.clear();

        manager.blocks_remaining.insert(hash, (0, 0));
        assert!(!manager.is_idle());
        manager.blocks_remaining.clear();

        manager.filters_matched.insert(hash);
        assert!(!manager.is_idle());
        manager.filters_matched.clear();

        manager.pending_batches.insert(FiltersBatch::new(0, 999, HashMap::new()));
        assert!(!manager.is_idle());
        manager.pending_batches.clear();

        manager.filter_pipeline.init(0, 999);
        assert!(!manager.is_idle());
        manager.filter_pipeline = FiltersPipeline::new();

        // Populate all fields, then clear_in_flight_state restores idleness
        manager.active_batches.insert(0, FiltersBatch::new(0, 999, HashMap::new()));
        manager.blocks_remaining.insert(hash, (0, 0));
        manager.filters_matched.insert(hash);
        manager.pending_batches.insert(FiltersBatch::new(1000, 1999, HashMap::new()));
        manager.filter_pipeline.init(2000, 2999);
        assert!(!manager.is_idle());

        manager.clear_in_flight_state();
        assert!(manager.is_idle());
    }

    #[tokio::test]
    async fn test_batch_collects_addresses() {
        use crate::sync::filters::batch::FiltersBatch;
        use dashcore::Network;

        let mut batch = FiltersBatch::new(0, 4999, HashMap::new());

        // Initially empty
        assert!(batch.take_collected_addresses().is_empty());

        // Add addresses using test utility
        let addr1 = dashcore::Address::dummy(Network::Testnet, 1);
        let addr2 = dashcore::Address::dummy(Network::Testnet, 2);

        batch.add_addresses([addr1.clone(), addr2.clone()]);

        let collected = batch.take_collected_addresses();
        assert_eq!(collected.len(), 2);
        assert!(collected.contains(&addr1));
        assert!(collected.contains(&addr2));

        // After take, should be empty
        assert!(batch.take_collected_addresses().is_empty());
    }

    #[tokio::test]
    async fn test_start_download_waits_when_filter_headers_insufficient() {
        let mut manager = create_test_manager().await;
        assert_eq!(manager.state(), SyncState::WaitForEvents);

        // Wallet committed to height 100, so scan_start will be 101
        manager.wallet.write().await.update_synced_height(100);
        // Filter headers only reached 50, so its below scan_start
        manager.progress.update_filter_header_tip_height(50);
        // Chain tip higher so the Synced early-return is not taken
        manager.progress.update_target_height(1000);

        let (tx, _rx) = unbounded_channel();
        let events = manager.start_download(&RequestSender::new(tx)).await.unwrap();

        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::WaitForEvents);
        assert!(manager.is_idle());
    }

    #[tokio::test]
    async fn test_start_download_transitions_to_syncing_when_filters_available() {
        let mut manager = create_test_manager().await;
        assert_eq!(manager.state(), SyncState::WaitForEvents);

        // Store headers so send_pending can resolve stop hashes
        let headers = dashcore::block::Header::dummy_batch(0..101);
        manager.header_storage.write().await.store_headers(&headers).await.unwrap();

        // Filter headers available up to 100, wallet at genesis (scan_start = 0)
        manager.progress.update_filter_header_tip_height(100);
        manager.progress.update_target_height(1000);

        let (tx, _rx) = unbounded_channel();
        let events = manager.start_download(&RequestSender::new(tx)).await.unwrap();

        assert_eq!(manager.state(), SyncState::Syncing);
        assert!(!manager.is_idle());
        assert!(events.is_empty());
        // Should have created an initial processing batch spanning scan_start to filter tip
        let batch = manager.active_batches.get(&0).expect("batch at scan_start=0");
        assert_eq!(batch.start_height(), 0);
        assert_eq!(batch.end_height(), 100);
    }

    #[tokio::test]
    async fn test_handle_new_filter_headers_transitions_synced_to_syncing() {
        let mut manager = create_test_manager().await;

        // Simulate fully synced state at height 100
        manager.set_state(SyncState::Synced);
        manager.progress.update_stored_height(100);
        manager.progress.update_filter_header_tip_height(100);
        manager.progress.update_committed_height(100);
        manager.progress.update_target_height(1000);
        // Pipeline target at 150 with no pending batches, so extend_target(150)
        // is a no-op and send_pending returns immediately (no headers needed)
        manager.filter_pipeline.init(151, 150);
        // Active batch prevents try_create_lookahead_batches from running
        manager.active_batches.insert(101, FiltersBatch::new(101, 200, HashMap::new()));

        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        // New filter headers arrive at 150: stored(100) < tip(150)
        let events = manager.handle_new_filter_headers(150, &requests).await.unwrap();

        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::Syncing);
        assert!(!manager.is_idle());
    }
}
