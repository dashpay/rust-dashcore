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
use dashcore::hash_types::FilterHeader;
use key_wallet_manager::wallet_interface::WalletInterface;
use key_wallet_manager::wallet_manager::{check_compact_filters_for_addresses, FilterMatchKey};
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
    pending_batches: BTreeSet<FiltersBatch>,
    /// Next batch start height to store (for filter verification/storage).
    next_batch_to_store: u32,

    // === Multi-batch processing state ===
    /// Active batches being processed (keyed by start_height).
    pub(super) active_batches: BTreeMap<u32, FiltersBatch>,
    /// Height that has been committed to wallet (all blocks up to this height processed).
    committed_height: u32,
    /// Current block height being processed (for progress tracking).
    processing_height: u32,
    /// Blocks remaining that need to be processed.
    /// Maps block_hash -> (height, batch_start) for batch association.
    pub(super) blocks_remaining: BTreeMap<BlockHash, (u32, u32)>,
    /// Block hashes that have been matched and queued for download.
    filters_matched: HashSet<BlockHash>,
    /// New addresses collected from processed blocks, per batch.
    collected_new_addresses: BTreeMap<u32, HashSet<Address>>,
}

impl<H: BlockHeaderStorage, FH: FilterHeaderStorage, F: FilterStorage, W: WalletInterface>
    FiltersManager<H, FH, F, W>
{
    /// Create a new filters manager with the given storage references.
    pub fn new(
        wallet: Arc<RwLock<W>>,
        header_storage: Arc<RwLock<H>>,
        filter_header_storage: Arc<RwLock<FH>>,
        filter_storage: Arc<RwLock<F>>,
    ) -> Self {
        Self {
            progress: FiltersProgress::default(),
            header_storage,
            filter_header_storage,
            filter_storage,
            wallet,
            filter_pipeline: FiltersPipeline::new(),
            pending_batches: BTreeSet::new(),
            next_batch_to_store: 0,
            // Multi-batch processing
            active_batches: BTreeMap::new(),
            committed_height: 0,
            processing_height: 0,
            blocks_remaining: BTreeMap::new(),
            filters_matched: HashSet::new(),
            collected_new_addresses: BTreeMap::new(),
        }
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

    /// Start or resume filter download.
    pub(super) async fn start_download(
        &mut self,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        self.set_state(SyncState::Syncing);
        // Get wallet state
        let (wallet_birth_height, wallet_synced_height) = {
            let wallet = self.wallet.read().await;
            (wallet.earliest_required_height().await, wallet.synced_height())
        };

        // Get stored filters tip
        let stored_filters_tip = self.filter_storage.read().await.filter_tip_height().await?;

        // Get header start height (for checkpoint sync)
        let header_start_height =
            self.header_storage.read().await.get_start_height().await.unwrap_or(0);

        // Calculate scan start (where we need to start processing)
        // Must be at least header_start_height for checkpoint-based sync
        let scan_start = if wallet_synced_height > 0 {
            wallet_birth_height.max(wallet_synced_height + 1)
        } else {
            wallet_birth_height
        }
        .max(header_start_height);

        // Check if already at target (nothing to download)
        if scan_start > self.progress.filter_header_tip_height() {
            // Only emit FiltersSyncComplete if we've also reached the chain tip
            // This prevents premature sync complete while filter headers are still syncing
            if self.progress.current_height() >= self.progress.target_height() {
                self.set_state(SyncState::Synced);
                tracing::info!("Filters already synced to {}", self.progress.target_height());
                return Ok(vec![SyncEvent::FiltersSyncComplete {
                    tip_height: self.progress.current_height(),
                }]);
            }
            // Caught up to available filter headers but chain tip not reached yet
            return Ok(vec![]);
        }

        // Determine download start (where we need to download from)
        // Must be at least header_start_height for checkpoint-based sync
        let download_start = if stored_filters_tip > 0 {
            (stored_filters_tip + 1).max(header_start_height)
        } else {
            scan_start
        };

        // Initialize storage tracking
        // If we have pending batches from a previous run, continue from their boundaries
        // instead of recalculating from storage (which might not reflect in-flight batches)
        if !self.pending_batches.is_empty() {
            let first_pending = self.pending_batches.first().unwrap().start_height();
            tracing::info!(
                "Resuming with {} pending batches, next_batch_to_store staying at {} (first pending: {})",
                self.pending_batches.len(),
                self.next_batch_to_store,
                first_pending
            );
            // Don't reset next_batch_to_store - keep the existing value
        } else {
            tracing::info!(
                "Initializing next_batch_to_store to {} (stored_filters_tip={}, scan_start={})",
                download_start,
                stored_filters_tip,
                scan_start
            );
            self.next_batch_to_store = download_start;
        }

        self.processing_height = scan_start;

        // Initialize download pipeline for all remaining filters
        if download_start <= self.progress.filter_header_tip_height() {
            // Only reinitialize if pipeline is empty - avoid losing in-flight batches
            if self.filter_pipeline.active_count() == 0 && self.pending_batches.is_empty() {
                self.filter_pipeline.init(download_start, self.progress.filter_header_tip_height());
                tracing::info!(
                    "Starting filter download from {} to {} (batch-based processing)",
                    download_start,
                    self.progress.filter_header_tip_height()
                );
            } else {
                // Extend target without resetting state - batches still in flight
                self.filter_pipeline.extend_target(self.progress.filter_header_tip_height());
                tracing::info!(
                    "Resuming filter download to {} (active batches: {}, pending: {})",
                    self.progress.filter_header_tip_height(),
                    self.filter_pipeline.active_count(),
                    self.pending_batches.len()
                );
            }

            let header_storage = self.header_storage.read().await;
            self.filter_pipeline.send_pending(requests, &*header_storage).await?;
            drop(header_storage);
        } else {
            // No new filters to download - initialize pipeline to a "complete" state
            // so it doesn't try to download from its default start height
            self.filter_pipeline.init(download_start, download_start.saturating_sub(1));
            tracing::info!("Rescan mode: no new filters to download, scanning stored filters only");
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
            // Update current_height to reflect stored filters are available
            self.progress.update_current_height(stored_filters_tip);
            self.load_filters(scan_start, end_height).await?
        } else {
            HashMap::new()
        };

        self.active_batches.insert(scan_start, FiltersBatch::new(scan_start, batch_end, filters));
        self.committed_height = scan_start.saturating_sub(1);

        // Only scan if all filters for the batch are already loaded
        if self.progress.current_height() >= batch_end {
            self.scan_batch(scan_start).await
        } else {
            tracing::debug!(
                "Initial batch {}-{}: waiting for filters (current_height={})",
                scan_start,
                batch_end,
                self.progress.current_height()
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
            self.progress.update_current_height(batch.end_height());
            self.next_batch_to_store = batch.end_height() + 1;
        }

        // If we stored any batches, try to process the batch containing the current processing height.
        // This is called only when batches complete, not on every filter
        if !events.is_empty() {
            tracing::debug!(
                "Calling try_process_batch after storing batches (current_height={}, target_height={})",
                self.progress.current_height(),
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

        // If no active batches and all filters downloaded, check if we can transition to Synced
        // Only emit SyncComplete if we've also reached the chain tip (target_height)
        if self.active_batches.is_empty()
            && self.state() == SyncState::Syncing
            && self.progress.current_height() >= self.progress.filter_header_tip_height()
            && self.progress.current_height() >= self.progress.target_height()
        {
            self.set_state(SyncState::Synced);
            tracing::info!("Filter sync complete at height {}", self.progress.current_height());
            events.push(SyncEvent::FiltersSyncComplete {
                tip_height: self.progress.current_height(),
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
                let addresses =
                    self.collected_new_addresses.remove(&batch_start).unwrap_or_default();
                if !addresses.is_empty() {
                    // Need to rescan this batch first
                    events.extend(self.rescan_batch(batch_start, addresses).await?);

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
            self.committed_height = batch.end_height();
            self.wallet.write().await.update_synced_height(batch.end_height());
            self.processing_height = batch.end_height() + 1;

            tracing::info!(
                "Committed batch {}-{}, committed_height now {}",
                batch.start_height(),
                batch.end_height(),
                self.committed_height
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
                !batch.scanned() && self.progress.current_height() >= batch.end_height()
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
            let available_end = self.progress.current_height().min(next_end);
            let filters = if next_start <= available_end {
                self.load_filters(next_start, available_end).await?
            } else {
                HashMap::new()
            };

            self.active_batches
                .insert(next_start, FiltersBatch::new(next_start, next_end, filters));

            // Scan immediately if filters are available
            if self.progress.current_height() >= next_end {
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
                if self.progress.current_height() < self.progress.filter_header_tip_height() =>
            {
                self.filter_pipeline.extend_target(tip_height);
                {
                    let header_storage = self.header_storage.read().await;
                    self.filter_pipeline.send_pending(requests, &*header_storage).await?;
                }

                if self.state() == SyncState::Synced && self.active_batches.is_empty() {
                    tracing::debug!("Processing new filter (target: {})", tip_height);
                    return self.try_create_lookahead_batches().await;
                }
            }
            SyncState::WaitingForConnections | SyncState::WaitForEvents
                if self.progress.current_height() < self.progress.filter_header_tip_height() =>
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
    use crate::network::MessageType;
    use crate::storage::{
        DiskStorageManager, PersistentBlockHeaderStorage, PersistentFilterHeaderStorage,
        PersistentFilterStorage,
    };
    use crate::sync::{ManagerIdentifier, SyncManagerProgress};
    use key_wallet_manager::test_utils::MockWallet;

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
            storage.header_storage(),
            storage.filter_header_storage(),
            storage.filter_storage(),
        )
    }

    #[tokio::test]
    async fn test_filters_manager_new() {
        let manager = create_test_manager().await;
        assert_eq!(manager.identifier(), ManagerIdentifier::Filter);
        assert_eq!(manager.state(), SyncState::Initializing);
        assert_eq!(manager.wanted_message_types(), vec![MessageType::CFilter]);
    }

    #[tokio::test]
    async fn test_filters_manager_progress() {
        let mut manager = create_test_manager().await;
        manager.set_state(SyncState::Syncing);
        manager.progress.update_current_height(500);
        manager.progress.update_target_height(1000);
        manager.progress.add_processed(350);
        manager.progress.add_downloaded(250);
        manager.progress.add_matched(150);

        let manager_ref: &TestSyncManager = &manager;
        let progress = manager_ref.progress();
        if let SyncManagerProgress::Filters(progress) = progress {
            assert_eq!(progress.state(), SyncState::Syncing);
            assert_eq!(progress.current_height(), 500);
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
        assert_eq!(manager.committed_height, 4999);
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
        assert_eq!(manager.committed_height, 9999); // Both committed
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
    async fn test_collected_addresses_per_batch() {
        let manager = create_test_manager().await;

        // Verify collected_new_addresses is a BTreeMap
        assert!(manager.collected_new_addresses.is_empty());
    }
}
