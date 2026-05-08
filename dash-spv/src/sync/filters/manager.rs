//! Filters manager for parallel sync.
//!
//! Downloads compact block filters (BIP 157/158), verifies them against headers,
//! and matches against wallet to identify blocks for download.
//! Emits FiltersStored, FiltersSyncComplete and BlocksNeeded events.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use dashcore::bip158::BlockFilter;
use dashcore::Address;

use super::batch::FiltersBatch;
use super::block_match_tracker::{BlockMatchTracker, BlockTrackResult};
use super::pipeline::FiltersPipeline;
use crate::error::SyncResult;
use crate::network::RequestSender;
use crate::storage::{BlockHeaderStorage, FilterHeaderStorage, FilterStorage};
use crate::sync::filters::util::get_prev_filter_header;
use crate::sync::{FiltersProgress, SyncEvent, SyncManager, SyncState};
use crate::validation::{FilterValidationInput, FilterValidator, Validator};

use crate::sync::progress::ProgressPercentage;
use dashcore::hash_types::FilterHeader;
use key_wallet_manager::WalletInterface;
use key_wallet_manager::{check_compact_filters_for_addresses, FilterMatchKey, WalletId};
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
    /// Per-block tracking state for matched blocks: in-flight blocks awaiting
    /// `BlockProcessed` and the per-wallet record of which wallets already
    /// have a given processed block applied.
    pub(super) tracker: BlockMatchTracker,
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
        let committed_height = wallet.read().await.synced_height();
        let stored_height = filter_storage.read().await.filter_tip_height().await.unwrap_or(0);
        let target_height =
            header_storage.read().await.get_tip().await.map(|t| t.height()).unwrap_or(0);
        let filter_header_tip = filter_header_storage
            .read()
            .await
            .get_filter_tip_height()
            .await
            .ok()
            .flatten()
            .unwrap_or(0);

        let mut initial_progress = FiltersProgress::default();
        initial_progress.update_committed_height(committed_height);
        initial_progress.update_stored_height(stored_height);
        initial_progress.update_target_height(target_height);
        initial_progress.update_filter_header_tip_height(filter_header_tip);

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
            tracker: BlockMatchTracker::new(),
        }
    }

    /// Returns true if there is no in-flight processing state.
    fn is_idle(&self) -> bool {
        self.active_batches.is_empty()
            && self.tracker.is_empty()
            && self.pending_batches.is_empty()
            && self.filter_pipeline.is_idle()
    }

    /// Drop all in-flight processing state so a fresh scan can begin from a
    /// rolled-back `committed_height`. Used by the wallet-rescan trigger in
    /// `tick` when a wallet's `synced_height` falls below the manager's
    /// current scan progress. Distinct from `on_disconnect`, which keeps
    /// in-progress work intact.
    pub(super) fn reset_for_rescan(&mut self) {
        self.active_batches.clear();
        self.tracker.clear();
        self.pending_batches.clear();
        self.filter_pipeline = FiltersPipeline::new();
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

        // Use synced_height for restart recovery instead of
        // last_processed_height, which advances per-block and may exceed committed scan progress.
        let (wallet_birth_height, wallet_committed_height) = {
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

        while let Some((&batch_start, batch)) = self.active_batches.first_key_value() {
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
                // Take per-wallet collected addresses from the batch
                let addresses_by_wallet = self
                    .active_batches
                    .get_mut(&batch_start)
                    .map(|b| b.take_collected_addresses())
                    .unwrap_or_default();

                if !addresses_by_wallet.is_empty() {
                    // Rescan current batch
                    events.extend(self.rescan_batch(batch_start, &addresses_by_wallet).await?);

                    // Also rescan later batches that are already scanned
                    let later_batches: Vec<u32> = self
                        .active_batches
                        .iter()
                        .filter(|(&start, batch)| start > batch_start && batch.scanned())
                        .map(|(&start, _)| start)
                        .collect();

                    for later_start in later_batches {
                        events.extend(self.rescan_batch(later_start, &addresses_by_wallet).await?);
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

            // Commit this batch. Advance per-wallet `synced_height` only for
            // wallets that were behind for this batch at scan time. Already-synced
            // wallets are never touched.
            let batch = self.active_batches.remove(&batch_start).unwrap();
            let end = batch.end_height();
            if end > self.progress.committed_height() {
                self.progress.update_committed_height(end);
                let scanned_wallets = batch.scanned_wallets().clone();
                if !scanned_wallets.is_empty() {
                    let mut wallet = self.wallet.write().await;
                    for wallet_id in &scanned_wallets {
                        wallet.update_wallet_synced_height(wallet_id, end);
                    }
                }
            }
            // Drop processed-wallet records for the committed range. Below the
            // new committed_height a new wallet can only get here via the
            // `tick` rescan trigger, which already wipes the map via
            // `reset_for_rescan`, so older entries can never be consulted.
            self.tracker.prune_at_or_below(end);
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

    /// Rescan a specific batch for newly discovered addresses, attributed per
    /// wallet so each new address is matched only against the filters relevant
    /// to its owning wallet.
    pub(super) async fn rescan_batch(
        &mut self,
        batch_start: u32,
        new_addresses: &HashMap<WalletId, HashSet<Address>>,
    ) -> SyncResult<Vec<SyncEvent>> {
        if new_addresses.is_empty() {
            return Ok(vec![]);
        }

        let Some(batch) = self.active_batches.get(&batch_start) else {
            return Ok(vec![]);
        };

        tracing::info!(
            "Rescan filters ({}-{}) for new addresses across {} wallets",
            batch.start_height(),
            batch.end_height(),
            new_addresses.len()
        );

        if batch.filters().is_empty() {
            return Ok(vec![]);
        }
        let batch_filters = batch.filters();

        // Per-wallet `synced_height` snapshot so heights below the wallet's
        // own progress are skipped during the rescan.
        let synced_heights: HashMap<WalletId, u32> = {
            let wallet = self.wallet.read().await;
            new_addresses.keys().map(|id| (*id, wallet.wallet_synced_height(id))).collect()
        };

        let mut block_to_wallets: BTreeMap<FilterMatchKey, BTreeSet<WalletId>> = BTreeMap::new();
        for (wallet_id, addresses) in new_addresses {
            if addresses.is_empty() {
                continue;
            }
            let addresses_vec: Vec<_> = addresses.iter().cloned().collect();
            let min_synced = synced_heights.get(wallet_id).copied().unwrap_or(0);
            let matches =
                check_compact_filters_for_addresses(batch_filters, addresses_vec, min_synced);
            for key in matches {
                block_to_wallets.entry(key).or_default().insert(*wallet_id);
            }
        }

        let mut events = Vec::new();
        let mut blocks_needed: BTreeMap<FilterMatchKey, BTreeSet<WalletId>> = BTreeMap::new();
        let mut new_blocks_count = 0;

        if !block_to_wallets.is_empty() {
            self.progress.add_matched(block_to_wallets.len() as u32);
        }
        for (key, wallets) in block_to_wallets {
            match self.tracker.track(&key, batch_start, wallets) {
                BlockTrackResult::NewlyTracked {
                    wallets,
                } => {
                    blocks_needed.insert(key, wallets);
                    new_blocks_count += 1;
                }
                BlockTrackResult::InFlight {
                    wallets,
                } => {
                    // Block already on its way; merge late wallet ids into the
                    // pipeline's pending wallet set via a fresh BlocksNeeded.
                    blocks_needed.insert(key, wallets);
                }
                BlockTrackResult::AlreadyProcessed => {}
            }
        }

        // Update batch pending_blocks count for the genuinely new entries only.
        if new_blocks_count > 0 {
            if let Some(batch) = self.active_batches.get_mut(&batch_start) {
                batch.set_pending_blocks(batch.pending_blocks() + new_blocks_count);
            }
            tracing::info!("Rescan found {} additional blocks", new_blocks_count);
        }
        if !blocks_needed.is_empty() {
            events.push(SyncEvent::BlocksNeeded {
                blocks: blocks_needed,
            });
        }

        Ok(events)
    }

    /// Scan a specific batch, matching its filters against each behind-wallet's
    /// addresses individually so already-synced wallets are not redundantly
    /// rescanned.
    async fn scan_batch(&mut self, batch_start: u32) -> SyncResult<Vec<SyncEvent>> {
        let mut events = Vec::new();

        let (batch_end, filters_empty) = {
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
            (batch.end_height(), batch.filters().is_empty())
        };

        // Snapshot per-wallet state for the wallets behind this batch's range.
        // A wallet whose `synced_height >= batch_end` is fully covered and is
        // skipped entirely, its addresses never even get tested against these
        // filters.
        let wallet = self.wallet.read().await;
        let behind = wallet.wallets_behind(batch_end);
        let mut wallet_states: Vec<(WalletId, u32, Vec<Address>)> = Vec::new();
        for wallet_id in &behind {
            let synced = wallet.wallet_synced_height(wallet_id);
            let addresses = wallet.monitored_addresses_for(wallet_id);
            if !addresses.is_empty() {
                wallet_states.push((*wallet_id, synced, addresses));
            }
        }
        drop(wallet);

        // Every behind wallet's coverage advances to `batch_end` once this
        // batch commits. That includes wallets without any monitored
        // addresses: they have nothing to match against these filters, so the
        // batch fully accounts for their range and their `synced_height` must
        // advance to keep `wallets_behind` from listing them on every future
        // batch.
        let scanned_wallets: BTreeSet<WalletId> = behind.clone();

        if let Some(batch) = self.active_batches.get_mut(&batch_start) {
            batch.set_scanned_wallets(scanned_wallets);
        }

        if filters_empty {
            tracing::debug!("scan_batch: batch filters are empty, returning early");
            return Ok(events);
        }

        if wallet_states.is_empty() {
            // No addresses to scan, but `scanned_wallets` was still recorded
            // so any zero-address behind wallets advance at commit.
            tracing::debug!("scan_batch: no behind wallets with monitored addresses");
            return Ok(events);
        }

        // Single-pass union-then-attribute: build the union of all addresses
        // across behind wallets, run the filters once, then for each matched
        // block re-test per-wallet scripts to attribute the match correctly.
        let union_addresses: Vec<Address> =
            wallet_states.iter().flat_map(|(_, _, addrs)| addrs.iter().cloned()).collect();
        let min_synced = wallet_states.iter().map(|(_, synced, _)| *synced).min().unwrap_or(0);

        let block_to_wallets = {
            let Some(batch) = self.active_batches.get(&batch_start) else {
                return Ok(events);
            };
            let batch_filters = batch.filters();

            let matches =
                check_compact_filters_for_addresses(batch_filters, union_addresses, min_synced);
            let mut block_to_wallets: BTreeMap<FilterMatchKey, BTreeSet<WalletId>> =
                BTreeMap::new();
            for key in matches {
                let Some(filter) = batch_filters.get(&key) else {
                    tracing::warn!(
                        "skipping unmatched filter key at height {}: hash {}",
                        key.height(),
                        key.hash()
                    );
                    continue;
                };
                for (wallet_id, wallet_synced, addresses) in &wallet_states {
                    if key.height() <= *wallet_synced {
                        continue;
                    }
                    let scripts: Vec<Vec<u8>> =
                        addresses.iter().map(|a| a.script_pubkey().to_bytes()).collect();
                    let matched = match filter
                        .match_any(key.hash(), scripts.iter().map(|v| v.as_slice()))
                    {
                        Ok(matched) => matched,
                        Err(e) => {
                            tracing::warn!(
                                "filter match_any error during attribution at height {}: {}; treating as non-match",
                                key.height(),
                                e
                            );
                            false
                        }
                    };
                    if matched {
                        block_to_wallets.entry(key.clone()).or_default().insert(*wallet_id);
                    }
                }
            }
            block_to_wallets
        };

        tracing::info!(
            "Batch {}-{}: found {} matching blocks across {} behind wallets",
            batch_start,
            batch_end,
            block_to_wallets.len(),
            wallet_states.len()
        );

        if block_to_wallets.is_empty() {
            return Ok(events);
        }

        self.progress.add_matched(block_to_wallets.len() as u32);

        // Either (re)queue the block via `BlocksNeeded` or skip if every
        // candidate wallet already has it processed. In-flight blocks still
        // re-emit so the BlocksPipeline merges any late-arriving wallet ids.
        let mut blocks_needed: BTreeMap<FilterMatchKey, BTreeSet<WalletId>> = BTreeMap::new();
        let mut new_blocks_count = 0;
        for (key, wallets) in block_to_wallets {
            match self.tracker.track(&key, batch_start, wallets) {
                BlockTrackResult::NewlyTracked {
                    wallets,
                } => {
                    blocks_needed.insert(key, wallets);
                    new_blocks_count += 1;
                }
                BlockTrackResult::InFlight {
                    wallets,
                } => {
                    blocks_needed.insert(key, wallets);
                }
                BlockTrackResult::AlreadyProcessed => {}
            }
        }

        // Update batch pending_blocks count for the genuinely new entries only.
        if new_blocks_count > 0 {
            if let Some(batch) = self.active_batches.get_mut(&batch_start) {
                batch.set_pending_blocks(batch.pending_blocks() + new_blocks_count);
            }
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
            SyncState::WaitingForConnections | SyncState::WaitForEvents => {
                // In-progress work preserved across a disconnect cycle. Don't
                // re-init via `start_download` — that would clobber existing
                // batches. Instead extend the target and let the eventual
                // `start_sync` (driven by `PeersUpdated`) resume from here.
                if !self.active_batches.is_empty() {
                    self.filter_pipeline.extend_target(tip_height);
                    return Ok(vec![]);
                }
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
        BlockHeaderStorage, DiskStorageManager, PersistentBlockHeaderStorage,
        PersistentFilterHeaderStorage, PersistentFilterStorage, StorageManager,
    };
    use crate::sync::{ManagerIdentifier, SyncManagerProgress};
    use dashcore::bip158::BlockFilter;
    use dashcore::Header;
    use dashcore::{Block, Network, Transaction};
    use dashcore_hashes::Hash;
    use key_wallet_manager::test_utils::{
        MockWallet, MockWalletState, MultiMockWallet, MOCK_WALLET_ID,
    };
    use tokio::sync::mpsc::unbounded_channel;

    type TestFiltersManager = FiltersManager<
        PersistentBlockHeaderStorage,
        PersistentFilterHeaderStorage,
        PersistentFilterStorage,
        MockWallet,
    >;
    type MultiTestFiltersManager = FiltersManager<
        PersistentBlockHeaderStorage,
        PersistentFilterHeaderStorage,
        PersistentFilterStorage,
        MultiMockWallet,
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

    async fn create_multi_test_manager(
        wallet: Arc<RwLock<MultiMockWallet>>,
    ) -> MultiTestFiltersManager {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        FiltersManager::new(
            wallet,
            storage.block_headers(),
            storage.filter_headers(),
            storage.filters(),
        )
        .await
    }

    /// Build a real `BlockFilter` for a single-output block paying `address`.
    fn filter_for_address(
        height: u32,
        address: &dashcore::Address,
    ) -> (FilterMatchKey, BlockFilter) {
        let tx = Transaction::dummy(address, 0..0, &[height as u64]);
        let block = Block::dummy(height, vec![tx]);
        let filter = BlockFilter::dummy(&block);
        (FilterMatchKey::new(height, block.block_hash()), filter)
    }

    #[tokio::test]
    async fn test_filters_manager_new() {
        let manager = create_test_manager().await;
        assert_eq!(manager.identifier(), ManagerIdentifier::Filter);
        assert_eq!(manager.state(), SyncState::WaitForEvents);
        assert_eq!(manager.wanted_message_types(), vec![MessageType::CFilter]);
        assert_eq!(manager.progress.committed_height(), 0);
        assert_eq!(manager.progress.stored_height(), 0);
        assert_eq!(manager.progress.target_height(), 0);
        assert_eq!(manager.progress.filter_header_tip_height(), 0);
    }

    #[tokio::test]
    async fn test_filters_manager_new_restores_from_storage() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();

        // Set wallet committed height via last_processed_height (MockWallet default delegates)
        let mut wallet = MockWallet::new();
        wallet.update_wallet_synced_height(&MOCK_WALLET_ID, 50);
        let wallet = Arc::new(RwLock::new(wallet));

        // Pre-populate filter storage with filters at heights 1..=100
        let filters = storage.filters();
        {
            let mut filter_store = filters.write().await;
            for height in 1..=100 {
                filter_store.store_filter(height, &[0u8; 32]).await.unwrap();
            }
        }

        // Pre-populate block header storage with 300 headers for target_height
        let block_headers = Header::dummy_batch(0..300);
        storage.block_headers().write().await.store_headers(&block_headers).await.unwrap();

        // Pre-populate filter header storage with headers at heights 1..=200
        let filter_headers = storage.filter_headers();
        {
            let dummy_headers = vec![FilterHeader::all_zeros(); 200];
            filter_headers
                .write()
                .await
                .store_filter_headers_at_height(&dummy_headers, 1)
                .await
                .unwrap();
        }

        let manager = FiltersManager::new(
            wallet,
            storage.block_headers(),
            storage.filter_headers(),
            storage.filters(),
        )
        .await;

        assert_eq!(manager.progress.committed_height(), 50);
        assert_eq!(manager.progress.stored_height(), 100);
        assert_eq!(manager.progress.target_height(), 299);
        assert_eq!(manager.progress.filter_header_tip_height(), 200);
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
        // No wallets were recorded as scanned for this batch, so the per-wallet
        // synced_height stays at its initial value.
        assert_eq!(manager.wallet.read().await.wallet_synced_height(&MOCK_WALLET_ID), 0);
    }

    #[tokio::test]
    async fn test_batch_commit_advances_only_scanned_wallets() {
        let mut manager = create_test_manager().await;
        manager.set_state(SyncState::Syncing);

        // First batch records MOCK_WALLET_ID as scanned, so its synced_height
        // advances to the batch end on commit.
        let mut batch1 = FiltersBatch::new(0, 4999, HashMap::new());
        batch1.set_pending_blocks(0);
        batch1.mark_scanned();
        batch1.mark_rescan_complete();
        batch1.set_scanned_wallets(BTreeSet::from([MOCK_WALLET_ID]));
        manager.active_batches.insert(0, batch1);

        manager.try_commit_batches().await.unwrap();
        assert_eq!(manager.progress.committed_height(), 4999);
        assert_eq!(manager.wallet.read().await.wallet_synced_height(&MOCK_WALLET_ID), 4999);

        // Second batch leaves scanned_wallets empty (nothing to scan in this
        // range), so the per-wallet synced_height stays put even though the
        // committed_height advances.
        let mut batch2 = FiltersBatch::new(5000, 9999, HashMap::new());
        batch2.set_pending_blocks(0);
        batch2.mark_scanned();
        batch2.mark_rescan_complete();
        manager.active_batches.insert(5000, batch2);

        manager.try_commit_batches().await.unwrap();
        assert_eq!(manager.progress.committed_height(), 9999);
        assert_eq!(manager.wallet.read().await.wallet_synced_height(&MOCK_WALLET_ID), 4999);
    }

    /// Two wallets in the same batch: only the wallet recorded in
    /// `scanned_wallets` advances, the other stays put even after commit.
    #[tokio::test]
    async fn test_batch_commit_advances_only_recorded_wallet_with_two_wallets() {
        let wallet_a: WalletId = [0xAA; 32];
        let wallet_b: WalletId = [0xBB; 32];
        let multi = MultiMockWallet::new();
        let multi = Arc::new(RwLock::new(multi));
        {
            let mut w = multi.write().await;
            w.insert_wallet(wallet_a, MockWalletState::default());
            w.insert_wallet(wallet_b, MockWalletState::default());
        }
        let mut manager = create_multi_test_manager(multi.clone()).await;
        manager.set_state(SyncState::Syncing);

        // Batch records only wallet_a as scanned. wallet_b is excluded.
        let mut batch = FiltersBatch::new(0, 4999, HashMap::new());
        batch.set_pending_blocks(0);
        batch.mark_scanned();
        batch.mark_rescan_complete();
        batch.set_scanned_wallets(BTreeSet::from([wallet_a]));
        manager.active_batches.insert(0, batch);

        manager.try_commit_batches().await.unwrap();
        assert_eq!(manager.progress.committed_height(), 4999);
        assert_eq!(multi.read().await.wallet_synced_height(&wallet_a), 4999);
        assert_eq!(multi.read().await.wallet_synced_height(&wallet_b), 0);
    }

    /// `scan_batch` with two wallets at different `synced_height` values:
    /// only the wallet whose synced_height is below the matching block's
    /// height should be attributed.
    #[tokio::test]
    async fn test_scan_batch_attributes_per_wallet_height() {
        let wallet_low: WalletId = [0x01; 32];
        let wallet_high: WalletId = [0x02; 32];
        let address_low = dashcore::Address::dummy(Network::Regtest, 1);
        let address_high = dashcore::Address::dummy(Network::Regtest, 2);

        let multi = MultiMockWallet::new();
        let multi = Arc::new(RwLock::new(multi));
        {
            let mut w = multi.write().await;
            // wallet_low is behind: synced_height=10, will see filters above 10.
            w.insert_wallet(
                wallet_low,
                MockWalletState {
                    addresses: vec![address_low.clone()],
                    synced_height: 10,
                    last_processed_height: 10,
                },
            );
            // wallet_high is mostly synced: synced_height=50, only sees > 50.
            w.insert_wallet(
                wallet_high,
                MockWalletState {
                    addresses: vec![address_high.clone()],
                    synced_height: 50,
                    last_processed_height: 50,
                },
            );
        }
        let mut manager = create_multi_test_manager(multi).await;
        manager.set_state(SyncState::Syncing);

        // Build a batch with three filters: at 30 paying wallet_low's address,
        // at 60 paying wallet_high's address, at 70 paying wallet_low's address.
        let mut filters: HashMap<FilterMatchKey, BlockFilter> = HashMap::new();
        let (key_30, f_30) = filter_for_address(30, &address_low);
        let (key_60, f_60) = filter_for_address(60, &address_high);
        let (key_70, f_70) = filter_for_address(70, &address_low);
        filters.insert(key_30.clone(), f_30);
        filters.insert(key_60.clone(), f_60);
        filters.insert(key_70.clone(), f_70);

        let mut batch = FiltersBatch::new(0, 99, filters);
        batch.mark_verified();
        manager.active_batches.insert(0, batch);
        manager.progress.update_stored_height(99);

        let events = manager.scan_batch(0).await.unwrap();

        // Find the BlocksNeeded event.
        let blocks = events
            .iter()
            .find_map(|e| match e {
                SyncEvent::BlocksNeeded {
                    blocks,
                } => Some(blocks),
                _ => None,
            })
            .expect("BlocksNeeded event");

        // Block at 30 only attributable to wallet_low (height <= wallet_high.synced)
        let attr_30 = blocks.get(&key_30).expect("entry for height 30");
        assert!(attr_30.contains(&wallet_low));
        assert!(!attr_30.contains(&wallet_high));

        // Block at 60 only attributable to wallet_high (matches its address);
        // wallet_low's address does not match so it shouldn't be there either.
        let attr_60 = blocks.get(&key_60).expect("entry for height 60");
        assert!(attr_60.contains(&wallet_high));
        assert!(!attr_60.contains(&wallet_low));

        // Block at 70 only attributable to wallet_low: matches wallet_low's
        // address, and wallet_high's address does not match this filter.
        let attr_70 = blocks.get(&key_70).expect("entry for height 70");
        assert!(attr_70.contains(&wallet_low));
        assert!(!attr_70.contains(&wallet_high));
    }

    /// `rescan_batch` with multiple wallets in `addresses_by_wallet`:
    /// each wallet's new addresses are matched independently and the
    /// attribution is correct in the emitted `BlocksNeeded`.
    #[tokio::test]
    async fn test_rescan_batch_attributes_per_wallet_addresses() {
        let wallet_a: WalletId = [0x0A; 32];
        let wallet_b: WalletId = [0x0B; 32];
        let address_a = dashcore::Address::dummy(Network::Regtest, 11);
        let address_b = dashcore::Address::dummy(Network::Regtest, 22);

        let multi = MultiMockWallet::new();
        let multi = Arc::new(RwLock::new(multi));
        {
            let mut w = multi.write().await;
            w.insert_wallet(wallet_a, MockWalletState::default());
            w.insert_wallet(wallet_b, MockWalletState::default());
        }
        let mut manager = create_multi_test_manager(multi).await;
        manager.set_state(SyncState::Syncing);

        let mut filters: HashMap<FilterMatchKey, BlockFilter> = HashMap::new();
        let (key_a, f_a) = filter_for_address(15, &address_a);
        let (key_b, f_b) = filter_for_address(25, &address_b);
        filters.insert(key_a.clone(), f_a);
        filters.insert(key_b.clone(), f_b);

        let mut batch = FiltersBatch::new(0, 99, filters);
        batch.mark_verified();
        manager.active_batches.insert(0, batch);

        let mut new_addresses: HashMap<WalletId, HashSet<Address>> = HashMap::new();
        new_addresses.insert(wallet_a, HashSet::from([address_a]));
        new_addresses.insert(wallet_b, HashSet::from([address_b]));

        let events = manager.rescan_batch(0, &new_addresses).await.unwrap();

        let blocks = events
            .iter()
            .find_map(|e| match e {
                SyncEvent::BlocksNeeded {
                    blocks,
                } => Some(blocks),
                _ => None,
            })
            .expect("BlocksNeeded event");

        let attr_a = blocks.get(&key_a).expect("entry for wallet_a's match");
        assert!(attr_a.contains(&wallet_a));
        assert!(!attr_a.contains(&wallet_b));

        let attr_b = blocks.get(&key_b).expect("entry for wallet_b's match");
        assert!(attr_b.contains(&wallet_b));
        assert!(!attr_b.contains(&wallet_a));
    }

    /// `rescan_batch` honours each wallet's own `synced_height`: a new
    /// address belonging to a wallet that has already advanced past a height
    /// must not produce a `BlocksNeeded` for that height, even when the
    /// filter for that height matches the new address. Two wallets at
    /// different heights are exercised so that both the include-above and
    /// skip-below paths run.
    #[tokio::test]
    async fn test_rescan_batch_skips_below_per_wallet_synced_height() {
        let wallet_low: WalletId = [0xA1; 32];
        let wallet_high: WalletId = [0xA2; 32];
        let address_low = dashcore::Address::dummy(Network::Regtest, 41);
        let address_high = dashcore::Address::dummy(Network::Regtest, 42);

        let multi = MultiMockWallet::new();
        let multi = Arc::new(RwLock::new(multi));
        {
            let mut w = multi.write().await;
            w.insert_wallet(
                wallet_low,
                MockWalletState {
                    addresses: vec![],
                    synced_height: 20,
                    last_processed_height: 20,
                },
            );
            w.insert_wallet(
                wallet_high,
                MockWalletState {
                    addresses: vec![],
                    synced_height: 60,
                    last_processed_height: 60,
                },
            );
        }
        let mut manager = create_multi_test_manager(multi).await;
        manager.set_state(SyncState::Syncing);

        // Filters at 30 (matches wallet_low) and 70 (matches wallet_high).
        // For wallet_low (synced=20), height 30 is fresh and 70 is also fresh
        // since 70 > 20. For wallet_high (synced=60), height 30 is below its
        // synced_height so it must be skipped, while 70 is fresh.
        let (key_30, f_30) = filter_for_address(30, &address_low);
        let (key_70, f_70) = filter_for_address(70, &address_high);
        let mut filters: HashMap<FilterMatchKey, BlockFilter> = HashMap::new();
        filters.insert(key_30.clone(), f_30);
        filters.insert(key_70.clone(), f_70);

        let mut batch = FiltersBatch::new(0, 99, filters);
        batch.mark_verified();
        manager.active_batches.insert(0, batch);

        // wallet_high also "discovers" address_low to demonstrate that even
        // when a new address would match a low height, the per-wallet
        // synced_height filter prevents emitting it.
        let mut new_addresses: HashMap<WalletId, HashSet<Address>> = HashMap::new();
        new_addresses.insert(wallet_low, HashSet::from([address_low.clone()]));
        new_addresses.insert(wallet_high, HashSet::from([address_low.clone(), address_high]));

        let events = manager.rescan_batch(0, &new_addresses).await.unwrap();

        let blocks = events
            .iter()
            .find_map(|e| match e {
                SyncEvent::BlocksNeeded {
                    blocks,
                } => Some(blocks),
                _ => None,
            })
            .expect("BlocksNeeded event");

        // wallet_low must see height 30, wallet_high must NOT (synced=60>30).
        let attr_30 = blocks.get(&key_30).expect("entry at height 30 for wallet_low");
        assert!(attr_30.contains(&wallet_low));
        assert!(!attr_30.contains(&wallet_high));

        // wallet_high must see height 70 since 70 > 60.
        let attr_70 = blocks.get(&key_70).expect("entry at height 70 for wallet_high");
        assert!(attr_70.contains(&wallet_high));
    }

    /// `scan_batch` for a behind wallet with no monitored addresses still
    /// records the wallet in `scanned_wallets` so its `synced_height`
    /// advances at commit. Otherwise zero-address wallets would be listed by
    /// `wallets_behind` on every batch forever.
    #[tokio::test]
    async fn test_scan_batch_advances_zero_address_wallet() {
        let wallet_id: WalletId = [0xCC; 32];
        let multi = MultiMockWallet::new();
        let multi = Arc::new(RwLock::new(multi));
        {
            let mut w = multi.write().await;
            w.insert_wallet(wallet_id, MockWalletState::default());
        }
        let mut manager = create_multi_test_manager(multi.clone()).await;
        manager.set_state(SyncState::Syncing);

        // Batch with one filter at height 50 (irrelevant: wallet has no addresses).
        let mut filters: HashMap<FilterMatchKey, BlockFilter> = HashMap::new();
        let throwaway_address = dashcore::Address::dummy(Network::Regtest, 99);
        let (key, filter) = filter_for_address(50, &throwaway_address);
        filters.insert(key, filter);

        let mut batch = FiltersBatch::new(0, 99, filters);
        batch.mark_verified();
        manager.active_batches.insert(0, batch);
        manager.progress.update_stored_height(99);

        let events = manager.scan_batch(0).await.unwrap();
        assert!(events.is_empty(), "no addresses should mean no BlocksNeeded events");

        // Mark batch ready so commit can run, then commit.
        if let Some(b) = manager.active_batches.get_mut(&0) {
            b.set_pending_blocks(0);
            b.mark_rescan_complete();
        }
        manager.try_commit_batches().await.unwrap();

        // Wallet had no addresses, but it was behind, so its synced_height
        // advances to the batch end after commit.
        assert_eq!(multi.read().await.wallet_synced_height(&wallet_id), 99);
    }

    /// `scan_batch` after a runtime-added wallet whose address matches a
    /// block already in flight must re-emit `BlocksNeeded` so the
    /// `BlocksPipeline` merges the new wallet id into the pending set.
    #[tokio::test]
    async fn test_scan_batch_in_flight_re_emits_for_late_wallet() {
        let wallet_id: WalletId = [0xDD; 32];
        let address = dashcore::Address::dummy(Network::Regtest, 7);

        let multi = MultiMockWallet::new();
        let multi = Arc::new(RwLock::new(multi));
        {
            let mut w = multi.write().await;
            w.insert_wallet(
                wallet_id,
                MockWalletState {
                    addresses: vec![address.clone()],
                    synced_height: 0,
                    last_processed_height: 0,
                },
            );
        }
        let mut manager = create_multi_test_manager(multi).await;
        manager.set_state(SyncState::Syncing);

        // One matching filter at height 40.
        let (key_40, f_40) = filter_for_address(40, &address);
        let mut filters: HashMap<FilterMatchKey, BlockFilter> = HashMap::new();
        filters.insert(key_40.clone(), f_40);

        let mut batch = FiltersBatch::new(0, 99, filters);
        batch.mark_verified();
        manager.active_batches.insert(0, batch);
        manager.progress.update_stored_height(99);

        // Pre-seed the tracker so `tracker.track` returns InFlight.
        manager.tracker.track(&key_40, 0, BTreeSet::from([wallet_id]));

        let events = manager.scan_batch(0).await.unwrap();

        let blocks = events
            .iter()
            .find_map(|e| match e {
                SyncEvent::BlocksNeeded {
                    blocks,
                } => Some(blocks),
                _ => None,
            })
            .expect("InFlight path must still emit BlocksNeeded for wallet-set merge");
        let attribution = blocks.get(&key_40).expect("entry for the in-flight block");
        assert!(attribution.contains(&wallet_id));
    }

    /// `scan_batch` `AlreadyProcessed` path: when every candidate wallet has
    /// already had this block processed, the block is skipped (no
    /// `BlocksNeeded`).
    #[tokio::test]
    async fn test_scan_batch_already_processed_is_skipped() {
        let wallet_id: WalletId = [0xEE; 32];
        let address = dashcore::Address::dummy(Network::Regtest, 8);

        let multi = MultiMockWallet::new();
        let multi = Arc::new(RwLock::new(multi));
        {
            let mut w = multi.write().await;
            w.insert_wallet(
                wallet_id,
                MockWalletState {
                    addresses: vec![address.clone()],
                    synced_height: 0,
                    last_processed_height: 0,
                },
            );
        }
        let mut manager = create_multi_test_manager(multi).await;
        manager.set_state(SyncState::Syncing);

        let (key_40, f_40) = filter_for_address(40, &address);
        let mut filters: HashMap<FilterMatchKey, BlockFilter> = HashMap::new();
        filters.insert(key_40.clone(), f_40);

        let mut batch = FiltersBatch::new(0, 99, filters);
        batch.mark_verified();
        manager.active_batches.insert(0, batch);
        manager.progress.update_stored_height(99);

        // Pre-record processing for the only candidate wallet so the residual
        // is empty and `tracker.track` returns `AlreadyProcessed`.
        manager.tracker.record_processed(40, *key_40.hash(), &BTreeSet::from([wallet_id]));

        let events = manager.scan_batch(0).await.unwrap();
        let has_blocks_needed = events.iter().any(|e| matches!(e, SyncEvent::BlocksNeeded { .. }));
        assert!(!has_blocks_needed, "AlreadyProcessed must not emit BlocksNeeded");
    }

    /// `scan_batch` for a wallet added at runtime whose address matches a
    /// block already processed for another wallet must re-emit `BlocksNeeded`
    /// with only the late wallet in the attribution set so the block reloads
    /// from storage and applies for the late wallet without disturbing the
    /// already-processed one.
    #[tokio::test]
    async fn test_scan_batch_late_wallet_recovers_already_processed_block() {
        let early: WalletId = [0xE1; 32];
        let late: WalletId = [0xE2; 32];
        let address = dashcore::Address::dummy(Network::Regtest, 9);

        let multi = MultiMockWallet::new();
        let multi = Arc::new(RwLock::new(multi));
        {
            let mut w = multi.write().await;
            w.insert_wallet(
                early,
                MockWalletState {
                    addresses: vec![address.clone()],
                    synced_height: 0,
                    last_processed_height: 0,
                },
            );
            w.insert_wallet(
                late,
                MockWalletState {
                    addresses: vec![address.clone()],
                    synced_height: 0,
                    last_processed_height: 0,
                },
            );
        }
        let mut manager = create_multi_test_manager(multi).await;
        manager.set_state(SyncState::Syncing);

        let (key_40, f_40) = filter_for_address(40, &address);
        let mut filters: HashMap<FilterMatchKey, BlockFilter> = HashMap::new();
        filters.insert(key_40.clone(), f_40);

        let mut batch = FiltersBatch::new(0, 99, filters);
        batch.mark_verified();
        manager.active_batches.insert(0, batch);
        manager.progress.update_stored_height(99);

        // The early wallet has already had this block applied. The late
        // wallet has not. Both wallets' addresses match the filter at 40.
        manager.tracker.record_processed(40, *key_40.hash(), &BTreeSet::from([early]));

        let events = manager.scan_batch(0).await.unwrap();
        let blocks = events
            .iter()
            .find_map(|e| match e {
                SyncEvent::BlocksNeeded {
                    blocks,
                } => Some(blocks),
                _ => None,
            })
            .expect("late wallet must trigger a BlocksNeeded re-emit");
        let attribution = blocks.get(&key_40).expect("entry for the recovered block");
        assert!(attribution.contains(&late), "late wallet must receive the block");
        assert!(
            !attribution.contains(&early),
            "early wallet was already processed for this block, must be excluded"
        );
    }

    /// `try_commit_batches` prunes `processed_blocks_per_wallet` entries at
    /// or below the new committed_height, since they cannot be reached again
    /// without `reset_for_rescan` wiping the map outright.
    #[tokio::test]
    async fn test_commit_prunes_processed_blocks_per_wallet() {
        let mut manager = create_test_manager().await;
        manager.set_state(SyncState::Syncing);

        let wallet_id: WalletId = [0xFA; 32];
        let hash_in = dashcore::block::Header::dummy(0).block_hash();
        let hash_out = dashcore::block::Header::dummy(1).block_hash();
        let key_in = FilterMatchKey::new(2500, hash_in);
        let key_out = FilterMatchKey::new(7500, hash_out);
        manager.tracker.record_processed(2500, hash_in, &BTreeSet::from([wallet_id]));
        manager.tracker.record_processed(7500, hash_out, &BTreeSet::from([wallet_id]));

        // Batch 0..=4999 is ready to commit; pruning drops the 2500 entry but
        // keeps the 7500 entry which sits above the new committed_height.
        let mut batch = FiltersBatch::new(0, 4999, HashMap::new());
        batch.set_pending_blocks(0);
        batch.mark_scanned();
        batch.mark_rescan_complete();
        manager.active_batches.insert(0, batch);

        manager.try_commit_batches().await.unwrap();

        assert_eq!(manager.progress.committed_height(), 4999);
        // The 2500 record is gone: a fresh `track` for the same wallet
        // re-tracks the block instead of returning `AlreadyProcessed`.
        assert!(matches!(
            manager.tracker.track(&key_in, 0, BTreeSet::from([wallet_id])),
            BlockTrackResult::NewlyTracked { .. }
        ));
        // The 7500 record survives above the committed height.
        assert_eq!(
            manager.tracker.track(&key_out, 0, BTreeSet::from([wallet_id])),
            BlockTrackResult::AlreadyProcessed
        );
    }

    /// `tick` rescan with a wallet that has a non-zero `synced_height`: the
    /// batch must start at `synced_height + 1`, not at genesis.
    #[tokio::test]
    async fn test_tick_rescans_from_wallet_synced_height_not_genesis() {
        let mut manager = create_test_manager().await;

        // Wallet sits at synced_height=150, manager committed at 300, so
        // the wallet falls behind and the rescan trigger fires.
        manager.wallet.write().await.update_wallet_synced_height(&MOCK_WALLET_ID, 150);
        manager.set_state(SyncState::Synced);
        manager.progress.update_committed_height(300);
        manager.progress.update_stored_height(300);
        manager.progress.update_filter_header_tip_height(300);
        manager.progress.update_target_height(300);

        // Headers must exist in storage so start_download can resolve them.
        let headers = dashcore::block::Header::dummy_batch(0..301);
        manager.header_storage.write().await.store_headers(&headers).await.unwrap();

        let (tx, _rx) = unbounded_channel();
        let _ = manager.tick(&RequestSender::new(tx)).await.unwrap();

        // Batch must start at 151, not at 0.
        assert!(manager.active_batches.contains_key(&151));
        assert!(!manager.active_batches.contains_key(&0));
    }

    /// scan_batch's union-then-attribute pass must not falsely attribute a
    /// block to a wallet whose own address does not actually match the
    /// filter, even if the union pass picked up the block.
    #[tokio::test]
    async fn test_scan_batch_attribution_excludes_non_matching_wallet() {
        let wallet_a: WalletId = [0xAA; 32];
        let wallet_b: WalletId = [0xBB; 32];
        let address_a = dashcore::Address::dummy(Network::Regtest, 31);
        let address_b = dashcore::Address::dummy(Network::Regtest, 32);

        let multi = MultiMockWallet::new();
        let multi = Arc::new(RwLock::new(multi));
        {
            let mut w = multi.write().await;
            w.insert_wallet(
                wallet_a,
                MockWalletState {
                    addresses: vec![address_a.clone()],
                    synced_height: 0,
                    last_processed_height: 0,
                },
            );
            w.insert_wallet(
                wallet_b,
                MockWalletState {
                    addresses: vec![address_b.clone()],
                    synced_height: 0,
                    last_processed_height: 0,
                },
            );
        }
        let mut manager = create_multi_test_manager(multi).await;
        manager.set_state(SyncState::Syncing);

        // Filter at height 40 only matches address_a. address_b is in the
        // union but does not match this specific filter, so the attribution
        // pass must exclude wallet_b.
        let (key_40, f_40) = filter_for_address(40, &address_a);
        let mut filters: HashMap<FilterMatchKey, BlockFilter> = HashMap::new();
        filters.insert(key_40.clone(), f_40);

        let mut batch = FiltersBatch::new(0, 99, filters);
        batch.mark_verified();
        manager.active_batches.insert(0, batch);
        manager.progress.update_stored_height(99);

        let events = manager.scan_batch(0).await.unwrap();
        let blocks = events
            .iter()
            .find_map(|e| match e {
                SyncEvent::BlocksNeeded {
                    blocks,
                } => Some(blocks),
                _ => None,
            })
            .expect("BlocksNeeded event");
        let attribution = blocks.get(&key_40).expect("entry for the matching block");
        assert!(attribution.contains(&wallet_a));
        assert!(!attribution.contains(&wallet_b));
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

        let wallet: WalletId = [1; 32];
        let hash1 = dashcore::block::Header::dummy(0).block_hash();
        let hash2 = dashcore::block::Header::dummy(1).block_hash();

        // Track blocks from two different batches.
        manager.tracker.track(&FilterMatchKey::new(100, hash1), 0, BTreeSet::from([wallet]));
        manager.tracker.track(&FilterMatchKey::new(5100, hash2), 5000, BTreeSet::from([wallet]));

        // Each block round-trips its (height, batch_start) on `finish_in_flight`.
        assert_eq!(manager.tracker.finish_in_flight(&hash1), Some((100, 0)));
        assert_eq!(manager.tracker.finish_in_flight(&hash2), Some((5100, 5000)));
    }

    #[tokio::test]
    async fn test_track_block_match_per_wallet_residual() {
        let mut manager = create_test_manager().await;
        let hash = dashcore::block::Header::dummy(0).block_hash();
        let key = FilterMatchKey::new(100, hash);
        let wallet_a: WalletId = [0xA1; 32];
        let wallet_b: WalletId = [0xB2; 32];

        // First match for {A}: nothing tracked yet, helper records the block.
        assert_eq!(
            manager.tracker.track(&key, 0, BTreeSet::from([wallet_a])),
            BlockTrackResult::NewlyTracked {
                wallets: BTreeSet::from([wallet_a])
            }
        );

        // Second match for {A} while still in flight: residual is {A} (no
        // processing has been recorded yet), so InFlight re-emits to merge
        // late-arriving wallet ids into the pipeline's pending set.
        assert_eq!(
            manager.tracker.track(&key, 0, BTreeSet::from([wallet_a])),
            BlockTrackResult::InFlight {
                wallets: BTreeSet::from([wallet_a])
            }
        );

        // Block is delivered and processed for {A}. Round-trip the (height,
        // batch_start) tuple while removing the in-flight entry, then record
        // the processing.
        assert_eq!(manager.tracker.finish_in_flight(&hash), Some((100, 0)));
        manager.tracker.record_processed(100, hash, &BTreeSet::from([wallet_a]));

        // Late-added wallet B's filter matches the same block. A is already
        // processed, B is not — residual is {B} and it gets re-queued via
        // NewlyTracked so the block reloads from storage and applies for B
        // only.
        assert_eq!(
            manager.tracker.track(&key, 5000, BTreeSet::from([wallet_a, wallet_b])),
            BlockTrackResult::NewlyTracked {
                wallets: BTreeSet::from([wallet_b])
            }
        );
        assert_eq!(manager.tracker.finish_in_flight(&hash), Some((100, 5000)));

        // After B is also processed, a third match including only A and B
        // returns AlreadyProcessed since both are covered.
        manager.tracker.record_processed(100, hash, &BTreeSet::from([wallet_b]));
        assert_eq!(
            manager.tracker.track(&key, 5000, BTreeSet::from([wallet_a, wallet_b])),
            BlockTrackResult::AlreadyProcessed
        );
        assert!(manager.tracker.finish_in_flight(&hash).is_none());
    }

    #[tokio::test]
    async fn test_is_idle() {
        let mut manager = create_test_manager().await;
        let hash = dashcore::block::Header::dummy(0).block_hash();
        let key = FilterMatchKey::new(100, hash);
        let wallet_id: WalletId = [0xCC; 32];

        // Fresh manager is idle
        assert!(manager.is_idle());

        // Test each involved field separately
        manager.active_batches.insert(0, FiltersBatch::new(0, 999, HashMap::new()));
        assert!(!manager.is_idle());
        manager.active_batches.clear();

        manager.tracker.track(&key, 0, BTreeSet::from([wallet_id]));
        assert!(!manager.is_idle());
        manager.tracker.clear();

        manager.tracker.record_processed(100, hash, &BTreeSet::from([wallet_id]));
        assert!(!manager.is_idle());
        manager.tracker.clear();

        manager.pending_batches.insert(FiltersBatch::new(0, 999, HashMap::new()));
        assert!(!manager.is_idle());
        manager.pending_batches.clear();

        manager.filter_pipeline.init(0, 999);
        assert!(!manager.is_idle());
        manager.filter_pipeline = FiltersPipeline::new();

        // Populate all fields, then reset_for_rescan restores idleness
        manager.active_batches.insert(0, FiltersBatch::new(0, 999, HashMap::new()));
        manager.tracker.track(&key, 0, BTreeSet::from([wallet_id]));
        manager.tracker.record_processed(100, hash, &BTreeSet::from([wallet_id]));
        manager.pending_batches.insert(FiltersBatch::new(1000, 1999, HashMap::new()));
        manager.filter_pipeline.init(2000, 2999);
        assert!(!manager.is_idle());

        manager.reset_for_rescan();
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
        let wallet_id: WalletId = [7; 32];

        batch.add_addresses_for_wallet(wallet_id, [addr1.clone(), addr2.clone()]);

        let collected = batch.take_collected_addresses();
        let for_wallet = collected.get(&wallet_id).expect("wallet entry");
        assert_eq!(for_wallet.len(), 2);
        assert!(for_wallet.contains(&addr1));
        assert!(for_wallet.contains(&addr2));

        // After take, should be empty
        assert!(batch.take_collected_addresses().is_empty());
    }

    #[tokio::test]
    async fn test_start_download_waits_when_filter_headers_insufficient() {
        let mut manager = create_test_manager().await;
        assert_eq!(manager.state(), SyncState::WaitForEvents);

        // Wallet committed to height 100, so scan_start will be 101
        manager.wallet.write().await.update_wallet_synced_height(&MOCK_WALLET_ID, 100);
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

    #[tokio::test]
    async fn test_handle_new_filter_headers_synced_restart() {
        let mut manager = create_test_manager().await;

        // Store block headers so start_download can resolve heights
        let headers = dashcore::block::Header::dummy_batch(0..101);
        manager.header_storage.write().await.store_headers(&headers).await.unwrap();

        // Simulate restart where everything is already synced but state is WaitForEvents.
        // committed == stored == filter_header_tip — start_download detects synced state.
        manager.set_state(SyncState::WaitForEvents);
        manager.wallet.write().await.update_wallet_synced_height(&MOCK_WALLET_ID, 100);
        manager.progress.update_committed_height(100);
        manager.progress.update_stored_height(100);
        manager.progress.update_filter_header_tip_height(100);
        manager.progress.update_target_height(100);

        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        let events = manager.handle_new_filter_headers(100, &requests).await.unwrap();

        assert_eq!(manager.state(), SyncState::Synced);
        assert!(
            events.iter().any(|e| matches!(
                e,
                SyncEvent::FiltersSyncComplete {
                    tip_height: 100
                }
            )),
            "expected FiltersSyncComplete(100), got {:?}",
            events
        );
        assert!(manager.active_batches.is_empty());
    }

    #[tokio::test]
    async fn test_handle_new_filter_headers_stays_synced_when_already_synced() {
        let mut manager = create_test_manager().await;

        // Already in Synced state with matching heights — should stay Synced without
        // emitting duplicate events.
        manager.set_state(SyncState::Synced);
        manager.progress.update_committed_height(100);
        manager.progress.update_stored_height(100);
        manager.progress.update_filter_header_tip_height(100);
        manager.progress.update_target_height(100);
        manager.filter_pipeline.init(101, 100);

        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        let events = manager.handle_new_filter_headers(100, &requests).await.unwrap();

        assert_eq!(manager.state(), SyncState::Synced);
        assert!(events.is_empty());
    }

    /// A wallet whose `synced_height` sits below the manager's `committed_height`
    /// must trigger a rescan from the wallet's height. This simulates a wallet
    /// being added at runtime behind current scan progress.
    #[tokio::test]
    async fn test_tick_rescans_when_wallet_falls_behind_committed() {
        let mut manager = create_test_manager().await;

        // Set up a single address on the wallet and a real matching filter at
        // height 50 so scan_batch can emit a `BlocksNeeded` for it on rescan.
        let address = dashcore::Address::dummy(Network::Regtest, 7);
        manager.wallet.write().await.set_addresses(vec![address.clone()]);

        // Build matching block + filter at height 50.
        let tx = Transaction::dummy(&address, 0..0, &[50u64]);
        let block_at_50 = Block::dummy(50, vec![tx]);
        let filter_at_50 = BlockFilter::dummy(&block_at_50);

        // Headers must form a contiguous range so the storage segment is
        // fully populated. Only the height-50 entry needs to be the real
        // header; the rest are dummies and never get matched against.
        let mut headers: Vec<dashcore::Header> = dashcore::block::Header::dummy_batch(0..201);
        headers[50] = block_at_50.header;
        manager.header_storage.write().await.store_headers(&headers).await.unwrap();

        // Persist a filter at every height in 0..=100 so `load_filters` over
        // the initial batch range succeeds. Non-matching heights get a
        // throwaway filter, only height 50 gets the address-matching one.
        let mut filter_store = manager.filter_storage.write().await;
        let dummy_filter = BlockFilter::new(&[0u8; 32]);
        for h in 0..=100u32 {
            if h == 50 {
                filter_store.store_filter(h, &filter_at_50.content).await.unwrap();
            } else {
                filter_store.store_filter(h, &dummy_filter.content).await.unwrap();
            }
        }
        drop(filter_store);

        // Manager believes filters are committed up to 100. Filter headers
        // and target are pinned at 100 too so start_download immediately
        // scans the freshly created batch instead of waiting for downloads.
        manager.set_state(SyncState::Synced);
        manager.progress.update_committed_height(100);
        manager.progress.update_stored_height(100);
        manager.progress.update_filter_header_tip_height(100);
        manager.progress.update_target_height(100);

        // Pre-populate in-flight state so we can verify reset_for_rescan runs.
        manager.active_batches.insert(101, FiltersBatch::new(101, 200, HashMap::new()));
        let stale_hash = dashcore::block::Header::dummy(0).block_hash();
        let stale_key = FilterMatchKey::new(150, stale_hash);
        manager.tracker.record_processed(150, stale_hash, &BTreeSet::from([MOCK_WALLET_ID]));
        manager.filter_pipeline.init(101, 200);

        // MockWallet defaults to synced_height=0, so wallets_behind(100) = {MOCK_WALLET_ID}.
        assert_eq!(manager.wallet.read().await.synced_height(), 0);

        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        // Sanity: the pre-populated stale processed record is present, so
        // `track` for the same wallet would short-circuit to AlreadyProcessed.
        assert_eq!(
            manager.tracker.track(&stale_key, 0, BTreeSet::from([MOCK_WALLET_ID])),
            BlockTrackResult::AlreadyProcessed
        );
        // Undo the side effect of the probing `track` so the original
        // processed record is the only state present going into `tick`.
        manager.tracker.clear();
        manager.tracker.record_processed(150, stale_hash, &BTreeSet::from([MOCK_WALLET_ID]));

        let events = manager.tick(&requests).await.unwrap();

        // Old in-flight state was cleared and a fresh batch was created at scan_start=0.
        assert!(!manager.active_batches.contains_key(&101));
        assert!(manager.active_batches.contains_key(&0));
        // The stale pre-populated record was wiped by `reset_for_rescan`:
        // a fresh `track` for the same wallet now returns `NewlyTracked`.
        assert!(matches!(
            manager.tracker.track(&stale_key, 0, BTreeSet::from([MOCK_WALLET_ID])),
            BlockTrackResult::NewlyTracked { .. }
        ));

        // start_download set committed_height to scan_start - 1 = 0.
        assert_eq!(manager.progress.committed_height(), 0);
        assert_eq!(manager.state(), SyncState::Syncing);

        // Verify a `BlocksNeeded` event was emitted that includes MOCK_WALLET_ID
        // for the matching block at height 50.
        let blocks_needed = events
            .iter()
            .find_map(|e| match e {
                SyncEvent::BlocksNeeded {
                    blocks,
                } => Some(blocks),
                _ => None,
            })
            .expect("BlocksNeeded event from rescan");
        let key_50 = FilterMatchKey::new(50, block_at_50.block_hash());
        let attribution = blocks_needed.get(&key_50).expect("entry for matching block 50");
        assert!(attribution.contains(&MOCK_WALLET_ID));
    }

    /// When every managed wallet is at or beyond `committed_height`, the rescan
    /// trigger must not fire even though the aggregate `synced_height` could
    /// otherwise look stale.
    #[tokio::test]
    async fn test_tick_does_not_rescan_when_no_wallets_behind() {
        let mut manager = create_test_manager().await;

        // Wallet at synced_height=200, manager committed at 100 → no wallets behind.
        manager.wallet.write().await.update_wallet_synced_height(&MOCK_WALLET_ID, 200);

        manager.set_state(SyncState::Synced);
        manager.progress.update_committed_height(100);
        manager.progress.update_stored_height(100);
        manager.progress.update_filter_header_tip_height(200);
        manager.progress.update_target_height(200);

        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        let events = manager.tick(&requests).await.unwrap();

        assert!(events.is_empty());
        assert_eq!(manager.progress.committed_height(), 100);
        assert_eq!(manager.state(), SyncState::Synced);
        assert!(manager.active_batches.is_empty());
    }

    /// `committed_height = 0` on a fresh manager must not falsely trip the
    /// rescan trigger. `wallets_behind(0)` returns an empty set since heights
    /// are unsigned, so no wallet can be strictly less than 0.
    #[tokio::test]
    async fn test_tick_does_not_rescan_at_genesis_committed() {
        let mut manager = create_test_manager().await;
        // Default state: committed_height=0, wallet synced_height=0, state=WaitForEvents.
        assert_eq!(manager.progress.committed_height(), 0);
        assert_eq!(manager.state(), SyncState::WaitForEvents);

        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        let events = manager.tick(&requests).await.unwrap();

        assert!(events.is_empty());
        assert!(manager.is_idle());
        assert_eq!(manager.state(), SyncState::WaitForEvents);
    }

    /// The rescan trigger only fires in `Syncing | Synced | WaitForEvents`.
    /// `WaitingForConnections` must be skipped since we're not actively syncing.
    #[tokio::test]
    async fn test_tick_does_not_rescan_in_waiting_for_connections() {
        let mut manager = create_test_manager().await;
        manager.set_state(SyncState::WaitingForConnections);
        manager.progress.update_committed_height(100);

        // Wallet behind committed — would normally trip the trigger.
        assert!(!manager.wallet.read().await.wallets_behind(100).is_empty());

        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        let events = manager.tick(&requests).await.unwrap();

        assert!(events.is_empty());
        // committed_height not lowered, no batches created.
        assert_eq!(manager.progress.committed_height(), 100);
        assert_eq!(manager.state(), SyncState::WaitingForConnections);
        assert!(manager.active_batches.is_empty());
    }

    /// `on_disconnect` for `FiltersManager` keeps the block-match tracker,
    /// active batches (with their `pending_blocks` counters), pending verified
    /// batches, and per-batch filter receipts, and moves any in-flight
    /// `getcfilters` slots back to pending so the next `send_pending` reissues
    /// them. This keeps `FiltersManager.tracker` in lockstep with
    /// `BlocksManager`'s preserved pipeline so already-counted matches do not
    /// leak into a permanent non-zero `pending_blocks`.
    #[tokio::test]
    async fn test_on_disconnect_preserves_in_progress_work() {
        let mut manager = create_test_manager().await;

        let key = FilterMatchKey::new(100, dashcore::block::Header::dummy(0).block_hash());
        let wallet_id = MOCK_WALLET_ID;

        let mut batch = FiltersBatch::new(0, 999, HashMap::new());
        batch.set_pending_blocks(1);
        manager.active_batches.insert(0, batch);
        manager.tracker.track(&key, 0, BTreeSet::from([wallet_id]));
        manager.pending_batches.insert(FiltersBatch::new(1000, 1999, HashMap::new()));
        manager.filter_pipeline.init(0, 1999);

        manager.on_disconnect();

        assert!(manager.active_batches.contains_key(&0));
        assert_eq!(
            manager.active_batches.get(&0).unwrap().pending_blocks(),
            1,
            "active batch's pending_blocks counter must not be reset"
        );
        assert_eq!(
            manager.tracker.track(&key, 0, BTreeSet::from([wallet_id])),
            BlockTrackResult::InFlight {
                wallets: BTreeSet::from([wallet_id])
            },
            "tracker must still see the hash as in-flight"
        );
        assert_eq!(manager.pending_batches.len(), 1);

        // Sanity check: the full-reset path (`reset_for_rescan`) does wipe
        // everything — the two paths must remain distinct.
        manager.reset_for_rescan();
        assert!(manager.active_batches.is_empty());
        assert!(manager.pending_batches.is_empty());
        assert!(manager.tracker.is_empty());
    }
}
