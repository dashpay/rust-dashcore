//! Filters manager for parallel sync.
//!
//! Downloads compact block filters (BIP 157/158), verifies them against headers,
//! and matches against wallet to identify blocks for download.
//! Emits FiltersStored, FiltersSyncComplete and BlocksNeeded events.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use dashcore::bip158::{BlockFilter, FilterQuery};
use dashcore::ScriptBuf;

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
use key_wallet_manager::{check_compact_filters_for_elements, FilterMatchKey, WalletId};
use tokio::sync::RwLock;

/// Batch size for processing filters.
const BATCH_PROCESSING_SIZE: u32 = 5000;

/// Snapshot of a behind wallet's compact-filter query inputs for a batch scan.
struct WalletScanState {
    /// The wallet these inputs belong to.
    id: WalletId,
    /// The wallet's committed sync checkpoint; heights at or below it are skipped.
    synced: u32,
    /// Monitored scriptPubKeys.
    scripts: Vec<ScriptBuf>,
    /// Bare `hash160` filter elements (owner/voting key hashes) a compact
    /// filter carries beyond the scriptPubKeys.
    elements: Vec<Vec<u8>>,
}

/// Maximum number of batches to scan ahead while waiting for blocks.
///
/// Raising this does not buy more throughput while a batch is stalled on a block.
/// Every scanned batch queues its matched blocks into one FIFO download window,
/// so a deeper lookahead fills that window with blocks belonging to batches that
/// cannot commit for a long time, ahead of the blocks the committing batch is
/// actually waiting on. Block downloads would have to be ordered by height
/// before this could go higher.
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
    ///
    /// `pub(super)` so the resume decision in `start_sync` can be taken on the
    /// same predicate `start_download` asserts. Checking a subset there is how
    /// a disconnect/reconnect cycle used to reach that assert.
    pub(super) fn is_idle(&self) -> bool {
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
            let key = FilterMatchKey::new(height, *header.hash());
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

        // Get the stored filters range. `stored_filters_tip` is a tip
        // watermark only: storage is dense within `[stored_filters_start,
        // stored_filters_tip]` but holds nothing below the start.
        // `stored_filters_start` is `None` exactly when no filters are stored;
        // `filter_tip_height` collapses both "empty" and "only height 0
        // stored" to 0, so the start must drive the "is anything stored?"
        // decision.
        let (stored_filters_tip, stored_filters_start) = {
            let filter_storage = self.filter_storage.read().await;
            (filter_storage.filter_tip_height().await?, filter_storage.filter_start_height().await)
        };

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

        // An anchor above the wallet's birth height leaves a range that no scan
        // will ever cover. Beyond the funds in it, BIP44 discovery is
        // sequential, so usage hidden down there also stops the gap-limit
        // window from advancing and can mask later addresses.
        if header_start_height > wallet_birth_height {
            tracing::warn!(
                "Chain anchored at height {} but wallet birth height is {}: heights {}..{} will never be scanned, \
                 so funds and address usage in that range stay invisible",
                header_start_height,
                wallet_birth_height,
                wallet_birth_height,
                header_start_height.saturating_sub(1)
            );
        }

        // The stored range is only usable for this scan when it actually
        // reaches down to `scan_start`. When headers previously synced from a
        // checkpoint above the wallet's birth height, only tip-region filters
        // exist: treating the tip watermark as contiguous coverage from
        // `scan_start` would preload never-populated segments (debug abort /
        // sentinel filter data in release builds). Gate purely on the stored
        // start so a genesis-only store (start = tip = 0) is recognized as
        // covering a scan from 0 rather than being misread as empty.
        let stored_covers_scan = stored_filters_start.is_some_and(|start| start <= scan_start);

        // Stored filters that don't reach down to `scan_start` cannot seed
        // this scan, and resuming the download from their tip would leave a
        // permanent hole below them that the in-order store loop can never
        // fill. Drop them and re-download from `scan_start`, exactly as if no
        // filters were stored, keeping storage dense within its stored range.
        // `is_some()` (not `tip > 0`) so this covers a lone above-scan filter
        // stored at height 0, though that cannot arise while the start is also
        // above `scan_start`.
        if stored_filters_start.is_some() && !stored_covers_scan {
            tracing::warn!(
                "Stored filters {:?}..={} do not reach scan start {}; discarding them and re-downloading",
                stored_filters_start,
                stored_filters_tip,
                scan_start
            );
            self.filter_storage.write().await.clear_filters().await?;
            self.progress.update_stored_height(0);
        }

        // Determine download start (where we need to download from)
        // Must be at least header_start_height for checkpoint-based sync
        let download_start = if stored_covers_scan {
            (stored_filters_tip + 1).max(header_start_height)
        } else {
            scan_start
        };

        // Anchor the scan and store frontiers even when we return early below.
        // A wallet that boots already synced takes the early return, and a
        // later new block would otherwise create a lookahead batch from a
        // stale `processing_height` of 0 and wedge the in-order store loop on
        // a `next_batch_to_store` of 0.
        self.processing_height = scan_start;
        self.next_batch_to_store = download_start;

        // Check if already at target (nothing to download)
        if scan_start > self.progress.filter_header_tip_height() {
            // Park the idle pipeline at the download frontier so a later
            // `extend_target` from a new block queues from here instead of
            // re-requesting every filter from an uninitialized position.
            self.filter_pipeline.init(download_start, download_start.saturating_sub(1));
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
        let filters = if stored_covers_scan && scan_start <= stored_filters_tip {
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
        if stored_covers_scan && stored_filters_tip >= batch_end {
            batch.mark_verified();
        }
        self.active_batches.insert(scan_start, batch);
        self.progress.update_committed_height(scan_start.saturating_sub(1));
        // Roll the storage watermark back in step with the scan position. This
        // is also the rescan entry point (the `tick` trigger resets progress
        // and re-enters here), so it keeps storage from releasing the range
        // this scan is about to re-read.
        self.filter_storage.write().await.set_committed_height(scan_start.saturating_sub(1)).await;

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

        // Phase 3: Commit newly scanned batches that are ready
        // (avoids a one-tick delay between scan and commit for small batches)
        events.extend(self.try_commit_batches().await?);

        // Phase 4: Create lookahead batches up to MAX_LOOKAHEAD_BATCHES
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

        // Lowest height any scan can ever reach. Read once, before the wallet
        // write lock below, so header storage is never locked underneath it.
        let scan_floor = self.header_storage.read().await.get_start_height().await.unwrap_or(0);

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
                // Take per-wallet collected scripts from the batch
                let scripts_by_wallet = self
                    .active_batches
                    .get_mut(&batch_start)
                    .map(|b| b.take_collected_scripts())
                    .unwrap_or_default();

                if !scripts_by_wallet.is_empty() {
                    // Rescan current batch
                    events.extend(self.rescan_batch(batch_start, &scripts_by_wallet).await?);

                    // Also rescan later batches that are already scanned
                    let later_batches: Vec<u32> = self
                        .active_batches
                        .iter()
                        .filter(|(&start, batch)| start > batch_start && batch.scanned())
                        .map(|(&start, _)| start)
                        .collect();

                    for later_start in later_batches {
                        events.extend(self.rescan_batch(later_start, &scripts_by_wallet).await?);
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
                    for (wallet_id, generation_at_scan) in &scanned_wallets {
                        // Generation guard: an account added after this batch
                        // was scanned means the scan never tested the new
                        // account's scripts, so the batch cannot certify
                        // coverage for the wallet's CURRENT account set — no
                        // matter where the account-add rewind left the
                        // checkpoint (below the batch, inside its range, or
                        // unmoved because it already sat at the birth floor).
                        // The wallet stays behind and the tick rescan picks it
                        // up (dashpay/rust-dashcore#649).
                        if wallet.wallet_account_generation(wallet_id) != *generation_at_scan {
                            continue;
                        }
                        // Contiguity guard: a batch extends a wallet's certified
                        // coverage only if the wallet was already certified up to
                        // the batch's start; a gap below the batch must be
                        // rescanned, not silently certified.
                        //
                        // Heights below `scan_floor` are the one exception: no
                        // batch can ever reach them, because the chain is
                        // anchored at a checkpoint and no headers exist below
                        // it. Treating that range as a gap leaves a wallet
                        // whose `synced_height` sits under the anchor
                        // permanently uncertifiable, which also starves the
                        // account-add rescan that clears
                        // dashpay/rust-dashcore#649. `scan_floor` itself is
                        // scanned, so only heights strictly below it count as
                        // out of scope. The guard is otherwise unchanged, so a
                        // genuine gap above the floor still blocks the advance.
                        let effective_synced = wallet
                            .wallet_synced_height(wallet_id)
                            .max(scan_floor.saturating_sub(1));
                        if effective_synced.saturating_add(1) >= batch_start {
                            wallet.update_wallet_synced_height(wallet_id, end);
                        }
                    }
                }
                // A batch commits only once every matched block in it has been
                // downloaded and applied, so filters at or below `end` are
                // fully consumed. Let storage release them from memory on the
                // next persist; they remain readable through `load_filters`,
                // which reloads from disk. The wallet guard above is out of
                // scope here and no storage guard is held.
                self.filter_storage.write().await.set_committed_height(end).await;
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

    /// Rescan a specific batch for newly discovered scriptPubKeys, attributed
    /// per wallet so each new script is matched only against the filters
    /// relevant to its owning wallet.
    pub(super) async fn rescan_batch(
        &mut self,
        batch_start: u32,
        new_scripts: &HashMap<WalletId, HashSet<ScriptBuf>>,
    ) -> SyncResult<Vec<SyncEvent>> {
        if new_scripts.is_empty() {
            return Ok(vec![]);
        }

        let Some(batch) = self.active_batches.get(&batch_start) else {
            return Ok(vec![]);
        };

        tracing::info!(
            "Rescan filters ({}-{}) for new scripts across {} wallets",
            batch.start_height(),
            batch.end_height(),
            new_scripts.len()
        );

        if batch.filters().is_empty() {
            return Ok(vec![]);
        }
        let batch_filters = batch.filters();

        // Per-wallet `synced_height` snapshot so heights below the wallet's
        // own progress are skipped during the rescan, plus the bare
        // owner/voting filter elements a compact filter carries beyond the
        // wallet's scriptPubKeys.
        let mut synced_heights: HashMap<WalletId, u32> = HashMap::new();
        let mut filter_elements: HashMap<WalletId, Vec<Vec<u8>>> = HashMap::new();
        {
            let wallet = self.wallet.read().await;
            for id in new_scripts.keys() {
                synced_heights.insert(*id, wallet.wallet_synced_height(id));
                filter_elements.insert(*id, wallet.monitored_filter_elements_for(id));
            }
        }

        let mut block_to_wallets: BTreeMap<FilterMatchKey, BTreeSet<WalletId>> = BTreeMap::new();
        for (wallet_id, scripts) in new_scripts {
            let elements = filter_elements.get(wallet_id).map(Vec::as_slice).unwrap_or(&[]);
            if scripts.is_empty() && elements.is_empty() {
                continue;
            }
            let scripts_vec: Vec<ScriptBuf> = scripts.iter().cloned().collect();
            let min_synced = synced_heights.get(wallet_id).copied().unwrap_or(0);
            let matches = check_compact_filters_for_elements(
                batch_filters,
                &scripts_vec,
                elements,
                min_synced,
            );
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
            // Matches here are driven by scripts that did not exist when the
            // block was first processed, so a processed record must not
            // suppress the re-download: the block has to be re-applied
            // against the extended pools.
            match self.tracker.track_for_new_scripts(&key, batch_start, wallets) {
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
                // Never returned by track_for_new_scripts.
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
        // skipped entirely, its scripts never even get tested against these
        // filters.
        let wallet = self.wallet.read().await;
        let behind = wallet.wallets_behind(batch_end);
        let mut wallet_states: Vec<WalletScanState> = Vec::new();
        for wallet_id in &behind {
            let synced = wallet.wallet_synced_height(wallet_id);
            // The scan query, not the full monitored set: spent single-use
            // (CoinJoin) addresses are pruned so the per-filter match cost
            // stays bounded by active UTXOs + gap lookahead instead of
            // growing with every historical mixing round
            // (dashpay/rust-dashcore#948).
            let scripts = wallet.scan_script_pubkeys_for(wallet_id);
            // Bare owner/voting key hashes a compact filter carries beyond the
            // wallet's scriptPubKeys.
            let elements = wallet.monitored_filter_elements_for(wallet_id);
            if !scripts.is_empty() || !elements.is_empty() {
                wallet_states.push(WalletScanState {
                    id: *wallet_id,
                    synced,
                    scripts,
                    elements,
                });
            }
        }
        // Every behind wallet's coverage advances to `batch_end` once this
        // batch commits. That includes wallets without any monitored
        // addresses: they have nothing to match against these filters, so the
        // batch fully accounts for their range and their `synced_height` must
        // advance to keep `wallets_behind` from listing them on every future
        // batch. Each wallet's `account_generation` is snapshotted under the
        // same read lock as the behind set: commit refuses to advance a wallet
        // whose account set changed after this scan
        // (dashpay/rust-dashcore#649).
        let scanned_wallets: BTreeMap<WalletId, u64> = behind
            .iter()
            .map(|wallet_id| (*wallet_id, wallet.wallet_account_generation(wallet_id)))
            .collect();
        drop(wallet);

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
            tracing::trace!("scan_batch: no behind wallets with monitored addresses");
            return Ok(events);
        }

        // Single-pass union-then-attribute: build the union of all scripts
        // and bare elements across behind wallets, run the filters once, then
        // for each matched block re-test per-wallet queries to attribute the
        // match correctly.
        let union_scripts: Vec<ScriptBuf> =
            wallet_states.iter().flat_map(|s| s.scripts.iter().cloned()).collect();
        let union_elements: Vec<Vec<u8>> =
            wallet_states.iter().flat_map(|s| s.elements.iter().cloned()).collect();
        let min_synced = wallet_states.iter().map(|s| s.synced).min().unwrap_or(0);

        // Pre-group each wallet's scripts and bare elements by length once;
        // reused across every matched filter.
        let wallet_queries: Vec<(WalletId, u32, FilterQuery)> = wallet_states
            .iter()
            .map(|s| {
                let mut query: FilterQuery = s.scripts.iter().map(|sp| sp.as_bytes()).collect();
                for element in &s.elements {
                    query.push(element);
                }
                (s.id, s.synced, query)
            })
            .collect();

        let block_to_wallets = {
            let Some(batch) = self.active_batches.get(&batch_start) else {
                return Ok(events);
            };
            let batch_filters = batch.filters();

            let matches = check_compact_filters_for_elements(
                batch_filters,
                &union_scripts,
                &union_elements,
                min_synced,
            );
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
                for (wallet_id, wallet_synced, query) in &wallet_queries {
                    if key.height() <= *wallet_synced {
                        continue;
                    }
                    let matched = match filter.match_any(key.hash(), query) {
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
                if self.progress.committed_height() < self.progress.filter_header_tip_height() =>
            {
                // Transition back to Syncing so is_synced() returns false
                // until all new filters and matched blocks are fully processed.
                if self.state() == SyncState::Synced {
                    self.set_state(SyncState::Syncing);
                }

                self.filter_pipeline.extend_target(tip_height);
                if self.progress.stored_height() < self.progress.filter_header_tip_height() {
                    let header_storage = self.header_storage.read().await;
                    self.filter_pipeline.send_pending(requests, &*header_storage).await?;
                }

                // Extend the processing boundary to the new tip whether or not a
                // historical rescan is still draining `active_batches`. A block
                // landing during a restart reinit window otherwise gets its body
                // downloaded but never a processing batch, freezing
                // `committed_height` one below tip.
                tracing::debug!("Processing new filter (target: {})", tip_height);
                return self.try_create_lookahead_batches().await;
            }
            SyncState::WaitingForConnections | SyncState::WaitForEvents => {
                // In-progress work preserved across a disconnect cycle. Don't
                // re-init via `start_download` — that would clobber existing
                // batches. Instead extend the target and let the eventual
                // `start_sync` (driven by `PeersUpdated`) resume from here.
                //
                // `is_idle()` for the same reason `start_sync` uses it: this is
                // the second route into `start_download`, and it asserts all
                // four conditions. `active_batches` alone is a strict subset —
                // a batch that finished downloading leaves it while its
                // verified output waits in `pending_batches` and its blocks
                // wait in the tracker, and `on_disconnect` moves the pipeline's
                // in-flight slots to pending rather than clearing them.
                //
                // Extending the target is the right answer for all four, not
                // just for active batches: `handle_message` keeps running
                // regardless of state (filters always want `CFilter`), so
                // `store_and_match_batches` drains the leftovers, and the next
                // filter-header event re-enters here once genuinely idle.
                if !self.is_idle() {
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
    use crate::network::{Message, MessageType, NetworkRequest, RequestSender};
    use crate::storage::{
        BlockHeaderStorage, DiskStorageManager, PersistentBlockHeaderStorage,
        PersistentFilterHeaderStorage, PersistentFilterStorage, StorageManager,
    };
    use crate::sync::{ManagerIdentifier, SyncManagerProgress};
    use crate::types::HashedBlockHeader;
    use dashcore::bip158::BlockFilter;
    use dashcore::network::message::NetworkMessage;
    use dashcore::network::message_filter::CFilter;
    use dashcore::{Address, Header};
    use dashcore::{Block, Network, Transaction};
    use dashcore_hashes::Hash;
    use key_wallet_manager::test_utils::{
        MockWallet, MockWalletState, MultiMockWallet, MOCK_WALLET_ID,
    };
    use std::net::SocketAddr;
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

    /// Store `count` headers starting at `anchor`, so `get_start_height`
    /// reports `anchor`. That is the value the scan floor is read from.
    async fn anchor_headers_at(
        storage: &Arc<RwLock<PersistentBlockHeaderStorage>>,
        anchor: u32,
        count: u32,
    ) {
        let headers = Header::dummy_batch(anchor..anchor + count);
        storage
            .write()
            .await
            .store_headers_at_height(
                &headers.iter().map(HashedBlockHeader::from).collect::<Vec<_>>(),
                anchor,
            )
            .await
            .unwrap();
    }

    /// Give an existing manager the checkpoint-sync shape: block headers,
    /// filter bodies and a filter header covering `anchor..=anchor + span`,
    /// with nothing below `anchor`. Seeds the storage the manager already
    /// holds, so its progress stays consistent with what it reads back.
    async fn seed_anchored_storage<W: WalletInterface + 'static>(
        manager: &FiltersManager<
            PersistentBlockHeaderStorage,
            PersistentFilterHeaderStorage,
            PersistentFilterStorage,
            W,
        >,
        anchor: u32,
        span: u32,
    ) {
        anchor_headers_at(&manager.header_storage, anchor, span + 1).await;

        let filter = BlockFilter::new(&[0u8; 32]);
        {
            let mut fs = manager.filter_storage.write().await;
            for height in anchor..=anchor + span {
                fs.store_filter(height, &filter.content).await.unwrap();
            }
        }

        // Non-zero, since the segment store reads an all-zero filter header
        // back as an empty slot.
        let prev_filter_header = FilterHeader::from_byte_array([1u8; 32]);
        manager
            .filter_header_storage
            .write()
            .await
            .store_filter_headers_at_height(
                &[prev_filter_header, filter.filter_header(&prev_filter_header)],
                anchor + span,
            )
            .await
            .unwrap();
    }

    /// Drain every `GetCFilters` request queued on `rx`.
    fn drain_getcfilters(rx: &mut tokio::sync::mpsc::UnboundedReceiver<NetworkRequest>) -> usize {
        let mut count = 0;
        while let Ok(request) = rx.try_recv() {
            let (NetworkRequest::SendMessage(msg)
            | NetworkRequest::SendMessageToPeer(msg, _)
            | NetworkRequest::BroadcastMessage(msg)) = request;
            if matches!(msg, NetworkMessage::GetCFilters(_)) {
                count += 1;
            }
        }
        count
    }

    /// Manager whose block headers start at `anchor` rather than genesis, the
    /// checkpoint-sync shape where the chain is anchored above a wallet's birth
    /// height. `get_start_height` is what the scan floor is derived from, so
    /// this reproduces the mainnet setup without depending on `Network`:
    /// `hd_wallet_sync_floor` is non-zero only for mainnet, which is why the
    /// rest of the suite never exercised a non-zero floor.
    ///
    /// Headers and filters both cover `anchor..=anchor + span`. Filter headers
    /// are stored so `handle_new_filter_headers` can drive a real download.
    async fn create_anchored_test_manager(anchor: u32, span: u32) -> TestFiltersManager {
        let manager = create_test_manager().await;
        seed_anchored_storage(&manager, anchor, span).await;
        manager
    }

    /// Set up a manager fully synced to height 100: block headers stored
    /// through the boundary block 101, filter bodies and filter headers
    /// persisted through 100, and progress anchored at 100. The returned
    /// boundary filter body for height 101 is fed in over the wire by callers.
    /// State is left untouched so each caller picks the reconnect or boot path.
    async fn setup_synced_manager_at_tip() -> (TestFiltersManager, Vec<Header>, BlockFilter) {
        let mut manager = create_test_manager().await;

        let headers = Header::dummy_batch(0..102);
        manager
            .header_storage
            .write()
            .await
            .store_headers(&headers.iter().map(HashedBlockHeader::from).collect::<Vec<_>>())
            .await
            .unwrap();

        let boundary_filter = BlockFilter::new(&[0u8; 32]);
        {
            let mut fs = manager.filter_storage.write().await;
            for h in 0..=100 {
                fs.store_filter(h, &boundary_filter.content).await.unwrap();
            }
        }

        // The prev header is non-zero because the segment store treats an
        // all-zero filter header as an empty (sentinel) slot.
        let prev_filter_header = FilterHeader::from_byte_array([1u8; 32]);
        manager
            .filter_header_storage
            .write()
            .await
            .store_filter_headers_at_height(
                &[prev_filter_header, boundary_filter.filter_header(&prev_filter_header)],
                100,
            )
            .await
            .unwrap();

        manager.wallet.write().await.update_wallet_synced_height(&MOCK_WALLET_ID, 100);
        manager.progress.update_committed_height(100);
        manager.progress.update_stored_height(100);
        manager.progress.update_filter_header_tip_height(100);
        manager.progress.update_target_height(100);

        (manager, headers, boundary_filter)
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
        storage
            .block_headers()
            .write()
            .await
            .store_headers(
                &block_headers
                    .iter()
                    .map(crate::types::HashedBlockHeader::from)
                    .collect::<Vec<_>>(),
            )
            .await
            .unwrap();

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
    async fn test_filter_header_tip_height_is_monotonic() {
        let mut manager = create_test_manager().await;
        manager.progress.update_filter_header_tip_height(500);
        assert_eq!(manager.progress.filter_header_tip_height(), 500);

        // Lower value is rejected
        manager.progress.update_filter_header_tip_height(200);
        assert_eq!(manager.progress.filter_header_tip_height(), 500);

        // Equal value is rejected (no spurious activity bump)
        manager.progress.update_filter_header_tip_height(500);
        assert_eq!(manager.progress.filter_header_tip_height(), 500);

        // Higher value is accepted
        manager.progress.update_filter_header_tip_height(600);
        assert_eq!(manager.progress.filter_header_tip_height(), 600);
    }

    /// Lookahead is what lets scanning continue past a batch that cannot commit
    /// because a block it matched is still downloading, so it must actually reach
    /// the cap rather than stopping at whatever the first pass created.
    #[tokio::test]
    async fn test_lookahead_fills_to_the_cap_and_stops() {
        let mut manager = create_test_manager().await;
        manager.set_state(SyncState::Syncing);

        // Far more headroom than the cap, so the cap is what stops it. The
        // filters themselves are still downloading, which is the state lookahead
        // exists for: the batches are created empty and scanned once they land.
        let tip = BATCH_PROCESSING_SIZE * (MAX_LOOKAHEAD_BATCHES as u32 + 4);
        manager.processing_height = 1;
        manager.progress.update_filter_header_tip_height(tip);
        manager.progress.update_target_height(tip);

        manager.try_create_lookahead_batches().await.unwrap();

        assert_eq!(manager.active_batches.len(), MAX_LOOKAHEAD_BATCHES);

        // A second pass adds nothing while the batches are still uncommitted.
        manager.try_create_lookahead_batches().await.unwrap();
        assert_eq!(manager.active_batches.len(), MAX_LOOKAHEAD_BATCHES);

        // The batches must tile the range contiguously from the processing head.
        let mut expected_start = manager.processing_height;
        for (&start, batch) in &manager.active_batches {
            assert_eq!(start, expected_start);
            expected_start = batch.end_height() + 1;
        }
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
        batch1.set_scanned_wallets(BTreeMap::from([(MOCK_WALLET_ID, 0)]));
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
        batch.set_scanned_wallets(BTreeMap::from([(wallet_a, 0)]));
        manager.active_batches.insert(0, batch);

        manager.try_commit_batches().await.unwrap();
        assert_eq!(manager.progress.committed_height(), 4999);
        assert_eq!(multi.read().await.wallet_synced_height(&wallet_a), 4999);
        assert_eq!(multi.read().await.wallet_synced_height(&wallet_b), 0);
    }

    /// Contiguity guard (dashpay/rust-dashcore#649): a batch scanned before an
    /// account-add rewinds the wallet's checkpoint must NOT clobber the rewound
    /// value forward at commit time — otherwise the account-addition rescan is
    /// silently cancelled. The wallet stays behind and the tick picks it up.
    #[tokio::test]
    async fn mid_flight_account_add_does_not_clobber_rescan_floor() {
        let wallet_a: WalletId = [0xAA; 32];
        let multi = Arc::new(RwLock::new(MultiMockWallet::new()));
        {
            let mut w = multi.write().await;
            // Already synced up to 4999, so the next batch legitimately starts at 5000.
            w.insert_wallet(
                wallet_a,
                MockWalletState {
                    synced_height: 4999,
                    ..MockWalletState::default()
                },
            );
        }
        let mut manager = create_multi_test_manager(multi.clone()).await;
        manager.set_state(SyncState::Syncing);

        // Batch [5000..9999] scanned with wallet_a recorded, ready to commit.
        let mut batch = FiltersBatch::new(5000, 9999, HashMap::new());
        batch.set_pending_blocks(0);
        batch.mark_scanned();
        batch.mark_rescan_complete();
        batch.set_scanned_wallets(BTreeMap::from([(wallet_a, 0)]));
        manager.active_batches.insert(5000, batch);

        // Simulate an account being added mid-flight: the wallet's checkpoint is
        // rewound to just below birth, far below this batch's start.
        multi.write().await.wallet_mut(&wallet_a).synced_height = 49;

        manager.try_commit_batches().await.unwrap();

        // committed_height still advances (chain progress), but the wallet's
        // checkpoint is NOT dragged forward over the gap it must rescan.
        assert_eq!(manager.progress.committed_height(), 9999);
        assert_eq!(
            multi.read().await.wallet_synced_height(&wallet_a),
            49,
            "the rewound checkpoint must survive commit — the batch is non-contiguous with it"
        );
        // The wallet is still behind, so the next tick rescans it.
        assert!(
            multi.read().await.wallets_behind(9999).contains(&wallet_a),
            "the wallet remains behind and is picked up by the tick rescan"
        );

        // Under an anchor, only heights strictly below it are out of scope. A
        // gap between the anchor and the batch is still a gap, so the floor
        // must not be read as "anything below the batch is fine".
        let wallet_b: WalletId = [0xBB; 32];
        multi.write().await.insert_wallet(wallet_b, MockWalletState::default());
        let mut manager = create_multi_test_manager(multi.clone()).await;
        anchor_headers_at(&manager.header_storage, 200_000, 2).await;
        manager.set_state(SyncState::Syncing);

        let mut batch = FiltersBatch::new(205_000, 209_999, HashMap::new());
        batch.set_pending_blocks(0);
        batch.mark_scanned();
        batch.mark_rescan_complete();
        batch.set_scanned_wallets(BTreeMap::from([(wallet_b, 0)]));
        manager.active_batches.insert(205_000, batch);

        manager.try_commit_batches().await.unwrap();

        assert_eq!(
            multi.read().await.wallet_synced_height(&wallet_b),
            0,
            "heights 200000..204999 are reachable and were never scanned, so the batch cannot certify"
        );
    }

    /// The contiguity guard is transparent in normal operation: contiguous
    /// ascending batches advance each wallet's checkpoint exactly as before.
    #[tokio::test]
    async fn contiguity_guard_permits_normal_advance() {
        let wallet_a: WalletId = [0xCC; 32];
        let multi = Arc::new(RwLock::new(MultiMockWallet::new()));
        multi.write().await.insert_wallet(wallet_a, MockWalletState::default());
        let mut manager = create_multi_test_manager(multi.clone()).await;
        manager.set_state(SyncState::Syncing);

        // First batch starts at 0 = synced_height (0) + ... the wallet is fresh,
        // so this batch is contiguous and advances the checkpoint.
        let mut batch1 = FiltersBatch::new(0, 4999, HashMap::new());
        batch1.set_pending_blocks(0);
        batch1.mark_scanned();
        batch1.mark_rescan_complete();
        batch1.set_scanned_wallets(BTreeMap::from([(wallet_a, 0)]));
        manager.active_batches.insert(0, batch1);

        manager.try_commit_batches().await.unwrap();
        assert_eq!(multi.read().await.wallet_synced_height(&wallet_a), 4999);

        // Second batch starts exactly at synced_height + 1 = 5000: still
        // contiguous, so it advances too.
        let mut batch2 = FiltersBatch::new(5000, 9999, HashMap::new());
        batch2.set_pending_blocks(0);
        batch2.mark_scanned();
        batch2.mark_rescan_complete();
        batch2.set_scanned_wallets(BTreeMap::from([(wallet_a, 0)]));
        manager.active_batches.insert(5000, batch2);

        manager.try_commit_batches().await.unwrap();
        assert_eq!(
            multi.read().await.wallet_synced_height(&wallet_a),
            9999,
            "contiguous ascending batches advance the checkpoint unchanged by the guard"
        );
    }

    /// Marvin QA-001 round 2: two wallets in the SAME batch, only one of them
    /// rewound mid-flight (simulating an account add on wallet_a only). The
    /// contiguity guard must block wallet_a's advance while still advancing
    /// wallet_b normally — a per-wallet leak here would either strand a
    /// healthy wallet or silently clobber the rewound one.
    #[tokio::test]
    async fn contiguity_guard_is_per_wallet_not_batch_wide() {
        let wallet_a: WalletId = [0xAA; 32];
        let wallet_b: WalletId = [0xBB; 32];
        let multi = Arc::new(RwLock::new(MultiMockWallet::new()));
        {
            let mut w = multi.write().await;
            w.insert_wallet(
                wallet_a,
                MockWalletState {
                    synced_height: 4999,
                    ..MockWalletState::default()
                },
            );
            w.insert_wallet(
                wallet_b,
                MockWalletState {
                    synced_height: 4999,
                    ..MockWalletState::default()
                },
            );
        }
        let mut manager = create_multi_test_manager(multi.clone()).await;
        manager.set_state(SyncState::Syncing);

        // Batch [5000..9999] scanned with BOTH wallets recorded.
        let mut batch = FiltersBatch::new(5000, 9999, HashMap::new());
        batch.set_pending_blocks(0);
        batch.mark_scanned();
        batch.mark_rescan_complete();
        batch.set_scanned_wallets(BTreeMap::from([(wallet_a, 0), (wallet_b, 0)]));
        manager.active_batches.insert(5000, batch);

        // Only wallet_a gets an account added mid-flight (rewound). wallet_b
        // is untouched and remains legitimately contiguous with this batch.
        multi.write().await.wallet_mut(&wallet_a).synced_height = 49;

        manager.try_commit_batches().await.unwrap();

        assert_eq!(manager.progress.committed_height(), 9999);
        assert_eq!(
            multi.read().await.wallet_synced_height(&wallet_a),
            49,
            "wallet_a's rewound checkpoint must survive commit"
        );
        assert_eq!(
            multi.read().await.wallet_synced_height(&wallet_b),
            9999,
            "wallet_b was legitimately contiguous and must still advance despite \
             sharing a batch with a rewound wallet"
        );
    }

    /// Generation guard, mid-batch rewind (Codex QA round 3): batch
    /// [5000..9999] is scanned while the wallet sits at 9000, then an account
    /// add rewinds the checkpoint to 7499 — INSIDE the batch's range. The
    /// height-only contiguity check (7500 >= 5000) cannot see anything wrong,
    /// but heights 7500..=9999 were scanned without the new account's scripts
    /// (and 7500..=9000 were not attributed to this wallet at all), so the
    /// commit must not certify them. The `account_generation` snapshot taken
    /// at scan time is what blocks it (dashpay/rust-dashcore#649).
    #[tokio::test]
    async fn account_add_rewind_inside_batch_range_does_not_certify_unscanned_gap() {
        let wallet_a: WalletId = [0xAA; 32];
        let multi = Arc::new(RwLock::new(MultiMockWallet::new()));
        multi.write().await.insert_wallet(
            wallet_a,
            MockWalletState {
                synced_height: 9000,
                ..MockWalletState::default()
            },
        );
        let mut manager = create_multi_test_manager(multi.clone()).await;
        manager.set_state(SyncState::Syncing);

        // Batch [5000..9999] scanned while the wallet's generation was 0.
        let mut batch = FiltersBatch::new(5000, 9999, HashMap::new());
        batch.set_pending_blocks(0);
        batch.mark_scanned();
        batch.mark_rescan_complete();
        batch.set_scanned_wallets(BTreeMap::from([(wallet_a, 0)]));
        manager.active_batches.insert(5000, batch);

        // Account added mid-flight: checkpoint rewound to birth-1 = 7499,
        // generation bumped — both done by the same rewind in key-wallet.
        {
            let mut w = multi.write().await;
            let state = w.wallet_mut(&wallet_a);
            state.synced_height = 7499;
            state.account_generation = 1;
        }

        manager.try_commit_batches().await.unwrap();

        assert_eq!(manager.progress.committed_height(), 9999);
        assert_eq!(
            multi.read().await.wallet_synced_height(&wallet_a),
            7499,
            "a rewind INSIDE the batch range must survive commit: 7500..=9999 were \
             scanned without the new account's scripts"
        );
        assert!(
            multi.read().await.wallets_behind(9999).contains(&wallet_a),
            "the wallet remains behind and is picked up by the tick rescan"
        );
    }

    /// Generation guard, height-invisible account add: the wallet still sits
    /// at its birth floor (999) when batch [1000..5999] is scanned, an account
    /// is added (the rewind moves nothing — the checkpoint is already at the
    /// floor), and the batch then commits. No height-based check can detect
    /// this: the batch is perfectly contiguous with the unchanged checkpoint,
    /// yet it was scanned without the new account's scripts. Only the
    /// generation mismatch blocks the advance (dashpay/rust-dashcore#649).
    #[tokio::test]
    async fn account_add_with_unmoved_checkpoint_still_blocks_commit_advance() {
        let wallet_a: WalletId = [0xAA; 32];
        let multi = Arc::new(RwLock::new(MultiMockWallet::new()));
        multi.write().await.insert_wallet(
            wallet_a,
            MockWalletState {
                synced_height: 999,
                ..MockWalletState::default()
            },
        );
        let mut manager = create_multi_test_manager(multi.clone()).await;
        manager.set_state(SyncState::Syncing);

        let mut batch = FiltersBatch::new(1000, 5999, HashMap::new());
        batch.set_pending_blocks(0);
        batch.mark_scanned();
        batch.mark_rescan_complete();
        batch.set_scanned_wallets(BTreeMap::from([(wallet_a, 0)]));
        manager.active_batches.insert(1000, batch);

        // Account added mid-flight; the checkpoint is already at the birth
        // floor so ONLY the generation moves.
        multi.write().await.wallet_mut(&wallet_a).account_generation = 1;

        manager.try_commit_batches().await.unwrap();

        assert_eq!(manager.progress.committed_height(), 5999);
        assert_eq!(
            multi.read().await.wallet_synced_height(&wallet_a),
            999,
            "an account add that moved no heights must still block the advance — \
             the batch was scanned without the new account's scripts"
        );

        // Same thing under an anchor, where the contiguity check passes on the
        // floor and the generation guard is the only thing left holding the
        // advance back.
        let wallet_b: WalletId = [0xBB; 32];
        multi.write().await.insert_wallet(wallet_b, MockWalletState::default());
        let mut manager = create_multi_test_manager(multi.clone()).await;
        anchor_headers_at(&manager.header_storage, 200_000, 2).await;
        manager.set_state(SyncState::Syncing);

        let mut batch = FiltersBatch::new(200_000, 204_999, HashMap::new());
        batch.set_pending_blocks(0);
        batch.mark_scanned();
        batch.mark_rescan_complete();
        batch.set_scanned_wallets(BTreeMap::from([(wallet_b, 0)]));
        manager.active_batches.insert(200_000, batch);

        multi.write().await.wallet_mut(&wallet_b).account_generation = 1;

        manager.try_commit_batches().await.unwrap();

        assert_eq!(
            multi.read().await.wallet_synced_height(&wallet_b),
            0,
            "the floor satisfies contiguity here, so the generation guard alone must block it"
        );
    }

    /// A generation bump after commit does not retroactively matter, and an
    /// unchanged generation lets contiguous batches advance exactly as before:
    /// the guard is transparent in normal operation.
    #[tokio::test]
    async fn generation_guard_transparent_when_generation_unchanged() {
        let wallet_a: WalletId = [0xDD; 32];
        let multi = Arc::new(RwLock::new(MultiMockWallet::new()));
        multi.write().await.insert_wallet(
            wallet_a,
            MockWalletState {
                // A wallet whose generation is already nonzero (accounts were
                // added before this scan): the snapshot captures the CURRENT
                // value, so commit still advances.
                account_generation: 3,
                ..MockWalletState::default()
            },
        );
        let mut manager = create_multi_test_manager(multi.clone()).await;
        manager.set_state(SyncState::Syncing);

        let mut batch = FiltersBatch::new(0, 4999, HashMap::new());
        batch.set_pending_blocks(0);
        batch.mark_scanned();
        batch.mark_rescan_complete();
        batch.set_scanned_wallets(BTreeMap::from([(wallet_a, 3)]));
        manager.active_batches.insert(0, batch);

        manager.try_commit_batches().await.unwrap();
        assert_eq!(
            multi.read().await.wallet_synced_height(&wallet_a),
            4999,
            "matching generation snapshot advances the checkpoint unchanged by the guard"
        );
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
                    account_generation: 0,
                },
            );
            // wallet_high is mostly synced: synced_height=50, only sees > 50.
            w.insert_wallet(
                wallet_high,
                MockWalletState {
                    addresses: vec![address_high.clone()],
                    synced_height: 50,
                    last_processed_height: 50,
                    account_generation: 0,
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

    /// `scan_batch` matches filters against the wallet's scan query
    /// (`scan_script_pubkeys_for`), not the full monitored set: a monitored
    /// script pruned from the scan query — a spent single-use CoinJoin
    /// address (dashpay/rust-dashcore#948) — must not pull its block in.
    #[tokio::test]
    async fn test_scan_batch_uses_pruned_scan_query() {
        let wallet_id: WalletId = [0x03; 32];
        let dead_address = dashcore::Address::dummy(Network::Regtest, 1);
        let live_address = dashcore::Address::dummy(Network::Regtest, 2);

        let multi = Arc::new(RwLock::new(MultiMockWallet::new()));
        {
            let mut w = multi.write().await;
            w.insert_wallet(
                wallet_id,
                MockWalletState {
                    addresses: vec![dead_address.clone(), live_address.clone()],
                    synced_height: 0,
                    last_processed_height: 0,
                    account_generation: 0,
                },
            );
            // The scan query excludes the dead address.
            w.set_scan_addresses(wallet_id, vec![live_address.clone()]);
        }
        let mut manager = create_multi_test_manager(multi).await;
        manager.set_state(SyncState::Syncing);

        let mut filters: HashMap<FilterMatchKey, BlockFilter> = HashMap::new();
        let (key_dead, f_dead) = filter_for_address(30, &dead_address);
        let (key_live, f_live) = filter_for_address(60, &live_address);
        filters.insert(key_dead.clone(), f_dead);
        filters.insert(key_live.clone(), f_live);

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

        assert!(blocks.contains_key(&key_live), "block paying the scan-query address is needed");
        assert!(
            !blocks.contains_key(&key_dead),
            "block paying only the pruned address must not be downloaded"
        );
    }

    /// `rescan_batch` with multiple wallets in `scripts_by_wallet`:
    /// each wallet's new scripts are matched independently and the
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

        let mut new_scripts: HashMap<WalletId, HashSet<ScriptBuf>> = HashMap::new();
        new_scripts.insert(wallet_a, HashSet::from([address_a.script_pubkey()]));
        new_scripts.insert(wallet_b, HashSet::from([address_b.script_pubkey()]));

        let events = manager.rescan_batch(0, &new_scripts).await.unwrap();

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

    /// A block that was already processed for a wallet is re-queued by
    /// `rescan_batch` when newly derived scripts match it: the prior
    /// processing predates those scripts, so the block must be re-applied
    /// against the extended pools. Plain scans keep skipping processed
    /// blocks.
    #[tokio::test]
    async fn test_rescan_batch_reprocesses_already_processed_block() {
        let address = Address::dummy(Network::Regtest, 33);
        let mut manager = create_test_manager().await;
        manager.set_state(SyncState::Syncing);

        let (key, filter) = filter_for_address(20, &address);
        let mut filters: HashMap<FilterMatchKey, BlockFilter> = HashMap::new();
        filters.insert(key.clone(), filter);
        let mut batch = FiltersBatch::new(0, 99, filters);
        batch.mark_verified();
        manager.active_batches.insert(0, batch);

        // The block was downloaded and processed for the wallet before the
        // rescan script existed.
        manager.tracker.record_processed(20, *key.hash(), &BTreeSet::from([MOCK_WALLET_ID]));

        let mut new_scripts: HashMap<WalletId, HashSet<ScriptBuf>> = HashMap::new();
        new_scripts.insert(MOCK_WALLET_ID, HashSet::from([address.script_pubkey()]));

        let events = manager.rescan_batch(0, &new_scripts).await.unwrap();

        let blocks = events
            .iter()
            .find_map(|e| match e {
                SyncEvent::BlocksNeeded {
                    blocks,
                } => Some(blocks),
                _ => None,
            })
            .expect("BlocksNeeded event for the re-queued block");
        assert!(blocks.get(&key).expect("re-queued block entry").contains(&MOCK_WALLET_ID));

        // The re-queued block is accounted exactly once so the batch cannot
        // commit before its re-processing completes.
        assert_eq!(manager.active_batches.get(&0).unwrap().pending_blocks(), 1);
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
                    account_generation: 0,
                },
            );
            w.insert_wallet(
                wallet_high,
                MockWalletState {
                    addresses: vec![],
                    synced_height: 60,
                    last_processed_height: 60,
                    account_generation: 0,
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

        // wallet_high also "discovers" address_low's script to demonstrate
        // that even when a new script would match a low height, the per-wallet
        // synced_height filter prevents emitting it.
        let mut new_scripts: HashMap<WalletId, HashSet<ScriptBuf>> = HashMap::new();
        new_scripts.insert(wallet_low, HashSet::from([address_low.script_pubkey()]));
        new_scripts.insert(
            wallet_high,
            HashSet::from([address_low.script_pubkey(), address_high.script_pubkey()]),
        );

        let events = manager.rescan_batch(0, &new_scripts).await.unwrap();

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
                    account_generation: 0,
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
                    account_generation: 0,
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
                    account_generation: 0,
                },
            );
            w.insert_wallet(
                late,
                MockWalletState {
                    addresses: vec![address.clone()],
                    synced_height: 0,
                    last_processed_height: 0,
                    account_generation: 0,
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
        manager
            .header_storage
            .write()
            .await
            .store_headers(
                &headers.iter().map(crate::types::HashedBlockHeader::from).collect::<Vec<_>>(),
            )
            .await
            .unwrap();

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
                    account_generation: 0,
                },
            );
            w.insert_wallet(
                wallet_b,
                MockWalletState {
                    addresses: vec![address_b.clone()],
                    synced_height: 0,
                    last_processed_height: 0,
                    account_generation: 0,
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
    async fn test_batch_collects_scripts() {
        use crate::sync::filters::batch::FiltersBatch;
        use dashcore::Network;

        let mut batch = FiltersBatch::new(0, 4999, HashMap::new());

        // Initially empty
        assert!(batch.take_collected_scripts().is_empty());

        // Add scripts using test utility
        let script1 = dashcore::Address::dummy(Network::Testnet, 1).script_pubkey();
        let script2 = dashcore::Address::dummy(Network::Testnet, 2).script_pubkey();
        let wallet_id: WalletId = [7; 32];

        batch.add_scripts_for_wallet(wallet_id, [script1.clone(), script2.clone()]);

        let collected = batch.take_collected_scripts();
        let for_wallet = collected.get(&wallet_id).expect("wallet entry");
        assert_eq!(for_wallet.len(), 2);
        assert!(for_wallet.contains(&script1));
        assert!(for_wallet.contains(&script2));

        // After take, should be empty
        assert!(batch.take_collected_scripts().is_empty());
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
        manager
            .header_storage
            .write()
            .await
            .store_headers(
                &headers.iter().map(crate::types::HashedBlockHeader::from).collect::<Vec<_>>(),
            )
            .await
            .unwrap();

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

    /// Reproduces #892: filters were only ever stored near a high tip (e.g.
    /// headers previously synced from a checkpoint), and the wallet's scan
    /// start is far below that region. `start_download` must not treat the
    /// stored tip watermark as contiguous coverage from `scan_start`:
    /// preloading `load_filters(scan_start, ..)` would read never-populated
    /// segments (debug abort in `SegmentCache::get_items`, sentinel filter
    /// data in release builds). The unreachable tip-region filters are
    /// discarded and the download restarts from `scan_start`.
    #[tokio::test]
    async fn test_start_download_discards_stored_filters_above_scan_start() {
        let mut manager = create_test_manager().await;

        // Block headers cover the whole range so send_pending can resolve stop hashes.
        let headers = dashcore::block::Header::dummy_batch(0..1001);
        manager
            .header_storage
            .write()
            .await
            .store_headers(
                &headers.iter().map(crate::types::HashedBlockHeader::from).collect::<Vec<_>>(),
            )
            .await
            .unwrap();

        // Filters were only ever stored near the tip: 900..=1000. The heights
        // below 900 were never populated.
        {
            let mut filter_storage = manager.filter_storage.write().await;
            for height in 900..=1000u32 {
                filter_storage.store_filter(height, &[height as u8; 8]).await.unwrap();
            }
        }
        // Restart shape: `new()` seeds stored_height from the tip watermark.
        manager.progress.update_stored_height(1000);
        manager.progress.update_filter_header_tip_height(1000);
        manager.progress.update_target_height(1000);

        // Wallet committed far below the stored region, so scan_start = 100.
        manager.wallet.write().await.update_wallet_synced_height(&MOCK_WALLET_ID, 99);

        let (tx, mut rx) = unbounded_channel();
        let events = manager.start_download(&RequestSender::new(tx)).await.unwrap();

        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::Syncing);

        // The unreachable tip-region filters were discarded entirely...
        assert_eq!(manager.filter_storage.read().await.filter_tip_height().await.unwrap(), 0);
        assert_eq!(manager.filter_storage.read().await.filter_start_height().await, None);

        // ...nothing was preloaded into the initial batch...
        let batch = manager.active_batches.get(&100).expect("initial batch at scan_start");
        assert!(batch.filters().is_empty());
        assert!(!batch.verified());
        assert!(!batch.scanned());
        assert_eq!(batch.end_height(), 1000);

        // ...scan gating no longer sees the stale tip watermark...
        assert_eq!(manager.progress.stored_height(), 0);

        // ...and both the store cursor and the download restart from
        // scan_start rather than stored_filters_tip + 1.
        assert_eq!(manager.next_batch_to_store, 100);
        match rx.try_recv().expect("a filter request must have been sent") {
            NetworkRequest::SendMessage(NetworkMessage::GetCFilters(gcf)) => {
                assert_eq!(gcf.start_height, 100);
            }
            other => panic!("Expected GetCFilters, got {:?}", other),
        }
    }

    /// Counterpart to the sparse-storage case: when the stored filter range
    /// actually reaches down to `scan_start`, the preload happens exactly as
    /// before and nothing is discarded.
    #[tokio::test]
    async fn test_start_download_preloads_when_stored_filters_cover_scan_start() {
        let mut manager = create_test_manager().await;

        let headers = dashcore::block::Header::dummy_batch(0..1001);
        manager
            .header_storage
            .write()
            .await
            .store_headers(
                &headers.iter().map(crate::types::HashedBlockHeader::from).collect::<Vec<_>>(),
            )
            .await
            .unwrap();

        // Filters stored densely from genesis through the tip.
        {
            let mut filter_storage = manager.filter_storage.write().await;
            for height in 0..=1000u32 {
                filter_storage.store_filter(height, &[height as u8; 8]).await.unwrap();
            }
        }
        manager.progress.update_stored_height(1000);
        manager.progress.update_filter_header_tip_height(1000);
        manager.progress.update_target_height(1000);

        manager.wallet.write().await.update_wallet_synced_height(&MOCK_WALLET_ID, 99);

        let (tx, mut rx) = unbounded_channel();
        manager.start_download(&RequestSender::new(tx)).await.unwrap();

        assert_eq!(manager.state(), SyncState::Syncing);

        // Storage is untouched.
        assert_eq!(manager.filter_storage.read().await.filter_tip_height().await.unwrap(), 1000);
        assert_eq!(manager.filter_storage.read().await.filter_start_height().await, Some(0));

        // The stored range 100..=1000 was preloaded and the batch is verified
        // and scanned immediately.
        let batch = manager.active_batches.get(&100).expect("initial batch at scan_start");
        assert_eq!(batch.filters().len(), 901);
        assert!(batch.verified());
        assert!(batch.scanned());
        assert_eq!(manager.progress.stored_height(), 1000);

        // Nothing left to download: everything through the filter header tip
        // is already stored.
        assert_eq!(manager.next_batch_to_store, 1001);
        assert!(rx.try_recv().is_err(), "no filter request expected");
    }

    /// Genesis-only storage: a single filter at height 0, scanning from 0.
    /// `filter_tip_height` collapses to 0 for both an empty store and this
    /// one, so gating the preload on `tip > 0` would misread it as empty and
    /// needlessly re-download height 0. The stored start (Some(0)) must drive
    /// the decision: the filter is preloaded and nothing is discarded or
    /// re-requested. Regtest can produce exactly this shape.
    #[tokio::test]
    async fn test_start_download_preloads_genesis_only_stored_filter() {
        let mut manager = create_test_manager().await;

        let headers = dashcore::block::Header::dummy_batch(0..1);
        manager
            .header_storage
            .write()
            .await
            .store_headers(
                &headers.iter().map(crate::types::HashedBlockHeader::from).collect::<Vec<_>>(),
            )
            .await
            .unwrap();

        // Exactly one filter stored, at height 0.
        manager.filter_storage.write().await.store_filter(0, &[0u8; 8]).await.unwrap();
        assert_eq!(manager.filter_storage.read().await.filter_tip_height().await.unwrap(), 0);
        assert_eq!(manager.filter_storage.read().await.filter_start_height().await, Some(0));

        // Restart shape at the genesis tip.
        manager.progress.update_stored_height(0);
        manager.progress.update_filter_header_tip_height(0);
        manager.progress.update_target_height(0);
        // Wallet at genesis: scan_start = 0.

        let (tx, mut rx) = unbounded_channel();
        manager.start_download(&RequestSender::new(tx)).await.unwrap();

        // The lone filter was NOT discarded...
        assert_eq!(manager.filter_storage.read().await.filter_tip_height().await.unwrap(), 0);
        assert_eq!(manager.filter_storage.read().await.filter_start_height().await, Some(0));

        // ...it was preloaded into the initial batch, which is verified and
        // scanned since the whole (single-height) range is covered...
        let batch = manager.active_batches.get(&0).expect("initial batch at scan_start");
        assert_eq!(batch.filters().len(), 1);
        assert!(batch.verified());
        assert!(batch.scanned());
        assert_eq!(manager.progress.stored_height(), 0);

        // ...and the download frontier sits above the stored tip, so no
        // filter request goes out for the already-stored genesis height.
        assert_eq!(manager.next_batch_to_store, 1);
        assert!(rx.try_recv().is_err(), "no filter request expected for the genesis-only store");
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
        // The active batch ends at 200, so try_create_lookahead_batches chains
        // its next start off 201, past the filter header tip 150, and the bound
        // stops it before creating any batch or emitting an event.
        manager.active_batches.insert(101, FiltersBatch::new(101, 200, HashMap::new()));

        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        // New filter headers arrive at 150: committed(100) < tip(150)
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
        manager
            .header_storage
            .write()
            .await
            .store_headers(
                &headers.iter().map(crate::types::HashedBlockHeader::from).collect::<Vec<_>>(),
            )
            .await
            .unwrap();

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

    /// A node that boots already synced takes the `start_download` early
    /// return. That path must still record the scan frontier in
    /// `processing_height`, otherwise the next block creates a lookahead batch
    /// from a stale 0 and reads filters at height 0 that were never stored
    /// (panicking on the empty leading segment).
    #[tokio::test]
    async fn test_handle_new_filter_headers_new_block_starts_at_frontier() {
        let mut manager = create_test_manager().await;

        // Headers cover the synced tip plus the new block. Filter storage is
        // intentionally left empty: with the old behavior the lookahead batch
        // reads from height 0 and trips the empty-segment guard.
        let headers = dashcore::block::Header::dummy_batch(0..102);
        manager
            .header_storage
            .write()
            .await
            .store_headers(
                &headers.iter().map(crate::types::HashedBlockHeader::from).collect::<Vec<_>>(),
            )
            .await
            .unwrap();

        manager.set_state(SyncState::WaitForEvents);
        manager.wallet.write().await.update_wallet_synced_height(&MOCK_WALLET_ID, 100);
        manager.progress.update_committed_height(100);
        manager.progress.update_stored_height(100);
        manager.progress.update_filter_header_tip_height(100);
        manager.progress.update_target_height(100);

        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        // Boot already synced: start_download detects the synced state and
        // returns early, but must still advance the scan frontier.
        let events = manager.start_download(&requests).await.unwrap();
        assert_eq!(manager.state(), SyncState::Synced);
        assert!(events.iter().any(|e| matches!(
            e,
            SyncEvent::FiltersSyncComplete {
                tip_height: 100
            }
        )));
        assert_eq!(manager.processing_height, 101);

        // A new block extends the chain; the lookahead batch must start at the
        // frontier, not at height 0.
        manager.handle_new_filter_headers(101, &requests).await.unwrap();
        assert!(!manager.active_batches.contains_key(&0));
        assert_eq!(manager.active_batches.keys().next(), Some(&101));
    }

    /// The same predicate mismatch on the OTHER route into `start_download`.
    ///
    /// A filter-header event arriving while the manager sits in `WaitForEvents`
    /// takes `handle_new_filter_headers`, not `start_sync` — and that arm asked
    /// the same subset question. A verified batch waiting in `pending_batches`
    /// with `active_batches` already empty therefore fell through to
    /// `start_download` and its `debug_assert!(is_idle())`.
    #[tokio::test]
    async fn test_new_filter_headers_resumes_when_only_pending_batches_survive() {
        let (mut manager, _headers, _filter) = setup_synced_manager_at_tip().await;

        manager.pending_batches.insert(FiltersBatch::new(0, 99, HashMap::new()));
        assert!(manager.active_batches.is_empty(), "the old predicate says idle");
        assert!(!manager.is_idle(), "the invariant start_download asserts says otherwise");

        manager.set_state(SyncState::WaitForEvents);
        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        // Must extend the target and leave the surviving work alone.
        let events = manager.handle_new_filter_headers(200, &requests).await.unwrap();

        assert!(events.is_empty(), "extending the target emits nothing");
        // `pending_batches` alone does not prove the guard held: `start_download`
        // preserves it too, so a broken guard would reinitialize the pipeline and
        // still leave this at 1. The state and the absence of a fresh active
        // batch are what tell resuming from restarting — and unlike the
        // `debug_assert` inside `start_download`, they still hold in a release
        // build, where that assert is compiled out.
        assert_eq!(
            manager.state(),
            SyncState::WaitForEvents,
            "the arm must return without changing state"
        );
        assert!(
            manager.active_batches.is_empty(),
            "must not start a fresh download over the surviving work"
        );
        assert_eq!(manager.pending_batches.len(), 1, "the surviving batch must not be discarded");
    }

    /// A verified batch waiting in `pending_batches` outlives the last active
    /// one, so a reconnect used to fall through the resume guard — which asked
    /// only about `active_batches` — into `start_download`, whose
    /// `debug_assert!(is_idle())` then aborted the process. It is reachable in
    /// the field: `on_disconnect` preserves this state by design, and a build
    /// with debug assertions on turns the mismatch into a crash rather than a
    /// log line.
    #[tokio::test]
    async fn test_start_sync_resumes_when_only_pending_batches_survive() {
        let (mut manager, _headers, _filter) = setup_synced_manager_at_tip().await;

        // What a disconnect leaves behind after the last active batch finished
        // downloading but before its verified output was processed.
        manager.pending_batches.insert(FiltersBatch::new(0, 99, HashMap::new()));
        assert!(manager.active_batches.is_empty(), "the guard's old predicate says idle");
        assert!(!manager.is_idle(), "the invariant start_download asserts says otherwise");

        manager.set_state(SyncState::WaitingForConnections);
        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        // Must resume rather than start a fresh download over the top of it.
        let events = manager.start_sync(&requests).await.unwrap();

        assert!(events.is_empty(), "resuming emits no SyncStart");
        assert_eq!(manager.state(), SyncState::Syncing);
        // See the sibling test: `start_download` keeps `pending_batches`, so only
        // the absence of a new active batch proves this resumed rather than
        // restarted, and it proves it without relying on a debug assertion.
        assert!(
            manager.active_batches.is_empty(),
            "must not start a fresh download over the surviving work"
        );
        assert_eq!(
            manager.pending_batches.len(),
            1,
            "the surviving batch must not be discarded by the resume"
        );
    }

    /// A fully synced node that reconnects and then sees one new block must
    /// commit it. `start_sync` takes the `stored == committed == tip` branch,
    /// reports `Synced`, and anchors the store and processing cursors at the
    /// frontier; the boundary block's filter header, body, and commit then flow
    /// through to the new tip. If those cursors were left at 0, the boundary
    /// block would create a batch from height 0 and wedge the in-order store
    /// loop so `committed_height` freezes one below tip.
    #[tokio::test]
    async fn test_start_sync_synced_restart_then_boundary_block_commits() {
        let (mut manager, headers, boundary_filter) = setup_synced_manager_at_tip().await;

        // Fully-synced restart: `start_sync` requires `WaitingForConnections`.
        manager.set_state(SyncState::WaitingForConnections);

        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        // Reconnect: the already-synced branch reports completion and anchors the
        // store/processing cursors at the frontier.
        let events = manager.start_sync(&requests).await.unwrap();
        assert_eq!(manager.state(), SyncState::Synced);
        assert!(events.iter().any(|e| matches!(
            e,
            SyncEvent::FiltersSyncComplete {
                tip_height: 100
            }
        )));

        // Block 101's filter header lands: the manager queues its body download
        // and a processing batch starting at the frontier (not at height 0).
        manager
            .handle_sync_event(
                &SyncEvent::FilterHeadersStored {
                    start_height: 101,
                    end_height: 101,
                    tip_height: 101,
                },
                &requests,
            )
            .await
            .unwrap();

        // The peer answers with the boundary filter body over the real path.
        let peer: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let cfilter = CFilter {
            filter_type: 0,
            block_hash: headers[101].block_hash(),
            filter: boundary_filter.content.clone(),
        };
        manager
            .handle_message(Message::new(peer, NetworkMessage::CFilter(cfilter)), &requests)
            .await
            .unwrap();

        // A trailing tick drives any residual processing to completion.
        manager.tick(&requests).await.unwrap();

        assert_eq!(manager.progress.committed_height(), 101);
        assert_eq!(manager.state(), SyncState::Synced);
        assert!(manager.active_batches.is_empty());
        assert!(manager.next_batch_to_store > 100);
    }

    /// A node that boots already synced (default `WaitForEvents` state, which
    /// `start_sync` never runs from) must commit a new block that lands after
    /// the initial `FilterHeadersSyncComplete`. That event drives
    /// `start_download`'s early return, which must anchor the store cursor and
    /// park the pipeline at the frontier. Left at their defaults, the next
    /// block makes `extend_target` re-request every filter from height 1 and
    /// wedges the in-order store loop on a `next_batch_to_store` of 0, freezing
    /// `committed_height` one below tip.
    #[tokio::test]
    async fn test_synced_boot_then_boundary_block_commits() {
        let (mut manager, headers, boundary_filter) = setup_synced_manager_at_tip().await;

        // Fully-synced boot leaves the manager in its default state.
        assert_eq!(manager.state(), SyncState::WaitForEvents);

        let (tx, mut rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        // Filter header sync completing at the stored tip reports Synced via
        // `start_download`'s early return, anchoring the frontier cursors.
        let events = manager
            .handle_sync_event(
                &SyncEvent::FilterHeadersSyncComplete {
                    tip_height: 100,
                },
                &requests,
            )
            .await
            .unwrap();
        assert_eq!(manager.state(), SyncState::Synced);
        assert!(events.iter().any(|e| matches!(
            e,
            SyncEvent::FiltersSyncComplete {
                tip_height: 100
            }
        )));
        assert_eq!(manager.next_batch_to_store, 101);

        // Block 101's filter header lands.
        manager
            .handle_sync_event(
                &SyncEvent::FilterHeadersStored {
                    start_height: 101,
                    end_height: 101,
                    tip_height: 101,
                },
                &requests,
            )
            .await
            .unwrap();

        // Only the boundary body may be requested: a pipeline left unparked
        // would re-request every filter from height 1 here.
        while let Ok(request) = rx.try_recv() {
            let (NetworkRequest::SendMessage(msg)
            | NetworkRequest::SendMessageToPeer(msg, _)
            | NetworkRequest::BroadcastMessage(msg)) = request;
            if let NetworkMessage::GetCFilters(get) = msg {
                assert_eq!(get.start_height, 101, "unexpected filter re-download");
            }
        }

        // The peer answers with the boundary filter body over the real path.
        let peer: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let cfilter = CFilter {
            filter_type: 0,
            block_hash: headers[101].block_hash(),
            filter: boundary_filter.content.clone(),
        };
        manager
            .handle_message(Message::new(peer, NetworkMessage::CFilter(cfilter)), &requests)
            .await
            .unwrap();

        // A trailing tick drives any residual processing to completion.
        manager.tick(&requests).await.unwrap();

        assert_eq!(manager.progress.committed_height(), 101);
        assert_eq!(manager.state(), SyncState::Synced);
        assert!(manager.active_batches.is_empty());
    }

    /// A node that restores its filter header tip ahead of its stored filter
    /// bodies (headers at 101, bodies and commit at 100) must download and
    /// commit the boundary body on reconnect. `start_sync` delegates to the
    /// download path, which sees the scan frontier at or below the restored
    /// tip and requests the boundary body rather than parking in
    /// `WaitForEvents` and never asking for it.
    #[tokio::test]
    async fn test_start_sync_filter_headers_ahead_of_bodies_commits_boundary() {
        let (mut manager, headers, boundary_filter) = setup_synced_manager_at_tip().await;

        // Filter headers restored ahead of the stored filter bodies.
        manager.progress.update_filter_header_tip_height(101);
        manager.set_state(SyncState::WaitingForConnections);

        let (tx, mut rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        // Reconnect delegates to the download path, which must request the
        // boundary body at 101 rather than parking without asking for it.
        let events = manager.start_sync(&requests).await.unwrap();
        assert_eq!(manager.state(), SyncState::Syncing);
        assert!(!events.iter().any(|e| matches!(e, SyncEvent::SyncStart { .. })));
        assert!(manager.active_batches.contains_key(&101));

        let mut requested_boundary = false;
        while let Ok(request) = rx.try_recv() {
            let (NetworkRequest::SendMessage(msg)
            | NetworkRequest::SendMessageToPeer(msg, _)
            | NetworkRequest::BroadcastMessage(msg)) = request;
            if let NetworkMessage::GetCFilters(get) = msg {
                assert_eq!(get.start_height, 101, "unexpected filter re-download");
                requested_boundary = true;
            }
        }
        assert!(requested_boundary, "boundary filter body 101 must be requested");

        // The peer answers with the boundary filter body over the real path.
        let peer: SocketAddr = "127.0.0.1:19999".parse().unwrap();
        let cfilter = CFilter {
            filter_type: 0,
            block_hash: headers[101].block_hash(),
            filter: boundary_filter.content.clone(),
        };
        manager
            .handle_message(Message::new(peer, NetworkMessage::CFilter(cfilter)), &requests)
            .await
            .unwrap();

        manager.tick(&requests).await.unwrap();

        assert_eq!(manager.progress.committed_height(), 101);
        assert_eq!(manager.state(), SyncState::Synced);
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
        manager
            .header_storage
            .write()
            .await
            .store_headers(
                &headers.iter().map(crate::types::HashedBlockHeader::from).collect::<Vec<_>>(),
            )
            .await
            .unwrap();

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

        // A wallet below the anchor is "behind" by the raw comparison, yet
        // needs nothing that any scan could reach. Restarting for it is what
        // wiped the in-flight batches. 199_998 rather than only 0 so a fix
        // keyed on "synced_height == 0" does not pass.
        for synced in [0, 1, 199_998, 199_999, 200_000] {
            let mut manager = create_anchored_test_manager(200_000, 10).await;
            manager.wallet.write().await.update_wallet_synced_height(&MOCK_WALLET_ID, synced);
            manager.set_state(SyncState::Synced);
            manager.progress.update_committed_height(199_999);
            manager.progress.update_stored_height(200_010);
            manager.progress.update_filter_header_tip_height(200_010);
            manager.progress.update_target_height(200_010);

            let events = manager.tick(&requests).await.unwrap();

            assert!(events.is_empty(), "synced_height {synced} produced events");
            assert!(
                manager.active_batches.is_empty(),
                "synced_height {synced} triggered a rescan below the anchor"
            );
            assert_eq!(manager.progress.committed_height(), 199_999, "synced_height {synced}");
            assert_eq!(manager.state(), SyncState::Synced, "synced_height {synced}");
        }
    }

    /// A wallet whose `synced_height` sits below the chain anchor must still
    /// reach `Synced`. This is the mainnet stall: the CLI creates wallets with
    /// birth height 0 while `hd_wallet_sync_floor` anchors the chain at the
    /// checkpoint above it, so `synced_height` stayed at 0 and every tick threw
    /// the scan away and started over.
    #[tokio::test]
    async fn anchored_chain_advances_a_wallet_that_starts_below_the_anchor() {
        let mut manager = create_anchored_test_manager(200_000, 10).await;
        manager.wallet.write().await.set_addresses(vec![Address::dummy(Network::Regtest, 7)]);
        assert_eq!(manager.wallet.read().await.wallet_synced_height(&MOCK_WALLET_ID), 0);

        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        manager.handle_new_filter_headers(200_010, &requests).await.unwrap();
        assert!(
            manager.active_batches.contains_key(&200_000),
            "the first batch starts at the anchor, not at the wallet's synced_height"
        );
        assert_eq!(manager.progress.committed_height(), 199_999);

        manager.tick(&requests).await.unwrap();

        assert_eq!(
            manager.wallet.read().await.wallet_synced_height(&MOCK_WALLET_ID),
            200_010,
            "the batch covers everything the wallet can ever be scanned for, so it certifies it"
        );
        assert_eq!(manager.progress.committed_height(), 200_010);
        assert!(manager.active_batches.is_empty());
        assert_eq!(manager.state(), SyncState::Synced);

        // A second tick must be a no-op rather than the start of another round.
        manager.tick(&requests).await.unwrap();
        assert_eq!(manager.progress.committed_height(), 200_010);
        assert!(manager.active_batches.is_empty());
        assert_eq!(manager.wallet.read().await.wallet_synced_height(&MOCK_WALLET_ID), 200_010);
    }

    /// The observed symptom of the stall: the same range requested over and
    /// over. A tick must not discard filters that are still in flight, which a
    /// rescan does by replacing the whole pipeline.
    #[tokio::test]
    async fn anchored_chain_tick_does_not_rerequest_in_flight_filters() {
        let mut manager = create_anchored_test_manager(200_000, 10).await;
        // Drop the stored filters so the batch needs a real download.
        manager.filter_storage.write().await.clear_filters().await.unwrap();
        manager.progress.update_stored_height(0);

        let (tx, mut rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        manager.handle_new_filter_headers(200_010, &requests).await.unwrap();

        assert_eq!(
            drain_getcfilters(&mut rx),
            1,
            "the initial download issues exactly one getcfilters"
        );

        manager.tick(&requests).await.unwrap();

        assert_eq!(
            drain_getcfilters(&mut rx),
            0,
            "a tick re-requested filters that were still in flight"
        );
    }

    /// A wallet added at runtime reports `synced_height = 0` regardless of what
    /// the client anchored at, so raising the birth height at construction does
    /// not cover this path. It must converge, not rescan forever.
    #[tokio::test]
    async fn anchored_chain_converges_for_a_wallet_added_after_the_anchor() {
        let wallet_a: WalletId = [0xA1; 32];
        let wallet_b: WalletId = [0xB2; 32];
        let multi = Arc::new(RwLock::new(MultiMockWallet::new()));
        multi.write().await.insert_wallet(
            wallet_a,
            MockWalletState {
                synced_height: 200_010,
                ..MockWalletState::default()
            },
        );

        let mut manager = create_multi_test_manager(multi.clone()).await;
        seed_anchored_storage(&manager, 200_000, 10).await;

        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        // Reach the frontier with only wallet A present.
        manager.handle_new_filter_headers(200_010, &requests).await.unwrap();
        manager.tick(&requests).await.unwrap();
        assert!(manager.active_batches.is_empty());
        assert_eq!(manager.progress.committed_height(), 200_010);

        // Wallet B joins afterwards, reporting 0 like every runtime add does.
        // This one genuinely needs a rescan, so the floor must not suppress it.
        multi.write().await.insert_wallet(wallet_b, MockWalletState::default());

        for _ in 0..3 {
            manager.tick(&requests).await.unwrap();
        }

        assert_eq!(
            multi.read().await.wallet_synced_height(&wallet_b),
            200_010,
            "the newly added wallet is certified for everything above the anchor"
        );
        assert_eq!(
            multi.read().await.wallet_synced_height(&wallet_a),
            200_010,
            "the already-synced wallet never regresses"
        );
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

    #[tokio::test]
    async fn test_handle_new_filter_headers_starts_scan_when_stored_equals_tip() {
        let mut manager = create_test_manager().await;

        let headers = dashcore::block::Header::dummy_batch(0..101);
        manager
            .header_storage
            .write()
            .await
            .store_headers(
                &headers.iter().map(crate::types::HashedBlockHeader::from).collect::<Vec<_>>(),
            )
            .await
            .unwrap();

        // Populate filter storage so load_filters succeeds during lookahead
        {
            let dummy_filter = BlockFilter::new(&[0u8; 32]);
            let mut fs = manager.filter_storage.write().await;
            for h in 0..=100 {
                fs.store_filter(h, &dummy_filter.content).await.unwrap();
            }
        }

        // Filters stored but not yet committed (restart scenario).
        manager.set_state(SyncState::Synced);
        manager.progress.update_filter_header_tip_height(100);
        manager.progress.update_stored_height(100);
        manager.progress.update_committed_height(0);
        manager.progress.update_target_height(1000);
        manager.filter_pipeline.init(101, 100);

        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        // committed(0) < tip(100) fires the guard even though stored == tip.
        // Because stored >= tip, send_pending is skipped (no downloads needed).
        let _events = manager.handle_new_filter_headers(100, &requests).await.unwrap();

        assert_eq!(manager.state(), SyncState::Syncing);
        assert!(
            manager.active_batches.contains_key(&0),
            "expected lookahead batch at processing_height=0, got keys: {:?}",
            manager.active_batches.keys().collect::<Vec<_>>()
        );
    }

    /// When the filter header tip grows while a historical rescan is still
    /// draining `active_batches`, the boundary block must still get a
    /// processing batch. `handle_new_filter_headers` must create the lookahead
    /// batch even with a non-empty active set, or a block landing during a
    /// restart reinit window gets its body downloaded but never a processing
    /// batch, freezing `committed_height` one below tip. Asserted directly
    /// after the call (no `tick`) so the deterministic path is verified in
    /// isolation.
    #[tokio::test]
    async fn test_handle_new_filter_headers_extends_boundary_during_rescan() {
        let mut manager = create_test_manager().await;

        let headers = Header::dummy_batch(0..102);
        manager
            .header_storage
            .write()
            .await
            .store_headers(&headers.iter().map(HashedBlockHeader::from).collect::<Vec<_>>())
            .await
            .unwrap();
        {
            let dummy_filter = BlockFilter::new(&[0u8; 32]);
            let mut fs = manager.filter_storage.write().await;
            for h in 0..=101 {
                fs.store_filter(h, &dummy_filter.content).await.unwrap();
            }
        }

        // Historical rescan in progress: an active batch ends at the old tip
        // 100, filters stored through 101, committed still climbing.
        manager.set_state(SyncState::Syncing);
        manager.progress.update_committed_height(0);
        manager.progress.update_stored_height(101);
        manager.progress.update_filter_header_tip_height(100);
        manager.progress.update_target_height(101);
        manager.active_batches.insert(0, FiltersBatch::new(0, 100, HashMap::new()));

        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        // New block 101 arrives: tip grows past the in-flight rescan boundary.
        manager.handle_new_filter_headers(101, &requests).await.unwrap();

        assert!(
            manager.active_batches.contains_key(&101),
            "boundary block 101 must get a processing batch even while a rescan \
             is draining active_batches, got keys: {:?}",
            manager.active_batches.keys().collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_handle_new_filter_headers_skips_when_fully_committed() {
        let mut manager = create_test_manager().await;

        // Everything committed, stored, and at tip. No work to do.
        manager.set_state(SyncState::Synced);
        manager.progress.update_committed_height(100);
        manager.progress.update_stored_height(100);
        manager.progress.update_filter_header_tip_height(100);
        manager.progress.update_target_height(1000);
        manager.filter_pipeline.init(101, 100);

        let (tx, _rx) = unbounded_channel();
        let requests = RequestSender::new(tx);

        let events = manager.handle_new_filter_headers(100, &requests).await.unwrap();

        assert_eq!(manager.state(), SyncState::Synced);
        assert!(events.is_empty());
        assert!(manager.active_batches.is_empty());
    }

    #[tokio::test]
    async fn test_try_process_batch_commits_after_scan_in_same_call() {
        let mut manager = create_test_manager().await;

        let headers = dashcore::block::Header::dummy_batch(0..101);
        manager
            .header_storage
            .write()
            .await
            .store_headers(
                &headers.iter().map(crate::types::HashedBlockHeader::from).collect::<Vec<_>>(),
            )
            .await
            .unwrap();
        {
            let dummy_filter = BlockFilter::new(&[0u8; 32]);
            let mut fs = manager.filter_storage.write().await;
            for h in 0..=100 {
                fs.store_filter(h, &dummy_filter.content).await.unwrap();
            }
        }

        manager.set_state(SyncState::Syncing);
        manager.progress.update_stored_height(100);
        manager.progress.update_filter_header_tip_height(100);
        manager.progress.update_committed_height(0);
        manager.progress.update_target_height(100);
        manager.processing_height = 0;

        // Create a batch that has all filters stored but is not yet scanned.
        // Phase 1 (commit) skips it because it's not scanned.
        // Phase 2 (scan) marks it scanned.
        // Phase 3 (second commit) commits it immediately.
        let mut batch = FiltersBatch::new(0, 100, manager.load_filters(0, 100).await.unwrap());
        batch.mark_verified();
        manager.active_batches.insert(0, batch);

        let events = manager.try_process_batch().await.unwrap();

        // Batch was scanned and committed in a single try_process_batch call.
        assert!(manager.active_batches.is_empty());
        assert_eq!(manager.progress.committed_height(), 100);
        assert!(
            events.iter().any(|e| matches!(
                e,
                SyncEvent::FiltersSyncComplete {
                    tip_height: 100
                }
            )),
            "expected FiltersSyncComplete, got {:?}",
            events
        );
    }
}
