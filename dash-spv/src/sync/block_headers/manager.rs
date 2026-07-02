//! Headers manager for parallel sync.
//!
//! Downloads and validates block headers from peers. Handles both initial sync
//! and post-sync header updates. Emits BlockHeadersStored events for other managers.
//!
//! Uses HeadersPipeline for parallel downloads across checkpoint-defined segments
//! during initial sync. The same pipeline is reused for post-sync updates.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::chain::{ChainWork, CheckpointManager, ForkCandidate};
use crate::error::{SyncError, SyncResult};
use crate::network::RequestSender;
use crate::storage::{BlockHeaderStorage, BlockHeaderTip, MetadataStorage};
use crate::sync::block_headers::fork_buffer::{BranchKey, ForkBuffer};
use crate::sync::block_headers::HeadersPipeline;
use crate::sync::{BlockHeadersProgress, ProgressPercentage, SyncEvent, SyncManager, SyncState};
use crate::types::HashedBlockHeader;
use crate::validation::{BlockHeaderValidator, Validator};
use dashcore::block::Header;
use dashcore::consensus::Params;
use dashcore::network::message_blockdata::Inventory;
use dashcore::{BlockHash, Network};
use tokio::sync::RwLock;

/// Headers manager for downloading and validating block headers.
///
/// This manager handles:
/// - Initial header sync using parallel pipeline (checkpoint-based segments)
/// - Post-sync header updates via inventory announcements
///
/// Generic over `H: BlockHeaderStorage` to allow different storage implementations.
pub struct BlockHeadersManager<H: BlockHeaderStorage, M: MetadataStorage> {
    /// Current progress of the manager.
    pub(super) progress: BlockHeadersProgress,
    /// Block header storage.
    pub(super) header_storage: Arc<RwLock<H>>,
    /// Metadata storage for persisting the best peer tip height.
    pub(super) metadata_storage: Arc<RwLock<M>>,
    /// Pipeline for parallel header downloads (used for both initial sync and post-sync).
    pub(super) pipeline: HeadersPipeline,
    /// Pending block announcements waiting for headers message (post-sync).
    pub(super) pending_announcements: HashMap<BlockHash, Instant>,
    /// Peers we've sent a GetHeaders to after sync, so Dash Core knows our tip
    /// and can send us header announcements instead of inv.
    pub(super) announced_peers: HashSet<SocketAddr>,
    /// Per-peer buffer of fork branches awaiting promotion.
    pub(super) fork_buffer: ForkBuffer,
    /// Fork branch that has beaten the active chain on work and is ready for
    /// promotion by the sync coordinator.
    pending_fork_candidate: Option<ForkCandidate>,
    /// Maps the last-known fork branch tip hash to its ancestor height.
    /// Populated whenever a fork batch is buffered so that subsequent batches
    /// extending the same branch are routed to `ingest_fork` correctly.
    fork_tip_index: HashMap<BlockHash, u32>,
}

impl<H: BlockHeaderStorage, M: MetadataStorage> std::fmt::Debug for BlockHeadersManager<H, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockHeadersManager")
            .field("progress", &self.progress)
            .field("pipeline", &self.pipeline)
            .finish_non_exhaustive()
    }
}

impl<H: BlockHeaderStorage, M: MetadataStorage> BlockHeadersManager<H, M> {
    /// Create a new headers manager with the given storage and checkpoint manager.
    pub async fn new(
        header_storage: Arc<RwLock<H>>,
        metadata_storage: Arc<RwLock<M>>,
        checkpoint_manager: Arc<CheckpointManager>,
        network: Network,
    ) -> SyncResult<Self> {
        let tip = header_storage
            .read()
            .await
            .get_tip()
            .await
            .ok_or_else(|| SyncError::MissingDependency("No tip in storage".to_string()))?;

        // Restore persisted target height, fall back to tip height
        let target_height =
            metadata_storage.read().await.load_last_target_height().await.unwrap_or(tip.height());

        let mut initial_progress = BlockHeadersProgress::default();
        initial_progress.set_state(SyncState::WaitingForConnections);
        initial_progress.update_tip_height(tip.height());
        initial_progress.update_target_height(target_height);

        tracing::info!("BlockHeadersManager initialized at height {}", tip.height());

        Ok(Self {
            progress: initial_progress,
            header_storage,
            metadata_storage,
            pipeline: HeadersPipeline::new(checkpoint_manager),
            pending_announcements: HashMap::new(),
            announced_peers: HashSet::new(),
            fork_buffer: ForkBuffer::new(Params::new(network)),
            pending_fork_candidate: None,
            fork_tip_index: HashMap::new(),
        })
    }

    /// Number of ancestor headers DGW v3 requires to compute next bits.
    const DGW_HISTORY: u32 = 24;

    /// Deepest ancestor below the tip a fork may anchor at. ChainLocks make
    /// reorgs beyond a handful of blocks impossible on Dash, so this bound sits
    /// far above any realistic reorg while capping the active-chain read a fork
    /// can trigger from an unauthenticated peer.
    const MAX_FORK_DEPTH: u32 = 2000;

    /// Consume the fork candidate set when a buffered branch overtook the
    /// active chain.
    fn take_pending_fork_candidate(&mut self) -> Option<ForkCandidate> {
        self.pending_fork_candidate.take()
    }

    /// Announce a detected fork candidate as a [`SyncEvent::ForkDetected`] so
    /// the coordinator observes staged detection through the event stream
    /// instead of the candidate being dropped by periodic maintenance.
    fn drain_fork_detection(&mut self) -> Vec<SyncEvent> {
        match self.take_pending_fork_candidate() {
            Some(candidate) => vec![SyncEvent::ForkDetected {
                ancestor_height: candidate.ancestor_height,
                header_count: candidate.headers.len(),
                total_work: candidate.total_work,
            }],
            None => Vec::new(),
        }
    }

    /// Load the DGW-window history needed to validate a fork anchored at
    /// `ancestor_height`, returning the ancestor header and the window (oldest
    /// first, ancestor last). Rejects forks anchored too deep or without enough
    /// stored history to retarget.
    async fn load_fork_history(&self, ancestor_height: u32) -> SyncResult<(Header, Vec<Header>)> {
        let storage = self.header_storage.read().await;
        let tip_height = storage
            .get_tip_height()
            .await
            .ok_or_else(|| SyncError::MissingDependency("no tip height".to_string()))?;
        // Reject forks anchored deeper than `MAX_FORK_DEPTH` below the tip
        // before loading any history or the active-chain extension. A single
        // valid-PoW header at a deep ancestor would otherwise force an
        // unbounded active-chain read from one unauthenticated peer. ChainLocks
        // make reorgs this deep impossible on Dash, so the bound is safe.
        if tip_height.saturating_sub(ancestor_height) > Self::MAX_FORK_DEPTH {
            return Err(SyncError::Validation(format!(
                "fork ancestor at height {} exceeds max fork depth {} below tip {}",
                ancestor_height,
                Self::MAX_FORK_DEPTH,
                tip_height
            )));
        }
        // Mirror dashd's pre-DGW-window short-circuit: when the ancestor sits
        // below `DGW_HISTORY`, DGW returns `pow_limit` regardless of the
        // window contents, so we only need what storage actually has.
        let pre_window = ancestor_height + 1 < Self::DGW_HISTORY;
        // A checkpoint-seeded node holds no headers below its storage floor.
        // Clamp the window there so a read never dips below the lowest stored
        // header, which would panic in debug and return zeroed sentinel headers
        // in release.
        let floor = storage.get_start_height().await.unwrap_or(0);
        let history_start = ancestor_height.saturating_sub(Self::DGW_HISTORY).max(floor);
        if !pre_window && ancestor_height + 1 - history_start < Self::DGW_HISTORY {
            return Err(SyncError::Validation(format!(
                "insufficient stored history to validate fork at ancestor height {}: need {} headers above storage floor {}",
                ancestor_height,
                Self::DGW_HISTORY,
                floor
            )));
        }
        let history = storage.load_headers(history_start..ancestor_height + 1).await?;
        let ancestor = *history.last().ok_or_else(|| {
            SyncError::Validation(format!("missing ancestor header at height {}", ancestor_height))
        })?;
        Ok((ancestor, history))
    }

    /// Buffer a fork extension whose ancestor is on the active chain at a
    /// height strictly below the current tip.
    async fn ingest_fork(
        &mut self,
        peer: SocketAddr,
        headers: &[Header],
        ancestor_height: u32,
    ) -> SyncResult<()> {
        let (ancestor, history) = self.load_fork_history(ancestor_height).await?;

        // Validate and buffer the fork before touching the active-chain
        // extension. The `history` load above is bounded to the DGW window,
        // but the extension load in `judge_fork_winner` is unbounded in the
        // ancestor depth, so it must stay behind full validation to deny a
        // cheap remote memory amplification via crafted low-ancestor forks.
        self.fork_buffer.ingest(peer, headers, ancestor_height, ancestor, &history)?;

        // Track the new fork tip so subsequent batches extending this branch
        // can be routed here even though their prev_blockhash won't be found
        // on the active chain.
        if let Some(last) = headers.last() {
            self.fork_tip_index.insert(last.block_hash(), ancestor_height);
        }

        self.judge_fork_winner(peer).await
    }

    /// Extend a buffered fork branch with a continuation batch that builds on
    /// its tip rather than on the active chain.
    async fn extend_fork(
        &mut self,
        peer: SocketAddr,
        ancestor_height: u32,
        tip_hash: BlockHash,
        headers: &[Header],
    ) -> SyncResult<()> {
        let (_ancestor, history) = self.load_fork_history(ancestor_height).await?;

        let new_tip = self.fork_buffer.extend_branch((peer, tip_hash), headers, &history)?;

        // Re-key the branch's tip so the next continuation still routes here.
        self.fork_tip_index.remove(&tip_hash);
        self.fork_tip_index.insert(new_tip, ancestor_height);

        self.judge_fork_winner(peer).await
    }

    /// Judge every buffered branch against the active-chain work measured from
    /// that branch's own ancestor and promote the heaviest winner, if any.
    async fn judge_fork_winner(&mut self, peer: SocketAddr) -> SyncResult<()> {
        // A branch that forks deeper must beat more active blocks, so each
        // baseline is branch-specific and a heavier raw extension can still lose
        // while a shallower branch wins.
        let branches: Vec<(BranchKey, u32, ChainWork)> = self.fork_buffer.branches().collect();
        let Some(min_ancestor) = branches.iter().map(|(_, ancestor, _)| *ancestor).min() else {
            return Ok(());
        };

        let storage = self.header_storage.read().await;
        let tip_height = storage
            .get_tip_height()
            .await
            .ok_or_else(|| SyncError::MissingDependency("no tip height".to_string()))?;
        let active = storage.load_headers(min_ancestor + 1..tip_height + 1).await?;
        drop(storage);

        // Among branches that outweigh their own baseline, pick the one with the
        // most work on the shared baseline anchored at the lowest candidate
        // ancestor. Every candidate forks off the same active chain, so the
        // active blocks below its own ancestor are the common prefix that makes
        // the totals comparable.
        let mut winner: Option<(BranchKey, ChainWork)> = None;
        for (key, ancestor, branch_work) in branches {
            let split = (ancestor - min_ancestor) as usize;
            let own_baseline = ChainWork::accumulate(ChainWork::zero(), &active[split..]);
            if branch_work <= own_baseline {
                continue;
            }
            let comparable = ChainWork::accumulate(branch_work, &active[..split]);
            if winner.as_ref().is_none_or(|(_, best)| comparable > *best) {
                winner = Some((key, comparable));
            }
        }

        if let Some((key, _)) = winner {
            if let Some(candidate) = self.fork_buffer.take_branch(key) {
                tracing::info!(
                    "Fork candidate ready for promotion: ancestor={} headers={} (peer {})",
                    candidate.ancestor_height,
                    candidate.headers.len(),
                    peer
                );
                self.pending_fork_candidate = Some(candidate);
                self.prune_fork_tip_index();
            }
        }
        Ok(())
    }

    /// Remove `fork_tip_index` entries whose branch no longer exists in the buffer.
    pub(super) fn prune_fork_tip_index(&mut self) {
        let live_tips: HashSet<BlockHash> = self.fork_buffer.branch_tip_hashes().copied().collect();
        self.fork_tip_index.retain(|tip, _| live_tips.contains(tip));
    }

    pub(super) async fn tip(&self) -> SyncResult<BlockHeaderTip> {
        self.header_storage
            .read()
            .await
            .get_tip()
            .await
            .ok_or_else(|| SyncError::MissingDependency("storage not initialized".to_string()))
    }

    /// Build a Dash Core style block locator from the current storage tip.
    ///
    /// First 10 entries step back by 1, then the step doubles each entry. The
    /// walk stops at the storage floor (the lowest stored height, genesis on a
    /// full client or the seed checkpoint on a checkpoint-synced client), which
    /// is always the final entry. Used as the `getheaders` locator so peers on
    /// a fork can find the most recent common ancestor.
    pub(super) async fn build_locator(&self) -> SyncResult<Vec<BlockHash>> {
        let storage = self.header_storage.read().await;
        let tip_height = storage
            .get_tip_height()
            .await
            .ok_or_else(|| SyncError::MissingDependency("storage not initialized".to_string()))?;
        let floor = storage.get_start_height().await.unwrap_or(0);

        let mut locator = Vec::with_capacity(32);
        let mut step: u32 = 1;
        let mut height = tip_height;
        let mut iterations: u32 = 0;
        loop {
            if let Some(header) = storage.get_header(height).await? {
                locator.push(header.block_hash());
            }
            if height <= floor {
                break;
            }
            // Clamp to the floor so a checkpoint-synced client never walks below
            // its lowest stored header. Double the step by iteration count, not
            // by entries found, so a missing header cannot stall the decay.
            height = height.saturating_sub(step).max(floor);
            iterations += 1;
            if iterations > 10 {
                step = step.saturating_mul(2);
            }
        }
        Ok(locator)
    }

    /// Build the fork-finding locator for a retry only when it would actually
    /// be sent: the tip segment must be ready to send and still anchored at the
    /// storage tip. Before the first response the tip segment tip equals the
    /// storage tip, so a peer on a fork can find a common ancestor. Once a
    /// response advances the segment past storage the storage-derived locator no
    /// longer matches the segment tip, so the empty slice keeps `send_pending`
    /// on its single-entry fallback and the walk's storage reads are skipped.
    pub(super) async fn tip_retry_locator(&self) -> SyncResult<Vec<BlockHash>> {
        match self.pipeline.sendable_tip_segment_hash() {
            Some(anchor) if anchor == *self.tip().await?.hash() => self.build_locator().await,
            _ => Ok(Vec::new()),
        }
    }

    /// Validate and store headers batch.
    async fn store_headers(&mut self, headers: &[HashedBlockHeader]) -> SyncResult<BlockHeaderTip> {
        debug_assert!(!headers.is_empty());

        // Validate batch for internal continuity and PoW
        BlockHeaderValidator::new().validate(headers)?;

        // Store headers
        self.header_storage.write().await.store_headers(headers).await?;

        let tip = self.tip().await?;

        // Update state
        self.progress.update_tip_height(tip.height());
        self.progress.add_processed(headers.len() as u32);

        Ok(tip)
    }

    /// Handle incoming headers message (used for both initial sync and post-sync).
    pub(super) async fn handle_headers_pipeline(
        &mut self,
        headers: &[Header],
        peer: SocketAddr,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        if !self.pipeline.is_initialized() {
            // Pipeline not initialized (shouldn't happen in normal flow)
            tracing::warn!("Received headers but pipeline not initialized");
            return Ok(vec![]);
        }

        // Classify the batch against the active chain before the pipeline sees
        // it. A batch is only a real fork when it diverges from what we already
        // store. Batches that merely re-list headers we hold (lagging or
        // retrying peers) must not be treated as forks, and an overlapping
        // batch that also carries new headers must yield its new tail to the
        // pipeline rather than the fork buffer.
        let mut pipeline_start = 0usize;
        if let Some(first) = headers.first() {
            let storage = self.header_storage.read().await;
            let prev_height = storage.get_header_height_by_hash(&first.prev_blockhash).await?;
            let tip_height = storage
                .get_tip_height()
                .await
                .ok_or_else(|| SyncError::MissingDependency("no tip height".to_string()))?;

            if let Some(prev_h) = prev_height {
                // Compare the batch against the active chain starting one past
                // the anchor. Only load the overlapping range, up to our tip.
                let scan_end = (prev_h + 1 + headers.len() as u32).min(tip_height + 1);
                let stored_overlap = if prev_h + 1 < scan_end {
                    storage.load_headers(prev_h + 1..scan_end).await?
                } else {
                    Vec::new()
                };
                drop(storage);

                let mut shared = 0usize;
                let mut forked = false;
                for (i, existing) in stored_overlap.iter().enumerate() {
                    if headers[i].block_hash() == existing.block_hash() {
                        shared += 1;
                    } else {
                        forked = true;
                        break;
                    }
                }

                if forked {
                    // Diverges at height `prev_h + 1 + shared`, anchored at the
                    // last header the batch and the active chain share.
                    self.ingest_fork(peer, &headers[shared..], prev_h + shared as u32).await?;
                    return Ok(self.drain_fork_detection());
                }
                if shared == headers.len() {
                    // Entire batch is already on the active chain: a duplicate.
                    return Ok(Vec::new());
                }
                // Headers past the shared prefix extend our tip. Hand only that
                // new tail to the pipeline.
                pipeline_start = shared;
            } else if let Some(&ancestor_height) = self.fork_tip_index.get(&first.prev_blockhash) {
                drop(storage);
                // prev_blockhash is a buffered fork tip, not on the active
                // chain. Extend that branch so a fork announced across several
                // headers messages accumulates work. A continuation whose tip
                // belongs to another peer's branch has no entry under this
                // peer's key and is dropped.
                let tip_hash = first.prev_blockhash;
                match self.extend_fork(peer, ancestor_height, tip_hash, headers).await {
                    Ok(()) => {}
                    Err(SyncError::ForkChainBreak(msg)) => {
                        tracing::debug!("fork continuation chain break: {}", msg);
                    }
                    Err(e) => return Err(e),
                }
                return Ok(self.drain_fork_detection());
            }
        }
        let headers = &headers[pipeline_start..];

        let was_syncing = self.state() == SyncState::Syncing;
        let tip_was_complete = self.pipeline.is_tip_complete();

        // Route headers to the pipeline, validates checkpoint match.
        let matched = self.pipeline.receive_headers(headers)?;

        if matched.is_none() && !headers.is_empty() {
            tracing::debug!(
                "Headers not matched by pipeline (prev_hash: {}), may be post-sync update",
                headers[0].prev_blockhash
            );
        }

        // Send more requests during initial sync or active post-sync catch-up
        // before processing ready batches so network and storage work overlap.
        // A retry that fires before the tip segment has advanced past storage
        // still needs the full fork-finding locator, so build it only when the
        // tip segment is anchored at the storage tip.
        if was_syncing || !tip_was_complete {
            let locator = self.tip_retry_locator().await?;
            let sent = self.pipeline.send_pending(requests, &locator)?;
            if sent > 0 {
                tracing::debug!("Pipeline sent {} more requests", sent);
            }
        }

        // Process ready-to-store segments
        let mut events = Vec::new();
        let ready_batches = self.pipeline.take_ready_to_store();

        for (_start_height, batch_headers) in ready_batches {
            if !batch_headers.is_empty() {
                // Validate chain continuity with current tip
                let tip = self.tip().await?;
                if batch_headers[0].header().prev_blockhash != *tip.hash() {
                    return Err(SyncError::Validation(format!(
                        "Segment chain break: expected prev {}, got {}",
                        tip.hash(),
                        batch_headers[0].header().prev_blockhash
                    )));
                }

                // Clear any pending announcements for headers we're storing
                for header in &batch_headers {
                    self.pending_announcements.remove(header.hash());
                }

                let new_tip = self.store_headers(&batch_headers).await?;
                // Update target if we've exceeded it (post-sync case)
                if new_tip.height() > self.progress.target_height() {
                    self.progress.update_target_height(new_tip.height());
                }
                events.push(SyncEvent::BlockHeadersStored {
                    tip_height: new_tip.height(),
                });
            }
        }

        // After storing unsolicited post-sync headers, mark the tip complete so the next header goes through
        // the clean reset path. Don't mark complete during active catch-up.
        if !was_syncing && tip_was_complete && !events.is_empty() {
            self.pipeline.mark_tip_complete();
        }

        if was_syncing && self.pipeline.is_complete() {
            // If blocks were announced during sync, request them before finalizing the sync
            if !self.pending_announcements.is_empty() {
                tracing::info!(
                    "Pipeline complete but {} blocks announced during sync, requesting headers",
                    self.pending_announcements.len()
                );
                self.pipeline.reset_tip_segment();
                let locator = self.build_locator().await?;
                self.pipeline.send_pending(requests, &locator)?;
            } else {
                // Synced to the tip and no pending announcements, finalize and emit event
                let tip = self.tip().await?;
                self.progress.update_target_height(tip.height());
                self.progress.set_state(SyncState::Synced);
                tracing::info!("Headers sync complete at height {}", tip.height());
                events.push(SyncEvent::BlockHeaderSyncComplete {
                    tip_height: tip.height(),
                });
            }
        }

        if matched.is_some() {
            self.progress.bump_last_activity();
        }
        Ok(events)
    }

    /// Handle inventory announcements for new blocks.
    ///
    /// During initial sync, Dash Core sends inv (not header announcements) because
    /// it doesn't think we have the parent block. We track these announcements so
    /// we can request headers after sync completes.
    ///
    /// When synced, we expect unsolicited header announcements. The tick handler
    /// uses a timeout to send fallback GetHeaders if headers don't arrive.
    pub(super) async fn handle_inventory(
        &mut self,
        inv: &[Inventory],
        _requests: &RequestSender,
    ) -> SyncResult<()> {
        for inv_item in inv {
            if let Inventory::Block(block_hash) = inv_item {
                // Check if already pending
                if self.pending_announcements.contains_key(block_hash) {
                    continue;
                }

                // Check if we already have this block
                if let Ok(Some(_)) =
                    self.header_storage.read().await.get_header_height_by_hash(block_hash).await
                {
                    continue;
                }

                tracing::info!("New block announced via inv: {}", block_hash);
                self.pending_announcements.insert(*block_hash, Instant::now());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::checkpoints::testnet_checkpoints;
    use crate::network::{MessageType, NetworkEvent, NetworkRequest, RequestSender};
    use crate::storage::{
        DiskStorageManager, PersistentBlockHeaderStorage, PersistentMetadataStorage, StorageManager,
    };
    use crate::sync::{ManagerIdentifier, SyncManager, SyncManagerProgress};
    use dashcore::network::message::NetworkMessage;
    use dashcore::{block::Version, CompactTarget, TxMerkleNode};
    use dashcore_hashes::Hash;
    use tokio::sync::mpsc::unbounded_channel;

    type TestBlockHeadersManager =
        BlockHeadersManager<PersistentBlockHeaderStorage, PersistentMetadataStorage>;

    fn create_test_checkpoint_manager() -> Arc<CheckpointManager> {
        Arc::new(CheckpointManager::new(testnet_checkpoints()))
    }

    async fn create_test_manager() -> TestBlockHeadersManager {
        let mut storage = DiskStorageManager::with_temp_dir().await.unwrap();
        // Store a genesis header so the manager can initialize
        let genesis = Header::dummy_batch(0..1);
        storage
            .store_headers(
                &genesis.iter().map(crate::types::HashedBlockHeader::from).collect::<Vec<_>>(),
            )
            .await
            .unwrap();
        let checkpoint_manager = create_test_checkpoint_manager();
        BlockHeadersManager::new(
            storage.block_headers(),
            storage.metadata(),
            checkpoint_manager,
            Network::Testnet,
        )
        .await
        .expect("Failed to create BlockHeadersManager")
    }

    /// Create a manager in synced state with an initialized pipeline.
    async fn create_synced_manager() -> TestBlockHeadersManager {
        let mut manager = create_test_manager().await;
        let tip = manager.tip().await.unwrap();
        manager.pipeline.init(tip.height(), *tip.hash(), tip.height());
        manager.progress.set_state(SyncState::Synced);
        manager
    }

    #[tokio::test]
    async fn test_block_headers_manager_new() {
        let manager = create_test_manager().await;
        assert_eq!(manager.identifier(), ManagerIdentifier::BlockHeader);
        assert_eq!(manager.state(), SyncState::WaitingForConnections);
        assert_eq!(manager.wanted_message_types(), vec![MessageType::Headers, MessageType::Inv]);
    }

    #[tokio::test]
    async fn test_headers_manager_progress() {
        let mut manager = create_test_manager().await;
        manager.progress.update_tip_height(100);
        manager.progress.update_target_height(200);
        manager.progress.add_processed(50);

        let progress = manager.progress();
        if let SyncManagerProgress::BlockHeaders(progress) = progress {
            assert_eq!(progress.state(), SyncState::WaitingForConnections);
            assert_eq!(progress.tip_height(), 100);
            assert_eq!(progress.target_height(), 200);
            assert_eq!(progress.processed(), 50);
            assert!(progress.last_activity().elapsed().as_secs() < 1);
        } else {
            panic!("Expected SyncManagerProgress::BlockHeaders");
        }
    }

    #[tokio::test]
    async fn test_headers_manager_has_pipeline() {
        let manager = create_test_manager().await;
        assert!(!manager.pipeline.is_initialized());
        assert_eq!(manager.pipeline.segment_count(), 0);
    }

    fn create_test_request_sender(
    ) -> (RequestSender, tokio::sync::mpsc::UnboundedReceiver<NetworkRequest>) {
        let (tx, rx) = unbounded_channel();
        (RequestSender::new(tx), rx)
    }

    #[tokio::test]
    async fn test_unsolicited_post_sync_header_does_not_trigger_get_headers() {
        let mut manager = create_test_manager().await;
        let tip = manager.tip().await.unwrap();
        let tip_hash = *tip.hash();

        // Simulate completed sync: pipeline initialized with tip segment marked complete
        manager.pipeline.init(0, tip_hash, 0);
        manager.pipeline.mark_tip_complete();
        manager.progress.set_state(SyncState::Synced);

        let (sender, mut rx) = create_test_request_sender();

        let header = Header::dummy_chain(1, tip_hash).remove(0);
        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();

        let events = manager.handle_headers_pipeline(&[header], peer, &sender).await.unwrap();

        // Header should have been stored
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            SyncEvent::BlockHeadersStored {
                tip_height: 1
            }
        ));

        // No GetHeaders request should have been sent
        assert!(rx.try_recv().is_err());

        // Tip segment marked complete again for the next unsolicited header
        assert!(manager.pipeline.is_tip_complete());
    }

    #[tokio::test]
    async fn test_peer_tip_announcement_lifecycle() {
        let mut manager = create_synced_manager().await;
        let (requests, mut rx) = create_test_request_sender();

        let addr: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let connect = NetworkEvent::PeerConnected {
            address: addr,
        };

        // Connect sends a peer-targeted GetHeaders
        let events = manager.handle_network_event(&connect, &requests).await.unwrap();
        assert!(events.is_empty());
        assert!(manager.announced_peers.contains(&addr));
        match rx.try_recv().unwrap() {
            NetworkRequest::SendMessageToPeer(_, target_addr) => {
                assert_eq!(target_addr, addr);
            }
            other => panic!("Expected SendMessageToPeer, got {:?}", other),
        }

        // Same peer again sends nothing (already announced)
        manager.handle_network_event(&connect, &requests).await.unwrap();
        assert!(rx.try_recv().is_err());

        // Disconnect removes from announced set
        let disconnect = NetworkEvent::PeerDisconnected {
            address: addr,
        };
        manager.handle_network_event(&disconnect, &requests).await.unwrap();
        assert!(!manager.announced_peers.contains(&addr));

        // Reconnect sends GetHeaders again
        manager.handle_network_event(&connect, &requests).await.unwrap();
        assert!(manager.announced_peers.contains(&addr));
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn test_peer_tip_announcement_guards() {
        // Not synced: peer connect does nothing
        let mut manager = create_test_manager().await;
        let (requests, mut rx) = create_test_request_sender();
        let addr: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let connect = NetworkEvent::PeerConnected {
            address: addr,
        };

        manager.handle_network_event(&connect, &requests).await.unwrap();
        assert!(!manager.announced_peers.contains(&addr));
        assert!(rx.try_recv().is_err());

        // Active catch-up: peer connect skipped while pipeline has pending request
        let mut manager = create_synced_manager().await;
        manager.pipeline.reset_tip_segment();
        let locator = manager.build_locator().await.unwrap();
        manager.pipeline.send_pending(&requests, &locator).unwrap();
        rx.try_recv().unwrap(); // drain the pipeline GetHeaders

        manager.handle_network_event(&connect, &requests).await.unwrap();
        assert!(!manager.announced_peers.contains(&addr));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_disconnect_preserves_pipeline_and_resumes_from_advanced_tip() {
        let mut manager = create_test_manager().await;
        let (requests, mut rx) = create_test_request_sender();

        // Use a target below the first testnet checkpoint (50000) so the
        // pipeline produces a single open-ended tip segment.
        let initial_event = NetworkEvent::PeersUpdated {
            connected_count: 1,
            best_height: Some(40_000),
            addresses: vec![],
        };
        manager.handle_network_event(&initial_event, &requests).await.unwrap();
        assert_eq!(manager.state(), SyncState::Syncing);
        assert!(manager.pipeline.is_initialized());
        assert_eq!(manager.pipeline.segment_count(), 1);

        let initial_locator = match rx.try_recv().expect("initial GetHeaders not sent") {
            NetworkRequest::SendMessage(NetworkMessage::GetHeaders(msg)) => msg.locator_hashes[0],
            other => panic!("Expected GetHeaders, got {:?}", other),
        };
        assert!(rx.try_recv().is_err());

        // Simulate a peer response. The single tip segment drains its buffer
        // through take_ready_to_store, advancing the storage tip and the
        // segment's current_tip_hash to advanced_hash.
        let header = Header::dummy_chain(1, initial_locator).remove(0);
        let advanced_hash = header.block_hash();
        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        manager.handle_headers_pipeline(&[header], peer, &requests).await.unwrap();

        // Drain the follow-up GetHeaders that send_pending issued.
        match rx.try_recv().expect("follow-up GetHeaders not sent") {
            NetworkRequest::SendMessage(NetworkMessage::GetHeaders(msg)) => {
                assert_eq!(msg.locator_hashes[0], advanced_hash);
            }
            other => panic!("Expected GetHeaders, got {:?}", other),
        }
        assert!(rx.try_recv().is_err());

        let disconnect_event = NetworkEvent::PeersUpdated {
            connected_count: 0,
            best_height: Some(40_000),
            addresses: vec![],
        };
        manager.handle_network_event(&disconnect_event, &requests).await.unwrap();
        assert_eq!(manager.state(), SyncState::WaitingForConnections);
        assert!(
            manager.pipeline.is_initialized(),
            "pipeline must survive disconnect so resume can reuse validated state"
        );
        assert_eq!(manager.pipeline.segment_count(), 1);

        // Reconnect: start_sync must skip pipeline.init and resume by sending
        // GetHeaders from each segment's preserved current_tip_hash.
        manager.handle_network_event(&initial_event, &requests).await.unwrap();
        assert_eq!(manager.state(), SyncState::Syncing);

        let resumed_locator = match rx.try_recv().expect("resumed GetHeaders not sent") {
            NetworkRequest::SendMessage(NetworkMessage::GetHeaders(msg)) => msg.locator_hashes[0],
            other => panic!("Expected GetHeaders, got {:?}", other),
        };
        assert_eq!(
            resumed_locator, advanced_hash,
            "GetHeaders on reconnect must use the preserved current_tip_hash"
        );
        assert_ne!(resumed_locator, initial_locator);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_disconnect_after_sync_resumes_and_catches_up() {
        let mut manager = create_synced_manager().await;
        let tip = manager.tip().await.unwrap();
        let synced_hash = *tip.hash();
        manager.pipeline.mark_tip_complete();
        assert!(manager.pipeline.is_tip_complete());

        let (requests, mut rx) = create_test_request_sender();

        let disconnect_event = NetworkEvent::PeersUpdated {
            connected_count: 0,
            best_height: Some(tip.height()),
            addresses: vec![],
        };
        manager.handle_network_event(&disconnect_event, &requests).await.unwrap();
        assert_eq!(manager.state(), SyncState::WaitingForConnections);
        assert!(manager.pipeline.is_initialized());

        // Reconnect with a higher peer best_height (a new block was mined).
        let reconnect_event = NetworkEvent::PeersUpdated {
            connected_count: 1,
            best_height: Some(tip.height() + 1),
            addresses: vec![],
        };
        manager.handle_network_event(&reconnect_event, &requests).await.unwrap();
        assert_eq!(manager.state(), SyncState::Syncing);

        let resumed_locator = match rx.try_recv().expect("resumed GetHeaders not sent") {
            NetworkRequest::SendMessage(NetworkMessage::GetHeaders(msg)) => msg.locator_hashes[0],
            other => panic!("Expected GetHeaders, got {:?}", other),
        };
        assert_eq!(resumed_locator, synced_hash);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn lagging_peer_sending_tip_extension_is_not_classified_as_fork() {
        // A header whose prev_blockhash equals our tip (equal height, not strictly
        // less) must flow through the normal pipeline path, never the fork
        // buffer. This guards against treating slow peers (or our own next
        // block arriving after a catch-up) as a reorg.
        let mut manager = create_test_manager().await;
        let tip = manager.tip().await.unwrap();
        let tip_hash = *tip.hash();

        manager.pipeline.init(0, tip_hash, 0);
        manager.pipeline.mark_tip_complete();
        manager.progress.set_state(SyncState::Synced);

        let (sender, _rx) = create_test_request_sender();
        let header = Header::dummy_chain(1, tip_hash).remove(0);
        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();

        let events = manager.handle_headers_pipeline(&[header], peer, &sender).await.unwrap();

        // Extension stored, no fork candidate generated.
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], SyncEvent::BlockHeadersStored { .. }));
        assert!(manager.take_pending_fork_candidate().is_none());
    }

    #[tokio::test]
    async fn test_build_locator_shape_matches_dashd_algorithm() {
        // Build a 10K-block chain in storage and verify the locator follows
        // the dashd algorithm: first 10 entries step back by 1, then the step
        // doubles, and genesis is always included.
        let mut storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let chain = Header::dummy_chain(10_000, BlockHash::all_zeros());
        // First header in dummy_chain has prev = all_zeros (treat as genesis).
        storage.store_headers(&chain).await.unwrap();
        let checkpoint_manager = create_test_checkpoint_manager();
        let manager = BlockHeadersManager::new(
            storage.block_headers(),
            storage.metadata(),
            checkpoint_manager,
            Network::Testnet,
        )
        .await
        .unwrap();

        let locator = manager.build_locator().await.unwrap();
        let tip_height = (chain.len() - 1) as u32;

        // First entry equals the tip hash.
        assert_eq!(locator[0], chain[tip_height as usize].block_hash());

        // Reconstruct expected heights with the dashd algorithm.
        let mut expected_heights: Vec<u32> = Vec::new();
        let mut step: u32 = 1;
        let mut height = tip_height;
        loop {
            expected_heights.push(height);
            if height == 0 {
                break;
            }
            height = height.saturating_sub(step);
            if expected_heights.len() > 10 {
                step = step.saturating_mul(2);
            }
        }

        assert_eq!(locator.len(), expected_heights.len(), "locator length");
        for (i, h) in expected_heights.iter().enumerate() {
            assert_eq!(
                locator[i],
                chain[*h as usize].block_hash(),
                "locator[{}] should be hash at height {}",
                i,
                h
            );
        }

        // Genesis is the final entry.
        assert_eq!(*locator.last().unwrap(), chain[0].block_hash());

        // Stays under the dashd ~32 entry bound.
        assert!(locator.len() <= 32, "locator should not exceed 32 entries, got {}", locator.len());
    }

    #[tokio::test]
    async fn build_locator_stops_at_checkpoint_floor() {
        // A checkpoint-synced client stores headers starting at a high height.
        // The locator must terminate at that floor instead of walking to
        // genesis, so it stays bounded and never probes below the floor.
        const FLOOR: u32 = 1_000_000;
        let mut storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let chain = Header::dummy_batch(FLOOR..FLOOR + 200);
        storage.store_headers_at_height(&chain, FLOOR).await.unwrap();
        let checkpoint_manager = create_test_checkpoint_manager();
        let manager = BlockHeadersManager::new(
            storage.block_headers(),
            storage.metadata(),
            checkpoint_manager,
            Network::Testnet,
        )
        .await
        .unwrap();

        let locator = manager.build_locator().await.unwrap();

        // First entry is the tip, last entry is the seed checkpoint floor.
        assert_eq!(locator[0], chain[chain.len() - 1].block_hash());
        assert_eq!(*locator.last().unwrap(), chain[0].block_hash());

        // Bounded, and far smaller than a full walk down to genesis would be.
        assert!(locator.len() <= 32, "locator should stay bounded, got {}", locator.len());

        // Every entry is a stored header at or above the floor.
        for hash in &locator {
            let height = manager
                .header_storage
                .read()
                .await
                .get_header_height_by_hash(hash)
                .await
                .unwrap()
                .expect("locator entry must be a stored header");
            assert!(height >= FLOOR, "locator probed below the floor at height {}", height);
        }
    }

    /// Mine a header extending `prev` at `time` with the given `bits`, using
    /// an easy target so a valid nonce is found in a few tries.
    fn mine_header(prev: BlockHash, time: u32, bits: CompactTarget) -> Header {
        for nonce in 0u32..256 {
            let header = Header {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: TxMerkleNode::all_zeros(),
                time,
                bits,
                nonce,
            };
            if header.target().is_met_by(header.block_hash()) {
                return header;
            }
        }
        panic!("nonce space exhausted");
    }

    /// Build a regtest manager seeded with `count` blocks so the storage tip is
    /// at height `count - 1`. Returns the manager and the stored chain.
    async fn create_regtest_manager_with_chain(
        count: usize,
    ) -> (TestBlockHeadersManager, Vec<Header>) {
        let mut storage = DiskStorageManager::with_temp_dir().await.unwrap();
        // Build a real hash-chained regtest chain using easy PoW so storage
        // can index the hashes for `get_header_height_by_hash`.
        let easy_bits = CompactTarget::from_consensus(0x207fffff);
        let mut prev = BlockHash::all_zeros();
        let mut chain = Vec::with_capacity(count);
        for i in 0..count {
            let h = mine_header(prev, 1_700_000_000 + i as u32 * 600, easy_bits);
            prev = h.block_hash();
            chain.push(h);
        }
        storage.store_headers(&chain).await.unwrap();
        let checkpoint_manager = Arc::new(CheckpointManager::new(vec![]));
        let manager = BlockHeadersManager::new(
            storage.block_headers(),
            storage.metadata(),
            checkpoint_manager,
            Network::Regtest,
        )
        .await
        .expect("failed to create regtest manager");
        (manager, chain)
    }

    #[tokio::test]
    async fn fork_near_checkpoint_floor_rejects_without_reading_below_floor() {
        // A checkpoint-seeded node holds no headers below its storage floor. A
        // fork anchored within the DGW window of that floor must be rejected
        // with a validation error rather than reading below the floor, which
        // panics in debug and returns sentinel headers in release.
        const FLOOR: u32 = 1_000_000;
        let easy_bits = CompactTarget::from_consensus(0x207fffff);
        let mut storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let mut prev = BlockHash::all_zeros();
        let mut chain = Vec::new();
        for i in 0..30u32 {
            let h = mine_header(prev, 1_700_000_000 + i * 600, easy_bits);
            prev = h.block_hash();
            chain.push(h);
        }
        storage.store_headers_at_height(&chain, FLOOR).await.unwrap();
        let mut manager = BlockHeadersManager::new(
            storage.block_headers(),
            storage.metadata(),
            Arc::new(CheckpointManager::new(vec![])),
            Network::Regtest,
        )
        .await
        .unwrap();

        // Ancestor sits three blocks above the floor, so the DGW window reaches
        // below it.
        let ancestor_height = FLOOR + 3;
        let ancestor = chain[3];
        let fork = mine_header(ancestor.block_hash(), ancestor.time + 11 * 600 + 1, easy_bits);
        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();

        let err = manager.ingest_fork(peer, &[fork], ancestor_height).await.unwrap_err();
        assert!(
            matches!(err, SyncError::Validation(_)),
            "expected a graceful validation error, got {:?}",
            err
        );
        assert_eq!(manager.fork_buffer.len(), 0);
    }

    #[tokio::test]
    async fn fork_deeper_than_max_depth_is_rejected_before_loading() {
        // A fork anchored deeper than MAX_FORK_DEPTH below the tip must be
        // rejected outright, before any history or active-chain read, so a
        // single peer cannot force a huge storage load.
        const FLOOR: u32 = 1_000_000;
        let easy_bits = CompactTarget::from_consensus(0x207fffff);
        let mut storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let mut prev = BlockHash::all_zeros();
        let mut chain = Vec::new();
        for i in 0..30u32 {
            let h = mine_header(prev, 1_700_000_000 + i * 600, easy_bits);
            prev = h.block_hash();
            chain.push(h);
        }
        storage.store_headers_at_height(&chain, FLOOR).await.unwrap();
        let mut manager = BlockHeadersManager::new(
            storage.block_headers(),
            storage.metadata(),
            Arc::new(CheckpointManager::new(vec![])),
            Network::Regtest,
        )
        .await
        .unwrap();

        let tip_height = manager.tip().await.unwrap().height();
        let ancestor_height = tip_height - (TestBlockHeadersManager::MAX_FORK_DEPTH + 1);
        let fork = mine_header(chain[0].block_hash(), chain[0].time + 11 * 600 + 1, easy_bits);
        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();

        let err = manager.ingest_fork(peer, &[fork], ancestor_height).await.unwrap_err();
        assert!(
            matches!(&err, SyncError::Validation(msg) if msg.contains("max fork depth")),
            "expected a max-fork-depth validation error, got {:?}",
            err
        );
        assert_eq!(manager.fork_buffer.len(), 0);
    }

    #[tokio::test]
    async fn overlap_batch_with_new_tip_is_stored_via_pipeline_not_buffered() {
        // A batch whose first header is our current tip and whose second header
        // is a genuinely new block must not be classified as a fork. It flows
        // through the normal pipeline, which stores the new tail.
        let easy_bits = CompactTarget::from_consensus(0x207fffff);
        let (mut manager, chain) = create_regtest_manager_with_chain(5).await;
        let tip = manager.tip().await.unwrap();
        let tip_hash = *tip.hash();

        manager.pipeline.init(0, tip_hash, tip.height());
        manager.pipeline.mark_tip_complete();
        manager.progress.set_state(SyncState::Synced);

        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let (sender, _rx) = create_test_request_sender();

        // Overlap: the current tip (chain[4]) followed by a new block.
        let overlap_tip = *chain.last().unwrap();
        let new_tip = mine_header(overlap_tip.block_hash(), overlap_tip.time + 600, easy_bits);
        let events =
            manager.handle_headers_pipeline(&[overlap_tip, new_tip], peer, &sender).await.unwrap();

        // Not buffered as a fork, and the new tip is stored.
        assert_eq!(manager.fork_buffer.len(), 0);
        assert!(manager.take_pending_fork_candidate().is_none());
        assert_eq!(manager.tip().await.unwrap().height(), 5);
        assert!(events.iter().any(|e| matches!(
            e,
            SyncEvent::BlockHeadersStored {
                tip_height: 5
            }
        )));
    }

    #[tokio::test]
    async fn fork_header_at_depth_is_routed_to_buffer() {
        // Store a 5-block chain (heights 0-4). Build a fork extending height 3,
        // whose active extension is only height 4 (one block). The first fork
        // header is routed to the fork buffer, not the pipeline. A continuation
        // header that builds on the buffered tip must extend the same branch so
        // the two-block fork outweighs the single active block and fires a
        // detection event.
        let easy_bits = CompactTarget::from_consensus(0x207fffff);

        let (mut manager, chain) = create_regtest_manager_with_chain(5).await;
        let tip = manager.tip().await.unwrap();
        let tip_hash = *tip.hash();

        manager.pipeline.init(0, tip_hash, tip.height());
        manager.pipeline.mark_tip_complete();
        manager.progress.set_state(SyncState::Synced);

        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let (sender, _rx) = create_test_request_sender();

        // Build one valid fork header extending chain[3] (height 3, depth 1).
        let ancestor = chain[3];
        let fork_time = ancestor.time + 11 * 600 + 1;
        let fork_header = mine_header(ancestor.block_hash(), fork_time, easy_bits);

        let events = manager.handle_headers_pipeline(&[fork_header], peer, &sender).await.unwrap();

        // Fork path returns no events, not the pipeline path. A single fork
        // block ties the single active block, so nothing is promoted yet.
        assert!(events.is_empty());
        assert_eq!(manager.fork_buffer.len(), 1);
        assert!(manager.take_pending_fork_candidate().is_none());

        // Second batch extending the fork: prev_blockhash is the first fork
        // header's hash, not on the active chain. The fork_tip_index routes it
        // into extend_fork, which extends the buffered branch rather than
        // dropping it. The branch now has two blocks and beats the single active
        // block, firing a ForkDetected event with the combined header count.
        let fork_tip = fork_header.block_hash();
        let second_fork_time = fork_time + 700;
        let second_fork_header = mine_header(fork_tip, second_fork_time, easy_bits);

        let events =
            manager.handle_headers_pipeline(&[second_fork_header], peer, &sender).await.unwrap();
        assert!(events.iter().any(|e| matches!(
            e,
            SyncEvent::ForkDetected {
                ancestor_height: 3,
                header_count: 2,
                ..
            }
        )));
        // The winning branch was taken for promotion, so the buffer is empty.
        assert_eq!(manager.fork_buffer.len(), 0);
    }

    #[tokio::test]
    async fn deeper_lighter_fork_is_judged_against_its_own_ancestor() {
        // A deep branch with the largest raw extension work can still lose
        // against the active chain measured from its own deep ancestor, while a
        // shallower branch beats the shorter active extension above its later
        // ancestor. Every buffered branch is judged against its own baseline, so
        // the deep loser never masks the shallow winner.
        let easy_bits = CompactTarget::from_consensus(0x207fffff);
        let (mut manager, chain) = create_regtest_manager_with_chain(5).await;
        let tip = manager.tip().await.unwrap();
        manager.pipeline.init(0, *tip.hash(), tip.height());
        manager.pipeline.mark_tip_complete();
        manager.progress.set_state(SyncState::Synced);

        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let (sender, _rx) = create_test_request_sender();

        // Deep fork forks at height 1 with three blocks. The active extension
        // from height 1 spans heights 2, 3, 4, so three equal-difficulty fork
        // blocks tie and cannot outweigh it.
        let deep_a = mine_header(chain[1].block_hash(), chain[1].time + 11 * 600 + 1, easy_bits);
        let deep_b = mine_header(deep_a.block_hash(), deep_a.time + 700, easy_bits);
        let deep_c = mine_header(deep_b.block_hash(), deep_b.time + 700, easy_bits);
        let events = manager
            .handle_headers_pipeline(&[deep_a, deep_b, deep_c], peer, &sender)
            .await
            .unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.fork_buffer.len(), 1);
        assert!(manager.take_pending_fork_candidate().is_none());

        // Shallow fork forks at height 3 with two blocks. Its active extension is
        // only height 4 (one block), so two blocks outweigh it. The deep branch
        // carries more raw extension work, so judging only the heaviest branch
        // would evaluate the deep loser and let the shallow winner expire.
        let shallow_a = mine_header(chain[3].block_hash(), chain[3].time + 11 * 600 + 5, easy_bits);
        let shallow_b = mine_header(shallow_a.block_hash(), shallow_a.time + 700, easy_bits);
        let events =
            manager.handle_headers_pipeline(&[shallow_a, shallow_b], peer, &sender).await.unwrap();

        // The shallow winner is detected on its own baseline (ancestor height 3),
        // even though the deep branch carries more raw extension work.
        assert!(events.iter().any(|e| matches!(
            e,
            SyncEvent::ForkDetected {
                ancestor_height: 3,
                header_count: 2,
                ..
            }
        )));
    }

    #[tokio::test]
    async fn winning_fork_emits_fork_detected_event() {
        // A fork that outweighs the active chain from its own ancestor is
        // promoted and announced as a `ForkDetected` event, so detection is
        // delivered through the event stream rather than dropped.
        let easy_bits = CompactTarget::from_consensus(0x207fffff);
        let (mut manager, chain) = create_regtest_manager_with_chain(5).await;
        let tip = manager.tip().await.unwrap();
        manager.pipeline.init(0, *tip.hash(), tip.height());
        manager.pipeline.mark_tip_complete();
        manager.progress.set_state(SyncState::Synced);

        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let (sender, _rx) = create_test_request_sender();

        // Fork at height 3, whose active extension is only height 4 (one block),
        // with two blocks, so it outweighs that single active block.
        let fork_a = mine_header(chain[3].block_hash(), chain[3].time + 11 * 600 + 1, easy_bits);
        let fork_b = mine_header(fork_a.block_hash(), fork_a.time + 700, easy_bits);
        let events =
            manager.handle_headers_pipeline(&[fork_a, fork_b], peer, &sender).await.unwrap();

        assert!(events.iter().any(|e| matches!(
            e,
            SyncEvent::ForkDetected {
                ancestor_height: 3,
                header_count: 2,
                ..
            }
        )));
        // The candidate was delivered via the event, not left pending.
        assert!(manager.take_pending_fork_candidate().is_none());
    }

    #[tokio::test]
    async fn fork_continuation_non_fork_chain_break_error_propagates() {
        let easy_bits = CompactTarget::from_consensus(0x207fffff);
        let (mut manager, chain) = create_regtest_manager_with_chain(5).await;
        let tip = manager.tip().await.unwrap();
        let tip_hash = *tip.hash();
        manager.pipeline.init(0, tip_hash, tip.height());
        manager.pipeline.mark_tip_complete();
        manager.progress.set_state(SyncState::Synced);

        let peer: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let (sender, _rx) = create_test_request_sender();

        // Buffer a genuine one-block branch off chain[3].
        let ancestor = chain[3];
        let fork_a = mine_header(ancestor.block_hash(), ancestor.time + 11 * 600 + 1, easy_bits);
        manager.handle_headers_pipeline(&[fork_a], peer, &sender).await.unwrap();
        assert_eq!(manager.fork_buffer.len(), 1);

        // A continuation whose PoW passes but whose bits differ from the DGW
        // expected value fails validation with a non-ForkChainBreak error, which
        // must reach the Err(e) => return Err(e) arm.
        let mut cont = mine_header(fork_a.block_hash(), fork_a.time + 700, easy_bits);
        cont.bits = CompactTarget::from_consensus(0x2100_ffff);

        let result = manager.handle_headers_pipeline(&[cont], peer, &sender).await;
        assert!(
            matches!(&result, Err(SyncError::Validation(_))),
            "non-ForkChainBreak error must propagate from fork continuation: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_empty_headers_after_tip_announcement_is_harmless() {
        let mut manager = create_synced_manager().await;
        manager.pipeline.mark_tip_complete();
        let (requests, mut rx) = create_test_request_sender();

        // Announce tip to a new peer
        let addr: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let connect = NetworkEvent::PeerConnected {
            address: addr,
        };
        manager.handle_network_event(&connect, &requests).await.unwrap();
        rx.try_recv().unwrap(); // drain the GetHeaders request

        // Peer responds with empty headers (same height as us)
        let events = manager.handle_headers_pipeline(&[], addr, &requests).await.unwrap();

        // No events emitted, no requests sent, tip segment stays complete
        assert!(events.is_empty());
        assert!(rx.try_recv().is_err());
        assert!(manager.pipeline.is_tip_complete());
    }

    #[tokio::test]
    async fn tick_retries_sync_with_full_locator_before_first_response() {
        // Simulate a timeout before any headers response arrives: the pipeline is
        // initialized but no headers have been received yet, so the tip segment's
        // current_tip_hash still equals the storage tip. The tick handler must
        // retry with the full fork-finding locator so a peer on a stale, reorged
        // tip can still find the most recent common ancestor. A single-entry
        // locator here would strand a node restarted on a reorged-away tip.
        let (mut manager, chain) = create_regtest_manager_with_chain(5).await;
        let expected_locator = manager.build_locator().await.unwrap();
        assert!(
            expected_locator.len() > 1,
            "test needs a multi-entry locator to distinguish full from single-entry"
        );
        assert_eq!(expected_locator[0], chain.last().unwrap().block_hash());

        let initial_event = NetworkEvent::PeersUpdated {
            connected_count: 1,
            best_height: Some(40_000),
            addresses: vec![],
        };
        let (requests, mut rx) = create_test_request_sender();
        manager.handle_network_event(&initial_event, &requests).await.unwrap();
        assert_eq!(manager.state(), SyncState::Syncing);

        // Drain the initial GetHeaders from start_sync.
        rx.try_recv().expect("start_sync must send initial GetHeaders");
        assert!(rx.try_recv().is_err());

        // Simulate a timeout: clear the in-flight request so send_pending can retry,
        // then fire tick as if the 30-second request timeout had elapsed.
        manager.pipeline.clear_in_flight();
        manager.tick(&requests).await.unwrap();

        // Tick must have issued a GetHeaders carrying the full locator, not just
        // the single storage-tip entry.
        let msg = rx.try_recv().expect("tick must send retry GetHeaders");
        match msg {
            NetworkRequest::SendMessage(NetworkMessage::GetHeaders(m)) => {
                assert_eq!(
                    m.locator_hashes, expected_locator,
                    "retry must reuse the full fork-finding locator"
                );
            }
            other => panic!("expected GetHeaders, got {:?}", other),
        }
    }
}
