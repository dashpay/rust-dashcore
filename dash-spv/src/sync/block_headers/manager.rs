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

use crate::chain::CheckpointManager;
use crate::error::{SyncError, SyncResult};
use crate::network::{NetworkManager, RequestKey};
use crate::storage::{BlockHeaderStorage, BlockHeaderTip, MetadataStorage};
use crate::sync::block_headers::HeadersPipeline;
use crate::sync::{
    BlockHeadersProgress, ProgressPercentage, SyncEvent, SyncManager, SyncState,
    BEST_CHAINLOCK_METADATA_STORAGE_KEY,
};
use crate::types::HashedBlockHeader;
use crate::validation::{BlockHeaderValidator, Validator};
#[cfg(test)]
use dashcore::block::Header;
use dashcore::blockdata::constants::genesis_block;
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::network::message_blockdata::Inventory;
use dashcore::pow::DGW_PAST_BLOCKS;
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
    /// Compiled-in checkpoints, which no fork may branch off below.
    checkpoint_manager: &'static CheckpointManager,
    /// Pending block announcements waiting for headers message (post-sync).
    pub(super) pending_announcements: HashMap<BlockHash, Instant>,
    /// Peers we've sent a GetHeaders to after sync, so Dash Core knows our tip
    /// and can send us header announcements instead of inv.
    pub(super) announced_peers: HashSet<SocketAddr>,
    /// Network whose difficulty rules new headers are checked against.
    network: Network,
    /// Lowest height a wallet needs, which [`Self::extend_down`] syncs down to.
    pub(super) floor: Option<u32>,
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
        checkpoint_manager: &'static CheckpointManager,
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
            checkpoint_manager,
            pending_announcements: HashMap::new(),
            announced_peers: HashSet::new(),
            network,
            floor: None,
        })
    }

    pub(super) async fn tip(&self) -> SyncResult<BlockHeaderTip> {
        self.header_storage
            .read()
            .await
            .get_tip()
            .await
            .ok_or_else(|| SyncError::MissingDependency("storage not initialized".to_string()))
    }

    /// Sync from the checkpoint below the lowest stored header, or genesis, up to
    /// it, once the pipeline runs, one checkpoint at a time down to [`Self::floor`].
    pub(super) async fn extend_down(&mut self) -> SyncResult<()> {
        if self.pipeline.is_syncing_below() || !self.pipeline.is_initialized() {
            return Ok(());
        }
        let Some(floor) = self.floor else {
            return Ok(());
        };
        let storage = self.header_storage.read().await;
        let Some(start) = storage.get_start_height().await.filter(|start| floor < *start) else {
            self.floor = None;
            return Ok(());
        };
        let join = storage
            .get_header(start)
            .await?
            .ok_or_else(|| SyncError::MissingDependency(format!("no header at {start}")))?
            .header()
            .prev_blockhash;
        drop(storage);

        let (anchor_start, anchor) = self.anchor_below(start);
        let anchor_height = anchor_start + anchor.len() as u32 - 1;
        if anchor_height + 1 == start {
            return self.store_below(start, &[]).await;
        }
        tracing::info!("Syncing headers {}..{} below the stored ones", anchor_height + 1, start);
        let anchor_hash = *anchor.last().expect("an anchor holds headers").hash();
        self.pipeline.sync_below(anchor_height, anchor_hash, start - 1, join);
        self.progress.set_state(SyncState::Syncing);
        Ok(())
    }

    /// The checkpoint below `start`, or genesis, as its first height and headers.
    fn anchor_below(&self, start: u32) -> (u32, Vec<HashedBlockHeader>) {
        match self.checkpoint_manager.last_checkpoint_before_height(start - 1) {
            Some(checkpoint) => (checkpoint.start_height(), checkpoint.headers().to_vec()),
            None => (0, vec![genesis_block(self.network).header.into()]),
        }
    }

    /// Store the anchor below `start` and the `downloaded` headers joining it to `start`.
    async fn store_below(
        &mut self,
        start: u32,
        downloaded: &[HashedBlockHeader],
    ) -> SyncResult<()> {
        let (anchor_start, mut headers) = self.anchor_below(start);
        let anchor_height = anchor_start + headers.len() as u32 - 1;
        if !downloaded.is_empty() {
            let ancestors = headers.iter().map(|header| *header.header()).collect();
            BlockHeaderValidator::new(self.network, ancestors, anchor_height)
                .validate(downloaded)?;
        }
        headers.extend_from_slice(downloaded);
        let mut storage = self.header_storage.write().await;
        let joins = storage.get_header(start).await?.map(|header| header.header().prev_blockhash)
            == headers.last().map(|last| *last.hash());
        if !joins {
            return Err(SyncError::Validation(format!("headers below {start} do not join it")));
        }
        storage.store_headers_at_height(&headers, anchor_start).await?;
        tracing::info!("Headers synced down to {}", anchor_start);
        Ok(())
    }

    /// Validate and store headers batch.
    async fn store_headers(&mut self, headers: &[HashedBlockHeader]) -> SyncResult<BlockHeaderTip> {
        debug_assert!(!headers.is_empty());

        // Validate batch for internal continuity, PoW and difficulty
        let tip = self.tip().await?;
        let storage = self.header_storage.read().await;

        // A storage started at a checkpoint holds less history than a full window.
        let first = tip
            .height()
            .saturating_sub(DGW_PAST_BLOCKS as u32 - 1)
            .max(storage.get_start_height().await.unwrap_or(0));

        let ancestors = storage.load_headers(first..tip.height() + 1).await?;

        drop(storage);

        let ancestors = ancestors.iter().map(|header| *header.header()).collect();

        BlockHeaderValidator::new(self.network, ancestors, tip.height()).validate(headers)?;

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
        peer: SocketAddr,
        headers: &[HashedBlockHeader],
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        if !self.pipeline.is_initialized() {
            // Pipeline not initialized (shouldn't happen in normal flow)
            tracing::warn!("Received headers but pipeline not initialized");
            return Ok(vec![]);
        }

        let was_syncing = self.state() == SyncState::Syncing;
        let tip_was_complete = self.pipeline.is_tip_complete();

        // Capture the answered locator before routing advances `current_tip_hash`. An
        // empty response has nothing to key on, so it answers the tip segment's locator.
        let answered_locator = match headers.first() {
            Some(first) => Some(first.header().prev_blockhash),
            None => self.pipeline.active_tip_locator(),
        };

        // Route headers to the pipeline, validates checkpoint match.
        let matched = match self.pipeline.receive_headers(headers) {
            Ok(matched) => matched,
            Err(e) => {
                network.ban_peer(peer).await;
                return Err(e);
            }
        };

        if matched.is_some() {
            if let Some(locator) = answered_locator {
                network.request_answered(RequestKey::Headers(locator)).await;
            }
        } else if !headers.is_empty() {
            if let Some(fork_height) = self.fork_height(headers).await? {
                return Ok(vec![SyncEvent::ForkDetected {
                    fork_height,
                }]);
            }
            tracing::debug!(
                "Headers not matched by pipeline (prev_hash: {}), may be post-sync update",
                headers[0].header().prev_blockhash
            );
        }

        // Process ready-to-store segments
        let mut events = Vec::new();
        let ready_batches = self.pipeline.take_ready_to_store();

        // Draining can expose new segments at the end of the active window, so
        // refill only after next_to_store has advanced. Skip unsolicited headers.
        if was_syncing || !tip_was_complete {
            let sent = self.pipeline.send_pending(network).await?;
            if sent > 0 {
                tracing::debug!("Pipeline sent {} more requests", sent);
            }
        }

        events.extend(self.store_ready_batches(ready_batches).await?);

        // After storing unsolicited post-sync headers, mark the tip complete so the next header goes through
        // the clean reset path. Don't mark complete during active catch-up.
        if !was_syncing && tip_was_complete && !events.is_empty() {
            self.pipeline.mark_tip_complete();
        }

        if was_syncing {
            events.extend(self.finalize_sync_if_complete(network).await?);
        }

        if matched.is_some() {
            self.progress.bump_last_activity();
        }
        Ok(events)
    }

    /// Height where `headers` branch off the stored chain below its tip, if they
    /// do. A branch off below the best ChainLock, or below the newest checkpoint
    /// the stored chain reaches, is not followed: the blocks they fix are final.
    async fn fork_height(&self, headers: &[HashedBlockHeader]) -> SyncResult<Option<u32>> {
        let storage = self.header_storage.read().await;

        // Skip the headers we already store: a peer may resend part of our chain.
        for header in headers {
            if storage.get_header_height_by_hash(header.hash()).await?.is_some() {
                continue;
            }

            let parent = storage.get_header_height_by_hash(&header.header().prev_blockhash).await?;
            let tip = storage.get_tip_height().await;
            let Some(fork_height) = parent.filter(|&parent| tip.is_some_and(|tip| parent < tip))
            else {
                return Ok(None);
            };

            if let Some(checkpoint) = tip
                .and_then(|tip| self.checkpoint_manager.last_checkpoint_before_height(tip))
                .filter(|checkpoint| fork_height < checkpoint.height())
            {
                tracing::warn!(
                    "Ignoring a fork at height {}, below the checkpoint at {}",
                    fork_height,
                    checkpoint.height()
                );
                return Ok(None);
            }

            let chain_lock = self
                .metadata_storage
                .read()
                .await
                .load_metadata::<ChainLock>(BEST_CHAINLOCK_METADATA_STORAGE_KEY)
                .await?;
            if let Some(chain_lock) = chain_lock.filter(|cl| fork_height < cl.block_height) {
                tracing::warn!(
                    "Ignoring a fork at height {}, below the ChainLock at {}",
                    fork_height,
                    chain_lock.block_height
                );
                return Ok(None);
            }

            return Ok(Some(fork_height));
        }

        Ok(None)
    }

    /// Write segments that finished downloading into storage.
    ///
    /// Split out of [`Self::handle_headers_pipeline`] so `tick` can promote
    /// headers too. Promotion used to be reachable only from there — i.e. only
    /// when a `Headers` message arrived — which leaves a sync no way to finish
    /// itself: once the last segment completes, no further `Headers` will ever
    /// come, and the already-downloaded, already-validated tail simply stays in
    /// memory. A testnet restore was found frozen exactly there, with 1,046,289
    /// headers buffered and the stored tip stuck at 1,474,000 while peers
    /// stayed connected and chain locks kept arriving.
    ///
    /// Takes the batches rather than draining them itself, so callers keep
    /// `take_ready_to_store` → `send_pending` → store ordering: draining can
    /// expose a new segment at the end of the active window, and the refill
    /// should pick it up in the same pass.
    pub(super) async fn store_ready_batches(
        &mut self,
        ready_batches: Vec<(u32, Vec<HashedBlockHeader>)>,
    ) -> SyncResult<Vec<SyncEvent>> {
        let mut events = Vec::new();

        if let Some(below) = self.pipeline.take_below() {
            let start = self.header_storage.read().await.get_start_height().await;
            let start = start.ok_or_else(|| {
                SyncError::MissingDependency("no headers stored to sync below".to_string())
            })?;
            self.store_below(start, &below).await?;
        }

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

        Ok(events)
    }

    /// Close out an initial sync whose pipeline has nothing left to download.
    ///
    /// Extracted alongside [`Self::store_ready_batches`] and for the same
    /// reason: a promotion driven by `tick` has to be able to reach the
    /// completion it just made possible, or the manager stores the last
    /// segment and then sits in `Syncing` forever.
    pub(super) async fn finalize_sync_if_complete(
        &mut self,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        if !self.pipeline.is_complete() {
            return Ok(Vec::new());
        }

        // If blocks were announced during sync, request them before finalizing the sync
        if !self.pending_announcements.is_empty() {
            tracing::info!(
                "Pipeline complete but {} blocks announced during sync, requesting headers",
                self.pending_announcements.len()
            );
            self.pipeline.reset_tip_segment();
            self.pipeline.send_pending(network).await?;
            return Ok(Vec::new());
        }

        // Synced to the tip and no pending announcements, finalize and emit event
        let tip = self.tip().await?;
        self.progress.update_target_height(tip.height());
        self.progress.set_state(SyncState::Synced);
        tracing::info!("Headers sync complete at height {}", tip.height());
        Ok(vec![SyncEvent::BlockHeaderSyncComplete {
            tip_height: tip.height(),
        }])
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
        _network: &Arc<dyn NetworkManager>,
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
    use crate::network::{MessageType, NetworkEvent};
    use crate::storage::{
        DiskStorageManager, PersistentBlockHeaderStorage, PersistentMetadataStorage, StorageManager,
    };
    use crate::sync::block_headers::pipeline::ACTIVE_SEGMENT_WINDOW;
    use crate::sync::block_headers::segment_state::SegmentState;
    use crate::sync::{ManagerIdentifier, SyncManager, SyncManagerProgress};
    use crate::test_utils::{test_socket_address, MockNetworkManager};
    use dashcore::network::message::NetworkMessage;
    use test_case::test_case;

    type TestBlockHeadersManager =
        BlockHeadersManager<PersistentBlockHeaderStorage, PersistentMetadataStorage>;

    fn create_test_checkpoint_manager() -> &'static CheckpointManager {
        CheckpointManager::for_network(dashcore::Network::Testnet)
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
            Network::Regtest,
        )
        .await
        .expect("Failed to create BlockHeadersManager")
    }

    #[test_case(None, 5, Some(5); "no ChainLock")]
    #[test_case(Some(6), 5, None; "below the ChainLock")]
    #[test_case(Some(5), 5, Some(5); "at the ChainLock")]
    #[test_case(Some(3), 5, Some(5); "above the ChainLock")]
    #[tokio::test]
    async fn a_branch_off_below_the_best_chain_lock_is_no_fork(
        chain_locked: Option<u32>,
        branch_off: u32,
        expected: Option<u32>,
    ) {
        let mut storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let stored = Header::dummy_batch(0..10);
        storage
            .store_headers(&stored.iter().map(HashedBlockHeader::from).collect::<Vec<_>>())
            .await
            .unwrap();
        if let Some(height) = chain_locked {
            let bytes = serde_json::to_vec(&ChainLock::dummy(height)).unwrap();
            storage.store_metadata(BEST_CHAINLOCK_METADATA_STORAGE_KEY, &bytes).await.unwrap();
        }
        let manager = BlockHeadersManager::new(
            storage.block_headers(),
            storage.metadata(),
            create_test_checkpoint_manager(),
            Network::Regtest,
        )
        .await
        .unwrap();

        let branch = Header {
            prev_blockhash: stored[branch_off as usize].block_hash(),
            ..Header::dummy(1_000)
        };

        assert_eq!(
            manager.fork_height(&[HashedBlockHeader::from(&branch)]).await.unwrap(),
            expected
        );
    }

    /// Blocks below the newest checkpoint the stored chain reaches are final, as
    /// below the best ChainLock. A checkpoint above the tip fixes nothing yet,
    /// or no fork could ever be followed before the chain reached it.
    #[test_case(49_999, None; "below the checkpoint")]
    #[test_case(50_000, Some(50_000); "at the checkpoint")]
    #[test_case(50_001, Some(50_001); "above the checkpoint")]
    #[tokio::test]
    async fn a_branch_off_below_the_newest_reached_checkpoint_is_no_fork(
        branch_off: u32,
        expected: Option<u32>,
    ) {
        let mut storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let start = 49_990;
        let stored: Vec<_> =
            Header::dummy_batch(start..50_010).iter().map(HashedBlockHeader::from).collect();
        storage.store_headers_at_height(&stored, start).await.unwrap();
        let manager = BlockHeadersManager::new(
            storage.block_headers(),
            storage.metadata(),
            create_test_checkpoint_manager(),
            Network::Regtest,
        )
        .await
        .unwrap();

        let branch = Header {
            prev_blockhash: *stored[(branch_off - start) as usize].hash(),
            ..Header::dummy(1_000_000)
        };

        assert_eq!(
            manager.fork_height(&[HashedBlockHeader::from(&branch)]).await.unwrap(),
            expected
        );
    }

    /// Create a manager in synced state with an initialized pipeline.
    async fn create_synced_manager() -> TestBlockHeadersManager {
        let mut manager = create_test_manager().await;
        let tip = manager.tip().await.unwrap();
        manager.pipeline.init(tip.height(), *tip.hash(), tip.height());
        manager.progress.set_state(SyncState::Synced);
        manager
    }

    /// Headers that finished downloading must reach storage even if no further
    /// `Headers` message ever arrives.
    ///
    /// Promotion used to hang off `handle_headers_pipeline` alone, so the last
    /// segment of a sync had nothing left to trigger it — the pipeline sat on
    /// fully downloaded, fully validated headers forever. Seen in the field on
    /// a testnet restore: 1,046,289 headers buffered, stored tip frozen at
    /// 1,474,000, peers healthy, chain locks still arriving.
    ///
    /// Asserts the completion too, not just the store: a regression that keeps
    /// the last segment but leaves the manager in `Syncing` is the same stall
    /// wearing a different hat.
    #[tokio::test]
    async fn test_tick_promotes_buffered_headers_with_no_further_messages() {
        let mut manager = create_test_manager().await;
        let tip = manager.tip().await.unwrap();
        let start_height = tip.height();

        manager.pipeline.init(start_height, *tip.hash(), start_height + 2);
        manager.progress.set_state(SyncState::Syncing);

        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();

        // Issue the request the segment expects, so the headers below are a
        // legitimate answer to it rather than unsolicited.
        manager.pipeline.send_pending(&network).await.unwrap();

        // The headers land in the pipeline without the manager's own
        // message-driven promotion running — the state the field stall was in.
        let headers: Vec<HashedBlockHeader> =
            Header::dummy_chain(2, *tip.hash()).iter().map(HashedBlockHeader::from).collect();
        manager.pipeline.receive_headers(&headers).unwrap();
        assert!(
            manager.pipeline.total_buffered() > 0,
            "precondition: headers are downloaded but not yet promoted"
        );
        assert_eq!(
            manager.tip().await.unwrap().height(),
            start_height,
            "precondition: storage has not advanced"
        );

        // No further `Headers` will arrive. The periodic tick is the only
        // thing left that can finish the job.
        let events = manager.tick(&network).await.unwrap();

        assert!(
            manager.tip().await.unwrap().height() > start_height,
            "tick must promote buffered headers into storage"
        );
        assert!(
            events.iter().any(|e| matches!(e, SyncEvent::BlockHeadersStored { .. })),
            "the promotion must be reported, not done silently"
        );

        // Completing the pipeline must also be reachable from a tick: an empty
        // response closes the tip segment, and the next tick has to announce
        // the sync rather than leaving the manager in `Syncing` forever.
        manager.pipeline.send_pending(&network).await.unwrap();
        manager.pipeline.receive_headers(&[]).unwrap();
        assert!(manager.pipeline.is_complete(), "precondition: nothing left to download");

        let events = manager.tick(&network).await.unwrap();

        assert_eq!(
            manager.state(),
            SyncState::Synced,
            "a tick over a complete pipeline must finish the sync"
        );
        assert!(
            events.iter().any(|e| matches!(e, SyncEvent::BlockHeaderSyncComplete { .. })),
            "completion must be announced, or downstream managers never start"
        );
    }

    #[tokio::test]
    async fn test_block_headers_manager_new() {
        let manager = create_test_manager().await;
        assert_eq!(manager.identifier(), ManagerIdentifier::BlockHeader);
        assert_eq!(manager.state(), SyncState::WaitingForConnections);
        assert_eq!(manager.wanted_message_types(), [MessageType::Headers, MessageType::Inv]);
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

    #[tokio::test]
    async fn test_unsolicited_post_sync_header_batch_does_not_trigger_get_headers() {
        let mut manager = create_test_manager().await;
        let tip = manager.tip().await.unwrap();
        let tip_hash = *tip.hash();

        // Simulate completed sync: pipeline initialized with tip segment marked complete
        manager.pipeline.init(0, tip_hash, 0);
        manager.pipeline.mark_tip_complete();
        manager.progress.set_state(SyncState::Synced);

        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();

        let headers = Header::dummy_chain(2, tip_hash)
            .into_iter()
            .map(HashedBlockHeader::from)
            .collect::<Vec<_>>();

        let events = manager
            .handle_headers_pipeline(test_socket_address(1), &headers, &network)
            .await
            .unwrap();

        // Header should have been stored
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            SyncEvent::BlockHeadersStored {
                tip_height: 2
            }
        ));

        // No GetHeaders request should have been sent
        assert!(mock.sent_messages().await.is_empty());
        assert!(mock.sent_to_messages().await.is_empty());

        // Tip segment marked complete again for the next unsolicited header
        assert!(manager.pipeline.is_tip_complete());
    }

    #[tokio::test]
    async fn test_response_cycle_refills_window_after_ordered_drain() {
        let mut manager = create_test_manager().await;
        let stored_tip = manager.tip().await.unwrap();
        let chain = Header::dummy_chain(ACTIVE_SEGMENT_WINDOW, *stored_tip.hash());

        let mut segments = Vec::new();
        for (id, header) in chain.iter().enumerate() {
            let start_hash = if id == 0 {
                *stored_tip.hash()
            } else {
                chain[id - 1].block_hash()
            };
            let target_hash = header.block_hash();
            let mut segment = SegmentState::new(
                id,
                id as u32,
                start_hash,
                Some(id as u32 + 1),
                Some(target_hash),
            );
            if id > 0 {
                segment.current_tip_hash = target_hash;
                segment.current_height = id as u32 + 1;
                segment.complete = true;
                segment.buffered_headers.push((*header).into());
            }
            segments.push(segment);
        }
        let next_locator = chain.last().expect("non-empty chain").block_hash();
        segments.push(SegmentState::new(
            ACTIVE_SEGMENT_WINDOW,
            ACTIVE_SEGMENT_WINDOW as u32,
            next_locator,
            None,
            None,
        ));
        manager.pipeline.set_segments_for_test(segments);
        manager.progress.set_state(SyncState::Syncing);

        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();

        let events = manager
            .handle_headers_pipeline(test_socket_address(1), &[chain[0].into()], &network)
            .await
            .unwrap();

        assert_eq!(events.len(), ACTIVE_SEGMENT_WINDOW);
        let sent = mock.sent_messages().await;
        assert_eq!(sent.len(), 1, "response cycle did not refill active window");
        match &sent[0] {
            NetworkMessage::GetHeaders(request) => {
                assert_eq!(request.locator_hashes[0], next_locator);
            }
            other => panic!("Expected GetHeaders, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_peer_tip_announcement_lifecycle() {
        let mut manager = create_synced_manager().await;
        manager.pipeline.mark_tip_complete();
        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();

        let addr = test_socket_address(1);
        let connect = NetworkEvent::PeerConnected(addr);

        // Connect sends a peer-targeted GetHeaders
        let events = manager.handle_network_event(&connect, &network).await.unwrap();
        assert!(events.is_empty());
        assert!(manager.announced_peers.contains(&addr));
        let sent_to = mock.sent_to_messages().await;
        assert_eq!(sent_to.len(), 1);
        assert_eq!(sent_to[0].0, addr);
        assert!(matches!(sent_to[0].1, NetworkMessage::GetHeaders(_)));

        // Same peer again sends nothing (already announced)
        manager.handle_network_event(&connect, &network).await.unwrap();
        assert_eq!(mock.sent_to_messages().await.len(), 1);

        // Disconnect removes from announced set
        let disconnect = NetworkEvent::PeerDisconnected(addr);
        manager.handle_network_event(&disconnect, &network).await.unwrap();
        assert!(!manager.announced_peers.contains(&addr));

        // Reconnect sends GetHeaders again
        manager.handle_network_event(&connect, &network).await.unwrap();
        assert!(manager.announced_peers.contains(&addr));
        assert_eq!(mock.sent_to_messages().await.len(), 2);
    }

    #[tokio::test]
    async fn test_peer_tip_announcement_guards() {
        // Not synced: peer connect does nothing
        let mut manager = create_test_manager().await;
        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();
        let addr = test_socket_address(1);
        let connect = NetworkEvent::PeerConnected(addr);

        manager.handle_network_event(&connect, &network).await.unwrap();
        assert!(!manager.announced_peers.contains(&addr));
        assert!(mock.sent_to_messages().await.is_empty());

        // Active catch-up: peer connect skipped while pipeline has pending request
        let mut manager = create_synced_manager().await;
        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();
        manager.pipeline.reset_tip_segment();
        manager.pipeline.send_pending(&network).await.unwrap();
        assert!(!mock.sent_messages().await.is_empty());

        manager.handle_network_event(&connect, &network).await.unwrap();
        assert!(!manager.announced_peers.contains(&addr));
        assert!(mock.sent_to_messages().await.is_empty());
    }

    #[tokio::test]
    async fn test_disconnect_preserves_pipeline_and_resumes_from_advanced_tip() {
        let mut manager = create_test_manager().await;
        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();

        // Use a target below the first testnet checkpoint (50000) so the
        // pipeline produces a single open-ended tip segment.
        let initial_event = NetworkEvent::PeersUpdated {
            connected_count: 1,
            best_height: 40_000,
        };
        manager.handle_network_event(&initial_event, &network).await.unwrap();
        assert_eq!(manager.state(), SyncState::Syncing);
        assert!(manager.pipeline.is_initialized());
        assert_eq!(manager.pipeline.segment_count(), 1);

        let sent = mock.sent_messages().await;
        assert_eq!(sent.len(), 1, "initial GetHeaders not sent");
        let initial_locator = match &sent[0] {
            NetworkMessage::GetHeaders(msg) => msg.locator_hashes[0],
            other => panic!("Expected GetHeaders, got {:?}", other),
        };
        mock.clear_sent().await;

        // Simulate a peer response. The single tip segment drains its buffer
        // through take_ready_to_store, advancing the storage tip and the
        // segment's current_tip_hash to advanced_hash.
        let header = Header::dummy_chain(1, initial_locator).remove(0);
        let advanced_hash = header.block_hash();
        manager
            .handle_headers_pipeline(test_socket_address(1), &[header.into()], &network)
            .await
            .unwrap();

        // Drain the follow-up GetHeaders that send_pending issued.
        let sent = mock.sent_messages().await;
        assert_eq!(sent.len(), 1, "follow-up GetHeaders not sent");
        match &sent[0] {
            NetworkMessage::GetHeaders(msg) => {
                assert_eq!(msg.locator_hashes[0], advanced_hash);
            }
            other => panic!("Expected GetHeaders, got {:?}", other),
        }
        mock.clear_sent().await;

        let disconnect_event = NetworkEvent::PeersUpdated {
            connected_count: 0,
            best_height: 40_000,
        };
        manager.handle_network_event(&disconnect_event, &network).await.unwrap();
        // The broker re-queues in-flight requests on disconnect, so the resumed request can go out.
        mock.release_requests_in_play().await;
        assert_eq!(manager.state(), SyncState::WaitingForConnections);
        assert!(
            manager.pipeline.is_initialized(),
            "pipeline must survive disconnect so resume can reuse validated state"
        );
        assert_eq!(manager.pipeline.segment_count(), 1);

        // Reconnect: start_sync must skip pipeline.init and resume by sending
        // GetHeaders from each segment's preserved current_tip_hash.
        manager.handle_network_event(&initial_event, &network).await.unwrap();
        assert_eq!(manager.state(), SyncState::Syncing);

        let sent = mock.sent_messages().await;
        assert_eq!(sent.len(), 1, "resumed GetHeaders not sent");
        let resumed_locator = match &sent[0] {
            NetworkMessage::GetHeaders(msg) => msg.locator_hashes[0],
            other => panic!("Expected GetHeaders, got {:?}", other),
        };
        assert_eq!(
            resumed_locator, advanced_hash,
            "GetHeaders on reconnect must use the preserved current_tip_hash"
        );
        assert_ne!(resumed_locator, initial_locator);
    }

    #[tokio::test]
    async fn test_disconnect_after_sync_resumes_and_catches_up() {
        let mut manager = create_synced_manager().await;
        let tip = manager.tip().await.unwrap();
        let synced_hash = *tip.hash();
        manager.pipeline.mark_tip_complete();
        assert!(manager.pipeline.is_tip_complete());

        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();

        let disconnect_event = NetworkEvent::PeersUpdated {
            connected_count: 0,
            best_height: tip.height(),
        };
        manager.handle_network_event(&disconnect_event, &network).await.unwrap();
        // The broker re-queues in-flight requests on disconnect, so the resumed request can go out.
        mock.release_requests_in_play().await;
        assert_eq!(manager.state(), SyncState::WaitingForConnections);
        assert!(manager.pipeline.is_initialized());

        // Reconnect with a higher peer best_height (a new block was mined).
        let reconnect_event = NetworkEvent::PeersUpdated {
            connected_count: 1,
            best_height: tip.height() + 1,
        };
        manager.handle_network_event(&reconnect_event, &network).await.unwrap();
        assert_eq!(manager.state(), SyncState::Syncing);

        let sent = mock.sent_messages().await;
        assert_eq!(sent.len(), 1, "resumed GetHeaders not sent");
        let resumed_locator = match &sent[0] {
            NetworkMessage::GetHeaders(msg) => msg.locator_hashes[0],
            other => panic!("Expected GetHeaders, got {:?}", other),
        };
        assert_eq!(resumed_locator, synced_hash);
    }

    #[tokio::test]
    async fn test_empty_headers_after_tip_announcement_is_harmless() {
        let mut manager = create_synced_manager().await;
        manager.pipeline.mark_tip_complete();
        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();

        // Announce tip to a new peer
        let addr = test_socket_address(1);
        let connect = NetworkEvent::PeerConnected(addr);
        manager.handle_network_event(&connect, &network).await.unwrap();
        assert_eq!(mock.sent_to_messages().await.len(), 1); // the GetHeaders announcement
        mock.clear_sent().await;

        // Peer responds with empty headers (same height as us)
        let events =
            manager.handle_headers_pipeline(test_socket_address(1), &[], &network).await.unwrap();

        // No events emitted, no requests sent, tip segment stays complete
        assert!(events.is_empty());
        assert!(mock.sent_messages().await.is_empty());
        assert!(mock.sent_to_messages().await.is_empty());
        assert!(manager.pipeline.is_tip_complete());
    }
}
