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
use crate::network::RequestSender;
use crate::storage::{BlockHeaderStorage, BlockHeaderTip, MetadataStorage};
use crate::sync::block_headers::HeadersPipeline;
use crate::sync::{BlockHeadersProgress, ProgressPercentage, SyncEvent, SyncManager, SyncState};
use crate::types::HashedBlockHeader;
use crate::validation::{BlockHeaderValidator, Validator};
#[cfg(test)]
use dashcore::block::Header;
use dashcore::network::message_blockdata::Inventory;
use dashcore::BlockHash;
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
        headers: &[HashedBlockHeader],
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        if !self.pipeline.is_initialized() {
            // Pipeline not initialized (shouldn't happen in normal flow)
            tracing::warn!("Received headers but pipeline not initialized");
            return Ok(vec![]);
        }

        let was_syncing = self.state() == SyncState::Syncing;
        let tip_was_complete = self.pipeline.is_tip_complete();

        // Route headers to the pipeline, validates checkpoint match.
        let matched = self.pipeline.receive_headers(headers)?;

        if matched.is_none() && !headers.is_empty() {
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
            let sent = self.pipeline.send_pending(requests)?;
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
            events.extend(self.finalize_sync_if_complete(requests).await?);
        }

        if matched.is_some() {
            self.progress.bump_last_activity();
        }
        Ok(events)
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
        requests: &RequestSender,
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
            self.pipeline.send_pending(requests)?;
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

    /// Fire one fallback `GetHeaders` for block announcements that have gone
    /// unanswered past the wait timeout, then drop them.
    ///
    /// Announced-but-unobtainable hashes (a peer that vanished, an orphan that
    /// never reconnected) otherwise pin the manager: `finalize_sync_if_complete`
    /// refuses to finish while any announcement is outstanding, so it resets the
    /// tip segment and re-requests every pass. That recovery loop only aged the
    /// stale entries out on the `Synced` branch of `tick`, which a `Syncing`
    /// manager never reaches — so during initial sync the loop ran forever,
    /// `BlockHeaderSyncComplete` never fired, and every downstream manager
    /// stalled behind it. Sweeping here, from every state, bounds the loop. (#960)
    pub(super) fn prune_stale_announcements(&mut self, requests: &RequestSender) -> SyncResult<()> {
        let now = Instant::now();
        let stale: Vec<BlockHash> = self
            .pending_announcements
            .iter()
            .filter(|(_, announced_at)| {
                now.duration_since(**announced_at)
                    > super::sync_manager::UNSOLICITED_HEADERS_WAIT_TIMEOUT
            })
            .map(|(hash, _)| *hash)
            .collect();

        if stale.is_empty() {
            return Ok(());
        }

        tracing::info!("Sending fallback GetHeaders for {} stale announcements", stale.len());
        self.pipeline.reset_tip_segment();
        self.pipeline.send_pending(requests)?;

        for hash in stale {
            self.pending_announcements.remove(&hash);
        }
        Ok(())
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
    use crate::sync::block_headers::pipeline::ACTIVE_SEGMENT_WINDOW;
    use crate::sync::block_headers::segment_state::SegmentState;
    use crate::sync::{ManagerIdentifier, SyncManager, SyncManagerProgress};
    use dashcore::network::message::NetworkMessage;
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
        BlockHeadersManager::new(storage.block_headers(), storage.metadata(), checkpoint_manager)
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

        let (sender, _rx) = create_test_request_sender();
        // Issue the request the segment expects, so the headers below are a
        // legitimate answer to it rather than unsolicited.
        manager.pipeline.send_pending(&sender).unwrap();

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
        let events = manager.tick(&sender).await.unwrap();

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
        manager.pipeline.send_pending(&sender).unwrap();
        manager.pipeline.receive_headers(&[]).unwrap();
        assert!(manager.pipeline.is_complete(), "precondition: nothing left to download");

        let events = manager.tick(&sender).await.unwrap();

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

    /// A block announced during initial sync that no peer will ever answer must
    /// not pin the manager in `Syncing`. `finalize_sync_if_complete` refuses to
    /// finish while any announcement is outstanding and re-requests it every
    /// pass; the aging-out sweep that breaks that loop used to run only on the
    /// `Synced` branch of `tick`, which a `Syncing` manager never reaches, so
    /// the loop ran forever and `BlockHeaderSyncComplete` never fired. (#960)
    #[tokio::test]
    async fn test_syncing_prunes_unobtainable_announcement_and_finalizes() {
        let mut manager = create_test_manager().await;
        let tip = manager.tip().await.unwrap();
        manager.pipeline.init(tip.height(), *tip.hash(), tip.height());
        manager.progress.set_state(SyncState::Syncing);

        let (requests, mut rx) = create_test_request_sender();

        // Drive the single tip segment complete: nothing left to download.
        manager.pipeline.send_pending(&requests).unwrap();
        while rx.try_recv().is_ok() {}
        manager.pipeline.receive_headers(&[]).unwrap();
        assert!(manager.pipeline.is_complete());

        // A phantom announcement, already aged past the wait timeout.
        let phantom = BlockHash::dummy(123);
        manager.pending_announcements.insert(
            phantom,
            std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(30))
                .expect("monotonic clock has been running longer than 30s"),
        );

        // First tick: the sweep fires its fallback (which re-opens the tip
        // segment) and drops the phantom so it can never block completion again.
        let events = manager.tick(&requests).await.unwrap();
        assert!(
            !manager.pending_announcements.contains_key(&phantom),
            "the stale announcement must be pruned"
        );
        assert!(!events.iter().any(|e| matches!(e, SyncEvent::BlockHeaderSyncComplete { .. })));
        assert_eq!(manager.state(), SyncState::Syncing);

        // The fallback GetHeaders is answered by the peer's tip: an empty
        // response re-completes the tip segment.
        while rx.try_recv().is_ok() {}
        manager.pipeline.receive_headers(&[]).unwrap();
        assert!(manager.pipeline.is_complete());

        // Second tick: nothing stale remains, so finalize runs and the sync ends.
        let events = manager.tick(&requests).await.unwrap();
        assert_eq!(
            manager.state(),
            SyncState::Synced,
            "with the announcement pruned, the tick must finish the sync"
        );
        assert!(
            events.iter().any(|e| matches!(e, SyncEvent::BlockHeaderSyncComplete { .. })),
            "completion must be announced so downstream managers start"
        );
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
    async fn test_unsolicited_post_sync_header_batch_does_not_trigger_get_headers() {
        let mut manager = create_test_manager().await;
        let tip = manager.tip().await.unwrap();
        let tip_hash = *tip.hash();

        // Simulate completed sync: pipeline initialized with tip segment marked complete
        manager.pipeline.init(0, tip_hash, 0);
        manager.pipeline.mark_tip_complete();
        manager.progress.set_state(SyncState::Synced);

        let (sender, mut rx) = create_test_request_sender();

        let headers = Header::dummy_chain(2, tip_hash)
            .into_iter()
            .map(HashedBlockHeader::from)
            .collect::<Vec<_>>();

        let events = manager.handle_headers_pipeline(&headers, &sender).await.unwrap();

        // Header should have been stored
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            SyncEvent::BlockHeadersStored {
                tip_height: 2
            }
        ));

        // No GetHeaders request should have been sent
        assert!(rx.try_recv().is_err());

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
            if id == 0 {
                segment.coordinator.mark_sent(&[start_hash]);
            } else {
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

        let (requests, mut rx) = create_test_request_sender();
        let events = manager.handle_headers_pipeline(&[chain[0].into()], &requests).await.unwrap();

        assert_eq!(events.len(), ACTIVE_SEGMENT_WINDOW);
        match rx.try_recv().expect("response cycle did not refill active window") {
            NetworkRequest::SendMessage(NetworkMessage::GetHeaders(request)) => {
                assert_eq!(request.locator_hashes[0], next_locator);
            }
            other => panic!("Expected GetHeaders, got {other:?}"),
        }
        assert!(rx.try_recv().is_err());
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
        manager.pipeline.send_pending(&requests).unwrap();
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
        manager.handle_headers_pipeline(&[header.into()], &requests).await.unwrap();

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
        let events = manager.handle_headers_pipeline(&[], &requests).await.unwrap();

        // No events emitted, no requests sent, tip segment stays complete
        assert!(events.is_empty());
        assert!(rx.try_recv().is_err());
        assert!(manager.pipeline.is_tip_complete());
    }
}
