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

    /// Rebuild the download pipeline from what is durably stored.
    ///
    /// Storage is the only thing that survives a rejected batch, so re-seeding
    /// from its tip discards whatever the pipeline had buffered and re-requests
    /// the range. The peer that served the bad batch is not excluded — nothing
    /// can exclude it yet — but the request is re-declared to the broker, which
    /// paces it across the peer set, so a retry is not guaranteed to land on the
    /// same one.
    async fn restart_pipeline_from_storage(
        &mut self,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<()> {
        let tip = self.tip().await?;
        let target = self.progress.target_height().max(tip.height());
        self.pipeline.init(tip.height(), *tip.hash(), target);
        self.pipeline.send_pending(network).await?;
        Ok(())
    }

    /// Handle incoming headers message (used for both initial sync and post-sync).
    pub(super) async fn handle_headers_pipeline(
        &mut self,
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

        // Capture the `getheaders` locator this response answers before routing —
        // routing advances the matched segment's `current_tip_hash`. A non-empty
        // response is keyed by its first header's `prev_blockhash` (the locator we
        // sent from); an empty response carries nothing to key on, so it answers
        // the active tip segment's locator.
        let answered_locator = match headers.first() {
            Some(first) => Some(first.header().prev_blockhash),
            None => self.pipeline.active_tip_locator(),
        };

        // Route headers to the pipeline, validates checkpoint match.
        let matched = self.pipeline.receive_headers(headers)?;

        // Correlated to a segment: tell the network manager the request is
        // answered so it stops timing it out and frees the key for re-request.
        if matched.is_some() {
            if let Some(locator) = answered_locator {
                network.request_answered(RequestKey::Headers(locator)).await;
            }
        } else if !headers.is_empty() {
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

        for (_start_height, batch_headers) in ready_batches {
            if batch_headers.is_empty() {
                continue;
            }

            // `take_ready_to_store` has already emptied this batch out of the
            // pipeline and advanced the segment past it, so a failure here cannot
            // just propagate: the headers exist nowhere, storage never moved, and
            // every later batch would trip the continuity check against a tip that
            // can never advance — one bad batch from any peer wedging header sync
            // for the rest of the session. Rebuild from storage instead.
            let tip = self.tip().await?;
            let result = if batch_headers[0].header().prev_blockhash != *tip.hash() {
                Err(SyncError::Validation(format!(
                    "Segment chain break: expected prev {}, got {}",
                    tip.hash(),
                    batch_headers[0].header().prev_blockhash
                )))
            } else {
                // Validates internal continuity and PoW before anything is written.
                self.store_headers(&batch_headers).await
            };

            let new_tip = match result {
                Ok(new_tip) => new_tip,
                Err(e) => {
                    tracing::warn!(
                        "Rejected a batch of {} headers ({}); re-syncing the pipeline from the stored tip {}",
                        batch_headers.len(),
                        e,
                        tip.height(),
                    );
                    self.restart_pipeline_from_storage(network).await?;
                    return Err(e);
                }
            };

            // Only now that the headers are durable: an announcement dropped for a
            // batch that was then rejected would never be requested again.
            for header in &batch_headers {
                self.pending_announcements.remove(header.hash());
            }

            // Update target if we've exceeded it (post-sync case)
            if new_tip.height() > self.progress.target_height() {
                self.progress.update_target_height(new_tip.height());
            }
            events.push(SyncEvent::BlockHeadersStored {
                tip_height: new_tip.height(),
            });
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
                self.pipeline.send_pending(network).await?;
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
    use crate::chain::checkpoints::testnet_checkpoints;
    use crate::network::{MessageType, NetworkEvent};
    use crate::storage::{
        DiskStorageManager, PersistentBlockHeaderStorage, PersistentMetadataStorage, StorageManager,
    };
    use crate::sync::block_headers::pipeline::ACTIVE_SEGMENT_WINDOW;
    use crate::sync::block_headers::segment_state::SegmentState;
    use crate::sync::{ManagerIdentifier, SyncManager, SyncManagerProgress};
    use crate::test_utils::{test_socket_address, MockNetworkManager};
    use dashcore::network::message::NetworkMessage;

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

    /// A batch that links to the stored tip but fails validation must not wedge
    /// header sync.
    ///
    /// `take_ready_to_store` empties the batch out of the pipeline and advances
    /// the segment before anything is validated, so a rejected batch used to
    /// leave the headers nowhere and storage unmoved — and every later batch then
    /// failed the continuity check against a tip that could never advance. Any
    /// peer could trigger it once, permanently.
    #[tokio::test]
    async fn a_rejected_batch_does_not_wedge_header_sync() {
        let mut manager = create_test_manager().await;
        let tip = manager.tip().await.unwrap();
        let tip_hash = *tip.hash();
        manager.pipeline.init(0, tip_hash, 0);
        manager.pipeline.mark_tip_complete();
        manager.progress.set_state(SyncState::Synced);

        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();

        // Links to the tip, so the pipeline takes it — but the second header does
        // not follow the first, which the validator rejects once the batch is
        // already out of the pipeline.
        let good = Header::dummy_chain(1, tip_hash).remove(0);
        let mut broken = Header::dummy(9);
        broken.prev_blockhash = BlockHash::dummy(200);

        let rejected =
            manager.handle_headers_pipeline(&[good.into(), broken.into()], &network).await;
        assert!(rejected.is_err(), "a batch failing validation must be reported");
        assert_eq!(
            manager.tip().await.unwrap().height(),
            tip.height(),
            "nothing from a rejected batch may reach storage"
        );

        // The wedge: sync must still be able to move afterwards. Before the fix
        // this failed forever with a chain break, because the segment had been
        // advanced past headers that were never stored.
        let good_again = Header::dummy_chain(1, tip_hash).remove(0);
        let events = manager
            .handle_headers_pipeline(&[good_again.into()], &network)
            .await
            .expect("header sync must recover from a rejected batch");
        assert!(
            matches!(
                events.as_slice(),
                [SyncEvent::BlockHeadersStored {
                    tip_height: 1
                }]
            ),
            "the re-sent header must store, got {:?}",
            events
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

        let events = manager.handle_headers_pipeline(&headers, &network).await.unwrap();

        // Header should have been stored
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            SyncEvent::BlockHeadersStored {
                tip_height: 2
            }
        ));

        // No GetHeaders request should have been sent
        assert!(mock.sent_messages().is_empty());
        assert!(mock.sent_to_messages().is_empty());

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

        let events = manager.handle_headers_pipeline(&[chain[0].into()], &network).await.unwrap();

        assert_eq!(events.len(), ACTIVE_SEGMENT_WINDOW);
        let sent = mock.sent_messages();
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
        // An idle synced tip has no in-flight catch-up request.
        manager.pipeline.mark_tip_complete();
        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();

        let addr = test_socket_address(1);
        let connect = NetworkEvent::PeerConnected(addr);

        // Connect sends a peer-targeted GetHeaders
        let events = manager.handle_network_event(&connect, &network).await.unwrap();
        assert!(events.is_empty());
        assert!(manager.announced_peers.contains(&addr));
        let sent_to = mock.sent_to_messages();
        assert_eq!(sent_to.len(), 1);
        assert_eq!(sent_to[0].0, addr);
        assert!(matches!(sent_to[0].1, NetworkMessage::GetHeaders(_)));

        // Same peer again sends nothing (already announced)
        manager.handle_network_event(&connect, &network).await.unwrap();
        assert_eq!(mock.sent_to_messages().len(), 1);

        // Disconnect removes from announced set
        let disconnect = NetworkEvent::PeerDisconnected(addr);
        manager.handle_network_event(&disconnect, &network).await.unwrap();
        assert!(!manager.announced_peers.contains(&addr));

        // Reconnect sends GetHeaders again
        manager.handle_network_event(&connect, &network).await.unwrap();
        assert!(manager.announced_peers.contains(&addr));
        assert_eq!(mock.sent_to_messages().len(), 2);
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
        assert!(mock.sent_to_messages().is_empty());

        // Active catch-up: peer connect skipped while pipeline has pending request
        let mut manager = create_synced_manager().await;
        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();
        manager.pipeline.reset_tip_segment();
        manager.pipeline.send_pending(&network).await.unwrap();
        // The pipeline GetHeaders is declared via `send`, not `send_to`.
        assert!(!mock.sent_messages().is_empty());

        manager.handle_network_event(&connect, &network).await.unwrap();
        assert!(!manager.announced_peers.contains(&addr));
        // No peer-targeted announcement while a catch-up request is in flight.
        assert!(mock.sent_to_messages().is_empty());
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

        let sent = mock.sent_messages();
        assert_eq!(sent.len(), 1, "initial GetHeaders not sent");
        let initial_locator = match &sent[0] {
            NetworkMessage::GetHeaders(msg) => msg.locator_hashes[0],
            other => panic!("Expected GetHeaders, got {:?}", other),
        };
        mock.clear_sent();

        // Simulate a peer response. The single tip segment drains its buffer
        // through take_ready_to_store, advancing the storage tip and the
        // segment's current_tip_hash to advanced_hash.
        let header = Header::dummy_chain(1, initial_locator).remove(0);
        let advanced_hash = header.block_hash();
        manager.handle_headers_pipeline(&[header.into()], &network).await.unwrap();

        // Drain the follow-up GetHeaders that send_pending issued.
        let sent = mock.sent_messages();
        assert_eq!(sent.len(), 1, "follow-up GetHeaders not sent");
        match &sent[0] {
            NetworkMessage::GetHeaders(msg) => {
                assert_eq!(msg.locator_hashes[0], advanced_hash);
            }
            other => panic!("Expected GetHeaders, got {:?}", other),
        }
        mock.clear_sent();

        let disconnect_event = NetworkEvent::PeersUpdated {
            connected_count: 0,
            best_height: 40_000,
        };
        manager.handle_network_event(&disconnect_event, &network).await.unwrap();
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

        let sent = mock.sent_messages();
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
        assert_eq!(manager.state(), SyncState::WaitingForConnections);
        assert!(manager.pipeline.is_initialized());

        // Reconnect with a higher peer best_height (a new block was mined).
        let reconnect_event = NetworkEvent::PeersUpdated {
            connected_count: 1,
            best_height: tip.height() + 1,
        };
        manager.handle_network_event(&reconnect_event, &network).await.unwrap();
        assert_eq!(manager.state(), SyncState::Syncing);

        let sent = mock.sent_messages();
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
        assert_eq!(mock.sent_to_messages().len(), 1); // the GetHeaders announcement
        mock.clear_sent();

        // Peer responds with empty headers (same height as us)
        let events = manager.handle_headers_pipeline(&[], &network).await.unwrap();

        // No events emitted, no requests sent, tip segment stays complete
        assert!(events.is_empty());
        assert!(mock.sent_messages().is_empty());
        assert!(mock.sent_to_messages().is_empty());
        assert!(manager.pipeline.is_tip_complete());
    }
}
