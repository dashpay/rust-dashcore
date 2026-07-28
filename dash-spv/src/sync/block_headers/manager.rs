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
use dashcore::block::Header;
use dashcore::network::message_blockdata::Inventory;
use dashcore::BlockHash;
use dashcore::Network;
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
    /// Network, for the genesis header a backfill below every checkpoint anchors on.
    network: Network,
    /// Lowest stored height when a backfill started, so its completion can be
    /// told apart from the ordinary segments finishing.
    backfill_ceiling: Option<u32>,
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
            network,
            backfill_ceiling: None,
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

    /// Fill in the headers below the stored range so a wallet born down there
    /// can be scanned.
    ///
    /// A client anchored on a checkpoint holds no headers below it, so no rescan
    /// can reach that history. Download it from the highest anchor at or below
    /// `from_height` — a lower checkpoint, else genesis — up to the lowest
    /// header already stored.
    pub(super) async fn backfill_from(
        &mut self,
        from_height: u32,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        let current_start = self.header_storage.read().await.get_start_height().await.unwrap_or(0);
        if from_height >= current_start {
            return Ok(vec![]);
        }

        // Anchor on a checkpoint below the requested height when one exists, so
        // only the range that is actually missing gets downloaded.
        let (anchor_height, anchor_hash) = match self
            .pipeline
            .checkpoint_at_or_below(from_height)
            .filter(|cp| cp.height > 0)
        {
            Some(checkpoint) => {
                // Store the anchor: the backfill's first batch links onto it, and
                // nothing below the old floor is in storage yet.
                let checkpoint = checkpoint.clone();
                self.header_storage
                    .write()
                    .await
                    .store_headers_at_height(&[checkpoint.anchor_header()], checkpoint.height)
                    .await?;
                (checkpoint.height, checkpoint.block_hash)
            }
            None => {
                // TODO: If the checkpoint manager return genesis this is
                // not needed and maybe the network field can be removed
                //
                // Genesis is the universal anchor. Store it so the backfilled
                // range is dense from height 0 rather than from height 1.
                let genesis = dashcore::blockdata::constants::genesis_block(self.network).header;
                let genesis = HashedBlockHeader::from(genesis);
                let hash = *genesis.hash();
                self.header_storage.write().await.store_headers_at_height(&[genesis], 0).await?;
                (0, hash)
            }
        };

        // The range to fetch ends one block below the stored one, which must not
        // be rewritten. What that stored header points back to is the hash the
        // last segment validates its final block against.
        let join =
            self.header_storage.read().await.get_header(current_start).await?.ok_or_else(|| {
                SyncError::MissingDependency(format!("no stored header at {current_start}"))
            })?;
        let last_height = current_start - 1;
        let last_hash = join.header().prev_blockhash;

        if anchor_height >= last_height {
            // Nothing to fetch: storing the anchor already made the range
            // contiguous, so the floor is as low as this wallet needs.
            tracing::info!("Headers already reach {anchor_height}, no backfill needed");
            return Ok(vec![SyncEvent::HeaderFloorLowered {
                start_height: anchor_height,
                previous_start_height: current_start,
            }]);
        }

        tracing::info!(
            "Backfilling headers {}..{} (wallet needs {})",
            anchor_height,
            current_start,
            from_height
        );

        self.backfill_ceiling = Some(current_start);
        self.pipeline.prepend_backfill(anchor_height, anchor_hash, last_height, last_hash);
        self.progress.set_state(SyncState::Syncing);
        self.pipeline.send_pending(network).await?;

        Ok(vec![])
    }

    /// Validate and store a headers batch starting at `start_height`.
    ///
    /// The height is explicit because a batch does not always extend the tip:
    /// a backfill lands below it, on top of a parent further down.
    async fn store_headers_at(
        &mut self,
        start_height: u32,
        headers: &[HashedBlockHeader],
    ) -> SyncResult<BlockHeaderTip> {
        debug_assert!(!headers.is_empty());

        // Validate batch for internal continuity and PoW
        BlockHeaderValidator::new().validate(headers)?;

        // Store headers
        self.header_storage.write().await.store_headers_at_height(headers, start_height).await?;

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
            Some(first) => Some(first.prev_blockhash),
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
                headers[0].prev_blockhash
            );
        }

        // Send more requests during initial sync or active post-sync catch-up.
        // Skip for unsolicited headers.
        if was_syncing || !tip_was_complete {
            let sent = self.pipeline.send_pending(network).await?;
            if sent > 0 {
                tracing::debug!("Pipeline sent {} more requests", sent);
            }
        }

        // Process ready-to-store segments
        let mut events = Vec::new();
        let ready_batches = self.pipeline.take_ready_to_store();

        for (_, batch_headers) in ready_batches {
            if !batch_headers.is_empty() {
                let tip = self.tip().await?;
                let parent = batch_headers[0].header().prev_blockhash;

                // Clear any pending announcements for headers we're storing
                for header in &batch_headers {
                    self.pending_announcements.remove(header.hash());
                }

                // A batch either extends the tip or, coming from a backfill,
                // lands on a stored parent further down. Either way the parent's
                // height is where it goes: look it up rather than trust the
                // segment's own start height, which only describes its first
                // batch.
                let start_height = if parent == *tip.hash() {
                    tip.height() + 1
                } else {
                    let parent_height =
                        self.header_storage.read().await.get_header_height_by_hash(&parent).await?;
                    match parent_height {
                        Some(height) => height + 1,
                        None => {
                            return Err(SyncError::Validation(format!(
                                "Segment chain break: parent {} of the incoming batch is neither \
                                 the tip {} nor a stored header",
                                parent,
                                tip.hash()
                            )))
                        }
                    }
                };

                let new_tip = self.store_headers_at(start_height, &batch_headers).await?;
                // Update target if we've exceeded it (post-sync case)
                if new_tip.height() > self.progress.target_height() {
                    self.progress.update_target_height(new_tip.height());
                }
                events.push(SyncEvent::BlockHeadersStored {
                    tip_height: new_tip.height(),
                });
            }
        }

        // Announce the lowered floor once the backfilled range is contiguous:
        // the filter-header side builds its request queue from stored headers,
        // so it can only run when the whole range is in.
        if let Some(ceiling) = self.backfill_ceiling {
            if self.pipeline.is_complete_below(ceiling) {
                let previous_start_height = ceiling;
                self.backfill_ceiling = None;
                let start_height =
                    self.header_storage.read().await.get_start_height().await.unwrap_or(0);
                tracing::info!(
                    "Header backfill complete: floor lowered from {} to {}",
                    previous_start_height,
                    start_height
                );
                events.push(SyncEvent::HeaderFloorLowered {
                    start_height,
                    previous_start_height,
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
        BlockHeadersManager::new(
            storage.block_headers(),
            storage.metadata(),
            checkpoint_manager,
            Network::Regtest,
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
    async fn test_unsolicited_post_sync_header_does_not_trigger_get_headers() {
        let mut manager = create_test_manager().await;
        let tip = manager.tip().await.unwrap();
        let tip_hash = *tip.hash();

        // Simulate completed sync: pipeline initialized with tip segment marked complete
        manager.pipeline.init(0, tip_hash, 0);
        manager.pipeline.mark_tip_complete();
        manager.progress.set_state(SyncState::Synced);

        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();

        let header = Header::dummy_chain(1, tip_hash).remove(0);

        let events = manager.handle_headers_pipeline(&[header], &network).await.unwrap();

        // Header should have been stored
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            SyncEvent::BlockHeadersStored {
                tip_height: 1
            }
        ));

        // No GetHeaders request should have been sent
        assert!(mock.sent_messages().is_empty());
        assert!(mock.sent_to_messages().is_empty());

        // Tip segment marked complete again for the next unsolicited header
        assert!(manager.pipeline.is_tip_complete());
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
        manager.handle_headers_pipeline(&[header], &network).await.unwrap();

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
