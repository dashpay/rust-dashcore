//! Filter headers manager for parallel sync.
//!
//! Downloads compact block filter headers (BIP 157/158). Reacts to BlockHeadersStored
//! events to know when new headers are available. Emits FilterHeadersStored events.

use std::sync::Arc;

use dashcore::network::message_filter::{CFHeaders, GetCFHeaders};
use dashcore::BlockHash;
use tokio::sync::RwLock;

use super::pipeline::{FilterHeadersPipeline, FILTER_HEADERS_BATCH_SIZE};
use crate::error::{SyncError, SyncResult};
use crate::network::{NetworkManager, SendRequest};
use crate::storage::{BlockHeaderStorage, FilterHeaderStorage};
use crate::sync::filter_headers::util::compute_filter_headers;
use crate::sync::progress::ProgressPercentage;
use crate::sync::{FilterHeadersProgress, SyncEvent, SyncManager, SyncState};

/// Filter headers manager for downloading compact block filter headers.
///
/// This manager:
/// - Subscribes to BlockHeadersStored events to know when to start/resume
/// - Downloads filter headers using pipelined requests
/// - Emits FilterHeadersStored events for FiltersManager
///
/// Generic over:
/// - `H: BlockHeaderStorage` for reading block headers
/// - `FH: FilterHeaderStorage` for storing filter headers
pub struct FilterHeadersManager<H: BlockHeaderStorage, FH: FilterHeaderStorage> {
    /// Current progress of the manager.
    pub(super) progress: FilterHeadersProgress,
    /// Block header storage (for reading headers).
    header_storage: Arc<RwLock<H>>,
    /// Filter header storage (for storing filter headers).
    pub(super) filter_header_storage: Arc<RwLock<FH>>,
    /// Pipeline for downloading filter headers.
    pub(super) pipeline: FilterHeadersPipeline,
    /// Checkpoint start height - set when syncing from checkpoint to store prev header once.
    pub(super) checkpoint_start_height: Option<u32>,
    /// Whether block header sync has completed. Gates FilterHeadersSyncComplete emission
    /// to ensure it never fires before BlockHeaderSyncComplete.
    pub(super) block_headers_synced: bool,
    /// Start and stop hash of the batch requested below the stored filter headers.
    pub(super) lower_batch: Option<(u32, BlockHash)>,
}

impl<H: BlockHeaderStorage, FH: FilterHeaderStorage> FilterHeadersManager<H, FH> {
    /// The tip height block-header storage holds right now.
    ///
    /// Distinct from `progress.block_header_tip_height()`, which is only ever
    /// as fresh as the last `BlockHeadersStored` / `BlockHeaderSyncComplete`
    /// this manager was handed. Storage can move without either arriving —
    /// an out-of-order segment completing promotes a run of buffered headers —
    /// so the tick reads storage directly to notice.
    pub(super) async fn stored_block_header_tip(&self) -> Option<u32> {
        self.header_storage.read().await.get_tip_height().await
    }

    /// Transition to `Synced` and return `FilterHeadersSyncComplete` if block headers
    /// are done and filter headers have reached the target. Returns `None` if already
    /// `Synced` or conditions are not met.
    pub(super) fn try_complete_sync(&mut self) -> Option<SyncEvent> {
        if self.block_headers_synced
            && self.progress.current_height() >= self.progress.target_height()
        {
            if self.state() == SyncState::Synced {
                return None;
            }
            self.set_state(SyncState::Synced);
            tracing::info!(
                "Filter header sync complete at height {}",
                self.progress.current_height()
            );
            return Some(SyncEvent::FilterHeadersSyncComplete {
                tip_height: self.progress.current_height(),
            });
        }
        None
    }

    /// Create a new filter headers manager with the given storage references.
    pub async fn new(
        header_storage: Arc<RwLock<H>>,
        filter_header_storage: Arc<RwLock<FH>>,
    ) -> SyncResult<Self> {
        // Load current filter tip
        let filter_tip =
            filter_header_storage.read().await.get_filter_tip_height().await?.unwrap_or(0);

        // Load block header tip for progress display
        let header_tip =
            header_storage.read().await.get_tip().await.map(|t| t.height()).unwrap_or(0);

        let mut initial_progress = FilterHeadersProgress::default();
        initial_progress.update_current_height(filter_tip);
        initial_progress.update_target_height(header_tip);
        initial_progress.update_block_header_tip_height(header_tip);

        Ok(Self {
            progress: initial_progress,
            header_storage,
            filter_header_storage,
            pipeline: FilterHeadersPipeline::default(),
            checkpoint_start_height: None,
            block_headers_synced: false,
            lower_batch: None,
        })
    }

    /// Process a CFHeaders response - store headers and update state.
    ///
    /// Returns `SyncError::Validation` without storing anything if the batch does
    /// not cover exactly `start_height..=height(stop_hash)` or does not connect to
    /// the filter header stored at `start_height - 1`.
    pub(super) async fn process_cfheaders(
        &mut self,
        cfheaders: &CFHeaders,
        start_height: u32,
    ) -> SyncResult<u32> {
        let stop_height = self
            .header_storage
            .read()
            .await
            .get_header_height_by_hash(&cfheaders.stop_hash)
            .await?
            .ok_or_else(|| {
                SyncError::Validation(format!(
                    "CFHeaders stop hash {} is not in header storage",
                    cfheaders.stop_hash
                ))
            })?;
        let expected = stop_height.checked_sub(start_height).map(|n| n as usize + 1);
        if expected != Some(cfheaders.filter_hashes.len()) {
            return Err(SyncError::Validation(format!(
                "CFHeaders batch {}..={} has {} filter hashes",
                start_height,
                stop_height,
                cfheaders.filter_hashes.len()
            )));
        }

        let is_first_checkpoint_batch =
            start_height > 0 && self.checkpoint_start_height == Some(start_height);

        let mut storage = self.filter_header_storage.write().await;

        // Every batch except the very first one must chain from the stored header.
        if start_height > 0 && !is_first_checkpoint_batch {
            let stored_prev = storage.get_filter_header(start_height - 1).await?;
            if stored_prev != Some(cfheaders.previous_filter_header) {
                return Err(SyncError::Validation(format!(
                    "CFHeaders batch at {} has previous filter header {}, stored header at {} is {:?}",
                    start_height,
                    cfheaders.previous_filter_header,
                    start_height - 1,
                    stored_prev
                )));
            }
        }

        let filter_headers = compute_filter_headers(cfheaders);
        let count = filter_headers.len() as u32;

        // For checkpoint sync, store previous_filter_header at start_height - 1
        // so filter verification can chain correctly. Only on first batch.
        if is_first_checkpoint_batch {
            storage
                .store_filter_headers_at_height(
                    &[cfheaders.previous_filter_header],
                    start_height - 1,
                )
                .await?;
            tracing::debug!(
                "Stored checkpoint previous filter header at height {}",
                start_height - 1
            );
            // Clear so we don't check again
            self.checkpoint_start_height = None;
        }

        storage.store_filter_headers_at_height(&filter_headers, start_height).await?;

        drop(storage);

        self.progress.add_processed(count);

        Ok(count)
    }

    /// Request the batch ending at the lowest stored filter header while block
    /// headers reach below it. Each batch is checked against the stored header
    /// it ends at, so the range fills downwards without gaps.
    pub(super) async fn extend_down(
        &mut self,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<()> {
        let header_storage = self.header_storage.read().await;
        let header_start = header_storage.get_start_height().await;
        let filter_start = self.filter_header_storage.read().await.get_filter_start_height().await;
        // A chain anchored at a checkpoint holds the filter header below it too.
        let (Some(header_start), Some(end)) = (header_start, filter_start) else {
            return Ok(());
        };
        if end <= header_start.saturating_sub(1) {
            return Ok(());
        }
        let start = header_start.max(end.saturating_sub(FILTER_HEADERS_BATCH_SIZE - 1));
        let stop_hash = *header_storage
            .get_header(end)
            .await?
            .ok_or_else(|| SyncError::Storage(format!("Missing header at height {end}")))?
            .hash();
        drop(header_storage);

        self.lower_batch = Some((start, stop_hash));
        network
            .send(GetCFHeaders {
                filter_type: 0,
                start_height: start,
                stop_hash,
            })
            .await;
        Ok(())
    }

    /// Store a batch [`Self::extend_down`] requested, if it ends at the stored
    /// filter header it was requested for.
    pub(super) async fn store_lower_batch(
        &mut self,
        start: u32,
        cfheaders: &CFHeaders,
    ) -> SyncResult<Vec<SyncEvent>> {
        self.lower_batch = None;
        let mut headers = compute_filter_headers(cfheaders);
        let end = (start + headers.len() as u32).saturating_sub(1);
        let mut storage = self.filter_header_storage.write().await;
        if headers.is_empty()
            || storage.get_filter_start_height().await != Some(end)
            || headers.pop() != storage.get_filter_header(end).await?
        {
            tracing::warn!(
                "CFHeaders batch at {} does not end at the stored filter headers",
                start
            );
            return Ok(vec![]);
        }
        if start > 0 {
            headers.insert(0, cfheaders.previous_filter_header);
        }
        let first = start.saturating_sub(1);
        storage.store_filter_headers_at_height(&headers, first).await?;
        Ok(vec![SyncEvent::FilterHeadersStored {
            start_height: first,
            end_height: end - 1,
            tip_height: self.progress.current_height(),
        }])
    }

    /// Start or resume filter header download.
    async fn start_download(
        &mut self,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        // Get current filter tip
        let filter_headers_tip =
            self.filter_header_storage.read().await.get_filter_tip_height().await?.unwrap_or(0);

        // Get header start height (for checkpoint sync)
        let header_start_height =
            self.header_storage.read().await.get_start_height().await.unwrap_or(0);

        // Calculate start height
        let start_height = match filter_headers_tip {
            0 => header_start_height,
            n => (n + 1).max(header_start_height),
        };

        self.progress.update_current_height(filter_headers_tip);

        // Check if already at target (nothing to download)
        if start_height > self.progress.block_header_tip_height() {
            if let Some(event) = self.try_complete_sync() {
                return Ok(vec![event]);
            }
            return Ok(vec![]);
        }

        tracing::info!(
            "Starting filter header sync from {} to {}",
            start_height,
            self.progress.block_header_tip_height()
        );

        // Track checkpoint start height for storing prev header on first batch.
        // Only needed on fresh checkpoint sync (no existing filter headers).
        // On resume, start_height-1 is already stored so re-inserting would panic in debug builds.
        if start_height > 0 && filter_headers_tip == 0 {
            self.checkpoint_start_height = Some(start_height);
        }

        // Initialize pipeline with storage references
        let header_storage = self.header_storage.read().await;
        self.pipeline
            .init(&*header_storage, start_height, self.progress.block_header_tip_height())
            .await?;
        drop(header_storage);

        self.pipeline.send_pending(network).await?;

        self.set_state(SyncState::Syncing);

        Ok(vec![])
    }

    /// Handle notification that new headers are available.
    ///
    /// Unified handler for both BlockHeaderSyncComplete and BlockHeadersStored events.
    /// Uses pipeline state to determine whether to init or extend.
    pub(super) async fn handle_new_headers(
        &mut self,
        tip_height: u32,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        self.progress.update_block_header_tip_height(tip_height);
        self.update_target_height(tip_height);

        // Nothing to do if caught up to available headers
        if self.progress.current_height() >= self.progress.block_header_tip_height() {
            let mut events = Vec::new();
            if let Some(event) = self.try_complete_sync() {
                events.push(event);
            }
            return Ok(events);
        }

        match self.state() {
            SyncState::Synced | SyncState::Syncing => {
                // Configure pipeline based on its current state
                let header_storage = self.header_storage.read().await;
                if self.pipeline.is_complete() {
                    // Pipeline done/empty, need fresh init
                    self.pipeline
                        .init(
                            &*header_storage,
                            self.progress.current_height() + 1,
                            self.progress.block_header_tip_height(),
                        )
                        .await?;
                } else {
                    // Pipeline active, extend it
                    self.pipeline
                        .extend_target(&*header_storage, self.progress.block_header_tip_height())
                        .await?;
                }
                drop(header_storage);
                self.pipeline.send_pending(network).await?;
                Ok(vec![])
            }
            SyncState::WaitingForConnections | SyncState::WaitForEvents => {
                // Need full startup (calculates start from storage, handles checkpoints)
                self.start_download(network).await
            }
            _ => Ok(vec![]),
        }
    }
}

impl<H: BlockHeaderStorage, FH: FilterHeaderStorage> std::fmt::Debug
    for FilterHeadersManager<H, FH>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilterHeadersManager").field("progress", &self.progress).finish()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::MessageType;
    use crate::storage::{
        DiskStorageManager, PersistentBlockHeaderStorage, PersistentFilterHeaderStorage,
        StorageManager,
    };
    use crate::sync::{ManagerIdentifier, SyncManagerProgress};
    use crate::test_utils::MockNetworkManager;
    use crate::types::HashedBlockHeader;
    use dashcore::hash_types::{FilterHash, FilterHeader};
    use dashcore::network::message::NetworkMessage;
    use dashcore::{block::Version, BlockHash, CompactTarget, Header as BlockHeader};
    use dashcore_hashes::Hash;

    type TestFilterHeadersManager =
        FilterHeadersManager<PersistentBlockHeaderStorage, PersistentFilterHeaderStorage>;
    type TestSyncManager = dyn SyncManager;

    async fn create_test_manager() -> TestFilterHeadersManager {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        FilterHeadersManager::new(storage.block_headers(), storage.filter_headers())
            .await
            .expect("Failed to create FilterHeadersManager")
    }

    #[tokio::test]
    async fn test_filter_headers_manager_new() {
        let manager = create_test_manager().await;
        assert_eq!(manager.identifier(), ManagerIdentifier::FilterHeader);
        assert_eq!(manager.state(), SyncState::WaitForEvents);
        assert_eq!(manager.wanted_message_types(), [MessageType::CfHeaders]);
        assert!(!manager.block_headers_synced);
    }

    #[tokio::test]
    async fn test_filter_headers_manager_progress() {
        let mut manager = create_test_manager().await;
        manager.progress.update_current_height(500);
        manager.progress.update_target_height(2000);
        manager.progress.update_block_header_tip_height(1000);
        manager.progress.add_processed(500);

        let manager_ref: &TestSyncManager = &manager;
        let progress = manager_ref.progress();
        if let SyncManagerProgress::FilterHeaders(progress) = progress {
            assert_eq!(progress.state(), SyncState::WaitForEvents);
            assert_eq!(progress.current_height(), 500);
            assert_eq!(progress.target_height(), 2000);
            assert_eq!(progress.block_header_tip_height(), 1000);
            assert_eq!(progress.processed(), 500);
            assert!(progress.last_activity().elapsed().as_secs() < 1);
        } else {
            panic!("Expected SyncManagerProgress::FilterHeaders");
        }
    }

    #[tokio::test]
    async fn test_try_complete_sync() {
        let mut manager = create_test_manager().await;
        manager.progress.update_current_height(1000);
        manager.progress.update_target_height(1000);
        manager.progress.update_block_header_tip_height(1000);
        manager.set_state(SyncState::Syncing);

        // Gated: returns None when block_headers_synced is false
        assert!(manager.try_complete_sync().is_none());
        assert_eq!(manager.state(), SyncState::Syncing);

        // Emits once block_headers_synced is set
        manager.block_headers_synced = true;
        assert!(matches!(
            manager.try_complete_sync(),
            Some(SyncEvent::FilterHeadersSyncComplete { .. })
        ));
        assert_eq!(manager.state(), SyncState::Synced);

        // Idempotent: returns None when already Synced
        assert!(manager.try_complete_sync().is_none());
        assert_eq!(manager.state(), SyncState::Synced);
    }

    #[tokio::test]
    async fn test_block_headers_synced_event_gating() {
        use crate::network::NetworkManager;
        use crate::test_utils::MockNetworkManager;

        let mut manager = create_test_manager().await;
        let network: Arc<dyn NetworkManager> = Arc::new(MockNetworkManager::new());

        // Filter headers caught up to block header tip and target
        manager.progress.update_current_height(1000);
        manager.progress.update_target_height(1000);
        manager.progress.update_block_header_tip_height(1000);
        manager.set_state(SyncState::WaitForEvents);

        // BlockHeadersStored does NOT set block_headers_synced, no completion emitted
        let event = SyncEvent::BlockHeadersStored {
            tip_height: 1000,
        };
        let events = manager.handle_sync_event(&event, &network).await.unwrap();
        assert!(!manager.block_headers_synced);
        assert!(!events.iter().any(|e| matches!(e, SyncEvent::FilterHeadersSyncComplete { .. })));

        // BlockHeaderSyncComplete sets the flag and emits completion
        let event = SyncEvent::BlockHeaderSyncComplete {
            tip_height: 1000,
        };
        let events = manager.handle_sync_event(&event, &network).await.unwrap();
        assert!(manager.block_headers_synced);
        assert!(events.iter().any(|e| matches!(e, SyncEvent::FilterHeadersSyncComplete { .. })));
        assert_eq!(manager.state(), SyncState::Synced);
    }

    #[tokio::test]
    async fn test_block_header_sync_complete_during_active_download() {
        use crate::network::NetworkManager;
        use crate::test_utils::MockNetworkManager;

        let mut manager = create_test_manager().await;
        let network: Arc<dyn NetworkManager> = Arc::new(MockNetworkManager::new());

        // Filter headers caught up to block tip, but target is higher (more headers coming)
        manager.progress.update_current_height(1000);
        manager.progress.update_target_height(2000);
        manager.progress.update_block_header_tip_height(1000);
        manager.set_state(SyncState::WaitForEvents);

        // BlockHeaderSyncComplete arrives but target not reached yet
        let event = SyncEvent::BlockHeaderSyncComplete {
            tip_height: 1000,
        };
        let events = manager.handle_sync_event(&event, &network).await.unwrap();

        assert!(manager.block_headers_synced);
        assert!(!events.iter().any(|e| matches!(e, SyncEvent::FilterHeadersSyncComplete { .. })));
    }

    /// The tick must notice block-header storage advancing on its own.
    ///
    /// `handle_new_headers` — the only path that extends the CFHeaders queue —
    /// runs off `BlockHeadersStored` / `BlockHeaderSyncComplete`. Storage can
    /// move without either arriving, because a segment completing out of order
    /// promotes a run of buffered headers. When that happened on a mainnet
    /// restore the queue stayed at its old target and filter headers stopped
    /// permanently, while block headers and ChainLocks carried on.
    #[tokio::test]
    async fn test_tick_extends_when_storage_tip_advanced_without_an_event() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let header_storage = storage.block_headers();
        let mut manager =
            FilterHeadersManager::new(header_storage.clone(), storage.filter_headers())
                .await
                .expect("Failed to create FilterHeadersManager");
        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();

        // Mid-sync: this manager was last told the tip was 1000.
        manager.progress.update_current_height(1000);
        manager.progress.update_target_height(1000);
        manager.progress.update_block_header_tip_height(1000);
        manager.set_state(SyncState::Syncing);

        // Storage moves past that on its own — no event is delivered.
        let mut headers = Vec::new();
        let mut prev = BlockHash::from_byte_array([0u8; 32]);
        for nonce in 0..1200u32 {
            let header = HashedBlockHeader::from(BlockHeader {
                version: Version::from_consensus(1),
                prev_blockhash: prev,
                merkle_root: dashcore::TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0x2100ffff),
                nonce,
            });
            prev = *header.hash();
            headers.push(header);
        }
        header_storage.write().await.store_headers_at_height(&headers, 0).await.unwrap();
        let stored_tip = manager.stored_block_header_tip().await.expect("storage has a tip");
        assert!(stored_tip > 1000, "test setup: storage tip must exceed the known tip");

        let manager_ref: &mut TestSyncManager = &mut manager;
        manager_ref.tick(&network).await.unwrap();

        assert_eq!(
            manager.progress.block_header_tip_height(),
            stored_tip,
            "tick must pick up a tip that advanced without an event"
        );

        // The tip alone is not the fix. `handle_new_headers` updates that
        // field before it touches the pipeline, so a version that noticed the
        // advance and then failed to queue anything would still satisfy the
        // assertion above — and would leave sync exactly as stuck as before.
        // What has to be true is that a request for the new range went out.
        let requested_stops: Vec<_> = mock
            .sent_messages()
            .await
            .into_iter()
            .filter_map(|msg| match msg {
                NetworkMessage::GetCFHeaders(get) => Some(get.stop_hash),
                _ => None,
            })
            .collect();
        assert!(
            !requested_stops.is_empty(),
            "tick must queue and send CFHeaders requests for the newly available range"
        );
        // Every stop hash must be a header the new range actually contains, so
        // a request built from the stale target cannot pass this.
        let storage = header_storage.read().await;
        for stop in &requested_stops {
            let mut found = false;
            for height in 1001..=stored_tip {
                if let Ok(Some(header)) = storage.get_header(height).await {
                    if header.hash() == stop {
                        found = true;
                        break;
                    }
                }
            }
            assert!(found, "CFHeaders stop hash {stop} is not in the newly discovered range");
        }
    }

    #[tokio::test]
    async fn test_on_disconnect() {
        let mut manager = create_test_manager().await;

        // Set all fields that on_disconnect resets
        manager.block_headers_synced = true;
        manager.checkpoint_start_height = Some(500);

        manager.on_disconnect();

        assert!(!manager.block_headers_synced);
        assert!(manager.checkpoint_start_height.is_none());
        assert!(manager.pipeline.is_complete());
    }

    /// Store a chain of `count` block headers starting at `start` and return their hashes.
    async fn store_block_headers(
        storage: &DiskStorageManager,
        start: u32,
        count: u32,
    ) -> Vec<BlockHash> {
        let mut headers = Vec::new();
        let mut prev = BlockHash::from_byte_array([0u8; 32]);
        for nonce in 0..count {
            let header = HashedBlockHeader::from(BlockHeader {
                version: Version::from_consensus(1),
                prev_blockhash: prev,
                merkle_root: dashcore::TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0x2100ffff),
                nonce,
            });
            prev = *header.hash();
            headers.push(header);
        }
        storage
            .block_headers()
            .write()
            .await
            .store_headers_at_height(&headers, start)
            .await
            .unwrap();
        headers.iter().map(|h| *h.hash()).collect()
    }

    /// A CFHeaders response with `count` filter hashes chained from `previous_filter_header`.
    fn cfheaders(
        previous_filter_header: FilterHeader,
        stop_hash: BlockHash,
        count: u32,
    ) -> CFHeaders {
        CFHeaders {
            filter_type: 0,
            stop_hash,
            previous_filter_header,
            filter_hashes: (0..count).map(|i| FilterHash::hash(&i.to_le_bytes())).collect(),
        }
    }

    /// Deliver a CFHeaders response. Returns the batches it stored and the
    /// `(start_height, stop_hash)` of every GetCFHeaders it sent.
    async fn deliver(
        manager: &mut TestFilterHeadersManager,
        mock: &Arc<MockNetworkManager>,
        msg: CFHeaders,
    ) -> (Vec<(u32, u32)>, Vec<(u32, BlockHash)>) {
        mock.clear_sent().await;
        let network: Arc<dyn NetworkManager> = mock.clone();
        let peer = "127.0.0.1:19999".parse().unwrap();
        let manager: &mut TestSyncManager = manager;
        let events = manager
            .handle_message(peer, NetworkMessage::CFHeaders(msg).into(), &network)
            .await
            .unwrap();
        let requests = mock
            .sent_messages()
            .await
            .into_iter()
            .filter_map(|msg| match msg {
                NetworkMessage::GetCFHeaders(get) => Some((get.start_height, get.stop_hash)),
                _ => None,
            })
            .collect();
        (stored_ranges(&events), requests)
    }

    fn stored_ranges(events: &[SyncEvent]) -> Vec<(u32, u32)> {
        events
            .iter()
            .filter_map(|e| match e {
                SyncEvent::FilterHeadersStored {
                    start_height,
                    end_height,
                    ..
                } => Some((*start_height, *end_height)),
                _ => None,
            })
            .collect()
    }

    /// Start a fresh sync to the stored block header tip and drain the initial requests.
    async fn start_sync(
        storage: &DiskStorageManager,
        tip: u32,
    ) -> (TestFilterHeadersManager, Arc<MockNetworkManager>) {
        let mut manager =
            FilterHeadersManager::new(storage.block_headers(), storage.filter_headers())
                .await
                .unwrap();
        let mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = mock.clone();
        manager.handle_new_headers(tip, &network).await.unwrap();
        assert_eq!(manager.state(), SyncState::Syncing);
        (manager, mock)
    }

    async fn filter_tip(storage: &DiskStorageManager) -> Option<u32> {
        storage.filter_headers().read().await.get_filter_tip_height().await.unwrap()
    }

    #[tokio::test]
    async fn test_cfheaders_batch_not_connecting_to_stored_header_is_requeued() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let hashes = store_block_headers(&storage, 0, 4000).await;
        let (mut manager, network) = start_sync(&storage, 3999).await;

        let first = cfheaders(FilterHeader::all_zeros(), hashes[1999], 2000);
        assert_eq!(deliver(&mut manager, &network, first.clone()).await.0, vec![(0, 1999)]);
        let stored_prev = *compute_filter_headers(&first).last().unwrap();

        // A second batch with a different previous filter header is not stored
        // and is requested again.
        let wrong = cfheaders(FilterHeader::hash(b"other"), hashes[3999], 2000);
        let (stored, requests) = deliver(&mut manager, &network, wrong).await;
        assert!(stored.is_empty());
        assert_eq!(requests, vec![(2000, hashes[3999])]);
        assert_eq!(filter_tip(&storage).await, Some(1999));
        assert_eq!(manager.pipeline.next_expected(), 2000);

        // A connecting response is stored.
        let right = cfheaders(stored_prev, hashes[3999], 2000);
        assert_eq!(deliver(&mut manager, &network, right).await.0, vec![(2000, 3999)]);
        assert_eq!(filter_tip(&storage).await, Some(3999));
    }

    #[tokio::test]
    async fn test_buffered_cfheaders_batch_not_connecting_is_requeued_when_ready() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let hashes = store_block_headers(&storage, 0, 4000).await;
        let (mut manager, network) = start_sync(&storage, 3999).await;

        // The second batch arrives first and is buffered.
        let wrong = cfheaders(FilterHeader::hash(b"other"), hashes[3999], 2000);
        assert_eq!(deliver(&mut manager, &network, wrong).await, (vec![], vec![]));

        // The first batch is stored; the buffered one is rejected and requested again.
        let first = cfheaders(FilterHeader::all_zeros(), hashes[1999], 2000);
        let (stored, requests) = deliver(&mut manager, &network, first).await;
        assert_eq!(stored, vec![(0, 1999)]);
        assert_eq!(requests, vec![(2000, hashes[3999])]);
        assert_eq!(filter_tip(&storage).await, Some(1999));
        assert_eq!(manager.pipeline.next_expected(), 2000);
    }

    #[tokio::test]
    async fn test_cfheaders_batch_shorter_than_its_range_is_rejected() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let hashes = store_block_headers(&storage, 0, 2000).await;
        let (mut manager, network) = start_sync(&storage, 1999).await;

        let short = cfheaders(FilterHeader::all_zeros(), hashes[1999], 1999);
        let (stored, requests) = deliver(&mut manager, &network, short).await;
        assert!(stored.is_empty());
        assert_eq!(requests, vec![(0, hashes[1999])]);
        assert_eq!(filter_tip(&storage).await, None);
        assert_eq!(manager.pipeline.next_expected(), 0);

        let full = cfheaders(FilterHeader::all_zeros(), hashes[1999], 2000);
        assert_eq!(deliver(&mut manager, &network, full).await.0, vec![(0, 1999)]);
    }

    #[tokio::test]
    async fn test_first_checkpoint_cfheaders_batch_is_accepted() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let hashes = store_block_headers(&storage, 5000, 100).await;
        let (mut manager, network) = start_sync(&storage, 5099).await;
        assert_eq!(manager.checkpoint_start_height, Some(5000));

        // Nothing is stored below the checkpoint, so its previous header is taken as is.
        let checkpoint_prev = FilterHeader::hash(b"checkpoint");
        let first = cfheaders(checkpoint_prev, hashes[99], 100);
        assert_eq!(deliver(&mut manager, &network, first).await.0, vec![(5000, 5099)]);
        let filter_headers = storage.filter_headers();
        let filter_headers = filter_headers.read().await;
        assert_eq!(filter_headers.get_filter_header(4999).await.unwrap(), Some(checkpoint_prev));
        assert_eq!(filter_headers.get_filter_tip_height().await.unwrap(), Some(5099));
    }

    #[tokio::test]
    async fn test_resumed_cfheaders_batch_chains_from_stored_header() {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let hashes = store_block_headers(&storage, 0, 4000).await;
        let first_headers =
            compute_filter_headers(&cfheaders(FilterHeader::all_zeros(), hashes[1999], 2000));
        storage
            .filter_headers()
            .write()
            .await
            .store_filter_headers_at_height(&first_headers, 0)
            .await
            .unwrap();

        // A manager started over existing filter headers resumes at 2000.
        let (mut manager, network) = start_sync(&storage, 3999).await;
        assert_eq!(manager.pipeline.next_expected(), 2000);
        assert_eq!(manager.checkpoint_start_height, None);

        let next = cfheaders(*first_headers.last().unwrap(), hashes[3999], 2000);
        assert_eq!(deliver(&mut manager, &network, next).await.0, vec![(2000, 3999)]);
    }
}
