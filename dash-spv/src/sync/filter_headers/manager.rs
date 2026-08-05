//! Filter headers manager for parallel sync.
//!
//! Downloads compact block filter headers (BIP 157/158). Reacts to BlockHeadersStored
//! events to know when new headers are available. Emits FilterHeadersStored events.

use std::sync::Arc;

use dashcore::network::message_filter::CFHeaders;
use tokio::sync::RwLock;

use super::pipeline::FilterHeadersPipeline;
use crate::error::SyncResult;
use crate::network::NetworkManager;
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
    /// Filling in a range below the stored one, where the storage tip stays put
    /// while the pipeline walks the low range.
    pub(super) backfilling: bool,
}

impl<H: BlockHeaderStorage, FH: FilterHeaderStorage> FilterHeadersManager<H, FH> {
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
            backfilling: false,
            block_headers_synced: false,
        })
    }

    /// Process a CFHeaders response - store headers and update state.
    pub(super) async fn process_cfheaders(
        &mut self,
        cfheaders: &CFHeaders,
        start_height: u32,
    ) -> SyncResult<u32> {
        let filter_headers = compute_filter_headers(cfheaders);
        let count = filter_headers.len() as u32;

        let mut storage = self.filter_header_storage.write().await;

        // For checkpoint sync, store previous_filter_header at start_height - 1
        // so filter verification can chain correctly. Only on first batch.
        if let Some(checkpoint_height) = self.checkpoint_start_height {
            if start_height == checkpoint_height && start_height > 0 {
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
        }

        storage.store_filter_headers_at_height(&filter_headers, start_height).await?;

        drop(storage);

        self.progress.add_processed(count);

        Ok(count)
    }

    /// Re-sync filter headers from a header floor that just moved down.
    ///
    /// `start_download` derives its start from the filter-header tip, so it can
    /// only ever move forward and would skip a range that became reachable
    /// below it. Re-initialize the pipeline at the new floor instead: the range
    /// above it is re-requested and stored back at the same heights, which
    /// keeps progress monotonic and avoids a second, backwards download path.
    pub(super) async fn resync_from_floor(
        &mut self,
        start_height: u32,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        // Only fetch what is actually missing: everything from the stored start
        // upwards is already there, and re-storing it would overwrite it.
        let stored_start = self.filter_header_storage.read().await.get_filter_start_height().await;
        let Some(target_height) = stored_start.map(|start| start.saturating_sub(1)) else {
            return Ok(vec![]);
        };
        if start_height > target_height {
            return Ok(vec![]);
        }

        tracing::info!(
            "Filling in filter headers {}..{} below the stored range",
            start_height,
            target_height
        );

        let header_storage = self.header_storage.read().await;
        self.pipeline.init(&*header_storage, start_height, target_height).await?;
        drop(header_storage);

        // Filter verification chains from the header below the range, so the
        // first batch has to store the predecessor the peer sends with it —
        // the same thing a fresh checkpoint sync does. Genesis has none.
        self.checkpoint_start_height = (start_height > 0).then_some(start_height);
        self.backfilling = true;
        self.progress.update_current_height(start_height.saturating_sub(1));
        self.pipeline.send_pending(network).await?;
        self.set_state(SyncState::Syncing);

        Ok(vec![])
    }

    /// Tip to report to other managers: the highest filter header stored, which
    /// during a backfill is above the range the pipeline is currently walking.
    pub(super) async fn reported_tip(&self) -> u32 {
        let stored_tip = self
            .filter_header_storage
            .read()
            .await
            .get_filter_tip_height()
            .await
            .ok()
            .flatten()
            .unwrap_or(0);
        stored_tip.max(self.progress.current_height())
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

        // Declare initial batches to the broker
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

        // While filling in a range below the stored one the pipeline is aimed at
        // that range, so extending it towards the tip here would queue the whole
        // already-stored span above it. The fill rebases onto the tip when it
        // finishes.
        if self.backfilling {
            return Ok(vec![]);
        }

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
}
