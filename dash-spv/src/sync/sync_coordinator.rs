//! Parallel sync coordinator.
//!
//! The coordinator orchestrates all sync managers, spawning each in its own
//! tokio task for true parallel processing. It tracks aggregate progress and
//! coordinates graceful shutdown.

use std::time::{Duration, Instant};

use futures::stream::{select_all, StreamExt};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_stream::wrappers::WatchStream;
use tokio_util::sync::CancellationToken;

use crate::error::SyncResult;
use crate::event_bus::{EventBus, EventReceiver};
use crate::network::NetworkManager;
use crate::storage::{BlockHeaderStorage, BlockStorage, FilterHeaderStorage, FilterStorage};
use crate::sync::{
    BlockHeadersManager, BlocksManager, ChainLockManager, FilterHeadersManager, FiltersManager,
    InstantSendManager, ManagerIdentifier, MasternodesManager, SyncEvent, SyncManager,
    SyncManagerProgress, SyncManagerTaskContext, SyncProgress,
};
use crate::SyncError;
use key_wallet_manager::wallet_interface::WalletInterface;

const TASK_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Macro to spawn a manager if present.
macro_rules! spawn_manager {
    ($self:expr, $field:ident, $network:expr) => {
        if let Some(manager) = $self.managers.$field.take() {
            let identifier = manager.identifier();
            let wanted_message_types = manager.wanted_message_types();
            let requests = $network.request_sender();
            let initial_peer_count = $network.peer_count();
            let best_peer_height = $network.get_peer_best_height().await;
            let message_receiver = $network.message_receiver(wanted_message_types).await;
            let network_event_rx = $network.subscribe_network_events();
            let (progress_sender, progress_receiver) = watch::channel(manager.progress());

            tracing::info!(
                "Spawning {} task, receiving message types: {:?}",
                identifier,
                wanted_message_types
            );

            let context = SyncManagerTaskContext {
                message_receiver,
                sync_event_bus: $self.sync_event_bus.clone(),
                network_event_receiver: network_event_rx,
                requests,
                shutdown: $self.shutdown.clone(),
                progress_sender,
                initial_peer_count,
                best_peer_height,
            };

            $self.tasks.spawn(manager.run(context));
            $self.progress_receivers.push(progress_receiver);
        }
    };
}

/// Container for all manager instances.
pub struct Managers<H, FH, F, B, W>
where
    H: BlockHeaderStorage,
    FH: FilterHeaderStorage,
    F: FilterStorage,
    B: BlockStorage,
    W: WalletInterface + 'static,
{
    pub block_headers: Option<BlockHeadersManager<H>>,
    pub filter_headers: Option<FilterHeadersManager<H, FH>>,
    pub filters: Option<FiltersManager<H, FH, F, W>>,
    pub blocks: Option<BlocksManager<H, B, W>>,
    pub masternode: Option<MasternodesManager<H>>,
    pub chainlock: Option<ChainLockManager<H>>,
    pub instantsend: Option<InstantSendManager>,
}

impl<H, FH, F, B, W> Default for Managers<H, FH, F, B, W>
where
    H: BlockHeaderStorage,
    FH: FilterHeaderStorage,
    F: FilterStorage,
    B: BlockStorage,
    W: WalletInterface + 'static,
{
    fn default() -> Self {
        Self {
            block_headers: None,
            filter_headers: None,
            filters: None,
            blocks: None,
            masternode: None,
            chainlock: None,
            instantsend: None,
        }
    }
}

/// Sync coordinator handling the separate sync managers.
///
/// - Spawns each manager in its own tokio task
/// - Tracks and aggregates progress via watch channels
/// - Coordinates graceful shutdown
pub struct SyncCoordinator<H, FH, F, B, W>
where
    H: BlockHeaderStorage,
    FH: FilterHeaderStorage,
    F: FilterStorage,
    B: BlockStorage,
    W: WalletInterface + 'static,
{
    /// Manager instances provided on construction and consumed in start spawned tasks.
    managers: Managers<H, FH, F, B, W>,
    /// Progress receivers from spawned manager tasks.
    progress_receivers: Vec<watch::Receiver<SyncManagerProgress>>,
    /// JoinSet for managing spawned tasks.
    tasks: JoinSet<SyncResult<ManagerIdentifier>>,
    /// Event bus for inter-manager communication.
    sync_event_bus: EventBus<SyncEvent>,
    /// Watch channel sender for progress updates.
    progress_sender: watch::Sender<SyncProgress>,
    /// Watch channel receiver for progress updates.
    progress_receiver: watch::Receiver<SyncProgress>,
    /// Time when sync started (for duration logging).
    sync_start_time: Option<Instant>,
    /// Shutdown token for all tasks.
    shutdown: CancellationToken,
    /// Handle for the progress aggregation task.
    progress_task: Option<tokio::task::JoinHandle<()>>,
}

impl<H, FH, F, B, W> SyncCoordinator<H, FH, F, B, W>
where
    H: BlockHeaderStorage,
    FH: FilterHeaderStorage,
    F: FilterStorage,
    B: BlockStorage,
    W: WalletInterface + 'static,
{
    /// Create a new coordinator with the given config.
    ///
    /// Managers are passed to `start()` when sync begins.
    pub fn new(managers: Managers<H, FH, F, B, W>) -> Self {
        let (progress_sender, progress_receiver) = watch::channel(SyncProgress::default());
        Self {
            managers,
            progress_receivers: Vec::new(),
            tasks: JoinSet::new(),
            sync_event_bus: EventBus::default(),
            progress_sender,
            progress_receiver,
            sync_start_time: None,
            shutdown: CancellationToken::new(),
            progress_task: None,
        }
    }

    /// Subscribe to progress updates.
    pub fn subscribe_progress(&self) -> watch::Receiver<SyncProgress> {
        self.progress_sender.subscribe()
    }

    /// Subscribe to sync events.
    pub fn subscribe_events(&self) -> EventReceiver<SyncEvent> {
        self.sync_event_bus.subscribe()
    }

    /// Start all managers by spawning each in its own task.
    ///
    /// Each manager receives:
    /// - A message stream filtered by its subscribed types
    /// - An event bus subscription for inter-manager events
    /// - A request sender for outgoing network messages
    /// - A shutdown token for graceful termination
    pub async fn start<N>(&mut self, network: &mut N) -> SyncResult<()>
    where
        N: NetworkManager,
    {
        if !self.tasks.is_empty() {
            return Err(SyncError::SyncInProgress);
        }

        tracing::info!("Starting sync managers in separate tasks");

        // Record sync start time
        let sync_start_time = Instant::now();
        self.sync_start_time = Some(sync_start_time);

        // Spawn each manager using the macro
        spawn_manager!(self, block_headers, network);
        spawn_manager!(self, filter_headers, network);
        spawn_manager!(self, filters, network);
        spawn_manager!(self, blocks, network);
        spawn_manager!(self, masternode, network);
        spawn_manager!(self, chainlock, network);
        spawn_manager!(self, instantsend, network);

        // Clone receivers for progress task
        let receivers = self.progress_receivers.clone();

        // Spawn progress aggregation task
        let progress_sender = self.progress_sender.clone();
        let sync_event_bus = self.sync_event_bus.clone();
        let shutdown = self.shutdown.clone();

        self.progress_task = Some(tokio::spawn(run_progress_task(
            receivers,
            progress_sender,
            sync_event_bus,
            shutdown,
            sync_start_time,
        )));

        tracing::info!("All {} manager tasks spawned", self.progress_receivers.len());

        Ok(())
    }

    /// Run periodic tick to check for task completion errors.
    ///
    /// Progress aggregation is handled reactively by the dedicated progress task.
    /// This method only checks for completed manager tasks (errors or early exits).
    pub async fn tick(&mut self) -> SyncResult<()> {
        while let Some(result) = self.tasks.try_join_next() {
            match result {
                Ok(Ok(identifier)) => {
                    tracing::debug!("{} task completed successfully", identifier);
                }
                Ok(Err(e)) => {
                    tracing::error!("Manager task failed: {}", e);
                }
                Err(e) => {
                    tracing::error!("Manager task panicked: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Gracefully shutdown all manager tasks.
    pub async fn shutdown(&mut self) -> SyncResult<()> {
        tracing::info!("Shutting down SyncCoordinator");

        // Signal all tasks to shutdown
        self.shutdown.cancel();

        // Wait for all manager tasks to complete with timeout
        let join_start = Instant::now();

        while let Some(result) = self.tasks.join_next().await {
            if join_start.elapsed() > TASK_JOIN_TIMEOUT {
                tracing::warn!("Shutdown timeout, some tasks may not have completed cleanly");
                break;
            }
            match result {
                Ok(Ok(identifier)) => {
                    tracing::debug!("{} task completed during shutdown", identifier);
                }
                Ok(Err(e)) => {
                    tracing::warn!("Manager task error during shutdown: {}", e);
                }
                Err(e) => {
                    tracing::error!("Manager task panic during shutdown: {}", e);
                }
            }
        }

        // Wait for progress task to complete
        if let Some(handle) = self.progress_task.take() {
            let _ = handle.await;
        }

        tracing::info!("Shutdown complete");

        Ok(())
    }

    /// Get current progress.
    pub fn progress(&self) -> SyncProgress {
        self.progress_receiver.borrow().clone()
    }

    /// Check if all managers are idle (sync complete).
    pub fn is_synced(&self) -> bool {
        self.progress_receiver.borrow().is_synced()
    }

    /// Get the duration since sync started.
    pub fn sync_duration(&self) -> Option<Duration> {
        self.sync_start_time.map(|start| start.elapsed())
    }
}

impl<H, FH, F, B, W> std::fmt::Debug for SyncCoordinator<H, FH, F, B, W>
where
    H: BlockHeaderStorage,
    FH: FilterHeaderStorage,
    F: FilterStorage,
    B: BlockStorage,
    W: WalletInterface + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncCoordinator")
            .field("manager_count", &self.tasks.len())
            .field("progress", &*self.progress_receiver.borrow())
            .finish()
    }
}

/// Reactive progress aggregation task.
///
/// Listens to all manager progress receivers and emits consolidated updates
/// immediately when any manager's progress changes.
async fn run_progress_task(
    receivers: Vec<watch::Receiver<SyncManagerProgress>>,
    progress_sender: watch::Sender<SyncProgress>,
    sync_event_bus: EventBus<SyncEvent>,
    shutdown: CancellationToken,
    sync_start_time: Instant,
) {
    let streams: Vec<_> =
        receivers.into_iter().map(|rx| WatchStream::new(rx).map(move |p| p)).collect();

    let mut merged = select_all(streams);
    let mut progress = SyncProgress::default();
    let mut sync_complete_emitted = false;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            Some(manager_progress) = merged.next() => {
                update_progress_from_manager(&mut progress, manager_progress);

                let _ = progress_sender.send(progress.clone());

                if progress.is_synced() && !sync_complete_emitted {
                    let duration = sync_start_time.elapsed();
                    tracing::info!("Initial sync complete in {:.2}s", duration.as_secs_f64());

                    let header_tip = progress.headers().ok().map(|h| h.current_height()).unwrap_or(0);
                    sync_event_bus.emit(&[SyncEvent::SyncComplete { header_tip }]);
                    sync_complete_emitted = true;
                }
            }
        }
    }
}

/// Update aggregate progress from a single manager's progress update.
fn update_progress_from_manager(
    progress: &mut SyncProgress,
    manager_progress: SyncManagerProgress,
) {
    match manager_progress {
        SyncManagerProgress::BlockHeaders(h) => progress.update_headers(h),
        SyncManagerProgress::FilterHeaders(fh) => progress.update_filter_headers(fh),
        SyncManagerProgress::Filters(f) => progress.update_filters(f),
        SyncManagerProgress::Blocks(b) => progress.update_blocks(b),
        SyncManagerProgress::Masternodes(m) => progress.update_masternodes(m),
        SyncManagerProgress::ChainLock(c) => progress.update_chainlocks(c),
        SyncManagerProgress::InstantSend(i) => progress.update_instantsend(i),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{BlockHeadersProgress, FiltersProgress, SyncState};

    #[test]
    fn test_sync_progress_default() {
        let progress = SyncProgress::default();
        assert_eq!(progress.state(), SyncState::Initializing);
        assert!(!progress.is_synced());
        // Fields are None by default - getters return errors
        assert!(progress.headers().is_err());
        assert!(progress.filters().is_err());
        assert!(progress.blocks().is_err());
    }

    #[test]
    fn test_sync_percentage_empty() {
        let progress = SyncProgress::default();
        // Both headers and filters are None, so percentage defaults to 1.0
        assert_eq!(progress.percentage(), 1.0);
    }

    #[test]
    fn test_sync_percentage() {
        let mut progress = SyncProgress::default();

        // Create headers progress at 50%
        let mut headers_progress = BlockHeadersProgress::default();
        headers_progress.set_state(SyncState::Syncing);
        headers_progress.update_current_height(500);
        headers_progress.update_target_height(1000);
        headers_progress.add_processed(500);
        progress.update_headers(headers_progress);

        // Create filters progress at 25%
        let mut filters_progress = FiltersProgress::default();
        filters_progress.set_state(SyncState::Syncing);
        filters_progress.update_current_height(250);
        filters_progress.update_target_height(1000);
        filters_progress.add_downloaded(250);
        progress.update_filters(filters_progress);

        // (0.5 + 1.0 + 0.25) / 3 = ~0.583 (filter_headers defaults to 1.0)
        assert!((progress.percentage() - 0.583).abs() < 0.01);
    }
}
