//! Parallel sync coordinator.
//!
//! The coordinator orchestrates all sync managers, spawning each in its own
//! tokio task for true parallel processing. It tracks aggregate progress and
//! coordinates graceful shutdown.

use std::time::{Duration, Instant};

use futures::stream::{select_all, StreamExt};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinSet;
use tokio_stream::wrappers::WatchStream;
use tokio_util::sync::CancellationToken;

use crate::error::SyncResult;
use crate::network::NetworkManager;
use crate::storage::{
    BlockHeaderStorage, BlockStorage, FilterHeaderStorage, FilterStorage, MetadataStorage,
};
use crate::sync::progress::ProgressPercentage;
use crate::sync::{
    BlockHeadersManager, BlocksManager, ChainLockManager, FilterHeadersManager, FiltersManager,
    InstantSendManager, ManagerIdentifier, MasternodesManager, MempoolManager, SyncEvent,
    SyncManager, SyncManagerProgress, SyncManagerTaskContext, SyncProgress,
};
use crate::SyncError;
use key_wallet_manager::WalletInterface;

const TASK_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_SYNC_EVENT_CAPACITY: usize = 10000;

/// Macro to spawn a manager if present.
macro_rules! spawn_manager {
    ($manager:expr, $network:expr, $sync_event_sender:expr, $shutdown:expr, $tasks:expr, $progress_receivers:expr) => {
        if let Some(manager) = $manager {
            let identifier = manager.identifier();
            let wanted_message_types = manager.wanted_message_types();
            let requests = $network.request_sender();
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
                sync_event_sender: $sync_event_sender.clone(),
                network_event_receiver: network_event_rx,
                requests,
                shutdown: $shutdown.clone(),
                progress_sender,
            };

            $tasks.spawn(manager.run(context));
            $progress_receivers.push(progress_receiver);
        }
    };
}

/// Container for all manager instances.
pub struct Managers<H, FH, F, B, M, W>
where
    H: BlockHeaderStorage,
    FH: FilterHeaderStorage,
    F: FilterStorage,
    B: BlockStorage,
    M: MetadataStorage,
    W: WalletInterface + 'static,
{
    pub block_headers: Option<BlockHeadersManager<H, M>>,
    pub filter_headers: Option<FilterHeadersManager<H, FH>>,
    pub filters: Option<FiltersManager<H, FH, F, W>>,
    pub blocks: Option<BlocksManager<H, B, W>>,
    pub masternode: Option<MasternodesManager<H>>,
    pub chainlock: Option<ChainLockManager<H, M>>,
    pub instantsend: Option<InstantSendManager<H>>,
    pub(crate) mempool: Option<MempoolManager<W>>,
}

impl<H, FH, F, B, M, W> Default for Managers<H, FH, F, B, M, W>
where
    H: BlockHeaderStorage,
    FH: FilterHeaderStorage,
    F: FilterStorage,
    B: BlockStorage,
    M: MetadataStorage,
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
            mempool: None,
        }
    }
}

impl<H, FH, F, B, M, W> Managers<H, FH, F, B, M, W>
where
    H: BlockHeaderStorage,
    FH: FilterHeaderStorage,
    F: FilterStorage,
    B: BlockStorage,
    M: MetadataStorage,
    W: WalletInterface + 'static,
{
    pub(crate) fn progress(&self) -> SyncProgress {
        let mut progress = SyncProgress::default();
        try_update_progress(self.block_headers.as_ref(), &mut progress);
        try_update_progress(self.filter_headers.as_ref(), &mut progress);
        try_update_progress(self.filters.as_ref(), &mut progress);
        try_update_progress(self.blocks.as_ref(), &mut progress);
        try_update_progress(self.masternode.as_ref(), &mut progress);
        try_update_progress(self.chainlock.as_ref(), &mut progress);
        try_update_progress(self.instantsend.as_ref(), &mut progress);
        try_update_progress(self.mempool.as_ref(), &mut progress);
        progress
    }
}

/// Sync coordinator handling the separate sync managers.
///
/// - Spawns each manager in its own tokio task
/// - Tracks and aggregates progress via watch channels
/// - Coordinates graceful shutdown
///
/// The event and progress channels live as long as the coordinator, so
/// subscribers keep receiving across runs; each [`Self::start`] runs a fresh
/// set of managers until the next [`Self::shutdown`].
pub struct SyncCoordinator {
    /// Event bus for inter-manager communication.
    sync_event_sender: broadcast::Sender<SyncEvent>,
    /// Watch channel sender for progress updates.
    progress_sender: watch::Sender<SyncProgress>,
    /// The managers' tasks, from `start` until `shutdown`.
    run: Option<SyncRun>,
}

/// The tasks spawned by one [`SyncCoordinator::start`].
struct SyncRun {
    tasks: JoinSet<SyncResult<ManagerIdentifier>>,
    shutdown: CancellationToken,
    progress_task: tokio::task::JoinHandle<()>,
    start_time: Instant,
}

impl SyncCoordinator {
    /// Create a stopped coordinator reporting `initial_progress`.
    pub(crate) fn new(initial_progress: SyncProgress) -> Self {
        Self {
            sync_event_sender: broadcast::Sender::new(DEFAULT_SYNC_EVENT_CAPACITY),
            progress_sender: watch::Sender::new(initial_progress),
            run: None,
        }
    }

    /// Subscribe to progress updates.
    pub fn subscribe_progress(&self) -> watch::Receiver<SyncProgress> {
        self.progress_sender.subscribe()
    }

    /// Subscribe to sync events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<SyncEvent> {
        self.sync_event_sender.subscribe()
    }

    /// Reset the reported progress, e.g. after the storage is wiped.
    pub(crate) fn reset_progress(&self) {
        self.progress_sender.send_replace(SyncProgress::default());
    }

    /// Start `managers` by spawning each in its own task.
    ///
    /// Each manager receives:
    /// - A message stream filtered by its subscribed types
    /// - An event bus subscription for inter-manager events
    /// - A request sender for outgoing network messages
    /// - A shutdown token for graceful termination
    pub async fn start<H, FH, F, B, M, W, N>(
        &mut self,
        managers: Managers<H, FH, F, B, M, W>,
        network: &mut N,
    ) -> SyncResult<()>
    where
        H: BlockHeaderStorage,
        FH: FilterHeaderStorage,
        F: FilterStorage,
        B: BlockStorage,
        M: MetadataStorage,
        W: WalletInterface + 'static,
        N: NetworkManager,
    {
        if self.run.is_some() {
            return Err(SyncError::InvalidState("SyncCoordinator already started".to_string()));
        }

        let initial_progress = managers.progress();
        tracing::info!("Initial sync progress {}", initial_progress.clone());
        self.progress_sender.send_replace(initial_progress);

        tracing::info!("Starting sync managers in separate tasks");

        let start_time = Instant::now();
        let shutdown = CancellationToken::new();
        let mut tasks = JoinSet::new();
        let mut progress_receivers = Vec::new();

        let Managers {
            block_headers,
            filter_headers,
            filters,
            blocks,
            masternode,
            chainlock,
            instantsend,
            mempool,
        } = managers;
        let events = &self.sync_event_sender;
        spawn_manager!(block_headers, network, events, shutdown, tasks, progress_receivers);
        spawn_manager!(filter_headers, network, events, shutdown, tasks, progress_receivers);
        spawn_manager!(filters, network, events, shutdown, tasks, progress_receivers);
        spawn_manager!(blocks, network, events, shutdown, tasks, progress_receivers);
        spawn_manager!(masternode, network, events, shutdown, tasks, progress_receivers);
        spawn_manager!(chainlock, network, events, shutdown, tasks, progress_receivers);
        spawn_manager!(instantsend, network, events, shutdown, tasks, progress_receivers);
        spawn_manager!(mempool, network, events, shutdown, tasks, progress_receivers);

        tracing::info!("All {} manager tasks spawned", progress_receivers.len());

        let progress_task = tokio::spawn(run_progress_task(
            progress_receivers,
            self.progress_sender.clone(),
            self.sync_event_sender.clone(),
            shutdown.clone(),
            start_time,
        ));

        self.run = Some(SyncRun {
            tasks,
            shutdown,
            progress_task,
            start_time,
        });

        Ok(())
    }

    /// Run periodic tick to check for task completion errors.
    ///
    /// Progress aggregation is handled reactively by the dedicated progress task.
    /// This method only checks for completed manager tasks (errors or early exits).
    pub async fn tick(&mut self) -> SyncResult<()> {
        let Some(run) = self.run.as_mut() else {
            return Ok(());
        };
        while let Some(result) = run.tasks.try_join_next() {
            match result {
                Ok(Ok(identifier)) => {
                    tracing::debug!("{} task completed successfully", identifier);
                }
                Ok(Err(e)) => {
                    tracing::error!("Manager task failed: {}", e);
                    return Err(e);
                }
                Err(e) => {
                    tracing::error!("Manager task panicked: {}", e);
                    return Err(SyncError::InvalidState(format!("Manager task panicked: {}", e)));
                }
            }
        }

        Ok(())
    }

    /// Gracefully shutdown all manager tasks.
    pub async fn shutdown(&mut self) -> SyncResult<()> {
        let Some(mut run) = self.run.take() else {
            return Ok(());
        };

        tracing::info!("Shutting down SyncCoordinator");

        // Signal all tasks to shutdown
        run.shutdown.cancel();

        // Wait for all manager tasks to complete with timeout
        let drain_tasks = async {
            while let Some(result) = run.tasks.join_next().await {
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
        };

        if tokio::time::timeout(TASK_JOIN_TIMEOUT, drain_tasks).await.is_err() {
            tracing::warn!(
                "Shutdown timeout after {:?}, {} tasks may not have completed cleanly",
                TASK_JOIN_TIMEOUT,
                run.tasks.len()
            );
        }

        run.tasks.shutdown().await;

        // Wait for progress task to complete with timeout
        if tokio::time::timeout(Duration::from_secs(1), &mut run.progress_task).await.is_err() {
            tracing::warn!("Progress task did not complete within timeout");
            run.progress_task.abort();
        }

        tracing::info!("Shutdown complete");

        Ok(())
    }

    /// Get current progress.
    pub fn progress(&self) -> SyncProgress {
        self.progress_sender.borrow().clone()
    }

    /// Check if all managers are idle (sync complete).
    pub fn is_synced(&self) -> bool {
        self.progress_sender.borrow().is_synced()
    }

    /// Get the duration since sync started.
    pub fn sync_duration(&self) -> Option<Duration> {
        self.run.as_ref().map(|run| run.start_time.elapsed())
    }
}

impl std::fmt::Debug for SyncCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncCoordinator")
            .field("manager_count", &self.run.as_ref().map_or(0, |run| run.tasks.len()))
            .field("progress", &*self.progress_sender.borrow())
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
    sync_event_sender: broadcast::Sender<SyncEvent>,
    shutdown: CancellationToken,
    sync_start_time: Instant,
) {
    let streams: Vec<_> = receivers.into_iter().map(WatchStream::from_changes).collect();

    let mut merged = select_all(streams);
    let mut progress = progress_sender.borrow().clone();
    let mut was_synced = false;
    let mut sync_cycle: u32 = 0;
    let mut cycle_start = sync_start_time;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            Some(manager_progress) = merged.next() => {
                update_progress_from_manager(&mut progress, manager_progress);

                let _ = progress_sender.send(progress.clone());

                let is_synced = progress.is_synced();
                if is_synced && !was_synced {
                    let duration = cycle_start.elapsed();
                    tracing::info!("Sync complete in {:.2}s (cycle {})", duration.as_secs_f64(), sync_cycle);

                    let header_tip = progress.headers().ok().map(|h| h.current_height()).unwrap_or(0);
                    let _ = sync_event_sender.send(SyncEvent::SyncComplete { header_tip, cycle: sync_cycle });
                    sync_cycle += 1;
                } else if !is_synced && was_synced {
                    cycle_start = Instant::now();
                }
                was_synced = is_synced;
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
        SyncManagerProgress::Mempool(m) => progress.update_mempool(m),
    }
}

/// Try to merge progress from an optional manager into a SyncProgress.
fn try_update_progress(manager: Option<&impl SyncManager>, sync_progress: &mut SyncProgress) {
    if let Some(manager) = manager {
        update_progress_from_manager(sync_progress, manager.progress());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{BlockHeadersProgress, FilterHeadersProgress, FiltersProgress, SyncState};

    #[test]
    fn test_sync_progress_default() {
        let progress = SyncProgress::default();
        assert_eq!(progress.state(), SyncState::WaitForEvents);
        assert!(!progress.is_synced());
        // Fields are None by default - getters return errors
        assert!(progress.headers().is_err());
        assert!(progress.filters().is_err());
        assert!(progress.blocks().is_err());
    }

    #[test]
    fn test_sync_percentage_empty() {
        let progress = SyncProgress::default();
        // All fields are None, no active phases, so percentage is 0.0
        assert_eq!(progress.percentage(), 0.0);
    }

    #[test]
    fn test_sync_percentage_headers_only() {
        let mut progress = SyncProgress::default();

        // Create headers progress at 50%
        let mut headers_progress = BlockHeadersProgress::default();
        headers_progress.set_state(SyncState::Syncing);
        headers_progress.update_tip_height(500);
        headers_progress.update_target_height(1000);
        headers_progress.add_processed(500);
        progress.update_headers(headers_progress);

        // Only headers is active, so percentage = 0.5
        assert_eq!(progress.percentage(), 0.5);
    }

    #[test]
    fn test_sync_percentage_mixed() {
        let mut progress = SyncProgress::default();

        // Create headers progress at 75%
        let mut headers_progress = BlockHeadersProgress::default();
        headers_progress.set_state(SyncState::Syncing);
        headers_progress.update_tip_height(750);
        headers_progress.update_target_height(1000);
        headers_progress.add_processed(750);
        progress.update_headers(headers_progress);

        // Create filter headers progress at 50%
        let mut filter_headers_progress = FilterHeadersProgress::default();
        filter_headers_progress.set_state(SyncState::Syncing);
        filter_headers_progress.update_current_height(500);
        filter_headers_progress.update_target_height(1000);
        filter_headers_progress.add_processed(500);
        progress.update_filter_headers(filter_headers_progress);

        // Create filters progress at 25%
        let mut filters_progress = FiltersProgress::default();
        filters_progress.set_state(SyncState::Syncing);
        filters_progress.update_committed_height(250);
        filters_progress.update_target_height(1000);
        filters_progress.add_downloaded(250);
        progress.update_filters(filters_progress);

        // Headers 75%, filter headers 50%, filters 25%: (0.75 + 0.5 + 0.25) / 3 = 0.5
        assert_eq!(progress.percentage(), 0.5);
    }
}
