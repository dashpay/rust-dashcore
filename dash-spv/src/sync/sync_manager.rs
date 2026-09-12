use crate::error::SyncResult;
use crate::network::{InboundMessage, MessageType, NetworkEvent, NetworkManager};
use crate::sync::{
    BlockHeadersProgress, BlocksProgress, ChainLockProgress, FilterHeadersProgress,
    FiltersProgress, InstantSendProgress, ManagerIdentifier, MasternodesProgress, MempoolProgress,
    SyncEvent, SyncState,
};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::SyncError;

/// Contains a trait for event-driven sync managers.
///
/// Each manager is responsible for a specific sync task (headers, filters, blocks, etc.)
/// and communicates with other managers via events. Managers progress independently and
/// catch up to each other as events flow between them.
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::watch;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, PartialEq)]
pub enum SyncManagerProgress {
    BlockHeaders(BlockHeadersProgress),
    FilterHeaders(FilterHeadersProgress),
    Filters(FiltersProgress),
    Blocks(BlocksProgress),
    Masternodes(MasternodesProgress),
    ChainLock(ChainLockProgress),
    InstantSend(InstantSendProgress),
    Mempool(MempoolProgress),
}

impl SyncManagerProgress {
    pub fn state(&self) -> SyncState {
        match self {
            SyncManagerProgress::BlockHeaders(progress) => progress.state(),
            SyncManagerProgress::FilterHeaders(progress) => progress.state(),
            SyncManagerProgress::Filters(progress) => progress.state(),
            SyncManagerProgress::Blocks(progress) => progress.state(),
            SyncManagerProgress::Masternodes(progress) => progress.state(),
            SyncManagerProgress::ChainLock(progress) => progress.state(),
            SyncManagerProgress::InstantSend(progress) => progress.state(),
            SyncManagerProgress::Mempool(progress) => progress.state(),
        }
    }
}

pub type Inbound = (SocketAddr, Arc<InboundMessage>);

pub struct SyncManagerTaskContext {
    pub(super) message_receiver: UnboundedReceiver<Inbound>,
    pub(super) sync_event_sender: broadcast::Sender<SyncEvent>,
    pub(super) network_event_receiver: broadcast::Receiver<NetworkEvent>,
    pub(super) network: Arc<dyn NetworkManager>,
    pub(super) shutdown: CancellationToken,
    pub(super) progress_sender: watch::Sender<SyncManagerProgress>,
}

impl SyncManagerTaskContext {
    pub(super) fn emit_sync_event(&self, event: SyncEvent) {
        let _ = self.sync_event_sender.send(event);
    }
    pub(super) fn emit_sync_events(&self, events: impl IntoIterator<Item = SyncEvent>) {
        for event in events {
            self.emit_sync_event(event);
        }
    }
}

// Display for the network event so the sync loop / broadcast monitor can log
// it (they require `Display`). Kept here to avoid modifying the network module.
impl std::fmt::Display for NetworkEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkEvent::PeersUpdated {
                connected_count,
                ..
            } => write!(f, "PeersUpdated({connected_count} peers)"),
            NetworkEvent::PeerConnected(addr) => write!(f, "PeerConnected({addr})"),
            NetworkEvent::PeerDisconnected(addr) => write!(f, "PeerDisconnected({addr})"),
        }
    }
}

/// The default [`SyncManager::handle_network_event`] body, callable from an override.
///
/// A manager that only cares about some `NetworkEvent` variants overrides
/// `handle_network_event` and delegates the rest here. Rust gives no way to call a
/// trait's default body from an override, so the shared logic lives in this free
/// function — the trait's default method just calls it.
pub(super) async fn default_handle_network_event<M: SyncManager + ?Sized>(
    manager: &mut M,
    event: &NetworkEvent,
    network: &Arc<dyn NetworkManager>,
) -> SyncResult<Vec<SyncEvent>> {
    // `PeersUpdated` is the cue to kick off the initial requests: the network manager
    // connects in `start`, after every manager has subscribed, so this is the first thing
    // we hear from it. Individual peer disconnects are recovered by per-request
    // timeout+retry, so they don't stop sync.
    if let NetworkEvent::PeersUpdated {
        ..
    } = event
    {
        // Seed every manager's target from the peers' advertised tip so the
        // height shows up right away (matches the pre-network `best_height`).
        manager.update_target_height(network.tip());
        if manager.state() == SyncState::WaitingForConnections {
            tracing::info!("{} - peers available, starting sync", manager.identifier());
            return manager.start_sync(network).await;
        }
    }
    Ok(vec![])
}

/// Guard that verifies a manager has not already been started.
pub(super) fn ensure_not_started(
    state: SyncState,
    identifier: ManagerIdentifier,
) -> SyncResult<()> {
    if state != SyncState::WaitingForConnections {
        tracing::warn!("{} sync already started.", identifier);
        return Err(SyncError::SyncInProgress(identifier));
    }
    Ok(())
}

#[async_trait]
pub trait SyncManager: Send + Sync + std::fmt::Debug {
    /// Get the unique identifier for this manager.
    fn identifier(&self) -> ManagerIdentifier;

    /// Get the manager's sync state.
    fn state(&self) -> SyncState;

    /// Update the manager's sync state.
    fn set_state(&mut self, state: SyncState);

    /// Update the target height for this manager.
    fn update_target_height(&mut self, _height: u32) {}

    /// Message types this manager subscribes to for topic-based routing.
    ///
    /// The network manager uses this to route only relevant messages to each
    /// manager's task via topic-based filtering.
    fn wanted_message_types(&self) -> &'static [MessageType];

    /// Start the sync process.
    ///
    /// Called after initialization to trigger the initial sync requests.
    /// For example, BlockHeadersManager sends its first getheaders request here.
    /// The default implementation is for reactive managers that just wait for events.
    async fn start_sync(
        &mut self,
        _network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        ensure_not_started(self.state(), self.identifier())?;
        self.set_state(SyncState::WaitForEvents);
        Ok(vec![SyncEvent::SyncStart {
            identifier: self.identifier(),
        }])
    }

    /// Stop the internal processing.
    /// Called when the network manager loses its peers.
    fn stop_sync(&mut self) {
        self.set_state(SyncState::WaitingForConnections);
        self.on_disconnect();
    }

    /// Drop peer-bound in-flight state on disconnect.
    ///
    /// Each manager keeps as much progress as it can across a disconnect, and
    /// only invalidates state that was tied to the now-dead peer. Anything
    /// derivable from durable storage (block headers, filter headers, the
    /// masternode engine) or from preserved per-batch bookkeeping should
    /// survive so reconnect resumes instead of restarting.
    fn on_disconnect(&mut self);

    /// Handle an incoming network message.
    ///
    /// Returns events to emit to other managers.
    async fn handle_message(
        &mut self,
        peer: SocketAddr,
        msg: InboundMessage,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>>;

    /// Handle a sync event from another manager.
    ///
    /// This is how managers learn about progress from other managers.
    /// For example, `FilterHeadersManager` subscribes to `BlockHeadersStored`
    /// events to know when new headers are available.
    async fn handle_sync_event(
        &mut self,
        event: &SyncEvent,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>>;

    /// Periodic tick for work that only a clock can trigger.
    ///
    /// Called every 100ms by the coordinator. Reserved for genuinely time-based
    /// work — expiry, retry schedules the broker does not own, polling — and for
    /// processing that cannot be driven from an arrival. It is *not* the place to
    /// re-declare requests: once declared, the broker owns their timeout, retry and
    /// peer hot-swap, so re-offering them costs a registry lock per item and buys
    /// nothing. Managers with no such work leave this alone.
    async fn tick(&mut self, _network: &Arc<dyn NetworkManager>) -> SyncResult<Vec<SyncEvent>> {
        Ok(vec![])
    }

    /// Handle a network event (peer connection changes).
    ///
    /// The default body handles state transitions for `WaitingForConnections`.
    /// Managers can override this to customize behavior.
    async fn handle_network_event(
        &mut self,
        event: &NetworkEvent,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        default_handle_network_event(self, event, network).await
    }

    /// Retrieves the current progress of the Manager.
    fn progress(&self) -> SyncManagerProgress;

    fn try_emit_progress(
        &self,
        progress_before: SyncManagerProgress,
        progress_sender: &watch::Sender<SyncManagerProgress>,
    ) {
        let progress_now = self.progress();
        if progress_now != progress_before {
            let _ = progress_sender.send(progress_now);
        }
    }

    /// Run the manager task, processing messages, events, and periodic ticks.
    ///
    /// This consumes the manager and runs until shutdown is signaled.
    async fn run(mut self, mut context: SyncManagerTaskContext) -> SyncResult<ManagerIdentifier>
    where
        Self: Sized,
    {
        let identifier = self.identifier();
        tracing::info!("{} task starting", identifier);

        let mut sync_event_receiver = context.sync_event_sender.subscribe();

        // Tick interval for periodic housekeeping
        let mut tick_interval = interval(Duration::from_millis(100));

        tracing::info!("{} task entering main loop", identifier);

        loop {
            tokio::select! {
                _ = context.shutdown.cancelled() => {
                    tracing::info!("{} task received shutdown signal", identifier);
                    break;
                }
                // Process incoming network messages
                Some((peer, message)) = context.message_receiver.recv() => {
                    tracing::trace!("{} received message: {}", identifier, message.cmd());
                    // The pump gives its last subscriber the sole reference, so for the
                    // message types only one manager watches — block, cfilter, cfheaders,
                    // headers — this takes the payload without copying it. A genuinely
                    // shared message (`inv` goes to several managers) falls back to a clone.
                    let message =
                        Arc::try_unwrap(message).unwrap_or_else(|shared| (*shared).clone());
                    let progress_before = self.progress();
                    match self.handle_message(peer, message, &context.network).await {
                        Ok(events) => {
                            if !events.is_empty() {
                                for event in &events {
                                    tracing::debug!("{} emitting: {}", identifier, event);
                                }
                                context.emit_sync_events(events);
                            }
                            self.try_emit_progress(progress_before, &context.progress_sender);
                        }
                        Err(e) => {
                            tracing::error!("{} error handling message: {}", identifier, e);
                            let error_event = SyncEvent::ManagerError {
                                manager: identifier,
                                error: e.to_string(),
                            };
                            context.emit_sync_event(error_event);
                        }
                    }
                }
                // Process events from other managers
                result = sync_event_receiver.recv() => {
                    match result {
                        Ok(event) => {
                            tracing::trace!("{} received event: {}", identifier, event);
                            let progress_before = self.progress();
                            match self.handle_sync_event(&event, &context.network).await {
                                Ok(events) => {
                                    if !events.is_empty() {
                                        for e in &events {
                                            tracing::trace!("{} emitting: {}", identifier, e);
                                        }
                                        context.emit_sync_events(events);
                                    }
                                    self.try_emit_progress(progress_before, &context.progress_sender);
                                }
                                Err(e) => {
                                    tracing::error!("{} error handling event: {}", identifier, e);
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            // Sync-event bus overflowed for this manager; skipped `n`
                            // events. Keep running rather than killing the task: a dead
                            // manager is a stalled sync. Nothing recovers the skipped
                            // events, so the bus is sized (10k) not to overflow.
                            tracing::warn!("{} lagged sync events, skipped {}", identifier, n);
                        }
                        Err(error) => {
                            tracing::error!("{} sync event error: {}", identifier, error);
                            break;
                        }
                    }
                }
                // Process network events
                result = context.network_event_receiver.recv() => {
                    match result {
                        Ok(event) => {
                            tracing::debug!("{} received network event: {}", identifier, event);
                            let progress_before = self.progress();
                            match self.handle_network_event(&event, &context.network).await {
                                Ok(events) => {
                                    if !events.is_empty() {
                                        for e in &events {
                                            tracing::debug!("{} emitting: {}", identifier, e);
                                        }
                                        context.emit_sync_events(events);
                                    }
                                    self.try_emit_progress(progress_before, &context.progress_sender);
                                }
                                Err(e) => {
                                    tracing::error!("{} error handling network event: {}", identifier, e);
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            // Network-event bus overflowed. The bus carries only
                            // low-volume events (peer churn), so lagging 4096 behind is
                            // not realistic; keep running rather than kill the manager.
                            tracing::warn!("{} lagged network events, skipped {}", identifier, n);
                        }
                        Err(error) => {
                            tracing::error!("{} network event error: {}", identifier, error);
                            break;
                        }
                    }
                }
                // Periodic tick for timeouts and housekeeping
                _ = tick_interval.tick() => {
                    let progress_before = self.progress();
                    match self.tick(&context.network).await {
                        Ok(events) => {
                            if !events.is_empty() {
                                context.emit_sync_events(events);
                            }
                            self.try_emit_progress(progress_before, &context.progress_sender);
                        }
                        Err(e) => {
                            tracing::error!("{} tick error: {}", identifier, e);
                        }
                    }
                }
            }
        }

        tracing::info!("{} task exiting", identifier);
        Ok(identifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::BlockHeadersProgress;
    use crate::test_utils::MockNetworkManager;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::sync::mpsc;

    /// Minimal manager that only counts the callbacks the run loop makes, so a
    /// test can observe that the loop is alive and that it stops on cancel.
    struct MockManager {
        identifier: ManagerIdentifier,
        state: SyncState,
        tick_count: Arc<AtomicU32>,
    }

    impl std::fmt::Debug for MockManager {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MockManager").field("identifier", &self.identifier).finish()
        }
    }

    #[async_trait]
    impl SyncManager for MockManager {
        fn identifier(&self) -> ManagerIdentifier {
            self.identifier
        }

        fn state(&self) -> SyncState {
            self.state
        }

        fn set_state(&mut self, state: SyncState) {
            self.state = state;
        }

        fn wanted_message_types(&self) -> &'static [MessageType] {
            &[]
        }

        fn on_disconnect(&mut self) {}

        async fn handle_message(
            &mut self,
            _peer: SocketAddr,
            _msg: InboundMessage,
            _network: &Arc<dyn NetworkManager>,
        ) -> SyncResult<Vec<SyncEvent>> {
            Ok(vec![])
        }

        async fn handle_sync_event(
            &mut self,
            _event: &SyncEvent,
            _network: &Arc<dyn NetworkManager>,
        ) -> SyncResult<Vec<SyncEvent>> {
            Ok(vec![])
        }

        async fn tick(&mut self, _network: &Arc<dyn NetworkManager>) -> SyncResult<Vec<SyncEvent>> {
            self.tick_count.fetch_add(1, Ordering::Relaxed);
            Ok(vec![])
        }

        fn progress(&self) -> SyncManagerProgress {
            let mut progress = BlockHeadersProgress::default();
            progress.set_state(self.state);
            SyncManagerProgress::BlockHeaders(progress)
        }
    }

    /// The shared run loop must keep ticking while it lives and return its
    /// identifier once the shutdown token is cancelled — a manager task that
    /// ignored the token would hang `SyncCoordinator::shutdown` forever.
    #[tokio::test]
    async fn test_manager_task_shutdown() {
        let tick_count = Arc::new(AtomicU32::new(0));

        let manager = MockManager {
            identifier: ManagerIdentifier::BlockHeader,
            state: SyncState::WaitForEvents,
            tick_count: tick_count.clone(),
        };

        let (_msg_tx, message_receiver) = mpsc::unbounded_channel();
        let sync_event_sender = broadcast::Sender::<SyncEvent>::new(100);
        let network_event_sender = broadcast::Sender::<NetworkEvent>::new(100);
        let network: Arc<dyn NetworkManager> = Arc::new(MockNetworkManager::new());
        let shutdown = CancellationToken::new();
        let (progress_sender, _progress_rx) = watch::channel(manager.progress());

        let context = SyncManagerTaskContext {
            message_receiver,
            sync_event_sender,
            network_event_receiver: network_event_sender.subscribe(),
            network,
            shutdown: shutdown.clone(),
            progress_sender,
        };

        let handle = tokio::spawn(async move { manager.run(context).await });

        // Let the 100ms tick fire a few times.
        tokio::time::sleep(Duration::from_millis(250)).await;
        shutdown.cancel();

        let result = handle.await.unwrap();
        assert_eq!(result.unwrap(), ManagerIdentifier::BlockHeader);
        assert!(
            tick_count.load(Ordering::Relaxed) >= 2,
            "the run loop should have ticked while alive, got {}",
            tick_count.load(Ordering::Relaxed)
        );
    }
}
