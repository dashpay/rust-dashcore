use crate::error::{SyncError, SyncResult};
use crate::network::{Message, MessageType, NetworkEvent, RequestSender};
use crate::sync::{
    BlockHeadersProgress, BlocksProgress, ChainLockProgress, FilterHeadersProgress,
    FiltersProgress, InstantSendProgress, ManagerIdentifier, MasternodesProgress, SyncEvent,
    SyncState,
};
use async_trait::async_trait;

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
        }
    }
}

pub struct SyncManagerTaskContext {
    pub(super) message_receiver: UnboundedReceiver<Message>,
    pub(super) sync_event_sender: broadcast::Sender<SyncEvent>,
    pub(super) network_event_receiver: broadcast::Receiver<NetworkEvent>,
    pub(super) requests: RequestSender,
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

    /// Initialize the manager.
    ///
    /// Called once at startup before the main loop. Loads persisted state
    /// from internal storage and initial target heights.
    async fn initialize(&mut self) -> SyncResult<()> {
        self.set_state(SyncState::WaitingForConnections);
        tracing::info!("{} initialized", self.identifier());
        Ok(())
    }

    /// Start the sync process.
    ///
    /// Called after initialization to trigger the initial sync requests.
    /// For example, BlockHeadersManager sends its first getheaders request here.
    /// The default implementation is for reactive managers that just wait for events.
    async fn start_sync(&mut self, _requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
        if !matches!(self.state(), SyncState::WaitingForConnections | SyncState::WaitForEvents) {
            tracing::warn!("{} sync already started.", self.identifier());
            return Ok(vec![]);
        }

        self.set_state(SyncState::WaitForEvents);
        Ok(vec![SyncEvent::SyncStart {
            identifier: self.identifier(),
        }])
    }

    /// Stop the internal processing.
    /// Called when the network manager loses its peers.
    fn stop_sync(&mut self) {
        self.set_state(SyncState::WaitingForConnections);
    }

    /// Handle an incoming network message.
    ///
    /// Returns events to emit to other managers.
    async fn handle_message(
        &mut self,
        msg: Message,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>>;

    /// Handle a sync event from another manager.
    ///
    /// This is how managers learn about progress from other managers.
    /// For example, `FilterHeadersManager` subscribes to `BlockHeadersStored`
    /// events to know when new headers are available.
    async fn handle_sync_event(
        &mut self,
        event: &SyncEvent,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>>;

    /// Periodic tick for timeouts, retries, and proactive work.
    ///
    /// Called regularly by the coordinator (e.g., every 100ms).
    /// Use this for:
    /// - Timeout detection and retry logic
    /// - Proactive request sending
    /// - State cleanup
    async fn tick(&mut self, requests: &RequestSender) -> SyncResult<Vec<SyncEvent>>;

    /// Handle a network event (peer connection changes).
    ///
    /// Default implementation handles state transitions for WaitingForConnections.
    /// Managers can override to customize behavior.
    async fn handle_network_event(
        &mut self,
        event: &NetworkEvent,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        // Default: transition from WaitingForConnections to Syncing when peers connect
        if let NetworkEvent::PeersUpdated {
            connected_count,
            best_height,
            ..
        } = event
        {
            if let Some(best_height) = best_height {
                self.update_target_height(*best_height);
            }
            if *connected_count == 0 {
                tracing::info!("{} - no peers available, stopping sync", self.identifier());
                self.stop_sync();
            } else if *connected_count > 0 && self.state() == SyncState::WaitingForConnections {
                tracing::info!(
                    "{} - peers available ({}), starting sync",
                    self.identifier(),
                    connected_count
                );
                return self.start_sync(requests).await;
            }
        }
        Ok(vec![])
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

    /// Reset to `WaitingForConnections`, report progress, and emit a `ManagerError` event.
    ///
    /// This bundles the state reset and error reporting into one call so that
    /// `set_state` is always invoked before the progress snapshot — eliminating
    /// the ordering bug where callers could forget to reset state first.
    fn recover_from_network_error(
        &mut self,
        context: &SyncManagerTaskContext,
        source: &str,
        msg: &str,
    ) {
        self.set_state(SyncState::WaitingForConnections);
        let progress = self.progress();
        let identifier = self.identifier();
        tracing::warn!("{} {} network error, resetting to WaitingForConnections: {}", identifier, source, msg);
        context.progress_sender.send(progress).ok();
        context.emit_sync_event(SyncEvent::ManagerError {
            manager: identifier,
            error: format!("Network error ({}): {}", source, msg),
        });
    }

    /// Run the manager task, processing messages, events, and periodic ticks.
    ///
    /// This consumes the manager and runs until shutdown is signaled.
    /// The `initial_peer_count` parameter indicates how many peers are connected at start.
    async fn run(mut self, mut context: SyncManagerTaskContext) -> SyncResult<ManagerIdentifier>
    where
        Self: Sized,
    {
        let identifier = self.identifier();
        tracing::info!("{} task starting", identifier);

        let mut sync_event_receiver = context.sync_event_sender.subscribe();

        // Initialize the manager
        self.initialize().await?;

        // Tick interval for periodic housekeeping
        let mut tick_interval = interval(Duration::from_millis(100));

        // Cooldown after a network-error recovery to avoid log/event flooding.
        // While active, the periodic tick branch is skipped (message and event
        // branches are externally driven and don't need throttling).
        let mut network_error_cooldown: Option<tokio::time::Instant> = None;

        tracing::info!("{} task entering main loop", identifier);

        loop {
            tokio::select! {
                _ = context.shutdown.cancelled() => {
                    tracing::info!("{} task received shutdown signal", identifier);
                    break;
                }
                // Process incoming network messages
                Some(message) = context.message_receiver.recv() => {
                    tracing::trace!("{} received message: {}", identifier, message.cmd());
                    let progress_before = self.progress();
                    match self.handle_message(message, &context.requests).await {
                        Ok(events) => {
                            if !events.is_empty() {
                                for event in &events {
                                    tracing::debug!("{} emitting: {}", identifier, event.description());
                                }
                                context.emit_sync_events(events);
                            }
                            self.try_emit_progress(progress_before, &context.progress_sender);
                        }
                        Err(SyncError::Network(ref msg)) => {
                            self.recover_from_network_error(&context, "message handler", msg);
                            network_error_cooldown = Some(tokio::time::Instant::now());
                            continue;
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
                            tracing::trace!("{} received event: {}", identifier, event.description());
                            let progress_before = self.progress();
                            match self.handle_sync_event(&event, &context.requests).await {
                                Ok(events) => {
                                    if !events.is_empty() {
                                        for e in &events {
                                            tracing::trace!("{} emitting: {}", identifier, e.description());
                                        }
                                        context.emit_sync_events(events);
                                    }
                                    self.try_emit_progress(progress_before, &context.progress_sender);
                                }
                                Err(SyncError::Network(ref msg)) => {
                                    self.recover_from_network_error(&context, "sync event handler", msg);
                                    network_error_cooldown = Some(tokio::time::Instant::now());
                                    continue;
                                }
                                Err(e) => {
                                    tracing::error!("{} error handling event: {}", identifier, e);
                                }
                            }
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
                            tracing::debug!("{} received network event: {}", identifier, event.description());
                            let progress_before = self.progress();
                            match self.handle_network_event(&event, &context.requests).await {
                                Ok(events) => {
                                    if !events.is_empty() {
                                        for e in &events {
                                            tracing::debug!("{} emitting: {}", identifier, e.description());
                                        }
                                        context.emit_sync_events(events);
                                    }
                                    self.try_emit_progress(progress_before, &context.progress_sender);
                                }
                                Err(SyncError::Network(ref msg)) => {
                                    self.recover_from_network_error(&context, "network event handler", msg);
                                    network_error_cooldown = Some(tokio::time::Instant::now());
                                    continue;
                                }
                                Err(e) => {
                                    tracing::error!("{} error handling network event: {}", identifier, e);
                                }
                            }
                        }
                        Err(error) => {
                            tracing::error!("{} network event error: {}", identifier, error);
                            break;
                        }
                    }
                }
                // Periodic tick for timeouts and housekeeping
                _ = tick_interval.tick() => {
                    // Skip tick processing while inside the network-error cooldown
                    // window. Message and event branches are externally driven and
                    // don't need this guard.
                    if let Some(since) = network_error_cooldown {
                        if since.elapsed() < Duration::from_secs(2) {
                            continue;
                        }
                        network_error_cooldown = None;
                    }

                    let progress_before = self.progress();
                    match self.tick(&context.requests).await {
                        Ok(events) => {
                            if !events.is_empty() {
                                context.emit_sync_events(events);
                            }
                            self.try_emit_progress(progress_before, &context.progress_sender);
                        }
                        Err(SyncError::Network(ref msg)) => {
                            self.recover_from_network_error(&context, "tick", msg);
                            network_error_cooldown = Some(tokio::time::Instant::now());
                            continue;
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
    use crate::network::NetworkRequest;
    use crate::sync::BlockHeadersProgress;
    use crate::sync::SyncState;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio::sync::{broadcast, mpsc};

    /// Mock manager for testing the task runner.
    struct MockManager {
        identifier: ManagerIdentifier,
        state: SyncState,
        message_count: Arc<AtomicU32>,
        event_count: Arc<AtomicU32>,
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
        fn progress(&self) -> SyncManagerProgress {
            let mut progress = BlockHeadersProgress::default();
            progress.set_state(self.state);
            SyncManagerProgress::BlockHeaders(progress)
        }

        async fn handle_message(
            &mut self,
            _msg: Message,
            _requests: &RequestSender,
        ) -> SyncResult<Vec<SyncEvent>> {
            self.message_count.fetch_add(1, Ordering::Relaxed);
            Ok(vec![])
        }

        async fn handle_sync_event(
            &mut self,
            _event: &SyncEvent,
            _requests: &RequestSender,
        ) -> SyncResult<Vec<SyncEvent>> {
            self.event_count.fetch_add(1, Ordering::Relaxed);
            Ok(vec![])
        }

        async fn tick(&mut self, _requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
            self.tick_count.fetch_add(1, Ordering::Relaxed);
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn test_manager_task_shutdown() {
        let message_count = Arc::new(AtomicU32::new(0));
        let event_count = Arc::new(AtomicU32::new(0));
        let tick_count = Arc::new(AtomicU32::new(0));

        let manager = MockManager {
            identifier: ManagerIdentifier::BlockHeader,
            state: SyncState::Initializing,
            message_count: message_count.clone(),
            event_count: event_count.clone(),
            tick_count: tick_count.clone(),
        };

        // Create channels
        let (_, message_receiver) = mpsc::unbounded_channel();
        let sync_event_sender = broadcast::Sender::<SyncEvent>::new(100);
        let network_event_sender = broadcast::Sender::<NetworkEvent>::new(100);
        let (req_tx, _req_rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(req_tx);
        let shutdown = CancellationToken::new();
        let (progress_sender, _progress_rx) = watch::channel(manager.progress());

        let context = SyncManagerTaskContext {
            message_receiver,
            sync_event_sender,
            network_event_receiver: network_event_sender.subscribe(),
            requests,
            shutdown: shutdown.clone(),
            progress_sender,
        };

        // Spawn the task using trait's run method
        let handle = tokio::spawn(async move { manager.run(context).await });

        // Let it run for a bit
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Signal shutdown
        shutdown.cancel();

        // Wait for task to complete
        let result = handle.await.unwrap();
        assert!(result.is_ok());

        // Verify the returned identifier matches
        assert_eq!(result.unwrap(), ManagerIdentifier::BlockHeader);

        // Verify tick was called multiple times
        assert!(tick_count.load(Ordering::Relaxed) > 0);
    }

    /// Mock manager whose tick() returns SyncError::Network after a threshold.
    struct NetworkErrorManager {
        identifier: ManagerIdentifier,
        state: SyncState,
        tick_count: Arc<AtomicU32>,
        error_after: u32,
    }

    impl std::fmt::Debug for NetworkErrorManager {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("NetworkErrorManager").field("identifier", &self.identifier).finish()
        }
    }

    #[async_trait]
    impl SyncManager for NetworkErrorManager {
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
        fn progress(&self) -> SyncManagerProgress {
            let mut progress = BlockHeadersProgress::default();
            progress.set_state(self.state);
            SyncManagerProgress::BlockHeaders(progress)
        }

        async fn handle_message(
            &mut self,
            _msg: Message,
            _requests: &RequestSender,
        ) -> SyncResult<Vec<SyncEvent>> {
            Ok(vec![])
        }

        async fn handle_sync_event(
            &mut self,
            _event: &SyncEvent,
            _requests: &RequestSender,
        ) -> SyncResult<Vec<SyncEvent>> {
            Ok(vec![])
        }

        async fn tick(&mut self, _requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
            let count = self.tick_count.fetch_add(1, Ordering::Relaxed);
            if count >= self.error_after {
                Err(SyncError::Network("channel closed".into()))
            } else {
                Ok(vec![])
            }
        }
    }

    /// Given a manager whose tick() returns SyncError::Network after a few calls,
    /// When the task loop processes the error,
    /// Then it resets to WaitingForConnections and keeps running.
    #[tokio::test]
    async fn test_manager_resets_on_fatal_network_error() {
        let tick_count = Arc::new(AtomicU32::new(0));

        let manager = NetworkErrorManager {
            identifier: ManagerIdentifier::BlockHeader,
            state: SyncState::Initializing,
            tick_count: tick_count.clone(),
            error_after: 3,
        };

        // Create channels
        let (_, message_receiver) = mpsc::unbounded_channel();
        let sync_event_sender = broadcast::Sender::<SyncEvent>::new(100);
        let network_event_sender = broadcast::Sender::<NetworkEvent>::new(100);
        let (req_tx, _req_rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(req_tx);
        let shutdown = CancellationToken::new();
        let (progress_sender, progress_rx) = watch::channel(manager.progress());

        let context = SyncManagerTaskContext {
            message_receiver,
            sync_event_sender: sync_event_sender.clone(),
            network_event_receiver: network_event_sender.subscribe(),
            requests,
            shutdown: shutdown.clone(),
            progress_sender,
        };

        // Subscribe to sync events to verify ManagerError is emitted
        let mut event_rx = sync_event_sender.subscribe();

        // Spawn the task — it should keep running after the Network error
        let handle = tokio::spawn(async move { manager.run(context).await });

        // Wait long enough for the error to fire (tick 3 at ~300ms) plus the
        // 2-second cooldown, plus a few more ticks after cooldown expires.
        tokio::time::sleep(Duration::from_millis(2800)).await;

        // Verify progress state is WaitingForConnections (not Error)
        assert_eq!(progress_rx.borrow().state(), SyncState::WaitingForConnections);

        // Verify tick was called more than the error threshold (manager kept
        // running after the Network error and cooldown expired).
        assert!(tick_count.load(Ordering::Relaxed) > 4,
            "manager should keep ticking after Network error and cooldown");

        // Verify ManagerError event was emitted
        let mut found_error = false;
        while let Ok(event) = event_rx.try_recv() {
            if matches!(event, SyncEvent::ManagerError { .. }) {
                found_error = true;
                break;
            }
        }
        assert!(found_error, "ManagerError event should have been emitted");

        // Shut down the manager via the shutdown token
        shutdown.cancel();

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task should exit after shutdown signal")
            .unwrap();

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ManagerIdentifier::BlockHeader);
    }
}
