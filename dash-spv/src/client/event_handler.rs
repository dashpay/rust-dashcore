//! Event handler trait for receiving SPV client events.
//!
//! Provides `EventHandler`, a trait with default no-op implementations that
//! consumers override to receive push-based event notifications. The monitoring
//! infrastructure subscribes to internal channels and dispatches to the handler.

use std::fmt::Display;
use std::sync::Arc;

use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::network::NetworkEvent;
use crate::sync::{SyncEvent, SyncProgress};
use key_wallet_manager::WalletEvent;

/// Trait for receiving SPV client events.
///
/// All methods have default no-op implementations, so consumers only
/// need to override the events they care about.
pub trait EventHandler: Send + Sync + 'static {
    /// Called for sync lifecycle events (headers stored, sync complete, etc.).
    fn on_sync_event(&self, _event: &SyncEvent) {}
    /// Called when peer connections change (connect, disconnect, peer list update).
    fn on_network_event(&self, _event: &NetworkEvent) {}
    /// Called when overall sync progress changes.
    fn on_progress(&self, _progress: &SyncProgress) {}
    /// Called for wallet events (transaction received, balance updated).
    fn on_wallet_event(&self, _event: &WalletEvent) {}
    /// Called on fatal errors (start failure, monitor channel failure, sync loop error).
    fn on_error(&self, _error: &str) {}
}

/// No-op implementation for consumers that don't need event notifications.
impl EventHandler for () {}

/// Spawns a task that monitors a broadcast channel and dispatches events to the handler.
///
/// Every received event is mirrored into `tracing::info!` as `"<name>: <event>"`
/// before consumer handlers run, so installing a tracing subscriber is enough to
/// get event log output. To silence event logs without affecting other
/// subscribers, set a per-target filter such as
/// `dash_spv::client::event_handler=warn`.
///
/// On failure, the error message is sent via `on_failure` so the coordinator can report
/// it as the single source of error handling.
pub(crate) fn spawn_broadcast_monitor<E, F>(
    name: &'static str,
    mut receiver: broadcast::Receiver<E>,
    handlers: Arc<Vec<Arc<dyn EventHandler>>>,
    shutdown: CancellationToken,
    on_failure: mpsc::Sender<String>,
    dispatch_fn: F,
) -> JoinHandle<()>
where
    E: Clone + Display + Send + 'static,
    F: Fn(&dyn EventHandler, &E) + Send + 'static,
{
    tokio::spawn(async move {
        tracing::debug!("{} monitoring task started", name);
        loop {
            tokio::select! {
                result = receiver.recv() => {
                    match result {
                        Ok(event) => {
                            tracing::info!("{}: {}", name, event);
                            for handler in handlers.iter() {
                                dispatch_fn(handler.as_ref(), &event);
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) if shutdown.is_cancelled() => break,
                        Err(broadcast::error::RecvError::Closed) => {
                            let msg = format!("{} monitor channel closed unexpectedly", name);
                            tracing::error!("{}", msg);
                            let _ = on_failure.try_send(msg);
                            break;
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) if shutdown.is_cancelled() => break,
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            let msg = format!("{} monitor lagged, missed {} events", name, n);
                            tracing::error!("{}", msg);
                            let _ = on_failure.try_send(msg);
                            break;
                        }
                    }
                }
                _ = shutdown.cancelled() => break,
            }
        }
        tracing::debug!("{} monitoring task exiting", name);
    })
}

/// Spawns a task that monitors a watch channel for progress updates.
///
/// Sends the initial progress value, then monitors for changes. Every value is
/// mirrored into `tracing::info!` before consumer handlers run, matching
/// `spawn_broadcast_monitor`'s behavior.
pub(crate) fn spawn_progress_monitor(
    mut receiver: watch::Receiver<SyncProgress>,
    handlers: Arc<Vec<Arc<dyn EventHandler>>>,
    shutdown: CancellationToken,
    on_failure: mpsc::Sender<String>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        tracing::debug!("Progress monitoring task started");

        {
            let guard = receiver.borrow_and_update();
            let progress: &SyncProgress = &guard;
            tracing::info!("SyncProgress: {}", progress);
            for handler in handlers.iter() {
                handler.on_progress(progress);
            }
        }

        loop {
            tokio::select! {
                result = receiver.changed() => {
                    match result {
                        Ok(()) => {
                            let guard = receiver.borrow_and_update();
                            let progress: &SyncProgress = &guard;
                            tracing::info!("SyncProgress: {}", progress);
                            for handler in handlers.iter() {
                                handler.on_progress(progress);
                            }
                        }
                        Err(_) if shutdown.is_cancelled() => break,
                        Err(_) => {
                            let msg = "Progress monitor channel closed unexpectedly".to_string();
                            tracing::error!("{}", msg);
                            let _ = on_failure.try_send(msg);
                            break;
                        }
                    }
                }
                _ = shutdown.cancelled() => break,
            }
        }
        tracing::debug!("Progress monitoring task exiting");
    })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use tokio::sync::{broadcast, mpsc, watch};
    use tokio_util::sync::CancellationToken;

    use super::{spawn_broadcast_monitor, spawn_progress_monitor, EventHandler};
    use crate::network::NetworkEvent;
    use crate::sync::{ManagerIdentifier, SyncEvent, SyncProgress};
    use key_wallet_manager::WalletEvent;

    struct RecordingHandler {
        sync_count: AtomicUsize,
        network_count: AtomicUsize,
        progress_count: AtomicUsize,
        wallet_count: AtomicUsize,
        error_count: AtomicUsize,
    }

    impl RecordingHandler {
        fn new() -> Self {
            Self {
                sync_count: AtomicUsize::new(0),
                network_count: AtomicUsize::new(0),
                progress_count: AtomicUsize::new(0),
                wallet_count: AtomicUsize::new(0),
                error_count: AtomicUsize::new(0),
            }
        }
    }

    impl EventHandler for RecordingHandler {
        fn on_sync_event(&self, _event: &SyncEvent) {
            self.sync_count.fetch_add(1, Ordering::SeqCst);
        }
        fn on_network_event(&self, _event: &NetworkEvent) {
            self.network_count.fetch_add(1, Ordering::SeqCst);
        }
        fn on_progress(&self, _progress: &SyncProgress) {
            self.progress_count.fetch_add(1, Ordering::SeqCst);
        }
        fn on_wallet_event(&self, _event: &WalletEvent) {
            self.wallet_count.fetch_add(1, Ordering::SeqCst);
        }
        fn on_error(&self, _error: &str) {
            self.error_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn handlers(
        entries: impl IntoIterator<Item = Arc<dyn EventHandler>>,
    ) -> Arc<Vec<Arc<dyn EventHandler>>> {
        Arc::new(entries.into_iter().collect())
    }

    #[tokio::test]
    async fn noop_handler_does_not_panic() {
        let handler: () = ();
        let event = SyncEvent::BlockHeadersStored {
            tip_height: 100,
        };
        handler.on_sync_event(&event);
        handler.on_network_event(&NetworkEvent::PeersUpdated {
            connected_count: 0,
            addresses: vec![],
            best_height: None,
        });
        handler.on_progress(&SyncProgress::default());
        handler.on_error("test error");
    }

    #[tokio::test]
    async fn broadcast_monitor_dispatches_events() {
        let (tx, rx) = broadcast::channel(16);
        let handler = Arc::new(RecordingHandler::new());
        let shutdown = CancellationToken::new();
        let (failure_tx, _failure_rx) = mpsc::channel(1);

        let task = spawn_broadcast_monitor(
            "test",
            rx,
            handlers([handler.clone() as Arc<dyn EventHandler>]),
            shutdown.clone(),
            failure_tx,
            |h, event: &SyncEvent| h.on_sync_event(event),
        );

        tx.send(SyncEvent::BlockHeadersStored {
            tip_height: 1,
        })
        .unwrap();
        tx.send(SyncEvent::BlockHeadersStored {
            tip_height: 2,
        })
        .unwrap();
        tx.send(SyncEvent::SyncStart {
            identifier: ManagerIdentifier::BlockHeader,
        })
        .unwrap();

        // Give the task time to process
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        shutdown.cancel();
        task.await.unwrap();

        assert_eq!(handler.sync_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn broadcast_monitor_exits_on_shutdown() {
        let (_tx, rx) = broadcast::channel::<SyncEvent>(16);
        let handler = Arc::new(RecordingHandler::new());
        let shutdown = CancellationToken::new();
        let (failure_tx, _failure_rx) = mpsc::channel(1);

        let task = spawn_broadcast_monitor(
            "test",
            rx,
            handlers([handler.clone() as Arc<dyn EventHandler>]),
            shutdown.clone(),
            failure_tx,
            |h, event: &SyncEvent| h.on_sync_event(event),
        );

        shutdown.cancel();
        task.await.unwrap();

        assert_eq!(handler.sync_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn broadcast_monitor_fails_on_unexpected_channel_close() {
        let (tx, rx) = broadcast::channel::<SyncEvent>(16);
        let handler = Arc::new(RecordingHandler::new());
        let shutdown = CancellationToken::new();
        let (failure_tx, mut failure_rx) = mpsc::channel(1);

        let task = spawn_broadcast_monitor(
            "test",
            rx,
            handlers([handler.clone() as Arc<dyn EventHandler>]),
            shutdown.clone(),
            failure_tx,
            |h, event: &SyncEvent| h.on_sync_event(event),
        );

        // Drop sender without cancelling shutdown — this is unexpected
        drop(tx);
        task.await.unwrap();

        let msg = failure_rx.try_recv().expect("should have received failure message");
        assert!(msg.contains("closed unexpectedly"));
        assert_eq!(handler.error_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn broadcast_monitor_exits_on_lagged_receiver() {
        let (tx, rx) = broadcast::channel(2);
        let handler = Arc::new(RecordingHandler::new());
        let shutdown = CancellationToken::new();
        let (failure_tx, mut failure_rx) = mpsc::channel(1);

        // Send more messages than the buffer can hold before spawning the monitor
        tx.send(SyncEvent::BlockHeadersStored {
            tip_height: 1,
        })
        .unwrap();
        tx.send(SyncEvent::BlockHeadersStored {
            tip_height: 2,
        })
        .unwrap();
        tx.send(SyncEvent::BlockHeadersStored {
            tip_height: 3,
        })
        .unwrap();

        let task = spawn_broadcast_monitor(
            "test",
            rx,
            handlers([handler.clone() as Arc<dyn EventHandler>]),
            shutdown.clone(),
            failure_tx,
            |h, event: &SyncEvent| h.on_sync_event(event),
        );

        // The monitor should exit on its own due to the lagged error
        task.await.unwrap();

        // No sync events should have been dispatched, failure sent via channel
        assert_eq!(handler.sync_count.load(Ordering::SeqCst), 0);
        assert_eq!(handler.error_count.load(Ordering::SeqCst), 0);
        let msg = failure_rx.try_recv().expect("should have received failure message");
        assert!(msg.contains("lagged"));
    }

    #[tokio::test]
    async fn progress_monitor_sends_initial_and_updates() {
        let (tx, rx) = watch::channel(SyncProgress::default());
        let handler = Arc::new(RecordingHandler::new());
        let shutdown = CancellationToken::new();
        let (failure_tx, _failure_rx) = mpsc::channel(1);

        let task = spawn_progress_monitor(
            rx,
            handlers([handler.clone() as Arc<dyn EventHandler>]),
            shutdown.clone(),
            failure_tx,
        );

        // Give the task time to send initial progress
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send two updates
        tx.send_modify(|_| {});
        tx.send_modify(|_| {});
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        shutdown.cancel();
        task.await.unwrap();

        // 1 initial + at least 1 update (watch coalesces rapid updates)
        assert!(handler.progress_count.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn progress_monitor_fails_on_unexpected_sender_drop() {
        let (tx, rx) = watch::channel(SyncProgress::default());
        let handler = Arc::new(RecordingHandler::new());
        let shutdown = CancellationToken::new();
        let (failure_tx, mut failure_rx) = mpsc::channel(1);

        let task = spawn_progress_monitor(
            rx,
            handlers([handler.clone() as Arc<dyn EventHandler>]),
            shutdown.clone(),
            failure_tx,
        );

        // Give it time to send initial
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Drop sender without cancelling shutdown — this is unexpected
        drop(tx);
        task.await.unwrap();

        // At least the initial progress was sent, failure sent via channel
        assert!(handler.progress_count.load(Ordering::SeqCst) >= 1);
        assert_eq!(handler.error_count.load(Ordering::SeqCst), 0);
        let msg = failure_rx.try_recv().expect("should have received failure message");
        assert!(msg.contains("closed unexpectedly"));
    }

    #[tokio::test]
    async fn network_event_dispatch() {
        let (tx, rx) = broadcast::channel(16);
        let handler = Arc::new(RecordingHandler::new());
        let shutdown = CancellationToken::new();
        let (failure_tx, _failure_rx) = mpsc::channel(1);

        let task = spawn_broadcast_monitor(
            "network",
            rx,
            handlers([handler.clone() as Arc<dyn EventHandler>]),
            shutdown.clone(),
            failure_tx,
            |h, event: &NetworkEvent| h.on_network_event(event),
        );

        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        tx.send(NetworkEvent::PeerConnected {
            address: addr,
        })
        .unwrap();
        tx.send(NetworkEvent::PeerDisconnected {
            address: addr,
        })
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        shutdown.cancel();
        task.await.unwrap();

        assert_eq!(handler.network_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn broadcast_monitor_dispatches_to_all_handlers() {
        let (tx, rx) = broadcast::channel(16);
        let first = Arc::new(RecordingHandler::new());
        let second = Arc::new(RecordingHandler::new());
        let shutdown = CancellationToken::new();
        let (failure_tx, _failure_rx) = mpsc::channel(1);

        let task = spawn_broadcast_monitor(
            "test",
            rx,
            handlers([
                first.clone() as Arc<dyn EventHandler>,
                second.clone() as Arc<dyn EventHandler>,
            ]),
            shutdown.clone(),
            failure_tx,
            |h, event: &SyncEvent| h.on_sync_event(event),
        );

        tx.send(SyncEvent::BlockHeadersStored {
            tip_height: 1,
        })
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        shutdown.cancel();
        task.await.unwrap();

        assert_eq!(first.sync_count.load(Ordering::SeqCst), 1);
        assert_eq!(second.sync_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn progress_monitor_dispatches_to_all_handlers() {
        let (tx, rx) = watch::channel(SyncProgress::default());
        let first = Arc::new(RecordingHandler::new());
        let second = Arc::new(RecordingHandler::new());
        let shutdown = CancellationToken::new();
        let (failure_tx, _failure_rx) = mpsc::channel(1);

        let task = spawn_progress_monitor(
            rx,
            handlers([
                first.clone() as Arc<dyn EventHandler>,
                second.clone() as Arc<dyn EventHandler>,
            ]),
            shutdown.clone(),
            failure_tx,
        );

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        tx.send_modify(|_| {});
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        shutdown.cancel();
        task.await.unwrap();

        assert!(first.progress_count.load(Ordering::SeqCst) >= 2);
        assert!(second.progress_count.load(Ordering::SeqCst) >= 2);
    }
}
