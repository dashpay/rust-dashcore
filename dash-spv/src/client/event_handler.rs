//! Event handler trait for receiving SPV client events.
//!
//! Provides `EventHandler`, a trait with default no-op implementations that
//! consumers override to receive push-based event notifications. The monitoring
//! infrastructure subscribes to internal channels and dispatches to the handler.

use std::sync::Arc;

use tokio::sync::{broadcast, watch};
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
pub(crate) fn spawn_broadcast_monitor<E, H, F>(
    name: &'static str,
    mut receiver: broadcast::Receiver<E>,
    handler: Arc<H>,
    shutdown: CancellationToken,
    dispatch_fn: F,
) -> JoinHandle<()>
where
    E: Clone + Send + 'static,
    H: EventHandler,
    F: Fn(&H, &E) + Send + 'static,
{
    tokio::spawn(async move {
        tracing::debug!("{} monitoring task started", name);
        loop {
            tokio::select! {
                result = receiver.recv() => {
                    match result {
                        Ok(event) => dispatch_fn(&handler, &event),
                        Err(broadcast::error::RecvError::Closed) => break,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
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
/// Sends the initial progress value, then monitors for changes.
pub(crate) fn spawn_progress_monitor<H: EventHandler>(
    mut receiver: watch::Receiver<SyncProgress>,
    handler: Arc<H>,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        tracing::debug!("Progress monitoring task started");

        handler.on_progress(&receiver.borrow_and_update());

        loop {
            tokio::select! {
                result = receiver.changed() => {
                    match result {
                        Ok(()) => handler.on_progress(&receiver.borrow_and_update()),
                        Err(_) => break,
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

    use tokio::sync::{broadcast, watch};
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

        let task = spawn_broadcast_monitor(
            "test",
            rx,
            handler.clone(),
            shutdown.clone(),
            |h: &RecordingHandler, event: &SyncEvent| h.on_sync_event(event),
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

        let task = spawn_broadcast_monitor(
            "test",
            rx,
            handler.clone(),
            shutdown.clone(),
            |h: &RecordingHandler, event: &SyncEvent| h.on_sync_event(event),
        );

        shutdown.cancel();
        task.await.unwrap();

        assert_eq!(handler.sync_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn broadcast_monitor_exits_on_channel_close() {
        let (tx, rx) = broadcast::channel::<SyncEvent>(16);
        let handler = Arc::new(RecordingHandler::new());
        let shutdown = CancellationToken::new();

        let task = spawn_broadcast_monitor(
            "test",
            rx,
            handler.clone(),
            shutdown.clone(),
            |h: &RecordingHandler, event: &SyncEvent| h.on_sync_event(event),
        );

        drop(tx);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn broadcast_monitor_handles_lagged_receiver() {
        let (tx, rx) = broadcast::channel(2);
        let handler = Arc::new(RecordingHandler::new());
        let shutdown = CancellationToken::new();

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
            handler.clone(),
            shutdown.clone(),
            |h: &RecordingHandler, event: &SyncEvent| h.on_sync_event(event),
        );

        // Send one more after the monitor starts
        tx.send(SyncEvent::BlockHeadersStored {
            tip_height: 4,
        })
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        shutdown.cancel();
        task.await.unwrap();

        // The monitor should have received at least the last message (and possibly
        // one from the lagged recovery). The key thing is it doesn't crash.
        assert!(handler.sync_count.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn progress_monitor_sends_initial_and_updates() {
        let (tx, rx) = watch::channel(SyncProgress::default());
        let handler = Arc::new(RecordingHandler::new());
        let shutdown = CancellationToken::new();

        let task = spawn_progress_monitor(rx, handler.clone(), shutdown.clone());

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
    async fn progress_monitor_exits_on_sender_drop() {
        let (tx, rx) = watch::channel(SyncProgress::default());
        let handler = Arc::new(RecordingHandler::new());
        let shutdown = CancellationToken::new();

        let task = spawn_progress_monitor(rx, handler.clone(), shutdown.clone());

        // Give it time to send initial
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        drop(tx);
        task.await.unwrap();

        // At least the initial progress was sent
        assert!(handler.progress_count.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn network_event_dispatch() {
        let (tx, rx) = broadcast::channel(16);
        let handler = Arc::new(RecordingHandler::new());
        let shutdown = CancellationToken::new();

        let task = spawn_broadcast_monitor(
            "network",
            rx,
            handler.clone(),
            shutdown.clone(),
            |h: &RecordingHandler, event: &NetworkEvent| h.on_network_event(event),
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
}
