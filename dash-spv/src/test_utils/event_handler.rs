//! Test event handler that bridges `EventHandler` back to tokio channels.
//!
//! Allows integration tests to use `run()` with an `EventHandler` while keeping
//! the ergonomic `tokio::select!` patterns that channels provide.

use tokio::sync::{broadcast, watch};

use crate::client::EventHandler;
use crate::network::NetworkEvent;
use crate::sync::{SyncEvent, SyncProgress};
use key_wallet::manager::WalletEvent;

/// Event handler that forwards all events to internal channels.
///
/// Tests create this handler, take receivers via the accessor methods,
/// then pass `Arc<TestEventHandler>` to `run()`.
pub struct TestEventHandler {
    sync_tx: broadcast::Sender<SyncEvent>,
    network_tx: broadcast::Sender<NetworkEvent>,
    progress_tx: watch::Sender<SyncProgress>,
    wallet_tx: broadcast::Sender<WalletEvent>,
}

impl TestEventHandler {
    pub fn new() -> Self {
        let (sync_tx, _) = broadcast::channel(256);
        let (network_tx, _) = broadcast::channel(256);
        let (progress_tx, _) = watch::channel(SyncProgress::default());
        let (wallet_tx, _) = broadcast::channel(256);
        Self {
            sync_tx,
            network_tx,
            progress_tx,
            wallet_tx,
        }
    }

    pub fn subscribe_sync_events(&self) -> broadcast::Receiver<SyncEvent> {
        self.sync_tx.subscribe()
    }

    pub fn subscribe_network_events(&self) -> broadcast::Receiver<NetworkEvent> {
        self.network_tx.subscribe()
    }

    pub fn subscribe_progress(&self) -> watch::Receiver<SyncProgress> {
        self.progress_tx.subscribe()
    }

    pub fn subscribe_wallet_events(&self) -> broadcast::Receiver<WalletEvent> {
        self.wallet_tx.subscribe()
    }
}

impl Default for TestEventHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl EventHandler for TestEventHandler {
    fn on_sync_event(&self, event: &SyncEvent) {
        let _ = self.sync_tx.send(event.clone());
    }

    fn on_network_event(&self, event: &NetworkEvent) {
        let _ = self.network_tx.send(event.clone());
    }

    fn on_progress(&self, progress: &SyncProgress) {
        self.progress_tx.send_replace(progress.clone());
    }

    fn on_wallet_event(&self, event: &WalletEvent) {
        let _ = self.wallet_tx.send(event.clone());
    }

    fn on_error(&self, error: &str) {
        tracing::error!("TestEventHandler received error: {}", error);
    }
}
