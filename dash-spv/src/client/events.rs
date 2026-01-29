//! Event handling and emission.
//!
//! This module contains:
//! - Event receiver management
//! - Event emission

use tokio::sync::{mpsc, watch};

use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::SyncProgress;
use crate::types::SpvEvent;
use key_wallet_manager::wallet_interface::WalletInterface;

use super::DashSpvClient;

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    /// Take the event receiver for external consumption.
    pub fn take_event_receiver(&mut self) -> Option<mpsc::UnboundedReceiver<SpvEvent>> {
        self.event_rx.take()
    }

    /// Emit an event.
    pub(crate) fn emit_event(&self, event: SpvEvent) {
        tracing::debug!("Emitting event: {:?}", event);
        let _ = self.event_tx.send(event);
    }

    /// Subscribe to sync progress updates via watch channel.
    pub fn subscribe_progress(&self) -> watch::Receiver<SyncProgress> {
        self.sync_coordinator.subscribe_progress()
    }

    /// Get current sync progress.
    pub fn progress(&self) -> SyncProgress {
        self.sync_coordinator.progress()
    }
}
