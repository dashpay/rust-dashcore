//! Event handling and emission.
//!
//! This module contains:
//! - Event receiver management
//! - Event emission

use tokio::sync::watch;

use crate::network::{NetworkEvent, NetworkManager};
use crate::storage::StorageManager;
use crate::sync::{SyncEvent, SyncProgress};
use key_wallet::manager::WalletInterface;
use tokio::sync::broadcast;

use super::{DashSpvClient, EventHandler};

impl<W: WalletInterface, N: NetworkManager, S: StorageManager, H: EventHandler>
    DashSpvClient<W, N, S, H>
{
    /// Subscribe to sync progress updates via watch channel.
    pub(crate) async fn subscribe_progress(&self) -> watch::Receiver<SyncProgress> {
        self.sync_coordinator.lock().await.subscribe_progress()
    }

    /// Get current sync progress.
    pub async fn progress(&self) -> SyncProgress {
        self.sync_coordinator.lock().await.progress()
    }

    /// Subscribe to sync events from the sync coordinator.
    pub(crate) async fn subscribe_sync_events(&self) -> broadcast::Receiver<SyncEvent> {
        self.sync_coordinator.lock().await.subscribe_events()
    }

    /// Subscribe to network events.
    pub(crate) async fn subscribe_network_events(&self) -> broadcast::Receiver<NetworkEvent> {
        self.network.lock().await.subscribe_network_events()
    }
}
