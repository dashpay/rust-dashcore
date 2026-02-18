//! Event handling and emission.
//!
//! This module contains:
//! - Event receiver management
//! - Event emission

use tokio::sync::watch;

use crate::network::{NetworkEvent, NetworkManager};
use crate::storage::StorageManager;
use crate::sync::{SyncEvent, SyncProgress};
use key_wallet_manager::wallet_interface::WalletInterface;
use tokio::sync::broadcast;

use super::DashSpvClient;

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    /// Subscribe to sync progress updates via watch channel.
    pub async fn subscribe_progress(&self) -> watch::Receiver<SyncProgress> {
        self.sync_coordinator.lock().await.subscribe_progress()
    }

    /// Get current sync progress.
    pub async fn progress(&self) -> SyncProgress {
        self.sync_coordinator.lock().await.progress()
    }

    /// Subscribe to sync events from the sync coordinator.
    pub async fn subscribe_sync_events(&self) -> broadcast::Receiver<SyncEvent> {
        self.sync_coordinator.lock().await.subscribe_events()
    }

    /// Subscribe to network events.
    pub async fn subscribe_network_events(&self) -> broadcast::Receiver<NetworkEvent> {
        self.network.lock().await.subscribe_network_events()
    }
}
