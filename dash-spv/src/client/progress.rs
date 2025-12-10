//! Progress tracking and reporting.
//!
//! This module contains:
//! - Sync progress calculation
//! - Phase-to-stage mapping
//! - Statistics gathering

use crate::error::Result;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::SyncProgress;
use crate::types::SpvStats;
use key_wallet_manager::wallet_interface::WalletInterface;

use super::DashSpvClient;

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    /// Get current sync progress.
    pub fn sync_progress(&self) -> SyncProgress {
        self.sync_coordinator.progress().clone()
    }

    /// Get current statistics.
    pub async fn stats(&self) -> Result<SpvStats> {
        let display = self.create_status_display().await;
        let mut stats = display.stats().await?;

        // Add real-time peer count and heights
        stats.connected_peers = self.network.peer_count() as u32;
        stats.total_peers = self.network.peer_count() as u32; // TODO: Track total discovered peers

        // Get current heights from storage
        {
            let storage = self.storage.lock().await;
            if let Some(header_height) = storage.get_tip_height().await {
                stats.header_height = header_height;
            }

            if let Ok(Some(filter_height)) = storage.get_filter_tip_height().await {
                stats.filter_height = filter_height;
            }
        }

        tracing::debug!(
            "get_stats: header_height={}, filter_height={}, peers={}",
            stats.header_height,
            stats.filter_height,
            stats.connected_peers
        );

        Ok(stats)
    }
}
