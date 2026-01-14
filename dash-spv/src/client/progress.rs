//! Progress tracking and reporting.
//!
//! This module contains:
//! - Sync progress calculation
//! - Phase-to-stage mapping
//! - Statistics gathering

use crate::error::Result;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::legacy::SyncPhase;
use crate::types::{SpvStats, SyncProgress, SyncStage};
use key_wallet_manager::wallet_interface::WalletInterface;

use super::DashSpvClient;

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    /// Get current sync progress.
    pub async fn sync_progress(&self) -> Result<SyncProgress> {
        let display = self.create_status_display().await;
        display.sync_progress().await
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

    /// Map a sync phase to a sync stage for progress reporting.
    pub(super) fn map_phase_to_stage(
        phase: &SyncPhase,
        sync_progress: &SyncProgress,
        peer_best_height: u32,
    ) -> SyncStage {
        match phase {
            SyncPhase::Idle => {
                if sync_progress.peer_count == 0 {
                    SyncStage::Connecting
                } else {
                    SyncStage::QueryingPeerHeight
                }
            }
            SyncPhase::DownloadingHeaders {
                start_height,
                target_height,
                ..
            } => SyncStage::DownloadingHeaders {
                start: *start_height,
                end: target_height.unwrap_or(peer_best_height),
            },
            SyncPhase::DownloadingMnList {
                diffs_processed,
                ..
            } => SyncStage::ValidatingHeaders {
                batch_size: *diffs_processed as usize,
            },
            SyncPhase::DownloadingCFHeaders {
                current_height,
                target_height,
                ..
            } => SyncStage::DownloadingFilterHeaders {
                current: *current_height,
                target: *target_height,
            },
            SyncPhase::DownloadingFilters {
                completed_heights,
                total_filters,
                ..
            } => SyncStage::DownloadingFilters {
                completed: completed_heights.len() as u32,
                total: *total_filters,
            },
            SyncPhase::DownloadingBlocks {
                pending_blocks,
                ..
            } => SyncStage::DownloadingBlocks {
                pending: pending_blocks.len(),
            },
            SyncPhase::FullySynced {
                ..
            } => SyncStage::Complete,
        }
    }
}
