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
use crate::types::{SyncProgress, SyncStage};
use key_wallet_manager::wallet_interface::WalletInterface;

use super::DashSpvClient;

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    /// Get current sync progress.
    pub async fn sync_progress(&self) -> Result<SyncProgress> {
        let display = self.create_status_display().await;
        display.sync_progress().await
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
