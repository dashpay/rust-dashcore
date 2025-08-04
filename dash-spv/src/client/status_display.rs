//! Status display and progress reporting for the Dash SPV client.

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::client::ClientConfig;
use crate::error::Result;
use crate::storage::StorageManager;
use crate::terminal::TerminalUI;
use crate::types::{ChainState, SpvStats, SyncProgress};

/// Status display manager for updating UI and reporting sync progress.
pub struct StatusDisplay<'a> {
    state: &'a Arc<RwLock<ChainState>>,
    stats: &'a Arc<RwLock<SpvStats>>,
    storage: &'a dyn StorageManager,
    terminal_ui: &'a Option<Arc<TerminalUI>>,
    config: &'a ClientConfig,
}

impl<'a> StatusDisplay<'a> {
    /// Create a new status display manager.
    pub fn new(
        state: &'a Arc<RwLock<ChainState>>,
        stats: &'a Arc<RwLock<SpvStats>>,
        storage: &'a dyn StorageManager,
        terminal_ui: &'a Option<Arc<TerminalUI>>,
        config: &'a ClientConfig,
    ) -> Self {
        Self {
            state,
            stats,
            storage,
            terminal_ui,
            config,
        }
    }

    /// Calculate the header height based on the current state and storage.
    /// This handles both checkpoint sync and normal sync scenarios.
    async fn calculate_header_height_with_logging(
        &self,
        state: &ChainState,
        with_logging: bool,
    ) -> u32 {
        if state.synced_from_checkpoint && state.sync_base_height > 0 {
            // Get the actual number of headers in storage
            if let Ok(Some(storage_tip)) = self.storage.get_tip_height().await {
                // The blockchain height is sync_base_height + storage_tip
                let blockchain_height = state.sync_base_height + storage_tip;
                if with_logging {
                    tracing::debug!(
                        "Status display (checkpoint sync): storage_tip={}, sync_base={}, blockchain_height={}",
                        storage_tip, state.sync_base_height, blockchain_height
                    );
                }
                blockchain_height
            } else {
                // No headers in storage yet, use the checkpoint height
                state.sync_base_height
            }
        } else {
            // Normal sync from genesis
            // Check if headers are in storage but not loaded into memory yet
            if state.headers.is_empty() {
                // Headers might be in storage but not loaded into ChainState yet
                if let Ok(Some(storage_tip)) = self.storage.get_tip_height().await {
                    if with_logging {
                        tracing::debug!(
                            "Status display (normal sync): ChainState empty but storage has {} headers",
                            storage_tip
                        );
                    }
                    storage_tip
                } else {
                    // No headers in storage or ChainState
                    0
                }
            } else {
                // Headers are loaded in ChainState, use tip_height()
                let tip = state.tip_height();
                if with_logging {
                    tracing::debug!(
                        "Status display (normal sync): chain state has {} headers, tip_height={}",
                        state.headers.len(),
                        tip
                    );
                }
                tip
            }
        }
    }

    /// Calculate the header height based on the current state and storage.
    /// This handles both checkpoint sync and normal sync scenarios.
    async fn calculate_header_height(&self, state: &ChainState) -> u32 {
        self.calculate_header_height_with_logging(state, false).await
    }

    /// Get current sync progress.
    pub async fn sync_progress(&self) -> Result<SyncProgress> {
        let state = self.state.read().await;
        let stats = self.stats.read().await;

        // Calculate last synced filter height from received filter heights
        let last_synced_filter_height = if let Ok(heights) = stats.received_filter_heights.lock() {
            heights.iter().max().copied()
        } else {
            None
        };

        // Calculate the actual header height considering checkpoint sync
        let header_height = self.calculate_header_height(&state).await;

        // Calculate filter header height considering checkpoint sync
        let filter_header_height = self.calculate_filter_header_height(&state).await;

        Ok(SyncProgress {
            header_height,
            filter_header_height,
            masternode_height: state.last_masternode_diff_height.unwrap_or(0),
            peer_count: 1,                // TODO: Get from network manager
            headers_synced: false,        // TODO: Implement
            filter_headers_synced: false, // TODO: Implement
            masternodes_synced: false,    // TODO: Implement
            filter_sync_available: false, // TODO: Get from network manager
            filters_downloaded: stats.filters_received,
            last_synced_filter_height,
            sync_start: std::time::SystemTime::now(), // TODO: Track properly
            last_update: std::time::SystemTime::now(),
        })
    }

    /// Get current statistics.
    pub async fn stats(&self) -> Result<SpvStats> {
        let stats = self.stats.read().await;
        Ok(stats.clone())
    }

    /// Get current chain state (read-only).
    pub async fn chain_state(&self) -> ChainState {
        let state = self.state.read().await;
        state.clone()
    }

    /// Update the status display.
    pub async fn update_status_display(&self) {
        if let Some(ui) = self.terminal_ui {
            // Get header height - when syncing from checkpoint, use the actual blockchain height
            let header_height = {
                let state = self.state.read().await;
                self.calculate_header_height_with_logging(&state, true).await
            };

            // Get filter header height - convert from storage height to blockchain height
            let filter_height = {
                let state = self.state.read().await;
                self.calculate_filter_header_height(&state).await
            };

            // Get latest chainlock height from state
            let chainlock_height = {
                let state = self.state.read().await;
                state.last_chainlock_height
            };

            // Get latest chainlock height from storage metadata (in case state wasn't updated)
            let stored_chainlock_height = if let Ok(Some(data)) =
                self.storage.load_metadata("latest_chainlock_height").await
            {
                if data.len() >= 4 {
                    Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
                } else {
                    None
                }
            } else {
                None
            };

            // Use the higher of the two chainlock heights
            let latest_chainlock = match (chainlock_height, stored_chainlock_height) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };

            // Update terminal UI
            let _ = ui
                .update_status(|status| {
                    status.headers = header_height;
                    status.filter_headers = filter_height;
                    status.chainlock_height = latest_chainlock;
                    status.peer_count = 1; // TODO: Get actual peer count
                    status.network = format!("{:?}", self.config.network);
                })
                .await;
        } else {
            // Fall back to simple logging if terminal UI is not enabled
            // Get header height - when syncing from checkpoint, use the actual blockchain height
            let header_height = {
                let state = self.state.read().await;
                self.calculate_header_height_with_logging(&state, true).await
            };

            // Get filter header height - convert from storage height to blockchain height
            let filter_height = {
                let state = self.state.read().await;
                self.calculate_filter_header_height(&state).await
            };

            let chainlock_height = {
                let state = self.state.read().await;
                state.last_chainlock_height.unwrap_or(0)
            };

            // Get filter and block processing statistics
            let stats = self.stats.read().await;
            let filters_matched = stats.filters_matched;
            let blocks_with_relevant_transactions = stats.blocks_with_relevant_transactions;
            let blocks_processed = stats.blocks_processed;
            drop(stats);

            tracing::info!(
                "📊 [SYNC STATUS] Headers: {} | Filter Headers: {} | Latest ChainLock: {} | Filters Matched: {} | Blocks w/ Relevant Txs: {} | Blocks Processed: {}",
                header_height,
                filter_height,
                if chainlock_height > 0 {
                    format!("#{}", chainlock_height)
                } else {
                    "None".to_string()
                },
                filters_matched,
                blocks_with_relevant_transactions,
                blocks_processed
            );
        }
    }

    /// Calculate the filter header height considering checkpoint sync.
    ///
    /// This helper method encapsulates the logic for determining the current filter header height,
    /// taking into account whether we're syncing from a checkpoint or from genesis.
    async fn calculate_filter_header_height(&self, state: &ChainState) -> u32 {
        if state.synced_from_checkpoint && state.sync_base_height > 0 {
            // Get the actual number of filter headers in storage
            if let Ok(Some(storage_height)) = self.storage.get_filter_tip_height().await {
                // The blockchain height is sync_base_height + storage_height
                state.sync_base_height + storage_height
            } else {
                // No filter headers in storage yet, use the checkpoint height
                state.sync_base_height
            }
        } else {
            // Normal sync from genesis
            // Check if filter headers are in storage but not loaded into memory yet
            if state.filter_headers.is_empty() {
                // Filter headers might be in storage but not loaded into ChainState yet
                if let Ok(Some(storage_height)) = self.storage.get_filter_tip_height().await {
                    storage_height
                } else {
                    // No filter headers in storage or ChainState
                    0
                }
            } else {
                // Filter headers are loaded in ChainState
                state.filter_headers.len().saturating_sub(1) as u32
            }
        }
    }
}
