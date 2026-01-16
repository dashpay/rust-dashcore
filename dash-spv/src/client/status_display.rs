//! Status display and progress reporting for the Dash SPV client.

use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use crate::client::Config;
use crate::error::Result;
use crate::storage::StorageManager;
#[cfg(feature = "terminal-ui")]
use crate::terminal::TerminalUI;
use crate::types::{ChainState, SpvStats, SyncProgress};
use key_wallet_manager::wallet_interface::WalletInterface;

/// Status display manager for updating UI and reporting sync progress.
pub struct StatusDisplay<'a, S: StorageManager, W: WalletInterface> {
    state: &'a Arc<RwLock<ChainState>>,
    stats: &'a Arc<RwLock<SpvStats>>,
    storage: Arc<Mutex<S>>,
    wallet: Option<&'a Arc<RwLock<W>>>,
    #[cfg(feature = "terminal-ui")]
    terminal_ui: &'a Option<Arc<TerminalUI>>,
    #[allow(dead_code)]
    config: &'a Config,
}

impl<'a, S: StorageManager, W: WalletInterface> StatusDisplay<'a, S, W> {
    /// Create a new status display manager.
    #[cfg(feature = "terminal-ui")]
    pub fn new(
        state: &'a Arc<RwLock<ChainState>>,
        stats: &'a Arc<RwLock<SpvStats>>,
        storage: Arc<Mutex<S>>,
        wallet: Option<&'a Arc<RwLock<W>>>,
        terminal_ui: &'a Option<Arc<TerminalUI>>,
        config: &'a Config,
    ) -> Self {
        Self {
            state,
            stats,
            storage,
            wallet,
            terminal_ui,
            config,
        }
    }

    /// Create a new status display manager (without terminal UI support).
    #[cfg(not(feature = "terminal-ui"))]
    pub fn new(
        state: &'a Arc<RwLock<ChainState>>,
        stats: &'a Arc<RwLock<SpvStats>>,
        storage: Arc<Mutex<S>>,
        wallet: Option<&'a Arc<RwLock<W>>>,
        _terminal_ui: &'a Option<()>,
        config: &'a Config,
    ) -> Self {
        Self {
            state,
            stats,
            storage,
            wallet,
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
        // Unified formula for both checkpoint and genesis sync:
        // For genesis sync: sync_base_height = 0, so height = 0 + storage_count
        // For checkpoint sync: height = checkpoint_height + storage_count
        let storage = self.storage.lock().await;
        if let Some(storage_tip) = storage.get_tip_height().await {
            let blockchain_height = storage_tip;
            if with_logging {
                tracing::debug!(
                    "Status display: reported tip height={}, sync_base={}, raw_storage_tip={}",
                    blockchain_height,
                    state.sync_base_height,
                    storage_tip
                );
            }
            blockchain_height
        } else {
            // No headers in storage yet
            state.sync_base_height
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
        // Clone the inner heights handle and copy needed counters without awaiting while holding the RwLock
        let (filters_received, received_heights) = {
            let stats = self.stats.read().await;
            (stats.filters_received, std::sync::Arc::clone(&stats.received_filter_heights))
        };

        // Calculate last synced filter height from received filter heights without holding the RwLock guard
        let last_synced_filter_height = {
            let heights = received_heights.lock().await;
            heights.iter().max().copied()
        };

        // Calculate the actual header height considering checkpoint sync
        let header_height = self.calculate_header_height(&state).await;

        // Get filter header height from storage
        let storage = self.storage.lock().await;
        let filter_header_height =
            storage.get_filter_tip_height().await.ok().flatten().unwrap_or(0);
        drop(storage);

        Ok(SyncProgress {
            header_height,
            filter_header_height,
            masternode_height: state.last_masternode_diff_height.unwrap_or(0),
            peer_count: 1,                // TODO: Get from network manager
            filter_sync_available: false, // TODO: Get from network manager
            filters_downloaded: filters_received,
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

    /// Helper to try to get wallet balance if W implements Any.
    /// This is a wrapper that handles the case where W might not implement Any.
    fn try_get_balance_if_any(wallet: &W) -> Option<u64>
    where
        W: 'static,
    {
        // Try to use Any trait for downcasting
        // We check if W is WalletManager<ManagedWalletInfo> using TypeId
        use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
        use key_wallet_manager::wallet_manager::WalletManager;
        use std::any::TypeId;

        // Check if W is WalletManager<ManagedWalletInfo>
        let wallet_type_id = TypeId::of::<W>();
        let wallet_manager_type_id = TypeId::of::<WalletManager<ManagedWalletInfo>>();

        if wallet_type_id == wallet_manager_type_id {
            // Unsafe downcast: we've verified the types match, so this is safe
            unsafe {
                let wallet_ptr = wallet as *const W as *const WalletManager<ManagedWalletInfo>;
                let wallet_ref = &*wallet_ptr;
                return Some(wallet_ref.get_total_balance());
            }
        }

        None
    }

    /// Format balance in DASH with 8 decimal places.
    fn format_balance(satoshis: u64) -> String {
        use dashcore::Amount;
        use dashcore::Denomination;
        let amount = Amount::from_sat(satoshis);
        amount.to_string_with_denomination(Denomination::Dash)
    }

    /// Update the status display.
    pub async fn update_status_display(&self) {
        #[cfg(feature = "terminal-ui")]
        {
            if let Some(ui) = self.terminal_ui {
                // Get header height - when syncing from checkpoint, use the actual blockchain height
                let header_height = {
                    let state = self.state.read().await;
                    self.calculate_header_height_with_logging(&state, true).await
                };

                // Get filter header height from storage
                let storage = self.storage.lock().await;
                let filter_height =
                    storage.get_filter_tip_height().await.ok().flatten().unwrap_or(0);
                drop(storage);

                // Get latest chainlock height from state
                let chainlock_height = {
                    let state = self.state.read().await;
                    state.last_chainlock_height
                };

                // Get latest chainlock height from storage metadata (in case state wasn't updated)
                let stored_chainlock_height = {
                    let storage = self.storage.lock().await;
                    if let Ok(Some(data)) = storage.load_metadata("latest_chainlock_height").await {
                        if data.len() >= 4 {
                            Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
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
                        status.network = format!("{:?}", self.config.network());
                    })
                    .await;
                return;
            }
        }

        {
            // Fall back to simple logging if terminal UI is not enabled
            // Get header height - when syncing from checkpoint, use the actual blockchain height
            let header_height = {
                let state = self.state.read().await;
                self.calculate_header_height_with_logging(&state, true).await
            };

            // Get filter header height from storage
            let storage = self.storage.lock().await;
            let filter_height = storage.get_filter_tip_height().await.ok().flatten().unwrap_or(0);
            drop(storage);

            let chainlock_height = {
                let state = self.state.read().await;
                state.last_chainlock_height.unwrap_or(0)
            };

            // Get filter and block processing statistics
            let stats = self.stats.read().await;
            let filters_received = stats.filters_received;
            let filters_matched = stats.filters_matched;
            let blocks_with_relevant_transactions = stats.blocks_with_relevant_transactions;
            let blocks_processed = stats.blocks_processed;
            drop(stats);

            // Get wallet balance if available
            let balance_str = if let Some(wallet_ref) = self.wallet {
                let wallet_guard = wallet_ref.read().await;
                // Try to get balance if W implements Any (for WalletManager support)
                // We use a helper that requires W: Any, so we need to handle this carefully
                // For now, we'll attempt to get balance only if possible
                Self::try_get_balance_if_any(&*wallet_guard)
                    .map(|balance_sat| format!(" | Balance: {}", Self::format_balance(balance_sat)))
                    .unwrap_or_default()
            } else {
                String::new()
            };

            tracing::info!(
                "📊 [SYNC STATUS] Headers: {} | Filter Headers: {} | Filters: {} | Latest ChainLock: {} | Filters Matched: {} | Blocks w/ Relevant Txs: {} | Blocks Processed: {}{}",
                header_height,
                filter_height,
                filters_received,
                if chainlock_height > 0 {
                    format!("#{}", chainlock_height)
                } else {
                    "None".to_string()
                },
                filters_matched,
                blocks_with_relevant_transactions,
                blocks_processed,
                balance_str
            );
        }
    }
}
