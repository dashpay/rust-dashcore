//! Core DashSpvClient struct definition and simple accessor methods.
//!
//! This module contains:
//! - The main `DashSpvClient` struct definition
//! - Simple getters for wallet, network, storage, etc.
//! - Storage operations (clear_storage, clear_sync_state, clear_filters)
//! - State queries (is_running, tip_hash, tip_height, chain_state, stats)
//! - Configuration updates
//! - Terminal UI accessors

use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};

#[cfg(feature = "terminal-ui")]
use crate::terminal::TerminalUI;

use crate::chain::ChainLockManager;
use crate::error::{Result, SpvError};
use crate::mempool_filter::MempoolFilter;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::filters::FilterNotificationSender;
use crate::sync::SyncManager;
use crate::types::{ChainState, DetailedSyncProgress, MempoolState, SpvEvent, SpvStats};
use key_wallet_manager::wallet_interface::WalletInterface;

use super::{ClientConfig, StatusDisplay};

/// Main Dash SPV client with generic trait-based architecture.
///
/// # Generic Design Philosophy
///
/// This struct uses three generic parameters (`W`, `N`, `S`) instead of concrete types or
/// trait objects. This design choice provides significant benefits for a library:
///
/// ## Benefits of Generic Architecture
///
/// ### 1. **Zero-Cost Abstraction** ⚡
/// - No runtime overhead from virtual dispatch (vtables)
/// - Compiler can fully inline and optimize across trait boundaries
/// - Critical for a wallet library where performance matters
///
/// ### 2. **Compile-Time Type Safety** ✅
/// - Errors caught at compile time, not runtime
/// - No possibility of trait object casting errors
/// - Strong guarantees about component compatibility
///
/// ### 3. **Library Flexibility** 🔌
/// - Users can plug in their own `WalletInterface` implementations
/// - Custom `NetworkManager` for specialized network requirements
/// - Alternative `StorageManager` (in-memory, cloud, custom DB)
/// - Essential for a reusable library
///
/// ### 4. **Testing Without Mocks** 🧪
/// - Test implementations (`MockNetworkManager`) are
///   first-class types, not runtime injections
/// - No conditional compilation or feature flags needed for tests
/// - Type system ensures test and production code are compatible
///
/// ### 5. **No Binary Bloat** 📦
/// - Despite being generic, production binaries contain only ONE instantiation
/// - Test-only implementations are behind `#[cfg(test)]` and don't ship
/// - Same binary size as trait objects, but with zero runtime cost
///
/// ## Type Parameters
///
/// - `W: WalletInterface` - Handles UTXO tracking, address management, transaction processing
/// - `N: NetworkManager` - Manages peer connections, message routing, network protocol
/// - `S: StorageManager` - Persistent storage for headers, filters, chain state
///
/// ## Common Configurations
///
/// While this struct is generic, most users will use standard configurations:
///
/// ```ignore
/// // Production configuration
/// type StandardSpvClient = DashSpvClient<
///     WalletManager,
///     PeerNetworkManager,
///     DiskStorageManager,
/// >;
///
/// // Test configuration
/// type TestSpvClient = DashSpvClient<
///     WalletManager,
///     MockNetworkManager,
///     DiskStorageManager,
/// >;
/// ```
///
/// ## Why Not Trait Objects?
///
/// Using `Arc<dyn WalletInterface>` instead of generics would:
/// - Add 5-10% runtime overhead from vtable dispatch
/// - Prevent compiler optimizations across trait boundaries
/// - Make the codebase less flexible for library users
/// - Not reduce binary size (production has one instantiation anyway)
///
/// The generic design is an intentional, beneficial architectural choice for a library.
pub struct DashSpvClient<W: WalletInterface, N: NetworkManager, S: StorageManager> {
    pub(super) config: ClientConfig,
    pub(super) state: Arc<RwLock<ChainState>>,
    pub(super) stats: Arc<RwLock<SpvStats>>,
    pub(super) network: N,
    pub(super) storage: Arc<Mutex<S>>,
    /// External wallet implementation (required)
    pub(super) wallet: Arc<RwLock<W>>,
    /// Synchronization manager for coordinating blockchain sync operations.
    ///
    /// # Architectural Design
    ///
    /// The sync manager is stored as a non-shared field (not wrapped in `Arc<Mutex<T>>`)
    /// for the following reasons:
    ///
    /// 1. **Single Owner Pattern**: The sync manager is exclusively owned by the client,
    ///    ensuring clear ownership and preventing concurrent access issues.
    ///
    /// 2. **Sequential Operations**: Blockchain synchronization is inherently sequential -
    ///    headers must be validated in order, and sync phases must complete before
    ///    progressing to the next phase.
    ///
    /// 3. **Simplified State Management**: Avoiding shared ownership eliminates complex
    ///    synchronization issues and makes the sync state machine easier to reason about.
    ///
    /// ## Future Considerations
    ///
    /// If concurrent access becomes necessary (e.g., for monitoring sync progress from
    /// multiple threads), consider:
    /// - Using interior mutability patterns (`Arc<Mutex<SyncManager>>`)
    /// - Extracting read-only state into a separate shared structure
    /// - Implementing a message-passing architecture for sync commands
    ///
    /// The current design prioritizes simplicity and correctness over concurrent access.
    pub(super) sync_manager: SyncManager<S, N, W>,
    pub(super) chainlock_manager: Arc<ChainLockManager>,
    pub(super) running: Arc<RwLock<bool>>,
    #[cfg(feature = "terminal-ui")]
    pub(super) terminal_ui: Option<Arc<TerminalUI>>,
    pub(super) filter_processor: Option<FilterNotificationSender>,
    pub(super) progress_sender: Option<mpsc::UnboundedSender<DetailedSyncProgress>>,
    pub(super) progress_receiver: Option<mpsc::UnboundedReceiver<DetailedSyncProgress>>,
    pub(super) event_tx: mpsc::UnboundedSender<SpvEvent>,
    pub(super) event_rx: Option<mpsc::UnboundedReceiver<SpvEvent>>,
    pub(super) mempool_state: Arc<RwLock<MempoolState>>,
    pub(super) mempool_filter: Option<Arc<MempoolFilter>>,
}

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    // ============ Simple Getters ============

    /// Get a reference to the wallet.
    pub fn wallet(&self) -> &Arc<RwLock<W>> {
        &self.wallet
    }

    /// Get the network configuration.
    pub fn network(&self) -> dashcore::Network {
        self.config.network()
    }

    /// Get access to storage manager (requires locking).
    pub fn storage(&self) -> Arc<Mutex<S>> {
        self.storage.clone()
    }

    /// Get reference to chainlock manager.
    pub fn chainlock_manager(&self) -> &Arc<ChainLockManager> {
        &self.chainlock_manager
    }

    /// Get mutable reference to sync manager (for testing).
    #[cfg(test)]
    pub fn sync_manager_mut(&mut self) -> &mut SyncManager<S, N, W> {
        &mut self.sync_manager
    }

    // ============ State Queries ============

    /// Check if the client is running.
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Returns the current chain tip hash if available.
    pub async fn tip_hash(&self) -> Option<dashcore::BlockHash> {
        let storage = self.storage.lock().await;
        storage.get_tip().await.map(|tip| *tip.hash())
    }

    /// Returns the current chain tip height (absolute), accounting for checkpoint base.
    pub async fn tip_height(&self) -> u32 {
        self.storage.lock().await.get_tip_height().await.unwrap_or(0)
    }

    /// Get current chain state (read-only).
    pub async fn chain_state(&self) -> ChainState {
        let display = self.create_status_display().await;
        display.chain_state().await
    }

    // ============ Storage Operations ============

    /// Clear all persisted storage (headers, filters, state, sync state) and reset in-memory state.
    pub async fn clear_storage(&mut self) -> Result<()> {
        // Wipe on-disk persistence fully
        {
            let mut storage = self.storage.lock().await;
            storage.clear().await.map_err(SpvError::Storage)?;
        }

        // Reset in-memory chain state to a clean baseline for the current network
        {
            let mut state = self.state.write().await;
            *state = ChainState::new_for_network(self.config.network());
        }

        // Reset sync manager filter state (headers/filters progress trackers)
        self.sync_manager.filter_sync_mut().clear_filter_state().await;

        // Reset in-memory statistics and received filter height tracking without
        // replacing the SharedFilterHeights Arc (to keep existing references valid)
        let received_heights = {
            let stats = self.stats.read().await;
            stats.received_filter_heights.clone()
        };

        {
            use std::time::Duration;
            let mut stats = self.stats.write().await;
            stats.connected_peers = 0;
            stats.total_peers = 0;
            stats.header_height = 0;
            stats.filter_height = 0;
            stats.headers_downloaded = 0;
            stats.filter_headers_downloaded = 0;
            stats.filters_downloaded = 0;
            stats.filters_matched = 0;
            stats.blocks_with_relevant_transactions = 0;
            stats.blocks_requested = 0;
            stats.blocks_processed = 0;
            stats.masternode_diffs_processed = 0;
            stats.bytes_received = 0;
            stats.bytes_sent = 0;
            stats.uptime = Duration::default();
            stats.filters_requested = 0;
            stats.filters_received = 0;
            stats.filter_sync_start_time = None;
            stats.last_filter_received_time = None;
            stats.active_filter_requests = 0;
            stats.pending_filter_requests = 0;
            stats.filter_request_timeouts = 0;
            stats.filter_requests_retried = 0;
        }

        received_heights.lock().await.clear();

        // Reset mempool tracking (state and bloom filter)
        {
            let mut mempool_state = self.mempool_state.write().await;
            *mempool_state = MempoolState::default();
        }
        self.mempool_filter = None;

        Ok(())
    }

    // ============ Configuration ============

    /// Update the client configuration.
    pub async fn update_config(&mut self, new_config: ClientConfig) -> Result<()> {
        // Ensure network hasn't changed
        if new_config.network() != self.config.network() {
            return Err(SpvError::Config("Cannot change network on running client".to_string()));
        }

        // Update configuration
        self.config = new_config;

        Ok(())
    }

    // ============ Terminal UI ============

    /// Enable terminal UI for status display.
    #[cfg(feature = "terminal-ui")]
    pub fn enable_terminal_ui(&mut self) {
        let ui = Arc::new(TerminalUI::new(true));
        self.terminal_ui = Some(ui);
    }

    /// Get the terminal UI handle.
    #[cfg(feature = "terminal-ui")]
    pub fn get_terminal_ui(&self) -> Option<Arc<TerminalUI>> {
        self.terminal_ui.clone()
    }

    // ============ Internal Helpers ============

    /// Helper to create a StatusDisplay instance.
    #[cfg(feature = "terminal-ui")]
    pub(super) async fn create_status_display(&self) -> StatusDisplay<'_, S, W> {
        StatusDisplay::new(
            &self.state,
            &self.stats,
            self.storage.clone(),
            Some(&self.wallet),
            &self.terminal_ui,
            &self.config,
        )
    }

    /// Helper to create a StatusDisplay instance (without terminal UI).
    #[cfg(not(feature = "terminal-ui"))]
    pub(super) async fn create_status_display(&self) -> StatusDisplay<'_, S, W> {
        StatusDisplay::new(
            &self.state,
            &self.stats,
            self.storage.clone(),
            Some(&self.wallet),
            &None,
            &self.config,
        )
    }

    /// Update the status display.
    pub(super) async fn update_status_display(&self) {
        let display = self.create_status_display().await;
        display.update_status_display().await;
    }
}
