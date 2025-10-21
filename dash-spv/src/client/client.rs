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
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, RwLock};

#[cfg(feature = "terminal-ui")]
use crate::terminal::TerminalUI;

use crate::chain::ChainLockManager;
use crate::error::{Result, SpvError};
use crate::mempool_filter::MempoolFilter;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::filters::FilterNotificationSender;
use crate::sync::sequential::SequentialSyncManager;
use crate::types::{ChainState, DetailedSyncProgress, MempoolState, SpvEvent, SpvStats};
use crate::validation::ValidationManager;
use key_wallet_manager::wallet_interface::WalletInterface;

use super::{BlockProcessingTask, ClientConfig, StatusDisplay};

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
/// - Test implementations (`MockNetworkManager`, `MemoryStorageManager`) are
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
///     MultiPeerNetworkManager,
///     DiskStorageManager,
/// >;
///
/// // Test configuration
/// type TestSpvClient = DashSpvClient<
///     WalletManager,
///     MockNetworkManager,
///     MemoryStorageManager,
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
    /// The sync manager is stored as a non-shared field (not wrapped in Arc<Mutex<T>>)
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
    /// - Using interior mutability patterns (Arc<Mutex<SequentialSyncManager>>)
    /// - Extracting read-only state into a separate shared structure
    /// - Implementing a message-passing architecture for sync commands
    ///
    /// The current design prioritizes simplicity and correctness over concurrent access.
    pub(super) sync_manager: SequentialSyncManager<S, N, W>,
    pub(super) validation: ValidationManager,
    pub(super) chainlock_manager: Arc<ChainLockManager>,
    pub(super) running: Arc<RwLock<bool>>,
    #[cfg(feature = "terminal-ui")]
    pub(super) terminal_ui: Option<Arc<TerminalUI>>,
    pub(super) filter_processor: Option<FilterNotificationSender>,
    pub(super) block_processor_tx: mpsc::UnboundedSender<BlockProcessingTask>,
    pub(super) progress_sender: Option<mpsc::UnboundedSender<DetailedSyncProgress>>,
    pub(super) progress_receiver: Option<mpsc::UnboundedReceiver<DetailedSyncProgress>>,
    pub(super) event_tx: mpsc::UnboundedSender<SpvEvent>,
    pub(super) event_rx: Option<mpsc::UnboundedReceiver<SpvEvent>>,
    pub(super) mempool_state: Arc<RwLock<MempoolState>>,
    pub(super) mempool_filter: Option<Arc<MempoolFilter>>,
    pub(super) last_sync_state_save: Arc<RwLock<u64>>,
}

impl<
        W: WalletInterface + Send + Sync + 'static,
        N: NetworkManager + Send + Sync + 'static,
        S: StorageManager + Send + Sync + 'static,
    > DashSpvClient<W, N, S>
{
    // ============ Simple Getters ============

    /// Get a reference to the wallet.
    pub fn wallet(&self) -> &Arc<RwLock<W>> {
        &self.wallet
    }

    /// Get the network configuration.
    pub fn network(&self) -> dashcore::Network {
        self.config.network
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
    pub fn sync_manager_mut(&mut self) -> &mut SequentialSyncManager<S, N, W> {
        &mut self.sync_manager
    }

    // ============ State Queries ============

    /// Check if the client is running.
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Returns the current chain tip hash if available.
    pub async fn tip_hash(&self) -> Option<dashcore::BlockHash> {
        let state = self.state.read().await;
        state.tip_hash()
    }

    /// Returns the current chain tip height (absolute), accounting for checkpoint base.
    pub async fn tip_height(&self) -> u32 {
        let state = self.state.read().await;
        state.tip_height()
    }

    /// Get current chain state (read-only).
    pub async fn chain_state(&self) -> ChainState {
        let display = self.create_status_display().await;
        display.chain_state().await
    }

    // ============ Storage Operations ============

    /// Clear all persisted storage (headers, filters, state, sync state).
    pub async fn clear_storage(&mut self) -> Result<()> {
        let mut storage = self.storage.lock().await;
        storage.clear().await.map_err(SpvError::Storage)
    }

    /// Clear only the persisted sync state snapshot (keep headers/filters).
    pub async fn clear_sync_state(&mut self) -> Result<()> {
        let mut storage = self.storage.lock().await;
        storage.clear_sync_state().await.map_err(SpvError::Storage)
    }

    /// Clear all stored filter headers and compact filters while keeping other data intact.
    pub async fn clear_filters(&mut self) -> Result<()> {
        {
            let mut storage = self.storage.lock().await;
            storage.clear_filters().await.map_err(SpvError::Storage)?;
        }

        // Reset in-memory chain state for filters
        {
            let mut state = self.state.write().await;
            state.filter_headers.clear();
            state.current_filter_tip = None;
        }

        // Reset filter sync manager tracking
        self.sync_manager.filter_sync_mut().clear_filter_state().await;

        // Reset filter-related statistics
        let received_heights = {
            let stats = self.stats.read().await;
            stats.received_filter_heights.clone()
        };

        {
            let mut stats = self.stats.write().await;
            stats.filter_headers_downloaded = 0;
            stats.filter_height = 0;
            stats.filters_downloaded = 0;
            stats.filters_received = 0;
        }

        received_heights.lock().await.clear();

        Ok(())
    }

    // ============ Configuration ============

    /// Update the client configuration.
    pub async fn update_config(&mut self, new_config: ClientConfig) -> Result<()> {
        // Validate new configuration
        new_config.validate().map_err(SpvError::Config)?;

        // Ensure network hasn't changed
        if new_config.network != self.config.network {
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
    pub(super) async fn create_status_display(&self) -> StatusDisplay<'_, S> {
        StatusDisplay::new(
            &self.state,
            &self.stats,
            self.storage.clone(),
            &self.terminal_ui,
            &self.config,
        )
    }

    /// Helper to create a StatusDisplay instance (without terminal UI).
    #[cfg(not(feature = "terminal-ui"))]
    pub(super) async fn create_status_display(&self) -> StatusDisplay<'_, S> {
        StatusDisplay::new(&self.state, &self.stats, self.storage.clone(), &None, &self.config)
    }

    /// Update the status display.
    pub(super) async fn update_status_display(&self) {
        let display = self.create_status_display().await;
        display.update_status_display().await;
    }
}
