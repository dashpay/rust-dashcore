//! Core DashSpvClient struct definition and simple accessor methods.
//!
//! This module contains:
//! - The main `DashSpvClient` struct definition
//! - Simple getters for wallet, network, storage, etc.
//! - Storage operations (clear_storage, clear_sync_state, clear_filters)
//! - State queries (is_running, tip_hash, tip_height, chain_state, stats)
//! - Configuration updates
//! - Terminal UI accessors

use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use super::ClientConfig;
use crate::error::{Result, SpvError};
use crate::mempool_filter::MempoolFilter;
use crate::network::NetworkManager;
use crate::storage::{
    PersistentBlockHeaderStorage, PersistentBlockStorage, PersistentFilterHeaderStorage,
    PersistentFilterStorage, PersistentMetadataStorage, StorageManager,
};
use crate::sync::SyncCoordinator;
use crate::types::MempoolState;
use key_wallet_manager::wallet_interface::WalletInterface;

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
    pub(super) network: N,
    pub(super) storage: Arc<Mutex<S>>,
    /// External wallet implementation (required)
    pub(super) wallet: Arc<RwLock<W>>,
    pub(super) masternode_engine: Option<Arc<RwLock<MasternodeListEngine>>>,
    pub(super) sync_coordinator: SyncCoordinator<
        PersistentBlockHeaderStorage,
        PersistentFilterHeaderStorage,
        PersistentFilterStorage,
        PersistentBlockStorage,
        PersistentMetadataStorage,
        W,
    >,
    pub(super) running: Arc<RwLock<bool>>,
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
        self.config.network
    }

    /// Get access to storage manager (requires locking).
    pub fn storage(&self) -> Arc<Mutex<S>> {
        self.storage.clone()
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

    // ============ Storage Operations ============

    /// Clear all persisted storage (headers, filters, state, sync state) and reset in-memory state.
    pub async fn clear_storage(&mut self) -> Result<()> {
        // Wipe on-disk persistence fully
        {
            let mut storage = self.storage.lock().await;
            storage.clear().await.map_err(SpvError::Storage)?;
        }

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
}
