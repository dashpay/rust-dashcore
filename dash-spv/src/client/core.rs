//! Core DashSpvClient struct definition and simple accessor methods.
//!
//! This module contains:
//! - The main `DashSpvClient` struct definition
//! - Simple getters for wallet and network
//! - State and header queries (is_running, tip_header, header_at, header_height)
//! - clear_storage
//! - Configuration updates

use crate::sml_engine::MasternodeListEngine;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::ClientConfig;
use crate::error::{Result, SpvError, StorageResult};
use crate::network::NetworkManager;
use crate::storage::{
    BlockHeaderStorage, BlockHeaderTip, DiskStorageManager, PersistentBlockHeaderStorage,
    PersistentBlockStorage, PersistentFilterHeaderStorage, PersistentFilterStorage,
    PersistentMetadataStorage, StorageManager,
};
use crate::sync::{Managers, SyncCoordinator};
use crate::types::HashedBlockHeader;
use key_wallet_manager::WalletInterface;

pub(super) type SyncManagers<W> = Managers<
    PersistentBlockHeaderStorage,
    PersistentFilterHeaderStorage,
    PersistentFilterStorage,
    PersistentBlockStorage,
    PersistentMetadataStorage,
    W,
>;

/// Main Dash SPV client with generic trait-based architecture.
///
/// # Generic Design Philosophy
///
/// This struct uses two generic parameters (`W`, `N`) instead of concrete types or
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
/// - Event handlers are stored as `Vec<Arc<dyn EventHandler>>`
///
/// ## Common Configurations
///
/// While this struct is generic, most users will use standard configurations:
///
/// ```ignore
/// // Production configuration
/// type StandardSpvClient = DashSpvClient<WalletManager, PeerNetworkManager>;
///
/// // Test configuration
/// type TestSpvClient = DashSpvClient<WalletManager, MockNetworkManager>;
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
pub struct DashSpvClient<W: WalletInterface, N: NetworkManager> {
    pub(super) config: Arc<RwLock<ClientConfig>>,
    pub(super) network: Arc<Mutex<N>>,
    pub(super) storage: Arc<Mutex<DiskStorageManager>>,
    /// External wallet implementation (required)
    pub(super) wallet: Arc<RwLock<W>>,
    pub(super) masternode_engine:
        Option<Arc<RwLock<MasternodeListEngine<PersistentBlockHeaderStorage>>>>,
    pub(super) sync_coordinator: Arc<Mutex<SyncCoordinator>>,
    /// The running sync loop, `None` while stopped. A loop whose `shutdown` is
    /// cancelled has failed and waits to be torn down. `run` and `stop` hold
    /// the lock throughout, so they never overlap.
    pub(super) sync_loop: Arc<Mutex<Option<SyncLoop>>>,
    /// Whether the sync loop is running, readable without locking `sync_loop`.
    /// Set once `run` started it, cleared as soon as it stops or fails.
    pub(super) running: Arc<AtomicBool>,
    pub(super) event_handlers: Arc<Vec<Arc<dyn super::EventHandler>>>,
}

/// The background task of a running client.
pub(super) struct SyncLoop {
    pub(super) task: JoinHandle<()>,
    /// Stops the loop and the event monitors it runs.
    pub(super) shutdown: CancellationToken,
}

impl<W: WalletInterface, N: NetworkManager> Clone for DashSpvClient<W, N> {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            network: Arc::clone(&self.network),
            storage: Arc::clone(&self.storage),
            wallet: Arc::clone(&self.wallet),
            masternode_engine: self.masternode_engine.clone(),
            sync_coordinator: Arc::clone(&self.sync_coordinator),
            sync_loop: Arc::clone(&self.sync_loop),
            running: Arc::clone(&self.running),
            event_handlers: Arc::clone(&self.event_handlers),
        }
    }
}

impl<W: WalletInterface, N: NetworkManager> DashSpvClient<W, N> {
    // ============ Simple Getters ============

    /// Get a reference to the wallet.
    pub fn wallet(&self) -> &Arc<RwLock<W>> {
        &self.wallet
    }

    /// Get the network configuration.
    pub async fn network(&self) -> dashcore::Network {
        self.config.read().await.network
    }

    // ============ State Queries ============

    /// Check if the client is running. Does not wait for an ongoing `run` or `stop`.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    pub async fn tip_header(&self) -> Option<BlockHeaderTip> {
        self.storage.lock().await.get_tip().await
    }

    pub async fn header_at(&self, height: u32) -> StorageResult<Option<HashedBlockHeader>> {
        self.storage.lock().await.get_header(height).await
    }

    pub async fn header_height(&self, hash: &dashcore::BlockHash) -> StorageResult<Option<u32>> {
        self.storage.lock().await.get_header_height_by_hash(hash).await
    }

    // ============ Storage Operations ============

    /// Stop the client and clear all persisted storage (headers, filters, state, sync state)
    /// and the in-memory state derived from it.
    pub async fn clear_storage(&self) -> Result<()> {
        self.stop().await;

        self.storage.lock().await.clear().await?;

        self.sync_coordinator.lock().await.reset_progress();
        if let Some(engine) = &self.masternode_engine {
            let network = self.config.read().await.network;
            let headers = self.storage.lock().await.block_headers();
            *engine.write().await = MasternodeListEngine::new(network, headers);
        }

        Ok(())
    }

    // ============ Configuration ============

    /// Update the client configuration.
    pub async fn update_config(&self, new_config: ClientConfig) -> Result<()> {
        // Validate new configuration
        new_config.validate().map_err(SpvError::Config)?;

        let mut config = self.config.write().await;

        // Ensure network hasn't changed
        if new_config.network != config.network {
            return Err(SpvError::Config("Cannot change network on running client".to_string()));
        }

        // Update configuration
        *config = new_config;

        Ok(())
    }
}
