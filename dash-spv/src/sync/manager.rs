//! Core SyncManager struct and simple accessor methods.

use super::phases::{PhaseTransition, SyncPhase};
use super::transitions::TransitionManager;
use crate::client::Config;
use crate::error::SyncResult;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::{FilterSyncManager, HeaderSyncManager, MasternodeSyncManager, ReorgConfig};
use crate::types::{SharedFilterHeights, SyncProgress};
use crate::{SpvStats, SyncError};
use dashcore::prelude::CoreBlockHeight;
use dashcore::BlockHash;
use key_wallet_manager::wallet_interface::WalletInterface;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Number of blocks back from a ChainLock's block height where we need the masternode list
/// for validation. ChainLock signatures are created by the masternode quorum that existed
/// 8 blocks before the ChainLock's block.
pub(super) const CHAINLOCK_VALIDATION_MASTERNODE_OFFSET: u32 = 8;

/// Manages sequential synchronization of all blockchain data types.
///
/// # Generic Parameters
///
/// This manager uses generic trait parameters for the same reasons as [`DashSpvClient`]:
///
/// - `S: StorageManager` - Allows swapping between persistent disk storage and in-memory storage for tests
/// - `N: NetworkManager` - Enables testing with mock network without network I/O
/// - `W: WalletInterface` - Supports custom wallet implementations and test wallets
///
/// ## Why Generics Are Essential Here
///
/// ### 1. **Testing Synchronization Logic** 🧪
/// The sync manager coordinates complex blockchain synchronization across multiple phases.
/// Testing this logic requires:
/// - Mock network that doesn't make real connections
/// - Memory storage that doesn't touch the filesystem
/// - Test wallet that doesn't require real keys
///
/// Generics allow these test implementations to be first-class types, not runtime hacks.
///
/// ### 2. **Performance** ⚡
/// Synchronization is performance-critical - we process thousands of headers and filters.
/// Generic monomorphization allows the compiler to:
/// - Inline storage operations
/// - Eliminate vtable overhead
/// - Optimize across trait boundaries
///
/// ### 3. **Delegation Pattern** 🔗
/// The sync manager delegates to specialized sub-managers (`HeaderSyncManager`,
/// `FilterSyncManager`, `MasternodeSyncManager`), each also generic over `S` and `N`.
/// This maintains type consistency throughout the sync pipeline.
///
/// ### 4. **Zero Runtime Cost** 📦
/// Despite being generic, production builds contain only one instantiation because
/// test-only storage/network types are behind `#[cfg(test)]`.
///
/// The generic design enables comprehensive testing while maintaining zero-cost abstraction.
///
/// [`DashSpvClient`]: crate::client::DashSpvClient
pub struct SyncManager<S: StorageManager, N: NetworkManager, W: WalletInterface> {
    pub(super) _phantom_s: std::marker::PhantomData<S>,
    pub(super) _phantom_n: std::marker::PhantomData<N>,
    /// Current synchronization phase
    pub(super) current_phase: SyncPhase,

    /// Phase transition manager
    pub(super) transition_manager: TransitionManager,

    /// Existing sync managers (wrapped and controlled)
    pub(super) header_sync: HeaderSyncManager<S, N>,
    pub(super) filter_sync: FilterSyncManager<S, N>,
    pub(super) masternode_sync: MasternodeSyncManager<S, N>,

    /// Configuration
    pub(super) config: Config,

    /// Phase transition history
    pub(super) phase_history: Vec<PhaseTransition>,

    /// Start time of the entire sync process
    pub(super) sync_start_time: Option<Instant>,

    /// Timeout duration for each phase
    pub(super) phase_timeout: Duration,

    /// Maximum retries per phase before giving up
    pub(super) max_phase_retries: u32,

    /// Current retry count for the active phase
    pub(super) current_phase_retries: u32,

    /// Optional wallet reference for filter checking
    pub(super) wallet: std::sync::Arc<tokio::sync::RwLock<W>>,

    /// Statistics for tracking sync progress
    pub(super) stats: std::sync::Arc<tokio::sync::RwLock<crate::types::SpvStats>>,
}

impl<S: StorageManager, N: NetworkManager, W: WalletInterface> SyncManager<S, N, W> {
    /// Create a new sequential sync manager
    pub fn new(
        config: &Config,
        received_filter_heights: SharedFilterHeights,
        wallet: Arc<RwLock<W>>,
        chain_state: Arc<RwLock<crate::types::ChainState>>,
        stats: Arc<RwLock<SpvStats>>,
    ) -> SyncResult<Self> {
        // Create reorg config with sensible defaults
        let reorg_config = ReorgConfig::default();

        Ok(Self {
            current_phase: SyncPhase::Idle,
            transition_manager: TransitionManager::new(config),
            header_sync: HeaderSyncManager::new(config, reorg_config, chain_state).map_err(
                |e| SyncError::InvalidState(format!("Failed to create header sync manager: {}", e)),
            )?,
            filter_sync: FilterSyncManager::new(config, received_filter_heights),
            masternode_sync: MasternodeSyncManager::new(config),
            config: config.clone(),
            phase_history: Vec::new(),
            sync_start_time: None,
            phase_timeout: Duration::from_secs(60), // 1 minute default timeout per phase
            max_phase_retries: 3,
            current_phase_retries: 0,
            wallet,
            stats,
            _phantom_s: std::marker::PhantomData,
            _phantom_n: std::marker::PhantomData,
        })
    }

    /// Load headers from storage into the sync managers
    pub async fn load_headers_from_storage(&mut self, storage: &S) {
        // Load headers into the header sync manager
        self.header_sync.load_headers_from_storage(storage).await;
    }

    /// Get the earliest wallet birth height hint for the configured network, if available.
    pub async fn wallet_birth_height_hint(&self) -> CoreBlockHeight {
        // Only acquire the wallet lock if we have a valid network mapping
        let wallet_guard = self.wallet.read().await;
        let result = wallet_guard.earliest_required_height().await;
        drop(wallet_guard);
        result
    }

    /// Get the configured start height hint, if any.
    pub fn config_start_height(&self) -> Option<u32> {
        self.config.start_from_height
    }

    /// Start the sequential sync process
    pub async fn start_sync(&mut self, network: &mut N, storage: &mut S) -> SyncResult<bool> {
        if self.current_phase.is_syncing() {
            return Err(SyncError::SyncInProgress);
        }

        tracing::info!("🚀 Starting sequential sync process");
        tracing::info!("📊 Current phase: {}", self.current_phase.name());
        self.sync_start_time = Some(Instant::now());

        // Transition from Idle to first phase
        self.transition_to_next_phase(storage, network, "Starting sync").await?;

        // The actual header request will be sent when we have peers
        match &self.current_phase {
            SyncPhase::DownloadingHeaders {
                ..
            } => {
                // Just prepare the sync, don't execute yet
                tracing::info!(
                    "📋 Sequential sync prepared, waiting for peers to send initial requests"
                );
                // Prepare the header sync without sending requests
                let base_hash = self.header_sync.prepare_sync(storage).await?;
                tracing::debug!("Starting from base hash: {:?}", base_hash);
            }
            _ => {
                // If we're not in headers phase, something is wrong
                return Err(SyncError::InvalidState(
                    "Expected to be in DownloadingHeaders phase".to_string(),
                ));
            }
        }

        Ok(true)
    }

    /// Send initial sync requests (called after peers are connected)
    pub async fn send_initial_requests(
        &mut self,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        match &self.current_phase {
            SyncPhase::DownloadingHeaders {
                ..
            } => {
                tracing::info!("📡 Sending initial header requests for sequential sync");
                // If header sync is already prepared, just send the request
                if self.header_sync.is_syncing() {
                    // Get current tip from storage to determine base hash
                    let base_hash = self.get_base_hash_from_storage(storage).await?;

                    // Request headers starting from our current tip
                    self.header_sync.request_headers(network, base_hash, storage).await?;
                } else {
                    // Otherwise start sync normally
                    self.header_sync.start_sync(network, storage).await?;
                }
            }
            _ => {
                tracing::warn!("send_initial_requests called but not in DownloadingHeaders phase");
            }
        }
        Ok(())
    }

    /// Reset any pending requests after restart.
    pub fn reset_pending_requests(&mut self) {
        // Reset all sync manager states
        let _ = self.header_sync.reset_pending_requests();
        self.filter_sync.reset_pending_requests();
        // Masternode sync doesn't have pending requests to reset

        // Reset phase tracking
        self.current_phase_retries = 0;

        tracing::debug!("Reset sequential sync manager pending requests");
    }

    /// Helper method to get base hash from storage
    pub(super) async fn get_base_hash_from_storage(
        &self,
        storage: &S,
    ) -> SyncResult<Option<BlockHash>> {
        let current_tip_height = storage.get_tip_height().await;

        let base_hash = match current_tip_height {
            None => None,
            Some(height) => {
                let tip_header = storage
                    .get_header(height)
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to get tip header: {}", e)))?;
                tip_header.map(|h| h.block_hash())
            }
        };

        Ok(base_hash)
    }

    /// Get current sync progress template.
    ///
    /// **IMPORTANT**: This method returns a TEMPLATE ONLY. It does NOT query storage or network
    /// for actual progress values. The returned `SyncProgress` struct contains:
    /// - Accurate sync phase status flags based on the current phase
    /// - PLACEHOLDER (zero/default) values for all heights, counts, and network data
    ///
    /// **Callers MUST populate the following fields with actual values from storage and network:**
    /// - `header_height`: Should be queried from storage (e.g., `storage.get_tip_height()`)
    /// - `filter_header_height`: Should be queried from storage (e.g., `storage.get_filter_tip_height()`)
    /// - `masternode_height`: Should be queried from masternode state in storage
    /// - `peer_count`: Should be queried from the network manager
    /// - `filters_downloaded`: Should be calculated from storage
    /// - `last_synced_filter_height`: Should be queried from storage
    ///
    /// # Examples
    /// ```ignore
    /// let mut progress = sync_manager.get_progress();
    /// progress.header_height = storage.get_tip_height().await?.unwrap_or(0);
    /// progress.filter_header_height = storage.get_filter_tip_height().await?.unwrap_or(0);
    /// progress.peer_count = network.peer_count() as u32;
    /// // ... populate other fields as needed
    /// ```
    pub fn get_progress(&self) -> SyncProgress {
        // WARNING: This method returns a TEMPLATE with PLACEHOLDER values.
        // Callers MUST populate header_height, filter_header_height, masternode_height,
        // peer_count, filters_downloaded, and last_synced_filter_height with actual values
        // from storage and network queries.

        // Create a basic progress report template
        let _phase_progress = self.current_phase.progress();

        SyncProgress {
            header_height: 0,        // PLACEHOLDER: Caller MUST query storage.get_tip_height()
            filter_header_height: 0, // PLACEHOLDER: Caller MUST query storage.get_filter_tip_height()
            masternode_height: 0,    // PLACEHOLDER: Caller MUST query masternode state from storage
            peer_count: 0,           // PLACEHOLDER: Caller MUST query network.peer_count()
            filters_downloaded: 0,   // PLACEHOLDER: Caller MUST calculate from storage
            last_synced_filter_height: None, // PLACEHOLDER: Caller MUST query from storage
            sync_start: std::time::SystemTime::now(),
            last_update: std::time::SystemTime::now(),
            filter_sync_available: self.config.enable_filters,
        }
    }

    /// Check if sync is complete
    pub fn is_synced(&self) -> bool {
        matches!(self.current_phase, SyncPhase::FullySynced { .. })
    }

    /// Check if the current phase needs to be executed
    /// This is true for phases that haven't been started yet
    pub(super) fn current_phase_needs_execution(&self) -> bool {
        match &self.current_phase {
            SyncPhase::DownloadingCFHeaders {
                ..
            } => {
                // Check if filter sync hasn't started yet (no progress time)
                self.current_phase.last_progress_time().is_none()
            }
            SyncPhase::DownloadingFilters {
                ..
            } => {
                // Check if filter download hasn't started yet
                self.current_phase.last_progress_time().is_none()
            }
            _ => false, // Other phases are started by messages or initial sync
        }
    }

    /// Check if currently in the downloading blocks phase
    pub fn is_in_downloading_blocks_phase(&self) -> bool {
        matches!(self.current_phase, SyncPhase::DownloadingBlocks { .. })
    }

    /// Get current phase
    pub fn current_phase(&self) -> &SyncPhase {
        &self.current_phase
    }

    /// Get a reference to the masternode list engine.
    /// Returns None if masternode sync is not enabled in config.
    pub fn masternode_list_engine(
        &self,
    ) -> Option<&dashcore::sml::masternode_list_engine::MasternodeListEngine> {
        self.masternode_sync.engine()
    }

    /// Update the chain state (used for checkpoint sync initialization)
    pub fn update_chain_state_cache(&mut self, sync_base_height: u32) {
        self.header_sync.update_cached_from_state_snapshot(sync_base_height);
    }

    /// Get reference to the masternode engine if available.
    /// Returns None if masternodes are disabled or engine is not initialized.
    pub fn get_masternode_engine(
        &self,
    ) -> Option<&dashcore::sml::masternode_list_engine::MasternodeListEngine> {
        self.masternode_sync.engine()
    }

    /// Get a reference to the filter sync manager.
    pub fn filter_sync(&self) -> &FilterSyncManager<S, N> {
        &self.filter_sync
    }

    /// Get a mutable reference to the filter sync manager.
    pub fn filter_sync_mut(&mut self) -> &mut FilterSyncManager<S, N> {
        &mut self.filter_sync
    }

    /// Get the actual blockchain height from storage height, accounting for checkpoints
    pub(super) async fn get_blockchain_height_from_storage(&self, storage: &S) -> u32 {
        storage.get_tip_height().await.unwrap_or(0)
    }
}
