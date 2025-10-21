//! Core SequentialSyncManager struct and simple accessor methods.

use std::time::{Duration, Instant};

use crate::client::ClientConfig;
use crate::error::SyncResult;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::{FilterSyncManager, HeaderSyncManagerWithReorg, MasternodeSyncManager};
use crate::types::{SharedFilterHeights, SyncProgress};
use key_wallet_manager::wallet_interface::WalletInterface;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::phases::{PhaseTransition, SyncPhase};
use super::request_control::RequestController;
use super::transitions::TransitionManager;

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
/// The sync manager delegates to specialized sub-managers (`HeaderSyncManagerWithReorg`,
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
pub struct SequentialSyncManager<S: StorageManager, N: NetworkManager, W: WalletInterface> {
    pub(super) _phantom_s: std::marker::PhantomData<S>,
    pub(super) _phantom_n: std::marker::PhantomData<N>,
    /// Current synchronization phase
    pub(super) current_phase: SyncPhase,

    /// Phase transition manager
    pub(super) transition_manager: TransitionManager,

    /// Request controller for phase-aware request management
    pub(super) request_controller: RequestController,

    /// Existing sync managers (wrapped and controlled)
    pub(super) header_sync: HeaderSyncManagerWithReorg<S, N>,
    pub(super) filter_sync: FilterSyncManager<S, N>,
    pub(super) masternode_sync: MasternodeSyncManager<S, N>,

    /// Configuration
    pub(super) config: ClientConfig,

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

impl<
        S: StorageManager + Send + Sync + 'static,
        N: NetworkManager + Send + Sync + 'static,
        W: WalletInterface,
    > SequentialSyncManager<S, N, W>
{
    /// Get the current chain height from the header sync manager
    pub fn get_chain_height(&self) -> u32 {
        self.header_sync.get_chain_height()
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
    /// # Example
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

    /// Get phase history
    pub fn phase_history(&self) -> &[PhaseTransition] {
        &self.phase_history
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
    pub fn update_chain_state_cache(
        &mut self,
        synced_from_checkpoint: bool,
        sync_base_height: u32,
        headers_len: u32,
    ) {
        self.header_sync.update_cached_from_state_snapshot(
            synced_from_checkpoint,
            sync_base_height,
            headers_len,
        );
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
    pub(super) async fn get_blockchain_height_from_storage(&self, storage: &S) -> SyncResult<u32> {
        let storage_height = storage
            .get_tip_height()
            .await
            .map_err(|e| {
                crate::error::SyncError::Storage(format!("Failed to get tip height: {}", e))
            })?
            .unwrap_or(0);

        // Check if we're syncing from a checkpoint
        if self.header_sync.is_synced_from_checkpoint()
            && self.header_sync.get_sync_base_height() > 0
        {
            // For checkpoint sync, blockchain height = sync_base_height + storage_height
            Ok(self.header_sync.get_sync_base_height() + storage_height)
        } else {
            // Normal sync: storage height IS the blockchain height
            Ok(storage_height)
        }
    }

    /// Set the current phase (for testing)
    #[cfg(test)]
    pub fn set_phase(&mut self, phase: SyncPhase) {
        self.current_phase = phase;
    }

    /// Get mutable reference to masternode sync manager (for testing)
    #[cfg(test)]
    pub fn masternode_sync_mut(&mut self) -> &mut MasternodeSyncManager<S, N> {
        &mut self.masternode_sync
    }
}
