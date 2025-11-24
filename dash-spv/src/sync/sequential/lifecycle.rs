//! Lifecycle management for SequentialSyncManager (initialization, startup, shutdown).

use std::time::{Duration, Instant};

use dashcore::BlockHash;

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::{
    FilterSyncManager, HeaderSyncManagerWithReorg, MasternodeSyncManager, ReorgConfig,
};
use crate::types::{SharedFilterHeights, SpvStats};
use key_wallet_manager::{wallet_interface::WalletInterface, Network as WalletNetwork};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::manager::SequentialSyncManager;
use super::phases::SyncPhase;
use super::request_control::RequestController;
use super::transitions::TransitionManager;

impl<
        S: StorageManager + Send + Sync + 'static,
        N: NetworkManager + Send + Sync + 'static,
        W: WalletInterface,
    > SequentialSyncManager<S, N, W>
{
    /// Create a new sequential sync manager
    pub fn new(
        config: &ClientConfig,
        received_filter_heights: SharedFilterHeights,
        wallet: Arc<RwLock<W>>,
        chain_state: Arc<RwLock<crate::types::ChainState>>,
        stats: Arc<RwLock<SpvStats>>,
    ) -> SyncResult<Self> {
        // Create reorg config with sensible defaults
        let reorg_config = ReorgConfig::default();

        // Create filter recheck queue with default config
        let filter_recheck_config = crate::sync::filters::recheck::FilterRecheckConfig::default();
        let filter_recheck_queue =
            crate::sync::filters::recheck::FilterRecheckQueue::new(filter_recheck_config);

        Ok(Self {
            current_phase: SyncPhase::Idle,
            transition_manager: TransitionManager::new(config),
            request_controller: RequestController::new(config),
            header_sync: HeaderSyncManagerWithReorg::new(config, reorg_config, chain_state)
                .map_err(|e| {
                    SyncError::InvalidState(format!("Failed to create header sync manager: {}", e))
                })?,
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
            filter_recheck_queue,
            _phantom_s: std::marker::PhantomData,
            _phantom_n: std::marker::PhantomData,
        })
    }

    /// Load headers from storage into the sync managers
    pub async fn load_headers_from_storage(&mut self, storage: &S) -> SyncResult<u32> {
        // Load headers into the header sync manager
        let loaded_count = self.header_sync.load_headers_from_storage(storage).await?;

        if loaded_count > 0 {
            tracing::info!("Sequential sync manager loaded {} headers from storage", loaded_count);

            // Update the current phase if we have headers
            // This helps the sync manager understand where to resume from
            if matches!(self.current_phase, SyncPhase::Idle) {
                // We have headers but haven't started sync yet
                // The phase will be properly set when start_sync is called
                tracing::debug!("Headers loaded but sync not started yet");
            }
        }

        Ok(loaded_count)
    }

    /// Get the earliest wallet birth height hint for the configured network, if available.
    pub async fn wallet_birth_height_hint(&self) -> Option<u32> {
        // Map the dashcore network to wallet network, returning None for unknown variants
        let wallet_network = match self.config.network {
            dashcore::Network::Dash => WalletNetwork::Dash,
            dashcore::Network::Testnet => WalletNetwork::Testnet,
            dashcore::Network::Devnet => WalletNetwork::Devnet,
            dashcore::Network::Regtest => WalletNetwork::Regtest,
            _ => return None, // Unknown network variant - return None instead of defaulting
        };

        // Only acquire the wallet lock if we have a valid network mapping
        let wallet_guard = self.wallet.read().await;
        let result = wallet_guard.earliest_required_height(wallet_network).await;
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
                    self.header_sync.request_headers(network, base_hash).await?;
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

        // Clear request controller state
        self.request_controller.clear_pending_requests();

        tracing::debug!("Reset sequential sync manager pending requests");
    }

    /// Fully reset the sync manager state to idle, used when sync initialization fails
    pub fn reset_to_idle(&mut self) {
        // First reset all pending requests
        self.reset_pending_requests();

        // Reset phase to idle
        self.current_phase = SyncPhase::Idle;

        // Clear sync start time
        self.sync_start_time = None;

        // Clear phase history
        self.phase_history.clear();

        tracing::info!("Reset sequential sync manager to idle state");
    }

    /// Helper method to get base hash from storage
    pub(super) async fn get_base_hash_from_storage(
        &self,
        storage: &S,
    ) -> SyncResult<Option<BlockHash>> {
        let current_tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?;

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
}
