//! Sequential synchronization manager for dash-spv
//!
//! This module implements a strict sequential sync pipeline where each phase
//! must complete 100% before the next phase begins.

pub mod phases;
pub mod progress;
pub mod recovery;
pub mod request_control;
pub mod transitions;

use std::ops::DerefMut;
use std::time::{Duration, Instant};

use dashcore::block::Header as BlockHeader;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::Inventory;
use dashcore::BlockHash;

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::{
    FilterSyncManager, HeaderSyncManagerWithReorg, MasternodeSyncManager, ReorgConfig,
};
use crate::types::ChainState;
use crate::types::{SharedFilterHeights, SyncProgress};
use key_wallet_manager::wallet_interface::WalletInterface;
use std::sync::Arc;
use tokio::sync::RwLock;

use phases::{PhaseTransition, SyncPhase};
use request_control::RequestController;
use transitions::TransitionManager;

/// Number of blocks back from a ChainLock's block height where we need the masternode list
/// for validation. ChainLock signatures are created by the masternode quorum that existed
/// 8 blocks before the ChainLock's block.
const CHAINLOCK_VALIDATION_MASTERNODE_OFFSET: u32 = 8;

/// Manages sequential synchronization of all data types
pub struct SequentialSyncManager<S: StorageManager, N: NetworkManager, W: WalletInterface> {
    _phantom_s: std::marker::PhantomData<S>,
    _phantom_n: std::marker::PhantomData<N>,
    /// Current synchronization phase
    current_phase: SyncPhase,

    /// Phase transition manager
    transition_manager: TransitionManager,

    /// Request controller for phase-aware request management
    request_controller: RequestController,

    /// Existing sync managers (wrapped and controlled)
    header_sync: HeaderSyncManagerWithReorg<S, N>,
    filter_sync: FilterSyncManager<S, N>,
    masternode_sync: MasternodeSyncManager<S, N>,

    /// Configuration
    config: ClientConfig,

    /// Phase transition history
    phase_history: Vec<PhaseTransition>,

    /// Start time of the entire sync process
    sync_start_time: Option<Instant>,

    /// Timeout duration for each phase
    phase_timeout: Duration,

    /// Maximum retries per phase before giving up
    max_phase_retries: u32,

    /// Current retry count for the active phase
    current_phase_retries: u32,

    /// Optional wallet reference for filter checking
    wallet: std::sync::Arc<tokio::sync::RwLock<W>>,
}

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
        wallet: std::sync::Arc<tokio::sync::RwLock<W>>,
        chain_state: Arc<RwLock<ChainState>>,
    ) -> SyncResult<Self> {
        // Create reorg config with sensible defaults
        let reorg_config = ReorgConfig::default();

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

    /// Get the current chain height from the header sync manager
    pub fn get_chain_height(&self) -> u32 {
        self.header_sync.get_chain_height()
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

    /// Execute the current sync phase
    async fn execute_current_phase(&mut self, network: &mut N, storage: &mut S) -> SyncResult<()> {
        match &self.current_phase {
            SyncPhase::DownloadingHeaders {
                ..
            } => {
                tracing::info!("📥 Starting header download phase");
                // Don't call start_sync if already prepared - just send the request
                if self.header_sync.is_syncing() {
                    // Already prepared, just send the initial request
                    let base_hash = self.get_base_hash_from_storage(storage).await?;

                    self.header_sync.request_headers(network, base_hash).await?;
                } else {
                    // Not prepared yet, start sync normally
                    self.header_sync.start_sync(network, storage).await?;
                }
            }

            SyncPhase::DownloadingMnList {
                ..
            } => {
                tracing::info!("📥 Starting masternode list download phase");
                // Get the effective chain height from header sync which accounts for checkpoint base
                let effective_height = self.header_sync.get_chain_height();
                let sync_base_height = self.header_sync.get_sync_base_height();

                // Also get the actual storage tip height to verify
                let storage_tip = storage
                    .get_tip_height()
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to get storage tip: {}", e)))?;

                // Debug: Check chain state
                let chain_state = storage.load_chain_state().await.map_err(|e| {
                    SyncError::Storage(format!("Failed to load chain state: {}", e))
                })?;
                let chain_state_height = chain_state.as_ref().map(|s| s.get_height()).unwrap_or(0);

                tracing::info!(
                    "Starting masternode sync: effective_height={}, sync_base={}, storage_tip={:?}, chain_state_height={}, expected_storage_index={}",
                    effective_height,
                    sync_base_height,
                    storage_tip,
                    chain_state_height,
                    if sync_base_height > 0 { effective_height.saturating_sub(sync_base_height) } else { effective_height }
                );

                // Use the minimum of effective height and what's actually in storage
                let _safe_height = if let Some(tip) = storage_tip {
                    let storage_based_height = sync_base_height + tip;
                    if storage_based_height < effective_height {
                        tracing::warn!(
                            "Chain state height {} exceeds storage height {}, using storage height",
                            effective_height,
                            storage_based_height
                        );
                        storage_based_height
                    } else {
                        effective_height
                    }
                } else {
                    effective_height
                };

                // Start masternode sync (unified processing)
                match self.masternode_sync.start_sync(network, storage).await {
                    Ok(_) => {
                        tracing::info!("🚀 Masternode sync initiated successfully, will complete when QRInfo arrives");
                    }
                    Err(e) => {
                        tracing::error!("❌ Failed to start masternode sync: {}", e);
                        return Err(e);
                    }
                }
            }

            SyncPhase::DownloadingCFHeaders {
                ..
            } => {
                tracing::info!("📥 Starting filter header download phase");

                // Get sync base height from header sync
                let sync_base_height = self.header_sync.get_sync_base_height();
                if sync_base_height > 0 {
                    tracing::info!(
                        "Setting filter sync base height to {} for checkpoint sync",
                        sync_base_height
                    );
                    self.filter_sync.set_sync_base_height(sync_base_height);
                }

                // Check if filter sync actually started
                let sync_started = self.filter_sync.start_sync_headers(network, storage).await?;

                if !sync_started {
                    // No peers support compact filters or already up to date
                    tracing::info!("Filter header sync not started (no peers support filters or already synced)");
                    // Transition to next phase immediately
                    self.transition_to_next_phase(
                        storage,
                        network,
                        "Filter sync skipped - no peer support",
                    )
                    .await?;
                    // Return early to let the main sync loop execute the next phase
                    return Ok(());
                }
            }

            SyncPhase::DownloadingFilters {
                ..
            } => {
                tracing::info!("📥 Starting filter download phase");

                // Get the range of filters to download
                // Note: get_filter_tip_height() now returns absolute blockchain height
                let filter_header_tip = storage
                    .get_filter_tip_height()
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to get filter tip: {}", e)))?
                    .unwrap_or(0);

                if filter_header_tip > 0 {
                    // Download all filters for complete blockchain history
                    // This ensures the wallet can find transactions from any point in history
                    let start_height = self.header_sync.get_sync_base_height().max(1);
                    let count = filter_header_tip - start_height + 1;

                    tracing::info!(
                        "Starting filter download from height {} to {} ({} filters)",
                        start_height,
                        filter_header_tip,
                        count
                    );

                    // Update the phase to track the expected total
                    if let SyncPhase::DownloadingFilters {
                        total_filters,
                        ..
                    } = &mut self.current_phase
                    {
                        *total_filters = count;
                    }

                    // Use the filter sync manager to download filters
                    self.filter_sync
                        .sync_filters_with_flow_control(
                            network,
                            storage,
                            Some(start_height),
                            Some(count),
                        )
                        .await?;
                } else {
                    // No filter headers available, skip to next phase
                    self.transition_to_next_phase(storage, network, "No filter headers available")
                        .await?;
                }
            }

            SyncPhase::DownloadingBlocks {
                ..
            } => {
                tracing::info!("📥 Starting block download phase");
                // Block download will be initiated based on filter matches
                // For now, we'll complete the sync
                self.transition_to_next_phase(storage, network, "No blocks to download").await?;
            }

            _ => {
                // Idle or FullySynced - nothing to execute
            }
        }

        Ok(())
    }

    /// Handle incoming network messages with phase filtering
    pub async fn handle_message(
        &mut self,
        message: NetworkMessage,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        // Special handling for blocks - they can arrive at any time due to filter matches
        if let NetworkMessage::Block(block) = message {
            // Always handle blocks when they arrive, regardless of phase
            // This is important because we request blocks when filters match
            tracing::info!(
                "📦 Received block {} (current phase: {})",
                block.block_hash(),
                self.current_phase.name()
            );

            // If we're in the DownloadingBlocks phase, handle it there
            return if matches!(self.current_phase, SyncPhase::DownloadingBlocks { .. }) {
                self.handle_block_message(block, network, storage).await
            } else if matches!(self.current_phase, SyncPhase::DownloadingMnList { .. }) {
                // During masternode sync, blocks are not processed
                tracing::debug!("Block received during MnList phase - ignoring");
                Ok(())
            } else {
                // Otherwise, just track that we received it but don't process for phase transitions
                // The block will be processed by the client's block processor
                tracing::debug!("Block received outside of DownloadingBlocks phase - will be processed by block processor");
                Ok(())
            };
        }

        // Check if this message is expected in the current phase
        if !self.is_message_expected_in_phase(&message) {
            tracing::debug!(
                "Ignoring unexpected {:?} message in phase {}",
                std::mem::discriminant(&message),
                self.current_phase.name()
            );
            return Ok(());
        }

        // Route to appropriate handler based on current phase
        match (&mut self.current_phase, message) {
            (
                SyncPhase::DownloadingHeaders {
                    ..
                },
                NetworkMessage::Headers(headers),
            ) => {
                self.handle_headers_message(headers, network, storage).await?;
            }

            (
                SyncPhase::DownloadingHeaders {
                    ..
                },
                NetworkMessage::Headers2(headers2),
            ) => {
                // Get the actual peer ID from the network manager
                let peer_id = network.get_last_message_peer_id().await;
                self.handle_headers2_message(headers2, peer_id, network, storage).await?;
            }

            (
                SyncPhase::DownloadingMnList {
                    ..
                },
                NetworkMessage::MnListDiff(diff),
            ) => {
                self.handle_mnlistdiff_message(diff, network, storage).await?;
            }

            (
                SyncPhase::DownloadingCFHeaders {
                    ..
                },
                NetworkMessage::CFHeaders(cfheaders),
            ) => {
                self.handle_cfheaders_message(cfheaders, network, storage).await?;
            }

            (
                SyncPhase::DownloadingFilters {
                    ..
                },
                NetworkMessage::CFilter(cfilter),
            ) => {
                self.handle_cfilter_message(cfilter, network, storage).await?;
            }

            // Handle headers when fully synced (from new block announcements)
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::Headers(headers),
            ) => {
                self.handle_new_headers(headers, network, storage).await?;
            }

            // Handle compressed headers when fully synced
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::Headers2(headers2),
            ) => {
                let peer_id = network.get_last_message_peer_id().await;
                self.handle_headers2_message(headers2, peer_id, network, storage).await?;
            }

            // Handle filter headers when fully synced
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::CFHeaders(cfheaders),
            ) => {
                self.handle_post_sync_cfheaders(cfheaders, network, storage).await?;
            }

            // Handle filters when fully synced
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::CFilter(cfilter),
            ) => {
                self.handle_post_sync_cfilter(cfilter, network, storage).await?;
            }

            // Handle masternode diffs when fully synced (for ChainLock validation)
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::MnListDiff(diff),
            ) => {
                self.handle_post_sync_mnlistdiff(diff, network, storage).await?;
            }

            // Handle QRInfo in masternode downloading phase
            (
                SyncPhase::DownloadingMnList {
                    ..
                },
                NetworkMessage::QRInfo(qr_info),
            ) => {
                self.handle_qrinfo_message(qr_info, network, storage).await?;
            }

            // Handle QRInfo when fully synced
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::QRInfo(qr_info),
            ) => {
                self.handle_qrinfo_message(qr_info, network, storage).await?;
            }

            _ => {
                tracing::debug!("Message type not handled in current phase");
            }
        }

        Ok(())
    }

    /// Check for timeouts and handle recovery
    pub async fn check_timeout(&mut self, network: &mut N, storage: &mut S) -> SyncResult<()> {
        // First check if the current phase needs to be executed (e.g., after a transition)
        if self.current_phase_needs_execution() {
            tracing::info!("Executing phase {} after transition", self.current_phase.name());
            self.execute_current_phase(network, storage).await?;
            return Ok(());
        }

        if let Some(last_progress) = self.current_phase.last_progress_time() {
            if last_progress.elapsed() > self.phase_timeout {
                tracing::warn!(
                    "⏰ Phase {} timed out after {:?}",
                    self.current_phase.name(),
                    self.phase_timeout
                );

                // Attempt recovery
                self.recover_from_timeout(network, storage).await?;
            }
        }

        // Also check phase-specific timeouts
        match &self.current_phase {
            SyncPhase::DownloadingHeaders {
                ..
            } => {
                self.header_sync.check_sync_timeout(storage, network).await?;
            }
            SyncPhase::DownloadingCFHeaders {
                ..
            } => {
                self.filter_sync.check_sync_timeout(storage, network).await?;
            }
            SyncPhase::DownloadingMnList {
                ..
            } => {
                self.masternode_sync.check_sync_timeout(storage, network).await?;
            }
            SyncPhase::DownloadingFilters {
                ..
            } => {
                // Always check for timed out filter requests, not just during phase timeout
                self.filter_sync.check_filter_request_timeouts(network, storage).await?;

                // For filter downloads, we need custom timeout handling
                // since the filter sync manager's timeout is for filter headers
                if let Some(last_progress) = self.current_phase.last_progress_time() {
                    if last_progress.elapsed() > self.phase_timeout {
                        tracing::warn!(
                            "⏰ Filter download phase timed out after {:?}",
                            self.phase_timeout
                        );

                        // Check if we have any active requests
                        let active_count = self.filter_sync.active_request_count();
                        let pending_count = self.filter_sync.pending_download_count();

                        tracing::warn!(
                            "Filter sync status: {} active requests, {} pending",
                            active_count,
                            pending_count
                        );

                        // First check for timed out filter requests
                        self.filter_sync.check_filter_request_timeouts(network, storage).await?;

                        // Try to recover by sending more requests if we have pending ones
                        if self.filter_sync.has_pending_filter_requests() && active_count < 10 {
                            tracing::info!("Attempting to recover by sending more filter requests");
                            self.filter_sync.send_next_filter_batch(network).await?;
                            self.current_phase.update_progress();
                        } else if active_count == 0
                            && !self.filter_sync.has_pending_filter_requests()
                        {
                            // No active requests and no pending - we're stuck
                            tracing::error!(
                                "Filter sync stalled with no active or pending requests"
                            );

                            // Check if we received some filters but not all
                            let received_count = self.filter_sync.get_received_filter_count();
                            if let SyncPhase::DownloadingFilters {
                                total_filters,
                                ..
                            } = &self.current_phase
                            {
                                if received_count > 0 && received_count < *total_filters {
                                    tracing::warn!(
                                        "Filter sync stalled at {}/{} filters - attempting recovery",
                                        received_count, total_filters
                                    );

                                    // Retry the entire filter sync phase
                                    self.current_phase_retries += 1;
                                    if self.current_phase_retries <= self.max_phase_retries {
                                        tracing::info!(
                                            "🔄 Retrying filter sync (attempt {}/{})",
                                            self.current_phase_retries,
                                            self.max_phase_retries
                                        );

                                        // Clear the filter sync state and restart
                                        self.filter_sync.reset();
                                        self.filter_sync.syncing_filters = false; // Allow restart

                                        // Update progress to prevent immediate timeout
                                        self.current_phase.update_progress();

                                        // Re-execute the phase
                                        self.execute_current_phase(network, storage).await?;
                                        return Ok(());
                                    } else {
                                        tracing::error!(
                                            "Filter sync failed after {} retries, forcing completion",
                                            self.max_phase_retries
                                        );
                                    }
                                }
                            }

                            // Force transition to next phase to avoid permanent stall
                            self.transition_to_next_phase(
                                storage,
                                network,
                                "Filter sync timeout - forcing completion",
                            )
                            .await?;
                            self.execute_current_phase(network, storage).await?;
                        }
                    }
                }
            }
            _ => {}
        }

        Ok(())
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
            headers_synced: matches!(
                self.current_phase,
                SyncPhase::DownloadingHeaders { .. } | SyncPhase::FullySynced { .. }
            ),
            header_height: 0, // PLACEHOLDER: Caller MUST query storage.get_tip_height()
            filter_headers_synced: matches!(
                self.current_phase,
                SyncPhase::DownloadingCFHeaders { .. } | SyncPhase::FullySynced { .. }
            ),
            filter_header_height: 0, // PLACEHOLDER: Caller MUST query storage.get_filter_tip_height()
            masternodes_synced: matches!(
                self.current_phase,
                SyncPhase::DownloadingMnList { .. } | SyncPhase::FullySynced { .. }
            ),
            masternode_height: 0, // PLACEHOLDER: Caller MUST query masternode state from storage
            peer_count: 0,        // PLACEHOLDER: Caller MUST query network.peer_count()
            filters_downloaded: 0, // PLACEHOLDER: Caller MUST calculate from storage
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
    fn current_phase_needs_execution(&self) -> bool {
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

    // Private helper methods

    /// Check if a message is expected in the current phase
    fn is_message_expected_in_phase(&self, message: &NetworkMessage) -> bool {
        match (&self.current_phase, message) {
            (
                SyncPhase::DownloadingHeaders {
                    ..
                },
                NetworkMessage::Headers(_),
            ) => true,
            (
                SyncPhase::DownloadingHeaders {
                    ..
                },
                NetworkMessage::Headers2(_),
            ) => true,
            (
                SyncPhase::DownloadingMnList {
                    ..
                },
                NetworkMessage::MnListDiff(_),
            ) => true,
            (
                SyncPhase::DownloadingMnList {
                    ..
                },
                NetworkMessage::QRInfo(_),
            ) => true, // Allow QRInfo during masternode sync
            (
                SyncPhase::DownloadingMnList {
                    ..
                },
                NetworkMessage::Block(_),
            ) => true, // Allow blocks during masternode sync
            (
                SyncPhase::DownloadingCFHeaders {
                    ..
                },
                NetworkMessage::CFHeaders(_),
            ) => true,
            (
                SyncPhase::DownloadingFilters {
                    ..
                },
                NetworkMessage::CFilter(_),
            ) => true,
            (
                SyncPhase::DownloadingBlocks {
                    ..
                },
                NetworkMessage::Block(_),
            ) => true,
            // During FullySynced phase, we need to accept sync maintenance messages
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::Headers(_),
            ) => true,
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::Headers2(_),
            ) => true,
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::CFHeaders(_),
            ) => true,
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::CFilter(_),
            ) => true,
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::MnListDiff(_),
            ) => true,
            (
                SyncPhase::FullySynced {
                    ..
                },
                NetworkMessage::QRInfo(_),
            ) => true, // Allow QRInfo when fully synced
            _ => false,
        }
    }

    /// Transition to the next phase
    async fn transition_to_next_phase(
        &mut self,
        storage: &mut S,
        network: &N,
        reason: &str,
    ) -> SyncResult<()> {
        // Get the next phase
        let next_phase =
            self.transition_manager.get_next_phase(&self.current_phase, storage, network).await?;

        if let Some(next) = next_phase {
            // Check if transition is allowed
            if !self
                .transition_manager
                .can_transition_to(&self.current_phase, &next, storage)
                .await?
            {
                return Err(SyncError::Validation(format!(
                    "Invalid phase transition from {} to {}",
                    self.current_phase.name(),
                    next.name()
                )));
            }

            // Create transition record
            let transition = self.transition_manager.create_transition(
                &self.current_phase,
                &next,
                reason.to_string(),
            );

            tracing::info!(
                "🔄 Phase transition: {} → {} (reason: {})",
                transition.from_phase,
                transition.to_phase,
                transition.reason
            );

            // Log final progress of the phase
            if let Some(ref progress) = transition.final_progress {
                tracing::info!(
                    "📊 Phase {} completed: {} items in {:?} ({:.1} items/sec)",
                    transition.from_phase,
                    progress.items_completed,
                    progress.elapsed,
                    progress.rate
                );
            }

            self.phase_history.push(transition);
            self.current_phase = next;
            self.current_phase_retries = 0;

            // Start the next phase
            // Note: We can't execute the next phase here as we don't have network access
            // The caller will need to execute the next phase
        } else {
            tracing::info!("✅ Sequential sync complete!");

            // Calculate total sync stats
            if let Some(start_time) = self.sync_start_time {
                let total_time = start_time.elapsed();
                let headers_synced = self.calculate_total_headers_synced();
                let filters_synced = self.calculate_total_filters_synced();
                let blocks_downloaded = self.calculate_total_blocks_downloaded();

                self.current_phase = SyncPhase::FullySynced {
                    sync_completed_at: Instant::now(),
                    total_sync_time: total_time,
                    headers_synced,
                    filters_synced,
                    blocks_downloaded,
                };

                tracing::info!(
                    "🎉 Sync completed in {:?} - {} headers, {} filters, {} blocks",
                    total_time,
                    headers_synced,
                    filters_synced,
                    blocks_downloaded
                );
            }
        }

        Ok(())
    }

    /// Recover from a timeout
    async fn recover_from_timeout(&mut self, network: &mut N, storage: &mut S) -> SyncResult<()> {
        self.current_phase_retries += 1;

        if self.current_phase_retries > self.max_phase_retries {
            return Err(SyncError::Timeout(format!(
                "Phase {} failed after {} retries",
                self.current_phase.name(),
                self.max_phase_retries
            )));
        }

        tracing::warn!(
            "🔄 Retrying phase {} (attempt {}/{})",
            self.current_phase.name(),
            self.current_phase_retries,
            self.max_phase_retries
        );

        // Update progress time to prevent immediate re-timeout
        self.current_phase.update_progress();

        // Execute phase-specific recovery
        match &self.current_phase {
            SyncPhase::DownloadingHeaders {
                ..
            } => {
                self.header_sync.check_sync_timeout(storage, network).await?;
            }
            SyncPhase::DownloadingMnList {
                ..
            } => {
                self.masternode_sync.check_sync_timeout(storage, network).await?;
            }
            SyncPhase::DownloadingCFHeaders {
                ..
            } => {
                self.filter_sync.check_sync_timeout(storage, network).await?;
            }
            _ => {
                // For other phases, we'll need phase-specific recovery
            }
        }

        Ok(())
    }

    // Message handlers for each phase

    async fn handle_headers2_message(
        &mut self,
        headers2: dashcore::network::message_headers2::Headers2Message,
        peer_id: crate::types::PeerId,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        let continue_sync = match self
            .header_sync
            .handle_headers2_message(headers2, peer_id, storage, network)
            .await
        {
            Ok(continue_sync) => continue_sync,
            Err(SyncError::Headers2DecompressionFailed(e)) => {
                // Headers2 decompression failed - we should fall back to regular headers
                tracing::warn!("Headers2 decompression failed: {} - peer may not properly support headers2 or connection issue", e);
                // For now, just return the error. In the future, we could trigger a fallback here
                return Err(SyncError::Headers2DecompressionFailed(e));
            }
            Err(e) => return Err(e),
        };

        // Calculate blockchain height before borrowing self.current_phase
        let blockchain_height = self.get_blockchain_height_from_storage(storage).await.unwrap_or(0);

        // Update phase state and check if we need to transition
        let should_transition = if let SyncPhase::DownloadingHeaders {
            current_height,

            last_progress,
            ..
        } = &mut self.current_phase
        {
            // Update current height - use blockchain height for checkpoint awareness
            *current_height = blockchain_height;

            // Note: We can't easily track headers_downloaded for compressed headers
            // without decompressing first, so we rely on the header sync manager's internal stats

            // Update progress time
            *last_progress = Instant::now();

            // Check if phase is complete
            !continue_sync
        } else {
            false
        };

        if should_transition {
            self.transition_to_next_phase(storage, network, "Headers sync complete via Headers2")
                .await?;

            // Execute the next phase
            self.execute_current_phase(network, storage).await?;
        }

        Ok(())
    }

    async fn handle_headers_message(
        &mut self,
        headers: Vec<dashcore::block::Header>,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        let continue_sync =
            self.header_sync.handle_headers_message(headers.clone(), storage, network).await?;

        // Calculate blockchain height before borrowing self.current_phase
        let blockchain_height = self.get_blockchain_height_from_storage(storage).await.unwrap_or(0);

        // Update phase state and check if we need to transition
        let should_transition = if let SyncPhase::DownloadingHeaders {
            current_height,
            headers_downloaded,
            start_time,
            headers_per_second,
            received_empty_response,
            last_progress,
            ..
        } = &mut self.current_phase
        {
            // Update current height - use blockchain height for checkpoint awareness
            *current_height = blockchain_height;

            // Update progress
            *headers_downloaded += headers.len() as u32;
            let elapsed = start_time.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                *headers_per_second = *headers_downloaded as f64 / elapsed;
            }

            // Check if we received empty response (sync complete)
            if headers.is_empty() {
                *received_empty_response = true;
            }

            // Update progress time
            *last_progress = Instant::now();

            // Check if phase is complete
            !continue_sync || *received_empty_response
        } else {
            false
        };

        if should_transition {
            self.transition_to_next_phase(storage, network, "Headers sync complete").await?;

            // Execute the next phase
            self.execute_current_phase(network, storage).await?;
        }

        Ok(())
    }

    async fn handle_mnlistdiff_message(
        &mut self,
        diff: dashcore::network::message_sml::MnListDiff,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        let continue_sync =
            self.masternode_sync.handle_mnlistdiff_message(diff, storage, network).await?;

        // Update phase state
        if let SyncPhase::DownloadingMnList {
            current_height,
            diffs_processed,
            ..
        } = &mut self.current_phase
        {
            // Update current height from storage
            if let Ok(Some(state)) = storage.load_masternode_state().await {
                *current_height = state.last_height;
            }

            *diffs_processed += 1;
            self.current_phase.update_progress();

            // Check if phase is complete
            if !continue_sync {
                // Masternode sync has completed - ensure phase state reflects this
                // by updating target_height to match current_height before transition
                if let SyncPhase::DownloadingMnList {
                    current_height,
                    target_height,
                    ..
                } = &mut self.current_phase
                {
                    // Force completion state by ensuring current >= target
                    if *current_height < *target_height {
                        *target_height = *current_height;
                    }
                }

                self.transition_to_next_phase(storage, network, "Masternode sync complete").await?;

                // Execute the next phase
                self.execute_current_phase(network, storage).await?;
            }
        }

        Ok(())
    }

    async fn handle_qrinfo_message(
        &mut self,
        qr_info: dashcore::network::message_qrinfo::QRInfo,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        tracing::info!("🔄 Sequential sync manager handling QRInfo message (unified processing)");

        // Get sync base height for height conversion
        let sync_base_height = self.header_sync.get_sync_base_height();
        tracing::debug!(
            "Using sync_base_height={} for masternode validation height conversion",
            sync_base_height
        );

        // Process QRInfo with full block height feeding and comprehensive processing
        self.masternode_sync
            .handle_qrinfo_message(qr_info.clone(), storage, network, sync_base_height)
            .await;

        // Check if QRInfo processing completed successfully
        if let Some(error) = self.masternode_sync.last_error() {
            tracing::error!("❌ QRInfo processing failed: {}", error);
            return Err(SyncError::Validation(error.to_string()));
        }

        // Update phase state - QRInfo processing should complete the masternode sync phase
        if let SyncPhase::DownloadingMnList {
            current_height,
            diffs_processed,
            ..
        } = &mut self.current_phase
        {
            // Update current height from storage
            if let Ok(Some(state)) = storage.load_masternode_state().await {
                *current_height = state.last_height;
            }
            *diffs_processed += 1;
            self.current_phase.update_progress();

            tracing::info!("✅ QRInfo processing completed, masternode sync phase finished");

            // Transition to next phase (filter headers)
            self.transition_to_next_phase(storage, network, "QRInfo processing completed").await?;
        }

        Ok(())
    }

    async fn handle_cfheaders_message(
        &mut self,
        cfheaders: dashcore::network::message_filter::CFHeaders,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        // Log source peer for CFHeaders batches when possible
        if let Some(addr) = network.get_last_message_peer_addr().await {
            tracing::debug!(
                "📨 Received CFHeaders ({} headers) from {} (stop_hash={})",
                cfheaders.filter_hashes.len(),
                addr,
                cfheaders.stop_hash
            );
        }
        let continue_sync =
            self.filter_sync.handle_cfheaders_message(cfheaders.clone(), storage, network).await?;

        // Update phase state
        if let SyncPhase::DownloadingCFHeaders {
            current_height,
            cfheaders_downloaded,
            start_time,
            cfheaders_per_second,
            ..
        } = &mut self.current_phase
        {
            // Update current height
            if let Ok(Some(tip)) = storage.get_filter_tip_height().await {
                *current_height = tip;
            }

            // Update progress
            *cfheaders_downloaded += cfheaders.filter_hashes.len() as u32;
            let elapsed = start_time.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                *cfheaders_per_second = *cfheaders_downloaded as f64 / elapsed;
            }

            self.current_phase.update_progress();

            // Check if phase is complete
            if !continue_sync {
                self.transition_to_next_phase(storage, network, "Filter headers sync complete")
                    .await?;

                // Execute the next phase
                self.execute_current_phase(network, storage).await?;
            }
        }

        Ok(())
    }

    async fn handle_cfilter_message(
        &mut self,
        cfilter: dashcore::network::message_filter::CFilter,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        // Include peer address when available for diagnostics
        let peer_addr = network.get_last_message_peer_addr().await;
        match peer_addr {
            Some(addr) => {
                tracing::debug!(
                    "📨 Received CFilter for block {} from {}",
                    cfilter.block_hash,
                    addr
                );
            }
            None => {
                tracing::debug!("📨 Received CFilter for block {}", cfilter.block_hash);
            }
        }

        let mut wallet = self.wallet.write().await;

        // Check filter against wallet if available
        let matches = self
            .filter_sync
            .check_filter_for_matches(
                &cfilter.filter,
                &cfilter.block_hash,
                wallet.deref_mut(),
                self.config.network,
            )
            .await?;

        drop(wallet);

        if matches {
            tracing::info!("🎯 Filter match found! Requesting block {}", cfilter.block_hash);
            // Request the full block
            let inv = Inventory::Block(cfilter.block_hash);
            network
                .send_message(NetworkMessage::GetData(vec![inv]))
                .await
                .map_err(|e| SyncError::Network(format!("Failed to request block: {}", e)))?;
        }

        // Handle filter message tracking
        let completed_ranges =
            self.filter_sync.mark_filter_received(cfilter.block_hash, storage).await?;

        // Process any newly completed ranges
        if !completed_ranges.is_empty() {
            tracing::debug!("Completed {} filter request ranges", completed_ranges.len());

            // Send more filter requests from the queue if we have available slots
            if self.filter_sync.has_pending_filter_requests() {
                let available_slots = self.filter_sync.get_available_request_slots();
                if available_slots > 0 {
                    tracing::debug!(
                        "Sending more filter requests: {} slots available, {} pending",
                        available_slots,
                        self.filter_sync.pending_download_count()
                    );
                    self.filter_sync.send_next_filter_batch(network).await?;
                } else {
                    tracing::trace!(
                        "No available slots for more filter requests (all {} slots in use)",
                        self.filter_sync.active_request_count()
                    );
                }
            } else {
                tracing::trace!("No more pending filter requests in queue");
            }
        }

        // Update phase state
        if let SyncPhase::DownloadingFilters {
            completed_heights,
            batches_processed,
            total_filters,
            ..
        } = &mut self.current_phase
        {
            // Mark this height as completed
            if let Ok(Some(height)) = storage.get_header_height_by_hash(&cfilter.block_hash).await {
                completed_heights.insert(height);

                // Log progress periodically
                if completed_heights.len() % 100 == 0
                    || completed_heights.len() == *total_filters as usize
                {
                    tracing::info!(
                        "📊 Filter download progress: {}/{} filters received",
                        completed_heights.len(),
                        total_filters
                    );
                }
            }

            *batches_processed += 1;
            self.current_phase.update_progress();

            // Check if all filters are downloaded
            // We need to track actual completion, not just request status
            if let SyncPhase::DownloadingFilters {
                total_filters,
                completed_heights,
                ..
            } = &self.current_phase
            {
                // For flow control, we need to check:
                // 1. All expected filters have been received (completed_heights matches total_filters)
                // 2. No more active or pending requests
                let has_pending = self.filter_sync.pending_download_count() > 0
                    || self.filter_sync.active_request_count() > 0;

                let all_received =
                    *total_filters > 0 && completed_heights.len() >= *total_filters as usize;

                // Only transition when we've received all filters AND no requests are pending
                if all_received && !has_pending {
                    tracing::info!(
                        "All {} filters received and processed",
                        completed_heights.len()
                    );
                    self.transition_to_next_phase(storage, network, "All filters downloaded")
                        .await?;

                    // Execute the next phase
                    self.execute_current_phase(network, storage).await?;
                } else if *total_filters == 0 && !has_pending {
                    // Edge case: no filters to download
                    self.transition_to_next_phase(storage, network, "No filters to download")
                        .await?;

                    // Execute the next phase
                    self.execute_current_phase(network, storage).await?;
                } else {
                    tracing::trace!(
                        "Filter sync progress: {}/{} received, {} active requests",
                        completed_heights.len(),
                        total_filters,
                        self.filter_sync.active_request_count()
                    );
                }
            }
        }

        Ok(())
    }

    async fn handle_block_message(
        &mut self,
        block: dashcore::block::Block,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        let block_hash = block.block_hash();

        // Process the block through the wallet if available
        let mut wallet = self.wallet.write().await;

        // Get the block height from storage
        let block_height = storage
            .get_header_height_by_hash(&block_hash)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get block height: {}", e)))?
            .unwrap_or(0);

        let relevant_txids = wallet.process_block(&block, block_height, self.config.network).await;

        drop(wallet);

        if !relevant_txids.is_empty() {
            tracing::info!(
                "💰 Found {} relevant transactions in block {} at height {}",
                relevant_txids.len(),
                block_hash,
                block_height
            );
            for txid in &relevant_txids {
                tracing::debug!("  - Transaction: {}", txid);
            }
        }

        // Handle block download and check if we need to transition
        let should_transition = if let SyncPhase::DownloadingBlocks {
            downloading,
            completed,
            last_progress,
            ..
        } = &mut self.current_phase
        {
            // Remove from downloading
            downloading.remove(&block_hash);

            // Add to completed
            completed.push(block_hash);

            // Update progress time
            *last_progress = Instant::now();

            // Check if all blocks are downloaded
            downloading.is_empty() && self.no_more_pending_blocks()
        } else {
            false
        };

        if should_transition {
            self.transition_to_next_phase(storage, network, "All blocks downloaded").await?;

            // Execute the next phase (if any)
            self.execute_current_phase(network, storage).await?;
        }

        Ok(())
    }

    // Helper methods for calculating totals

    fn calculate_total_headers_synced(&self) -> u32 {
        self.phase_history
            .iter()
            .find(|t| t.from_phase == "Downloading Headers")
            .and_then(|t| t.final_progress.as_ref())
            .map(|p| p.items_completed)
            .unwrap_or(0)
    }

    fn calculate_total_filters_synced(&self) -> u32 {
        self.phase_history
            .iter()
            .find(|t| t.from_phase == "Downloading Filters")
            .and_then(|t| t.final_progress.as_ref())
            .map(|p| p.items_completed)
            .unwrap_or(0)
    }

    fn calculate_total_blocks_downloaded(&self) -> u32 {
        self.phase_history
            .iter()
            .find(|t| t.from_phase == "Downloading Blocks")
            .and_then(|t| t.final_progress.as_ref())
            .map(|p| p.items_completed)
            .unwrap_or(0)
    }

    fn no_more_pending_blocks(&self) -> bool {
        // This would check if there are more blocks to download
        // For now, return true
        true
    }

    /// Helper method to get base hash from storage
    async fn get_base_hash_from_storage(&self, storage: &S) -> SyncResult<Option<BlockHash>> {
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

    /// Handle inventory messages for sequential sync
    pub async fn handle_inventory(
        &mut self,
        inv: Vec<Inventory>,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        // Only process inventory when we're fully synced
        if !matches!(self.current_phase, SyncPhase::FullySynced { .. }) {
            tracing::debug!("Ignoring inventory during sync phase: {}", self.current_phase.name());
            return Ok(());
        }

        // Process inventory items
        for inv_item in inv {
            match inv_item {
                Inventory::Block(block_hash) => {
                    tracing::info!("📨 New block announced: {}", block_hash);

                    // Get our current tip to use as locator - use the helper method
                    let base_hash = self.get_base_hash_from_storage(storage).await?;

                    // Build locator hashes based on base hash
                    let locator_hashes = match base_hash {
                        Some(hash) => {
                            tracing::info!("📍 Using tip hash as locator: {}", hash);
                            vec![hash]
                        }
                        None => {
                            // No headers found - this should only happen on initial sync
                            tracing::info!("📍 No headers found in storage, using empty locator for initial sync");
                            Vec::new()
                        }
                    };

                    // Request headers starting from our tip
                    // Use the same protocol version as during initial sync
                    let get_headers = NetworkMessage::GetHeaders(
                        dashcore::network::message_blockdata::GetHeadersMessage {
                            version: dashcore::network::constants::PROTOCOL_VERSION,
                            locator_hashes,
                            stop_hash: BlockHash::from_raw_hash(dashcore::hashes::Hash::all_zeros()),
                        },
                    );

                    tracing::info!(
                        "📤 Sending GetHeaders with protocol version {}",
                        dashcore::network::constants::PROTOCOL_VERSION
                    );
                    network.send_message(get_headers).await.map_err(|e| {
                        SyncError::Network(format!("Failed to request headers: {}", e))
                    })?;

                    // After we receive the header, we'll need to:
                    // 1. Request filter headers
                    // 2. Request the filter
                    // 3. Check if it matches
                    // 4. Request the block if it matches
                }

                Inventory::ChainLock(chainlock_hash) => {
                    tracing::info!("🔒 ChainLock announced: {}", chainlock_hash);
                    // Request the ChainLock
                    let get_data =
                        NetworkMessage::GetData(vec![Inventory::ChainLock(chainlock_hash)]);
                    network.send_message(get_data).await.map_err(|e| {
                        SyncError::Network(format!("Failed to request chainlock: {}", e))
                    })?;

                    // ChainLocks can help us detect if we're behind
                    // The ChainLock handler will check if we need to catch up
                }

                Inventory::InstantSendLock(islock_hash) => {
                    tracing::info!("⚡ InstantSend lock announced: {}", islock_hash);
                    // Request the InstantSend lock
                    let get_data =
                        NetworkMessage::GetData(vec![Inventory::InstantSendLock(islock_hash)]);
                    network.send_message(get_data).await.map_err(|e| {
                        SyncError::Network(format!("Failed to request islock: {}", e))
                    })?;
                }

                Inventory::Transaction(txid) => {
                    // We don't track individual transactions in SPV mode
                    tracing::debug!("Transaction announced: {} (ignored)", txid);
                }

                _ => {
                    tracing::debug!("Unhandled inventory type: {:?}", inv_item);
                }
            }
        }

        Ok(())
    }

    /// Handle new headers that arrive after initial sync (from inventory)
    pub async fn handle_new_headers(
        &mut self,
        headers: Vec<BlockHeader>,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        // Only process new headers when we're fully synced
        if !matches!(self.current_phase, SyncPhase::FullySynced { .. }) {
            tracing::debug!(
                "Ignoring headers - not in FullySynced phase (current: {})",
                self.current_phase.name()
            );
            return Ok(());
        }

        if headers.is_empty() {
            tracing::debug!("No new headers to process");
            // Check if we might be behind based on ChainLocks we've seen
            // This is handled elsewhere, so just return for now
            return Ok(());
        }

        tracing::info!("📥 Processing {} new headers after sync", headers.len());
        tracing::info!(
            "🔗 First header: {} Last header: {}",
            headers.first().map(|h| h.block_hash().to_string()).unwrap_or_default(),
            headers.last().map(|h| h.block_hash().to_string()).unwrap_or_default()
        );

        // Store the new headers
        storage
            .store_headers(&headers)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to store headers: {}", e)))?;

        // First, check if we need to catch up on masternode lists for ChainLock validation
        if self.config.enable_masternodes && !headers.is_empty() {
            // Get the current masternode state to check for gaps
            let mn_state = storage.load_masternode_state().await.map_err(|e| {
                SyncError::Storage(format!("Failed to load masternode state: {}", e))
            })?;

            if let Some(state) = mn_state {
                // Get the height of the first new header
                let first_height = storage
                    .get_header_height_by_hash(&headers[0].block_hash())
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to get block height: {}", e)))?
                    .ok_or(SyncError::InvalidState("Failed to get block height".to_string()))?;

                // Check if we have a gap (masternode lists are more than 1 block behind)
                if state.last_height + 1 < first_height {
                    let gap_size = first_height - state.last_height - 1;
                    tracing::warn!(
                        "⚠️ Detected gap in masternode lists: last height {} vs new block {}, gap of {} blocks",
                        state.last_height,
                        first_height,
                        gap_size
                    );

                    // Request catch-up masternode diff for the gap
                    // We need to ensure we have lists for at least the last 8 blocks for ChainLock validation
                    let catch_up_start = state.last_height;
                    let catch_up_end = first_height.saturating_sub(1);

                    if catch_up_end > catch_up_start {
                        let base_hash = storage
                            .get_header(catch_up_start)
                            .await
                            .map_err(|e| {
                                SyncError::Storage(format!(
                                    "Failed to get catch-up base block: {}",
                                    e
                                ))
                            })?
                            .map(|h| h.block_hash())
                            .ok_or(SyncError::InvalidState(
                                "Catch-up base block not found".to_string(),
                            ))?;

                        let stop_hash = storage
                            .get_header(catch_up_end)
                            .await
                            .map_err(|e| {
                                SyncError::Storage(format!(
                                    "Failed to get catch-up stop block: {}",
                                    e
                                ))
                            })?
                            .map(|h| h.block_hash())
                            .ok_or(SyncError::InvalidState(
                                "Catch-up stop block not found".to_string(),
                            ))?;

                        tracing::info!(
                            "📋 Requesting catch-up masternode diff from height {} to {} to fill gap",
                            catch_up_start,
                            catch_up_end
                        );

                        let catch_up_request = NetworkMessage::GetMnListD(
                            dashcore::network::message_sml::GetMnListDiff {
                                base_block_hash: base_hash,
                                block_hash: stop_hash,
                            },
                        );

                        network.send_message(catch_up_request).await.map_err(|e| {
                            SyncError::Network(format!(
                                "Failed to request catch-up masternode diff: {}",
                                e
                            ))
                        })?;
                    }
                }
            }
        }

        for header in &headers {
            let height = storage
                .get_header_height_by_hash(&header.block_hash())
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get block height: {}", e)))?
                .ok_or(SyncError::InvalidState("Failed to get block height".to_string()))?;

            // The height from storage is already the absolute blockchain height
            let blockchain_height = height;

            tracing::info!("📦 New block at height {}: {}", blockchain_height, header.block_hash());

            // If we have masternodes enabled, request masternode list updates for ChainLock validation
            if self.config.enable_masternodes {
                // For ChainLock validation, we need masternode lists at (block_height - CHAINLOCK_VALIDATION_MASTERNODE_OFFSET)
                // We request the masternode diff for each new block (not just offset blocks) to maintain a complete rolling window
                let base_block_hash = if height > 0 {
                    // Get the previous block hash
                    storage
                        .get_header(height - 1)
                        .await
                        .map_err(|e| {
                            SyncError::Storage(format!("Failed to get previous block: {}", e))
                        })?
                        .map(|h| h.block_hash())
                        .ok_or(SyncError::InvalidState("Previous block not found".to_string()))?
                } else {
                    // Genesis block case
                    dashcore::blockdata::constants::genesis_block(self.config.network).block_hash()
                };

                tracing::info!(
                    "📋 Requesting masternode list diff for block at height {} to maintain ChainLock validation window",
                    blockchain_height
                );

                let getmnlistdiff =
                    NetworkMessage::GetMnListD(dashcore::network::message_sml::GetMnListDiff {
                        base_block_hash,
                        block_hash: header.block_hash(),
                    });

                network.send_message(getmnlistdiff).await.map_err(|e| {
                    SyncError::Network(format!("Failed to request masternode diff: {}", e))
                })?;

                // The masternode diff will arrive via handle_message and be processed by masternode_sync
            }

            // If we have filters enabled, request filter headers for the new blocks
            if self.config.enable_filters {
                // Request filter headers for the new block
                let stop_hash = header.block_hash();
                let start_height = height.saturating_sub(1);

                tracing::info!(
                    "📋 Requesting filter headers for block at height {} (start: {}, stop: {})",
                    blockchain_height,
                    start_height,
                    stop_hash
                );

                let get_cfheaders =
                    NetworkMessage::GetCFHeaders(dashcore::network::message_filter::GetCFHeaders {
                        filter_type: 0, // Basic filter
                        start_height,
                        stop_hash,
                    });

                network.send_message(get_cfheaders).await.map_err(|e| {
                    SyncError::Network(format!("Failed to request filter headers: {}", e))
                })?;

                // The filter headers will arrive via handle_message
                // Then we'll request the actual filter
                // Then check if it matches our watch items
                // Then request the block if it matches
            }
        }

        Ok(())
    }

    /// Handle filter headers that arrive after initial sync
    async fn handle_post_sync_cfheaders(
        &mut self,
        cfheaders: dashcore::network::message_filter::CFHeaders,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        tracing::info!("📥 Processing filter headers for new block after sync");

        // Store the filter headers
        let stop_hash = cfheaders.stop_hash;
        self.filter_sync.store_filter_headers(cfheaders, storage).await?;

        // Get the height of the stop_hash
        if let Some(height) = storage
            .get_header_height_by_hash(&stop_hash)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get filter header height: {}", e)))?
        {
            // Request the actual filter for this block
            let get_cfilters =
                NetworkMessage::GetCFilters(dashcore::network::message_filter::GetCFilters {
                    filter_type: 0, // Basic filter
                    start_height: height,
                    stop_hash,
                });

            network
                .send_message(get_cfilters)
                .await
                .map_err(|e| SyncError::Network(format!("Failed to request filters: {}", e)))?;
        }

        Ok(())
    }

    /// Handle filters that arrive after initial sync
    async fn handle_post_sync_cfilter(
        &mut self,
        cfilter: dashcore::network::message_filter::CFilter,
        _network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        tracing::info!("📥 Processing filter for new block after sync");

        // Get the height for this filter's block
        let height = storage
            .get_header_height_by_hash(&cfilter.block_hash)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get filter block height: {}", e)))?
            .ok_or(SyncError::InvalidState("Filter block height not found".to_string()))?;

        // Store the filter
        storage
            .store_filter(height, &cfilter.filter)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to store filter: {}", e)))?;

        // TODO: Check filter against wallet instead of watch items
        // This will be integrated with wallet's check_compact_filter method
        tracing::debug!("Filter checking disabled until wallet integration is complete");

        Ok(())
    }

    /// Handle masternode list diffs that arrive after initial sync (for ChainLock validation)
    async fn handle_post_sync_mnlistdiff(
        &mut self,
        diff: dashcore::network::message_sml::MnListDiff,
        network: &mut N,
        storage: &mut S,
    ) -> SyncResult<()> {
        // Get block heights for better logging (get_header_height_by_hash returns blockchain heights)
        let base_blockchain_height =
            storage.get_header_height_by_hash(&diff.base_block_hash).await.ok().flatten();
        let target_blockchain_height =
            storage.get_header_height_by_hash(&diff.block_hash).await.ok().flatten();

        // Determine if we're syncing from a checkpoint for height conversion
        let is_ckpt = self.header_sync.is_synced_from_checkpoint();
        let sync_base = self.header_sync.get_sync_base_height();

        tracing::info!(
            "📥 Processing post-sync masternode diff for block {} at height {:?} (base: {} at height {:?})",
            diff.block_hash,
            target_blockchain_height,
            diff.base_block_hash,
            base_blockchain_height
        );

        // Process the diff through the masternode sync manager
        // This will update the masternode engine's state
        self.masternode_sync.handle_mnlistdiff_message(diff, storage, network).await?;

        // Log the current masternode state after update
        if let Ok(Some(mn_state)) = storage.load_masternode_state().await {
            // Convert masternode storage height to blockchain height
            let mn_blockchain_height = if is_ckpt && sync_base > 0 {
                sync_base + mn_state.last_height
            } else {
                mn_state.last_height
            };

            tracing::debug!(
                "📊 Masternode state after update: last height = {}, can validate ChainLocks up to height {}",
                mn_blockchain_height,
                mn_blockchain_height + CHAINLOCK_VALIDATION_MASTERNODE_OFFSET
            );
        }

        // After processing the diff, check if we have any pending ChainLocks that can now be validated
        // TODO: Implement chain manager functionality for pending ChainLocks
        // if let Ok(Some(chain_manager)) = storage.load_chain_manager().await {
        //     if chain_manager.has_pending_chainlocks() {
        //         tracing::info!(
        //             "🔒 Checking {} pending ChainLocks after masternode list update",
        //             chain_manager.pending_chainlocks_count()
        //         );
        //
        //         // The chain manager will handle validation of pending ChainLocks
        //         // when it receives the next ChainLock or during periodic validation
        //     }
        // }

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

    /// Get reference to the masternode engine if available.
    /// Returns None if masternodes are disabled or engine is not initialized.
    pub fn get_masternode_engine(
        &self,
    ) -> Option<&dashcore::sml::masternode_list_engine::MasternodeListEngine> {
        self.masternode_sync.engine()
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

    /// Get a reference to the filter sync manager.
    pub fn filter_sync(&self) -> &FilterSyncManager<S, N> {
        &self.filter_sync
    }

    /// Get a mutable reference to the filter sync manager.
    pub fn filter_sync_mut(&mut self) -> &mut FilterSyncManager<S, N> {
        &mut self.filter_sync
    }

    /// Get the actual blockchain height from storage height, accounting for checkpoints
    pub(crate) async fn get_blockchain_height_from_storage(&self, storage: &S) -> SyncResult<u32> {
        let storage_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?
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
}
