//! Sequential synchronization manager for dash-spv
//!
//! This module implements a strict sequential sync pipeline where each phase
//! must complete 100% before the next phase begins.

pub mod phases;
pub mod progress;
pub mod recovery;
pub mod request_control;
pub mod transitions;

use std::time::{Duration, Instant};

use dashcore::block::Header as BlockHeader;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::Inventory;
use dashcore::BlockHash;

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::types::ChainState;
use crate::storage::StorageManager;
use crate::sync::{
    FilterSyncManager, HeaderSyncManagerWithReorg, MasternodeSyncManager, ReorgConfig,
};
use crate::types::SyncProgress;

use phases::{PhaseTransition, SyncPhase};
use request_control::RequestController;
use transitions::TransitionManager;

/// Manages sequential synchronization of all data types
pub struct SequentialSyncManager {
    /// Current synchronization phase
    current_phase: SyncPhase,

    /// Phase transition manager
    transition_manager: TransitionManager,

    /// Request controller for phase-aware request management
    request_controller: RequestController,

    /// Existing sync managers (wrapped and controlled)
    header_sync: HeaderSyncManagerWithReorg,
    filter_sync: FilterSyncManager,
    masternode_sync: MasternodeSyncManager,

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

    /// Time of last header request to detect timeouts near tip
    last_header_request_time: Option<Instant>,

    /// Height at which we last requested headers
    last_header_request_height: Option<u32>,
}

impl SequentialSyncManager {
    /// Create a new sequential sync manager
    pub fn new(
        config: &ClientConfig,
        received_filter_heights: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<u32>>>,
    ) -> SyncResult<Self> {
        // Create reorg config with sensible defaults
        let reorg_config = ReorgConfig::default();

        Ok(Self {
            current_phase: SyncPhase::Idle,
            transition_manager: TransitionManager::new(config),
            request_controller: RequestController::new(config),
            header_sync: HeaderSyncManagerWithReorg::new(config, reorg_config).map_err(|e| {
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
            last_header_request_time: None,
            last_header_request_height: None,
        })
    }

    /// Load headers from storage into the sync managers
    pub async fn load_headers_from_storage(
        &mut self,
        storage: &dyn StorageManager,
    ) -> SyncResult<u32> {
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

        // Also restore masternode engine state from storage
        self.masternode_sync.restore_engine_state(storage).await?;

        Ok(loaded_count)
    }

    /// Get the current chain height from the header sync manager
    pub fn get_chain_height(&self) -> u32 {
        self.header_sync.get_chain_height()
    }

    /// Update the chain state (used for checkpoint sync)
    pub fn update_chain_state(&mut self, chain_state: ChainState) {
        self.header_sync.update_chain_state(chain_state);
    }

    /// Start the sequential sync process
    pub async fn start_sync(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<bool> {
        if self.current_phase.is_syncing() {
            return Err(SyncError::SyncInProgress);
        }

        tracing::info!("🚀 Starting sequential sync process");
        tracing::info!("📊 Current phase: {}", self.current_phase.name());
        self.sync_start_time = Some(Instant::now());

        // Check if we actually need to sync more headers
        let current_height = self.header_sync.get_chain_height();
        let peer_best_height = network
            .get_peer_best_height()
            .await
            .map_err(|e| SyncError::Network(format!("Failed to get peer height: {}", e)))?
            .unwrap_or(current_height);

        tracing::info!(
            "🔍 Checking sync status - current height: {}, peer best height: {}",
            current_height,
            peer_best_height
        );

        // Update target height in the phase if we're downloading headers
        if let SyncPhase::DownloadingHeaders {
            target_height,
            ..
        } = &mut self.current_phase
        {
            *target_height = Some(peer_best_height);
        }

        // If we're already synced to peer height and have headers, transition directly to FullySynced
        if current_height >= peer_best_height && current_height > 0 {
            tracing::info!(
                "✅ Already synced to peer height {} - transitioning directly to FullySynced",
                current_height
            );

            // Calculate sync stats for already-synced state
            let headers_synced = current_height;
            let filters_synced = storage
                .get_filter_tip_height()
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get filter tip: {}", e)))?
                .unwrap_or(0);

            self.current_phase = SyncPhase::FullySynced {
                sync_completed_at: Instant::now(),
                total_sync_time: Duration::from_secs(0), // No actual sync time since we were already synced
                headers_synced,
                filters_synced,
                blocks_downloaded: 0,
            };

            tracing::info!(
                "🎉 Sync state updated to FullySynced (headers: {}, filters: {})",
                headers_synced,
                filters_synced
            );

            return Ok(true);
        }

        // We need to sync more headers, proceed with normal sync
        tracing::info!(
            "📥 Need to sync {} more headers from {} to {}",
            peer_best_height.saturating_sub(current_height),
            current_height,
            peer_best_height
        );

        // Transition from Idle to first phase
        self.transition_to_next_phase(storage, "Starting sync").await?;

        // For the initial sync start, we should just prepare like interleaved does
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

                // Ensure the header sync knows it needs to continue syncing
                if peer_best_height > current_height {
                    tracing::info!(
                        "📡 Header sync needs to fetch {} more headers",
                        peer_best_height - current_height
                    );
                    // The header sync manager's syncing_headers flag is already set by prepare_sync
                }
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
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
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

                    // Track when we made this request and at what height
                    let current_height = self.get_blockchain_height_from_storage(storage).await?;
                    self.last_header_request_time = Some(Instant::now());
                    self.last_header_request_height = Some(current_height);

                    // Request headers starting from our current tip
                    tracing::info!(
                        "📤 [DEBUG] Sequential sync requesting headers with base_hash: {:?}",
                        base_hash
                    );
                    match self.header_sync.request_headers(network, base_hash).await {
                        Ok(_) => {
                            tracing::info!("✅ [DEBUG] Header request sent successfully");
                        }
                        Err(e) => {
                            tracing::error!("❌ [DEBUG] Failed to request headers: {}", e);
                            return Err(e);
                        }
                    }
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

    /// Execute the current sync phase (wrapper that prevents recursion)
    async fn execute_current_phase(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
        self.execute_current_phase_internal(network, storage).await?;
        Ok(())
    }

    /// Execute the current sync phase (internal implementation)
    /// Returns true if phase completed and can continue, false if waiting for messages
    async fn execute_current_phase_internal(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<bool> {
        tracing::info!(
            "🔧 [DEBUG] Execute current phase called for: {}",
            self.current_phase.name()
        );

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
                // Return false to indicate we need to wait for headers messages
                return Ok(false);
            }

            SyncPhase::DownloadingMnList {
                ..
            } => {
                tracing::info!("📥 Starting masternode list download phase");
                tracing::info!(
                    "🔍 [DEBUG] Config: enable_masternodes = {}",
                    self.config.enable_masternodes
                );

                // Get the effective chain height from header sync which accounts for checkpoint base
                let effective_height = self.header_sync.get_chain_height();
                let sync_base_height = self.header_sync.get_sync_base_height();

                tracing::info!(
                    "🔍 [DEBUG] Masternode sync starting with effective_height={}, sync_base_height={}",
                    effective_height,
                    sync_base_height
                );

                // Also get the actual storage tip height to verify
                let storage_tip = storage
                    .get_tip_height()
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to get storage tip: {}", e)))?;

                tracing::info!(
                    "Starting masternode sync: effective_height={}, sync_base={}, storage_tip={:?}, expected_storage_height={}",
                    effective_height,
                    sync_base_height,
                    storage_tip,
                    if sync_base_height > 0 { effective_height - sync_base_height } else { effective_height }
                );

                // Use the minimum of effective height and what's actually in storage
                let safe_height = if let Some(tip) = storage_tip {
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

                let sync_started = self
                    .masternode_sync
                    .start_sync_with_height(network, storage, safe_height, sync_base_height)
                    .await?;

                if !sync_started {
                    // Masternode sync reports it's already up to date
                    tracing::info!("📊 Masternode sync reports already up to date, transitioning to next phase");
                    self.transition_to_next_phase(storage, "Masternode list already synced")
                        .await?;
                    // Return true to indicate we transitioned and can continue execution
                    return Ok(true);
                }
                // Return false to indicate we need to wait for messages
                return Ok(false);
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
                    self.transition_to_next_phase(storage, "Filter sync skipped - no peer support")
                        .await?;
                    // Return true to indicate we transitioned and can continue execution
                    return Ok(true);
                }
                // Return false to indicate we need to wait for messages
                return Ok(false);
            }

            SyncPhase::DownloadingFilters {
                ..
            } => {
                tracing::info!("📥 Starting filter download phase");

                // Get the range of filters to download
                let filter_header_tip_storage = storage
                    .get_filter_tip_height()
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to get filter tip: {}", e)))?
                    .unwrap_or(0);

                // Convert storage height to blockchain height for checkpoint sync
                let sync_base_height = self.header_sync.get_sync_base_height();
                let filter_header_tip = if sync_base_height > 0 && filter_header_tip_storage > 0 {
                    sync_base_height + filter_header_tip_storage
                } else {
                    filter_header_tip_storage
                };

                if filter_header_tip > 0 {
                    // Download filters for recent blocks by default
                    // Most wallets only need recent filters for transaction discovery
                    // Full chain scanning can be done on demand
                    const DEFAULT_FILTER_RANGE: u32 = 10000; // Download last 10k blocks
                    let start_height = filter_header_tip.saturating_sub(DEFAULT_FILTER_RANGE - 1);
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
                    self.transition_to_next_phase(storage, "No filter headers available").await?;
                    // Return true to indicate we transitioned and can continue execution
                    return Ok(true);
                }
                // Return false to indicate we need to wait for messages
                return Ok(false);
            }

            SyncPhase::DownloadingBlocks {
                ..
            } => {
                tracing::info!("📥 Starting block download phase");
                // Block download will be initiated based on filter matches
                // For now, we'll complete the sync
                self.transition_to_next_phase(storage, "No blocks to download").await?;
                // Return true to indicate we transitioned and can continue execution
                return Ok(true);
            }

            _ => {
                // Idle or FullySynced - nothing to execute
                tracing::info!(
                    "🔧 [DEBUG] No execution needed for phase: {}",
                    self.current_phase.name()
                );
                return Ok(false);
            }
        }

        // Default return - waiting for messages
        Ok(false)
    }

    /// Handle incoming network messages with phase filtering
    pub async fn handle_message(
        &mut self,
        message: NetworkMessage,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
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
            if matches!(self.current_phase, SyncPhase::DownloadingBlocks { .. }) {
                return self.handle_block_message(block, network, storage).await;
            } else {
                // Otherwise, just track that we received it but don't process for phase transitions
                // The block will be processed by the client's block processor
                tracing::debug!("Block received outside of DownloadingBlocks phase - will be processed by block processor");
                return Ok(());
            }
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

            _ => {
                tracing::debug!("Message type not handled in current phase");
            }
        }

        Ok(())
    }

    /// Check for timeouts and handle recovery
    pub async fn check_timeout(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
        // First check if the current phase needs to be executed (e.g., after a transition)
        if self.current_phase_needs_execution() {
            tracing::info!("Executing phase {} after transition", self.current_phase.name());
            self.execute_phases_until_blocked(network, storage).await?;
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
                current_height,
                ..
            } => {
                // First check if we have no peers - this might indicate peers served their headers and disconnected
                if network.peer_count() == 0 {
                    tracing::warn!(
                        "⚠️ No connected peers during header sync phase at height {}",
                        current_height
                    );

                    // If we have a reasonable number of headers, consider sync complete
                    if *current_height > 0 {
                        tracing::info!(
                            "📊 Headers sync likely complete - all peers disconnected after serving headers up to height {}",
                            current_height
                        );
                        self.transition_to_next_phase(
                            storage,
                            "Headers sync complete - peers disconnected",
                        )
                        .await?;
                        self.execute_phases_until_blocked(network, storage).await?;
                        return Ok(());
                    }
                }

                // Check if we have a pending header request that might have timed out
                if let (Some(request_time), Some(request_height)) =
                    (self.last_header_request_time, self.last_header_request_height)
                {
                    // Get peer best height to check if we're near the tip
                    let peer_best_height = network
                        .get_peer_best_height()
                        .await
                        .map_err(|e| {
                            SyncError::Network(format!("Failed to get peer height: {}", e))
                        })?
                        .unwrap_or(*current_height);

                    let blocks_from_tip = peer_best_height.saturating_sub(request_height);
                    let time_waiting = request_time.elapsed();

                    // If we're within 10 blocks of peer tip and waited 5+ seconds, consider sync complete
                    if blocks_from_tip <= 10 && time_waiting >= Duration::from_secs(5) {
                        tracing::info!(
                            "📊 Header sync complete - no response after {}s when {} blocks from tip (height {} vs peer {})",
                            time_waiting.as_secs(),
                            blocks_from_tip,
                            request_height,
                            peer_best_height
                        );
                        self.transition_to_next_phase(
                            storage,
                            "Headers sync complete - near peer tip with timeout",
                        )
                        .await?;
                        self.execute_phases_until_blocked(network, storage).await?;
                        return Ok(());
                    }
                }

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
                                        self.execute_phases_until_blocked(network, storage).await?;
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
                                "Filter sync timeout - forcing completion",
                            )
                            .await?;
                            self.execute_phases_until_blocked(network, storage).await?;
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
        let phase_progress = self.current_phase.progress();

        // Convert phase progress to SyncPhaseInfo
        let current_phase = Some(crate::types::SyncPhaseInfo {
            phase_name: phase_progress.phase_name.to_string(),
            progress_percentage: phase_progress.percentage,
            items_completed: phase_progress.items_completed,
            items_total: phase_progress.items_total,
            rate: phase_progress.rate,
            eta_seconds: phase_progress.eta.map(|d| d.as_secs()),
            elapsed_seconds: phase_progress.elapsed.as_secs(),
            details: self.get_phase_details(),
            current_position: phase_progress.current_position,
            target_position: phase_progress.target_position,
            rate_units: Some(self.get_phase_rate_units()),
        });

        SyncProgress {
            headers_synced: matches!(
                self.current_phase,
                SyncPhase::DownloadingMnList { .. }
                    | SyncPhase::DownloadingCFHeaders { .. }
                    | SyncPhase::DownloadingFilters { .. }
                    | SyncPhase::DownloadingBlocks { .. }
                    | SyncPhase::FullySynced { .. }
            ),
            header_height: 0, // PLACEHOLDER: Caller MUST query storage.get_tip_height()
            filter_headers_synced: matches!(
                self.current_phase,
                SyncPhase::DownloadingFilters { .. }
                    | SyncPhase::DownloadingBlocks { .. }
                    | SyncPhase::FullySynced { .. }
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
            current_phase,
        }
    }

    /// Check if sync is complete
    pub fn is_synced(&self) -> bool {
        matches!(self.current_phase, SyncPhase::FullySynced { .. })
    }

    /// Get rate units for the current phase
    fn get_phase_rate_units(&self) -> String {
        match &self.current_phase {
            SyncPhase::DownloadingHeaders {
                ..
            } => "headers/sec".to_string(),
            SyncPhase::DownloadingMnList {
                ..
            } => "diffs/sec".to_string(),
            SyncPhase::DownloadingCFHeaders {
                ..
            } => "filter headers/sec".to_string(),
            SyncPhase::DownloadingFilters {
                ..
            } => "filters/sec".to_string(),
            SyncPhase::DownloadingBlocks {
                ..
            } => "blocks/sec".to_string(),
            _ => "items/sec".to_string(),
        }
    }

    /// Get phase-specific details for the current sync phase
    fn get_phase_details(&self) -> Option<String> {
        match &self.current_phase {
            SyncPhase::Idle => Some("Waiting to start synchronization".to_string()),
            SyncPhase::DownloadingHeaders {
                target_height,
                current_height,
                ..
            } => {
                if let Some(target) = target_height {
                    Some(format!("Syncing headers from {} to {}", current_height, target))
                } else {
                    Some(format!("Syncing headers from height {}", current_height))
                }
            }
            SyncPhase::DownloadingMnList {
                current_height,
                target_height,
                ..
            } => Some(format!(
                "Syncing masternode lists from {} to {}",
                current_height, target_height
            )),
            SyncPhase::DownloadingCFHeaders {
                current_height,
                target_height,
                ..
            } => {
                Some(format!("Syncing filter headers from {} to {}", current_height, target_height))
            }
            SyncPhase::DownloadingFilters {
                completed_heights,
                total_filters,
                ..
            } => {
                Some(format!("{} of {} filters downloaded", completed_heights.len(), total_filters))
            }
            SyncPhase::DownloadingBlocks {
                completed,
                total_blocks,
                ..
            } => Some(format!("{} of {} blocks downloaded", completed.len(), total_blocks)),
            SyncPhase::FullySynced {
                headers_synced,
                filters_synced,
                blocks_downloaded,
                ..
            } => Some(format!("Sync complete")),
        }
    }

    /// Execute phases until we reach one that needs to wait for network messages
    async fn execute_phases_until_blocked(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
        const MAX_ITERATIONS: usize = 10; // Safety limit to prevent infinite loops
        let mut iterations = 0;

        loop {
            iterations += 1;
            if iterations > MAX_ITERATIONS {
                tracing::warn!("⚠️ Reached maximum phase execution iterations, stopping");
                break;
            }

            let previous_phase = std::mem::discriminant(&self.current_phase);

            // Execute the current phase with special handling
            match &self.current_phase {
                SyncPhase::DownloadingMnList {
                    ..
                } => {
                    // Special handling for masternode sync that might already be complete
                    let sync_result = self.execute_current_phase_internal(network, storage).await?;
                    if !sync_result {
                        // Phase indicated it needs to wait for messages
                        break;
                    }
                }
                _ => {
                    // Normal execution
                    self.execute_current_phase_internal(network, storage).await?;
                }
            }

            let current_phase_discriminant = std::mem::discriminant(&self.current_phase);

            // If we didn't transition to a new phase, we're done
            if previous_phase == current_phase_discriminant {
                break;
            }

            // If we reached a phase that needs network messages or is complete, stop
            match &self.current_phase {
                SyncPhase::DownloadingHeaders {
                    ..
                }
                | SyncPhase::DownloadingMnList {
                    ..
                }
                | SyncPhase::DownloadingCFHeaders {
                    ..
                }
                | SyncPhase::DownloadingFilters {
                    ..
                }
                | SyncPhase::DownloadingBlocks {
                    ..
                } => {
                    // These phases need to wait for network messages
                    break;
                }
                SyncPhase::FullySynced {
                    ..
                }
                | SyncPhase::Idle => {
                    // We're done
                    break;
                }
            }
        }

        Ok(())
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
            _ => false,
        }
    }

    /// Transition to the next phase
    async fn transition_to_next_phase(
        &mut self,
        storage: &mut dyn StorageManager,
        reason: &str,
    ) -> SyncResult<()> {
        tracing::info!(
            "🔄 [DEBUG] Starting transition from {} - reason: {}",
            self.current_phase.name(),
            reason
        );

        // Get the next phase
        let next_phase =
            self.transition_manager.get_next_phase(&self.current_phase, storage).await?;

        if let Some(next) = next_phase {
            tracing::info!("🔄 [DEBUG] Next phase determined: {}", next.name());

            // Check if transition is allowed
            let can_transition = self
                .transition_manager
                .can_transition_to(&self.current_phase, &next, storage)
                .await?;

            tracing::info!(
                "🔄 [DEBUG] Can transition from {} to {}: {}",
                self.current_phase.name(),
                next.name(),
                can_transition
            );

            if !can_transition {
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

            tracing::info!(
                "✅ [DEBUG] Phase transition complete. Current phase is now: {}",
                self.current_phase.name()
            );
            tracing::info!(
                "📋 [DEBUG] Config state: enable_masternodes={}, enable_filters={}",
                self.config.enable_masternodes,
                self.config.enable_filters
            );

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
    async fn recover_from_timeout(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
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
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
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
                // For now, just return the error. In future, we could trigger a fallback here
                return Err(SyncError::Headers2DecompressionFailed(e));
            }
            Err(e) => return Err(e),
        };

        // Calculate blockchain height before borrowing self.current_phase
        let blockchain_height = self.get_blockchain_height_from_storage(storage).await.unwrap_or(0);

        // Update phase state and check if we need to transition
        let should_transition = if let SyncPhase::DownloadingHeaders {
            current_height,
            target_height,
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
            self.transition_to_next_phase(storage, "Headers sync complete via Headers2").await?;

            // Execute the next phase
            self.execute_current_phase(network, storage).await?;
        }

        Ok(())
    }

    async fn handle_headers_message(
        &mut self,
        headers: Vec<dashcore::block::Header>,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
        let continue_sync = match self
            .header_sync
            .handle_headers_message(headers.clone(), storage, network)
            .await
        {
            Ok(continue_sync) => continue_sync,
            Err(SyncError::Network(msg)) if msg.contains("No connected peers") => {
                // Special case: peers disconnected after serving headers
                // Check if we're near the tip and should consider sync complete
                let current_height = self.get_blockchain_height_from_storage(storage).await?;
                tracing::warn!(
                    "⚠️ Header sync failed due to no connected peers at height {}",
                    current_height
                );

                // If we've made progress and have a reasonable number of headers, consider it complete
                if current_height > 0 && headers.len() < 2000 {
                    tracing::info!(
                        "📊 Headers sync likely complete - peers disconnected after serving headers up to height {}",
                        current_height
                    );
                    false // Don't continue sync
                } else {
                    return Err(SyncError::Network(msg));
                }
            }
            Err(e) => return Err(e),
        };

        // Calculate blockchain height before borrowing self.current_phase
        let blockchain_height = self.get_blockchain_height_from_storage(storage).await.unwrap_or(0);

        // Update phase state and check if we need to transition
        let should_transition = if let SyncPhase::DownloadingHeaders {
            current_height,
            target_height,
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

            // Update target height if we can get peer's best height
            if target_height.is_none() {
                if let Ok(Some(peer_height)) = network.get_peer_best_height().await {
                    *target_height = Some(peer_height);
                    tracing::debug!("Updated target height to {}", peer_height);
                }
            }

            // Update progress
            *headers_downloaded += headers.len() as u32;
            let elapsed = start_time.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                *headers_per_second = *headers_downloaded as f64 / elapsed;
            }

            // Check if we received empty response (sync complete)
            if headers.is_empty() {
                *received_empty_response = true;
                tracing::info!("🎆 Received empty headers response - sync complete");
            }

            // Update progress time
            *last_progress = Instant::now();

            // Log the decision factors
            tracing::info!(
                "📊 Header sync decision - continue_sync: {}, headers_received: {}, empty_response: {}, current_height: {}",
                continue_sync,
                headers.len(),
                *received_empty_response,
                *current_height
            );

            // Check if phase is complete
            // Only transition if we got an empty response OR the sync manager explicitly said to stop
            let should_transition = !continue_sync || *received_empty_response;

            // Additional check: if we're within 5 headers of peer tip, consider sync complete
            let should_transition = if should_transition {
                true
            } else if let Ok(Some(peer_height)) = network.get_peer_best_height().await {
                let gap = peer_height.saturating_sub(*current_height);
                if gap <= 5 && headers.len() < 100 {
                    tracing::info!(
                        "📊 Headers sync complete - within {} headers of peer tip (height {} vs peer {})",
                        gap,
                        *current_height,
                        peer_height
                    );
                    // Mark as having received empty response so transition logic works
                    *received_empty_response = true;
                    true
                } else {
                    false
                }
            } else {
                should_transition
            };

            should_transition
        } else {
            false
        };

        if should_transition {
            tracing::info!(
                "📊 Transitioning away from headers phase - continue_sync: {}, headers.len(): {}",
                continue_sync,
                headers.len()
            );

            // Double-check with peer height before transitioning
            if let Ok(Some(peer_height)) = network.get_peer_best_height().await {
                let gap = peer_height.saturating_sub(blockchain_height);
                if gap > 5 {
                    tracing::error!(
                        "❌ Headers sync ending prematurely! Our height: {}, peer height: {}, gap: {} headers",
                        blockchain_height,
                        peer_height,
                        gap
                    );
                } else if gap > 0 {
                    tracing::info!(
                        "✅ Headers sync complete - within acceptable range of peer tip. Gap: {} headers (height {} vs peer {})",
                        gap,
                        blockchain_height,
                        peer_height
                    );
                }
            }

            self.transition_to_next_phase(storage, "Headers sync complete").await?;

            tracing::info!("🚀 [DEBUG] About to execute next phase after headers complete");

            // Execute phases that can complete immediately (like when masternode sync is already up to date)
            self.execute_phases_until_blocked(network, storage).await?;

            tracing::info!(
                "✅ [DEBUG] Phase execution complete, current phase: {}",
                self.current_phase.name()
            );
        } else if continue_sync {
            // Headers sync returned true, meaning we should continue requesting more headers
            tracing::info!("📡 [DEBUG] Headers sync wants to continue (continue_sync=true)");

            // Only request more if we're still in the downloading headers phase
            if matches!(self.current_phase, SyncPhase::DownloadingHeaders { .. }) {
                // The header sync manager has already requested more headers internally
                // We just need to update our tracking
                tracing::info!("📡 [DEBUG] Headers sync continuing - more headers expected. Waiting for network response...");

                // Update the phase to track that we're waiting for more headers
                if let SyncPhase::DownloadingHeaders {
                    last_progress,
                    ..
                } = &mut self.current_phase
                {
                    *last_progress = Instant::now();
                }
            }
        }

        Ok(())
    }

    async fn handle_mnlistdiff_message(
        &mut self,
        diff: dashcore::network::message_sml::MnListDiff,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
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
                // Masternode sync reports complete - verify we've actually reached the target
                if let SyncPhase::DownloadingMnList {
                    current_height,
                    target_height,
                    ..
                } = &self.current_phase
                {
                    if *current_height >= *target_height {
                        // We've reached or exceeded the target height
                        self.transition_to_next_phase(storage, "Masternode sync complete").await?;
                        // Execute phases that can complete immediately
                        self.execute_phases_until_blocked(network, storage).await?;
                    } else {
                        // Masternode sync thinks it's done but we haven't reached target
                        // This can happen after a genesis sync that only gets us partway
                        tracing::info!(
                            "Masternode sync reports complete but only at height {} of target {}. Continuing sync...",
                            *current_height, *target_height
                        );

                        // Re-start the masternode sync to continue from current height
                        let effective_height = self.header_sync.get_chain_height();
                        let sync_base_height = self.header_sync.get_sync_base_height();

                        self.masternode_sync
                            .start_sync_with_height(
                                network,
                                storage,
                                effective_height,
                                sync_base_height,
                            )
                            .await?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_cfheaders_message(
        &mut self,
        cfheaders: dashcore::network::message_filter::CFHeaders,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
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
                self.transition_to_next_phase(storage, "Filter headers sync complete").await?;

                // Execute phases that can complete immediately
                self.execute_phases_until_blocked(network, storage).await?;
            }
        }

        Ok(())
    }

    async fn handle_cfilter_message(
        &mut self,
        cfilter: dashcore::network::message_filter::CFilter,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
        tracing::debug!("📨 Received CFilter for block {}", cfilter.block_hash);

        // First, check if this filter matches any watch items
        // This is the key part that was missing!
        if self.config.enable_filters {
            // Get watch items from config (in a real implementation, this would come from the client)
            // For now, we'll check if we have any watched addresses in storage
            if let Ok(Some(watch_items_data)) = storage.load_metadata("watch_items").await {
                if let Ok(watch_items) =
                    serde_json::from_slice::<Vec<crate::types::WatchItem>>(&watch_items_data)
                {
                    if !watch_items.is_empty() {
                        // Check if the filter matches any watch items
                        match self
                            .filter_sync
                            .check_filter_for_matches(
                                &cfilter.filter,
                                &cfilter.block_hash,
                                &watch_items,
                                storage,
                            )
                            .await
                        {
                            Ok(true) => {
                                tracing::info!(
                                    "🎯 Filter match found for block {} at height {:?}!",
                                    cfilter.block_hash,
                                    storage
                                        .get_header_height_by_hash(&cfilter.block_hash)
                                        .await
                                        .ok()
                                        .flatten()
                                );

                                // Request the full block for processing
                                let getdata = NetworkMessage::GetData(vec![Inventory::Block(
                                    cfilter.block_hash,
                                )]);

                                if let Err(e) = network.send_message(getdata).await {
                                    tracing::error!(
                                        "Failed to request block {}: {}",
                                        cfilter.block_hash,
                                        e
                                    );
                                }

                                // Track the match in phase state
                                if let SyncPhase::DownloadingFilters {
                                    ..
                                } = &mut self.current_phase
                                {
                                    // Update some tracking for matched filters
                                    tracing::info!("📊 Filter match recorded, block requested");
                                }
                            }
                            Ok(false) => {
                                // No match, continue normally
                            }
                            Err(e) => {
                                tracing::warn!("Failed to check filter for matches: {}", e);
                            }
                        }
                    }
                }
            }
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
                    self.transition_to_next_phase(storage, "All filters downloaded").await?;

                    // Execute phases that can complete immediately
                    self.execute_phases_until_blocked(network, storage).await?;
                } else if *total_filters == 0 && !has_pending {
                    // Edge case: no filters to download
                    self.transition_to_next_phase(storage, "No filters to download").await?;

                    // Execute phases that can complete immediately
                    self.execute_phases_until_blocked(network, storage).await?;
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
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
        let block_hash = block.block_hash();

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

            // Process the block (would be handled by block processor)
            // ...

            // Check if all blocks are downloaded
            downloading.is_empty() && self.no_more_pending_blocks()
        } else {
            false
        };

        if should_transition {
            self.transition_to_next_phase(storage, "All blocks downloaded").await?;

            // Execute phases that can complete immediately
            self.execute_phases_until_blocked(network, storage).await?;
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
    async fn get_base_hash_from_storage(
        &self,
        storage: &dyn StorageManager,
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

    /// Handle inventory messages for sequential sync
    pub async fn handle_inventory(
        &mut self,
        inv: Vec<Inventory>,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
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
                    let get_headers = dashcore::network::message::NetworkMessage::GetHeaders(
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
                    let get_data = dashcore::network::message::NetworkMessage::GetData(vec![
                        Inventory::ChainLock(chainlock_hash),
                    ]);
                    network.send_message(get_data).await.map_err(|e| {
                        SyncError::Network(format!("Failed to request chainlock: {}", e))
                    })?;

                    // ChainLocks can help us detect if we're behind
                    // The ChainLock handler will check if we need to catch up
                }

                Inventory::InstantSendLock(islock_hash) => {
                    tracing::info!("⚡ InstantSend lock announced: {}", islock_hash);
                    // Request the InstantSend lock
                    let get_data = dashcore::network::message::NetworkMessage::GetData(vec![
                        Inventory::InstantSendLock(islock_hash),
                    ]);
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
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
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

                        let catch_up_request =
                            dashcore::network::message::NetworkMessage::GetMnListD(
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

            tracing::info!("📦 New block at height {}: {}", height, header.block_hash());

            // If we have masternodes enabled, request masternode list updates for ChainLock validation
            if self.config.enable_masternodes {
                // For ChainLock validation, we need masternode lists at (block_height - 8)
                // So we request the masternode diff for this new block to maintain our rolling window
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
                    dashcore::blockdata::constants::genesis_block(self.config.network.into())
                        .block_hash()
                };

                tracing::info!(
                    "📋 Requesting masternode list diff for block at height {} to maintain ChainLock validation window",
                    height
                );

                let getmnlistdiff = dashcore::network::message::NetworkMessage::GetMnListD(
                    dashcore::network::message_sml::GetMnListDiff {
                        base_block_hash,
                        block_hash: header.block_hash(),
                    },
                );

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
                    height,
                    start_height,
                    stop_hash
                );

                let get_cfheaders = dashcore::network::message::NetworkMessage::GetCFHeaders(
                    dashcore::network::message_filter::GetCFHeaders {
                        filter_type: 0, // Basic filter
                        start_height,
                        stop_hash,
                    },
                );

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
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
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
            let get_cfilters = dashcore::network::message::NetworkMessage::GetCFilters(
                dashcore::network::message_filter::GetCFilters {
                    filter_type: 0, // Basic filter
                    start_height: height,
                    stop_hash,
                },
            );

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
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
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

        // Load watch items from storage (consistent with sync-time behavior)
        let mut watch_items = Vec::new();

        // First try to load from storage metadata
        if let Ok(Some(watch_items_data)) = storage.load_metadata("watch_items").await {
            if let Ok(stored_items) =
                serde_json::from_slice::<Vec<crate::types::WatchItem>>(&watch_items_data)
            {
                watch_items = stored_items;
                tracing::debug!(
                    "Loaded {} watch items from storage for post-sync filter check",
                    watch_items.len()
                );
            }
        }

        // If no items in storage, fall back to config
        if watch_items.is_empty() && !self.config.watch_items.is_empty() {
            watch_items = self.config.watch_items.clone();
            tracing::debug!(
                "Using {} watch items from config for post-sync filter check",
                watch_items.len()
            );
        }

        // Check if the filter matches any of our watch items
        if !watch_items.is_empty() {
            let matches = self
                .filter_sync
                .check_filter_for_matches(
                    &cfilter.filter,
                    &cfilter.block_hash,
                    &watch_items,
                    storage,
                )
                .await?;

            if matches {
                tracing::info!("🎯 Filter matches! Requesting block {}", cfilter.block_hash);

                // Request the full block
                let get_data =
                    dashcore::network::message::NetworkMessage::GetData(vec![Inventory::Block(
                        cfilter.block_hash,
                    )]);

                network
                    .send_message(get_data)
                    .await
                    .map_err(|e| SyncError::Network(format!("Failed to request block: {}", e)))?;
            } else {
                tracing::debug!(
                    "Filter for block {} does not match any watch items",
                    cfilter.block_hash
                );
            }
        } else {
            tracing::warn!("No watch items available for post-sync filter check");
        }

        Ok(())
    }

    /// Handle masternode list diffs that arrive after initial sync (for ChainLock validation)
    async fn handle_post_sync_mnlistdiff(
        &mut self,
        diff: dashcore::network::message_sml::MnListDiff,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
        // Get block heights for better logging
        let base_height =
            storage.get_header_height_by_hash(&diff.base_block_hash).await.ok().flatten();
        let target_height =
            storage.get_header_height_by_hash(&diff.block_hash).await.ok().flatten();

        tracing::info!(
            "📥 Processing post-sync masternode diff for block {} at height {:?} (base: {} at height {:?})",
            diff.block_hash,
            target_height,
            diff.base_block_hash,
            base_height
        );

        // Process the diff through the masternode sync manager
        // This will update the masternode engine's state
        self.masternode_sync.handle_mnlistdiff_message(diff, storage, network).await?;

        // Log the current masternode state after update
        if let Ok(Some(mn_state)) = storage.load_masternode_state().await {
            tracing::debug!(
                "📊 Masternode state after update: last height = {}, can validate ChainLocks up to height {}",
                mn_state.last_height,
                mn_state.last_height + 8
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
        self.header_sync.reset_pending_requests();
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

        // Reset header request tracking
        self.last_header_request_time = None;
        self.last_header_request_height = None;

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
    pub fn masternode_sync_mut(&mut self) -> &mut MasternodeSyncManager {
        &mut self.masternode_sync
    }

    /// Get the actual blockchain height from storage height, accounting for checkpoints
    pub(crate) async fn get_blockchain_height_from_storage(
        &self,
        storage: &dyn StorageManager,
    ) -> SyncResult<u32> {
        let storage_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?
            .unwrap_or(0);

        // Check if we're syncing from a checkpoint
        let chain_state = self.header_sync.get_chain_state();
        if chain_state.synced_from_checkpoint && chain_state.sync_base_height > 0 {
            // For checkpoint sync, blockchain height = sync_base_height + storage_height
            Ok(chain_state.sync_base_height + storage_height)
        } else {
            // Normal sync: storage height IS the blockchain height
            Ok(storage_height)
        }
    }
}
