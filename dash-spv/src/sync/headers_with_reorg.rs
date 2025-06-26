//! Header synchronization with reorganization support
//!
//! This module extends the basic header sync with fork detection and reorg handling.

use dashcore::{
    block::Header as BlockHeader, network::constants::NetworkExt, network::message::NetworkMessage,
    network::message_blockdata::GetHeadersMessage, BlockHash,
};
use dashcore_hashes::Hash;

use crate::chain::checkpoints::{mainnet_checkpoints, testnet_checkpoints, CheckpointManager};
use crate::chain::{
    ChainTip, ChainTipManager, ChainWork, ForkDetectionResult, ForkDetector, ReorgManager,
};
use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::headers2_state::Headers2StateManager;
use crate::types::ChainState;
use crate::validation::ValidationManager;
use crate::wallet::WalletState;

/// Configuration for reorg handling
pub struct ReorgConfig {
    /// Maximum depth of reorganization to handle
    pub max_reorg_depth: u32,
    /// Whether to respect chain locks
    pub respect_chain_locks: bool,
    /// Maximum number of forks to track
    pub max_forks: usize,
    /// Whether to enforce checkpoint validation
    pub enforce_checkpoints: bool,
}

impl Default for ReorgConfig {
    fn default() -> Self {
        Self {
            max_reorg_depth: 1000,
            respect_chain_locks: true,
            max_forks: 10,
            enforce_checkpoints: true,
        }
    }
}

/// Manages header synchronization with reorg support
pub struct HeaderSyncManagerWithReorg {
    config: ClientConfig,
    validation: ValidationManager,
    fork_detector: ForkDetector,
    reorg_manager: ReorgManager,
    tip_manager: ChainTipManager,
    checkpoint_manager: CheckpointManager,
    reorg_config: ReorgConfig,
    chain_state: ChainState,
    wallet_state: WalletState,
    headers2_state: Headers2StateManager,
    total_headers_synced: u32,
    last_progress_log: Option<std::time::Instant>,
    syncing_headers: bool,
    last_sync_progress: std::time::Instant,
    headers2_failed: bool,
}

impl HeaderSyncManagerWithReorg {
    /// Create a new header sync manager with reorg support
    pub fn new(config: &ClientConfig, reorg_config: ReorgConfig) -> Self {
        let chain_state = ChainState::new_for_network(config.network);
        let wallet_state = WalletState::new(config.network);

        // Create checkpoint manager based on network
        let checkpoints = match config.network {
            dashcore::Network::Dash => mainnet_checkpoints(),
            dashcore::Network::Testnet => testnet_checkpoints(),
            _ => Vec::new(), // No checkpoints for other networks
        };
        let checkpoint_manager = CheckpointManager::new(checkpoints);

        Self {
            config: config.clone(),
            validation: ValidationManager::new(config.validation_mode),
            fork_detector: ForkDetector::new(reorg_config.max_forks),
            reorg_manager: ReorgManager::new(
                reorg_config.max_reorg_depth,
                reorg_config.respect_chain_locks,
            ),
            tip_manager: ChainTipManager::new(reorg_config.max_forks),
            checkpoint_manager,
            reorg_config,
            chain_state,
            wallet_state,
            headers2_state: Headers2StateManager::new(),
            total_headers_synced: 0,
            last_progress_log: None,
            syncing_headers: false,
            last_sync_progress: std::time::Instant::now(),
            headers2_failed: false,
        }
    }

    /// Load headers from storage into the chain state
    pub async fn load_headers_from_storage(
        &mut self,
        storage: &dyn StorageManager,
    ) -> SyncResult<u32> {
        // Get the current tip height from storage
        let tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?;

        let Some(tip_height) = tip_height else {
            tracing::debug!("No headers found in storage");
            return Ok(0);
        };

        if tip_height == 0 {
            tracing::debug!("Only genesis block in storage");
            return Ok(0);
        }

        tracing::info!("Loading {} headers from storage into HeaderSyncManager", tip_height);
        let start_time = std::time::Instant::now();

        // Load headers in batches
        const BATCH_SIZE: u32 = 10_000;
        let mut loaded_count = 0u32;
        let mut current_height = 1u32; // Start from 1 (genesis already in chain state)

        while current_height <= tip_height {
            let end_height = (current_height + BATCH_SIZE - 1).min(tip_height);

            // Load batch from storage
            let headers = storage
                .load_headers(current_height..end_height + 1)
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to load headers: {}", e)))?;

            if headers.is_empty() {
                return Err(SyncError::Storage(format!(
                    "No headers found for range {}..{}",
                    current_height,
                    end_height + 1
                )));
            }

            // Add headers to chain state
            for header in headers {
                self.chain_state.add_header(header);
                loaded_count += 1;
            }

            // Progress logging
            if loaded_count % 50_000 == 0 || loaded_count == tip_height {
                let elapsed = start_time.elapsed();
                let headers_per_sec = loaded_count as f64 / elapsed.as_secs_f64();
                tracing::info!(
                    "Loaded {}/{} headers ({:.0} headers/sec)",
                    loaded_count,
                    tip_height,
                    headers_per_sec
                );
            }

            current_height = end_height + 1;
        }

        self.total_headers_synced = tip_height;

        let elapsed = start_time.elapsed();
        tracing::info!(
            "✅ Loaded {} headers into HeaderSyncManager in {:.2}s ({:.0} headers/sec)",
            loaded_count,
            elapsed.as_secs_f64(),
            loaded_count as f64 / elapsed.as_secs_f64()
        );

        Ok(loaded_count)
    }

    /// Handle a Headers message with fork detection and reorg support
    pub async fn handle_headers_message(
        &mut self,
        headers: Vec<BlockHeader>,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<bool> {
        tracing::info!("🔍 Handle headers message with {} headers (reorg-aware)", headers.len(),);

        if headers.is_empty() {
            tracing::info!("📊 Header sync complete - no more headers from peers");
            self.syncing_headers = false;
            return Ok(false);
        }

        self.last_sync_progress = std::time::Instant::now();
        self.total_headers_synced += headers.len() as u32;

        // Process each header with fork detection
        for header in &headers {
            match self.process_header_with_fork_detection(header, storage).await? {
                HeaderProcessResult::ExtendedMainChain => {
                    // Normal case - header extends the main chain
                }
                HeaderProcessResult::CreatedFork => {
                    tracing::warn!("⚠️ Fork detected at height {}", self.chain_state.get_height());
                }
                HeaderProcessResult::ExtendedFork => {
                    tracing::debug!("Fork extended");
                }
                HeaderProcessResult::Orphan => {
                    tracing::debug!("Orphan header received: {}", header.block_hash());
                }
                HeaderProcessResult::TriggeredReorg(depth) => {
                    tracing::warn!("🔄 Chain reorganization triggered - depth: {}", depth);
                }
            }
        }

        // Check if any fork is now stronger than the main chain
        self.check_for_reorg(storage).await?;

        if self.syncing_headers {
            // During sync mode - request next batch
            if let Some(tip) = self.chain_state.get_tip_header() {
                self.request_headers(network, Some(tip.block_hash())).await?;
            }
        }

        Ok(true)
    }

    /// Process a single header with fork detection
    async fn process_header_with_fork_detection(
        &mut self,
        header: &BlockHeader,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<HeaderProcessResult> {
        // First validate the header structure
        self.validation
            .validate_header(header, None)
            .map_err(|e| SyncError::Validation(format!("Invalid header: {}", e)))?;

        // Create a sync storage adapter
        let sync_storage = SyncStorageAdapter::new(storage);

        // Check for forks
        let fork_result = self.fork_detector.check_header(header, &self.chain_state, &sync_storage);

        match fork_result {
            ForkDetectionResult::ExtendsMainChain => {
                // Normal case - add to chain state and storage
                self.chain_state.add_header(*header);
                let height = self.chain_state.get_height();

                // Validate against checkpoints if enabled
                if self.reorg_config.enforce_checkpoints {
                    if !self.checkpoint_manager.validate_block(height, &header.block_hash()) {
                        // Block doesn't match checkpoint - reject it
                        return Err(SyncError::Validation(format!(
                            "Block at height {} does not match checkpoint",
                            height
                        )));
                    }
                }

                // Store in async storage
                storage
                    .store_headers(&[*header])
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to store header: {}", e)))?;

                // Update chain tip manager
                let chain_work = ChainWork::from_height_and_header(height, header);
                let tip = crate::chain::ChainTip::new(*header, height, chain_work);
                self.tip_manager
                    .add_tip(tip)
                    .map_err(|e| SyncError::Storage(format!("Failed to update tip: {}", e)))?;

                Ok(HeaderProcessResult::ExtendedMainChain)
            }
            ForkDetectionResult::CreatesNewFork(fork) => {
                // Check if fork violates checkpoints
                if self.reorg_config.enforce_checkpoints {
                    // Don't reject forks from genesis (height 0) as this is the natural starting point
                    if fork.fork_height > 0 {
                        if let Some(checkpoint) =
                            self.checkpoint_manager.last_checkpoint_before_height(fork.fork_height)
                        {
                            if fork.fork_height <= checkpoint.height {
                                tracing::warn!(
                                    "Rejecting fork that would reorg past checkpoint at height {}",
                                    checkpoint.height
                                );
                                return Ok(HeaderProcessResult::Orphan); // Treat as orphan
                            }
                        }
                    }
                }

                tracing::warn!(
                    "Fork created at height {} from block {}",
                    fork.fork_height,
                    fork.fork_point
                );
                Ok(HeaderProcessResult::CreatedFork)
            }
            ForkDetectionResult::ExtendsFork(fork) => {
                tracing::debug!("Fork extended to height {}", fork.tip_height);
                Ok(HeaderProcessResult::ExtendedFork)
            }
            ForkDetectionResult::Orphan => {
                // TODO: Add to orphan pool for later processing
                Ok(HeaderProcessResult::Orphan)
            }
        }
    }

    /// Check if any fork should trigger a reorganization
    async fn check_for_reorg(&mut self, storage: &mut dyn StorageManager) -> SyncResult<()> {
        if let Some(strongest_fork) = self.fork_detector.get_strongest_fork() {
            if let Some(current_tip) = self.tip_manager.get_active_tip() {
                // First phase: Check if reorganization is needed (read-only)
                let should_reorg = {
                    let sync_storage = SyncStorageAdapter::new(storage);
                    self.reorg_manager
                        .should_reorganize(current_tip, strongest_fork, &sync_storage)
                        .map_err(|e| SyncError::Validation(format!("Reorg check failed: {}", e)))?
                };

                if should_reorg {
                    // Clone necessary data before reorganization to avoid borrow conflicts
                    let fork_tip_hash = strongest_fork.tip_hash;
                    let fork_clone = strongest_fork.clone();

                    tracing::info!(
                        "⚠️ Reorganization needed: fork at height {} (work: {:?}) > main chain at height {} (work: {:?})",
                        fork_clone.tip_height,
                        fork_clone.chain_work,
                        current_tip.height,
                        current_tip.chain_work
                    );

                    // Second phase: Perform reorganization using only StorageManager
                    let event = self
                        .reorg_manager
                        .reorganize(
                            &mut self.chain_state,
                            &mut self.wallet_state,
                            &fork_clone,
                            storage, // Only StorageManager needed now
                        )
                        .await
                        .map_err(|e| {
                            SyncError::Validation(format!("Reorganization failed: {}", e))
                        })?;

                    tracing::info!(
                        "🔄 Reorganization complete - common ancestor: {} at height {}, disconnected: {} blocks, connected: {} blocks",
                        event.common_ancestor,
                        event.common_height,
                        event.disconnected_headers.len(),
                        event.connected_headers.len()
                    );

                    // Update tip manager with new chain tip
                    if let Some(new_tip_header) = fork_clone.headers.last() {
                        let new_tip = ChainTip::new(
                            *new_tip_header,
                            fork_clone.tip_height,
                            fork_clone.chain_work.clone(),
                        );
                        let _ = self.tip_manager.add_tip(new_tip);
                    }

                    // Remove the processed fork
                    self.fork_detector.remove_fork(&fork_tip_hash);

                    // Notify about affected transactions
                    if !event.affected_transactions.is_empty() {
                        tracing::info!(
                            "📝 {} transactions affected by reorganization",
                            event.affected_transactions.len()
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Request headers from the network
    pub async fn request_headers(
        &mut self,
        network: &mut dyn NetworkManager,
        base_hash: Option<BlockHash>,
    ) -> SyncResult<()> {
        let block_locator = match base_hash {
            Some(hash) => {
                // Check if this is genesis and we're using headers2
                if network.has_headers2_peer().await && !self.headers2_failed {
                    let genesis_hash = self.config.network.known_genesis_block_hash();
                    if genesis_hash == Some(hash) {
                        tracing::info!("📍 Using empty locator for headers2 genesis sync");
                        vec![]
                    } else {
                        vec![hash]
                    }
                } else {
                    vec![hash]
                }
            },
            None => {
                // When starting from genesis, include genesis hash in locator
                let genesis_hash = self.config.network.known_genesis_block_hash()
                    .unwrap_or(BlockHash::from_byte_array([0; 32]));
                vec![genesis_hash]
            },
        };

        let stop_hash = BlockHash::from_byte_array([0; 32]);
        let getheaders_msg = GetHeadersMessage::new(block_locator.clone(), stop_hash);
        
        // Log the GetHeaders message details
        tracing::info!(
            "GetHeaders message - version: {}, locator_count: {}, locator: {:?}, stop_hash: {:?}",
            getheaders_msg.version,
            getheaders_msg.locator_hashes.len(),
            getheaders_msg.locator_hashes,
            getheaders_msg.stop_hash
        );

        // Headers2 is currently disabled due to protocol compatibility issues
        // TODO: Fix headers2 decompression before re-enabling
        let use_headers2 = false; // Disabled until headers2 implementation is fixed
        
        // Log details about the request
        tracing::info!(
            "Preparing headers request - height: {}, base_hash: {:?}, headers2_supported: {}",
            self.chain_state.tip_height(),
            base_hash,
            use_headers2
        );

        // Try GetHeaders2 first if peer supports it, with fallback to regular GetHeaders
        if use_headers2 {
            tracing::info!("📤 Sending GetHeaders2 message (compressed headers)");
            tracing::debug!("GetHeaders2 details: version={}, locator_hashes={:?}, stop_hash={}", 
                getheaders_msg.version, 
                getheaders_msg.locator_hashes, 
                getheaders_msg.stop_hash
            );
            
            // Log the raw message bytes for debugging
            let msg_bytes = dashcore::consensus::encode::serialize(&getheaders_msg);
            tracing::debug!("GetHeaders2 raw bytes ({}): {:02x?}", msg_bytes.len(), &msg_bytes[..std::cmp::min(100, msg_bytes.len())]);
            
            // Send GetHeaders2 message for compressed headers
            let result =
                network.send_message(NetworkMessage::GetHeaders2(getheaders_msg.clone())).await;

            match result {
                Ok(_) => {
                    // TODO: Implement timeout and fallback mechanism
                    // For now, we rely on the network layer's timeout handling
                    // In the future, we should:
                    // 1. Track the request with a unique ID
                    // 2. Set a specific timeout for GetHeaders2 response
                    // 3. Fall back to GetHeaders if no response within timeout
                    // 4. Mark peers that don't respond to GetHeaders2 properly
                }
                Err(e) => {
                    tracing::warn!("Failed to send GetHeaders2, falling back to GetHeaders: {}", e);
                    // Fall back to regular GetHeaders
                    network
                        .send_message(NetworkMessage::GetHeaders(getheaders_msg))
                        .await
                        .map_err(|e| {
                            SyncError::Network(format!("Failed to send GetHeaders: {}", e))
                        })?;
                }
            }
        } else {
            tracing::info!("📤 Sending GetHeaders message (uncompressed headers)");
            // Send regular GetHeaders message
            network
                .send_message(NetworkMessage::GetHeaders(getheaders_msg))
                .await
                .map_err(|e| SyncError::Network(format!("Failed to send GetHeaders: {}", e)))?;
        }

        Ok(())
    }

    /// Handle a Headers2 message with compressed headers.
    /// Returns true if the message was processed and sync should continue, false if sync is complete.
    pub async fn handle_headers2_message(
        &mut self,
        headers2: dashcore::network::message_headers2::Headers2Message,
        peer_id: crate::types::PeerId,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<bool> {
        tracing::warn!(
            "⚠️ Headers2 support is currently NON-FUNCTIONAL. Received {} compressed headers from peer {} but cannot process them.",
            headers2.headers.len(),
            peer_id
        );

        // Mark headers2 as failed for this session to avoid retrying
        self.headers2_failed = true;

        // Return an error to trigger fallback to regular headers
        return Err(SyncError::Headers2DecompressionFailed(
            "Headers2 is currently disabled due to protocol compatibility issues".to_string()
        ));
        // If this is the first headers2 message and we need to initialize compression state
        if !headers2.headers.is_empty() {
            // Check if we need to initialize the compression state
            let state = self.headers2_state.get_state(peer_id);
            if state.prev_header.is_none() {
                // If we're syncing from genesis (height 0), initialize with genesis header
                if self.chain_state.tip_height() == 0 {
                    // We have genesis header at index 0
                    if let Some(genesis_header) = self.chain_state.header_at_height(0) {
                        tracing::info!(
                            "Initializing headers2 compression state for peer {} with genesis header",
                            peer_id
                        );
                        self.headers2_state.init_peer_state(peer_id, genesis_header.clone());
                    }
                } else if self.chain_state.tip_height() > 0 {
                    // Get our current tip to use as the base for compression
                    if let Some(tip_header) = self.chain_state.get_tip_header() {
                        tracing::info!(
                            "Initializing headers2 compression state for peer {} with tip header at height {}",
                            peer_id,
                            self.chain_state.tip_height()
                        );
                        self.headers2_state.init_peer_state(peer_id, tip_header);
                    }
                }
            }
        }

        // Decompress headers using the peer's compression state
        let headers = match self
            .headers2_state
            .process_headers(peer_id, headers2.headers.clone())
        {
            Ok(headers) => headers,
            Err(e) => {
                tracing::error!(
                    "Failed to decompress headers2 from peer {}: {}. Headers count: {}, first header compressed: {}, chain height: {}",
                    peer_id,
                    e,
                    headers2.headers.len(),
                    if headers2.headers.is_empty() {
                        "N/A (empty)".to_string()
                    } else {
                        (!headers2.headers[0].is_full()).to_string()
                    },
                    self.chain_state.tip_height()
                );
                
                // If we failed due to missing previous header and we're at genesis,
                // this might be a protocol issue where peer expects us to have genesis in compression state
                if matches!(e, crate::sync::headers2_state::ProcessError::DecompressionError(0, _)) 
                    && self.chain_state.tip_height() == 0 {
                    tracing::warn!(
                        "Headers2 decompression failed at genesis. Peer may be sending compressed headers that reference genesis. Consider falling back to regular headers."
                    );
                }
                
                // Return a specific error that can trigger fallback
                // Mark that headers2 failed for this sync session
                self.headers2_failed = true;
                return Err(SyncError::Headers2DecompressionFailed(format!("Failed to decompress headers: {}", e)));
            }
        };

        // Log compression statistics
        let stats = self.headers2_state.get_stats();
        tracing::info!(
            "📊 Headers2 compression stats: {:.1}% bandwidth saved, {:.1}% compression ratio",
            stats.bandwidth_savings,
            stats.compression_ratio * 100.0
        );

        // Process decompressed headers through the normal flow
        self.handle_headers_message(headers, storage, network).await
    }

    /// Prepare sync state without sending network requests.
    /// This allows monitoring to be set up before requests are sent.
    pub async fn prepare_sync(
        &mut self,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<Option<BlockHash>> {
        if self.syncing_headers {
            return Err(SyncError::SyncInProgress);
        }

        tracing::info!("Preparing header synchronization with reorg support");

        // Get current tip from storage
        let current_tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?;

        let base_hash = match current_tip_height {
            None => {
                // No headers in storage, ensure genesis is stored
                tracing::info!("No tip height found, ensuring genesis block is stored");

                // Get genesis header from chain state (which was initialized with genesis)
                if let Some(genesis_header) = self.chain_state.header_at_height(0) {
                    // Store genesis in storage if not already there
                    if storage
                        .get_header(0)
                        .await
                        .map_err(|e| SyncError::Storage(format!("Failed to check genesis: {}", e)))?
                        .is_none()
                    {
                        tracing::info!("Storing genesis block in storage");
                        storage.store_headers(&[*genesis_header]).await.map_err(|e| {
                            SyncError::Storage(format!("Failed to store genesis: {}", e))
                        })?;
                    }

                    let genesis_hash = genesis_header.block_hash();
                    tracing::info!("Starting from genesis block: {}", genesis_hash);
                    Some(genesis_hash)
                } else {
                    // Check if we can start from a checkpoint
                    if let Some((height, hash)) = self.get_sync_starting_point() {
                        tracing::info!("Starting from checkpoint at height {}", height);
                        Some(hash)
                    } else {
                        // Use network genesis as fallback
                        let genesis_hash =
                            self.config.network.known_genesis_block_hash().ok_or_else(|| {
                                SyncError::Storage("No known genesis hash".to_string())
                            })?;
                        tracing::info!("Starting from network genesis: {}", genesis_hash);
                        Some(genesis_hash)
                    }
                }
            }
            Some(height) => {
                tracing::info!("Current tip height: {}", height);
                // Get the current tip hash
                let tip_header = storage
                    .get_header(height)
                    .await
                    .map_err(|e| SyncError::Storage(format!("Failed to get tip header: {}", e)))?;
                let hash = tip_header.map(|h| h.block_hash());
                tracing::info!("Current tip hash: {:?}", hash);
                hash
            }
        };

        // Set sync state but don't send requests yet
        self.syncing_headers = true;
        self.last_sync_progress = std::time::Instant::now();
        tracing::info!(
            "✅ Prepared header sync state with reorg support, ready to request headers from {:?}",
            base_hash
        );

        Ok(base_hash)
    }

    /// Start synchronizing headers (initialize the sync state).
    pub async fn start_sync(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<bool> {
        tracing::info!("Starting header synchronization with reorg support");

        // Prepare sync state (this will check if sync is already in progress)
        let base_hash = self.prepare_sync(storage).await?;

        // Request headers starting from our current tip or checkpoint
        self.request_headers(network, base_hash).await?;

        Ok(true) // Sync started
    }

    /// Check if a sync timeout has occurred and handle recovery.
    pub async fn check_sync_timeout(
        &mut self,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<bool> {
        if !self.syncing_headers {
            return Ok(false);
        }

        let timeout_duration = if network.peer_count() == 0 {
            // More aggressive timeout when no peers
            std::time::Duration::from_secs(5)
        } else {
            std::time::Duration::from_millis(500)
        };

        if self.last_sync_progress.elapsed() > timeout_duration {
            if network.peer_count() == 0 {
                tracing::warn!("📊 Header sync stalled - no connected peers");
                self.syncing_headers = false; // Reset state to allow restart
                return Err(SyncError::Network("No connected peers for header sync".to_string()));
            }

            tracing::warn!(
                "📊 No header sync progress for {}+ seconds, re-sending header request",
                timeout_duration.as_secs()
            );

            // Get current tip for recovery
            let current_tip_height = storage
                .get_tip_height()
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?;

            let recovery_base_hash = match current_tip_height {
                None => None, // Genesis
                Some(height) => {
                    // Get the current tip hash
                    storage
                        .get_header(height)
                        .await
                        .map_err(|e| {
                            SyncError::Storage(format!(
                                "Failed to get tip header for recovery: {}",
                                e
                            ))
                        })?
                        .map(|h| h.block_hash())
                }
            };

            self.request_headers(network, recovery_base_hash).await?;
            self.last_sync_progress = std::time::Instant::now();

            return Ok(true);
        }

        Ok(false)
    }

    /// Get the optimal starting point for sync based on checkpoints
    pub fn get_sync_starting_point(&self) -> Option<(u32, BlockHash)> {
        // For now, don't use checkpoints as starting point during initial sync
        // This is because we need to have the headers in storage to properly sync
        // TODO: Implement checkpoint-based fast sync that pre-populates headers
        None
    }

    /// Check if we can skip ahead to a checkpoint
    pub fn can_skip_to_checkpoint(&self, current_height: u32) -> Option<(u32, BlockHash)> {
        // Find next checkpoint after current height
        for height in self.checkpoint_manager.checkpoint_heights() {
            if *height > current_height + 1000 {
                // Only skip if checkpoint is far enough ahead
                if let Some(checkpoint) = self.checkpoint_manager.get_checkpoint(*height) {
                    return Some((checkpoint.height, checkpoint.block_hash));
                }
            }
        }
        None
    }

    /// Check if we're past all checkpoints and can relax validation
    pub fn is_past_checkpoints(&self) -> bool {
        self.checkpoint_manager.is_past_last_checkpoint(self.chain_state.get_height())
    }

    /// Check if header sync is currently in progress
    pub fn is_syncing(&self) -> bool {
        self.syncing_headers
    }

    /// Download a single header by hash
    pub async fn download_single_header(
        &mut self,
        block_hash: BlockHash,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
        // Check if we already have this header using the efficient reverse index
        if let Some(height) = storage
            .get_header_height_by_hash(&block_hash)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to check header existence: {}", e)))?
        {
            tracing::debug!("Header for block {} already exists at height {}", block_hash, height);
            return Ok(());
        }

        tracing::info!("📥 Requesting header for block {}", block_hash);

        // Get current tip hash to use as locator
        let current_tip = if let Some(tip_height) = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?
        {
            storage
                .get_header(tip_height)
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get tip header: {}", e)))?
                .map(|h| h.block_hash())
                .unwrap_or_else(|| {
                    self.config
                        .network
                        .known_genesis_block_hash()
                        .expect("unable to get genesis block hash")
                })
        } else {
            self.config
                .network
                .known_genesis_block_hash()
                .expect("unable to get genesis block hash")
        };

        // Create GetHeaders message with specific stop hash
        let getheaders = GetHeadersMessage::new(vec![current_tip], block_hash);

        network
            .send_message(NetworkMessage::GetHeaders(getheaders))
            .await
            .map_err(|e| SyncError::Network(format!("Failed to send GetHeaders: {}", e)))?;

        Ok(())
    }

    /// Reset any pending requests after restart.
    pub fn reset_pending_requests(&mut self) {
        // Reset sync state
        self.syncing_headers = false;
        self.last_sync_progress = std::time::Instant::now();
        // Clear any fork tracking state that shouldn't persist across restarts
        self.fork_detector = ForkDetector::new(self.reorg_config.max_forks);
        tracing::debug!("Reset header sync pending requests");
    }

    /// Get the current chain height
    pub fn get_chain_height(&self) -> u32 {
        self.chain_state.get_height()
    }

    /// Get the tip hash
    pub fn get_tip_hash(&self) -> Option<BlockHash> {
        self.chain_state.tip_hash()
    }
}

/// Result of processing a header
enum HeaderProcessResult {
    ExtendedMainChain,
    CreatedFork,
    ExtendedFork,
    Orphan,
    TriggeredReorg(u32), // Reorg depth
}

/// Adapter to make async StorageManager work with sync ChainStorage
struct SyncStorageAdapter<'a> {
    storage: &'a dyn StorageManager,
}

impl<'a> SyncStorageAdapter<'a> {
    fn new(storage: &'a dyn StorageManager) -> Self {
        Self {
            storage,
        }
    }
}

impl<'a> crate::storage::ChainStorage for SyncStorageAdapter<'a> {
    fn get_header(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<BlockHeader>, crate::error::StorageError> {
        // Use block_in_place to run async code in sync context
        // This is safe because we're already in a tokio runtime
        tokio::task::block_in_place(|| {
            // Get a handle to the current runtime
            let handle = tokio::runtime::Handle::current();

            // Block on the async operation
            handle.block_on(async {
                tracing::trace!("SyncStorageAdapter: Looking up header by hash: {}", hash);

                // First, we need to find the height of this block by hash
                match self.storage.get_header_height_by_hash(hash).await {
                    Ok(Some(height)) => {
                        tracing::trace!(
                            "SyncStorageAdapter: Found header at height {} for hash {}",
                            height,
                            hash
                        );
                        // Now get the header at that height
                        self.storage.get_header(height).await.map_err(|e| {
                            crate::error::StorageError::Io(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                e.to_string(),
                            ))
                        })
                    }
                    Ok(None) => {
                        tracing::trace!("SyncStorageAdapter: No header found for hash {}", hash);
                        Ok(None)
                    }
                    Err(e) => {
                        tracing::error!(
                            "SyncStorageAdapter: Error looking up header by hash {}: {}",
                            hash,
                            e
                        );
                        Err(crate::error::StorageError::Io(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            e.to_string(),
                        )))
                    }
                }
            })
        })
    }

    fn get_header_by_height(
        &self,
        height: u32,
    ) -> Result<Option<BlockHeader>, crate::error::StorageError> {
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();

            handle.block_on(async {
                tracing::trace!("SyncStorageAdapter: Looking up header by height: {}", height);

                match self.storage.get_header(height).await {
                    Ok(header) => {
                        if header.is_some() {
                            tracing::trace!(
                                "SyncStorageAdapter: Found header at height {}",
                                height
                            );
                        } else {
                            tracing::trace!(
                                "SyncStorageAdapter: No header found at height {}",
                                height
                            );
                        }
                        Ok(header)
                    }
                    Err(e) => {
                        tracing::error!(
                            "SyncStorageAdapter: Error looking up header at height {}: {}",
                            height,
                            e
                        );
                        Err(crate::error::StorageError::Io(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            e.to_string(),
                        )))
                    }
                }
            })
        })
    }

    fn get_header_height(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<u32>, crate::error::StorageError> {
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();

            handle.block_on(async {
                tracing::trace!("SyncStorageAdapter: Looking up height for hash: {}", hash);

                match self.storage.get_header_height_by_hash(hash).await {
                    Ok(height) => {
                        if let Some(h) = height {
                            tracing::trace!("SyncStorageAdapter: Hash {} is at height {}", hash, h);
                        } else {
                            tracing::trace!("SyncStorageAdapter: Hash {} not found", hash);
                        }
                        Ok(height)
                    }
                    Err(e) => {
                        tracing::error!(
                            "SyncStorageAdapter: Error looking up height for hash {}: {}",
                            hash,
                            e
                        );
                        Err(crate::error::StorageError::Io(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            e.to_string(),
                        )))
                    }
                }
            })
        })
    }

    fn store_header(
        &self,
        _header: &BlockHeader,
        _height: u32,
    ) -> Result<(), crate::error::StorageError> {
        // Note: This method cannot be properly implemented because StorageManager's store_headers
        // requires &mut self, but ChainStorage's store_header only provides &self.
        // In production code, headers are stored directly through the async StorageManager,
        // not through this sync adapter. This method is only used in tests with MemoryStorage
        // which implements both traits.
        Err(crate::error::StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Cannot store headers through immutable sync adapter",
        )))
    }

    fn get_block_transactions(
        &self,
        _block_hash: &BlockHash,
    ) -> Result<Option<Vec<dashcore::Txid>>, crate::error::StorageError> {
        // Currently not implemented in StorageManager, return None
        Ok(None)
    }

    fn get_transaction(
        &self,
        _txid: &dashcore::Txid,
    ) -> Result<Option<dashcore::Transaction>, crate::error::StorageError> {
        // Currently not implemented in StorageManager, return None
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{ChainStorage, MemoryStorageManager, StorageManager};
    use dashcore_hashes::Hash;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_sync_storage_adapter_queries_storage() {
        // Create a memory storage manager
        let mut storage = MemoryStorageManager::new().await.unwrap();

        // Create a test header
        let genesis = dashcore::blockdata::constants::genesis_block(dashcore::Network::Dash).header;
        let genesis_hash = genesis.block_hash();

        // Store the header using async storage
        storage.store_headers(&[genesis]).await.unwrap();

        // Create sync adapter
        let sync_adapter = SyncStorageAdapter::new(&storage);

        // Test get_header_by_height
        let header = sync_adapter.get_header_by_height(0).unwrap();
        assert!(header.is_some());
        assert_eq!(header.unwrap().block_hash(), genesis_hash);

        // Test get_header_height
        let height = sync_adapter.get_header_height(&genesis_hash).unwrap();
        assert_eq!(height, Some(0));

        // Test get_header (by hash)
        let header = sync_adapter.get_header(&genesis_hash).unwrap();
        assert!(header.is_some());
        assert_eq!(header.unwrap().block_hash(), genesis_hash);

        // Test non-existent header
        let fake_hash = BlockHash::from_byte_array([1; 32]);
        let header = sync_adapter.get_header(&fake_hash).unwrap();
        assert!(header.is_none());

        let height = sync_adapter.get_header_height(&fake_hash).unwrap();
        assert!(height.is_none());
    }
}
