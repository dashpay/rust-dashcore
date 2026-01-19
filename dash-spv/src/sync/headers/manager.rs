//! Header synchronization with fork detection and reorganization handling.

use dashcore::{
    block::Header as BlockHeader, network::constants::NetworkExt, network::message::NetworkMessage,
    network::message_blockdata::GetHeadersMessage, BlockHash,
};
use dashcore_hashes::Hash;

use crate::chain::checkpoints::{mainnet_checkpoints, testnet_checkpoints, CheckpointManager};
use crate::chain::{ChainTip, ChainTipManager, ChainWork};
use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::types::{ChainState, HashedBlockHeader};
use crate::validation::{BlockHeaderValidator, Validator};
use crate::ValidationMode;
use std::sync::Arc;
use tokio::sync::RwLock;

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

/// Manages header synchronization with fork detection and reorganization support
pub struct HeaderSyncManager<S: StorageManager, N: NetworkManager> {
    _phantom_s: std::marker::PhantomData<S>,
    _phantom_n: std::marker::PhantomData<N>,
    config: ClientConfig,
    tip_manager: ChainTipManager,
    checkpoint_manager: CheckpointManager,
    reorg_config: ReorgConfig,
    chain_state: Arc<RwLock<ChainState>>,
    syncing_headers: bool,
    last_sync_progress: std::time::Instant,
    // Cached flag for quick access without locking
    cached_sync_base_height: u32,
}

impl<S: StorageManager, N: NetworkManager> HeaderSyncManager<S, N> {
    /// Create a new header sync manager
    pub fn new(
        config: &ClientConfig,
        reorg_config: ReorgConfig,
        chain_state: Arc<RwLock<ChainState>>,
    ) -> SyncResult<Self> {
        // WalletState removed - wallet functionality is now handled externally

        // Create checkpoint manager based on network
        let checkpoints = match config.network() {
            dashcore::Network::Dash => mainnet_checkpoints(),
            dashcore::Network::Testnet => testnet_checkpoints(),
            _ => Vec::new(), // No checkpoints for other networks
        };
        let checkpoint_manager = CheckpointManager::new(checkpoints);

        Ok(Self {
            config: config.clone(),
            tip_manager: ChainTipManager::new(reorg_config.max_forks),
            checkpoint_manager,
            reorg_config,
            chain_state,
            syncing_headers: false,
            last_sync_progress: std::time::Instant::now(),
            cached_sync_base_height: 0,
            _phantom_s: std::marker::PhantomData,
            _phantom_n: std::marker::PhantomData,
        })
    }

    /// Load headers from storage into the chain state
    pub async fn load_headers_from_storage(&mut self, storage: &S) {
        // First, try to load the persisted chain state which may contain sync_base_height
        if let Ok(Some(stored_chain_state)) = storage.load_chain_state().await {
            tracing::info!(
                "Loaded chain state from storage with sync_base_height: {}",
                stored_chain_state.sync_base_height,
            );
            // Update our chain state with the loaded one
            {
                self.cached_sync_base_height = stored_chain_state.sync_base_height;
                let mut cs = self.chain_state.write().await;
                *cs = stored_chain_state;
            }
        }
    }

    /// Handle a Headers message
    pub async fn handle_headers_message(
        &mut self,
        headers: &[BlockHeader],
        storage: &mut S,
        network: &mut N,
    ) -> SyncResult<bool> {
        tracing::info!("🔍 Handle headers message with {} headers", headers.len());

        // Step 1: Handle Empty Batch
        if headers.is_empty() {
            tracing::info!(
                "📊 Header sync complete - no more headers from peers. Total headers synced: {}, chain_state.tip_height: {}",
                storage.get_stored_headers_len().await,
                storage.get_tip_height().await.unwrap_or(0),
            );
            self.syncing_headers = false;
            return Ok(false);
        }

        // Wrap headers in CachedHeader to avoid redundant X11 hashing
        // This prevents recomputing hashes during validation, logging, and storage
        let cached_headers: Vec<_> = headers.iter().map(HashedBlockHeader::from).collect();

        // Step 2: Validate Batch
        let first_cached = &cached_headers[0];
        let first_header = first_cached.header();

        let tip_height = storage
            .get_tip_height()
            .await
            .ok_or_else(|| SyncError::InvalidState("No tip height in storage".to_string()))?;

        let tip = storage
            .get_header(tip_height)
            .await
            .ok()
            .flatten()
            .ok_or_else(|| SyncError::InvalidState("No tip header in storage".to_string()))?;

        // Check if the first header connects to our tip
        // Cache tip hash to avoid recomputing it
        let tip_cached = HashedBlockHeader::from(tip);
        let tip_hash = tip_cached.hash();

        if first_header.prev_blockhash != *tip_hash {
            tracing::warn!(
                "Received header batch that does not connect to our tip. Expected prev_hash: {}, got: {}. Dropping message.",
                tip_hash,
                first_header.prev_blockhash
            );
            // Gracefully drop the message and let timeout mechanism handle re-requesting
            return Ok(true);
        }

        // Special handling for checkpoint sync validation
        if self.is_synced_from_checkpoint() && !headers.is_empty() {
            // Check if this might be a genesis or very early block
            let is_genesis = first_header.prev_blockhash == BlockHash::from_byte_array([0; 32]);
            let is_early_block =
                first_header.bits.to_consensus() == 0x1e0ffff0 || first_header.time < 1400000000;

            if is_genesis || is_early_block {
                tracing::error!(
                    "CHECKPOINT SYNC FAILED: Peer sent headers from genesis instead of connecting to checkpoint at height {}. \
                    This indicates the checkpoint may not be valid for this network or the peer doesn't have it.",
                    self.get_sync_base_height()
                );
                return Err(SyncError::InvalidState(format!(
                    "Checkpoint sync failed: peer doesn't recognize checkpoint at height {}",
                    self.get_sync_base_height()
                )));
            }
        }

        if self.config.validation_mode() != ValidationMode::None {
            BlockHeaderValidator::new().validate(&cached_headers).map_err(|e| {
                let error = format!("Header validation failed: {}", e);
                tracing::error!(error);
                SyncError::Validation(error)
            })?;
        }

        self.last_sync_progress = std::time::Instant::now();

        // Log details about the batch for debugging
        if !cached_headers.is_empty() {
            let last_cached = cached_headers.last().unwrap();
            // Use cached hashes to avoid redundant X11 computation
            let first_hash = first_cached.hash();
            let last_hash = last_cached.hash();
            tracing::debug!(
                "Received headers batch: first.prev_hash={}, first.hash={}, last.hash={}, count={}",
                first_header.prev_blockhash,
                first_hash,
                last_hash,
                cached_headers.len()
            );
        }

        // Step 3: Process the Entire Validated Batch

        // Checkpoint Validation: Perform in-memory security check against checkpoints
        for (index, cached_header) in cached_headers.iter().enumerate() {
            let prospective_height = tip_height + (index as u32) + 1;

            if self.reorg_config.enforce_checkpoints {
                // Use cached hash to avoid redundant X11 computation in loop
                let header_hash = cached_header.hash();
                if !self.checkpoint_manager.validate_block(prospective_height, header_hash) {
                    return Err(SyncError::Validation(format!(
                        "Block at height {} does not match checkpoint",
                        prospective_height
                    )));
                }
            }
        }

        storage
            .store_headers(headers)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to store headers batch: {}", e)))?;

        tracing::info!(
            "Header sync progress: processed {} headers in batch, total_headers_synced: {}",
            headers.len() as u32,
            storage.get_stored_headers_len().await,
        );

        // Update chain tip manager with the last header in the batch
        if let Some(last_header) = headers.last() {
            let final_height = storage.get_tip_height().await.unwrap_or(0);
            let chain_work = ChainWork::from_height_and_header(final_height, last_header);
            let tip = ChainTip::new(*last_header, final_height, chain_work);
            self.tip_manager
                .add_tip(tip)
                .map_err(|e| SyncError::Storage(format!("Failed to update tip: {}", e)))?;
        }

        // Note: Fork detection is temporarily disabled for batch processing
        // In a production implementation, we would need to handle fork detection
        // at the batch level or in a separate phase

        if self.syncing_headers {
            // During sync mode - request next batch
            // Use the last cached header's hash to avoid redundant X11 computation
            if let Some(last_cached) = cached_headers.last() {
                let hash = last_cached.hash();
                self.request_headers(network, Some(*hash), storage).await?;
            }
        }

        Ok(true)
    }

    /// Request headers from the network
    pub async fn request_headers(
        &mut self,
        network: &mut N,
        base_hash: Option<BlockHash>,
        storage: &S,
    ) -> SyncResult<()> {
        let block_locator = match base_hash {
            Some(hash) => vec![hash],
            None => {
                // Check if we're syncing from a checkpoint
                if self.is_synced_from_checkpoint() && storage.get_stored_headers_len().await > 0 {
                    let first_height = storage
                        .get_start_height()
                        .await
                        .ok_or(SyncError::Storage("Failed to get start height".to_string()))?;
                    let checkpoint_header = storage
                        .get_header(first_height)
                        .await
                        .map_err(|e| {
                            SyncError::Storage(format!("Failed to get first header: {}", e))
                        })?
                        .ok_or(SyncError::Storage(
                            "Storage didn't return first header".to_string(),
                        ))?;

                    // Use the checkpoint hash from chain state
                    let checkpoint_hash = checkpoint_header.block_hash();
                    tracing::info!(
                        "📍 No base_hash provided but syncing from checkpoint at height {}. Using checkpoint hash: {}",
                        self.get_sync_base_height(),
                        checkpoint_hash
                    );
                    vec![checkpoint_hash]
                } else {
                    // Normal sync from genesis
                    let genesis_hash = self
                        .config
                        .network()
                        .known_genesis_block_hash()
                        .unwrap_or(BlockHash::from_byte_array([0; 32]));
                    vec![genesis_hash]
                }
            }
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

        // Log details about the request
        tracing::info!(
            "Preparing headers request - height: {}, base_hash: {:?}",
            storage.get_tip_height().await.unwrap_or(0),
            base_hash
        );

        tracing::debug!("Sending GetHeaders message");
        network
            .send_message(NetworkMessage::GetHeaders(getheaders_msg))
            .await
            .map_err(|e| SyncError::Network(format!("Failed to send GetHeaders: {}", e)))?;

        Ok(())
    }

    /// Prepare sync state without sending network requests.
    /// This allows monitoring to be set up before requests are sent.
    pub async fn prepare_sync(&mut self, storage: &mut S) -> SyncResult<Option<BlockHash>> {
        if self.syncing_headers {
            return Err(SyncError::SyncInProgress);
        }

        tracing::info!("Preparing header synchronization");
        tracing::info!(
            "Chain state before prepare_sync: sync_base_height={}, headers_count={}",
            self.get_sync_base_height(),
            storage.get_stored_headers_len().await
        );

        // Get current tip from storage
        let current_tip_height = storage.get_tip_height().await;

        // If we're syncing from a checkpoint, we need to account for sync_base_height
        let effective_tip_height = if self.is_synced_from_checkpoint() {
            if let Some(tip_height) = current_tip_height {
                tracing::info!(
                    "Syncing from checkpoint: sync_base_height={}, tip_height={}",
                    self.get_sync_base_height(),
                    tip_height
                );
                Some(tip_height)
            } else {
                None
            }
        } else {
            tracing::info!(
                "Not syncing from checkpoint or no tip height. sync_base_height={}, current_tip_height={:?}",
                self.get_sync_base_height(),
                current_tip_height
            );
            current_tip_height
        };

        // We're syncing from a checkpoint and have the checkpoint header
        let first_height = storage
            .get_start_height()
            .await
            .ok_or(SyncError::Storage("Failed to get start height".to_string()))?;
        let checkpoint_header = storage
            .get_header(first_height)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get first header: {}", e)))?
            .ok_or(SyncError::Storage("Storage didn't return first header".to_string()))?;

        let base_hash = match effective_tip_height {
            None => {
                // No headers in storage - check if we're syncing from a checkpoint
                if self.is_synced_from_checkpoint() && storage.get_stored_headers_len().await > 0 {
                    let checkpoint_hash = checkpoint_header.block_hash();
                    tracing::info!(
                        "No headers in storage but syncing from checkpoint at height {}. Using checkpoint hash: {}",
                        self.get_sync_base_height(),
                        checkpoint_hash
                    );
                    Some(checkpoint_hash)
                } else {
                    // Normal sync from genesis
                    tracing::info!("No tip height found, ensuring genesis block is stored");

                    // Get genesis header from chain state (which was initialized with genesis)
                    if let Some(genesis_header) = storage.get_header(0).await.map_err(|e| {
                        SyncError::Storage(format!(
                            "Error trying to get genesis block from storage: {}",
                            e
                        ))
                    })? {
                        // Store genesis in storage if not already there
                        if storage
                            .get_header(0)
                            .await
                            .map_err(|e| {
                                SyncError::Storage(format!("Failed to check genesis: {}", e))
                            })?
                            .is_none()
                        {
                            tracing::info!("Storing genesis block in storage");
                            storage.store_headers(&[genesis_header]).await.map_err(|e| {
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
                                self.config.network().known_genesis_block_hash().ok_or_else(
                                    || SyncError::Storage("No known genesis hash".to_string()),
                                )?;
                            tracing::info!("Starting from network genesis: {}", genesis_hash);
                            Some(genesis_hash)
                        }
                    }
                }
            }
            Some(height) => {
                tracing::info!("Current effective tip height: {}", height);

                // When syncing from a checkpoint, we need to use the checkpoint hash directly
                // if we only have the checkpoint header stored
                if self.is_synced_from_checkpoint() && height == self.get_sync_base_height() {
                    // We're at the checkpoint height - use the checkpoint hash from chain state
                    tracing::info!(
                        "At checkpoint height {}. Chain state has {} headers",
                        height,
                        storage.get_stored_headers_len().await
                    );

                    // The checkpoint header should be the first (and possibly only) header
                    if storage.get_stored_headers_len().await > 0 {
                        let hash = checkpoint_header.block_hash();
                        tracing::info!("Using checkpoint hash for height {}: {}", height, hash);
                        Some(hash)
                    } else {
                        tracing::error!("Synced from checkpoint but no headers in chain state!");
                        None
                    }
                } else {
                    // Get the current tip hash from storage
                    let tip_header = storage.get_header(height).await.map_err(|e| {
                        SyncError::Storage(format!(
                            "Failed to get tip header at height {}: {}",
                            height, e
                        ))
                    })?;
                    let hash = tip_header.map(|h| h.block_hash());
                    tracing::info!("Current tip hash at height {}: {:?}", height, hash);
                    hash
                }
            }
        };

        // Set sync state but don't send requests yet
        self.syncing_headers = true;
        self.last_sync_progress = std::time::Instant::now();
        tracing::info!(
            "✅ Prepared header sync state, ready to request headers from {:?}",
            base_hash
        );

        Ok(base_hash)
    }

    /// Start synchronizing headers (initialize the sync state).
    pub async fn start_sync(&mut self, network: &mut N, storage: &mut S) -> SyncResult<bool> {
        tracing::info!("Starting header synchronization");

        // Prepare sync state (this will check if sync is already in progress)
        let base_hash = self.prepare_sync(storage).await?;

        // Request headers starting from our current tip or checkpoint
        self.request_headers(network, base_hash, storage).await?;

        Ok(true) // Sync started
    }

    /// Check if a sync timeout has occurred and handle recovery.
    pub async fn check_sync_timeout(
        &mut self,
        storage: &mut S,
        network: &mut N,
    ) -> SyncResult<bool> {
        if !self.syncing_headers {
            return Ok(false);
        }

        let timeout_duration = if network.peer_count() == 0 {
            // More aggressive timeout when no peers
            std::time::Duration::from_secs(10)
        } else {
            std::time::Duration::from_secs(5)
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
            let current_tip_height = storage.get_tip_height().await;

            let first_height = storage
                .get_start_height()
                .await
                .ok_or(SyncError::Storage("Failed to get start height".to_string()))?;
            let checkpoint_header = storage
                .get_header(first_height)
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get first header: {}", e)))?
                .ok_or(SyncError::Storage("Storage didn't return first header".to_string()))?;

            let recovery_base_hash = match current_tip_height {
                None => {
                    // No headers in storage - check if we're syncing from a checkpoint
                    if self.is_synced_from_checkpoint() {
                        // Use the checkpoint hash from chain state
                        if storage.get_stored_headers_len().await > 0 {
                            let checkpoint_hash = checkpoint_header.block_hash();
                            tracing::info!(
                                "Using checkpoint hash for recovery: {} (chain state has {} headers, first header time: {})",
                                checkpoint_hash,
                                storage.get_stored_headers_len().await,
                                checkpoint_header.time
                            );
                            Some(checkpoint_hash)
                        } else {
                            tracing::warn!("No checkpoint header in chain state for recovery");
                            None
                        }
                    } else {
                        None // Genesis
                    }
                }
                Some(height) => {
                    // When syncing from checkpoint, adjust the storage height
                    let storage_height = height;

                    // Get the current tip hash
                    storage
                        .get_header(storage_height)
                        .await
                        .map_err(|e| {
                            SyncError::Storage(format!(
                                "Failed to get tip header for recovery at height {}: {}",
                                storage_height, e
                            ))
                        })?
                        .map(|h| h.block_hash())
                }
            };

            self.request_headers(network, recovery_base_hash, storage).await?;
            self.last_sync_progress = std::time::Instant::now();

            return Ok(true);
        }

        Ok(false)
    }

    /// Get the optimal starting point for sync based on checkpoints
    pub fn get_sync_starting_point(&self) -> Option<(u32, BlockHash)> {
        // For now, we can't check storage here without passing it as parameter
        // The actual implementation would need to check if headers exist in storage
        // before deciding to use checkpoints

        // No headers in storage, use checkpoint based on wallet creation time
        // TODO: Pass wallet creation time from client config
        if let Some(checkpoint) = self.checkpoint_manager.get_sync_checkpoint(None) {
            // Return checkpoint as starting point
            // Note: We'll need to prepopulate headers from checkpoints for this to work properly
            return Some((checkpoint.height, checkpoint.block_hash));
        }

        // No suitable checkpoint, start from genesis
        None
    }

    /// Check if we can skip ahead to a checkpoint during sync
    pub fn can_skip_to_checkpoint(
        &self,
        current_height: u32,
        peer_height: u32,
    ) -> Option<(u32, BlockHash)> {
        // Don't skip if we're already close to the peer's tip
        if peer_height.saturating_sub(current_height) < 1000 {
            return None;
        }

        // Find next checkpoint after current height
        let checkpoint_heights = self.checkpoint_manager.checkpoint_heights();

        for height in checkpoint_heights {
            // Skip if checkpoint is:
            // 1. After our current position
            // 2. Before or at peer's height (peer has it)
            // 3. Far enough ahead to be worth skipping (at least 500 blocks)
            if *height > current_height && *height <= peer_height && *height > current_height + 500
            {
                if let Some(checkpoint) = self.checkpoint_manager.get_checkpoint(*height) {
                    tracing::info!(
                        "Can skip from height {} to checkpoint at height {}",
                        current_height,
                        checkpoint.height
                    );
                    return Some((checkpoint.height, checkpoint.block_hash));
                }
            }
        }
        None
    }

    /// Check if header sync is currently in progress
    pub fn is_syncing(&self) -> bool {
        self.syncing_headers
    }

    /// Download a single header by hash
    pub async fn download_single_header(
        &mut self,
        block_hash: BlockHash,
        network: &mut N,
        storage: &mut S,
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
        let current_tip = if let Some(tip_height) = storage.get_tip_height().await {
            storage
                .get_header(tip_height)
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get tip header: {}", e)))?
                .map(|h| h.block_hash())
                .ok_or_else(|| SyncError::MissingDependency("no tip header found".to_string()))?
        } else {
            self.config.network().known_genesis_block_hash().ok_or_else(|| {
                SyncError::MissingDependency("no genesis block hash for network".to_string())
            })?
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
    pub fn reset_pending_requests(&mut self) -> SyncResult<()> {
        // Reset sync state
        self.syncing_headers = false;
        self.last_sync_progress = std::time::Instant::now();
        tracing::debug!("Reset header sync pending requests");
        Ok(())
    }

    /// Get the current chain height
    pub async fn get_chain_height(&self, storage: &S) -> u32 {
        storage.get_tip_height().await.unwrap_or(0)
    }

    /// Get the sync base height (used when syncing from checkpoint)
    pub fn get_sync_base_height(&self) -> u32 {
        self.cached_sync_base_height
    }

    /// Whether we're syncing from a checkpoint
    pub fn is_synced_from_checkpoint(&self) -> bool {
        self.cached_sync_base_height > 0
    }

    /// Update cached flags and totals based on an external state snapshot
    pub fn update_cached_from_state_snapshot(&mut self, sync_base_height: u32) {
        self.cached_sync_base_height = sync_base_height;
    }
}
