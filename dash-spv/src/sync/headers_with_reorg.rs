//! Header synchronization with reorganization support
//!
//! This module extends the basic header sync with fork detection and reorg handling.

use dashcore::{
    block::{Header as BlockHeader, Version},
    network::constants::NetworkExt,
    network::message::NetworkMessage,
    network::message_blockdata::GetHeadersMessage,
    BlockHash, TxMerkleNode,
};
use dashcore_hashes::Hash;

use crate::chain::checkpoints::{mainnet_checkpoints, testnet_checkpoints, CheckpointManager};
use crate::chain::{ChainTip, ChainTipManager, ChainWork, ForkDetector};
use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::headers2_state::Headers2StateManager;
use crate::types::ChainState;

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
pub struct HeaderSyncManagerWithReorg<S: StorageManager, N: NetworkManager> {
    _phantom_s: std::marker::PhantomData<S>,
    _phantom_n: std::marker::PhantomData<N>,
    config: ClientConfig,
    fork_detector: ForkDetector,
    tip_manager: ChainTipManager,
    checkpoint_manager: CheckpointManager,
    reorg_config: ReorgConfig,
    chain_state: ChainState,
    // WalletState removed - wallet functionality is now handled externally
    headers2_state: Headers2StateManager,
    total_headers_synced: u32,
    syncing_headers: bool,
    last_sync_progress: std::time::Instant,
    headers2_failed: bool,
}

impl<S: StorageManager + Send + Sync + 'static, N: NetworkManager + Send + Sync + 'static>
    HeaderSyncManagerWithReorg<S, N>
{
    /// Create a new header sync manager with reorg support
    pub fn new(config: &ClientConfig, reorg_config: ReorgConfig) -> SyncResult<Self> {
        let chain_state = ChainState::new_for_network(config.network);
        // WalletState removed - wallet functionality is now handled externally

        // Create checkpoint manager based on network
        let checkpoints = match config.network {
            dashcore::Network::Dash => mainnet_checkpoints(),
            dashcore::Network::Testnet => testnet_checkpoints(),
            _ => Vec::new(), // No checkpoints for other networks
        };
        let checkpoint_manager = CheckpointManager::new(checkpoints);

        Ok(Self {
            config: config.clone(),
            fork_detector: ForkDetector::new(reorg_config.max_forks)
                .map_err(|e| SyncError::InvalidState(e.to_string()))?,
            tip_manager: ChainTipManager::new(reorg_config.max_forks),
            checkpoint_manager,
            reorg_config,
            chain_state,
            // WalletState removed
            headers2_state: Headers2StateManager::new(),
            total_headers_synced: 0,
            syncing_headers: false,
            last_sync_progress: std::time::Instant::now(),
            headers2_failed: false,
            _phantom_s: std::marker::PhantomData,
            _phantom_n: std::marker::PhantomData,
        })
    }

    /// Load headers from storage into the chain state
    pub async fn load_headers_from_storage(&mut self, storage: &S) -> SyncResult<u32> {
        // First, try to load the persisted chain state which may contain sync_base_height
        if let Ok(Some(stored_chain_state)) = storage.load_chain_state().await {
            tracing::info!(
                "Loaded chain state from storage with sync_base_height: {}, synced_from_checkpoint: {}",
                stored_chain_state.sync_base_height,
                stored_chain_state.synced_from_checkpoint
            );
            // Update our chain state with the loaded one to preserve sync_base_height
            self.chain_state = stored_chain_state;
        }

        // Get the current tip height from storage
        let tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?;

        let Some(tip_height) = tip_height else {
            tracing::debug!("No headers found in storage");
            // If we're syncing from a checkpoint, this is expected
            if self.chain_state.synced_from_checkpoint && self.chain_state.sync_base_height > 0 {
                tracing::info!("No headers in storage for checkpoint sync - this is expected");
                return Ok(0);
            }
            return Ok(0);
        };

        if tip_height == 0 && !self.chain_state.synced_from_checkpoint {
            tracing::debug!("Only genesis block in storage");
            return Ok(0);
        }

        tracing::info!("Loading {} headers from storage into HeaderSyncManager", tip_height);
        let start_time = std::time::Instant::now();

        // Load headers in batches
        const BATCH_SIZE: u32 = 10_000;
        let mut loaded_count = 0u32;

        // When syncing from a checkpoint, we need to handle storage differently
        // Storage indices start at 0, but represent blockchain heights starting from sync_base_height
        let mut current_storage_index =
            if self.chain_state.synced_from_checkpoint && self.chain_state.sync_base_height > 0 {
                // For checkpoint sync, start from index 0 in storage
                // (which represents blockchain height sync_base_height)
                0u32
            } else {
                // For normal sync from genesis, start from 1 (genesis already in chain state)
                1u32
            };

        while current_storage_index <= tip_height {
            let end_storage_index = (current_storage_index + BATCH_SIZE - 1).min(tip_height);

            // Load batch from storage
            let headers_result =
                storage.load_headers(current_storage_index..end_storage_index + 1).await;

            match headers_result {
                Ok(headers) if !headers.is_empty() => {
                    // Add headers to chain state
                    for header in headers {
                        self.chain_state.add_header(header);
                        loaded_count += 1;
                    }
                }
                Ok(_) => {
                    // Empty headers - this can happen for checkpoint sync with minimal headers
                    tracing::debug!(
                        "No headers found for range {}..{} - continuing",
                        current_storage_index,
                        end_storage_index + 1
                    );
                    // Break out of the loop since we've reached the end of available headers
                    break;
                }
                Err(e) => {
                    // For checkpoint sync with only 1 header stored, this is expected
                    if self.chain_state.synced_from_checkpoint
                        && loaded_count == 0
                        && tip_height == 0
                    {
                        tracing::info!(
                            "No additional headers to load for checkpoint sync - this is expected"
                        );
                        return Ok(0);
                    }
                    return Err(SyncError::Storage(format!("Failed to load headers: {}", e)));
                }
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

            current_storage_index = end_storage_index + 1;
        }

        // When loading from storage, tip_height is the storage index (0-based)
        // Convert to absolute blockchain height
        if self.chain_state.synced_from_checkpoint && self.chain_state.sync_base_height > 0 {
            self.total_headers_synced = self.chain_state.sync_base_height + tip_height;
            tracing::info!(
                "Checkpoint sync initialization: storage_tip={}, sync_base={}, total_headers_synced={}, chain_state.headers.len()={}",
                tip_height,
                self.chain_state.sync_base_height,
                self.total_headers_synced,
                self.chain_state.headers.len()
            );
        } else {
            self.total_headers_synced = tip_height;
        }

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
        storage: &mut S,
        network: &mut N,
    ) -> SyncResult<bool> {
        tracing::info!("🔍 Handle headers message with {} headers (reorg-aware)", headers.len());

        // Step 1: Handle Empty Batch
        if headers.is_empty() {
            tracing::info!(
                "📊 Header sync complete - no more headers from peers. Total headers synced: {}, chain_state.tip_height: {}", 
                self.total_headers_synced,
                self.chain_state.tip_height()
            );
            self.syncing_headers = false;
            return Ok(false);
        }

        // Step 2: Validate Batch Connection Point
        let first_header = &headers[0];
        let tip = self
            .chain_state
            .get_tip_header()
            .ok_or_else(|| SyncError::InvalidState("No tip header in chain state".to_string()))?;

        // Check if the first header connects to our tip
        if first_header.prev_blockhash != tip.block_hash() {
            tracing::warn!(
                "Received header batch that does not connect to our tip. Expected prev_hash: {}, got: {}. Dropping message.",
                tip.block_hash(),
                first_header.prev_blockhash
            );
            // Gracefully drop the message and let timeout mechanism handle re-requesting
            return Ok(true);
        }

        // Special handling for checkpoint sync validation
        if self.chain_state.synced_from_checkpoint && !headers.is_empty() {
            // Check if this might be a genesis or very early block
            let is_genesis = first_header.prev_blockhash == BlockHash::from_byte_array([0; 32]);
            let is_early_block =
                first_header.bits.to_consensus() == 0x1e0ffff0 || first_header.time < 1400000000;

            if is_genesis || is_early_block {
                tracing::error!(
                    "CHECKPOINT SYNC FAILED: Peer sent headers from genesis instead of connecting to checkpoint at height {}. \
                    This indicates the checkpoint may not be valid for this network or the peer doesn't have it.",
                    self.chain_state.sync_base_height
                );
                return Err(SyncError::InvalidState(format!(
                    "Checkpoint sync failed: peer doesn't recognize checkpoint at height {}",
                    self.chain_state.sync_base_height
                )));
            }
        }

        self.last_sync_progress = std::time::Instant::now();

        // Log details about the batch for debugging
        if !headers.is_empty() {
            let last = headers.last().unwrap();
            tracing::debug!(
                "Received headers batch: first.prev_hash={}, first.hash={}, last.hash={}, count={}",
                first_header.prev_blockhash,
                first_header.block_hash(),
                last.block_hash(),
                headers.len()
            );
        }

        // Step 3: Process the Entire Validated Batch

        // Checkpoint Validation: Perform in-memory security check against checkpoints
        let current_height = self.chain_state.get_height();
        for (index, header) in headers.iter().enumerate() {
            let prospective_height = current_height + (index as u32) + 1;

            if self.reorg_config.enforce_checkpoints
                && !self.checkpoint_manager.validate_block(prospective_height, &header.block_hash())
            {
                return Err(SyncError::Validation(format!(
                    "Block at height {} does not match checkpoint",
                    prospective_height
                )));
            }
        }

        // Update Chain State: Add all headers to in-memory chain_state
        for header in &headers {
            self.chain_state.add_header(*header);
        }

        // Store Headers in Bulk: Single atomic database operation
        storage
            .store_headers(&headers)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to store headers batch: {}", e)))?;

        // Update Sync Progress
        let batch_size = headers.len() as u32;
        let previous_total = self.total_headers_synced;
        self.total_headers_synced += batch_size;

        tracing::info!(
            "Header sync progress: processed {} headers in batch, total_headers_synced: {} -> {}, chain_state.headers.len()={}",
            batch_size,
            previous_total,
            self.total_headers_synced,
            self.chain_state.headers.len()
        );

        // Update chain tip manager with the last header in the batch
        if let Some(last_header) = headers.last() {
            let final_height = self.chain_state.get_height();
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
            if let Some(tip) = self.chain_state.get_tip_header() {
                self.request_headers(network, Some(tip.block_hash())).await?;
            }
        }

        Ok(true)
    }

    /// Request headers from the network
    pub async fn request_headers(
        &mut self,
        network: &mut N,
        base_hash: Option<BlockHash>,
    ) -> SyncResult<()> {
        let block_locator = match base_hash {
            Some(hash) => {
                // When syncing from a checkpoint, we need to create a proper locator
                // that helps the peer understand we want headers AFTER this point
                if self.chain_state.synced_from_checkpoint && self.chain_state.sync_base_height > 0
                {
                    // For checkpoint sync, only include the checkpoint hash
                    // Including genesis would allow peers to fall back to sending headers from genesis
                    // if they don't recognize the checkpoint, which is exactly what we want to avoid
                    tracing::debug!(
                        "📍 Using checkpoint-only locator for height {}: [{}]",
                        self.chain_state.sync_base_height,
                        hash
                    );
                    vec![hash]
                } else if network.has_headers2_peer().await && !self.headers2_failed {
                    // Check if this is genesis and we're using headers2
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
            }
            None => {
                // Check if we're syncing from a checkpoint
                if self.chain_state.synced_from_checkpoint && !self.chain_state.headers.is_empty() {
                    // Use the checkpoint hash from chain state
                    let checkpoint_hash = self.chain_state.headers[0].block_hash();
                    tracing::info!(
                        "📍 No base_hash provided but syncing from checkpoint at height {}. Using checkpoint hash: {}",
                        self.chain_state.sync_base_height,
                        checkpoint_hash
                    );
                    vec![checkpoint_hash]
                } else {
                    // Normal sync from genesis
                    let genesis_hash = self
                        .config
                        .network
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
            tracing::debug!(
                "GetHeaders2 details: version={}, locator_hashes={:?}, stop_hash={}",
                getheaders_msg.version,
                getheaders_msg.locator_hashes,
                getheaders_msg.stop_hash
            );

            // Log the raw message bytes for debugging
            let msg_bytes = dashcore::consensus::encode::serialize(&getheaders_msg);
            tracing::debug!(
                "GetHeaders2 raw bytes ({}): {:02x?}",
                msg_bytes.len(),
                &msg_bytes[..std::cmp::min(100, msg_bytes.len())]
            );

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
        _storage: &mut S,
        _network: &mut N,
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
            "Headers2 is currently disabled due to protocol compatibility issues".to_string(),
        ));

        #[allow(unreachable_code)]
        {
            // If this is the first headers2 message, and we need to initialize compression state
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
                            self.headers2_state.init_peer_state(peer_id, *genesis_header);
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

                    // If we failed due to missing previous header, and we're at genesis,
                    // this might be a protocol issue where peer expects us to have genesis in compression state
                    if matches!(
                        e,
                        crate::sync::headers2_state::ProcessError::DecompressionError(0, _)
                    ) && self.chain_state.tip_height() == 0
                    {
                        tracing::warn!(
                        "Headers2 decompression failed at genesis. Peer may be sending compressed headers that reference genesis. Consider falling back to regular headers."
                    );
                    }

                    // Return a specific error that can trigger fallback
                    // Mark that headers2 failed for this sync session
                    self.headers2_failed = true;
                    return Err(SyncError::Headers2DecompressionFailed(format!(
                        "Failed to decompress headers: {}",
                        e
                    )));
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
            self.handle_headers_message(headers, _storage, _network).await
        }
    }

    /// Prepare sync state without sending network requests.
    /// This allows monitoring to be set up before requests are sent.
    pub async fn prepare_sync(&mut self, storage: &mut S) -> SyncResult<Option<BlockHash>> {
        if self.syncing_headers {
            return Err(SyncError::SyncInProgress);
        }

        tracing::info!("Preparing header synchronization with reorg support");
        tracing::info!(
            "Chain state before prepare_sync: sync_base_height={}, synced_from_checkpoint={}, headers_count={}",
            self.chain_state.sync_base_height,
            self.chain_state.synced_from_checkpoint,
            self.chain_state.headers.len()
        );

        // Get current tip from storage
        let current_tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?;

        // If we're syncing from a checkpoint, we need to account for sync_base_height
        let effective_tip_height = if self.chain_state.synced_from_checkpoint {
            if let Some(stored_headers) = current_tip_height {
                let actual_height = self.chain_state.sync_base_height + stored_headers;
                tracing::info!(
                    "Syncing from checkpoint: sync_base_height={}, stored_headers={}, effective_height={}",
                    self.chain_state.sync_base_height,
                    stored_headers,
                    actual_height
                );
                Some(actual_height)
            } else {
                None
            }
        } else {
            tracing::info!(
                "Not syncing from checkpoint or no tip height. synced_from_checkpoint={}, current_tip_height={:?}",
                self.chain_state.synced_from_checkpoint,
                current_tip_height
            );
            current_tip_height
        };

        let base_hash = match effective_tip_height {
            None => {
                // No headers in storage - check if we're syncing from a checkpoint
                if self.chain_state.synced_from_checkpoint && !self.chain_state.headers.is_empty() {
                    // We're syncing from a checkpoint and have the checkpoint header
                    let checkpoint_header = &self.chain_state.headers[0];
                    let checkpoint_hash = checkpoint_header.block_hash();
                    tracing::info!(
                        "No headers in storage but syncing from checkpoint at height {}. Using checkpoint hash: {}",
                        self.chain_state.sync_base_height,
                        checkpoint_hash
                    );
                    Some(checkpoint_hash)
                } else {
                    // Normal sync from genesis
                    tracing::info!("No tip height found, ensuring genesis block is stored");

                    // Get genesis header from chain state (which was initialized with genesis)
                    if let Some(genesis_header) = self.chain_state.header_at_height(0) {
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
                                self.config.network.known_genesis_block_hash().ok_or_else(
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
                if self.chain_state.synced_from_checkpoint
                    && height == self.chain_state.sync_base_height
                {
                    // We're at the checkpoint height - use the checkpoint hash from chain state
                    tracing::info!(
                        "At checkpoint height {}. Chain state has {} headers",
                        height,
                        self.chain_state.headers.len()
                    );

                    // The checkpoint header should be the first (and possibly only) header
                    if !self.chain_state.headers.is_empty() {
                        let checkpoint_header = &self.chain_state.headers[0];
                        let hash = checkpoint_header.block_hash();
                        tracing::info!("Using checkpoint hash for height {}: {}", height, hash);
                        Some(hash)
                    } else {
                        tracing::error!("Synced from checkpoint but no headers in chain state!");
                        None
                    }
                } else {
                    // Get the current tip hash from storage
                    // When syncing from checkpoint, the storage height is different from effective height
                    let storage_height = if self.chain_state.synced_from_checkpoint {
                        // The actual storage height is effective_height - sync_base_height
                        height.saturating_sub(self.chain_state.sync_base_height)
                    } else {
                        height
                    };

                    let tip_header = storage.get_header(storage_height).await.map_err(|e| {
                        SyncError::Storage(format!(
                            "Failed to get tip header at storage height {}: {}",
                            storage_height, e
                        ))
                    })?;
                    let hash = tip_header.map(|h| h.block_hash());
                    tracing::info!(
                        "Current tip hash from storage height {}: {:?}",
                        storage_height,
                        hash
                    );
                    hash
                }
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
    pub async fn start_sync(&mut self, network: &mut N, storage: &mut S) -> SyncResult<bool> {
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
            let current_tip_height = storage
                .get_tip_height()
                .await
                .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?;

            let recovery_base_hash = match current_tip_height {
                None => {
                    // No headers in storage - check if we're syncing from a checkpoint
                    if self.chain_state.synced_from_checkpoint
                        && self.chain_state.sync_base_height > 0
                    {
                        // Use the checkpoint hash from chain state
                        if !self.chain_state.headers.is_empty() {
                            let checkpoint_hash = self.chain_state.headers[0].block_hash();
                            tracing::info!(
                                "Using checkpoint hash for recovery: {} (chain state has {} headers, first header time: {})",
                                checkpoint_hash,
                                self.chain_state.headers.len(),
                                self.chain_state.headers[0].time
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

            self.request_headers(network, recovery_base_hash).await?;
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

    /// Check if we're past all checkpoints and can relax validation
    pub fn is_past_checkpoints(&self) -> bool {
        self.checkpoint_manager.is_past_last_checkpoint(self.chain_state.get_height())
    }

    /// Pre-populate headers from checkpoints for fast initial sync
    /// Note: This requires having prev_blockhash data for checkpoints
    pub async fn prepopulate_from_checkpoints(&mut self, storage: &S) -> SyncResult<u32> {
        // Check if we already have headers
        if let Some(tip_height) = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get tip height: {}", e)))?
        {
            if tip_height > 0 {
                tracing::debug!("Headers already exist in storage (height {}), skipping checkpoint prepopulation", tip_height);
                return Ok(0);
            }
        }

        tracing::info!("Pre-populating headers from checkpoints for fast sync");

        // Now that we have prev_blockhash data, we can implement this!
        let checkpoints = self.checkpoint_manager.checkpoint_heights();
        let mut headers_to_insert = Vec::new();

        for &height in checkpoints {
            if let Some(checkpoint) = self.checkpoint_manager.get_checkpoint(height) {
                // Convert checkpoint to header
                let header = BlockHeader {
                    version: Version::from_consensus(1),
                    prev_blockhash: checkpoint.prev_blockhash,
                    merkle_root: checkpoint
                        .merkle_root
                        .map(|hash| TxMerkleNode::from_byte_array(*hash.as_byte_array()))
                        .unwrap_or_else(|| TxMerkleNode::from_byte_array([0u8; 32])),
                    time: checkpoint.timestamp,
                    bits: checkpoint.target.to_compact_lossy(),
                    nonce: checkpoint.nonce,
                };

                // Verify the header hash matches the checkpoint
                let calculated_hash = header.block_hash();
                if calculated_hash != checkpoint.block_hash {
                    tracing::error!(
                        "Checkpoint hash mismatch at height {}: expected {:?}, got {:?}",
                        height,
                        checkpoint.block_hash,
                        calculated_hash
                    );
                    continue;
                }

                headers_to_insert.push((height, header));
            }
        }

        if headers_to_insert.is_empty() {
            tracing::warn!("No valid headers to prepopulate from checkpoints");
            return Ok(0);
        }

        tracing::info!("Prepopulating {} checkpoint headers", headers_to_insert.len());

        // TODO: Implement batch storage operation
        // For now, we'll need to store them one by one
        let mut count = 0;
        for (height, _header) in headers_to_insert {
            // Note: This would need proper storage implementation
            tracing::debug!("Would store checkpoint header at height {}", height);
            count += 1;
        }

        Ok(count)
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
                .ok_or_else(|| SyncError::MissingDependency("no tip header found".to_string()))?
        } else {
            self.config.network.known_genesis_block_hash().ok_or_else(|| {
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
        // Clear any fork tracking state that shouldn't persist across restarts
        self.fork_detector = ForkDetector::new(self.reorg_config.max_forks).map_err(|e| {
            SyncError::InvalidState(format!("Failed to create fork detector: {}", e))
        })?;
        tracing::debug!("Reset header sync pending requests");
        Ok(())
    }

    /// Get the current chain height
    pub fn get_chain_height(&self) -> u32 {
        // Always use total_headers_synced which tracks the absolute blockchain height
        self.total_headers_synced
    }

    /// Get the tip hash
    pub fn get_tip_hash(&self) -> Option<BlockHash> {
        self.chain_state.tip_hash()
    }

    /// Get the sync base height (used when syncing from checkpoint)
    pub fn get_sync_base_height(&self) -> u32 {
        self.chain_state.sync_base_height
    }

    /// Get the chain state for checkpoint-aware operations
    pub fn get_chain_state(&self) -> &ChainState {
        &self.chain_state
    }

    /// Update the chain state with an externally initialized state (e.g., from checkpoint)
    pub fn set_chain_state(&mut self, chain_state: ChainState) {
        tracing::info!(
            "Updating HeaderSyncManager chain state: sync_base_height={}, synced_from_checkpoint={}, headers_count={}",
            chain_state.sync_base_height,
            chain_state.synced_from_checkpoint,
            chain_state.headers.len()
        );

        // Update total_headers_synced based on the new chain state
        if chain_state.synced_from_checkpoint && chain_state.sync_base_height > 0 {
            // For checkpoint sync, total headers includes the base height
            self.total_headers_synced =
                chain_state.sync_base_height + chain_state.headers.len() as u32;
        } else {
            // For normal sync, it's just the number of headers
            self.total_headers_synced = chain_state.headers.len() as u32;
        }

        self.chain_state = chain_state;
    }
}
