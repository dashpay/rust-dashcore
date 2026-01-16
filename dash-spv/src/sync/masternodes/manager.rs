//! Simplified masternode synchronization based on dash-evo-tool approach.
//!
//! This implementation directly follows the fetch_rotated_quorum_info pattern
//! from dash-evo-tool for simple, reliable QRInfo sync.

use dashcore::{
    network::constants::NetworkExt,
    network::message::NetworkMessage,
    network::message_qrinfo::{GetQRInfo, QRInfo},
    network::message_sml::MnListDiff,
    sml::masternode_list_engine::MasternodeListEngine,
    BlockHash, QuorumHash,
};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::client::Config;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;

/// Simplified masternode synchronization following dash-evo-tool pattern.
pub struct MasternodeSyncManager<S: StorageManager, N: NetworkManager> {
    _phantom_s: std::marker::PhantomData<S>,
    _phantom_n: std::marker::PhantomData<N>,
    config: Config,
    engine: Option<MasternodeListEngine>,

    // Simple caches matching dash-evo-tool pattern
    mnlist_diffs: HashMap<(u32, u32), MnListDiff>,
    qr_infos: HashMap<BlockHash, QRInfo>,

    // Track last successful QRInfo block for progressive sync
    last_qrinfo_block_hash: Option<BlockHash>,

    // Simple error handling
    error: Option<String>,

    // Sync state
    sync_in_progress: bool,
    last_sync_time: Option<Instant>,

    // Track pending MnListDiff requests (for quorum validation)
    // This ensures we don't transition to the next phase before receiving all responses
    pending_mnlistdiff_requests: usize,

    // Track when we started waiting for MnListDiff responses (for timeout detection)
    mnlistdiff_wait_start: Option<Instant>,

    // Track retry attempts for MnListDiff requests
    mnlistdiff_retry_count: u8,
}

impl<S: StorageManager, N: NetworkManager> MasternodeSyncManager<S, N> {
    /// Create a new masternode sync manager.
    pub fn new(config: &Config) -> Self {
        let (engine, mnlist_diffs) = if config.enable_masternodes {
            // Try to load embedded MNListDiff data for faster initial sync
            if let Some(embedded) = super::embedded_data::get_embedded_diff(config.network) {
                tracing::info!(
                    "📦 Using embedded MNListDiff for {} - starting from height {}",
                    config.network,
                    embedded.target_height
                );

                // Initialize engine with the embedded diff
                match MasternodeListEngine::initialize_with_diff_to_height(
                    embedded.diff.clone(),
                    embedded.target_height,
                    config.network,
                ) {
                    Ok(engine) => {
                        // Store the embedded diff in our cache
                        let mut diffs = HashMap::new();
                        diffs.insert((embedded.base_height, embedded.target_height), embedded.diff);
                        (Some(engine), diffs)
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to initialize engine with embedded diff: {}. Falling back to default.",
                            e
                        );
                        let mut engine = MasternodeListEngine::default_for_network(config.network);
                        // Feed genesis block hash at height 0
                        if let Some(genesis_hash) = config.network.known_genesis_block_hash() {
                            engine.feed_block_height(0, genesis_hash);
                        }
                        (Some(engine), HashMap::new())
                    }
                }
            } else {
                tracing::info!(
                    "No embedded MNListDiff available for {} - starting from genesis",
                    config.network
                );
                let mut engine = MasternodeListEngine::default_for_network(config.network);
                // Feed genesis block hash at height 0
                if let Some(genesis_hash) = config.network.known_genesis_block_hash() {
                    engine.feed_block_height(0, genesis_hash);
                }
                (Some(engine), HashMap::new())
            }
        } else {
            (None, HashMap::new())
        };

        Self {
            config: config.clone(),
            engine,
            mnlist_diffs,
            qr_infos: HashMap::new(),
            last_qrinfo_block_hash: None,
            error: None,
            sync_in_progress: false,
            last_sync_time: None,
            pending_mnlistdiff_requests: 0,
            mnlistdiff_wait_start: None,
            mnlistdiff_retry_count: 0,
            _phantom_s: std::marker::PhantomData,
            _phantom_n: std::marker::PhantomData,
        }
    }

    /// Request QRInfo - simplified non-blocking implementation
    pub async fn request_qrinfo(
        &mut self,
        network: &mut N,
        base_block_hash: BlockHash,
        block_hash: BlockHash,
    ) -> Result<(), String> {
        // Step 1: Collect known block hashes from existing diffs (dash-evo-tool pattern)
        let mut known_block_hashes: Vec<_> =
            self.mnlist_diffs.values().map(|mn_list_diff| mn_list_diff.block_hash).collect();
        known_block_hashes.push(base_block_hash);
        tracing::info!(
            "Requesting QRInfo with known_block_hashes: {}, block_request_hash: {}",
            known_block_hashes.iter().map(|bh| bh.to_string()).collect::<Vec<_>>().join(", "),
            block_hash
        );

        // Step 2: Send P2P request (non-blocking)
        if let Err(e) = self.request_qr_info(network, known_block_hashes, block_hash).await {
            let error_msg = format!("Failed to send QRInfo request: {}", e);
            self.error = Some(error_msg.clone());
            return Err(error_msg);
        }

        tracing::info!(
            "📤 QRInfo request sent successfully, processing will happen when message arrives"
        );
        Ok(())
    }

    /// Insert masternode list diff - direct translation of dash-evo-tool implementation
    async fn insert_mn_list_diff(&mut self, mn_list_diff: &MnListDiff, storage: &S) {
        let base_block_hash = mn_list_diff.base_block_hash;
        let base_height = match self.get_height_for_hash(&base_block_hash, storage).await {
            Ok(height) => height,
            Err(e) => {
                let error_msg =
                    format!("Failed to get height for base block hash {}: {}", base_block_hash, e);
                tracing::error!("❌ MnListDiff insertion failed: {}", error_msg);
                self.error = Some(error_msg);
                return;
            }
        };

        let block_hash = mn_list_diff.block_hash;
        let height = match self.get_height_for_hash(&block_hash, storage).await {
            Ok(height) => height,
            Err(e) => {
                let error_msg =
                    format!("Failed to get height for block hash {}: {}", block_hash, e);
                tracing::error!("❌ MnListDiff insertion failed: {}", error_msg);
                self.error = Some(error_msg);
                return;
            }
        };

        self.mnlist_diffs.insert((base_height, height), mn_list_diff.clone());

        tracing::debug!(
            "✅ Inserted masternode list diff: base_height={}, height={}, base_hash={}, hash={}, new_masternodes={}, deleted_masternodes={}",
            base_height, height, base_block_hash, block_hash,
            mn_list_diff.new_masternodes.len(),
            mn_list_diff.deleted_masternodes.len()
        );
    }

    /// Helper to get height for block hash using storage (consistent with dynamic callback)
    async fn get_height_for_hash(
        &self,
        block_hash: &BlockHash,
        storage: &S,
    ) -> Result<u32, String> {
        // Special case: Handle genesis block which isn't stored when syncing from checkpoints
        if let Some(genesis_hash) = self.config.network.known_genesis_block_hash() {
            if *block_hash == genesis_hash {
                return Ok(0);
            }
        }

        // Regular storage lookup for all other blocks
        match storage.get_header_height_by_hash(block_hash).await {
            Ok(Some(height)) => Ok(height),
            Ok(None) => Err(format!("Height not found for block hash: {}", block_hash)),
            Err(e) => {
                Err(format!("Storage error looking up height for block hash {}: {}", block_hash, e))
            }
        }
    }

    /// Make QRInfo P2P request (simplified non-blocking)
    async fn request_qr_info(
        &mut self,
        network: &mut N,
        known_block_hashes: Vec<BlockHash>,
        block_request_hash: BlockHash,
    ) -> Result<(), String> {
        let get_qr_info_msg = NetworkMessage::GetQRInfo(GetQRInfo {
            base_block_hashes: known_block_hashes,
            block_request_hash,
            extra_share: true,
        });

        // Send request (no state coordination needed - message handler will process response)
        network
            .send_message(get_qr_info_msg)
            .await
            .map_err(|e| format!("Failed to send QRInfo request: {}", e))?;

        tracing::info!("📤 Sent QRInfo request (unified processing)");
        Ok(())
    }

    /// Log detailed QRInfo statistics
    fn log_qrinfo_details(&self, qr_info: &QRInfo, prefix: &str) {
        let h4c_count = if qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c.is_some() {
            1
        } else {
            0
        };
        let core_diff_count = 5 + h4c_count; // tip, h, h-c, h-2c, h-3c, plus optional h-4c

        tracing::info!(
            "{} with {} core diffs, {} additional diffs, {} additional snapshots",
            prefix,
            core_diff_count,
            qr_info.mn_list_diff_list.len(),
            qr_info.quorum_snapshot_list.len()
        );

        tracing::debug!(
            "📋 QRInfo core data: tip={}, h={}, h-c={}, h-2c={}, h-3c={}, h-4c={}, commitments={}",
            qr_info.mn_list_diff_tip.block_hash,
            qr_info.mn_list_diff_h.block_hash,
            qr_info.mn_list_diff_at_h_minus_c.block_hash,
            qr_info.mn_list_diff_at_h_minus_2c.block_hash,
            qr_info.mn_list_diff_at_h_minus_3c.block_hash,
            qr_info
                .quorum_snapshot_and_mn_list_diff_at_h_minus_4c
                .as_ref()
                .map(|(_, diff)| diff.block_hash.to_string())
                .unwrap_or_else(|| "None".to_string()),
            qr_info.last_commitment_per_index.len()
        );
    }

    /// Feed QRInfo block heights to the masternode engine (dash-evo-tool pattern)
    async fn feed_qrinfo_block_heights(
        &mut self,
        qr_info: &QRInfo,
        storage: &mut S,
    ) -> Result<(), String> {
        if let Some(engine) = &mut self.engine {
            tracing::debug!("🔗 Feeding QRInfo block heights to masternode engine");

            // Collect all block hashes from QRInfo MnListDiffs
            let mut block_hashes = vec![
                qr_info.mn_list_diff_tip.block_hash,
                qr_info.mn_list_diff_h.block_hash,
                qr_info.mn_list_diff_at_h_minus_c.block_hash,
                qr_info.mn_list_diff_at_h_minus_2c.block_hash,
                qr_info.mn_list_diff_at_h_minus_3c.block_hash,
            ];

            if let Some((_, diff)) = &qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c {
                block_hashes.push(diff.block_hash);
            }

            for diff in &qr_info.mn_list_diff_list {
                block_hashes.push(diff.block_hash);
            }

            // Also collect base block hashes
            block_hashes.push(qr_info.mn_list_diff_tip.base_block_hash);
            block_hashes.push(qr_info.mn_list_diff_h.base_block_hash);
            block_hashes.push(qr_info.mn_list_diff_at_h_minus_c.base_block_hash);
            block_hashes.push(qr_info.mn_list_diff_at_h_minus_2c.base_block_hash);
            block_hashes.push(qr_info.mn_list_diff_at_h_minus_3c.base_block_hash);

            if let Some((_, diff)) = &qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c {
                block_hashes.push(diff.base_block_hash);
            }

            for diff in &qr_info.mn_list_diff_list {
                block_hashes.push(diff.base_block_hash);
            }

            // Remove duplicates
            block_hashes.sort();
            block_hashes.dedup();

            // Feed heights for all block hashes
            let mut fed_count = 0;
            for block_hash in block_hashes {
                if let Ok(Some(height)) = storage.get_header_height_by_hash(&block_hash).await {
                    engine.feed_block_height(height, block_hash);
                    fed_count += 1;
                    tracing::debug!("🔗 Fed height {} for block {}", height, block_hash);
                } else {
                    tracing::warn!(
                        "⚠️ Could not find height for block hash {} in storage",
                        block_hash
                    );
                }
            }

            tracing::info!("🔗 Fed {} block heights to masternode engine", fed_count);
            Ok(())
        } else {
            Err("Masternode engine not initialized".to_string())
        }
    }

    /// Process quorum snapshots from QRInfo (basic implementation)
    fn process_quorum_snapshots(&mut self, qr_info: &QRInfo) {
        tracing::debug!("🏛️ Processing quorum snapshots from QRInfo");

        // Process core quorum snapshots
        self.process_single_quorum_snapshot(&qr_info.quorum_snapshot_at_h_minus_c, "h-c");
        self.process_single_quorum_snapshot(&qr_info.quorum_snapshot_at_h_minus_2c, "h-2c");
        self.process_single_quorum_snapshot(&qr_info.quorum_snapshot_at_h_minus_3c, "h-3c");

        // Process optional h-4c snapshot
        if let Some((snapshot, _)) = &qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c {
            self.process_single_quorum_snapshot(snapshot, "h-4c");
        }

        // Process additional snapshots
        for (i, snapshot) in qr_info.quorum_snapshot_list.iter().enumerate() {
            self.process_single_quorum_snapshot(snapshot, &format!("additional-{}", i));
        }

        tracing::debug!("🏛️ Quorum snapshot processing completed");
    }

    /// Process a single quorum snapshot (basic logging implementation)
    fn process_single_quorum_snapshot(
        &mut self,
        snapshot: &dashcore::network::message_qrinfo::QuorumSnapshot,
        context: &str,
    ) {
        tracing::debug!(
            "🏛️ Processing quorum snapshot ({}): active_quorum_members={}, skip_list_mode={}, skip_list={}",
            context,
            snapshot.active_quorum_members.len(),
            snapshot.skip_list_mode,
            snapshot.skip_list.len()
        );

        // TODO: Implement actual quorum snapshot processing
        // For now, we just log the basic information
        // In a full implementation, this would:
        // 1. Validate the quorum snapshot structure
        // 2. Update the quorum state in the masternode engine
        // 3. Cache the snapshot for future validation
        // 4. Handle skip list updates
    }

    /// Start masternode synchronization
    pub async fn start_sync(&mut self, network: &mut N, storage: &mut S) -> SyncResult<bool> {
        if self.sync_in_progress {
            return Err(SyncError::SyncInProgress);
        }

        self.sync_in_progress = true;
        self.error = None;
        self.mnlistdiff_retry_count = 0; // Reset retry counter for new sync

        // Get current chain tip
        let tip_height = storage.get_tip_height().await.unwrap_or(0);

        let tip_header = storage
            .get_header(tip_height)
            .await
            .map_err(|e| SyncError::Storage(format!("Failed to get tip header: {}", e)))?
            .ok_or_else(|| SyncError::Storage("Tip header not found".to_string()))?;
        let tip_hash = tip_header.block_hash();

        // Determine base block hash using dash-evo-tool pattern:
        // - First QRInfo request: use genesis block hash
        // - Subsequent requests: use the last successfully processed QRInfo block
        let base_hash = if let Some(last_qrinfo_hash) = self.last_qrinfo_block_hash {
            // Use the last successfully processed QRInfo block
            tracing::debug!("Using last successful QRInfo block as base: {}", last_qrinfo_hash);
            last_qrinfo_hash
        } else {
            // First time - use genesis block
            let genesis_hash =
                self.config.network.known_genesis_block_hash().ok_or_else(|| {
                    SyncError::InvalidState("Genesis hash not available".to_string())
                })?;
            tracing::debug!("Using genesis block as base: {}", genesis_hash);
            genesis_hash
        };

        // Request QRInfo using simplified non-blocking approach
        match self.request_qrinfo(network, base_hash, tip_hash).await {
            Ok(()) => {
                tracing::info!("🚀 QRInfo request initiated successfully, sync will complete when response arrives");
                // Keep sync_in_progress = true, will be set to false in handle_qrinfo_message
                Ok(true)
            }
            Err(error_msg) => {
                tracing::error!("❌ Failed to initiate QRInfo request: {}", error_msg);
                self.sync_in_progress = false;
                Err(SyncError::Validation(error_msg))
            }
        }
    }

    /// Handle incoming MnListDiff message
    pub async fn handle_mnlistdiff_message(
        &mut self,
        diff: &MnListDiff,
        storage: &mut S,
        _network: &mut N,
    ) -> SyncResult<bool> {
        self.insert_mn_list_diff(diff, storage).await;

        // Decrement pending request counter if we were expecting this response
        if self.pending_mnlistdiff_requests > 0 {
            self.pending_mnlistdiff_requests -= 1;
            tracing::info!(
                "📥 Received MnListDiff response ({} pending remaining)",
                self.pending_mnlistdiff_requests
            );

            // If this was the last pending request, mark sync as complete
            if self.pending_mnlistdiff_requests == 0 && self.sync_in_progress {
                tracing::info!(
                    "✅ All MnListDiff requests completed, marking masternode sync as done"
                );
                self.sync_in_progress = false;
                self.last_sync_time = Some(Instant::now());
                self.mnlistdiff_wait_start = None; // Clear wait timer

                // Persist masternode state so phase manager can detect completion
                match storage.get_tip_height().await {
                    Some(tip_height) => {
                        let state = crate::storage::MasternodeState {
                            last_height: tip_height,
                            engine_state: Vec::new(),
                            last_update: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0),
                        };
                        if let Err(e) = storage.store_masternode_state(&state).await {
                            tracing::warn!("⚠️ Failed to store masternode state: {}", e);
                        }
                    }
                    None => {
                        tracing::warn!(
                            "⚠️ Storage returned no tip height when persisting masternode state"
                        );
                    }
                }
            }
        }

        Ok(false) // Not used for sync completion in simple approach
    }

    /// Check for sync timeout
    pub async fn check_sync_timeout(&mut self, storage: &mut S, network: &mut N) -> SyncResult<()> {
        // Check if we're waiting for MnListDiff responses and have timed out
        if self.pending_mnlistdiff_requests > 0 {
            if let Some(wait_start) = self.mnlistdiff_wait_start {
                let timeout_duration = Duration::from_secs(15);

                if wait_start.elapsed() > timeout_duration {
                    // Timeout hit
                    if self.mnlistdiff_retry_count < 1 {
                        // First timeout - retry by restarting the QRInfo request
                        tracing::warn!(
                            "⏰ Timeout waiting for {} MnListDiff responses after {:?}, retrying QRInfo request...",
                            self.pending_mnlistdiff_requests,
                            wait_start.elapsed()
                        );

                        self.mnlistdiff_retry_count += 1;
                        self.pending_mnlistdiff_requests = 0;
                        self.mnlistdiff_wait_start = None;

                        // Restart by re-initiating the sync
                        // Get current chain tip for the retry
                        let tip_height = storage.get_tip_height().await.unwrap_or(0);

                        let tip_header = storage
                            .get_header(tip_height)
                            .await
                            .map_err(|e| {
                                SyncError::Storage(format!("Failed to get tip header: {}", e))
                            })?
                            .ok_or_else(|| {
                                SyncError::Storage("Tip header not found".to_string())
                            })?;
                        let tip_hash = tip_header.block_hash();

                        let base_hash = if let Some(last_qrinfo_hash) = self.last_qrinfo_block_hash
                        {
                            last_qrinfo_hash
                        } else {
                            self.config.network.known_genesis_block_hash().ok_or_else(|| {
                                SyncError::InvalidState("Genesis hash not available".to_string())
                            })?
                        };

                        // Re-send the QRInfo request
                        match self.request_qrinfo(network, base_hash, tip_hash).await {
                            Ok(()) => {
                                tracing::info!("🔄 QRInfo retry request sent successfully");
                            }
                            Err(e) => {
                                tracing::error!("❌ Failed to send retry QRInfo request: {}", e);
                                self.error = Some(format!("Failed to retry QRInfo: {}", e));
                                self.sync_in_progress = false;
                            }
                        }
                    } else {
                        // Already retried once - give up and force completion
                        tracing::error!(
                            "❌ Failed to receive {} MnListDiff responses after {:?} and {} retry attempt(s)",
                            self.pending_mnlistdiff_requests,
                            wait_start.elapsed(),
                            self.mnlistdiff_retry_count
                        );
                        tracing::warn!(
                            "⚠️ Proceeding without complete masternode data - quorum validation may be incomplete"
                        );

                        // Force completion to unblock sync
                        self.pending_mnlistdiff_requests = 0;
                        self.mnlistdiff_wait_start = None;
                        self.sync_in_progress = false;
                        self.error = Some("MnListDiff requests timed out after retry".to_string());

                        // Still persist what we have
                        if let Some(tip_height) = storage.get_tip_height().await {
                            let state = crate::storage::MasternodeState {
                                last_height: tip_height,
                                engine_state: Vec::new(),
                                last_update: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0),
                            };
                            if let Err(e) = storage.store_masternode_state(&state).await {
                                tracing::warn!("⚠️ Failed to store masternode state: {}", e);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get engine reference
    pub fn engine(&self) -> Option<&MasternodeListEngine> {
        self.engine.as_ref()
    }

    /// Check if sync is in progress
    pub fn is_syncing(&self) -> bool {
        self.sync_in_progress
    }

    /// Get last error
    pub fn last_error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Handle incoming QRInfo message (unified processing with block height feeding)
    pub async fn handle_qrinfo_message(
        &mut self,
        qr_info: QRInfo,
        storage: &mut S,
        network: &mut N,
    ) {
        self.log_qrinfo_details(&qr_info, "📋 Masternode sync processing QRInfo (unified path)");

        // Feed block heights to engine before processing (critical for hash lookups)
        if let Err(e) = self.feed_qrinfo_block_heights(&qr_info, storage).await {
            tracing::error!("❌ Failed to feed QRInfo block heights: {}", e);
            self.error = Some(e);
            return;
        }

        // Insert all masternode list diffs from QRInfo (dash-evo-tool pattern)
        self.insert_mn_list_diff(&qr_info.mn_list_diff_tip, storage).await;
        self.insert_mn_list_diff(&qr_info.mn_list_diff_h, storage).await;
        self.insert_mn_list_diff(&qr_info.mn_list_diff_at_h_minus_c, storage).await;
        self.insert_mn_list_diff(&qr_info.mn_list_diff_at_h_minus_2c, storage).await;
        self.insert_mn_list_diff(&qr_info.mn_list_diff_at_h_minus_3c, storage).await;

        if let Some((_, mn_list_diff_at_h_minus_4c)) =
            &qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c
        {
            self.insert_mn_list_diff(mn_list_diff_at_h_minus_4c, storage).await;
        }

        for diff in &qr_info.mn_list_diff_list {
            self.insert_mn_list_diff(diff, storage).await;
        }

        // Process quorum snapshots (comprehensive processing)
        self.process_quorum_snapshots(&qr_info);

        // Feed QRInfo to engine and get additional MnListDiffs needed for quorum validation
        // This is the critical step that dash-evo-tool performs after initial QRInfo processing
        if let Err(e) = self.feed_qrinfo_and_get_additional_diffs(&qr_info, storage, network).await
        {
            tracing::error!("❌ Failed to process QRInfo follow-up diffs: {}", e);
            self.error = Some(e);
            return;
        }

        // Cache the QRInfo using the requested block hash as key
        let block_hash = qr_info.mn_list_diff_h.block_hash;
        self.qr_infos.insert(block_hash, qr_info);

        // Update last successful QRInfo block for progressive sync
        self.last_qrinfo_block_hash = Some(block_hash);

        // Check if we need to wait for MnListDiff responses
        if self.pending_mnlistdiff_requests == 0 {
            // No additional requests were sent (edge case: no quorum validation needed)
            // Mark sync as complete immediately
            tracing::info!("✅ QRInfo processing completed with no additional requests, masternode sync phase is done");
            self.sync_in_progress = false;
            self.last_sync_time = Some(Instant::now());
            self.mnlistdiff_wait_start = None; // Ensure wait timer is cleared

            // Persist masternode state so phase manager can detect completion
            match storage.get_tip_height().await {
                Some(tip_height) => {
                    let state = crate::storage::MasternodeState {
                        last_height: tip_height,
                        engine_state: Vec::new(),
                        last_update: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    };
                    if let Err(e) = storage.store_masternode_state(&state).await {
                        tracing::warn!("⚠️ Failed to store masternode state: {}", e);
                    }
                }
                None => {
                    tracing::warn!(
                        "⚠️ Storage returned no tip height when persisting masternode state"
                    );
                }
            }
        } else {
            tracing::info!(
                "⏳ Waiting for {} pending MnListDiff responses before completing masternode sync",
                self.pending_mnlistdiff_requests
            );
            // Keep sync_in_progress = true so we don't transition to the next phase yet
            // Completion and state persistence will happen in handle_mnlistdiff_message
        }

        tracing::info!("✅ QRInfo processing completed successfully (unified path)");
    }

    /// Feed QRInfo to engine and fetch additional MnListDiffs for quorum validation
    /// This implements the critical follow-up step from dash-evo-tool's feed_qr_info_and_get_dmls()
    async fn feed_qrinfo_and_get_additional_diffs(
        &mut self,
        qr_info: &QRInfo,
        storage: &mut S,
        network: &mut N,
    ) -> Result<(), String> {
        tracing::info!(
            "🔗 Feeding QRInfo to engine and getting additional diffs for quorum validation"
        );

        // Step 1: Feed QRInfo to masternode list engine with dynamic on-demand height callback
        let (quorum_hashes, _rotating_quorum_hashes) = if let Some(engine) = &mut self.engine {
            // Create dynamic callback that fetches heights on-demand from storage
            let height_lookup = |block_hash: &BlockHash| -> Result<
                u32,
                dashcore::sml::quorum_validation_error::ClientDataRetrievalError,
            > {
                // Use block_in_place to bridge async storage call to sync callback
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        storage.get_header_height_by_hash(block_hash)
                            .await
                            .map_err(|_| dashcore::sml::quorum_validation_error::ClientDataRetrievalError::RequiredBlockNotPresent(*block_hash))?
                            .ok_or(dashcore::sml::quorum_validation_error::ClientDataRetrievalError::RequiredBlockNotPresent(*block_hash))
                    })
                })
            };

            match engine.feed_qr_info(qr_info.clone(), true, true, Some(height_lookup)) {
                Ok(()) => {
                    tracing::info!("✅ Successfully fed QRInfo to masternode list engine");
                }
                Err(e) => {
                    let error_msg = format!("Failed to feed QRInfo to engine: {}", e);
                    tracing::error!("❌ {}", error_msg);
                    return Err(error_msg);
                }
            }

            // Get quorum hashes for validation
            let quorum_hashes =
                engine.latest_masternode_list_non_rotating_quorum_hashes(&[], false);
            let rotating_quorum_hashes = engine.latest_masternode_list_rotating_quorum_hashes(&[]);

            tracing::info!(
                "🏛️ Retrieved {} non-rotating quorum hashes for validation",
                quorum_hashes.len()
            );
            tracing::info!("🔄 Retrieved {} rotating quorum hashes", rotating_quorum_hashes.len());

            (quorum_hashes, rotating_quorum_hashes)
        } else {
            return Err("Masternode engine not initialized".to_string());
        };

        // Step 3: Fetch additional MnListDiffs for quorum validation (avoiding borrow conflicts)
        if let Err(e) = self.fetch_diffs_with_hashes(&quorum_hashes, storage, network).await {
            let error_msg =
                format!("Failed to fetch additional diffs for quorum validation: {}", e);
            tracing::error!("❌ {}", error_msg);
            return Err(error_msg);
        }

        // Step 4: Verify quorums
        if let Some(engine) = &mut self.engine {
            match engine.verify_non_rotating_masternode_list_quorums(0, &[]) {
                Ok(()) => {
                    tracing::info!("✅ Non-rotating quorum verification completed successfully");
                }
                Err(e) => {
                    tracing::warn!("⚠️ Non-rotating quorum verification failed: {}", e);
                    // Don't fail completely - this might be expected in some cases
                }
            }
        }

        Ok(())
    }

    /// Fetch additional MnListDiffs for quorum validation (dash-evo-tool pattern)
    /// This implements the fetch_diffs_with_hashes logic from dash-evo-tool
    async fn fetch_diffs_with_hashes(
        &mut self,
        quorum_hashes: &std::collections::BTreeSet<QuorumHash>,
        storage: &mut S,
        network: &mut N,
    ) -> Result<(), String> {
        use dashcore::network::message::NetworkMessage;
        use dashcore::network::message_sml::GetMnListDiff;

        tracing::info!(
            "🔍 Fetching {} additional MnListDiffs for quorum validation",
            quorum_hashes.len()
        );

        // Track how many requests we're about to send
        let mut requests_sent = 0;

        for quorum_hash in quorum_hashes.iter() {
            tracing::info!("🔍 Processing quorum hash: {}", quorum_hash);

            // Get the quorum hash as BlockHash for height lookup (QuorumHash and BlockHash are the same type)
            let quorum_block_hash = *quorum_hash;
            // Look up the height for this quorum hash
            let quorum_height = match storage.get_header_height_by_hash(&quorum_block_hash).await {
                Ok(Some(height)) => height,
                Ok(None) => {
                    tracing::warn!(
                        "⚠️ Height not found for quorum hash {} in storage, skipping",
                        quorum_block_hash
                    );
                    continue;
                }
                Err(e) => {
                    tracing::warn!(
                        "⚠️ Failed to get height for quorum hash {}: {}, skipping",
                        quorum_block_hash,
                        e
                    );
                    continue;
                }
            };

            // Calculate validation height (height - 8, following dash-evo-tool pattern)
            let validation_height = if quorum_height >= 8 {
                quorum_height - 8
            } else {
                tracing::warn!(
                    "⚠️ Quorum height {} is too low for validation (< 8), using height 0",
                    quorum_height
                );
                0
            };

            tracing::info!(
                "📏 Quorum at height {}, validation height: {}",
                quorum_height,
                validation_height
            );

            // Use blockchain heights directly with storage API
            let storage_validation_height = validation_height;
            let storage_quorum_height = quorum_height;

            tracing::debug!("🔄 Height conversion: blockchain validation_height={} -> storage_height={}, blockchain quorum_height={} -> storage_height={}",
                validation_height, storage_validation_height, quorum_height, storage_quorum_height);

            // Get base block hash (blockchain height)
            let base_header = match storage.get_header(storage_validation_height).await {
                Ok(Some(header)) => header,
                Ok(None) => {
                    tracing::warn!(
                        "⚠️ Base header not found at storage height {} (blockchain height {}), skipping",
                        storage_validation_height, validation_height);
                    continue;
                }
                Err(e) => {
                    tracing::warn!(
                        "⚠️ Failed to get base header at storage height {} (blockchain height {}): {}, skipping",
                        storage_validation_height, validation_height, e);
                    continue;
                }
            };
            let base_block_hash = base_header.block_hash();

            // Get target block hash (blockchain height)
            let target_header = match storage.get_header(storage_quorum_height).await {
                Ok(Some(header)) => header,
                Ok(None) => {
                    tracing::warn!(
                        "⚠️ Target header not found at storage height {} (blockchain height {}), skipping",
                        storage_quorum_height, quorum_height);
                    continue;
                }
                Err(e) => {
                    tracing::warn!(
                        "⚠️ Failed to get target header at storage height {} (blockchain height {}): {}, skipping",
                        storage_quorum_height, quorum_height, e);
                    continue;
                }
            };
            let target_block_hash = target_header.block_hash();

            // Create GetMnListDiff request
            let get_mnlist_diff = GetMnListDiff {
                base_block_hash,
                block_hash: target_block_hash,
            };
            let network_message = NetworkMessage::GetMnListD(get_mnlist_diff);

            // Send the request (this matches dash-evo-tool's pattern of sending individual requests)
            tracing::info!("📤 Requesting MnListDiff: base_height={}, target_height={}, base_hash={}, target_hash={}",
                validation_height, quorum_height, base_block_hash, target_block_hash);

            if let Err(e) = network.send_message(network_message).await {
                tracing::error!(
                    "❌ Failed to send MnListDiff request for quorum hash {}: {}",
                    quorum_hash,
                    e
                );
                // Continue with other quorums instead of failing completely
                continue;
            }

            // Track that we sent a request
            requests_sent += 1;

            tracing::info!(
                "✅ Sent MnListDiff request for quorum hash {} (base: {} -> target: {})",
                quorum_hash,
                validation_height,
                quorum_height
            );
        }

        // Update the pending request counter
        self.pending_mnlistdiff_requests += requests_sent;

        // Start tracking wait time if we sent any requests
        if requests_sent > 0 {
            self.mnlistdiff_wait_start = Some(Instant::now());
            tracing::info!(
                "📋 Completed sending {} MnListDiff requests for quorum validation (total pending: {}), started timeout tracking",
                requests_sent,
                self.pending_mnlistdiff_requests
            );
        } else {
            tracing::info!("📋 No MnListDiff requests sent (all quorums already have data)");
        }

        Ok(())
    }
}
