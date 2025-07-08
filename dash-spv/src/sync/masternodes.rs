//! Masternode synchronization functionality.

use dashcore::{
    network::constants::NetworkExt,
    network::message::NetworkMessage,
    network::message_sml::{GetMnListDiff, MnListDiff},
    sml::{
        masternode_list_engine::MasternodeListEngine,
        masternode_list::MasternodeList,
        masternode_list_entry::{
            EntryMasternodeType, MasternodeListEntry,
            qualified_masternode_list_entry::QualifiedMasternodeListEntry,
        },
    },
    bls_sig_utils::BLSPublicKey,
    hash_types::MerkleRootMasternodeList,
    address::{Address, Payload},
    BlockHash, ProTxHash, PubkeyHash,
};
use dashcore_hashes::Hash;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str::FromStr;

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::{MasternodeState, StorageManager};
use crate::sync::terminal_blocks::TerminalBlockManager;

/// Callback function type for updating the sync quorum cache when masternode data changes.
/// 
/// Parameters:
/// - quorum_type: Type of quorum (1=InstantSend, 2=ChainLock, etc.)
/// - quorum_hash: 32-byte hash of the quorum
/// - public_key: 48-byte compressed BLS public key
/// - height: Block height of this quorum data
pub type QuorumCacheUpdateCallback = Box<dyn Fn(u8, [u8; 32], [u8; 48], u32) + Send + Sync>;

/// Manages masternode list synchronization.
pub struct MasternodeSyncManager {
    config: ClientConfig,
    sync_in_progress: bool,
    engine: Option<MasternodeListEngine>,
    /// Last time sync progress was made (for timeout detection)
    last_sync_progress: std::time::Instant,
    /// Terminal block manager for optimized sync
    terminal_block_manager: TerminalBlockManager,
    /// Callback for updating the sync quorum cache when new quorum data is processed
    quorum_cache_callback: Option<QuorumCacheUpdateCallback>,
}

impl MasternodeSyncManager {
    /// Create a new masternode sync manager.
    pub fn new(config: &ClientConfig) -> Self {
        let engine = if config.enable_masternodes {
            let mut engine = MasternodeListEngine::default_for_network(config.network);
            // Feed genesis block hash at height 0
            if let Some(genesis_hash) = config.network.known_genesis_block_hash() {
                engine.feed_block_height(0, genesis_hash);
            }
            Some(engine)
        } else {
            None
        };

        Self {
            config: config.clone(),
            sync_in_progress: false,
            engine,
            last_sync_progress: std::time::Instant::now(),
            terminal_block_manager: TerminalBlockManager::new(config.network),
            quorum_cache_callback: None,
        }
    }

    /// Set the callback for updating the sync quorum cache.
    /// 
    /// This callback will be called whenever new quorum data is processed during masternode sync.
    pub fn set_quorum_cache_callback(&mut self, callback: QuorumCacheUpdateCallback) {
        self.quorum_cache_callback = Some(callback);
    }

    /// Update the sync quorum cache with data from the masternode list engine.
    /// 
    /// This method extracts all quorum public keys from the current masternode list
    /// and calls the cache update callback for each one.
    fn update_sync_cache_from_engine(&self, height: u32) {
        if let Some(ref callback) = self.quorum_cache_callback {
            if let Some(engine) = &self.engine {
                if let Some(masternode_list) = engine.latest_masternode_list() {
                    let mut updated_count = 0;
                    
                    // Extract all quorum public keys from the masternode list
                    for (llmq_type, type_quorums) in &masternode_list.quorums {
                        // Convert LLMQType to u8
                        let quorum_type = match llmq_type {
                            dashcore::sml::llmq_type::LLMQType::Llmqtype50_60 => 1,
                            dashcore::sml::llmq_type::LLMQType::Llmqtype400_60 => 2,
                            dashcore::sml::llmq_type::LLMQType::Llmqtype400_85 => 3,
                            dashcore::sml::llmq_type::LLMQType::Llmqtype100_67 => 4,
                            dashcore::sml::llmq_type::LLMQType::Llmqtype60_75 => 5,
                            _ => continue, // Skip unknown types
                        };
                        
                        for (quorum_hash, qualified_quorum_entry) in type_quorums {
                            // Extract the BLS public key (already in compressed format)
                            let public_key_bytes: [u8; 48] = *qualified_quorum_entry.quorum_entry.quorum_public_key.as_ref();
                            
                            // Convert quorum hash to bytes
                            let quorum_hash_bytes = quorum_hash.to_byte_array();
                            
                            // Call the callback to update the cache
                            callback(quorum_type, quorum_hash_bytes, public_key_bytes, height);
                            updated_count += 1;
                        }
                    }
                    
                    if updated_count > 0 {
                        tracing::debug!("Updated sync cache with {} quorum keys at height {}", updated_count, height);
                    }
                } else {
                    tracing::debug!("No masternode list available for cache update");
                }
            } else {
                tracing::debug!("No masternode engine available for cache update");
            }
        }
    }

    /// Validate a terminal block against the chain and return its height if valid.
    /// Returns 0 if the block is not valid or not yet synced.
    async fn validate_terminal_block(
        &self,
        storage: &dyn StorageManager,
        terminal_height: u32,
        expected_hash: BlockHash,
        has_precalculated_data: bool,
    ) -> SyncResult<u32> {
        // Check if the terminal block exists in our chain
        match storage.get_header(terminal_height).await {
            Ok(Some(header)) => {
                if header.block_hash() == expected_hash {
                    if has_precalculated_data {
                        tracing::info!(
                            "Using terminal block at height {} with pre-calculated masternode data as base for sync",
                            terminal_height
                        );
                    } else {
                        tracing::info!(
                            "Using terminal block at height {} as base for masternode sync (no pre-calculated data)",
                            terminal_height
                        );
                    }
                    Ok(terminal_height)
                } else {
                    let msg = if has_precalculated_data {
                        "Terminal block hash mismatch at height {} (with pre-calculated data) - falling back to genesis"
                    } else {
                        "Terminal block hash mismatch at height {} (without pre-calculated data) - falling back to genesis"
                    };
                    tracing::warn!(msg, terminal_height);
                    Ok(0)
                }
            },
            Ok(None) => {
                tracing::info!(
                    "Terminal block at height {} not yet synced - starting from genesis",
                    terminal_height
                );
                Ok(0)
            },
            Err(e) => {
                Err(SyncError::SyncFailed(format!("Failed to get terminal block header: {}", e)))
            }
        }
    }

    /// Handle an MnListDiff message during masternode synchronization.
    /// Returns true if the message was processed and sync should continue, false if sync is complete.
    pub async fn handle_mnlistdiff_message(
        &mut self,
        diff: MnListDiff,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<bool> {
        if !self.sync_in_progress {
            tracing::warn!(
                "📨 Received MnListDiff but masternode sync is not in progress - ignoring message"
            );
            return Ok(true);
        }

        self.last_sync_progress = std::time::Instant::now();

        // Process the diff with fallback to genesis if incremental diff fails
        match self.process_masternode_diff(diff, storage).await {
            Ok(()) => {
                // Success - diff applied
            }
            Err(e) if e.to_string().contains("MissingStartMasternodeList") => {
                tracing::warn!("Incremental masternode diff failed with MissingStartMasternodeList, retrying from genesis");

                // Reset sync state but keep in progress
                self.last_sync_progress = std::time::Instant::now();

                // Get current height again
                let current_height = storage
                    .get_tip_height()
                    .await
                    .map_err(|e| {
                        SyncError::SyncFailed(format!(
                            "Failed to get current height for fallback: {}",
                            e
                        ))
                    })?
                    .unwrap_or(0);

                // Request full diff from genesis
                tracing::info!(
                    "Requesting fallback masternode diff from genesis to height {}",
                    current_height
                );
                self.request_masternode_diff(network, storage, 0, current_height).await?;

                // Return true to continue waiting for the new response
                return Ok(true);
            }
            Err(e) => {
                // Other error - propagate it
                return Err(e);
            }
        }

        // Masternode sync typically completes after processing one diff
        self.sync_in_progress = false;
        Ok(false)
    }

    /// Check if a sync timeout has occurred and handle recovery.
    pub async fn check_sync_timeout(
        &mut self,
        storage: &mut dyn StorageManager,
        network: &mut dyn NetworkManager,
    ) -> SyncResult<bool> {
        if !self.sync_in_progress {
            return Ok(false);
        }

        if self.last_sync_progress.elapsed() > std::time::Duration::from_secs(10) {
            tracing::warn!("📊 No masternode sync progress for 10+ seconds, re-sending request");

            // Get current header height for recovery request
            let current_height = storage
                .get_tip_height()
                .await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to get current height: {}", e)))?
                .unwrap_or(0);

            let last_masternode_height =
                match storage.load_masternode_state().await.map_err(|e| {
                    SyncError::SyncFailed(format!("Failed to load masternode state: {}", e))
                })? {
                    Some(state) => state.last_height,
                    None => 0,
                };

            self.request_masternode_diff(network, storage, last_masternode_height, current_height)
                .await?;
            self.last_sync_progress = std::time::Instant::now();

            return Ok(true);
        }

        Ok(false)
    }

    /// Start synchronizing masternodes (initialize the sync state).
    /// This replaces the old sync method but doesn't loop for messages.
    pub async fn start_sync(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<bool> {
        if self.sync_in_progress {
            return Err(SyncError::SyncInProgress);
        }

        // Skip if masternodes are disabled
        if !self.config.enable_masternodes || self.engine.is_none() {
            return Ok(false);
        }

        tracing::info!("Starting masternode list synchronization");

        // Get current header height
        let current_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get current height: {}", e)))?
            .unwrap_or(0);

        // Get last known masternode height
        let last_masternode_height =
            match storage.load_masternode_state().await.map_err(|e| {
                SyncError::SyncFailed(format!("Failed to load masternode state: {}", e))
            })? {
                Some(state) => state.last_height,
                None => 0,
            };

        // If we're already up to date, no need to sync
        if last_masternode_height >= current_height {
            tracing::info!(
                "Masternode list already synced to current height (last: {}, current: {})",
                last_masternode_height,
                current_height
            );
            return Ok(false);
        }

        tracing::info!(
            "Starting masternode sync: last_height={}, current_height={}",
            last_masternode_height,
            current_height
        );

        // Set sync state
        self.sync_in_progress = true;
        self.last_sync_progress = std::time::Instant::now();

        // Check if we can use a terminal block as a base for optimization
        let base_height = if last_masternode_height > 0 {
            // We have a previous state, try incremental sync
            tracing::info!(
                "Attempting incremental masternode diff from height {} to {}",
                last_masternode_height,
                current_height
            );
            last_masternode_height
        } else {
            // No previous state - check if we can start from a terminal block with pre-calculated data
            if let Some(terminal_data) = self.terminal_block_manager.find_best_terminal_block_with_data(current_height).cloned() {
                // We have pre-calculated masternode data for this terminal block!
                self.load_precalculated_masternode_data(&terminal_data, storage).await?
            } else if let Some(terminal_block) = self.terminal_block_manager.find_best_base_terminal_block(current_height) {
                // No pre-calculated data, but we have a terminal block reference
                self.validate_terminal_block(
                    storage,
                    terminal_block.height,
                    terminal_block.block_hash,
                    false
                ).await?
            } else {
                tracing::info!(
                    "No suitable terminal block found - requesting full diff from genesis to height {}",
                    current_height
                );
                0
            }
        };

        // Request masternode list diff
        self.request_masternode_diff(network, storage, base_height, current_height).await?;

        Ok(true) // Sync started
    }

    /// Load pre-calculated masternode data from a terminal block into the engine
    async fn load_precalculated_masternode_data(
        &mut self,
        terminal_data: &crate::sync::terminal_block_data::TerminalBlockMasternodeState,
        storage: &dyn StorageManager,
    ) -> SyncResult<u32> {
        if let Ok(terminal_block_hash) = terminal_data.get_block_hash() {
            let validated_height = self.validate_terminal_block(
                storage,
                terminal_data.height,
                terminal_block_hash,
                true
            ).await?;
            
            if validated_height > 0 {
                tracing::info!(
                    "Terminal block has {} masternodes in pre-calculated data",
                    terminal_data.masternode_count
                );
                
                // Load the pre-calculated masternode list into the engine
                if let Some(engine) = &mut self.engine {
                    // Convert stored masternode entries to MasternodeListEntry
                    let mut masternodes = BTreeMap::new();
                    
                    for stored_mn in &terminal_data.masternode_list {
                        // Parse ProTxHash
                        let pro_tx_hash_bytes = match hex::decode(&stored_mn.pro_tx_hash) {
                            Ok(bytes) if bytes.len() == 32 => {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&bytes);
                                arr
                            }
                            _ => {
                                tracing::warn!("Invalid ProTxHash for masternode: {}", stored_mn.pro_tx_hash);
                                continue;
                            }
                        };
                        let pro_tx_hash = ProTxHash::from_byte_array(pro_tx_hash_bytes);
                        
                        // Parse service address
                        let service_address = match SocketAddr::from_str(&stored_mn.service) {
                            Ok(addr) => addr,
                            Err(e) => {
                                tracing::warn!("Invalid service address for masternode {}: {}", stored_mn.pro_tx_hash, e);
                                continue;
                            }
                        };
                        
                        // Parse BLS public key
                        let operator_public_key_bytes = match hex::decode(&stored_mn.pub_key_operator) {
                            Ok(bytes) if bytes.len() == 48 => bytes,
                            _ => {
                                tracing::warn!("Invalid BLS public key for masternode: {}", stored_mn.pro_tx_hash);
                                continue;
                            }
                        };
                        let operator_public_key = match BLSPublicKey::try_from(operator_public_key_bytes.as_slice()) {
                            Ok(key) => key,
                            Err(e) => {
                                tracing::warn!("Failed to parse BLS public key for masternode {}: {:?}", stored_mn.pro_tx_hash, e);
                                continue;
                            }
                        };
                        
                        // Parse voting key hash from the voting address
                        let key_id_voting = match Address::from_str(&stored_mn.voting_address) {
                            Ok(addr) => {
                                match addr.payload() {
                                    Payload::PubkeyHash(hash) => *hash,
                                    _ => {
                                        tracing::warn!("Voting address is not a P2PKH address for masternode {}: {}", stored_mn.pro_tx_hash, stored_mn.voting_address);
                                        continue;
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Failed to parse voting address for masternode {}: {:?}", stored_mn.pro_tx_hash, e);
                                continue;
                            }
                        };
                        
                        // Determine masternode type
                        let mn_type = match stored_mn.n_type {
                            0 => EntryMasternodeType::Regular,
                            1 => EntryMasternodeType::HighPerformance {
                                platform_http_port: 0, // Not available in stored data
                                platform_node_id: PubkeyHash::all_zeros(), // Not available in stored data
                            },
                            _ => {
                                tracing::warn!("Unknown masternode type {} for masternode: {}", stored_mn.n_type, stored_mn.pro_tx_hash);
                                continue;
                            }
                        };
                        
                        // Create MasternodeListEntry
                        let entry = MasternodeListEntry {
                            version: 2, // Latest version
                            pro_reg_tx_hash: pro_tx_hash,
                            confirmed_hash: None, // Not available in stored data
                            service_address,
                            operator_public_key,
                            key_id_voting,
                            is_valid: stored_mn.is_valid,
                            mn_type,
                        };
                        
                        // Convert to qualified entry
                        let qualified_entry = QualifiedMasternodeListEntry::from(entry);
                        masternodes.insert(pro_tx_hash, qualified_entry);
                    }
                    
                    // Parse merkle root
                    let merkle_root_bytes = match hex::decode(&terminal_data.merkle_root_mn_list) {
                        Ok(bytes) if bytes.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            arr
                        }
                        _ => {
                            tracing::warn!("Invalid merkle root in terminal data");
                            [0u8; 32]
                        }
                    };
                    let merkle_root = MerkleRootMasternodeList::from_byte_array(merkle_root_bytes);
                    
                    // Build masternode list
                    let masternode_list = MasternodeList::build(
                        masternodes,
                        BTreeMap::new(), // No quorum data in terminal blocks
                        terminal_block_hash,
                        terminal_data.height,
                    )
                    .with_merkle_roots(merkle_root, None)
                    .build();
                    
                    // Insert into engine
                    engine.masternode_lists.insert(terminal_data.height, masternode_list);
                    engine.feed_block_height(terminal_data.height, terminal_block_hash);
                    
                    tracing::info!(
                        "Successfully loaded {} masternodes from terminal block at height {}",
                        terminal_data.masternode_list.len(),
                        terminal_data.height
                    );
                }
            }
            Ok(validated_height)
        } else {
            tracing::warn!(
                "Failed to get terminal block hash at height {} - falling back to genesis",
                terminal_data.height
            );
            Ok(0)
        }
    }

    /// Request masternode list diff.
    async fn request_masternode_diff(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &dyn StorageManager,
        base_height: u32,
        current_height: u32,
    ) -> SyncResult<()> {
        // Get base block hash
        let base_block_hash = if base_height == 0 {
            self.config
                .network
                .known_genesis_block_hash()
                .ok_or_else(|| SyncError::Network("No genesis hash for network".to_string()))?
        } else {
            storage
                .get_header(base_height)
                .await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to get base header: {}", e)))?
                .ok_or_else(|| SyncError::SyncFailed("Base header not found".to_string()))?
                .block_hash()
        };

        // Get current block hash
        let current_block_hash = storage
            .get_header(current_height)
            .await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get current header: {}", e)))?
            .ok_or_else(|| SyncError::SyncFailed("Current header not found".to_string()))?
            .block_hash();

        let get_mn_list_diff = GetMnListDiff {
            base_block_hash,
            block_hash: current_block_hash,
        };

        network
            .send_message(NetworkMessage::GetMnListD(get_mn_list_diff))
            .await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to send GetMnListDiff: {}", e)))?;

        tracing::debug!(
            "Requested masternode list diff from {} to {}",
            base_height,
            current_height
        );

        Ok(())
    }

    /// Process received masternode list diff.
    async fn process_masternode_diff(
        &mut self,
        diff: MnListDiff,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<()> {
        let engine = self.engine.as_mut().ok_or_else(|| {
            SyncError::SyncFailed("Masternode engine not initialized".to_string())
        })?;

        let _target_block_hash = diff.block_hash;

        // Get tip height first as it's needed later
        let tip_height = storage
            .get_tip_height()
            .await
            .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip height: {}", e)))?
            .unwrap_or(0);

        // Only feed the block headers that are actually needed by the masternode engine
        let target_block_hash = diff.block_hash;
        let base_block_hash = diff.base_block_hash;

        // Special case: Zero hash indicates empty masternode list (common in regtest)
        let zero_hash = BlockHash::all_zeros();
        let is_zero_hash = target_block_hash == zero_hash;

        if is_zero_hash {
            tracing::debug!("Target block hash is zero - likely empty masternode list in regtest");
        } else {
            // Feed target block hash
            if let Some(target_height) =
                storage.get_header_height_by_hash(&target_block_hash).await.map_err(|e| {
                    SyncError::SyncFailed(format!("Failed to lookup target hash: {}", e))
                })?
            {
                engine.feed_block_height(target_height, target_block_hash);
                tracing::debug!(
                    "Fed target block hash {} at height {}",
                    target_block_hash,
                    target_height
                );
            } else {
                return Err(SyncError::SyncFailed(format!(
                    "Target block hash {} not found in storage",
                    target_block_hash
                )));
            }

            // Feed base block hash
            if let Some(base_height) = storage
                .get_header_height_by_hash(&base_block_hash)
                .await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to lookup base hash: {}", e)))?
            {
                engine.feed_block_height(base_height, base_block_hash);
                tracing::debug!(
                    "Fed base block hash {} at height {}",
                    base_block_hash,
                    base_height
                );
            }

            // Calculate start_height for filtering redundant submissions
            // Feed last 1000 headers or from base height, whichever is more recent
            let start_height = if let Some(base_height) = storage
                .get_header_height_by_hash(&base_block_hash)
                .await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to lookup base hash: {}", e)))?
            {
                base_height.saturating_sub(100) // Include some headers before base
            } else {
                tip_height.saturating_sub(1000)
            };

            // Feed any quorum hashes from new_quorums that are block hashes
            for quorum in &diff.new_quorums {
                // Note: quorum_hash is not necessarily a block hash, so we check if it exists
                if let Some(quorum_height) =
                    storage.get_header_height_by_hash(&quorum.quorum_hash).await.map_err(|e| {
                        SyncError::SyncFailed(format!("Failed to lookup quorum hash: {}", e))
                    })?
                {
                    // Only feed blocks at or after start_height to avoid redundant submissions
                    if quorum_height >= start_height {
                        engine.feed_block_height(quorum_height, quorum.quorum_hash);
                        tracing::debug!(
                            "Fed quorum hash {} at height {}",
                            quorum.quorum_hash,
                            quorum_height
                        );
                    } else {
                        tracing::trace!(
                            "Skipping quorum hash {} at height {} (before start_height {})",
                            quorum.quorum_hash,
                            quorum_height,
                            start_height
                        );
                    }
                }
            }

            // Feed a reasonable range of recent headers for validation purposes
            // The engine may need recent headers for various validations

            if start_height < tip_height {
                tracing::debug!(
                    "Feeding headers from {} to {} to masternode engine",
                    start_height,
                    tip_height
                );
                let headers =
                    storage.get_headers_batch(start_height, tip_height).await.map_err(|e| {
                        SyncError::SyncFailed(format!("Failed to batch load headers: {}", e))
                    })?;

                for (height, header) in headers {
                    engine.feed_block_height(height, header.block_hash());
                }
            }
        }

        // Special handling for regtest: skip empty diffs
        if self.config.network == dashcore::Network::Regtest {
            // In regtest, masternode diffs might be empty, which is normal
            if is_zero_hash || (diff.merkle_hashes.is_empty() && diff.new_masternodes.is_empty()) {
                tracing::info!(
                    "Skipping empty masternode diff in regtest - no masternodes configured"
                );

                // Store empty masternode state to mark sync as complete
                let masternode_state = MasternodeState {
                    last_height: tip_height,
                    engine_state: Vec::new(), // Empty state for regtest
                    last_update: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    terminal_block_hash: None,
                };

                storage.store_masternode_state(&masternode_state).await.map_err(|e| {
                    SyncError::SyncFailed(format!("Failed to store masternode state: {}", e))
                })?;

                tracing::info!("Masternode synchronization completed (empty in regtest)");
                return Ok(());
            }
        }

        // Apply the diff to our engine
        engine.apply_diff(diff, None, true, None)
            .map_err(|e| {
                // Provide more context for IncompleteMnListDiff in regtest
                if self.config.network == dashcore::Network::Regtest && e.to_string().contains("IncompleteMnListDiff") {
                    SyncError::SyncFailed(format!(
                        "Failed to apply masternode diff in regtest (this is normal if no masternodes are configured): {:?}", e
                    ))
                } else {
                    SyncError::SyncFailed(format!("Failed to apply masternode diff: {:?}", e))
                }
            })?;

        tracing::info!("Successfully applied masternode list diff");

        // Find the height of the target block
        let target_height = if let Some(height) = storage.get_header_height_by_hash(&target_block_hash).await.map_err(|e| {
            SyncError::SyncFailed(format!("Failed to lookup target block height: {}", e))
        })? {
            height
        } else {
            // Fallback to tip height if we can't find the specific block
            storage
                .get_tip_height()
                .await
                .map_err(|e| SyncError::SyncFailed(format!("Failed to get tip height: {}", e)))?
                .unwrap_or(0)
        };

        // Update the sync quorum cache with the new masternode data
        self.update_sync_cache_from_engine(target_height);

        // Validate terminal block if this is one
        if self.terminal_block_manager.is_terminal_block_height(target_height) {
            let is_valid = self.terminal_block_manager
                .validate_terminal_block(target_height, &target_block_hash, storage)
                .await?;
            
            if !is_valid {
                return Err(SyncError::SyncFailed(format!(
                    "Terminal block validation failed at height {}",
                    target_height
                )));
            }
            
            tracing::info!("✅ Terminal block validated at height {}", target_height);
        }

        // Store the updated masternode state
        let terminal_block_hash = if self.terminal_block_manager.is_terminal_block_height(target_height) {
            Some(target_block_hash.to_byte_array())
        } else {
            None
        };
        
        let masternode_state = MasternodeState {
            last_height: target_height,
            engine_state: Vec::new(), // TODO: Serialize engine state
            last_update: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            terminal_block_hash,
        };

        storage.store_masternode_state(&masternode_state).await.map_err(|e| {
            SyncError::SyncFailed(format!("Failed to store masternode state: {}", e))
        })?;

        tracing::info!("Updated masternode list sync height to {}", target_height);

        Ok(())
    }

    /// Reset sync state.
    pub fn reset(&mut self) {
        self.sync_in_progress = false;
        if let Some(_engine) = &mut self.engine {
            // TODO: Reset engine state if needed
        }
    }

    /// Get a reference to the masternode engine for validation.
    pub fn engine(&self) -> Option<&MasternodeListEngine> {
        self.engine.as_ref()
    }

    /// Get a quorum public key from the masternode engine's historical data.
    /// 
    /// # Arguments
    /// * `quorum_type` - Type of quorum (1=InstantSend, 2=ChainLock, etc.)
    /// * `quorum_hash` - Hash of the quorum as 32 bytes
    /// 
    /// # Returns
    /// The 48-byte compressed BLS public key if found, None otherwise
    /// 
    /// This method searches through the engine's historical masternode lists
    /// to find the requested quorum, checking from newest to oldest.
    pub fn get_historical_quorum_public_key(&self, quorum_type: u8, quorum_hash: [u8; 32]) -> Option<[u8; 48]> {
        let engine = self.engine.as_ref()?;
        
        // Convert quorum_type to LLMQType
        let llmq_type = match quorum_type {
            1 => dashcore::sml::llmq_type::LLMQType::Llmqtype50_60,
            2 => dashcore::sml::llmq_type::LLMQType::Llmqtype400_60,
            3 => dashcore::sml::llmq_type::LLMQType::Llmqtype400_85,
            4 => dashcore::sml::llmq_type::LLMQType::Llmqtype100_67,
            5 => dashcore::sml::llmq_type::LLMQType::Llmqtype60_75,
            _ => return None,
        };
        
        // Convert quorum_hash to QuorumHash
        let quorum_hash_obj = dashcore::QuorumHash::from_byte_array(quorum_hash);
        
        // Search through masternode lists (from newest to oldest)
        let mut heights: Vec<_> = engine.masternode_lists.keys().collect();
        heights.sort_by(|a, b| b.cmp(a)); // Sort descending (newest first)
        
        for &height in heights {
            if let Some(masternode_list) = engine.masternode_lists.get(&height) {
                // Check if this height has quorums of the requested type
                if let Some(type_quorums) = masternode_list.quorums.get(&llmq_type) {
                    // Look for the specific quorum hash
                    if let Some(qualified_quorum_entry) = type_quorums.get(&quorum_hash_obj) {
                        // Extract the BLS public key (already in compressed format)
                        let public_key_bytes: [u8; 48] = *qualified_quorum_entry.quorum_entry.quorum_public_key.as_ref();
                        return Some(public_key_bytes);
                    }
                }
            }
        }
        
        None
    }

    /// Get a quorum public key from a specific block height in the engine.
    /// 
    /// # Arguments
    /// * `quorum_type` - Type of quorum (1=InstantSend, 2=ChainLock, etc.)
    /// * `quorum_hash` - Hash of the quorum as 32 bytes
    /// * `height` - Specific block height to search
    /// 
    /// # Returns
    /// The 48-byte compressed BLS public key if found at that height, None otherwise
    pub fn get_quorum_public_key_at_height(&self, quorum_type: u8, quorum_hash: [u8; 32], height: u32) -> Option<[u8; 48]> {
        let engine = self.engine.as_ref()?;
        
        // Convert quorum_type to LLMQType
        let llmq_type = match quorum_type {
            1 => dashcore::sml::llmq_type::LLMQType::Llmqtype50_60,
            2 => dashcore::sml::llmq_type::LLMQType::Llmqtype400_60,
            3 => dashcore::sml::llmq_type::LLMQType::Llmqtype400_85,
            4 => dashcore::sml::llmq_type::LLMQType::Llmqtype100_67,
            5 => dashcore::sml::llmq_type::LLMQType::Llmqtype60_75,
            _ => return None,
        };
        
        // Convert quorum_hash to QuorumHash
        let quorum_hash_obj = dashcore::QuorumHash::from_byte_array(quorum_hash);
        
        // Get masternode list for specific height
        let masternode_list = engine.masternode_lists.get(&height)?;
        
        // Check if this height has quorums of the requested type
        let type_quorums = masternode_list.quorums.get(&llmq_type)?;
        
        // Look for the specific quorum hash
        let qualified_quorum_entry = type_quorums.get(&quorum_hash_obj)?;
        
        // Extract the BLS public key (already in compressed format)
        let public_key_bytes: [u8; 48] = *qualified_quorum_entry.quorum_entry.quorum_public_key.as_ref();
        Some(public_key_bytes)
    }

    /// Get all available heights in the masternode engine.
    /// 
    /// # Returns
    /// Vector of heights in descending order (newest first)
    pub fn get_available_heights(&self) -> Vec<u32> {
        if let Some(engine) = &self.engine {
            let mut heights: Vec<u32> = engine.masternode_lists.keys().copied().collect();
            heights.sort_by(|a, b| b.cmp(a)); // Sort descending
            heights
        } else {
            Vec::new()
        }
    }

    /// Get the number of quorums available at a specific height.
    /// 
    /// # Arguments
    /// * `height` - Block height to query
    /// 
    /// # Returns
    /// Total number of quorums at that height, 0 if height not found
    pub fn get_quorum_count_at_height(&self, height: u32) -> usize {
        self.engine.as_ref()
            .and_then(|engine| engine.masternode_lists.get(&height))
            .map(|list| list.quorums.values().map(|type_quorums| type_quorums.len()).sum())
            .unwrap_or(0)
    }

    /// Get a reference to the terminal block manager.
    pub fn terminal_block_manager(&self) -> &TerminalBlockManager {
        &self.terminal_block_manager
    }

    /// Get the next terminal block after the current masternode sync height.
    pub async fn get_next_terminal_block(
        &self,
        storage: &dyn StorageManager,
    ) -> SyncResult<Option<&crate::sync::terminal_blocks::TerminalBlock>> {
        let current_height = match storage.load_masternode_state().await.map_err(|e| {
            SyncError::SyncFailed(format!("Failed to load masternode state: {}", e))
        })? {
            Some(state) => state.last_height,
            None => 0,
        };

        Ok(self.terminal_block_manager.get_next_terminal_block(current_height))
    }
}
