//! Post-sync message handlers (messages that arrive after initial sync is complete).

use dashcore::block::Header as BlockHeader;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::Inventory;
use dashcore::BlockHash;

use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use key_wallet_manager::wallet_interface::WalletInterface;

use super::manager::{SyncManager, CHAINLOCK_VALIDATION_MASTERNODE_OFFSET};
use super::phases::SyncPhase;

impl<S: StorageManager, N: NetworkManager, W: WalletInterface> SyncManager<S, N, W> {
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
        headers: &[BlockHeader],
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
            .store_headers(headers)
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

        for header in headers {
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
                // Use the latest persisted masternode state height as base to guarantee base < stop
                let base_height = match storage.load_masternode_state().await {
                    Ok(Some(state)) => state.last_height,
                    _ => 0,
                };

                if base_height < height {
                    let base_block_hash = if base_height > 0 {
                        storage
                            .get_header(base_height)
                            .await
                            .map_err(|e| {
                                SyncError::Storage(format!(
                                    "Failed to get masternode base block at {}: {}",
                                    base_height, e
                                ))
                            })?
                            .map(|h| h.block_hash())
                            .ok_or(SyncError::InvalidState(
                                "Masternode base block not found".to_string(),
                            ))?
                    } else {
                        // Genesis block case
                        dashcore::blockdata::constants::genesis_block(self.config.network)
                            .block_hash()
                    };

                    tracing::info!(
                        "📋 Requesting masternode list diff for block at height {} (base: {} -> target: {})",
                        blockchain_height,
                        base_height,
                        height
                    );

                    let getmnlistdiff =
                        NetworkMessage::GetMnListD(dashcore::network::message_sml::GetMnListDiff {
                            base_block_hash,
                            block_hash: header.block_hash(),
                        });

                    network.send_message(getmnlistdiff).await.map_err(|e| {
                        SyncError::Network(format!("Failed to request masternode diff: {}", e))
                    })?;
                } else {
                    tracing::debug!(
                        "Skipping masternode diff request: base_height {} >= target height {}",
                        base_height,
                        height
                    );
                }

                // The masternode diff will arrive via handle_message and be processed by masternode_sync
            }

            // If we have filters enabled, request filter headers for the new blocks
            if self.config.enable_filters {
                // Determine stop as the previous block to avoid peer race on newly announced tip
                let stop_hash = if height > 0 {
                    storage
                        .get_header(height - 1)
                        .await
                        .map_err(|e| {
                            SyncError::Storage(format!(
                                "Failed to get previous block for CFHeaders stop: {}",
                                e
                            ))
                        })?
                        .map(|h| h.block_hash())
                        .ok_or(SyncError::InvalidState(
                            "Previous block not found for CFHeaders stop".to_string(),
                        ))?
                } else {
                    dashcore::blockdata::constants::genesis_block(self.config.network).block_hash()
                };

                // Resolve the absolute blockchain height for stop_hash
                let stop_height = storage
                    .get_header_height_by_hash(&stop_hash)
                    .await
                    .map_err(|e| {
                        SyncError::Storage(format!(
                            "Failed to get stop height for CFHeaders: {}",
                            e
                        ))
                    })?
                    .ok_or(SyncError::InvalidState("Stop block height not found".to_string()))?;

                // Current filter headers tip (absolute blockchain height)
                let filter_tip = storage
                    .get_filter_tip_height()
                    .await
                    .map_err(|e| {
                        SyncError::Storage(format!("Failed to get filter tip height: {}", e))
                    })?
                    .unwrap_or(0);

                // Check if we're already up-to-date before computing start_height
                if filter_tip >= stop_height {
                    tracing::debug!(
                        "Skipping CFHeaders request: already up-to-date (filter_tip: {}, stop_height: {})",
                        filter_tip,
                        stop_height
                    );
                } else {
                    // Request from the first missing height after our current filter tip
                    // We already verified filter_tip < stop_height above
                    let start_height = filter_tip.saturating_add(1);

                    tracing::info!(
                        "📋 Requesting filter headers up to height {} (start: {}, stop: {})",
                        stop_height,
                        start_height,
                        stop_hash
                    );

                    let get_cfheaders = NetworkMessage::GetCFHeaders(
                        dashcore::network::message_filter::GetCFHeaders {
                            filter_type: 0, // Basic filter
                            start_height,
                            stop_hash,
                        },
                    );

                    network.send_message(get_cfheaders).await.map_err(|e| {
                        SyncError::Network(format!("Failed to request filter headers: {}", e))
                    })?;

                    // The filter headers will arrive via handle_message, then we'll request filters
                }
            }
        }

        Ok(())
    }

    /// Handle filter headers that arrive after initial sync
    pub(super) async fn handle_post_sync_cfheaders(
        &mut self,
        cfheaders: &dashcore::network::message_filter::CFHeaders,
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
    pub(super) async fn handle_post_sync_cfilter(
        &mut self,
        cfilter: &dashcore::network::message_filter::CFilter,
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

        // Verify against expected header chain before storing
        let header_ok = self
            .filter_sync
            .verify_cfilter_against_headers(&cfilter.filter, height, &*storage)
            .await?;
        if !header_ok {
            tracing::warn!(
                "Rejecting post-sync CFilter for block {} at height {} due to header mismatch",
                cfilter.block_hash,
                height
            );
            return Ok(());
        }

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
    pub(super) async fn handle_post_sync_mnlistdiff(
        &mut self,
        diff: &dashcore::network::message_sml::MnListDiff,
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
}
