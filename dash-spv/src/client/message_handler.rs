//! Network message handling for the Dash SPV client.

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::client::ClientConfig;
use crate::error::{Result, SpvError};
use crate::mempool_filter::MempoolFilter;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::filters::FilterNotificationSender;
use crate::sync::sequential::SequentialSyncManager;
use crate::types::{MempoolState, SpvEvent, SpvStats};
use crate::wallet::Wallet;

/// Network message handler for processing incoming Dash protocol messages.
pub struct MessageHandler<'a> {
    sync_manager: &'a mut SequentialSyncManager,
    storage: &'a mut dyn StorageManager,
    network: &'a mut dyn NetworkManager,
    config: &'a ClientConfig,
    stats: &'a Arc<RwLock<SpvStats>>,
    filter_processor: &'a Option<FilterNotificationSender>,
    block_processor_tx: &'a tokio::sync::mpsc::UnboundedSender<crate::client::BlockProcessingTask>,
    wallet: &'a Arc<RwLock<Wallet>>,
    mempool_filter: &'a Option<Arc<MempoolFilter>>,
    mempool_state: &'a Arc<RwLock<MempoolState>>,
    event_tx: &'a tokio::sync::mpsc::UnboundedSender<SpvEvent>,
}

impl<'a> MessageHandler<'a> {
    /// Create a new message handler.
    pub fn new(
        sync_manager: &'a mut SequentialSyncManager,
        storage: &'a mut dyn StorageManager,
        network: &'a mut dyn NetworkManager,
        config: &'a ClientConfig,
        stats: &'a Arc<RwLock<SpvStats>>,
        filter_processor: &'a Option<FilterNotificationSender>,
        block_processor_tx: &'a tokio::sync::mpsc::UnboundedSender<
            crate::client::BlockProcessingTask,
        >,
        wallet: &'a Arc<RwLock<Wallet>>,
        mempool_filter: &'a Option<Arc<MempoolFilter>>,
        mempool_state: &'a Arc<RwLock<MempoolState>>,
        event_tx: &'a tokio::sync::mpsc::UnboundedSender<SpvEvent>,
    ) -> Self {
        Self {
            sync_manager,
            storage,
            network,
            config,
            stats,
            filter_processor,
            block_processor_tx,
            wallet,
            mempool_filter,
            mempool_state,
            event_tx,
        }
    }

    /// Handle incoming network messages during monitoring.
    pub async fn handle_network_message(
        &mut self,
        message: dashcore::network::message::NetworkMessage,
    ) -> Result<()> {
        use dashcore::network::message::NetworkMessage;

        tracing::debug!("Client handling network message: {:?}", std::mem::discriminant(&message));

        // First check if this is a message that ONLY the sync manager handles
        // These messages can be moved to the sync manager without cloning
        match message {
            NetworkMessage::Headers2(ref headers2) => {
                tracing::info!("📋 Received Headers2 message with {} compressed headers", headers2.headers.len());
                // Move to sync manager without cloning
                return self.sync_manager.handle_message(message, &mut *self.network, &mut *self.storage)
                    .await
                    .map_err(|e| {
                        tracing::error!("Sequential sync manager error handling message: {}", e);
                        SpvError::Sync(e)
                    });
            }
            NetworkMessage::MnListDiff(ref diff) => {
                tracing::info!("📨 Received MnListDiff message: {} new masternodes, {} deleted masternodes, {} quorums", 
                              diff.new_masternodes.len(), diff.deleted_masternodes.len(), diff.new_quorums.len());
                // Move to sync manager without cloning
                return self.sync_manager.handle_message(message, &mut *self.network, &mut *self.storage)
                    .await
                    .map_err(|e| {
                        tracing::error!("Sequential sync manager error handling message: {}", e);
                        SpvError::Sync(e)
                    });
            }
            NetworkMessage::CFHeaders(ref cf_headers) => {
                tracing::info!(
                    "📨 Client received CFHeaders message with {} filter headers",
                    cf_headers.filter_hashes.len()
                );
                // Move to sync manager without cloning
                return self.sync_manager.handle_message(message, &mut *self.network, &mut *self.storage)
                    .await
                    .map_err(|e| {
                        tracing::error!("Sequential sync manager error handling message: {}", e);
                        SpvError::Sync(e)
                    });
            }
            _ => {}
        }

        // For messages that need both sync manager and client processing,
        // we need to clone to share ownership
        let needs_sync_handling = matches!(
            &message,
            NetworkMessage::Headers(_) |
            NetworkMessage::CFilter(_) |
            NetworkMessage::Block(_)
        );

        if needs_sync_handling {
            if let Err(e) = self.sync_manager.handle_message(message.clone(), &mut *self.network, &mut *self.storage).await {
                tracing::error!("Sequential sync manager error handling message: {}", e);
                // Don't return error immediately - some messages might need additional processing
            }
        }

        // Then handle client-specific message processing
        match message {
            NetworkMessage::Headers(headers) => {
                // For post-sync headers, we need special handling
                if self.sync_manager.is_synced() && !headers.is_empty() {
                    tracing::info!("📋 Post-sync headers received, additional processing may be needed");
                }
            }
            NetworkMessage::Block(block) => {
                let block_hash = block.header.block_hash();
                tracing::info!("Received new block: {}", block_hash);
                tracing::debug!(
                    "📋 Block {} contains {} transactions",
                    block_hash,
                    block.txdata.len()
                );

                // Process new block (update state, check watched items)
                if let Err(e) = self.process_new_block(block).await {
                    tracing::error!("❌ Failed to process new block {}: {}", block_hash, e);
                    return Err(e);
                }
            }
            NetworkMessage::Inv(inv) => {
                tracing::debug!("Received inventory message with {} items", inv.len());
                // Handle inventory messages (new blocks, transactions, etc.)
                self.handle_inventory(inv).await?;
            }
            NetworkMessage::Tx(tx) => {
                tracing::info!("📨 Received transaction: {}", tx.txid());
                
                // Only process if mempool tracking is enabled
                if let Some(filter) = self.mempool_filter {
                    // Check if we should process this transaction
                    let wallet = self.wallet.read().await;
                    if let Some(unconfirmed_tx) = filter.process_transaction(tx.clone(), &wallet).await {
                        let txid = unconfirmed_tx.txid();
                        let amount = unconfirmed_tx.net_amount;
                        let is_instant_send = unconfirmed_tx.is_instant_send;
                        let addresses: Vec<String> = unconfirmed_tx.addresses.iter()
                            .map(|a| a.to_string())
                            .collect();
                        
                        // Store in mempool
                        let mut state = self.mempool_state.write().await;
                        state.add_transaction(unconfirmed_tx.clone());
                        drop(state);
                        
                        // Store in storage if persistence is enabled
                        if self.config.persist_mempool {
                            if let Err(e) = self.storage.store_mempool_transaction(&txid, &unconfirmed_tx).await {
                                tracing::error!("Failed to persist mempool transaction: {}", e);
                            }
                        }
                        
                        // Emit event
                        let event = SpvEvent::MempoolTransactionAdded {
                            txid,
                            transaction: tx,
                            amount,
                            addresses,
                            is_instant_send,
                        };
                        let _ = self.event_tx.send(event);
                        
                        tracing::info!("💸 Added mempool transaction {} (amount: {})", txid, amount);
                    } else {
                        tracing::debug!("Transaction {} not relevant or at capacity, ignoring", tx.txid());
                    }
                } else {
                    tracing::warn!("⚠️ Received transaction {} but mempool tracking is disabled (enable_mempool_tracking=false)", tx.txid());
                }
            }
            NetworkMessage::CLSig(chain_lock) => {
                tracing::info!("Received ChainLock for block {}", chain_lock.block_hash);
                // ChainLock processing would need access to state and validation
                // This might need to be handled at the client level
                tracing::debug!("ChainLock processing not yet implemented in message handler");
            }
            NetworkMessage::ISLock(instant_lock) => {
                tracing::info!("Received InstantSendLock for tx {}", instant_lock.txid);
                // InstantLock processing would need access to validation
                // This might need to be handled at the client level
                tracing::debug!("InstantLock processing not yet implemented in message handler");
            }
            NetworkMessage::Ping(nonce) => {
                tracing::debug!("Received ping with nonce {}", nonce);
                // Automatically respond with pong
                if let Err(e) = self.network.handle_ping(nonce).await {
                    tracing::error!("Failed to send pong response: {}", e);
                }
            }
            NetworkMessage::Pong(nonce) => {
                tracing::debug!("Received pong with nonce {}", nonce);
                // Validate the pong nonce
                if let Err(e) = self.network.handle_pong(nonce) {
                    tracing::warn!("Invalid pong received: {}", e);
                }
            }
            NetworkMessage::CFilter(cfilter) => {
                tracing::debug!("Received CFilter for block {}", cfilter.block_hash);

                // Record the height of this received filter for gap tracking
                crate::sync::filters::FilterSyncManager::record_filter_received_at_height(
                    self.stats,
                    &*self.storage,
                    &cfilter.block_hash,
                )
                .await;

                // Sequential sync manager handles the filter internally
                // For sequential sync, filter checking is done within the sync manager
            }
            _ => {
                // Ignore other message types for now
                tracing::debug!("Received network message: {:?}", std::mem::discriminant(&message));
            }
        }

        Ok(())
    }

    /// Handle inventory messages - auto-request ChainLocks and other important data.
    pub async fn handle_inventory(
        &mut self,
        inv: Vec<dashcore::network::message_blockdata::Inventory>,
    ) -> Result<()> {
        use dashcore::network::message::NetworkMessage;
        use dashcore::network::message_blockdata::Inventory;

        let mut chainlocks_to_request = Vec::new();
        let mut blocks_to_request = Vec::new();
        let mut islocks_to_request = Vec::new();

        for item in inv {
            match item {
                Inventory::Block(block_hash) => {
                    tracing::info!("🆕 Inventory: New block announcement {}", block_hash);
                    blocks_to_request.push(item);
                }
                Inventory::ChainLock(chainlock_hash) => {
                    tracing::info!("🔒 Inventory: New ChainLock {}", chainlock_hash);
                    chainlocks_to_request.push(item);
                }
                Inventory::InstantSendLock(islock_hash) => {
                    tracing::info!("⚡ Inventory: New InstantSendLock {}", islock_hash);
                    islocks_to_request.push(item);
                }
                Inventory::Transaction(txid) => {
                    tracing::debug!("💸 Inventory: New transaction {}", txid);
                    
                    // Check if we should fetch this transaction
                    if let Some(filter) = self.mempool_filter {
                        if self.config.fetch_mempool_transactions && 
                           filter.should_fetch_transaction(&txid).await {
                            tracing::info!("📥 Requesting transaction {}", txid);
                            // Request the transaction
                            let getdata = NetworkMessage::GetData(vec![item]);
                            if let Err(e) = self.network.send_message(getdata).await {
                                tracing::error!("Failed to request transaction {}: {}", txid, e);
                            }
                        } else {
                            tracing::debug!("Not fetching transaction {} (fetch_mempool_transactions={}, should_fetch={})", 
                                txid, 
                                self.config.fetch_mempool_transactions,
                                filter.should_fetch_transaction(&txid).await
                            );
                        }
                    } else {
                        tracing::warn!("⚠️ Transaction {} announced but mempool tracking is disabled (enable_mempool_tracking=false)", txid);
                    }
                }
                _ => {
                    tracing::debug!("❓ Inventory: Other item type");
                }
            }
        }

        // Auto-request ChainLocks (highest priority for validation)
        if !chainlocks_to_request.is_empty() {
            tracing::info!("Requesting {} ChainLocks", chainlocks_to_request.len());
            let getdata = NetworkMessage::GetData(chainlocks_to_request);
            self.network.send_message(getdata).await.map_err(SpvError::Network)?;
        }

        // Auto-request InstantLocks
        if !islocks_to_request.is_empty() {
            tracing::info!("Requesting {} InstantLocks", islocks_to_request.len());
            let getdata = NetworkMessage::GetData(islocks_to_request);
            self.network.send_message(getdata).await.map_err(SpvError::Network)?;
        }

        // Process new blocks immediately when detected
        if !blocks_to_request.is_empty() {
            tracing::info!("🔄 Processing {} new block announcements to stay synchronized", blocks_to_request.len());

            // Extract block hashes
            let block_hashes: Vec<dashcore::BlockHash> = blocks_to_request
                .iter()
                .filter_map(|inv| {
                    if let Inventory::Block(hash) = inv {
                        Some(*hash)
                    } else {
                        None
                    }
                })
                .collect();

            // Process each new block
            for block_hash in block_hashes {
                tracing::info!("📥 Requesting header for new block {}", block_hash);
                if let Err(e) = self.process_new_block_hash(block_hash).await {
                    tracing::error!("❌ Failed to process new block {}: {}", block_hash, e);
                }
            }
        }

        Ok(())
    }

    /// Process new headers received from the network.
    pub async fn process_new_headers(
        &mut self,
        headers: Vec<dashcore::block::Header>,
    ) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }

        // For sequential sync, new headers are handled by the sync manager's message handler
        // We just need to send them through the unified message interface
        let headers_msg = dashcore::network::message::NetworkMessage::Headers(headers);
        self.sync_manager.handle_message(headers_msg, &mut *self.network, &mut *self.storage)
            .await
            .map_err(SpvError::Sync)?;

        Ok(())
    }

    /// Process a new block hash detected from inventory.
    pub async fn process_new_block_hash(&mut self, block_hash: dashcore::BlockHash) -> Result<()> {
        tracing::info!("🔗 Processing new block hash: {}", block_hash);

        // For sequential sync, handle through inventory message
        let inv = vec![dashcore::network::message_blockdata::Inventory::Block(block_hash)];
        self.sync_manager.handle_inventory(inv, &mut *self.network, &mut *self.storage)
            .await
            .map_err(SpvError::Sync)?;

        Ok(())
    }

    /// Process received filter headers.
    pub async fn process_filter_headers(
        &mut self,
        cfheaders: dashcore::network::message_filter::CFHeaders,
    ) -> Result<()> {
        tracing::debug!("Processing filter headers for block {}", cfheaders.stop_hash);

        tracing::info!(
            "✅ Received filter headers for block {} (type: {}, count: {})",
            cfheaders.stop_hash,
            cfheaders.filter_type,
            cfheaders.filter_hashes.len()
        );

        // For sequential sync, route through the message handler
        let cfheaders_msg = dashcore::network::message::NetworkMessage::CFHeaders(cfheaders);
        self.sync_manager.handle_message(cfheaders_msg, &mut *self.network, &mut *self.storage)
            .await
            .map_err(SpvError::Sync)?;

        Ok(())
    }

    /// Helper method to find height for a block hash.
    pub async fn find_height_for_block_hash(&self, block_hash: dashcore::BlockHash) -> Option<u32> {
        // Use the efficient reverse index
        self.storage.get_header_height_by_hash(&block_hash).await.ok().flatten()
    }

    /// Process a new block.
    pub async fn process_new_block(&mut self, block: dashcore::Block) -> Result<()> {
        let block_hash = block.block_hash();

        tracing::info!("📦 Routing block {} to async block processor", block_hash);

        // Send block to the background processor without waiting for completion
        let (response_tx, _response_rx) = tokio::sync::oneshot::channel();
        let task = crate::client::BlockProcessingTask::ProcessBlock {
            block,
            response_tx,
        };

        if let Err(e) = self.block_processor_tx.send(task) {
            tracing::error!("Failed to send block to processor: {}", e);
            return Err(SpvError::Config("Block processor channel closed".to_string()));
        }

        // Return immediately - processing happens asynchronously in the background
        tracing::debug!("Block {} queued for background processing", block_hash);
        Ok(())
    }

    /// Handle new headers received after the initial sync is complete.
    /// The sequential sync manager will handle requesting filter headers internally.
    pub async fn handle_post_sync_headers(
        &mut self,
        headers: &[dashcore::block::Header],
    ) -> Result<()> {
        if !self.config.enable_filters {
            tracing::debug!(
                "Filters not enabled, skipping post-sync filter requests for {} headers",
                headers.len()
            );
            return Ok(());
        }

        tracing::info!("Handling {} post-sync headers - sequential sync will manage filter requests", headers.len());

        // The sequential sync manager's handle_new_headers method will automatically
        // request filter headers and filters as needed
        self.sync_manager.handle_new_headers(headers.to_vec(), &mut *self.network, &mut *self.storage)
            .await
            .map_err(SpvError::Sync)?;

        Ok(())
    }
}
