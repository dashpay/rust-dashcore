//! Network message handling for the Dash SPV client.

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{Result, SpvError};
use crate::sync::SyncManager;
use crate::storage::StorageManager;
use crate::network::NetworkManager;
use crate::sync::filters::FilterNotificationSender;
use crate::types::SpvStats;
use crate::client::ClientConfig;

/// Network message handler for processing incoming Dash protocol messages.
pub struct MessageHandler<'a> {
    sync_manager: &'a mut SyncManager,
    storage: &'a mut dyn StorageManager,
    network: &'a mut dyn NetworkManager,
    config: &'a ClientConfig,
    stats: &'a Arc<RwLock<SpvStats>>,
    filter_processor: &'a Option<FilterNotificationSender>,
    block_processor_tx: &'a tokio::sync::mpsc::UnboundedSender<crate::client::BlockProcessingTask>,
}

impl<'a> MessageHandler<'a> {
    /// Create a new message handler.
    pub fn new(
        sync_manager: &'a mut SyncManager,
        storage: &'a mut dyn StorageManager,
        network: &'a mut dyn NetworkManager,
        config: &'a ClientConfig,
        stats: &'a Arc<RwLock<SpvStats>>,
        filter_processor: &'a Option<FilterNotificationSender>,
        block_processor_tx: &'a tokio::sync::mpsc::UnboundedSender<crate::client::BlockProcessingTask>,
    ) -> Self {
        Self {
            sync_manager,
            storage,
            network,
            config,
            stats,
            filter_processor,
            block_processor_tx,
        }
    }

    /// Handle incoming network messages during monitoring.
    pub async fn handle_network_message(&mut self, message: dashcore::network::message::NetworkMessage) -> Result<()> {
        use dashcore::network::message::NetworkMessage;
        
        tracing::debug!("Client handling network message: {:?}", std::mem::discriminant(&message));
        
        match message {
            NetworkMessage::Headers(headers) => {
                // Route to header sync manager if active, otherwise process normally
                match self.sync_manager.handle_headers_message(headers.clone(), &mut *self.storage, &mut *self.network).await {
                    Ok(false) => {
                        tracing::info!("🎯 Header sync completed (handle_headers_message returned false)");
                        // Header sync manager has already cleared its internal syncing_headers flag
                        
                        // Auto-trigger masternode sync after header sync completion
                        if self.config.enable_masternodes {
                            tracing::info!("🚀 Header sync complete, starting masternode sync...");
                            match self.sync_manager.sync_masternodes(&mut *self.network, &mut *self.storage).await {
                                Ok(_) => {
                                    tracing::info!("✅ Masternode sync initiated after header sync completion");
                                }
                                Err(e) => {
                                    tracing::error!("❌ Failed to start masternode sync after headers: {}", e);
                                    // Don't fail the entire flow if masternode sync fails to start
                                }
                            }
                        }
                    }
                    Ok(true) => {
                        // Headers processed successfully
                        if self.sync_manager.header_sync().is_syncing() {
                            tracing::debug!("🔄 Header sync continuing (handle_headers_message returned true)");
                        } else {
                            // Post-sync headers received - request filter headers and filters for new blocks
                            tracing::info!("📋 Post-sync headers received, requesting filter headers and filters");
                            self.handle_post_sync_headers(&headers).await?;
                        }
                    }
                    Err(e) => {
                        tracing::error!("❌ Error handling headers: {:?}", e);
                        return Err(e.into());
                    }
                }
            }
            NetworkMessage::CFHeaders(cf_headers) => {
                tracing::info!("📨 Client received CFHeaders message with {} filter headers", cf_headers.filter_hashes.len());
                // Route to filter sync manager if active
                match self.sync_manager.handle_cfheaders_message(cf_headers, &mut *self.storage, &mut *self.network).await {
                    Ok(false) => {
                        tracing::info!("🎯 Filter header sync completed (handle_cfheaders_message returned false)");
                        // Properly finish the sync state
                        self.sync_manager.sync_state_mut().finish_sync(crate::sync::SyncComponent::FilterHeaders);
                        
                        // Note: Auto-trigger logic for filter downloading would need access to watch_items and client methods
                        // This might need to be handled at the client level or passed as a callback
                    }
                    Ok(true) => {
                        tracing::debug!("🔄 Filter header sync continuing (handle_cfheaders_message returned true)");
                    }
                    Err(e) => {
                        tracing::error!("❌ Error handling CFHeaders: {:?}", e);
                        // Don't fail the entire sync if filter header processing fails
                    }
                }
            }
            NetworkMessage::MnListDiff(diff) => {
                tracing::info!("📨 Received MnListDiff message: {} new masternodes, {} deleted masternodes, {} quorums", 
                              diff.new_masternodes.len(), diff.deleted_masternodes.len(), diff.new_quorums.len());
                // Route to masternode sync manager if active
                match self.sync_manager.handle_mnlistdiff_message(diff, &mut *self.storage, &mut *self.network).await {
                    Ok(false) => {
                        tracing::info!("🎯 Masternode sync completed");
                    }
                    Ok(true) => {
                        tracing::debug!("MnListDiff processed, sync continuing");
                    }
                    Err(e) => {
                        tracing::error!("❌ Failed to process MnListDiff: {}", e);
                    }
                }
                // MnListDiff is only relevant during sync, so we don't process them normally
            }
            NetworkMessage::Block(block) => {
                let block_hash = block.header.block_hash();
                tracing::info!("Received new block: {}", block_hash);
                tracing::debug!("📋 Block {} contains {} transactions", block_hash, block.txdata.len());
                
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
                tracing::debug!("Received transaction: {}", tx.txid());
                // Check if transaction affects watched addresses/scripts
                // This would need access to transaction processing logic
                tracing::debug!("Transaction processing not yet implemented in message handler");
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
                    &cfilter.block_hash
                ).await;
                
                // Enhanced sync coordination with flow control
                if let Err(e) = self.sync_manager.handle_cfilter_message(
                    cfilter.block_hash, 
                    &mut *self.storage, 
                    &mut *self.network
                ).await {
                    tracing::error!("Failed to handle CFilter in sync manager: {}", e);
                }
                
                // Always send to filter processor for watch item checking if available
                if let Some(filter_processor) = self.filter_processor {
                    tracing::debug!("Sending compact filter for block {} to processing thread", cfilter.block_hash);
                    if let Err(e) = filter_processor.send(cfilter) {
                        tracing::error!("Failed to send filter to processing thread: {}", e);
                    }
                } else {
                    // This should not happen since we always create filter processor when filters are enabled
                    tracing::warn!("Received CFilter for block {} but no filter processor available - filters may not be enabled", cfilter.block_hash);
                }
            }
            _ => {
                // Ignore other message types for now
                tracing::debug!("Received network message: {:?}", std::mem::discriminant(&message));
            }
        }
        
        Ok(())
    }

    /// Handle inventory messages - auto-request ChainLocks and other important data.
    pub async fn handle_inventory(&mut self, inv: Vec<dashcore::network::message_blockdata::Inventory>) -> Result<()> {
        use dashcore::network::message_blockdata::Inventory;
        use dashcore::network::message::NetworkMessage;
        
        let mut chainlocks_to_request = Vec::new();
        let mut blocks_to_request = Vec::new();
        let mut islocks_to_request = Vec::new();
        
        for item in inv {
            match item {
                Inventory::Block(block_hash) => {
                    tracing::debug!("Inventory: New block {}", block_hash);
                    blocks_to_request.push(item);
                }
                Inventory::ChainLock(chainlock_hash) => {
                    tracing::info!("Inventory: New ChainLock {}", chainlock_hash);
                    chainlocks_to_request.push(item);
                }
                Inventory::InstantSendLock(islock_hash) => {
                    tracing::info!("Inventory: New InstantSendLock {}", islock_hash);
                    islocks_to_request.push(item);
                }
                Inventory::Transaction(txid) => {
                    tracing::debug!("Inventory: New transaction {}", txid);
                    // Only request transactions we're interested in (watched addresses/scripts)
                    // For now, skip transaction requests
                }
                _ => {
                    tracing::debug!("Inventory: Other item type");
                }
            }
        }
        
        // Auto-request ChainLocks (highest priority for validation)
        if !chainlocks_to_request.is_empty() {
            tracing::info!("Requesting {} ChainLocks", chainlocks_to_request.len());
            let getdata = NetworkMessage::GetData(chainlocks_to_request);
            self.network.send_message(getdata).await
                .map_err(|e| SpvError::Network(e))?;
        }
        
        // Auto-request InstantLocks 
        if !islocks_to_request.is_empty() {
            tracing::info!("Requesting {} InstantLocks", islocks_to_request.len());
            let getdata = NetworkMessage::GetData(islocks_to_request);
            self.network.send_message(getdata).await
                .map_err(|e| SpvError::Network(e))?;
        }
        
        // Process new blocks immediately when detected
        if !blocks_to_request.is_empty() {
            tracing::info!("Processing {} new blocks", blocks_to_request.len());
            
            // Extract block hashes
            let block_hashes: Vec<dashcore::BlockHash> = blocks_to_request.iter()
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
                if let Err(e) = self.process_new_block_hash(block_hash).await {
                    tracing::error!("Failed to process new block {}: {}", block_hash, e);
                }
            }
        }
        
        Ok(())
    }

    /// Process new headers received from the network.
    pub async fn process_new_headers(&mut self, headers: Vec<dashcore::block::Header>) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }
        
        // Get the height before storing new headers
        let initial_height = self.storage.get_tip_height().await
            .map_err(|e| SpvError::Storage(e))?
            .unwrap_or(0);
        
        // Store the headers using the sync manager
        // This will validate and store them properly
        self.sync_manager.sync_all(&mut *self.network, &mut *self.storage).await
            .map_err(|e| SpvError::Sync(e))?;
        
        // Check if filters are enabled and request filter headers for new blocks
        if self.config.enable_filters {
            // Get the new tip height after storing headers
            let new_height = self.storage.get_tip_height().await
                .map_err(|e| SpvError::Storage(e))?
                .unwrap_or(0);
            
            // If we stored new headers, request filter headers for them
            if new_height > initial_height {
                tracing::info!("New headers stored from height {} to {}, requesting filter headers", 
                              initial_height + 1, new_height);
                
                // Request filter headers for each new header
                for height in (initial_height + 1)..=new_height {
                    if let Some(header) = self.storage.get_header(height).await
                        .map_err(|e| SpvError::Storage(e))? {
                        
                        let block_hash = header.block_hash();
                        tracing::debug!("Requesting filter header for block {} at height {}", block_hash, height);
                        
                        // Request filter header for this block
                        self.sync_manager.filter_sync_mut().download_filter_header_for_block(
                            block_hash, &mut *self.network, &mut *self.storage
                        ).await.map_err(|e| SpvError::Sync(e))?;
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Process a new block hash detected from inventory.
    pub async fn process_new_block_hash(&mut self, block_hash: dashcore::BlockHash) -> Result<()> {
        tracing::info!("🔗 Processing new block hash: {}", block_hash);
        
        // Just request the header - filter operations will be triggered when we receive it
        self.sync_manager.header_sync_mut().download_single_header(
            block_hash, &mut *self.network, &mut *self.storage
        ).await.map_err(|e| SpvError::Sync(e))?;
        
        Ok(())
    }
    
    /// Process received filter headers.
    pub async fn process_filter_headers(&mut self, cfheaders: dashcore::network::message_filter::CFHeaders) -> Result<()> {
        tracing::debug!("Processing filter headers for block {}", cfheaders.stop_hash);
        
        tracing::info!("✅ Received filter headers for block {} (type: {}, count: {})", 
                      cfheaders.stop_hash, cfheaders.filter_type, cfheaders.filter_hashes.len());
        
        // Store filter headers in storage via FilterSyncManager
        self.sync_manager.filter_sync_mut().store_filter_headers(cfheaders, &mut *self.storage).await
            .map_err(|e| SpvError::Sync(e))?;
        
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
    /// Request filter headers for these new blocks. Filters will be requested
    /// automatically when the CFHeaders responses arrive.
    pub async fn handle_post_sync_headers(&mut self, headers: &[dashcore::block::Header]) -> Result<()> {
        if !self.config.enable_filters {
            tracing::debug!("Filters not enabled, skipping post-sync filter requests for {} headers", headers.len());
            return Ok(());
        }
        
        tracing::info!("Handling {} post-sync headers - requesting filter headers (filters will follow automatically)", headers.len());
        
        for header in headers {
            let block_hash = header.block_hash();
            
            // Only request filter header for this new block
            // The CFilter will be requested automatically when the CFHeader response arrives
            // (this happens in the CFHeaders message handler)
            if let Err(e) = self.sync_manager.filter_sync_mut().download_filter_header_for_block(
                block_hash, &mut *self.network, &mut *self.storage
            ).await {
                tracing::error!("Failed to request filter header for new block {}: {}", block_hash, e);
                continue;
            }
            
            tracing::debug!("Requested filter header for new block {} (filter will be requested when CFHeader arrives)", block_hash);
        }
        
        tracing::info!("✅ Completed post-sync filter header requests for {} new blocks", headers.len());
        Ok(())
    }
}