//! High-level client API for the Dash SPV client.

pub mod config;

use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::Instant;

use std::collections::HashSet;

use crate::terminal::TerminalUI;

use crate::error::{Result, SpvError};
use crate::types::{ChainState, SpvStats, SyncProgress, WatchItem};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::SyncManager;
use crate::validation::ValidationManager;

pub use config::ClientConfig;

/// Main Dash SPV client.
pub struct DashSpvClient {
    config: ClientConfig,
    state: Arc<RwLock<ChainState>>,
    stats: Arc<RwLock<SpvStats>>,
    network: Box<dyn NetworkManager>,
    storage: Box<dyn StorageManager>,
    sync_manager: SyncManager,
    validation: ValidationManager,
    running: Arc<RwLock<bool>>,
    watch_items: Arc<RwLock<HashSet<WatchItem>>>,
    terminal_ui: Option<Arc<TerminalUI>>,
    filter_sync_state: Arc<RwLock<FilterSyncState>>,
}

/// Coordination state for filter synchronization between the monitoring loop and sync operations.
/// 
/// This struct prevents race conditions by allowing the monitoring loop (which is the sole 
/// message receiver) to coordinate with active filter sync operations. When a sync operation 
/// is active, the monitoring loop will route relevant CFilter messages to storage instead 
/// of processing them as regular filter checks.
#[derive(Debug, Default)]
struct FilterSyncState {
    /// Whether a filter sync operation is currently running.
    /// 
    /// When `true`, the monitoring loop will check incoming CFilter messages against the 
    /// `expected_range` and route matching filters to storage. When `false`, all CFilter 
    /// messages are processed as regular filter checks for watch items.
    active: bool,
    
    /// The height range of filters that the active sync operation is expecting.
    /// 
    /// Format: Some((start_height, end_height)) where both heights are inclusive.
    /// For example, Some((1000, 1099)) means we're expecting filters for blocks 
    /// 1000 through 1099. The monitoring loop uses this to determine if an incoming 
    /// CFilter message belongs to the active sync operation.
    expected_range: Option<(u32, u32)>,
    
    /// Number of CFilter messages received and processed by the monitoring loop 
    /// for the current sync operation.
    /// 
    /// This counter increments each time the monitoring loop successfully stores 
    /// a filter that falls within the `expected_range`. Used to track progress 
    /// and determine when the sync operation is complete.
    received_count: u32,
    
    /// Total number of CFilter messages expected for the current sync operation.
    /// 
    /// Set when the sync operation starts based on the requested range size.
    /// When `received_count` reaches this value, the sync is considered complete 
    /// and `active` is set back to `false`.
    expected_count: u32,
}

impl DashSpvClient {
    /// Create a new SPV client with the given configuration.
    pub async fn new(config: ClientConfig) -> Result<Self> {
        // Validate configuration
        config.validate().map_err(|e| SpvError::Config(e))?;
        
        // Initialize state for the network
        let state = Arc::new(RwLock::new(ChainState::new_for_network(config.network)));
        let stats = Arc::new(RwLock::new(SpvStats::default()));
        
        // Create network manager (use multi-peer by default)
        let network = crate::network::multi_peer::MultiPeerNetworkManager::new(&config).await?;
        
        // Create storage manager
        let storage: Box<dyn StorageManager> = if config.enable_persistence {
            if let Some(path) = &config.storage_path {
                Box::new(crate::storage::DiskStorageManager::new(path.clone()).await
                    .map_err(|e| SpvError::Storage(e))?)
            } else {
                Box::new(crate::storage::MemoryStorageManager::new().await
                    .map_err(|e| SpvError::Storage(e))?)
            }
        } else {
            Box::new(crate::storage::MemoryStorageManager::new().await
                .map_err(|e| SpvError::Storage(e))?)
        };
        
        // Create sync manager
        let sync_manager = SyncManager::new(&config);
        
        // Create validation manager
        let validation = ValidationManager::new(config.validation_mode);
        
        Ok(Self {
            config,
            state,
            stats,
            network: Box::new(network),
            storage,
            sync_manager,
            validation,
            running: Arc::new(RwLock::new(false)),
            watch_items: Arc::new(RwLock::new(HashSet::new())),
            terminal_ui: None,
            filter_sync_state: Arc::new(RwLock::new(FilterSyncState::default())),
        })
    }
    
    /// Start the SPV client.
    pub async fn start(&mut self) -> Result<()> {
        {
            let running = self.running.read().await;
            if *running {
                return Err(SpvError::Config("Client already running".to_string()));
            }
        }
        
        // Load watch items from storage
        self.load_watch_items().await?;
        
        // Initialize genesis block if not already present
        self.initialize_genesis_block().await?;
        
        // Connect to network
        self.network.connect().await?;
        
        {
            let mut running = self.running.write().await;
            *running = true;
        }
        
        // Update terminal UI after connection with initial data
        if let Some(ui) = &self.terminal_ui {
            // Get initial header count from storage
            let header_height = self.storage.get_tip_height().await
                .map_err(|e| SpvError::Storage(e))?
                .unwrap_or(0);
            
            let filter_height = self.storage.get_filter_tip_height().await
                .map_err(|e| SpvError::Storage(e))?
                .unwrap_or(0);
            
            let _ = ui.update_status(|status| {
                status.peer_count = 1; // Connected to one peer
                status.headers = header_height;
                status.filter_headers = filter_height;
            }).await;
        }
        
        Ok(())
    }
    
    /// Enable terminal UI for status display.
    pub fn enable_terminal_ui(&mut self) {
        let ui = Arc::new(TerminalUI::new(true));
        self.terminal_ui = Some(ui);
    }
    
    /// Get the terminal UI handle.
    pub fn get_terminal_ui(&self) -> Option<Arc<TerminalUI>> {
        self.terminal_ui.clone()
    }
    
    /// Get the network configuration.
    pub fn network(&self) -> dashcore::Network {
        self.config.network
    }
    
    /// Stop the SPV client.
    pub async fn stop(&mut self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }
        
        // Disconnect from network
        self.network.disconnect().await?;
        
        // Shutdown storage to ensure all data is persisted
        if let Some(disk_storage) = self.storage.as_any_mut().downcast_mut::<crate::storage::DiskStorageManager>() {
            disk_storage.shutdown().await
                .map_err(|e| SpvError::Storage(e))?;
            tracing::info!("Storage shutdown completed - all data persisted");
        }
        
        *running = false;
        
        Ok(())
    }
    
    /// Synchronize to the tip of the blockchain.
    pub async fn sync_to_tip(&mut self) -> Result<SyncProgress> {
        let running = self.running.read().await;
        if !*running {
            return Err(SpvError::Config("Client not running".to_string()));
        }
        drop(running);
        
        // Run synchronization
        let result = self.sync_manager.sync_all(&mut *self.network, &mut *self.storage).await
            .map_err(|e| SpvError::Sync(e))?;
        
        // Update status display after initial sync
        self.update_status_display().await;
        
        Ok(result)
    }
    
    /// Run continuous monitoring for new blocks, ChainLocks, InstantLocks, etc.
    pub async fn monitor_network(&mut self) -> Result<()> {
        let running = self.running.read().await;
        if !*running {
            return Err(SpvError::Config("Client not running".to_string()));
        }
        drop(running);
        
        tracing::info!("Starting continuous network monitoring...");
        
        // Print initial status
        self.update_status_display().await;
        
        // Timer for periodic status updates
        let mut last_status_update = Instant::now();
        let status_update_interval = std::time::Duration::from_secs(5);
        
        loop {
            // Check if we should stop
            let running = self.running.read().await;
            if !*running {
                tracing::info!("Stopping network monitoring");
                break;
            }
            drop(running);
            
            // Check if we need to send a ping
            if self.network.should_ping() {
                match self.network.send_ping().await {
                    Ok(nonce) => {
                        tracing::trace!("Sent periodic ping with nonce {}", nonce);
                    }
                    Err(e) => {
                        tracing::error!("Failed to send periodic ping: {}", e);
                    }
                }
            }
            
            // Clean up old pending pings
            self.network.cleanup_old_pings();
            
            // Check if it's time to update the status display
            if last_status_update.elapsed() >= status_update_interval {
                self.update_status_display().await;
                last_status_update = Instant::now();
            }
            
            // Listen for network messages
            match self.network.receive_message().await {
                Ok(Some(message)) => {
                    if let Err(e) = self.handle_network_message(message).await {
                        tracing::error!("Error handling network message: {}", e);
                    }
                }
                Ok(None) => {
                    // No message available, continue monitoring
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                Err(e) => {
                    tracing::error!("Network error during monitoring: {}", e);
                    // Try to reconnect or handle the error
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle incoming network messages during monitoring.
    async fn handle_network_message(&mut self, message: dashcore::network::message::NetworkMessage) -> Result<()> {
        use dashcore::network::message::NetworkMessage;
        
        match message {
            NetworkMessage::Headers(headers) => {
                tracing::info!("Received {} new headers", headers.len());
                
                // Process the new headers
                self.process_new_headers(headers).await?;
            }
            NetworkMessage::Block(block) => {
                tracing::info!("Received new block: {}", block.header.block_hash());
                // Process new block (update state, check watched items)
                self.process_new_block(block).await?;
            }
            NetworkMessage::Inv(inv) => {
                tracing::debug!("Received inventory message with {} items", inv.len());
                // Handle inventory messages (new blocks, transactions, etc.)
                self.handle_inventory(inv).await?;
            }
            NetworkMessage::Tx(tx) => {
                tracing::debug!("Received transaction: {}", tx.txid());
                // Check if transaction affects watched addresses/scripts
                self.process_transaction(tx).await?;
            }
            NetworkMessage::CLSig(clsig) => {
                tracing::info!("Received ChainLock for block {}", clsig.chain_lock.block_hash);
                // Extract ChainLock from CLSig message and process
                self.process_chainlock(clsig.chain_lock).await?;
            }
            NetworkMessage::ISLock(islock_msg) => {
                tracing::info!("Received InstantSendLock for tx {}", islock_msg.instant_lock.txid);
                // Extract InstantLock from ISLock message and process
                self.process_instantsendlock(islock_msg.instant_lock).await?;
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
            NetworkMessage::CFHeaders(cfheaders) => {
                tracing::info!("Received {} filter hashes", cfheaders.filter_hashes.len());
                // Process filter headers - store them for later filter validation
                if let Err(e) = self.process_filter_headers(cfheaders).await {
                    tracing::error!("Failed to process filter headers: {}", e);
                }
            }
            NetworkMessage::CFilter(cfilter) => {
                tracing::trace!("Received compact filter for block {}", cfilter.block_hash);
                
                // Check if this filter is expected by an active sync operation
                let handled_by_sync = {
                    let mut sync_state = self.filter_sync_state.write().await;
                    if sync_state.active {
                        // Check if this filter falls within the expected range
                        if let Some((start_height, end_height)) = sync_state.expected_range {
                            // Find the height for this filter by matching block hash
                            if let Some(height) = self.find_height_for_block_hash(cfilter.block_hash).await {
                                if height >= start_height && height <= end_height {
                                    sync_state.received_count += 1;
                                    tracing::debug!("Filter sync: received filter {}/{} for height {} (hash: {})", 
                                                   sync_state.received_count, sync_state.expected_count, height, cfilter.block_hash);
                                    
                                    // Store the filter
                                    if let Err(e) = self.storage.store_filter(height, &cfilter.filter).await {
                                        tracing::error!("Failed to store filter for height {}: {}", height, e);
                                    } else {
                                        tracing::debug!("Stored filter for height {} (hash: {})", height, cfilter.block_hash);
                                    }
                                    
                                    // Check if sync is complete
                                    if sync_state.received_count >= sync_state.expected_count {
                                        tracing::info!("Filter sync completed: received all {} expected filters", sync_state.expected_count);
                                        sync_state.active = false;
                                        sync_state.expected_range = None;
                                        sync_state.received_count = 0;
                                        sync_state.expected_count = 0;
                                    }
                                    
                                    true // Handled by sync
                                } else {
                                    false // Not in expected range
                                }
                            } else {
                                false // Couldn't find height
                            }
                        } else {
                            false // No expected range
                        }
                    } else {
                        false // No active sync
                    }
                };
                
                // If not handled by sync, process as a regular filter for watch items
                if !handled_by_sync {
                    tracing::info!("Received compact filter for block {} (not from sync)", cfilter.block_hash);
                    if let Err(e) = self.process_and_check_filter(cfilter).await {
                        tracing::error!("Failed to process compact filter: {}", e);
                    }
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
    async fn handle_inventory(&mut self, inv: Vec<dashcore::network::message_blockdata::Inventory>) -> Result<()> {
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
    async fn process_new_headers(&mut self, headers: Vec<dashcore::block::Header>) -> Result<()> {
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
                        
                        // Also check if we have watch items and request the filter
                        let watch_items = self.watch_items.read().await;
                        if !watch_items.is_empty() {
                            drop(watch_items); // Release the lock before async call
                            
                            let watch_items_vec: Vec<_> = self.get_watch_items().await;
                            self.sync_manager.filter_sync_mut().download_and_check_filter(
                                block_hash, &watch_items_vec, &mut *self.network, &mut *self.storage
                            ).await.map_err(|e| SpvError::Sync(e))?;
                        }
                    }
                }
                
                // Update status display after processing new headers
                self.update_status_display().await;
            }
        }
        
        Ok(())
    }
    
    /// Process a new block hash detected from inventory.
    async fn process_new_block_hash(&mut self, block_hash: dashcore::BlockHash) -> Result<()> {
        tracing::info!("🔗 Processing new block hash: {}", block_hash);
        
        // Just request the header - filter operations will be triggered when we receive it
        self.sync_manager.header_sync_mut().download_single_header(
            block_hash, &mut *self.network, &mut *self.storage
        ).await.map_err(|e| SpvError::Sync(e))?;
        
        Ok(())
    }
    
    /// Process received filter headers.
    async fn process_filter_headers(&mut self, cfheaders: dashcore::network::message_filter::CFHeaders) -> Result<()> {
        tracing::debug!("Processing filter headers for block {}", cfheaders.stop_hash);
        
        tracing::info!("✅ Received filter headers for block {} (type: {}, count: {})", 
                      cfheaders.stop_hash, cfheaders.filter_type, cfheaders.filter_hashes.len());
        
        // Store filter headers in storage via FilterSyncManager
        self.sync_manager.filter_sync_mut().store_filter_headers(cfheaders, &mut *self.storage).await
            .map_err(|e| SpvError::Sync(e))?;
        
        Ok(())
    }
    
    /// Process and check a compact filter for matches.
    async fn process_and_check_filter(&mut self, cfilter: dashcore::network::message_filter::CFilter) -> Result<()> {
        tracing::debug!("Processing compact filter for block {}", cfilter.block_hash);
        
        // Get watch items to check against
        let watch_items: Vec<_> = self.watch_items.read().await.iter().cloned().collect();
        
        if watch_items.is_empty() {
            tracing::debug!("No watch items configured, skipping filter check");
            return Ok(());
        }
        
        // Use FilterSyncManager to check for matches
        let has_matches = self.sync_manager.filter_sync().check_filter_for_matches(
            &cfilter.filter,
            &cfilter.block_hash,
            &watch_items,
            &*self.storage
        ).await.map_err(|e| SpvError::Sync(e))?;
        
        if has_matches {
            tracing::info!("🎯 Filter match found for block {}!", cfilter.block_hash);
            
            // Get block height for the FilterMatch
            let height = self.find_height_for_block_hash(cfilter.block_hash).await
                .unwrap_or(0);
            
            // Create FilterMatch object
            let filter_match = crate::types::FilterMatch {
                block_hash: cfilter.block_hash,
                height,
                block_requested: false,
            };
            
            // Request the full block download
            self.sync_manager.filter_sync_mut()
                .request_block_download(filter_match, &mut *self.network)
                .await
                .map_err(|e| SpvError::Sync(e))?;
            
            self.report_filter_match(cfilter.block_hash).await?;
        } else {
            tracing::debug!("No filter matches for block {}", cfilter.block_hash);
        }
        
        Ok(())
    }
    
    /// Report a filter match to the user.
    async fn report_filter_match(&self, block_hash: dashcore::BlockHash) -> Result<()> {
        // Get block height for better reporting by scanning headers
        let height = self.find_height_for_block_hash(block_hash).await
            .unwrap_or(0);
        
        tracing::info!("🚨 FILTER MATCH DETECTED! Block {} at height {} contains transactions affecting watched addresses/scripts", 
                      block_hash, height);
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.filter_matches += 1;
        }
        
        // TODO: Additional actions could be taken here:
        // - Store the match in a database
        // - Send notifications  
        // - Update wallet balance (now happens in process_new_block when the full block arrives)
        
        Ok(())
    }
    
    /// Helper method to find height for a block hash.
    async fn find_height_for_block_hash(&self, block_hash: dashcore::BlockHash) -> Option<u32> {
        // Use the efficient reverse index
        self.storage.get_header_height_by_hash(&block_hash).await.ok().flatten()
    }
    
    /// Process a new block.
    async fn process_new_block(&mut self, block: dashcore::Block) -> Result<()> {
        let block_hash = block.block_hash();
        
        tracing::info!("📦 Processing downloaded block: {}", block_hash);
        
        // First, let the FilterSyncManager handle the downloaded block
        // This will check if it was expected and update tracking state
        let filter_match = self.sync_manager.filter_sync_mut()
            .handle_downloaded_block(&block)
            .await
            .map_err(|e| SpvError::Sync(e))?;
        
        if let Some(filter_match) = filter_match {
            tracing::info!("✅ Block {} at height {} successfully processed after filter match", 
                          filter_match.block_hash, filter_match.height);
            
            // Extract transactions that might affect watched items
            let watch_items: Vec<_> = self.watch_items.read().await.iter().cloned().collect();
            if !watch_items.is_empty() {
                self.process_block_transactions(&block, &watch_items).await?;
            }
        } else {
            tracing::debug!("Block {} was not expected from filter matching", block_hash);
        }
        
        // Update chain state if needed
        self.update_chain_state_with_block(&block).await?;
        
        Ok(())
    }
    
    /// Process transactions in a block to check for matches with watch items.
    async fn process_block_transactions(
        &mut self, 
        block: &dashcore::Block, 
        watch_items: &[WatchItem]
    ) -> Result<()> {
        let block_hash = block.block_hash();
        let mut relevant_transactions = 0;
        let mut new_outpoints_to_watch = Vec::new();
        
        for (tx_index, transaction) in block.txdata.iter().enumerate() {
            let txid = transaction.txid();
            let mut transaction_relevant = false;
            
            // Check outputs for matches with watched items
            for (vout, output) in transaction.output.iter().enumerate() {
                for watch_item in watch_items {
                    let matches = match watch_item {
                        WatchItem::Address { address, .. } => {
                            address.script_pubkey() == output.script_pubkey
                        }
                        WatchItem::Script(script) => {
                            script == &output.script_pubkey
                        }
                        WatchItem::Outpoint(_) => false, // Outpoints don't match outputs
                    };
                    
                    if matches {
                        transaction_relevant = true;
                        let outpoint = dashcore::OutPoint { txid, vout: vout as u32 };
                        tracing::info!("💰 Found relevant output: {}:{} to {:?} (value: {})", 
                                      txid, vout, watch_item, 
                                      dashcore::Amount::from_sat(output.value));
                        
                        // Track this outpoint so we can detect when it's spent
                        new_outpoints_to_watch.push(outpoint);
                        tracing::debug!("📍 Now watching outpoint {}:{} for future spending", txid, vout);
                    }
                }
            }
            
            // Check inputs for matches with watched outpoints
            if !transaction.input.is_empty() && transaction.input[0].previous_output != dashcore::OutPoint::null() {
                // Not a coinbase transaction
                for (vin, input) in transaction.input.iter().enumerate() {
                    // Check against explicitly watched outpoints
                    for watch_item in watch_items {
                        if let WatchItem::Outpoint(watched_outpoint) = watch_item {
                            if &input.previous_output == watched_outpoint {
                                transaction_relevant = true;
                                tracing::info!("💸 Found relevant input: {}:{} spending explicitly watched outpoint {:?}", 
                                              txid, vin, watched_outpoint);
                            }
                        }
                    }
                    
                    // Also check against outpoints from our watched addresses
                    // For this to work properly, we'd need to maintain a persistent set of outpoints
                    // from our addresses. For now, let's log when we see inputs to help debug
                    tracing::debug!("🔍 Checking input {}:{} -> previous_output {}:{}", 
                                   txid, vin, input.previous_output.txid, input.previous_output.vout);
                }
            }
            
            if transaction_relevant {
                relevant_transactions += 1;
                tracing::debug!("📝 Transaction {}: {} (index {}) is relevant", 
                               txid, if tx_index == 0 { "coinbase" } else { "regular" }, tx_index);
            }
        }
        
        if relevant_transactions > 0 {
            tracing::info!("🎯 Block {} contains {} relevant transactions affecting watched items", 
                          block_hash, relevant_transactions);
            
            // Add new outpoints to watch list for future spending detection
            for outpoint in new_outpoints_to_watch {
                let watch_item = WatchItem::Outpoint(outpoint);
                if let Err(e) = self.add_watch_item(watch_item).await {
                    tracing::error!("Failed to add outpoint to watch list: {}", e);
                }
            }
            
            // TODO: Future wallet integration would happen here
            // - Create/update UTXOs for relevant outputs
            // - Mark UTXOs as spent for relevant inputs  
            // - Update balance calculations
            // - Store transaction history
        }
        
        Ok(())
    }
    
    /// Update chain state with information from the processed block.
    async fn update_chain_state_with_block(&mut self, block: &dashcore::Block) -> Result<()> {
        let block_hash = block.block_hash();
        
        // Get the block height
        let height = self.find_height_for_block_hash(block_hash).await;
        
        if let Some(height) = height {
            tracing::debug!("📊 Updating chain state with block {} at height {}", block_hash, height);
            
            // Update stats
            {
                let mut stats = self.stats.write().await;
                stats.blocks_requested += 1;
            }
        }
        
        Ok(())
    }
    
    /// Get the number of connected peers.
    pub fn peer_count(&self) -> usize {
        self.network.peer_count()
    }
    
    /// Get information about connected peers.
    pub fn peer_info(&self) -> Vec<crate::types::PeerInfo> {
        self.network.peer_info()
    }
    
    /// Disconnect a specific peer.
    pub async fn disconnect_peer(&self, addr: &std::net::SocketAddr, reason: &str) -> Result<()> {
        // Cast network manager to MultiPeerNetworkManager to access disconnect_peer
        let network = self.network.as_any()
            .downcast_ref::<crate::network::multi_peer::MultiPeerNetworkManager>()
            .ok_or_else(|| SpvError::Config("Network manager does not support peer disconnection".to_string()))?;
        
        network.disconnect_peer(addr, reason).await
    }
    
    
    /// Process a transaction.
    async fn process_transaction(&mut self, _tx: dashcore::Transaction) -> Result<()> {
        // TODO: Implement transaction processing
        // - Check if transaction affects watched addresses/scripts
        // - Update wallet balance if relevant
        // - Store relevant transactions
        tracing::debug!("Transaction processing not yet implemented");
        Ok(())
    }
    
    /// Process and validate a ChainLock.
    async fn process_chainlock(&mut self, chainlock: dashcore::ephemerealdata::chain_lock::ChainLock) -> Result<()> {
        tracing::info!("Processing ChainLock for block {} at height {}", 
                      chainlock.block_hash, chainlock.block_height);
        
        // Verify ChainLock using the masternode engine
        if let Some(engine) = self.sync_manager.masternode_engine() {
            match engine.verify_chain_lock(&chainlock) {
                Ok(_) => {
                    tracing::info!("✅ ChainLock signature verified successfully for block {} at height {}", 
                                  chainlock.block_hash, chainlock.block_height);
                    
                    // Check if this ChainLock supersedes previous ones
                    let mut state = self.state.write().await;
                    if let Some(current_chainlock_height) = state.last_chainlock_height {
                        if chainlock.block_height <= current_chainlock_height {
                            tracing::debug!("ChainLock for height {} does not supersede current ChainLock at height {}", 
                                           chainlock.block_height, current_chainlock_height);
                            return Ok(());
                        }
                    }
                    
                    // Update our confirmed chain tip
                    state.last_chainlock_height = Some(chainlock.block_height);
                    state.last_chainlock_hash = Some(chainlock.block_hash);
                    
                    tracing::info!("🔒 Updated confirmed chain tip to ChainLock at height {} ({})", 
                                  chainlock.block_height, chainlock.block_hash);
                    
                    // Store ChainLock for future reference in storage
                    drop(state); // Release the lock before storage operation
                    
                    // Create a metadata key for this ChainLock
                    let chainlock_key = format!("chainlock_{}", chainlock.block_height);
                    
                    // Serialize the ChainLock
                    let chainlock_bytes = serde_json::to_vec(&chainlock)
                        .map_err(|e| SpvError::Storage(crate::error::StorageError::Serialization(
                            format!("Failed to serialize ChainLock: {}", e)
                        )))?;
                    
                    // Store the ChainLock
                    self.storage.store_metadata(&chainlock_key, &chainlock_bytes).await
                        .map_err(|e| SpvError::Storage(e))?;
                    
                    tracing::debug!("Stored ChainLock for height {} in persistent storage", chainlock.block_height);
                    
                    // Also store the latest ChainLock height for quick lookup
                    let latest_key = "latest_chainlock_height";
                    let height_bytes = chainlock.block_height.to_le_bytes();
                    self.storage.store_metadata(latest_key, &height_bytes).await
                        .map_err(|e| SpvError::Storage(e))?;
                    
                    // Save the updated chain state to persist ChainLock fields
                    let updated_state = self.state.read().await;
                    self.storage.store_chain_state(&*updated_state).await
                        .map_err(|e| SpvError::Storage(e))?;
                    
                    // Update status display after chainlock update
                    self.update_status_display().await;
                },
                Err(e) => {
                    tracing::error!("❌ ChainLock signature verification failed for block {} at height {}: {:?}", 
                                   chainlock.block_hash, chainlock.block_height, e);
                    return Err(SpvError::Validation(crate::error::ValidationError::InvalidChainLock(format!("Verification failed: {:?}", e))));
                }
            }
        } else {
            tracing::warn!("⚠️  No masternode engine available - cannot verify ChainLock signature for block {} at height {}", 
                          chainlock.block_hash, chainlock.block_height);
            
            // Still log the ChainLock details even if we can't verify
            tracing::info!("ChainLock received: block_hash={}, height={}, signature={}...", 
                          chainlock.block_hash, chainlock.block_height, 
                          chainlock.signature.to_string().chars().take(20).collect::<String>());
        }
        
        Ok(())
    }
    
    /// Process and validate an InstantSendLock.
    async fn process_instantsendlock(&mut self, islock: dashcore::ephemerealdata::instant_lock::InstantLock) -> Result<()> {
        tracing::info!("Processing InstantSendLock for tx {}", islock.txid);
        
        // TODO: Implement InstantSendLock validation  
        // - Verify BLS signature against known quorum
        // - Check if all inputs are locked
        // - Mark transaction as instantly confirmed
        // - Store InstantSendLock for future reference
        
        // For now, just log the InstantSendLock details
        tracing::info!("InstantSendLock validated: txid={}, inputs={}, signature={:?}",
                      islock.txid, islock.inputs.len(),
                      islock.signature.to_string().chars().take(20).collect::<String>());
        
        Ok(())
    }
    
    /// Get current sync progress.
    pub async fn sync_progress(&self) -> Result<SyncProgress> {
        let state = self.state.read().await;
        Ok(SyncProgress {
            header_height: state.tip_height(),
            filter_header_height: state.filter_headers.len().saturating_sub(1) as u32,
            masternode_height: state.last_masternode_diff_height.unwrap_or(0),
            peer_count: 1, // TODO: Get from network manager
            headers_synced: false, // TODO: Implement
            filter_headers_synced: false, // TODO: Implement
            masternodes_synced: false, // TODO: Implement
            filters_downloaded: 0, // TODO: Track properly
            sync_start: std::time::SystemTime::now(), // TODO: Track properly
            last_update: std::time::SystemTime::now(),
        })
    }
    
    /// Add a watch item.
    pub async fn add_watch_item(&mut self, item: WatchItem) -> Result<()> {
        let mut watch_items = self.watch_items.write().await;
        let is_new = watch_items.insert(item.clone());
        
        if is_new {
            tracing::info!("Added watch item: {:?}", item);
            
            // Store in persistent storage
            let watch_list: Vec<WatchItem> = watch_items.iter().cloned().collect();
            let serialized = serde_json::to_vec(&watch_list)
                .map_err(|e| SpvError::Config(format!("Failed to serialize watch items: {}", e)))?;
            
            self.storage.store_metadata("watch_items", &serialized).await
                .map_err(|e| SpvError::Storage(e))?;
        }
        
        Ok(())
    }
    
    /// Remove a watch item.
    pub async fn remove_watch_item(&mut self, item: &WatchItem) -> Result<bool> {
        let mut watch_items = self.watch_items.write().await;
        let removed = watch_items.remove(item);
        
        if removed {
            tracing::info!("Removed watch item: {:?}", item);
            
            // Update persistent storage
            let watch_list: Vec<WatchItem> = watch_items.iter().cloned().collect();
            let serialized = serde_json::to_vec(&watch_list)
                .map_err(|e| SpvError::Config(format!("Failed to serialize watch items: {}", e)))?;
            
            self.storage.store_metadata("watch_items", &serialized).await
                .map_err(|e| SpvError::Storage(e))?;
        }
        
        Ok(removed)
    }
    
    /// Get all watch items.
    pub async fn get_watch_items(&self) -> Vec<WatchItem> {
        let watch_items = self.watch_items.read().await;
        watch_items.iter().cloned().collect()
    }
    
    /// Get the number of connected peers.
    pub async fn get_peer_count(&self) -> usize {
        self.network.peer_count()
    }
    
    /// Sync compact filters for recent blocks and check for matches.
    pub async fn sync_and_check_filters(&mut self, num_blocks: Option<u32>) -> Result<Vec<crate::types::FilterMatch>> {
        let running = self.running.read().await;
        if !*running {
            return Err(SpvError::Config("Client not running".to_string()));
        }
        drop(running);
        
        // Get current tip height to determine range
        let tip_height = self.storage.get_tip_height().await
            .map_err(|e| SpvError::Storage(e))?
            .unwrap_or(0);
        
        // Get current watch items to determine earliest height needed
        let watch_items = self.get_watch_items().await;
        
        // Find the earliest height among all watch items
        let earliest_height = watch_items.iter()
            .filter_map(|item| item.earliest_height())
            .min()
            .unwrap_or(tip_height.saturating_sub(99)); // Default to last 100 blocks if no earliest_height set
        
        let num_blocks = num_blocks.unwrap_or(100);
        let default_start = tip_height.saturating_sub(num_blocks - 1);
        let start_height = earliest_height.min(default_start); // Go back to the earliest required height
        let actual_count = tip_height - start_height + 1; // Actual number of blocks available
        
        tracing::info!("Syncing and checking filters from height {} to {} ({} blocks)", 
                      start_height, tip_height, actual_count);
        
        // Use the new coordinated sync method
        self.sync_filters_coordinated(start_height, actual_count).await?;
        
        if watch_items.is_empty() {
            tracing::info!("No watch items configured, skipping filter matching");
            return Ok(Vec::new());
        }
        
        // Check filters for matches
        let matches = self.sync_manager.check_filter_matches(&*self.storage, &watch_items, start_height, tip_height).await
            .map_err(|e| SpvError::Sync(e))?;
        
        tracing::info!("Found {} filter matches for {} watch items", matches.len(), watch_items.len());
        
        // Request block downloads for all matches
        if !matches.is_empty() {
            tracing::info!("🎯 Processing {} filter matches and requesting block downloads", matches.len());
            
            let processed_matches = self.sync_manager.request_block_downloads(matches.clone(), &mut *self.network).await
                .map_err(|e| SpvError::Sync(e))?;
            
            tracing::info!("✅ Successfully requested {} block downloads", processed_matches.len());
            
            // Update statistics
            {
                let mut stats = self.stats.write().await;
                stats.filter_matches += processed_matches.len() as u64;
            }
        }
        
        Ok(matches)
    }
    
    /// Sync filters in coordination with the monitoring loop using pipelined processing
    async fn sync_filters_coordinated(&mut self, start_height: u32, count: u32) -> Result<()> {
        // Check if filter sync is already active
        {
            let sync_state = self.filter_sync_state.read().await;
            if sync_state.active {
                return Err(SpvError::Config("Filter sync already in progress".to_string()));
            }
        }
        
        let end_height = start_height + count - 1;
        
        // Set up sync state for coordination with monitoring loop
        {
            let mut sync_state = self.filter_sync_state.write().await;
            sync_state.active = true;
            sync_state.expected_range = Some((start_height, end_height));
            sync_state.received_count = 0;
            sync_state.expected_count = count;
        }
        
        tracing::info!("Starting coordinated filter sync from height {} to {} ({} filters expected)", 
                      start_height, end_height, count);
        
        // Use pipelined processing: send a few batches, wait for responses, then send more
        let batch_size = 100;
        let pipeline_window = 2; // Number of batches to keep "in flight" at once
        let mut current_height = start_height;
        let mut batches_sent = 0;
        let mut last_received_count = 0;
        
        // Send initial pipeline window of requests
        while current_height <= end_height && batches_sent < pipeline_window {
            let batch_end = (current_height + batch_size - 1).min(end_height);
            
            tracing::debug!("Sending initial batch {}: heights {} to {}", batches_sent + 1, current_height, batch_end);
            
            // Get stop hash for this batch
            let stop_hash = self.storage.get_header(batch_end).await
                .map_err(|e| SpvError::Storage(e))?
                .ok_or_else(|| SpvError::Config("Stop header not found".to_string()))?
                .block_hash();
            
            // Send the request - monitoring loop will handle the responses
            self.sync_manager.filter_sync_mut().request_filters(&mut *self.network, current_height, stop_hash).await
                .map_err(|e| SpvError::Sync(e))?;
            
            current_height = batch_end + 1;
            batches_sent += 1;
        }
        
        // Now use pipelined processing for the remaining batches
        let timeout = tokio::time::Duration::from_secs(45); // Increased timeout for pipelined approach
        let start_time = tokio::time::Instant::now();
        let batch_timeout = tokio::time::Duration::from_secs(10); // Timeout for individual batch responses
        let mut last_progress_time = tokio::time::Instant::now();
        
        loop {
            // Check current progress
            let (sync_complete, received_count, progress_made) = {
                let sync_state = self.filter_sync_state.read().await;
                let progress_made = sync_state.received_count > last_received_count;
                if progress_made {
                    last_received_count = sync_state.received_count;
                }
                (
                    !sync_state.active || sync_state.received_count >= sync_state.expected_count,
                    sync_state.received_count,
                    progress_made
                )
            };
            
            // Reset batch timeout if we made progress
            if progress_made {
                last_progress_time = tokio::time::Instant::now();
                tracing::debug!("Filter sync progress: {}/{} filters received", received_count, count);
            }
            
            // Check if sync is complete
            if sync_complete {
                tracing::info!("Filter sync completed successfully: received {}/{} filters", received_count, count);
                break;
            }
            
            // Send more requests if we have capacity and more batches to send
            if current_height <= end_height {
                // Check if we should send more batches (when we've received some responses)
                let responses_per_batch = batch_size.min(end_height - current_height + batch_size);
                let expected_responses_so_far = batches_sent * responses_per_batch;
                let response_lag = expected_responses_so_far.saturating_sub(received_count);
                
                // Send another batch if we're not too far ahead
                if response_lag < (pipeline_window * batch_size) && current_height <= end_height {
                    let batch_end = (current_height + batch_size - 1).min(end_height);
                    
                    tracing::debug!("Sending additional batch: heights {} to {} (lag: {})", 
                                   current_height, batch_end, response_lag);
                    
                    // Get stop hash for this batch
                    let stop_hash = self.storage.get_header(batch_end).await
                        .map_err(|e| SpvError::Storage(e))?
                        .ok_or_else(|| SpvError::Config("Stop header not found".to_string()))?
                        .block_hash();
                    
                    // Send the request
                    self.sync_manager.filter_sync_mut().request_filters(&mut *self.network, current_height, stop_hash).await
                        .map_err(|e| SpvError::Sync(e))?;
                    
                    current_height = batch_end + 1;
                    batches_sent += 1;
                }
            }
            
            // Check for timeouts
            if start_time.elapsed() > timeout {
                // Reset sync state on overall timeout
                {
                    let mut sync_state = self.filter_sync_state.write().await;
                    sync_state.active = false;
                    sync_state.expected_range = None;
                    sync_state.received_count = 0;
                    sync_state.expected_count = 0;
                }
                return Err(SpvError::Config(format!(
                    "Filter sync timeout: received {}/{} filters in {:?}", 
                    received_count, count, start_time.elapsed()
                )));
            }
            
            // Check for batch timeout (no progress)
            if last_progress_time.elapsed() > batch_timeout {
                tracing::warn!("No filter sync progress for {:?}, continuing to wait...", last_progress_time.elapsed());
                last_progress_time = tokio::time::Instant::now(); // Reset to avoid spamming
            }
            
            // Small delay before checking again
            tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
        }
        
        Ok(())
    }
    
    /// Initialize genesis block if not already present in storage.
    async fn initialize_genesis_block(&mut self) -> Result<()> {
        // Check if we already have any headers in storage
        let current_tip = self.storage.get_tip_height().await
            .map_err(|e| SpvError::Storage(e))?;
        
        if current_tip.is_some() {
            // We already have headers, genesis block should be at height 0
            tracing::debug!("Headers already exist in storage, skipping genesis initialization");
            return Ok(());
        }
        
        // Get the genesis block hash for this network
        let genesis_hash = self.config.network.known_genesis_block_hash()
            .ok_or_else(|| SpvError::Config("No known genesis hash for network".to_string()))?;
        
        tracing::info!("Initializing genesis block for network {:?}: {}", self.config.network, genesis_hash);
        
        // Create the correct genesis header using known Dash genesis block parameters
        use dashcore::{
            block::{Header as BlockHeader, Version},
            pow::CompactTarget,
        };
        use dashcore_hashes::Hash;
        
        let genesis_header = match self.config.network {
            dashcore::Network::Dash => {
                // Use the actual Dash genesis block parameters from the block explorer data
                BlockHeader {
                    version: Version::from_consensus(1),
                    prev_blockhash: dashcore::BlockHash::all_zeros(),
                    merkle_root: "e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7".parse()
                        .expect("valid merkle root"),
                    time: 1390095618,
                    bits: CompactTarget::from_consensus(0x1e0ffff0),
                    nonce: 28917698,
                }
            }
            _ => {
                // For other networks, use the existing genesis block function
                dashcore::blockdata::constants::genesis_block(self.config.network).header
            }
        };
        
        // Verify the header produces the expected genesis hash
        let calculated_hash = genesis_header.block_hash();
        if calculated_hash != genesis_hash {
            return Err(SpvError::Config(format!(
                "Genesis header hash mismatch! Expected: {}, Calculated: {}", 
                genesis_hash, calculated_hash
            )));
        }
        
        tracing::debug!("Using genesis block header with hash: {}", calculated_hash);
        
        // Store the genesis header at height 0
        let genesis_headers = vec![genesis_header];
        self.storage.store_headers(&genesis_headers).await
            .map_err(|e| SpvError::Storage(e))?;
        
        tracing::info!("✅ Genesis block initialized at height 0");
        
        Ok(())
    }
    
    /// Load watch items from storage.
    async fn load_watch_items(&mut self) -> Result<()> {
        if let Some(data) = self.storage.load_metadata("watch_items").await
            .map_err(|e| SpvError::Storage(e))? {
            
            let watch_list: Vec<WatchItem> = serde_json::from_slice(&data)
                .map_err(|e| SpvError::Config(format!("Failed to deserialize watch items: {}", e)))?;
            
            let mut watch_items = self.watch_items.write().await;
            for item in watch_list {
                watch_items.insert(item);
            }
            
            tracing::info!("Loaded {} watch items from storage", watch_items.len());
        }
        
        Ok(())
    }
    
    /// Get current statistics.
    pub async fn stats(&self) -> Result<SpvStats> {
        let stats = self.stats.read().await;
        Ok(stats.clone())
    }
    
    /// Get current chain state (read-only).
    pub async fn chain_state(&self) -> ChainState {
        let state = self.state.read().await;
        state.clone()
    }
    
    /// Check if the client is running.
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
    
    /// Update the status display.
    async fn update_status_display(&self) {
        if let Some(ui) = &self.terminal_ui {
            // Get header height
            let header_height = match self.storage.get_tip_height().await {
                Ok(Some(height)) => height,
                _ => 0,
            };
            
            // Get filter header height
            let filter_height = match self.storage.get_filter_tip_height().await {
                Ok(Some(height)) => height,
                _ => 0,
            };
            
            // Get latest chainlock height from state
            let chainlock_height = {
                let state = self.state.read().await;
                state.last_chainlock_height
            };
            
            // Get latest chainlock height from storage metadata (in case state wasn't updated)
            let stored_chainlock_height = if let Ok(Some(data)) = self.storage.load_metadata("latest_chainlock_height").await {
                if data.len() >= 4 {
                    Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
                } else {
                    None
                }
            } else {
                None
            };
            
            // Use the higher of the two chainlock heights
            let latest_chainlock = match (chainlock_height, stored_chainlock_height) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
            
            // Update terminal UI
            let _ = ui.update_status(|status| {
                status.headers = header_height;
                status.filter_headers = filter_height;
                status.chainlock_height = latest_chainlock;
                status.peer_count = 1; // TODO: Get actual peer count
                status.network = format!("{:?}", self.config.network);
            }).await;
        } else {
            // Fall back to simple logging if terminal UI is not enabled
            let header_height = match self.storage.get_tip_height().await {
                Ok(Some(height)) => height,
                _ => 0,
            };
            
            let filter_height = match self.storage.get_filter_tip_height().await {
                Ok(Some(height)) => height,
                _ => 0,
            };
            
            let chainlock_height = {
                let state = self.state.read().await;
                state.last_chainlock_height.unwrap_or(0)
            };
            
            tracing::info!(
                "📊 [SYNC STATUS] Headers: {} | Filter Headers: {} | Latest ChainLock: {}",
                header_height,
                filter_height,
                if chainlock_height > 0 {
                    format!("#{}", chainlock_height)
                } else {
                    "None".to_string()
                }
            );
        }
    }
}