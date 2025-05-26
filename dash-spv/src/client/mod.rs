//! High-level client API for the Dash SPV client.

pub mod config;

use std::sync::Arc;
use tokio::sync::RwLock;

use std::collections::HashSet;

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
}

impl DashSpvClient {
    /// Create a new SPV client with the given configuration.
    pub async fn new(config: ClientConfig) -> Result<Self> {
        // Validate configuration
        config.validate().map_err(|e| SpvError::Config(e))?;
        
        // Initialize state for the network
        let state = Arc::new(RwLock::new(ChainState::new_for_network(config.network)));
        let stats = Arc::new(RwLock::new(SpvStats::default()));
        
        // Create network manager
        let network = crate::network::TcpNetworkManager::new(&config).await
            .map_err(|e| SpvError::Network(e))?;
        
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
        
        // Connect to network
        self.network.connect().await?;
        
        {
            let mut running = self.running.write().await;
            *running = true;
        }
        
        Ok(())
    }
    
    /// Stop the SPV client.
    pub async fn stop(&mut self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }
        
        // Disconnect from network
        self.network.disconnect().await?;
        
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
        self.sync_manager.sync_all(&mut *self.network, &mut *self.storage).await
            .map_err(|e| SpvError::Sync(e))
    }
    
    /// Run continuous monitoring for new blocks, ChainLocks, InstantLocks, etc.
    pub async fn monitor_network(&mut self) -> Result<()> {
        let running = self.running.read().await;
        if !*running {
            return Err(SpvError::Config("Client not running".to_string()));
        }
        drop(running);
        
        tracing::info!("Starting continuous network monitoring...");
        
        loop {
            // Check if we should stop
            let running = self.running.read().await;
            if !*running {
                tracing::info!("Stopping network monitoring");
                break;
            }
            drop(running);
            
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
                // Update our chain tip with new headers
                // TODO: Implement process_new_headers in sync manager
                self.sync_manager.sync_all(&mut *self.network, &mut *self.storage).await
                    .map_err(|e| SpvError::Sync(e))?;
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
        
        // Request new block headers (but not full blocks for SPV)
        if !blocks_to_request.is_empty() {
            tracing::info!("New blocks available, will request headers in next sync");
            // For SPV, we usually request headers rather than full blocks
            // The next sync cycle will pick up new headers
        }
        
        Ok(())
    }

    /// Process a new block.
    async fn process_new_block(&mut self, _block: dashcore::Block) -> Result<()> {
        // TODO: Implement block processing
        // - Update chain state
        // - Check for watched transactions
        // - Update filter headers if needed
        tracing::info!("Block processing not yet implemented");
        Ok(())
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
                    
                    // TODO: Store ChainLock for future reference in storage
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
        
        let num_blocks = num_blocks.unwrap_or(100);
        let start_height = tip_height.saturating_sub(num_blocks - 1);
        
        tracing::info!("Syncing and checking filters from height {} to {} ({} blocks)", 
                      start_height, tip_height, num_blocks);
        
        // Sync filters for the range
        self.sync_manager.sync_filters(&mut *self.network, &mut *self.storage, Some(start_height), Some(num_blocks)).await
            .map_err(|e| SpvError::Sync(e))?;
        
        // Get current watch items
        let watch_items = self.get_watch_items().await;
        
        if watch_items.is_empty() {
            tracing::info!("No watch items configured, skipping filter matching");
            return Ok(Vec::new());
        }
        
        // Check filters for matches
        let matches = self.sync_manager.check_filter_matches(&*self.storage, &watch_items, start_height, tip_height).await
            .map_err(|e| SpvError::Sync(e))?;
        
        tracing::info!("Found {} filter matches for {} watch items", matches.len(), watch_items.len());
        
        Ok(matches)
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
}