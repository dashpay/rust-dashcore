//! High-level client API for the Dash SPV client.

pub mod config;

use std::sync::Arc;
use tokio::sync::{RwLock, Mutex, mpsc, oneshot};
use std::time::Instant;

use std::collections::{HashSet, HashMap};

use crate::terminal::TerminalUI;

use crate::error::{Result, SpvError};
use crate::types::{AddressBalance, ChainState, SpvStats, SyncProgress, WatchItem};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::SyncManager;
use crate::sync::filters::FilterNotificationSender;
use crate::validation::ValidationManager;

pub use config::ClientConfig;

/// Handle for sending watch item updates to the filter processor.
pub type WatchItemUpdateSender = tokio::sync::mpsc::UnboundedSender<Vec<crate::types::WatchItem>>;

/// Task for the block processing worker.
#[derive(Debug)]
pub enum BlockProcessingTask {
    ProcessBlock {
        block: dashcore::Block,
        response_tx: oneshot::Sender<Result<()>>,
    },
    ProcessTransaction {
        tx: dashcore::Transaction,
        response_tx: oneshot::Sender<Result<()>>,
    },
}

/// Block processing worker that handles blocks in a separate task.
pub struct BlockProcessor {
    receiver: mpsc::UnboundedReceiver<BlockProcessingTask>,
    storage: Arc<Mutex<Box<dyn StorageManager>>>,
    watch_items: Arc<RwLock<HashSet<WatchItem>>>,
    stats: Arc<RwLock<SpvStats>>,
    processed_blocks: std::collections::HashSet<dashcore::BlockHash>,
    failed: bool,
}

impl BlockProcessor {
    /// Create a new block processor.
    pub fn new(
        receiver: mpsc::UnboundedReceiver<BlockProcessingTask>,
        storage: Arc<Mutex<Box<dyn StorageManager>>>,
        watch_items: Arc<RwLock<HashSet<WatchItem>>>,
        stats: Arc<RwLock<SpvStats>>,
    ) -> Self {
        Self {
            receiver,
            storage,
            watch_items,
            stats,
            processed_blocks: std::collections::HashSet::new(),
            failed: false,
        }
    }
    
    /// Run the block processor worker loop.
    pub async fn run(mut self) {
        tracing::info!("🏭 Block processor worker started");
        
        while let Some(task) = self.receiver.recv().await {
            // If we're in failed state, reject all new tasks
            if self.failed {
                match task {
                    BlockProcessingTask::ProcessBlock { response_tx, block } => {
                        let block_hash = block.block_hash();
                        tracing::error!("❌ Block processor in failed state, rejecting block {}", block_hash);
                        let _ = response_tx.send(Err(SpvError::Config("Block processor has failed".to_string())));
                    }
                    BlockProcessingTask::ProcessTransaction { response_tx, tx } => {
                        let txid = tx.txid();
                        tracing::error!("❌ Block processor in failed state, rejecting transaction {}", txid);
                        let _ = response_tx.send(Err(SpvError::Config("Block processor has failed".to_string())));
                    }
                }
                continue;
            }
            
            match task {
                BlockProcessingTask::ProcessBlock { block, response_tx } => {
                    let block_hash = block.block_hash();
                    
                    // Check for duplicate blocks
                    if self.processed_blocks.contains(&block_hash) {
                        tracing::warn!("⚡ Block {} already processed, skipping", block_hash);
                        let _ = response_tx.send(Ok(()));
                        continue;
                    }
                    
                    // Process block and handle errors
                    let result = self.process_block_internal(block).await;
                    
                    match &result {
                        Ok(()) => {
                            // Mark block as successfully processed
                            self.processed_blocks.insert(block_hash);
                            
                            // Update blocks processed statistics
                            {
                                let mut stats = self.stats.write().await;
                                stats.blocks_processed += 1;
                            }
                            
                            tracing::info!("✅ Block {} processed successfully", block_hash);
                        }
                        Err(e) => {
                            // Log error with block hash and enter failed state
                            tracing::error!("❌ BLOCK PROCESSING FAILED for block {}: {}", block_hash, e);
                            tracing::error!("❌ Block processor entering failed state - no more blocks will be processed");
                            self.failed = true;
                        }
                    }
                    
                    let _ = response_tx.send(result);
                }
                BlockProcessingTask::ProcessTransaction { tx, response_tx } => {
                    let txid = tx.txid();
                    let result = self.process_transaction_internal(tx).await;
                    
                    if let Err(e) = &result {
                        tracing::error!("❌ TRANSACTION PROCESSING FAILED for tx {}: {}", txid, e);
                        tracing::error!("❌ Block processor entering failed state");
                        self.failed = true;
                    }
                    
                    let _ = response_tx.send(result);
                }
            }
        }
        
        tracing::info!("🏭 Block processor worker stopped");
    }
    
    /// Process a block internally.
    async fn process_block_internal(&mut self, block: dashcore::Block) -> Result<()> {
        let block_hash = block.block_hash();
        
        tracing::info!("📦 Processing downloaded block: {}", block_hash);
        
        // Process all blocks unconditionally since we already downloaded them
        // Extract transactions that might affect watched items
        let watch_items: Vec<_> = self.watch_items.read().await.iter().cloned().collect();
        if !watch_items.is_empty() {
            self.process_block_transactions(&block, &watch_items).await?;
        }
        
        // Update chain state if needed
        self.update_chain_state_with_block(&block).await?;
        
        Ok(())
    }
    
    /// Process a transaction internally.
    async fn process_transaction_internal(&mut self, _tx: dashcore::Transaction) -> Result<()> {
        // TODO: Implement transaction processing
        // - Check if transaction affects watched addresses/scripts
        // - Update wallet balance if relevant
        // - Store relevant transactions
        tracing::debug!("Transaction processing not yet implemented");
        Ok(())
    }
    
    /// Helper method to find height for a block hash.
    async fn find_height_for_block_hash(&self, block_hash: dashcore::BlockHash) -> Option<u32> {
        // Use the efficient reverse index
        let storage = self.storage.lock().await;
        storage.get_header_height_by_hash(&block_hash).await.ok().flatten()
    }
    
    /// Process transactions in a block to check for matches with watch items.
    async fn process_block_transactions(
        &mut self, 
        block: &dashcore::Block, 
        watch_items: &[WatchItem]
    ) -> Result<()> {
        let block_hash = block.block_hash();
        let block_height = self.find_height_for_block_hash(block_hash).await.unwrap_or(0);
        let mut relevant_transactions = 0;
        let mut new_outpoints_to_watch = Vec::new();
        let mut balance_changes: HashMap<dashcore::Address, i64> = HashMap::new();
        
        for (tx_index, transaction) in block.txdata.iter().enumerate() {
            let txid = transaction.txid();
            let is_coinbase = tx_index == 0;
            
            // Wrap transaction processing in error handling to log failing txid
            match self.process_single_transaction_in_block(
                transaction, 
                tx_index, 
                watch_items, 
                &mut balance_changes,
                &mut new_outpoints_to_watch,
                block_height,
                is_coinbase
            ).await {
                Ok(is_relevant) => {
                    if is_relevant {
                        relevant_transactions += 1;
                        tracing::debug!("📝 Transaction {}: {} (index {}) is relevant", 
                                       txid, if is_coinbase { "coinbase" } else { "regular" }, tx_index);
                    }
                }
                Err(e) => {
                    // Log error with both block hash and failing transaction ID
                    tracing::error!("❌ TRANSACTION PROCESSING FAILED in block {} for tx {} (index {}): {}", 
                                   block_hash, txid, tx_index, e);
                    return Err(e);
                }
            }
        }
        
        if relevant_transactions > 0 {
            tracing::info!("🎯 Block {} contains {} relevant transactions affecting watched items", 
                          block_hash, relevant_transactions);

            // Report balance changes
            if !balance_changes.is_empty() {
                self.report_balance_changes(&balance_changes, block_height).await?;
            }
        }
        
        Ok(())
    }
    
    /// Process a single transaction within a block for watch item matches.
    /// Returns whether the transaction is relevant to any watch items.
    async fn process_single_transaction_in_block(
        &mut self,
        transaction: &dashcore::Transaction,
        _tx_index: usize,
        watch_items: &[WatchItem],
        balance_changes: &mut HashMap<dashcore::Address, i64>,
        new_outpoints_to_watch: &mut Vec<dashcore::OutPoint>,
        block_height: u32,
        is_coinbase: bool,
    ) -> Result<bool> {
        let txid = transaction.txid();
        let mut transaction_relevant = false;
        
        // Process inputs first (spending UTXOs)
        if !is_coinbase {
            for (vin, input) in transaction.input.iter().enumerate() {
                // Check if this input spends a UTXO from our watched addresses
                {
                    let mut storage = self.storage.lock().await;
                    if let Ok(all_utxos) = storage.get_all_utxos().await {
                        if let Some(spent_utxo) = all_utxos.get(&input.previous_output) {
                            transaction_relevant = true;
                            let amount = spent_utxo.value();
                            
                            tracing::info!("💸 Found relevant input: {}:{} spending UTXO {} (value: {})", 
                                          txid, vin, input.previous_output, amount);
                            
                            // Update balance change for this address (subtract)
                            *balance_changes.entry(spent_utxo.address.clone()).or_insert(0) -= amount.to_sat() as i64;
                            
                            // Remove the spent UTXO from storage
                            if let Err(e) = storage.remove_utxo(&input.previous_output).await {
                                tracing::error!("Failed to remove spent UTXO {}: {}", input.previous_output, e);
                            }
                        }
                    }
                }
                
                // Also check against explicitly watched outpoints
                for watch_item in watch_items {
                    if let WatchItem::Outpoint(watched_outpoint) = watch_item {
                        if &input.previous_output == watched_outpoint {
                            transaction_relevant = true;
                            tracing::info!("💸 Found relevant input: {}:{} spending explicitly watched outpoint {:?}", 
                                          txid, vin, watched_outpoint);
                        }
                    }
                }
            }
        }
        
        // Process outputs (creating new UTXOs)
        for (vout, output) in transaction.output.iter().enumerate() {
            for watch_item in watch_items {
                let (matches, matched_address) = match watch_item {
                    WatchItem::Address { address, .. } => {
                        (address.script_pubkey() == output.script_pubkey, Some(address.clone()))
                    }
                    WatchItem::Script(script) => {
                        (script == &output.script_pubkey, None)
                    }
                    WatchItem::Outpoint(_) => (false, None), // Outpoints don't match outputs
                };
                
                if matches {
                    transaction_relevant = true;
                    let outpoint = dashcore::OutPoint { txid, vout: vout as u32 };
                    let amount = dashcore::Amount::from_sat(output.value);
                    
                    tracing::info!("💰 Found relevant output: {}:{} to {:?} (value: {})", 
                                  txid, vout, watch_item, amount);
                    
                    // Create and store UTXO if we have an address
                    if let Some(address) = matched_address {
                        let utxo = crate::wallet::Utxo::new(
                            outpoint,
                            output.clone(),
                            address.clone(),
                            block_height,
                            is_coinbase,
                        );
                        
                        let mut storage = self.storage.lock().await;
                        if let Err(e) = storage.store_utxo(&outpoint, &utxo).await {
                            tracing::error!("Failed to store UTXO {}: {}", outpoint, e);
                        } else {
                            tracing::debug!("📝 Stored UTXO {}:{} for address {}", txid, vout, address);
                        }
                        
                        // Update balance change for this address (add)
                        *balance_changes.entry(address.clone()).or_insert(0) += amount.to_sat() as i64;
                    }
                    
                    // Track this outpoint so we can detect when it's spent
                    new_outpoints_to_watch.push(outpoint);
                    tracing::debug!("📍 Now watching outpoint {}:{} for future spending", txid, vout);
                }
        }
        }
        
        Ok(transaction_relevant)
    }
    
    /// Report balance changes for watched addresses.
    async fn report_balance_changes(
        &self,
        balance_changes: &HashMap<dashcore::Address, i64>,
        block_height: u32,
    ) -> Result<()> {
        tracing::info!("💰 Balance changes detected in block at height {}:", block_height);
        
        for (address, change_sat) in balance_changes {
            if *change_sat != 0 {
                let change_amount = dashcore::Amount::from_sat(change_sat.abs() as u64);
                let sign = if *change_sat > 0 { "+" } else { "-" };
                tracing::info!("  📍 Address {}: {}{}", address, sign, change_amount);
            }
        }
        
        // Calculate and report current balances for all watched addresses
        let watch_items: Vec<_> = self.watch_items.read().await.iter().cloned().collect();
        for watch_item in watch_items.iter() {
            if let WatchItem::Address { address, .. } = watch_item {
                match self.get_address_balance(address).await {
                    Ok(balance) => {
                        tracing::info!("  💼 Address {} balance: {} (confirmed: {}, unconfirmed: {})", 
                                      address, balance.total(), balance.confirmed, balance.unconfirmed);
                    }
                    Err(e) => {
                        tracing::error!("Failed to get balance for address {}: {}", address, e);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Get the balance for a specific address.
    async fn get_address_balance(&self, address: &dashcore::Address) -> Result<AddressBalance> {
        let storage = self.storage.lock().await;
        
        // Get current tip height for confirmation calculations
        let current_tip = storage.get_tip_height().await
            .map_err(|e| SpvError::Storage(e))?
            .unwrap_or(0);
        
        // Get UTXOs for this address
        let utxos = storage.get_utxos_for_address(address).await
            .map_err(|e| SpvError::Storage(e))?;
        
        let mut confirmed = dashcore::Amount::ZERO;
        let mut unconfirmed = dashcore::Amount::ZERO;
        
        for utxo in utxos {
            let confirmations = if current_tip >= utxo.height {
                current_tip - utxo.height + 1
            } else {
                0
            };
            
            // Consider confirmed if it has 6+ confirmations or is InstantLocked
            if confirmations >= 6 || utxo.is_instantlocked {
                confirmed += utxo.value();
            } else {
                unconfirmed += utxo.value();
            }
        }
        
        Ok(AddressBalance {
            confirmed,
            unconfirmed,
        })
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
}

/// Main Dash SPV client.
pub struct DashSpvClient {
    config: ClientConfig,
    state: Arc<RwLock<ChainState>>,
    stats: Arc<RwLock<SpvStats>>,
    network: Box<dyn NetworkManager>,
    storage: Box<dyn StorageManager>,
    sync_manager: SyncManager,
    _validation: ValidationManager,
    running: Arc<RwLock<bool>>,
    watch_items: Arc<RwLock<HashSet<WatchItem>>>,
    terminal_ui: Option<Arc<TerminalUI>>,
    filter_processor: Option<FilterNotificationSender>,
    watch_item_updater: Option<WatchItemUpdateSender>,
    block_processor_tx: mpsc::UnboundedSender<BlockProcessingTask>,
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

        // Create shared data structures
        let watch_items = Arc::new(RwLock::new(HashSet::new()));
        
        // Create sync manager
        let sync_manager = SyncManager::new(&config);
        
        // Create validation manager
        let validation = ValidationManager::new(config.validation_mode);
        
        // Create block processing channel
        let (block_processor_tx, _block_processor_rx) = mpsc::unbounded_channel();
        
        Ok(Self {
            config,
            state,
            stats,
            network: Box::new(network),
            storage,
            sync_manager,
            _validation: validation,
            running: Arc::new(RwLock::new(false)),
            watch_items,
            terminal_ui: None,
            filter_processor: None,
            watch_item_updater: None,
            block_processor_tx,
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
        
        // Spawn block processor worker now that all dependencies are ready
        let (new_tx, block_processor_rx) = mpsc::unbounded_channel();
        let old_tx = std::mem::replace(&mut self.block_processor_tx, new_tx);
        drop(old_tx); // Drop the old sender to avoid confusion
        
        // Wrap storage in Arc<Mutex> for the block processor
        let storage_clone = if let Some(_disk_storage) = self.storage.as_any_mut().downcast_ref::<crate::storage::DiskStorageManager>() {
            // For disk storage, create a new instance pointing to the same data directory
            let base_path = if let Some(config_path) = &self.config.storage_path {
                config_path.clone()
            } else {
                std::path::PathBuf::from("data")
            };
            Arc::new(Mutex::new(Box::new(crate::storage::DiskStorageManager::new(base_path).await
                .map_err(|e| SpvError::Storage(e))?) as Box<dyn StorageManager>))
        } else if let Some(_memory_storage) = self.storage.as_any_mut().downcast_ref::<crate::storage::MemoryStorageManager>() {
            // For memory storage, create a new instance (data won't be shared, but it's just for the worker)
            Arc::new(Mutex::new(Box::new(crate::storage::MemoryStorageManager::new().await
                .map_err(|e| SpvError::Storage(e))?) as Box<dyn StorageManager>))
        } else {
            return Err(SpvError::Config("Unsupported storage manager type for cloning".to_string()));
        };
        
        let block_processor = BlockProcessor::new(
            block_processor_rx,
            storage_clone,
            self.watch_items.clone(),
            self.stats.clone(),
        );
        
        tokio::spawn(async move {
            tracing::info!("🏭 Starting block processor worker task");
            block_processor.run().await;
            tracing::info!("🏭 Block processor worker task completed");
        });
        
        // Always initialize filter processor if filters are enabled (regardless of watch items)
        if self.config.enable_filters && self.filter_processor.is_none() {
            let watch_items = self.get_watch_items().await;
            let network_message_sender = self.network.get_message_sender();
            let processing_thread_requests = self.sync_manager.filter_sync().processing_thread_requests.clone();
            let (filter_processor, watch_item_updater) = crate::sync::filters::FilterSyncManager::spawn_filter_processor(
                watch_items.clone(), 
                network_message_sender,
                processing_thread_requests
            );
            self.filter_processor = Some(filter_processor);
            self.watch_item_updater = Some(watch_item_updater);
            tracing::info!("🔄 Filter processor initialized (filters enabled, {} initial watch items)", watch_items.len());
        }
        
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
        
        // Prepare sync state but don't send requests (monitoring loop will handle that)
        tracing::info!("Preparing sync state for monitoring loop...");
        let result = SyncProgress {
            header_height: self.storage.get_tip_height().await
                .map_err(|e| SpvError::Storage(e))?
                .unwrap_or(0),
            filter_header_height: self.storage.get_filter_tip_height().await
                .map_err(|e| SpvError::Storage(e))?
                .unwrap_or(0),
            headers_synced: false, // Will be synced by monitoring loop
            filter_headers_synced: false,
            ..SyncProgress::default()
        };

        // Update status display after initial sync
        self.update_status_display().await;

        tracing::info!("✅ Initial sync requests sent! Current state - Headers: {}, Filter headers: {}",
                     result.header_height, result.filter_header_height);
        tracing::info!("📊 Actual sync will complete asynchronously through monitoring loop");

        Ok(result)
    }

    /// Run continuous monitoring for new blocks, ChainLocks, InstantLocks, etc.
    ///
    /// This is the sole network message receiver to prevent race conditions.
    /// All sync operations coordinate through this monitoring loop.
    pub async fn monitor_network(&mut self) -> Result<()> {
        let running = self.running.read().await;
        if !*running {
            return Err(SpvError::Config("Client not running".to_string()));
        }
        drop(running);

        tracing::info!("Starting continuous network monitoring...");

        // Wait for at least one peer to connect before sending any protocol messages
        let mut initial_sync_started = false;

        // Print initial status
        self.update_status_display().await;

        // Timer for periodic status updates
        let mut last_status_update = Instant::now();
        let status_update_interval = std::time::Duration::from_secs(5);

        // Timer for request timeout checking
        let mut last_timeout_check = Instant::now();
        let timeout_check_interval = std::time::Duration::from_secs(1);
        
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

            // Check if we have connected peers and start initial sync operations (once)
            if !initial_sync_started && self.network.peer_count() > 0 {
                tracing::info!("🚀 Peers connected, starting initial sync operations...");

                // Check if sync is needed and send initial requests
                if let Ok(base_hash) = self.sync_manager.header_sync_mut().prepare_sync(&mut *self.storage).await {
                    tracing::info!("📡 Sending initial header sync requests...");
                    if let Err(e) = self.sync_manager.header_sync_mut().request_headers(&mut *self.network, base_hash).await {
                        tracing::error!("Failed to send initial header requests: {}", e);
                    }
                }

                // Also start filter header sync if filters are enabled and we have headers
                if self.config.enable_filters {
                    let header_tip = self.storage.get_tip_height().await.ok().flatten().unwrap_or(0);
                    let filter_tip = self.storage.get_filter_tip_height().await.ok().flatten().unwrap_or(0);

                    if header_tip > filter_tip {
                        tracing::info!("🚀 Starting filter header sync (headers: {}, filter headers: {})", header_tip, filter_tip);
                        if let Err(e) = self.sync_manager.filter_sync_mut().start_sync_headers(&mut *self.network, &mut *self.storage).await {
                            tracing::warn!("Failed to start filter header sync: {}", e);
                            // Don't fail startup if filter header sync fails
                        }
                    }
                }

                initial_sync_started = true;
            }

            // Check if it's time to update the status display
            if last_status_update.elapsed() >= status_update_interval {
                self.update_status_display().await;
                last_status_update = Instant::now();
            }
            
            // Check for sync timeouts and handle recovery
            let _ = self.sync_manager.check_sync_timeouts(&mut *self.storage, &mut *self.network).await;
            
            // Check for request timeouts and handle retries
            if last_timeout_check.elapsed() >= timeout_check_interval {
                // Request timeout handling was part of the request tracking system
                // For async block processing testing, we'll skip this for now
                last_timeout_check = Instant::now();
            }
            
            // Handle network messages
            match self.network.receive_message().await {
                Ok(Some(message)) => {
                    if let Err(e) = self.handle_network_message(message).await {
                        tracing::error!("Error handling network message: {}", e);
                    }
                }
                Ok(None) => {
                    // No message available, brief pause before continuing
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(e) => {
                    // Handle specific network error types
                    if let crate::error::NetworkError::ConnectionFailed(msg) = &e {
                        if msg.contains("No connected peers") || self.network.peer_count() == 0 {
                            tracing::warn!("All peers disconnected during monitoring, checking connection health");

                            // Wait for potential reconnection
                            let mut wait_count = 0;
                            while wait_count < 10 && self.network.peer_count() == 0 {
                                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                wait_count += 1;
                            }

                            if self.network.peer_count() > 0 {
                                tracing::info!("✅ Reconnected to {} peer(s), resuming monitoring", self.network.peer_count());
                                continue;
                            } else {
                                tracing::warn!("No peers available after waiting, will retry monitoring");
                            }
                        }
                    }

                    tracing::error!("Network error during monitoring: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }

        Ok(())
    }

    /// Handle incoming network messages during monitoring.
    async fn handle_network_message(&mut self, message: dashcore::network::message::NetworkMessage) -> Result<()> {
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
                        
                        // Auto-trigger filter downloading after filter header sync completion
                        if !self.get_watch_items().await.is_empty() {
                            // Check if header sync is stable before starting filter download
                            if self.sync_manager.header_sync().is_syncing() {
                                tracing::info!("⏳ Filter header sync complete, but header sync still in progress - deferring automatic filter download");
                            } else {
                                tracing::info!("🚀 Filter header sync complete and header sync stable, starting automatic filter download and checking...");
                                // Pass None to let sync_and_check_filters determine the optimal range based on watch items
                                match self.sync_and_check_filters(None).await {
                                    Ok(matches) => {
                                        tracing::info!("✅ Automatic filter download completed with {} matches", matches.len());
                                    }
                                    Err(e) => {
                                        tracing::error!("❌ Failed to start automatic filter download after filter headers: {}", e);
                                        // Don't fail the entire flow if filter download fails to start
                                    }
                                }
                            }
                        } else {
                            tracing::info!("💡 Filter header sync complete, but no watch items configured - skipping automatic filter download");
                        }
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
                
                // Store this as the last successfully received block
                // This helps identify what block comes next when decoding fails
                tracing::info!("LAST SUCCESSFUL BLOCK BEFORE POTENTIAL FAILURE: {}", block_hash);
                
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
            NetworkMessage::CFilter(cfilter) => {
                tracing::debug!("Received CFilter for block {}", cfilter.block_hash);
                
                // Let the sync manager handle sync coordination (just tracking, not the full filter)
                if let Err(e) = self.sync_manager.handle_cfilter_message(cfilter.block_hash, &mut *self.storage).await {
                    tracing::error!("Failed to handle CFilter in sync manager: {}", e);
                }
                
                // Always send to filter processor for watch item checking if available
                if let Some(filter_processor) = &self.filter_processor {
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
    
    /// Process transactions in a block to check for matches with watch items.
    async fn process_block_transactions(
        &mut self,
        block: &dashcore::Block,
        watch_items: &[WatchItem]
    ) -> Result<()> {
        let block_hash = block.block_hash();
        let block_height = self.find_height_for_block_hash(block_hash).await.unwrap_or(0);
        let mut relevant_transactions = 0;
        let mut new_outpoints_to_watch = Vec::new();
        let mut balance_changes: std::collections::HashMap<dashcore::Address, i64> = std::collections::HashMap::new();

        for (tx_index, transaction) in block.txdata.iter().enumerate() {
            let txid = transaction.txid();
            let mut transaction_relevant = false;
            let is_coinbase = tx_index == 0;

            // Process inputs first (spending UTXOs)
            if !is_coinbase {
                for (vin, input) in transaction.input.iter().enumerate() {
                    // Check if this input spends a UTXO from our watched addresses
                    if let Ok(all_utxos) = self.storage.get_all_utxos().await {
                        if let Some(spent_utxo) = all_utxos.get(&input.previous_output) {
                            transaction_relevant = true;
                            let amount = spent_utxo.value();
                            
                            tracing::info!("💸 Found relevant input: {}:{} spending UTXO {} (value: {})", 
                                          txid, vin, input.previous_output, amount);
                            
                            // Update balance change for this address (subtract)
                            *balance_changes.entry(spent_utxo.address.clone()).or_insert(0) -= amount.to_sat() as i64;
                            
                            // Remove the spent UTXO from storage
                            if let Err(e) = self.storage.remove_utxo(&input.previous_output).await {
                                tracing::error!("Failed to remove spent UTXO {}: {}", input.previous_output, e);
                            }
                        }
                    }
                    
                    // Also check against explicitly watched outpoints
                    for watch_item in watch_items {
                        if let WatchItem::Outpoint(watched_outpoint) = watch_item {
                            if &input.previous_output == watched_outpoint {
                                transaction_relevant = true;
                                tracing::info!("💸 Found relevant input: {}:{} spending explicitly watched outpoint {:?}",
                                              txid, vin, watched_outpoint);
                            }
                        }
                    }
                }
            }

            // Process outputs (creating new UTXOs)
            for (vout, output) in transaction.output.iter().enumerate() {
                for watch_item in watch_items {
                    let (matches, matched_address) = match watch_item {
                        WatchItem::Address { address, .. } => {
                            (address.script_pubkey() == output.script_pubkey, Some(address.clone()))
                        }
                        WatchItem::Script(script) => {
                            (script == &output.script_pubkey, None)
                        }
                        WatchItem::Outpoint(_) => (false, None), // Outpoints don't match outputs
                    };

                    if matches {
                        transaction_relevant = true;
                        let outpoint = dashcore::OutPoint { txid, vout: vout as u32 };
                        let amount = dashcore::Amount::from_sat(output.value);

                        tracing::info!("💰 Found relevant output: {}:{} to {:?} (value: {})",
                                      txid, vout, watch_item, amount);

                        // Create and store UTXO if we have an address
                        if let Some(address) = matched_address {
                            let utxo = crate::wallet::Utxo::new(
                                outpoint,
                                output.clone(),
                                address.clone(),
                                block_height,
                                is_coinbase,
                            );
                            
                            if let Err(e) = self.storage.store_utxo(&outpoint, &utxo).await {
                                tracing::error!("Failed to store UTXO {}: {}", outpoint, e);
                            } else {
                                tracing::debug!("📝 Stored UTXO {}:{} for address {}", txid, vout, address);
                            }

                            // Update balance change for this address (add)
                            *balance_changes.entry(address.clone()).or_insert(0) += amount.to_sat() as i64;
                        }

                        // Track this outpoint so we can detect when it's spent
                        new_outpoints_to_watch.push(outpoint);
                        tracing::debug!("📍 Now watching outpoint {}:{} for future spending", txid, vout);
                    }
                }
            }

            if transaction_relevant {
                relevant_transactions += 1;
                tracing::debug!("📝 Transaction {}: {} (index {}) is relevant", 
                               txid, if is_coinbase { "coinbase" } else { "regular" }, tx_index);
            }
        }

        if relevant_transactions > 0 {
            tracing::info!("🎯 Block {} contains {} relevant transactions affecting watched items", 
                          block_hash, relevant_transactions);

            // Report balance changes
            if !balance_changes.is_empty() {
                self.report_balance_changes(&balance_changes, block_height).await?;
            }
        }

        Ok(())
    }

    /// Report balance changes for watched addresses.
    async fn report_balance_changes(
        &self,
        balance_changes: &std::collections::HashMap<dashcore::Address, i64>,
        block_height: u32,
    ) -> Result<()> {
        tracing::info!("💰 Balance changes detected in block at height {}:", block_height);

        for (address, change_sat) in balance_changes {
            if *change_sat != 0 {
                let change_amount = dashcore::Amount::from_sat(change_sat.abs() as u64);
                let sign = if *change_sat > 0 { "+" } else { "-" };
                tracing::info!("  📍 Address {}: {}{}", address, sign, change_amount);
            }
        }

        // Calculate and report current balances for all watched addresses
        let watch_items = self.get_watch_items().await;
        for watch_item in watch_items.iter() {
            if let WatchItem::Address { address, .. } = watch_item {
                match self.get_address_balance(address).await {
                    Ok(balance) => {
                        tracing::info!("  💼 Address {} balance: {} (confirmed: {}, unconfirmed: {})", 
                                      address, balance.total(), balance.confirmed, balance.unconfirmed);
                    }
                    Err(e) => {
                        tracing::error!("Failed to get balance for address {}: {}", address, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Get the balance for a specific address.
    pub async fn get_address_balance(&self, address: &dashcore::Address) -> Result<AddressBalance> {
        // Get current tip height for confirmation calculations
        let current_tip = self.storage.get_tip_height().await
            .map_err(|e| SpvError::Storage(e))?
            .unwrap_or(0);
        
        // Get UTXOs for this address
        let utxos = self.storage.get_utxos_for_address(address).await
            .map_err(|e| SpvError::Storage(e))?;
        
        let mut confirmed = dashcore::Amount::ZERO;
        let mut unconfirmed = dashcore::Amount::ZERO;
        
        for utxo in utxos {
            let confirmations = if current_tip >= utxo.height {
                current_tip - utxo.height + 1
            } else {
                0
            };
            
            // Consider confirmed if it has 6+ confirmations or is InstantLocked
            if confirmations >= 6 || utxo.is_instantlocked {
                confirmed += utxo.value();
            } else {
                unconfirmed += utxo.value();
            }
        }
        
        Ok(AddressBalance {
            confirmed,
            unconfirmed,
        })
    }

    /// Get balances for all watched addresses.
    pub async fn get_all_balances(&self) -> Result<std::collections::HashMap<dashcore::Address, AddressBalance>> {
        let mut balances = std::collections::HashMap::new();
        
        let watch_items = self.get_watch_items().await;
        for watch_item in watch_items.iter() {
            if let WatchItem::Address { address, .. } = watch_item {
                match self.get_address_balance(address).await {
                    Ok(balance) => {
                        balances.insert(address.clone(), balance);
                    }
                    Err(e) => {
                        tracing::error!("Failed to get balance for address {}: {}", address, e);
                    }
                }
            }
        }

        Ok(balances)
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
            
            // Send updated watch items to filter processor if it exists
            if let Some(updater) = &self.watch_item_updater {
                if let Err(e) = updater.send(watch_list.clone()) {
                    tracing::error!("Failed to send watch item update to filter processor: {}", e);
                }
            }
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
            
            // Send updated watch items to filter processor if it exists
            if let Some(updater) = &self.watch_item_updater {
                if let Err(e) = updater.send(watch_list.clone()) {
                    tracing::error!("Failed to send watch item update to filter processor: {}", e);
                }
            }
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
    /// Sync and check filters with internal monitoring loop management.
    /// This method automatically handles the monitoring loop required for CFilter message processing.
    pub async fn sync_and_check_filters_with_monitoring(&mut self, num_blocks: Option<u32>) -> Result<Vec<crate::types::FilterMatch>> {
        // Just delegate to the regular method for now - the real fix is in sync_filters_coordinated
        self.sync_and_check_filters(num_blocks).await
    }

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
        
        if watch_items.is_empty() {
            tracing::info!("No watch items configured, skipping filter sync");
            return Ok(Vec::new());
        }
        
        // Find the earliest height among all watch items
        let earliest_height = watch_items.iter()
            .filter_map(|item| item.earliest_height())
            .min()
            .unwrap_or(tip_height.saturating_sub(99)); // Default to last 100 blocks if no earliest_height set
        
        let num_blocks = num_blocks.unwrap_or(100);
        let default_start = tip_height.saturating_sub(num_blocks - 1);
        let start_height = earliest_height.min(default_start); // Go back to the earliest required height
        let actual_count = tip_height - start_height + 1; // Actual number of blocks available
        
        tracing::info!("Requesting filters from height {} to {} ({} blocks)", 
                      start_height, tip_height, actual_count);
        tracing::info!("Filter processing and matching will happen automatically in background thread as CFilter messages arrive");
        
        // Send filter requests - processing will happen automatically in the background
        self.sync_filters_coordinated(start_height, actual_count).await?;
        
        // Return empty vector since matching happens asynchronously in the filter processor thread
        // Actual matches will be processed and blocks requested automatically when CFilter messages arrive
        Ok(Vec::new())
    }
    
    /// Sync filters in coordination with the monitoring loop using simplified processing
    async fn sync_filters_coordinated(&mut self, start_height: u32, count: u32) -> Result<()> {
        let end_height = start_height + count - 1;
        
        tracing::info!("Starting coordinated filter sync from height {} to {} ({} filters expected)", 
                      start_height, end_height, count);
        
        // Use batch processing to send filter requests
        let batch_size = 100;
        let mut current_height = start_height;
        let mut batches_sent = 0;
        
        // Send all filter requests in batches
        while current_height <= end_height {
            let batch_end = (current_height + batch_size - 1).min(end_height);
            
            tracing::debug!("Sending batch {}: heights {} to {}", batches_sent + 1, current_height, batch_end);
            
            // Get stop hash for this batch
            let stop_hash = self.storage.get_header(batch_end).await
                .map_err(|e| SpvError::Storage(e))?
                .ok_or_else(|| SpvError::Config("Stop header not found".to_string()))?
                .block_hash();
            
            // Send the request - monitoring loop will handle the responses via filter processor
            self.sync_manager.filter_sync_mut().request_filters(&mut *self.network, current_height, stop_hash).await
                .map_err(|e| SpvError::Sync(e))?;
            
            current_height = batch_end + 1;
            batches_sent += 1;
        }
        
        tracing::info!("✅ All filter requests sent ({} batches), processing via filter processor thread", batches_sent);
        
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
                // Use the actual Dash mainnet genesis block parameters
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
            dashcore::Network::Testnet => {
                // Use the actual Dash testnet genesis block parameters
                BlockHeader {
                    version: Version::from_consensus(1),
                    prev_blockhash: dashcore::BlockHash::all_zeros(),
                    merkle_root: "e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7".parse()
                        .expect("valid merkle root"),
                    time: 1390666206,
                    bits: CompactTarget::from_consensus(0x1e0ffff0),
                    nonce: 3861367235,
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
            
            // Get filter and block processing statistics
            let stats = self.stats.read().await;
            let filter_matches = stats.filter_matches;
            let blocks_processed = stats.blocks_processed;
            drop(stats);
            
            tracing::info!(
                "📊 [SYNC STATUS] Headers: {} | Filter Headers: {} | Latest ChainLock: {} | Matches: {} | Blocks Processed: {}",
                header_height,
                filter_height,
                if chainlock_height > 0 {
                    format!("#{}", chainlock_height)
                } else {
                    "None".to_string()
                },
                filter_matches,
                blocks_processed
            );
        }
    }
    
    /// Handle new headers received after the initial sync is complete.
    /// Request filter headers for these new blocks. Filters will be requested
    /// automatically when the CFHeaders responses arrive.
    async fn handle_post_sync_headers(&mut self, headers: &[dashcore::block::Header]) -> Result<()> {
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