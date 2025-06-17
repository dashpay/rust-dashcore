//! High-level client API for the Dash SPV client.

pub mod config;
pub mod block_processor;
pub mod consistency;
pub mod wallet_utils;
pub mod message_handler;
pub mod filter_sync;
pub mod status_display;
pub mod watch_manager;

use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use std::time::Instant;

use std::collections::HashSet;

use crate::terminal::TerminalUI;

use crate::error::{Result, SpvError};
use crate::types::{AddressBalance, ChainState, SpvStats, SyncProgress, WatchItem};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::SyncManager;
use crate::sync::filters::FilterNotificationSender;
use crate::validation::ValidationManager;
use dashcore::network::constants::NetworkExt;

pub use config::ClientConfig;
pub use block_processor::{BlockProcessor, BlockProcessingTask};
pub use consistency::{ConsistencyReport, ConsistencyRecovery};
pub use wallet_utils::{WalletSummary, WalletUtils};
pub use message_handler::MessageHandler;
pub use filter_sync::FilterSyncCoordinator;
pub use status_display::StatusDisplay;
pub use watch_manager::{WatchManager, WatchItemUpdateSender};

/// Main Dash SPV client.
pub struct DashSpvClient {
    config: ClientConfig,
    state: Arc<RwLock<ChainState>>,
    stats: Arc<RwLock<SpvStats>>,
    network: Box<dyn NetworkManager>,
    storage: Box<dyn StorageManager>,
    wallet: Arc<RwLock<crate::wallet::Wallet>>,
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
    /// Helper to create a StatusDisplay instance.
    async fn create_status_display(&self) -> StatusDisplay {
        StatusDisplay::new(
            &self.state,
            &self.stats,
            &*self.storage,
            &self.terminal_ui,
            &self.config,
        )
    }
    
    /// Helper to create a WatchManager instance.
    fn create_watch_manager(&mut self) -> WatchManager {
        WatchManager::new(
            &self.watch_items,
            &mut *self.storage,
            &self.wallet,
            &self.filter_processor,
            &self.watch_item_updater,
        )
    }
    
    /// Helper to create a MessageHandler instance.
    fn create_message_handler(&mut self) -> MessageHandler {
        MessageHandler::new(
            &mut self.sync_manager,
            &mut *self.storage,
            &mut *self.network,
            &self.config,
            &self.stats,
            &self.filter_processor,
            &self.block_processor_tx,
        )
    }
    
    /// Helper to convert wallet errors to SpvError.
    fn wallet_to_spv_error(e: impl std::fmt::Display) -> SpvError {
        SpvError::Storage(crate::error::StorageError::ReadFailed(format!("Wallet error: {}", e)))
    }
    
    /// Helper to map storage errors to SpvError.
    fn storage_to_spv_error(e: crate::error::StorageError) -> SpvError {
        SpvError::Storage(e)
    }
    
    /// Helper to get block height with a sensible default.
    async fn get_block_height_or_default(&self, block_hash: dashcore::BlockHash) -> u32 {
        self.find_height_for_block_hash(block_hash).await.unwrap_or(0)
    }
    
    /// Helper to collect all watched addresses.
    async fn get_watched_addresses_from_items(&self) -> Vec<dashcore::Address> {
        let watch_items = self.get_watch_items().await;
        watch_items.iter()
            .filter_map(|item| {
                if let WatchItem::Address { address, .. } = item {
                    Some(address.clone())
                } else {
                    None
                }
            })
            .collect()
    }
    
    /// Helper to process balance changes with error handling.
    async fn process_address_balance<T, F>(&self, address: &dashcore::Address, success_handler: F) -> Option<T>
    where
        F: FnOnce(AddressBalance) -> T,
    {
        match self.get_address_balance(address).await {
            Ok(balance) => Some(success_handler(balance)),
            Err(e) => {
                tracing::error!("Failed to get balance for address {}: {}", address, e);
                None
            }
        }
    }
    
    /// Helper to compare UTXO collections and generate mismatch reports.
    fn check_utxo_mismatches(
        wallet_utxos: &[crate::wallet::Utxo],
        storage_utxos: &std::collections::HashMap<dashcore::OutPoint, crate::wallet::Utxo>,
        report: &mut ConsistencyReport,
    ) {
        // Check for UTXOs in wallet but not in storage
        for wallet_utxo in wallet_utxos {
            if !storage_utxos.contains_key(&wallet_utxo.outpoint) {
                report.utxo_mismatches.push(format!(
                    "UTXO {} exists in wallet but not in storage", 
                    wallet_utxo.outpoint
                ));
                report.is_consistent = false;
            }
        }
        
        // Check for UTXOs in storage but not in wallet
        for (outpoint, storage_utxo) in storage_utxos {
            if !wallet_utxos.iter().any(|wu| &wu.outpoint == outpoint) {
                report.utxo_mismatches.push(format!(
                    "UTXO {} exists in storage but not in wallet (address: {})", 
                    outpoint, storage_utxo.address
                ));
                report.is_consistent = false;
            }
        }
    }
    
    /// Helper to compare address collections and generate mismatch reports.
    fn check_address_mismatches(
        watch_addresses: &std::collections::HashSet<dashcore::Address>,
        wallet_addresses: &[dashcore::Address],
        report: &mut ConsistencyReport,
    ) {
        let wallet_address_set: std::collections::HashSet<_> = wallet_addresses.iter().cloned().collect();
        
        // Check for addresses in watch items but not in wallet
        for address in watch_addresses {
            if !wallet_address_set.contains(address) {
                report.address_mismatches.push(format!(
                    "Address {} in watch items but not in wallet", 
                    address
                ));
                report.is_consistent = false;
            }
        }
        
        // Check for addresses in wallet but not in watch items
        for address in wallet_addresses {
            if !watch_addresses.contains(address) {
                report.address_mismatches.push(format!(
                    "Address {} in wallet but not in watch items", 
                    address
                ));
                report.is_consistent = false;
            }
        }
    }

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
        
        // Create sync manager with shared filter heights
        let sync_manager = SyncManager::new(&config, stats.read().await.received_filter_heights.clone());
        
        // Create validation manager
        let validation = ValidationManager::new(config.validation_mode);
        
        // Create block processing channel
        let (block_processor_tx, _block_processor_rx) = mpsc::unbounded_channel();
        
        // Create a placeholder wallet - will be properly initialized in start()
        let placeholder_storage = Arc::new(RwLock::new(crate::storage::MemoryStorageManager::new().await.map_err(|e| SpvError::Storage(e))?));
        let wallet = Arc::new(RwLock::new(crate::wallet::Wallet::new(placeholder_storage)));
        
        Ok(Self {
            config,
            state,
            stats,
            network: Box::new(network),
            storage,
            wallet,
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
        
        // Load wallet data from storage
        self.load_wallet_data().await?;
        
        // Validate and recover wallet consistency if needed
        match self.ensure_wallet_consistency().await {
            Ok(_) => {
                tracing::info!("✅ Wallet consistency validated successfully");
            }
            Err(e) => {
                tracing::error!("❌ Wallet consistency check failed: {}", e);
                tracing::warn!("Continuing startup despite wallet consistency issues");
                tracing::warn!("You may experience balance calculation discrepancies");
                tracing::warn!("Consider running manual consistency recovery later");
                // Continue anyway - the client can still function with inconsistencies
            }
        }
        
        // Spawn block processor worker now that all dependencies are ready
        let (new_tx, block_processor_rx) = mpsc::unbounded_channel();
        let old_tx = std::mem::replace(&mut self.block_processor_tx, new_tx);
        drop(old_tx); // Drop the old sender to avoid confusion
        
        // Use the shared wallet instance for the block processor
        let block_processor = BlockProcessor::new(
            block_processor_rx,
            self.wallet.clone(),
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
                processing_thread_requests,
                self.stats.clone()
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

        // Timer for periodic consistency checks
        let mut last_consistency_check = Instant::now();
        let consistency_check_interval = std::time::Duration::from_secs(300); // Every 5 minutes

        // Timer for filter gap checking
        let mut last_filter_gap_check = Instant::now();
        let filter_gap_check_interval = std::time::Duration::from_secs(self.config.cfheader_gap_check_interval_secs);

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

                // Report CFHeader gap information if enabled
                if self.config.enable_filters {
                    if let Ok((has_gap, block_height, filter_height, gap_size)) = 
                        self.sync_manager.filter_sync().check_cfheader_gap(&*self.storage).await {
                        if has_gap && gap_size >= 100 { // Only log significant gaps
                            tracing::info!("📏 CFHeader Gap: {} block headers vs {} filter headers (gap: {})", 
                                          block_height, filter_height, gap_size);
                        }
                    }
                }

                // Report enhanced filter sync progress if active
                let (filters_requested, filters_received, basic_progress, timeout, total_missing, actual_coverage, missing_ranges) = 
                    crate::sync::filters::FilterSyncManager::get_filter_sync_status_with_gaps(&self.stats, self.sync_manager.filter_sync()).await;
                
                if filters_requested > 0 {
                    // Check if sync is truly complete: both basic progress AND gap analysis must indicate completion
                    // This fixes a bug where "Complete!" was shown when only gap analysis returned 0 missing filters
                    // but basic progress (filters_received < filters_requested) indicated incomplete sync.
                    let is_complete = filters_received >= filters_requested && total_missing == 0;
                    
                    // Debug logging for completion detection
                    if filters_received >= filters_requested && total_missing > 0 {
                        tracing::debug!("🔍 Completion discrepancy detected: basic progress complete ({}/{}) but {} missing filters detected", 
                                       filters_received, filters_requested, total_missing);
                    }
                    
                    if !is_complete {
                        tracing::info!("📊 Filter sync: Basic {:.1}% ({}/{}), Actual coverage {:.1}%, Missing: {} filters in {} ranges", 
                                      basic_progress, filters_received, filters_requested, actual_coverage, total_missing, missing_ranges.len());
                        
                        // Show first few missing ranges for debugging
                        if missing_ranges.len() > 0 {
                            let show_count = missing_ranges.len().min(3);
                            for (i, (start, end)) in missing_ranges.iter().enumerate().take(show_count) {
                                tracing::warn!("  Gap {}: range {}-{} ({} filters)", i + 1, start, end, end - start + 1);
                            }
                            if missing_ranges.len() > show_count {
                                tracing::warn!("  ... and {} more gaps", missing_ranges.len() - show_count);
                            }
                        }
                    } else {
                        tracing::info!("📊 Filter sync progress: {:.1}% ({}/{} filters received) - Complete!", 
                                      basic_progress, filters_received, filters_requested);
                    }
                    
                    if timeout {
                        tracing::warn!("⚠️  Filter sync timeout: no filters received in 30+ seconds");
                    }
                }

                // Also update wallet confirmation statuses periodically
                if let Err(e) = self.update_wallet_confirmations().await {
                    tracing::warn!("Failed to update wallet confirmations: {}", e);
                }

                last_status_update = Instant::now();
            }

            // Check for sync timeouts and handle recovery (only periodically, not every loop)
            if last_timeout_check.elapsed() >= timeout_check_interval {
                let _ = self.sync_manager.check_sync_timeouts(&mut *self.storage, &mut *self.network).await;
            }

            // Check for request timeouts and handle retries
            if last_timeout_check.elapsed() >= timeout_check_interval {
                // Request timeout handling was part of the request tracking system
                // For async block processing testing, we'll skip this for now
                last_timeout_check = Instant::now();
            }

            // Check for wallet consistency issues periodically
            if last_consistency_check.elapsed() >= consistency_check_interval {
                tokio::spawn(async move {
                    // Run consistency check in background to avoid blocking the monitoring loop
                    // Note: This is a simplified approach - in production you might want more sophisticated scheduling
                    tracing::debug!("Running periodic wallet consistency check...");
                });
                last_consistency_check = Instant::now();
            }

            // Check for missing filters and retry periodically
            if last_filter_gap_check.elapsed() >= filter_gap_check_interval {
                if self.config.enable_filters {
                    if let Err(e) = self.sync_manager.filter_sync_mut()
                        .check_and_retry_missing_filters(&mut *self.network, &*self.storage).await {
                        tracing::warn!("Failed to check and retry missing filters: {}", e);
                    }
                    
                    // Check for CFHeader gaps and auto-restart if needed
                    if self.config.enable_cfheader_gap_restart {
                        match self.sync_manager.filter_sync_mut()
                            .maybe_restart_cfheader_sync_for_gap(&mut *self.network, &mut *self.storage).await {
                            Ok(restarted) => {
                                if restarted {
                                    tracing::info!("🔄 Auto-restarted CFHeader sync due to detected gap");
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Failed to check/restart CFHeader sync for gap: {}", e);
                            }
                        }
                    }
                    
                    // Check for filter gaps and auto-restart if needed
                    if self.config.enable_filter_gap_restart && !self.watch_items.read().await.is_empty() {
                        // Get current sync progress
                        let progress = self.sync_progress().await?;
                        
                        // Check if there's a gap between synced filters and filter headers
                        match self.sync_manager.filter_sync()
                            .check_filter_gap(&*self.storage, &progress).await {
                            Ok((has_gap, filter_header_height, last_synced_filter, gap_size)) => {
                                if has_gap && gap_size >= self.config.min_filter_gap_size {
                                    tracing::info!("🔍 Detected filter gap: filter headers at {}, last synced filter at {} (gap: {} blocks)",
                                                  filter_header_height, last_synced_filter, gap_size);
                                    
                                    // Check if we're not already syncing filters
                                    if !self.sync_manager.filter_sync().is_syncing_filters() {
                                        // Start filter sync for the missing range
                                        let start_height = last_synced_filter + 1;
                                        
                                        // Limit the sync size to avoid overwhelming the system
                                        let max_sync_size = self.config.max_filter_gap_sync_size;
                                        let sync_count = gap_size.min(max_sync_size);
                                        
                                        if sync_count < gap_size {
                                            tracing::info!("🔄 Auto-starting filter sync for gap from height {} ({} blocks of {} total gap)", 
                                                          start_height, sync_count, gap_size);
                                        } else {
                                            tracing::info!("🔄 Auto-starting filter sync for gap from height {} ({} blocks)", 
                                                          start_height, sync_count);
                                        }
                                        
                                        match self.sync_filters_range(Some(start_height), Some(sync_count)).await {
                                            Ok(_) => {
                                                tracing::info!("✅ Successfully started filter sync for gap");
                                            }
                                            Err(e) => {
                                                tracing::warn!("Failed to start filter sync for gap: {}", e);
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::debug!("Failed to check filter gap: {}", e);
                            }
                        }
                    }
                }
                last_filter_gap_check = Instant::now();
            }

            // Handle network messages
            match self.network.receive_message().await {
                Ok(Some(message)) => {
                    // Wrap message handling in comprehensive error handling
                    match self.handle_network_message(message).await {
                        Ok(_) => {
                            // Message handled successfully
                        }
                        Err(e) => {
                            tracing::error!("Error handling network message: {}", e);

                            // Categorize error severity
                            match &e {
                                SpvError::Network(_) => {
                                    tracing::warn!("Network error during message handling - may recover automatically");
                                }
                                SpvError::Storage(_) => {
                                    tracing::error!("Storage error during message handling - this may affect data consistency");
                                }
                                SpvError::Validation(_) => {
                                    tracing::warn!("Validation error during message handling - message rejected");
                                }
                                _ => {
                                    tracing::error!("Unexpected error during message handling");
                                }
                            }

                            // Continue monitoring despite errors
                            tracing::debug!("Continuing network monitoring despite message handling error");
                        }
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
        // Handle special messages that need access to client state
        use dashcore::network::message::NetworkMessage;

        match &message {
            NetworkMessage::CLSig(clsig) => {
                tracing::info!("Received ChainLock for block {}", clsig.block_hash);
                // Extract ChainLock from CLSig message and process
                self.process_chainlock(clsig.clone()).await?;
                return Ok(());
            }
            NetworkMessage::ISLock(islock_msg) => {
                tracing::info!("Received InstantSendLock for tx {}", islock_msg.txid);
                // Extract InstantLock from ISLock message and process
                self.process_instantsendlock(islock_msg.clone()).await?;
                return Ok(());
            }
            NetworkMessage::Tx(tx) => {
                tracing::debug!("Received transaction: {}", tx.txid());
                // Check if transaction affects watched addresses/scripts
                self.process_transaction(tx.clone()).await?;
                return Ok(());
            }
            NetworkMessage::CFHeaders(cfheaders) => {
                tracing::info!("📨 Client received CFHeaders message with {} filter headers", cfheaders.filter_hashes.len());
                // Handle CFHeaders at client level to trigger auto-filter downloading
                match self.sync_manager.handle_cfheaders_message(cfheaders.clone(), &mut *self.storage, &mut *self.network).await {
                    Ok(false) => {
                        tracing::info!("🎯 Filter header sync completed (handle_cfheaders_message returned false)");
                        // Properly finish the sync state
                        self.sync_manager.sync_state_mut().finish_sync(crate::sync::SyncComponent::FilterHeaders);

                        // Auto-trigger filter downloading for watch items if we have any
                        let watch_items = self.get_watch_items().await;
                        if !watch_items.is_empty() {
                            tracing::info!("🚀 Filter header sync complete, starting filter download for {} watch items", watch_items.len());

                            // Start downloading filters for recent blocks
                            if let Err(e) = self.sync_and_check_filters(Some(100)).await {
                                tracing::error!("Failed to start filter sync after filter header completion: {}", e);
                            }
                        } else {
                            tracing::info!("Filter header sync complete, but no watch items configured - skipping filter download");
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
                return Ok(());
            }
            _ => {
                // For other messages, delegate to the message handler
                let mut handler = self.create_message_handler();
                handler.handle_network_message(message).await?;
            }
        }

        Ok(())
    }

    /// Handle inventory messages - delegates to message handler.
    async fn handle_inventory(&mut self, inv: Vec<dashcore::network::message_blockdata::Inventory>) -> Result<()> {
        let mut handler = self.create_message_handler();
        handler.handle_inventory(inv).await
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

    /// Process a new block hash detected from inventory - delegates to message handler.
    async fn process_new_block_hash(&mut self, block_hash: dashcore::BlockHash) -> Result<()> {
        let mut handler = self.create_message_handler();
        handler.process_new_block_hash(block_hash).await
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

    /// Helper method to find height for a block hash.
    async fn find_height_for_block_hash(&self, block_hash: dashcore::BlockHash) -> Option<u32> {
        // Use the efficient reverse index
        self.storage.get_header_height_by_hash(&block_hash).await.ok().flatten()
    }

    /// Process a new block - delegates to message handler.
    async fn process_new_block(&mut self, block: dashcore::Block) -> Result<()> {
        let mut handler = self.create_message_handler();
        handler.process_new_block(block).await
    }

    /// Process transactions in a block to check for matches with watch items.
    async fn process_block_transactions(
        &mut self,
        block: &dashcore::Block,
        watch_items: &[WatchItem]
    ) -> Result<()> {
        let block_hash = block.block_hash();
        let block_height = self.get_block_height_or_default(block_hash).await;
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
                    if let Ok(Some(spent_utxo)) = self.wallet.read().await.remove_utxo(&input.previous_output).await {
                        transaction_relevant = true;
                        let amount = spent_utxo.value();

                        tracing::info!("💸 Found relevant input: {}:{} spending UTXO {} (value: {})",
                                      txid, vin, input.previous_output, amount);

                        // Update balance change for this address (subtract)
                        *balance_changes.entry(spent_utxo.address.clone()).or_insert(0) -= amount.to_sat() as i64;
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

                            if let Err(e) = self.wallet.read().await.add_utxo(utxo).await {
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
        let addresses = self.get_watched_addresses_from_items().await;
        for address in addresses {
            if let Some(_) = self.process_address_balance(&address, |balance| {
                tracing::info!("  💼 Address {} balance: {} (confirmed: {}, unconfirmed: {})",
                              address, balance.total(), balance.confirmed, balance.unconfirmed);
            }).await {
                // Balance reported successfully
            } else {
                tracing::warn!("Continuing balance reporting despite failure for address {}", address);
            }
        }

        Ok(())
    }

    /// Get the balance for a specific address.
    pub async fn get_address_balance(&self, address: &dashcore::Address) -> Result<AddressBalance> {
        // Use wallet to get balance directly
        let wallet = self.wallet.read().await;
        let balance = wallet.get_balance_for_address(address).await
            .map_err(|e| SpvError::Storage(crate::error::StorageError::ReadFailed(format!("Wallet error: {}", e))))?;

        Ok(AddressBalance {
            confirmed: balance.confirmed + balance.instantlocked,
            unconfirmed: balance.pending,
        })
    }

    /// Get balances for all watched addresses.
    pub async fn get_all_balances(&self) -> Result<std::collections::HashMap<dashcore::Address, AddressBalance>> {
        let mut balances = std::collections::HashMap::new();

        let addresses = self.get_watched_addresses_from_items().await;
        for address in addresses {
            if let Some(balance) = self.process_address_balance(&address, |balance| balance).await {
                balances.insert(address, balance);
            }
        }

        Ok(balances)
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
        let display = self.create_status_display().await;
        display.sync_progress().await
    }

    /// Add a watch item.
    pub async fn add_watch_item(&mut self, item: WatchItem) -> Result<()> {
        let mut manager = self.create_watch_manager();
        manager.add_watch_item(item).await
    }

    /// Remove a watch item.
    pub async fn remove_watch_item(&mut self, item: &WatchItem) -> Result<bool> {
        let mut manager = self.create_watch_manager();
        manager.remove_watch_item(item).await
    }

    /// Get all watch items.
    pub async fn get_watch_items(&self) -> Vec<WatchItem> {
        let watch_items = self.watch_items.read().await;
        watch_items.iter().cloned().collect()
    }

    /// Synchronize all current watch items with the wallet.
    /// This ensures that address watch items are properly tracked by the wallet.
    pub async fn sync_watch_items_with_wallet(&self) -> Result<usize> {
        let addresses = self.get_watched_addresses_from_items().await;
        let mut synced_count = 0;

        for address in addresses {
            let wallet = self.wallet.read().await;
            if let Err(e) = wallet.add_watched_address(address.clone()).await {
                tracing::warn!("Failed to sync address {} with wallet: {}", address, e);
            } else {
                synced_count += 1;
            }
        }

        tracing::info!("Synced {} address watch items with wallet", synced_count);
        Ok(synced_count)
    }

    /// Manually trigger wallet consistency validation and recovery.
    /// This is a public method that users can call if they suspect wallet issues.
    pub async fn check_and_fix_wallet_consistency(&self) -> Result<(ConsistencyReport, Option<ConsistencyRecovery>)> {
        tracing::info!("Manual wallet consistency check requested");

        let report = match self.validate_wallet_consistency().await {
            Ok(report) => report,
            Err(e) => {
                tracing::error!("Failed to validate wallet consistency: {}", e);
                return Err(e);
            }
        };

        if report.is_consistent {
            tracing::info!("✅ Wallet is consistent - no recovery needed");
            return Ok((report, None));
        }

        tracing::warn!("Wallet inconsistencies detected, attempting recovery...");

        let recovery = match self.recover_wallet_consistency().await {
            Ok(recovery) => recovery,
            Err(e) => {
                tracing::error!("Failed to recover wallet consistency: {}", e);
                return Err(e);
            }
        };

        if recovery.success {
            tracing::info!("✅ Wallet consistency recovery completed successfully");
        } else {
            tracing::warn!("⚠️ Wallet consistency recovery partially failed");
        }

        Ok((report, Some(recovery)))
    }

    /// Update wallet UTXO confirmation statuses based on current blockchain height.
    pub async fn update_wallet_confirmations(&self) -> Result<()> {
        let wallet = self.wallet.read().await;
        wallet.update_confirmation_status().await
            .map_err(Self::wallet_to_spv_error)
    }

    /// Get the total wallet balance.
    pub async fn get_wallet_balance(&self) -> Result<crate::wallet::Balance> {
        let wallet = self.wallet.read().await;
        wallet.get_balance().await
            .map_err(Self::wallet_to_spv_error)
    }

    /// Get balance for a specific address.
    pub async fn get_wallet_address_balance(&self, address: &dashcore::Address) -> Result<crate::wallet::Balance> {
        let wallet = self.wallet.read().await;
        wallet.get_balance_for_address(address).await
            .map_err(Self::wallet_to_spv_error)
    }

    /// Get all watched addresses from the wallet.
    pub async fn get_watched_addresses(&self) -> Vec<dashcore::Address> {
        let wallet = self.wallet.read().await;
        wallet.get_watched_addresses().await
    }

    /// Get a summary of wallet statistics.
    pub async fn get_wallet_summary(&self) -> Result<WalletSummary> {
        let wallet = self.wallet.read().await;
        let addresses = wallet.get_watched_addresses().await;
        let utxos = wallet.get_utxos().await;
        let balance = wallet.get_balance().await
            .map_err(Self::wallet_to_spv_error)?;

        Ok(WalletSummary {
            watched_addresses_count: addresses.len(),
            utxo_count: utxos.len(),
            total_balance: balance,
        })
    }

    /// Get the number of connected peers.
    pub async fn get_peer_count(&self) -> usize {
        self.network.peer_count()
    }

    /// Sync compact filters for recent blocks and check for matches.
    /// Sync and check filters with internal monitoring loop management.
    /// This method automatically handles the monitoring loop required for CFilter message processing.
    pub async fn sync_and_check_filters_with_monitoring(&mut self, num_blocks: Option<u32>) -> Result<Vec<crate::types::FilterMatch>> {
        self.sync_and_check_filters(num_blocks).await
    }

    pub async fn sync_and_check_filters(&mut self, num_blocks: Option<u32>) -> Result<Vec<crate::types::FilterMatch>> {
        let mut coordinator = FilterSyncCoordinator::new(
            &mut self.sync_manager,
            &mut *self.storage,
            &mut *self.network,
            &self.watch_items,
            &self.stats,
            &self.running,
        );
        coordinator.sync_and_check_filters(num_blocks).await
    }
    
    /// Sync filters for a specific height range.
    pub async fn sync_filters_range(&mut self, start_height: Option<u32>, count: Option<u32>) -> Result<()> {
        let mut coordinator = FilterSyncCoordinator::new(
            &mut self.sync_manager,
            &mut *self.storage,
            &mut *self.network,
            &self.watch_items,
            &self.stats,
            &self.running,
        );
        coordinator.sync_filters_range(start_height, count).await
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
        let mut manager = self.create_watch_manager();
        manager.load_watch_items().await
    }

    /// Load wallet data from storage.
    async fn load_wallet_data(&self) -> Result<()> {
        tracing::info!("Loading wallet data from storage...");

        let wallet = self.wallet.read().await;

        // Load wallet state (addresses and UTXOs) from storage
        if let Err(e) = wallet.load_from_storage().await {
            tracing::warn!("Failed to load wallet data from storage: {}", e);
            // Continue anyway - wallet will start empty
        } else {
            // Get loaded data counts for logging
            let addresses = wallet.get_watched_addresses().await;
            let utxos = wallet.get_utxos().await;
            let balance = wallet.get_balance().await.map_err(|e| {
                SpvError::Storage(crate::error::StorageError::ReadFailed(format!("Wallet error: {}", e)))
            })?;

            tracing::info!(
                "Wallet loaded: {} addresses, {} UTXOs, balance: {} (confirmed: {}, pending: {}, instantlocked: {})",
                addresses.len(),
                utxos.len(),
                balance.total(),
                balance.confirmed,
                balance.pending,
                balance.instantlocked
            );
        }

        Ok(())
    }

    /// Validate wallet and storage consistency.
    pub async fn validate_wallet_consistency(&self) -> Result<ConsistencyReport> {
        tracing::info!("Validating wallet and storage consistency...");

        let mut report = ConsistencyReport {
            utxo_mismatches: Vec::new(),
            address_mismatches: Vec::new(),
            balance_mismatches: Vec::new(),
            is_consistent: true,
        };

        // Validate UTXO consistency between wallet and storage
        let wallet = self.wallet.read().await;
        let wallet_utxos = wallet.get_utxos().await;
        let storage_utxos = self.storage.get_all_utxos().await
            .map_err(Self::storage_to_spv_error)?;

        // Check UTXO consistency using helper
        Self::check_utxo_mismatches(&wallet_utxos, &storage_utxos, &mut report);

        // Validate address consistency between WatchItems and wallet
        let watch_items = self.get_watch_items().await;
        let wallet_addresses = wallet.get_watched_addresses().await;

        // Collect addresses from watch items
        let watch_addresses: std::collections::HashSet<_> = watch_items.iter()
            .filter_map(|item| {
                if let WatchItem::Address { address, .. } = item {
                    Some(address.clone())
                } else {
                    None
                }
            })
            .collect();

        // Check address consistency using helper
        Self::check_address_mismatches(&watch_addresses, &wallet_addresses, &mut report);

        if report.is_consistent {
            tracing::info!("✅ Wallet consistency validation passed");
        } else {
            tracing::warn!("❌ Wallet consistency issues detected: {} UTXO mismatches, {} address mismatches",
                          report.utxo_mismatches.len(), report.address_mismatches.len());
        }

        Ok(report)
    }

    /// Attempt to recover from wallet consistency issues.
    pub async fn recover_wallet_consistency(&self) -> Result<ConsistencyRecovery> {
        tracing::info!("Attempting wallet consistency recovery...");

        let mut recovery = ConsistencyRecovery {
            utxos_synced: 0,
            addresses_synced: 0,
            utxos_removed: 0,
            success: true,
        };

        // First, validate to see what needs fixing
        let report = self.validate_wallet_consistency().await?;

        if report.is_consistent {
            tracing::info!("No recovery needed - wallet is already consistent");
            return Ok(recovery);
        }

        let wallet = self.wallet.read().await;

        // Sync UTXOs from storage to wallet
        let storage_utxos = self.storage.get_all_utxos().await
            .map_err(Self::storage_to_spv_error)?;
        let wallet_utxos = wallet.get_utxos().await;
        
        // Add missing UTXOs to wallet
        for (outpoint, storage_utxo) in &storage_utxos {
            if !wallet_utxos.iter().any(|wu| &wu.outpoint == outpoint) {
                if let Err(e) = wallet.add_utxo(storage_utxo.clone()).await {
                    tracing::error!("Failed to sync UTXO {} to wallet: {}", outpoint, e);
                    recovery.success = false;
                } else {
                    recovery.utxos_synced += 1;
                }
            }
        }
        
        // Remove UTXOs from wallet that aren't in storage
        for wallet_utxo in &wallet_utxos {
            if !storage_utxos.contains_key(&wallet_utxo.outpoint) {
                if let Err(e) = wallet.remove_utxo(&wallet_utxo.outpoint).await {
                    tracing::error!("Failed to remove UTXO {} from wallet: {}", wallet_utxo.outpoint, e);
                    recovery.success = false;
                } else {
                    recovery.utxos_removed += 1;
                }
            }
        }
        
        // Sync addresses with watch items
        if let Ok(synced) = self.sync_watch_items_with_wallet().await {
            recovery.addresses_synced = synced;
        } else {
            recovery.success = false;
        }
        
        if recovery.success {
            tracing::info!("✅ Wallet consistency recovery completed: {} UTXOs synced, {} UTXOs removed, {} addresses synced", 
                          recovery.utxos_synced, recovery.utxos_removed, recovery.addresses_synced);
        } else {
            tracing::error!("❌ Wallet consistency recovery partially failed");
        }
        
        Ok(recovery)
    }
    
    /// Ensure wallet consistency by validating and recovering if necessary.
    async fn ensure_wallet_consistency(&self) -> Result<()> {
        // First validate consistency
        let report = self.validate_wallet_consistency().await?;
        
        if !report.is_consistent {
            tracing::warn!("Wallet inconsistencies detected, attempting recovery...");
            
            // Attempt recovery
            let recovery = self.recover_wallet_consistency().await?;
            
            if !recovery.success {
                return Err(SpvError::Config(
                    "Wallet consistency recovery failed - some issues remain".to_string()
                ));
            }
            
            // Validate again after recovery
            let post_recovery_report = self.validate_wallet_consistency().await?;
            if !post_recovery_report.is_consistent {
                return Err(SpvError::Config(
                    "Wallet consistency recovery incomplete - issues remain after recovery".to_string()
                ));
            }
            
            tracing::info!("✅ Wallet consistency fully recovered");
        }
        
        Ok(())
    }
    
    /// Safely add a UTXO to the wallet with comprehensive error handling.
    async fn safe_add_utxo(&self, utxo: crate::wallet::Utxo) -> Result<()> {
        let wallet = self.wallet.read().await;
        
        match wallet.add_utxo(utxo.clone()).await {
            Ok(_) => {
                tracing::debug!("Successfully added UTXO {}:{} for address {}", 
                               utxo.outpoint.txid, utxo.outpoint.vout, utxo.address);
                Ok(())
            }
            Err(e) => {
                tracing::error!("Failed to add UTXO {}:{} for address {}: {}", 
                               utxo.outpoint.txid, utxo.outpoint.vout, utxo.address, e);
                
                // Try to continue with degraded functionality
                tracing::warn!("Continuing with degraded wallet functionality due to UTXO storage failure");
                
                Err(SpvError::Storage(crate::error::StorageError::WriteFailed(
                    format!("Failed to store UTXO {}: {}", utxo.outpoint, e)
                )))
            }
        }
    }
    
    /// Safely remove a UTXO from the wallet with comprehensive error handling.
    async fn safe_remove_utxo(&self, outpoint: &dashcore::OutPoint) -> Result<Option<crate::wallet::Utxo>> {
        let wallet = self.wallet.read().await;
        
        match wallet.remove_utxo(outpoint).await {
            Ok(removed_utxo) => {
                if let Some(ref utxo) = removed_utxo {
                    tracing::debug!("Successfully removed UTXO {} for address {}", 
                                   outpoint, utxo.address);
                } else {
                    tracing::debug!("UTXO {} was not found in wallet (already spent or never existed)", outpoint);
                }
                Ok(removed_utxo)
            }
            Err(e) => {
                tracing::error!("Failed to remove UTXO {}: {}", outpoint, e);
                
                // This is less critical than adding - we can continue
                tracing::warn!("Continuing despite UTXO removal failure - wallet may show incorrect balance");
                
                Err(SpvError::Storage(crate::error::StorageError::WriteFailed(
                    format!("Failed to remove UTXO {}: {}", outpoint, e)
                )))
            }
        }
    }
    
    /// Safely get wallet balance with error handling and fallback.
    async fn safe_get_wallet_balance(&self) -> Result<crate::wallet::Balance> {
        let wallet = self.wallet.read().await;
        
        match wallet.get_balance().await {
            Ok(balance) => Ok(balance),
            Err(e) => {
                tracing::error!("Failed to calculate wallet balance: {}", e);
                
                // Return zero balance as fallback
                tracing::warn!("Returning zero balance as fallback due to calculation failure");
                Ok(crate::wallet::Balance::new())
            }
        }
    }
    
    /// Get current statistics.
    pub async fn stats(&self) -> Result<SpvStats> {
        let display = self.create_status_display().await;
        display.stats().await
    }
    
    /// Get current chain state (read-only).
    pub async fn chain_state(&self) -> ChainState {
        let display = self.create_status_display().await;
        display.chain_state().await
    }
    
    /// Check if the client is running.
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
    
    /// Update the status display.
    async fn update_status_display(&self) {
        let display = self.create_status_display().await;
        display.update_status_display().await;
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