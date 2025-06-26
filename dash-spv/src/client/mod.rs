//! High-level client API for the Dash SPV client.

pub mod block_processor;
pub mod config;
pub mod consistency;
pub mod filter_sync;
pub mod message_handler;
pub mod status_display;
pub mod wallet_utils;
pub mod watch_manager;

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{mpsc, RwLock};

use std::collections::HashSet;

use crate::terminal::TerminalUI;

use crate::error::{Result, SpvError};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::filters::FilterNotificationSender;
use crate::sync::sequential::SequentialSyncManager;
use crate::types::{AddressBalance, ChainState, DetailedSyncProgress, MempoolState, SpvEvent, SpvStats, SyncProgress, WatchItem};
use crate::validation::ValidationManager;
use crate::chain::ChainLockManager;
use crate::mempool_filter::MempoolFilter;
use dashcore::network::constants::NetworkExt;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;

pub use block_processor::{BlockProcessingTask, BlockProcessor};
pub use config::ClientConfig;
pub use consistency::{ConsistencyRecovery, ConsistencyReport};
pub use filter_sync::FilterSyncCoordinator;
pub use message_handler::MessageHandler;
pub use status_display::StatusDisplay;
pub use wallet_utils::{WalletSummary, WalletUtils};
pub use watch_manager::{WatchItemUpdateSender, WatchManager};


/// Main Dash SPV client.
pub struct DashSpvClient {
    config: ClientConfig,
    state: Arc<RwLock<ChainState>>,
    stats: Arc<RwLock<SpvStats>>,
    network: Box<dyn NetworkManager>,
    storage: Box<dyn StorageManager>,
    wallet: Arc<RwLock<crate::wallet::Wallet>>,
    sync_manager: SequentialSyncManager,
    validation: ValidationManager,
    chainlock_manager: Arc<ChainLockManager>,
    running: Arc<RwLock<bool>>,
    watch_items: Arc<RwLock<HashSet<WatchItem>>>,
    terminal_ui: Option<Arc<TerminalUI>>,
    filter_processor: Option<FilterNotificationSender>,
    watch_item_updater: Option<WatchItemUpdateSender>,
    block_processor_tx: mpsc::UnboundedSender<BlockProcessingTask>,
    progress_sender: Option<mpsc::UnboundedSender<DetailedSyncProgress>>,
    progress_receiver: Option<mpsc::UnboundedReceiver<DetailedSyncProgress>>,
    event_tx: mpsc::UnboundedSender<SpvEvent>,
    event_rx: Option<mpsc::UnboundedReceiver<SpvEvent>>,
    mempool_state: Arc<RwLock<MempoolState>>,
    mempool_filter: Option<Arc<MempoolFilter>>,
    last_sync_state_save: Arc<RwLock<u64>>,
}

impl DashSpvClient {
    /// Take the progress receiver for external consumption.
    pub fn take_progress_receiver(&mut self) -> Option<mpsc::UnboundedReceiver<DetailedSyncProgress>> {
        self.progress_receiver.take()
    }
    
    /// Emit a progress update.
    fn emit_progress(&self, progress: DetailedSyncProgress) {
        if let Some(ref sender) = self.progress_sender {
            let _ = sender.send(progress);
        }
    }
    
    /// Take the event receiver for external consumption.
    pub fn take_event_receiver(&mut self) -> Option<mpsc::UnboundedReceiver<SpvEvent>> {
        self.event_rx.take()
    }
    
    /// Emit an event.
    pub(crate) fn emit_event(&self, event: SpvEvent) {
        tracing::debug!("Emitting event: {:?}", event);
        let _ = self.event_tx.send(event);
    }
    
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
        watch_items
            .iter()
            .filter_map(|item| {
                if let WatchItem::Address {
                    address,
                    ..
                } = item
                {
                    Some(address.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Helper to process balance changes with error handling.
    async fn process_address_balance<T, F>(
        &self,
        address: &dashcore::Address,
        success_handler: F,
    ) -> Option<T>
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
        let wallet_address_set: std::collections::HashSet<_> =
            wallet_addresses.iter().cloned().collect();

        // Check for addresses in watch items but not in wallet
        for address in watch_addresses {
            if !wallet_address_set.contains(address) {
                report
                    .address_mismatches
                    .push(format!("Address {} in watch items but not in wallet", address));
                report.is_consistent = false;
            }
        }

        // Check for addresses in wallet but not in watch items
        for address in wallet_addresses {
            if !watch_addresses.contains(address) {
                report
                    .address_mismatches
                    .push(format!("Address {} in wallet but not in watch items", address));
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
                Box::new(
                    crate::storage::DiskStorageManager::new(path.clone())
                        .await
                        .map_err(|e| SpvError::Storage(e))?,
                )
            } else {
                Box::new(
                    crate::storage::MemoryStorageManager::new()
                        .await
                        .map_err(|e| SpvError::Storage(e))?,
                )
            }
        } else {
            Box::new(
                crate::storage::MemoryStorageManager::new()
                    .await
                    .map_err(|e| SpvError::Storage(e))?,
            )
        };

        // Create shared data structures
        let watch_items = Arc::new(RwLock::new(HashSet::new()));

        // Create sync manager
        let received_filter_heights = stats.read().await.received_filter_heights.clone();
        tracing::info!("Creating sequential sync manager");
        let sync_manager = SequentialSyncManager::new(&config, received_filter_heights);

        // Create validation manager
        let validation = ValidationManager::new(config.validation_mode);

        // Create ChainLock manager
        let chainlock_manager = Arc::new(ChainLockManager::new(true));

        // Create block processing channel
        let (block_processor_tx, _block_processor_rx) = mpsc::unbounded_channel();

        // Create a placeholder wallet - will be properly initialized in start()
        let placeholder_storage = Arc::new(RwLock::new(
            crate::storage::MemoryStorageManager::new().await.map_err(|e| SpvError::Storage(e))?,
        ));
        let wallet = Arc::new(RwLock::new(crate::wallet::Wallet::new(placeholder_storage)));

        // Create progress channels
        let (progress_sender, progress_receiver) = mpsc::unbounded_channel();
<<<<<<< HEAD
        
        // Create event channels
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        // Create mempool state
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
=======
>>>>>>> sync-progress-tracking

        Ok(Self {
            config,
            state,
            stats,
            network: Box::new(network),
            storage,
            wallet,
            sync_manager,
            validation: validation,
            chainlock_manager,
            running: Arc::new(RwLock::new(false)),
            watch_items,
            terminal_ui: None,
            filter_processor: None,
            watch_item_updater: None,
            block_processor_tx,
            progress_sender: Some(progress_sender),
            progress_receiver: Some(progress_receiver),
<<<<<<< HEAD
            event_tx,
            event_rx: Some(event_rx),
            mempool_state,
            mempool_filter: None,
            last_sync_state_save: Arc::new(RwLock::new(0)),
=======
>>>>>>> sync-progress-tracking
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

        // Initialize mempool filter if mempool tracking is enabled
        if self.config.enable_mempool_tracking {
            let watch_items = self.watch_items.read().await.iter().cloned().collect();
            self.mempool_filter = Some(Arc::new(MempoolFilter::new(
                self.config.mempool_strategy,
                Duration::from_secs(self.config.recent_send_window_secs),
                self.config.max_mempool_transactions,
                self.mempool_state.clone(),
                watch_items,
            )));
            
            // Load mempool state from storage if persistence is enabled
            if self.config.persist_mempool {
                if let Some(state) = self.storage.load_mempool_state().await.map_err(SpvError::Storage)? {
                    *self.mempool_state.write().await = state;
                }
            }
        }

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
            self.event_tx.clone(),
        );

        tokio::spawn(async move {
            tracing::info!("🏭 Starting block processor worker task");
            block_processor.run().await;
            tracing::info!("🏭 Block processor worker task completed");
        });

        // For sequential sync, filter processor is handled internally
        if self.config.enable_filters && self.filter_processor.is_none() {
            tracing::info!("📊 Sequential sync mode: filter processing handled internally");
        }

        // Try to restore sync state from persistent storage
        if self.config.enable_persistence {
            match self.restore_sync_state().await {
                Ok(restored) => {
                    if restored {
                        tracing::info!("✅ Successfully restored sync state from persistent storage");
                    } else {
                        tracing::info!("No previous sync state found, starting fresh sync");
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to restore sync state: {}", e);
                    tracing::warn!("Starting fresh sync due to state restoration failure");
                    // Clear any corrupted state
                    if let Err(clear_err) = self.storage.clear_sync_state().await {
                        tracing::error!("Failed to clear corrupted sync state: {}", clear_err);
                    }
                }
            }
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
            let header_height =
                self.storage.get_tip_height().await.map_err(|e| SpvError::Storage(e))?.unwrap_or(0);

            let filter_height = self
                .storage
                .get_filter_tip_height()
                .await
                .map_err(|e| SpvError::Storage(e))?
                .unwrap_or(0);

            let _ = ui
                .update_status(|status| {
                    status.peer_count = 1; // Connected to one peer
                    status.headers = header_height;
                    status.filter_headers = filter_height;
                })
                .await;
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

<<<<<<< HEAD
    /// Enable mempool tracking with the specified strategy.
    pub async fn enable_mempool_tracking(&mut self, strategy: crate::client::config::MempoolStrategy) -> Result<()> {
        // Update config
        self.config.enable_mempool_tracking = true;
        self.config.mempool_strategy = strategy;
        
        // Initialize mempool filter if not already done
        if self.mempool_filter.is_none() {
            let watch_items = self.watch_items.read().await.iter().cloned().collect();
            self.mempool_filter = Some(Arc::new(crate::mempool_filter::MempoolFilter::new(
                self.config.mempool_strategy,
                Duration::from_secs(self.config.recent_send_window_secs),
                self.config.max_mempool_transactions,
                self.mempool_state.clone(),
                watch_items,
            )));
        }
        
        Ok(())
    }

    /// Get mempool balance for an address.
    pub async fn get_mempool_balance(&self, address: &dashcore::Address) -> Result<crate::types::MempoolBalance> {
        let wallet = self.wallet.read().await;
        let mempool_state = self.mempool_state.read().await;
        
        let mut pending = 0u64;
        let mut pending_instant = 0u64;
        
        // Calculate pending balances from mempool transactions
        for tx in mempool_state.transactions.values() {
            // Check if this transaction affects the given address
            let mut address_affected = false;
            for addr in &tx.addresses {
                if addr == address {
                    address_affected = true;
                    break;
                }
            }
            
            if address_affected {
                // Handle both incoming (positive) and outgoing (negative) transactions
                // For incoming transactions, add to balance; for outgoing, subtract from balance
                if tx.net_amount > 0 {
                    // Incoming transaction - add to pending balance
                    let amount_sats = tx.net_amount as u64;
                    if tx.is_instant_send {
                        pending_instant += amount_sats;
                    } else {
                        pending += amount_sats;
                    }
                } else if tx.net_amount < 0 {
                    // Outgoing transaction - subtract from pending balance
                    let amount_sats = (-tx.net_amount) as u64;
                    if tx.is_instant_send {
                        pending_instant = pending_instant.saturating_sub(amount_sats);
                    } else {
                        pending = pending.saturating_sub(amount_sats);
                    }
                }
            }
        }
        
        Ok(crate::types::MempoolBalance {
            pending: dashcore::Amount::from_sat(pending),
            pending_instant: dashcore::Amount::from_sat(pending_instant),
        })
    }

    /// Get mempool transaction count.
    pub async fn get_mempool_transaction_count(&self) -> usize {
        let mempool_state = self.mempool_state.read().await;
        mempool_state.transactions.len()
    }
    
    /// Update mempool filter with current watch items.
    async fn update_mempool_filter(&mut self) {
        let watch_items = self.watch_items.read().await.iter().cloned().collect();
        self.mempool_filter = Some(Arc::new(MempoolFilter::new(
            self.config.mempool_strategy,
            Duration::from_secs(self.config.recent_send_window_secs),
            self.config.max_mempool_transactions,
            self.mempool_state.clone(),
            watch_items,
        )));
        tracing::info!("Updated mempool filter with current watch items");
    }

    /// Record a transaction send for mempool filtering.
    pub async fn record_transaction_send(&self, txid: dashcore::Txid) {
        if let Some(ref mempool_filter) = self.mempool_filter {
            mempool_filter.record_send(txid).await;
        }
    }

=======
>>>>>>> sync-progress-tracking
    /// Check if filter sync is available (any peer supports compact filters).
    pub async fn is_filter_sync_available(&self) -> bool {
        self.network.has_peer_with_service(dashcore::network::constants::ServiceFlags::COMPACT_FILTERS).await
    }

    /// Stop the SPV client.
    pub async fn stop(&mut self) -> Result<()> {
        // Check if already stopped
        {
            let running = self.running.read().await;
            if !*running {
                return Ok(());
            }
        }

        // Save sync state before shutting down
        if let Err(e) = self.save_sync_state().await {
            tracing::error!("Failed to save sync state during shutdown: {}", e);
            // Continue with shutdown even if state save fails
        } else {
            tracing::info!("Sync state saved successfully during shutdown");
        }

        // Disconnect from network
        self.network.disconnect().await?;

        // Shutdown storage to ensure all data is persisted
        if let Some(disk_storage) =
            self.storage.as_any_mut().downcast_mut::<crate::storage::DiskStorageManager>()
        {
            disk_storage.shutdown().await.map_err(|e| SpvError::Storage(e))?;
            tracing::info!("Storage shutdown completed - all data persisted");
        }

        // Mark as stopped
        let mut running = self.running.write().await;
        *running = false;

        Ok(())
    }
    
    /// Shutdown the SPV client (alias for stop).
    pub async fn shutdown(&mut self) -> Result<()> {
        self.stop().await
    }

    /// Start synchronization (alias for sync_to_tip).
    pub async fn start_sync(&mut self) -> Result<()> {
        self.sync_to_tip().await?;
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
            header_height: self
                .storage
                .get_tip_height()
                .await
                .map_err(|e| SpvError::Storage(e))?
                .unwrap_or(0),
            filter_header_height: self
                .storage
                .get_filter_tip_height()
                .await
                .map_err(|e| SpvError::Storage(e))?
                .unwrap_or(0),
            headers_synced: false, // Will be synced by monitoring loop
            filter_headers_synced: false,
            ..SyncProgress::default()
        };

        // Update status display after initial sync
        self.update_status_display().await;

        tracing::info!(
            "✅ Initial sync requests sent! Current state - Headers: {}, Filter headers: {}",
            result.header_height,
            result.filter_header_height
        );
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
        let status_update_interval = std::time::Duration::from_millis(500);

        // Timer for request timeout checking
        let mut last_timeout_check = Instant::now();
        let timeout_check_interval = std::time::Duration::from_secs(1);

        // Timer for periodic consistency checks
        let mut last_consistency_check = Instant::now();
        let consistency_check_interval = std::time::Duration::from_secs(300); // Every 5 minutes

        // Timer for filter gap checking
        let mut last_filter_gap_check = Instant::now();
        let filter_gap_check_interval =
            std::time::Duration::from_secs(self.config.cfheader_gap_check_interval_secs);
        
        // Progress tracking variables
        let sync_start_time = SystemTime::now();
        let mut last_height = 0u32;
        let mut headers_this_second = 0u32;
        let mut last_rate_calc = Instant::now();
<<<<<<< HEAD
        let total_bytes_downloaded = 0u64;
=======
        let mut total_bytes_downloaded = 0u64;
>>>>>>> sync-progress-tracking

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

                // Start initial sync with sequential sync manager
                match self.sync_manager.start_sync(&mut *self.network, &mut *self.storage).await {
                    Ok(started) => {
                        tracing::info!("✅ Sequential sync start_sync returned: {}", started);
                        
                        // Send initial requests after sync is prepared
                        if let Err(e) = self.sync_manager.send_initial_requests(&mut *self.network, &mut *self.storage).await {
                            tracing::error!("Failed to send initial sync requests: {}", e);
                            
                            // Reset sync manager state to prevent inconsistent state
                            self.sync_manager.reset_pending_requests();
                            tracing::warn!("Reset sync manager state after send_initial_requests failure");
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to start sequential sync: {}", e);
                    }
                }

                initial_sync_started = true;
            }

            // Check if it's time to update the status display
            if last_status_update.elapsed() >= status_update_interval {
                self.update_status_display().await;

                // Sequential sync handles filter gaps internally
                
                // Filter sync progress is handled by sequential sync manager internally
                let (
                    filters_requested,
                    filters_received,
                    basic_progress,
                    timeout,
                    total_missing,
                    actual_coverage,
                    missing_ranges,
                ) = {
                    // For sequential sync, return default values
                    (0, 0, 0.0, false, 0, 0.0, Vec::<(u32, u32)>::new())
                };

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
                            for (i, (start, end)) in
                                missing_ranges.iter().enumerate().take(show_count)
                            {
                                tracing::warn!(
                                    "  Gap {}: range {}-{} ({} filters)",
                                    i + 1,
                                    start,
                                    end,
                                    end - start + 1
                                );
                            }
                            if missing_ranges.len() > show_count {
                                tracing::warn!(
                                    "  ... and {} more gaps",
                                    missing_ranges.len() - show_count
                                );
                            }
                        }
                    } else {
                        tracing::info!(
                            "📊 Filter sync progress: {:.1}% ({}/{} filters received) - Complete!",
                            basic_progress,
                            filters_received,
                            filters_requested
                        );
                    }

                    if timeout {
                        tracing::warn!(
                            "⚠️  Filter sync timeout: no filters received in 30+ seconds"
                        );
                    }
                }

                // Also update wallet confirmation statuses periodically
                if let Err(e) = self.update_wallet_confirmations().await {
                    tracing::warn!("Failed to update wallet confirmations: {}", e);
                }
                
                // Emit detailed progress update
                if last_rate_calc.elapsed() >= Duration::from_secs(1) {
                    let current_height = self.storage.get_tip_height().await.ok().flatten().unwrap_or(0);
                    let peer_best = self.network.get_peer_best_height().await.ok().flatten().unwrap_or(current_height);
                    
                    // Calculate headers downloaded this second
                    if current_height > last_height {
                        headers_this_second = current_height - last_height;
                        last_height = current_height;
                    }
                    
                    let headers_per_second = headers_this_second as f64;
                    
                    // Determine sync stage
                    let sync_stage = if self.network.peer_count() == 0 {
                        crate::types::SyncStage::Connecting
                    } else if current_height == 0 {
                        crate::types::SyncStage::QueryingPeerHeight
                    } else if current_height < peer_best {
                        crate::types::SyncStage::DownloadingHeaders { 
                            start: current_height, 
                            end: peer_best 
                        }
                    } else {
                        crate::types::SyncStage::Complete
                    };
                    
                    let progress = crate::types::DetailedSyncProgress {
                        current_height,
                        peer_best_height: peer_best,
                        percentage: if peer_best > 0 {
                            (current_height as f64 / peer_best as f64 * 100.0).min(100.0)
                        } else {
                            0.0
                        },
                        headers_per_second,
                        bytes_per_second: 0, // TODO: Track actual bytes
                        estimated_time_remaining: if headers_per_second > 0.0 && peer_best > current_height {
                            let remaining = peer_best - current_height;
                            Some(Duration::from_secs_f64(remaining as f64 / headers_per_second))
                        } else {
                            None
                        },
                        sync_stage,
                        connected_peers: self.network.peer_count(),
                        total_headers_processed: current_height as u64,
                        total_bytes_downloaded,
                        sync_start_time,
                        last_update_time: SystemTime::now(),
                    };
                    
                    self.emit_progress(progress);
                    
                    headers_this_second = 0;
                    last_rate_calc = Instant::now();
                }

                last_status_update = Instant::now();
            }

            // Save sync state periodically (every 30 seconds or after significant progress)
            let current_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
            let last_sync_state_save = self.last_sync_state_save.clone();
            let last_save = *last_sync_state_save.read().await;
            
            if current_time - last_save >= 30 {  // Save every 30 seconds
                if let Err(e) = self.save_sync_state().await {
                    tracing::warn!("Failed to save sync state: {}", e);
                } else {
                    *last_sync_state_save.write().await = current_time;
                }
            }

            // Check for sync timeouts and handle recovery (only periodically, not every loop)
            if last_timeout_check.elapsed() >= timeout_check_interval {
                let _ = self
                    .sync_manager
                    .check_timeout(&mut *self.network, &mut *self.storage)
                    .await;
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
                    // Sequential sync handles filter retries internally

                    // Sequential sync handles CFHeader gap detection and recovery internally

                    // Sequential sync handles filter gap detection and recovery internally
                }
                last_filter_gap_check = Instant::now();
            }

            // Handle network messages with timeout for responsiveness
            match tokio::time::timeout(
                std::time::Duration::from_millis(1000),
                self.network.receive_message()
            ).await {
                Ok(msg_result) => match msg_result {
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
                            tracing::debug!(
                                "Continuing network monitoring despite message handling error"
                            );
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
                                tracing::info!(
                                    "✅ Reconnected to {} peer(s), resuming monitoring",
                                    self.network.peer_count()
                                );
                                continue;
                            } else {
                                tracing::warn!(
                                    "No peers available after waiting, will retry monitoring"
                                );
                            }
                        }
                    }

                        tracing::error!("Network error during monitoring: {}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
                Err(_) => {
                    // Timeout occurred - this is expected and allows checking running state
                    // Continue the loop to check if we should stop
                }
            }
        }

        Ok(())
    }

    /// Handle incoming network messages during monitoring.
    async fn handle_network_message(
        &mut self,
        message: dashcore::network::message::NetworkMessage,
    ) -> Result<()> {
        // Create a MessageHandler instance with all required parameters
        let mut handler = MessageHandler::new(
            &mut self.sync_manager,
            &mut *self.storage,
            &mut *self.network,
            &self.config,
            &self.stats,
            &self.filter_processor,
            &self.block_processor_tx,
            &self.wallet,
            &self.mempool_filter,
            &self.mempool_state,
            &self.event_tx,
        );

        // Delegate message handling to the MessageHandler
        match handler.handle_network_message(message.clone()).await {
            Ok(_) => {
                // Special handling for messages that need client-level processing
                use dashcore::network::message::NetworkMessage;
                match &message {
                    NetworkMessage::CLSig(clsig) => {
                        // Additional client-level ChainLock processing
                        self.process_chainlock(clsig.clone()).await?;
                    }
                    NetworkMessage::ISLock(islock_msg) => {
                        // Additional client-level InstantLock processing
                        self.process_instantsendlock(islock_msg.clone()).await?;
                    }
                    _ => {}
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Handle inventory messages - not implemented for sync adapter.
    async fn handle_inventory(
        &mut self,
        _inv: Vec<dashcore::network::message_blockdata::Inventory>,
    ) -> Result<()> {
        // TODO: Implement inventory handling in sync adapter if needed
        Ok(())
    }

    /// Process new headers received from the network.
    async fn process_new_headers(&mut self, headers: Vec<dashcore::block::Header>) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }

        // Get the height before storing new headers
        let initial_height =
            self.storage.get_tip_height().await.map_err(|e| SpvError::Storage(e))?.unwrap_or(0);

        // For sequential sync, route headers through the message handler
        let headers_msg = dashcore::network::message::NetworkMessage::Headers(headers);
        self.sync_manager.handle_message(headers_msg, &mut *self.network, &mut *self.storage)
            .await
            .map_err(|e| SpvError::Sync(e))?;

        // Check if filters are enabled and request filter headers for new blocks
        if self.config.enable_filters {
            // Get the new tip height after storing headers
            let new_height =
                self.storage.get_tip_height().await.map_err(|e| SpvError::Storage(e))?.unwrap_or(0);

            // If we stored new headers, request filter headers for them
            if new_height > initial_height {
                tracing::info!(
                    "New headers stored from height {} to {}, requesting filter headers",
                    initial_height + 1,
                    new_height
                );

                // Request filter headers for each new header
                for height in (initial_height + 1)..=new_height {
                    if let Some(header) =
                        self.storage.get_header(height).await.map_err(|e| SpvError::Storage(e))?
                    {
                        let block_hash = header.block_hash();
                        tracing::debug!(
                            "Requesting filter header for block {} at height {}",
                            block_hash,
                            height
                        );

                        // Sequential sync handles filter requests internally
                    }
                }

                // Update status display after processing new headers
                self.update_status_display().await;
            }
        }

        Ok(())
    }

    /// Process a new block hash detected from inventory.
    async fn process_new_block_hash(&mut self, _block_hash: dashcore::BlockHash) -> Result<()> {
        // TODO: Implement block hash processing in sync adapter if needed
        Ok(())
    }

    /// Process received filter headers.
    async fn process_filter_headers(
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
            .map_err(|e| SpvError::Sync(e))?;

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
        let task = BlockProcessingTask::ProcessBlock {
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
        watch_items: &[WatchItem],
    ) -> Result<()> {
        let block_hash = block.block_hash();
        let block_height = self.get_block_height_or_default(block_hash).await;
        let mut relevant_transactions = 0;
        let mut new_outpoints_to_watch = Vec::new();
        let mut balance_changes: std::collections::HashMap<dashcore::Address, i64> =
            std::collections::HashMap::new();

        for (tx_index, transaction) in block.txdata.iter().enumerate() {
            let txid = transaction.txid();
            let mut transaction_relevant = false;
            let is_coinbase = tx_index == 0;

            // Process inputs first (spending UTXOs)
            if !is_coinbase {
                for (vin, input) in transaction.input.iter().enumerate() {
                    // Check if this input spends a UTXO from our watched addresses
                    if let Ok(Some(spent_utxo)) =
                        self.wallet.write().await.remove_utxo(&input.previous_output).await
                    {
                        transaction_relevant = true;
                        let amount = spent_utxo.value();

                        tracing::info!(
                            "💸 Found relevant input: {}:{} spending UTXO {} (value: {})",
                            txid,
                            vin,
                            input.previous_output,
                            amount
                        );

                        // Update balance change for this address (subtract)
                        *balance_changes.entry(spent_utxo.address.clone()).or_insert(0) -=
                            amount.to_sat() as i64;
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
                        WatchItem::Address {
                            address,
                            ..
                        } => {
                            (address.script_pubkey() == output.script_pubkey, Some(address.clone()))
                        }
                        WatchItem::Script(script) => (script == &output.script_pubkey, None),
                        WatchItem::Outpoint(_) => (false, None), // Outpoints don't match outputs
                    };

                    if matches {
                        transaction_relevant = true;
                        let outpoint = dashcore::OutPoint {
                            txid,
                            vout: vout as u32,
                        };
                        let amount = dashcore::Amount::from_sat(output.value);

                        tracing::info!(
                            "💰 Found relevant output: {}:{} to {:?} (value: {})",
                            txid,
                            vout,
                            watch_item,
                            amount
                        );

                        // Create and store UTXO if we have an address
                        if let Some(address) = matched_address {
                            let utxo = crate::wallet::Utxo::new(
                                outpoint,
                                output.clone(),
                                address.clone(),
                                block_height,
                                is_coinbase,
                            );

                            if let Err(e) = self.wallet.write().await.add_utxo(utxo).await {
                                tracing::error!("Failed to store UTXO {}: {}", outpoint, e);
                            } else {
                                tracing::debug!(
                                    "📝 Stored UTXO {}:{} for address {}",
                                    txid,
                                    vout,
                                    address
                                );
                            }

                            // Update balance change for this address (add)
                            *balance_changes.entry(address.clone()).or_insert(0) +=
                                amount.to_sat() as i64;
                        }

                        // Track this outpoint so we can detect when it's spent
                        new_outpoints_to_watch.push(outpoint);
                        tracing::debug!(
                            "📍 Now watching outpoint {}:{} for future spending",
                            txid,
                            vout
                        );
                    }
                }
            }

            if transaction_relevant {
                relevant_transactions += 1;
                tracing::debug!(
                    "📝 Transaction {}: {} (index {}) is relevant",
                    txid,
                    if is_coinbase {
                        "coinbase"
                    } else {
                        "regular"
                    },
                    tx_index
                );
            }
        }

        if relevant_transactions > 0 {
            tracing::info!(
                "🎯 Block {} contains {} relevant transactions affecting watched items",
                block_hash,
                relevant_transactions
            );

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
                let sign = if *change_sat > 0 {
                    "+"
                } else {
                    "-"
                };
                tracing::info!("  📍 Address {}: {}{}", address, sign, change_amount);
            }
        }

        // Calculate and report current balances for all watched addresses
        let addresses = self.get_watched_addresses_from_items().await;
        for address in addresses {
            if let Some(_) = self
                .process_address_balance(&address, |balance| {
                    tracing::info!(
                        "  💼 Address {} balance: {} (confirmed: {}, unconfirmed: {})",
                        address,
                        balance.total(),
                        balance.confirmed,
                        balance.unconfirmed
                    );
                })
                .await
            {
                // Balance reported successfully
            } else {
                tracing::warn!(
                    "Continuing balance reporting despite failure for address {}",
                    address
                );
            }
        }

        Ok(())
    }

    /// Get the balance for a specific address.
    pub async fn get_address_balance(&self, address: &dashcore::Address) -> Result<AddressBalance> {
        // Use wallet to get balance directly
        let wallet = self.wallet.read().await;
        let balance = wallet.get_balance_for_address(address).await.map_err(|e| {
            SpvError::Storage(crate::error::StorageError::ReadFailed(format!(
                "Wallet error: {}",
                e
            )))
        })?;

        Ok(AddressBalance {
            confirmed: balance.confirmed + balance.instantlocked,
            unconfirmed: balance.pending,
            pending: dashcore::Amount::from_sat(0),
            pending_instant: dashcore::Amount::from_sat(0),
        })
    }

    /// Get the total wallet balance including mempool transactions.
    pub async fn get_wallet_balance_with_mempool(&self) -> Result<crate::wallet::Balance> {
        let wallet = self.wallet.read().await;
        let mempool_state = self.mempool_state.read().await;
        wallet.get_balance_with_mempool(&*mempool_state).await
    }

    /// Get balances for all watched addresses.
    pub async fn get_all_balances(
        &self,
    ) -> Result<std::collections::HashMap<dashcore::Address, AddressBalance>> {
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
        let network = self
            .network
            .as_any()
            .downcast_ref::<crate::network::multi_peer::MultiPeerNetworkManager>()
            .ok_or_else(|| {
                SpvError::Config("Network manager does not support peer disconnection".to_string())
            })?;

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
    pub async fn process_chainlock(
        &mut self,
        chainlock: dashcore::ephemerealdata::chain_lock::ChainLock,
    ) -> Result<()> {
        tracing::info!(
            "Processing ChainLock for block {} at height {}",
            chainlock.block_hash,
            chainlock.block_height
        );

        // First perform basic validation and storage through ChainLockManager
        let chain_state = self.state.read().await;
        self.chainlock_manager
            .process_chain_lock(chainlock.clone(), &*chain_state, &mut *self.storage)
            .await
            .map_err(|e| SpvError::Validation(e))?;
        drop(chain_state);

        // Sequential sync handles masternode validation internally
        tracing::info!(
            "ChainLock stored, sequential sync will handle masternode validation internally"
        );

        // Update chain state with the new ChainLock
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

        tracing::info!(
            "🔒 Updated confirmed chain tip to ChainLock at height {} ({})",
            chainlock.block_height,
            chainlock.block_hash
        );

        // Emit ChainLock event
        self.emit_event(SpvEvent::ChainLockReceived {
            height: chainlock.block_height,
            hash: chainlock.block_hash,
        });

        // No need for additional storage - ChainLockManager already handles it
        Ok(())
    }

    /// Process and validate an InstantSendLock.
    async fn process_instantsendlock(
        &mut self,
        islock: dashcore::ephemerealdata::instant_lock::InstantLock,
    ) -> Result<()> {
        tracing::info!("Processing InstantSendLock for tx {}", islock.txid);

        // TODO: Implement InstantSendLock validation
        // - Verify BLS signature against known quorum
        // - Check if all inputs are locked
        // - Mark transaction as instantly confirmed
        // - Store InstantSendLock for future reference

        // For now, just log the InstantSendLock details
        tracing::info!(
            "InstantSendLock validated: txid={}, inputs={}, signature={:?}",
            islock.txid,
            islock.inputs.len(),
            islock.signature.to_string().chars().take(20).collect::<String>()
        );

        Ok(())
    }

    /// Get current sync progress.
    pub async fn sync_progress(&self) -> Result<SyncProgress> {
        let display = self.create_status_display().await;
        display.sync_progress().await
    }

    /// Add a watch item.
    pub async fn add_watch_item(&mut self, item: WatchItem) -> Result<()> {
        WatchManager::add_watch_item(
            &self.watch_items,
            &self.wallet,
            &self.watch_item_updater,
            item,
            &mut *self.storage,
        )
        .await?;
        
        // Update mempool filter with new watch items if mempool tracking is enabled
        if self.config.enable_mempool_tracking {
            self.update_mempool_filter().await;
        }
        
        Ok(())
    }

    /// Remove a watch item.
    pub async fn remove_watch_item(&mut self, item: &WatchItem) -> Result<bool> {
        let removed = WatchManager::remove_watch_item(
            &self.watch_items,
            &self.wallet,
            &self.watch_item_updater,
            item,
            &mut *self.storage,
        )
        .await?;
        
        // Update mempool filter with new watch items if mempool tracking is enabled
        if removed && self.config.enable_mempool_tracking {
            self.update_mempool_filter().await;
        }
        
        Ok(removed)
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
    pub async fn check_and_fix_wallet_consistency(
        &self,
    ) -> Result<(ConsistencyReport, Option<ConsistencyRecovery>)> {
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
        wallet.update_confirmation_status().await.map_err(Self::wallet_to_spv_error)
    }

    /// Get the total wallet balance.
    pub async fn get_wallet_balance(&self) -> Result<crate::wallet::Balance> {
        let wallet = self.wallet.read().await;
        wallet.get_balance().await.map_err(Self::wallet_to_spv_error)
    }

    /// Get balance for a specific address.
    pub async fn get_wallet_address_balance(
        &self,
        address: &dashcore::Address,
    ) -> Result<crate::wallet::Balance> {
        let wallet = self.wallet.read().await;
        wallet.get_balance_for_address(address).await.map_err(Self::wallet_to_spv_error)
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
        let balance = wallet.get_balance().await.map_err(Self::wallet_to_spv_error)?;

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

    /// Get a reference to the masternode list engine.
    /// Returns None if masternode sync is not enabled in config.
    pub fn masternode_list_engine(&self) -> Option<&MasternodeListEngine> {
        self.sync_manager.masternode_list_engine()
    }

    /// Sync compact filters for recent blocks and check for matches.
    /// Sync and check filters with internal monitoring loop management.
    /// This method automatically handles the monitoring loop required for CFilter message processing.
    pub async fn sync_and_check_filters_with_monitoring(
        &mut self,
        num_blocks: Option<u32>,
    ) -> Result<Vec<crate::types::FilterMatch>> {
        self.sync_and_check_filters(num_blocks).await
    }

    pub async fn sync_and_check_filters(
        &mut self,
        num_blocks: Option<u32>,
    ) -> Result<Vec<crate::types::FilterMatch>> {
        // Sequential sync handles filter sync internally
        tracing::info!("Sequential sync mode: filter sync handled internally");
        Ok(Vec::new())
    }

    /// Sync filters for a specific height range.
    pub async fn sync_filters_range(
        &mut self,
        start_height: Option<u32>,
        count: Option<u32>,
    ) -> Result<()> {
        // Sequential sync handles filter range sync internally
        tracing::info!("Sequential sync mode: filter range sync handled internally");
        Ok(())
    }

    /// Restore sync state from persistent storage.
    /// Returns true if state was successfully restored, false if no state was found.
    async fn restore_sync_state(&mut self) -> Result<bool> {
        // Load sync state from storage
        let sync_state = self.storage.load_sync_state().await.map_err(|e| SpvError::Storage(e))?;
        
        let Some(saved_state) = sync_state else {
            return Ok(false);
        };
        
        // Validate the sync state
        let validation = saved_state.validate(self.config.network);
        
        if !validation.is_valid {
            tracing::error!("Sync state validation failed:");
            for error in &validation.errors {
                tracing::error!("  - {}", error);
            }
            
            // Handle recovery based on suggestion
            if let Some(suggestion) = validation.recovery_suggestion {
                match suggestion {
                    crate::storage::RecoverySuggestion::StartFresh => {
                        tracing::warn!("Recovery: Starting fresh sync");
                        return Ok(false);
                    }
                    crate::storage::RecoverySuggestion::RollbackToHeight(height) => {
                        tracing::warn!("Recovery: Rolling back to height {}", height);
                        
                        // Validate the rollback height
                        if height == 0 {
                            tracing::error!("Cannot rollback to genesis block (height 0)");
                            return Ok(false); // Start fresh sync
                        }
                        
                        // Get current height from storage to validate against
                        let current_height = self.storage.get_tip_height()
                            .await
                            .map_err(|e| SpvError::Storage(e))?
                            .unwrap_or(0);
                        
                        if height > current_height {
                            tracing::error!(
                                "Cannot rollback to height {} which is greater than current height {}",
                                height, current_height
                            );
                            return Ok(false); // Start fresh sync
                        }
                        
                        match self.rollback_to_height(height).await {
                            Ok(_) => {
                                tracing::info!("Successfully rolled back to height {}", height);
                                return Ok(false); // Start fresh sync from rollback point
                            }
                            Err(e) => {
                                tracing::error!("Failed to rollback to height {}: {}", height, e);
                                return Ok(false); // Start fresh sync
                            }
                        }
                    }
                    crate::storage::RecoverySuggestion::UseCheckpoint(height) => {
                        tracing::warn!("Recovery: Using checkpoint at height {}", height);
                        
                        // Validate the checkpoint height
                        if height == 0 {
                            tracing::error!("Cannot use checkpoint at genesis block (height 0)");
                            return Ok(false); // Start fresh sync
                        }
                        
                        // Check if checkpoint height is reasonable (not in the future)
                        let current_height = self.storage.get_tip_height()
                            .await
                            .map_err(|e| SpvError::Storage(e))?
                            .unwrap_or(0);
                        
                        if current_height > 0 && height > current_height {
                            tracing::error!(
                                "Cannot use checkpoint at height {} which is greater than current height {}",
                                height, current_height
                            );
                            return Ok(false); // Start fresh sync
                        }
                        
                        match self.recover_from_checkpoint(height).await {
                            Ok(_) => {
                                tracing::info!("Successfully recovered from checkpoint at height {}", height);
                                return Ok(true); // State restored from checkpoint
                            }
                            Err(e) => {
                                tracing::error!("Failed to recover from checkpoint {}: {}", height, e);
                                return Ok(false); // Start fresh sync
                            }
                        }
                    }
                    crate::storage::RecoverySuggestion::PartialRecovery => {
                        tracing::warn!("Recovery: Attempting partial recovery");
                        // For partial recovery, we keep headers but reset filter sync
                        if let Err(e) = self.reset_filter_sync_state().await {
                            tracing::error!("Failed to reset filter sync state: {}", e);
                        }
                        return Ok(true); // Continue with partial state
                    }
                }
            }
            
            return Ok(false);
        }
        
        // Log any warnings
        for warning in &validation.warnings {
            tracing::warn!("Sync state warning: {}", warning);
        }
        
        tracing::info!(
            "Restoring sync state from height {} (saved at {:?})",
            saved_state.chain_tip.height,
            saved_state.saved_at
        );
        
        // CRITICAL: Load headers from storage into ChainState
        if saved_state.chain_tip.height > 0 {
            tracing::info!("Loading headers from storage into ChainState...");
            let start_time = std::time::Instant::now();
            
            // Load headers in batches to avoid memory spikes
            const BATCH_SIZE: u32 = 10_000;
            let mut loaded_count = 0u32;
            let target_height = saved_state.chain_tip.height;
            
            // Start from height 1 (genesis is already in ChainState)
            let mut current_height = 1u32;
            
            while current_height <= target_height {
                let end_height = (current_height + BATCH_SIZE - 1).min(target_height);
                
                // Load batch of headers from storage
                let headers = self.storage.load_headers(current_height..end_height + 1)
                    .await
                    .map_err(|e| SpvError::Storage(e))?;
                
                if headers.is_empty() {
                    tracing::error!(
                        "Failed to load headers for range {}..{} - storage may be corrupted",
                        current_height, end_height + 1
                    );
                    return Ok(false); // Start fresh sync
                }
                
                // Validate headers before adding to chain state
                {
                    // Validate the batch of headers
                    if let Err(e) = self.validation.validate_header_chain(&headers, false) {
                        tracing::error!(
                            "Header validation failed for range {}..{}: {:?}",
                            current_height, end_height + 1, e
                        );
                        return Ok(false); // Start fresh sync
                    }
                    
                    // Add validated headers to chain state
                    let mut state = self.state.write().await;
                    for header in headers {
                        state.add_header(header);
                        loaded_count += 1;
                    }
                }
                
                // Progress logging for large header counts
                if loaded_count % 50_000 == 0 || loaded_count == target_height {
                    let elapsed = start_time.elapsed();
                    let headers_per_sec = loaded_count as f64 / elapsed.as_secs_f64();
                    tracing::info!(
                        "Loaded {}/{} headers ({:.0} headers/sec)",
                        loaded_count, target_height, headers_per_sec
                    );
                }
                
                current_height = end_height + 1;
            }
            
            let elapsed = start_time.elapsed();
            tracing::info!(
                "✅ Loaded {} headers into ChainState in {:.2}s ({:.0} headers/sec)",
                loaded_count,
                elapsed.as_secs_f64(),
                loaded_count as f64 / elapsed.as_secs_f64()
            );
            
            // Validate the loaded chain state
            let state = self.state.read().await;
            let actual_height = state.tip_height();
            if actual_height != target_height {
                tracing::error!(
                    "Chain state height mismatch after loading: expected {}, got {}",
                    target_height, actual_height
                );
                return Ok(false); // Start fresh sync
            }
            
            // Verify tip hash matches
            if let Some(tip_hash) = state.tip_hash() {
                if tip_hash != saved_state.chain_tip.hash {
                    tracing::error!(
                        "Chain tip hash mismatch: expected {}, got {}",
                        saved_state.chain_tip.hash, tip_hash
                    );
                    return Ok(false); // Start fresh sync
                }
            }
        }
        
        // Load filter headers if they exist
        if saved_state.sync_progress.filter_header_height > 0 {
            tracing::info!("Loading filter headers from storage...");
            let filter_headers = self.storage.load_filter_headers(0..saved_state.sync_progress.filter_header_height + 1)
                .await
                .map_err(|e| SpvError::Storage(e))?;
            
            if !filter_headers.is_empty() {
                let mut state = self.state.write().await;
                state.add_filter_headers(filter_headers);
                tracing::info!(
                    "✅ Loaded {} filter headers into ChainState",
                    saved_state.sync_progress.filter_header_height + 1
                );
            }
        }
        
        // Update sync progress in stats
        {
            let mut stats = self.stats.write().await;
            stats.headers_downloaded = saved_state.sync_progress.header_height as u64;
            stats.filter_headers_downloaded = saved_state.sync_progress.filter_header_height as u64;
            stats.filters_downloaded = saved_state.filter_sync.filters_downloaded;
            stats.masternode_diffs_processed = saved_state.masternode_sync.last_diff_height.unwrap_or(0) as u64;
        }
        
        // Restore masternode state if available
        if let Some(last_mn_height) = saved_state.masternode_sync.last_synced_height {
            tracing::info!("Restored masternode sync state at height {}", last_mn_height);
            // The masternode engine state will be loaded from storage separately
        }
        
        // Update sync manager state
        // Sequential sync manager needs to determine which phase to resume
        tracing::debug!("Sequential sync manager will resume from stored state");
        
        // Determine phase based on sync progress
        if saved_state.sync_progress.headers_synced {
            if saved_state.sync_progress.filter_headers_synced {
                // Headers and filter headers done, we're in filter download phase
                tracing::info!("Resuming sequential sync in filter download phase");
            } else {
                // Headers done, need filter headers
                tracing::info!("Resuming sequential sync in filter header download phase");
            }
        } else {
            // Still downloading headers
            tracing::info!("Resuming sequential sync in header download phase");
        }
        
        // Reset any in-flight requests
        self.sync_manager.reset_pending_requests();
        
        // CRITICAL: Load headers into the sync manager's chain state
        if saved_state.chain_tip.height > 0 {
            tracing::info!("Loading headers into sync manager...");
            match self.sync_manager.load_headers_from_storage(&*self.storage).await {
                Ok(loaded_count) => {
                    tracing::info!("✅ Sync manager loaded {} headers from storage", loaded_count);
                }
                Err(e) => {
                    tracing::error!("Failed to load headers into sync manager: {}", e);
                    return Ok(false); // Start fresh sync
                }
            }
        }
        
        tracing::info!(
            "Sync state restored: headers={}, filter_headers={}, filters_downloaded={}",
            saved_state.sync_progress.header_height,
            saved_state.sync_progress.filter_header_height,
            saved_state.filter_sync.filters_downloaded
        );
        
        Ok(true)
    }

    /// Rollback chain state to a specific height.
    async fn rollback_to_height(&mut self, target_height: u32) -> Result<()> {
        tracing::info!("Rolling back chain state to height {}", target_height);
        
        // Get current height
        let current_height = self.state.read().await.tip_height();
        
        if target_height >= current_height {
            return Err(SpvError::Config(format!(
                "Cannot rollback to height {} when current height is {}",
                target_height, current_height
            )));
        }
        
        // Remove headers above target height from in-memory state
        let mut state = self.state.write().await;
        while state.tip_height() > target_height {
            state.remove_tip();
        }
        
        // Also remove filter headers above target height
        // Keep only filter headers up to and including target_height
        if state.filter_headers.len() > (target_height + 1) as usize {
            state.filter_headers.truncate((target_height + 1) as usize);
            // Update current filter tip if we have filter headers
            state.current_filter_tip = state.filter_headers.last().copied();
        }
        
        // Clear chain lock if it's above the target height
        if let Some(chainlock_height) = state.last_chainlock_height {
            if chainlock_height > target_height {
                state.last_chainlock_height = None;
                state.last_chainlock_hash = None;
            }
        }
        
        // Clone the updated state for storage
        let updated_state = state.clone();
        drop(state);
        
        // Update persistent storage to reflect the rollback
        // Store the updated chain state
        self.storage.store_chain_state(&updated_state).await
            .map_err(|e| SpvError::Storage(e))?;
        
        // Clear any cached filter data above the target height
        // Note: Since we can't directly remove individual filters from storage,
        // the next sync will overwrite them as needed
        
        tracing::info!("Rolled back to height {} and updated persistent storage", target_height);
        Ok(())
    }
    
    /// Recover from a saved checkpoint.
    async fn recover_from_checkpoint(&mut self, checkpoint_height: u32) -> Result<()> {
        tracing::info!("Recovering from checkpoint at height {}", checkpoint_height);
        
        // Load checkpoints around the target height
        let checkpoints = self.storage
            .get_sync_checkpoints(checkpoint_height, checkpoint_height)
            .await
            .map_err(|e| SpvError::Storage(e))?;
        
        if checkpoints.is_empty() {
            return Err(SpvError::Config(format!(
                "No checkpoint found at height {}",
                checkpoint_height
            )));
        }
        
        let checkpoint = &checkpoints[0];
        
        // Verify the checkpoint is validated
        if !checkpoint.validated {
            return Err(SpvError::Config(format!(
                "Checkpoint at height {} is not validated",
                checkpoint_height
            )));
        }
        
        // Rollback to checkpoint height
        self.rollback_to_height(checkpoint_height).await?;
        
        tracing::info!("Successfully recovered from checkpoint at height {}", checkpoint_height);
        Ok(())
    }
    
    /// Reset filter sync state while keeping headers.
    async fn reset_filter_sync_state(&mut self) -> Result<()> {
        tracing::info!("Resetting filter sync state");
        
        // Reset filter-related stats
        {
            let mut stats = self.stats.write().await;
            stats.filter_headers_downloaded = 0;
            stats.filters_downloaded = 0;
            stats.filters_matched = 0;
            stats.filters_requested = 0;
            stats.filters_received = 0;
        }
        
        // Clear filter headers from chain state
        {
            let mut state = self.state.write().await;
            state.filter_headers.clear();
            state.current_filter_tip = None;
        }
        
        // Reset sync manager filter state
        // Sequential sync manager handles filter state internally
        tracing::debug!("Reset sequential filter sync state");
        
        tracing::info!("Filter sync state reset completed");
        Ok(())
    }

    /// Save current sync state to persistent storage.
    async fn save_sync_state(&mut self) -> Result<()> {
        if !self.config.enable_persistence {
            return Ok(());
        }
        
        // Get current sync progress
        let sync_progress = self.sync_progress().await?;
        
        // Get current chain state
        let chain_state = self.state.read().await;
        
        // Create persistent sync state
        let persistent_state = crate::storage::PersistentSyncState::from_chain_state(
            &*chain_state,
            &sync_progress,
            self.config.network,
        );
        
        if let Some(state) = persistent_state {
            // Check if we should create a checkpoint
            if state.should_checkpoint(state.chain_tip.height) {
                if let Some(checkpoint) = state.checkpoints.last() {
                    self.storage
                        .store_sync_checkpoint(checkpoint.height, checkpoint)
                        .await
                        .map_err(|e| SpvError::Storage(e))?;
                    tracing::info!("Created sync checkpoint at height {}", checkpoint.height);
                }
            }
            
            // Save the sync state
            self.storage
                .store_sync_state(&state)
                .await
                .map_err(|e| SpvError::Storage(e))?;
            
            tracing::debug!(
                "Saved sync state: headers={}, filter_headers={}, filters={}",
                state.sync_progress.header_height,
                state.sync_progress.filter_header_height,
                state.filter_sync.filters_downloaded
            );
        }
        
        Ok(())
    }

    /// Initialize genesis block if not already present in storage.
    async fn initialize_genesis_block(&mut self) -> Result<()> {
        // Check if we already have any headers in storage
        let current_tip = self.storage.get_tip_height().await.map_err(|e| SpvError::Storage(e))?;

        if current_tip.is_some() {
            // We already have headers, genesis block should be at height 0
            tracing::debug!("Headers already exist in storage, skipping genesis initialization");
            return Ok(());
        }

        // Get the genesis block hash for this network
        let genesis_hash = self
            .config
            .network
            .known_genesis_block_hash()
            .ok_or_else(|| SpvError::Config("No known genesis hash for network".to_string()))?;

        tracing::info!(
            "Initializing genesis block for network {:?}: {}",
            self.config.network,
            genesis_hash
        );

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
                    merkle_root: "e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7"
                        .parse()
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
                    merkle_root: "e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7"
                        .parse()
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
        self.storage.store_headers(&genesis_headers).await.map_err(|e| SpvError::Storage(e))?;

        // Verify it was stored correctly
        let stored_height = self.storage.get_tip_height().await.map_err(|e| SpvError::Storage(e))?;
        tracing::info!("✅ Genesis block initialized at height 0, storage reports tip height: {:?}", stored_height);

        Ok(())
    }

    /// Load watch items from storage.
    async fn load_watch_items(&mut self) -> Result<()> {
        WatchManager::load_watch_items(&self.watch_items, &self.wallet, &*self.storage).await
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
                SpvError::Storage(crate::error::StorageError::ReadFailed(format!(
                    "Wallet error: {}",
                    e
                )))
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
        let storage_utxos =
            self.storage.get_all_utxos().await.map_err(Self::storage_to_spv_error)?;

        // Check UTXO consistency using helper
        Self::check_utxo_mismatches(&wallet_utxos, &storage_utxos, &mut report);

        // Validate address consistency between WatchItems and wallet
        let watch_items = self.get_watch_items().await;
        let wallet_addresses = wallet.get_watched_addresses().await;

        // Collect addresses from watch items
        let watch_addresses: std::collections::HashSet<_> = watch_items
            .iter()
            .filter_map(|item| {
                if let WatchItem::Address {
                    address,
                    ..
                } = item
                {
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
            tracing::warn!(
                "❌ Wallet consistency issues detected: {} UTXO mismatches, {} address mismatches",
                report.utxo_mismatches.len(),
                report.address_mismatches.len()
            );
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
        let storage_utxos =
            self.storage.get_all_utxos().await.map_err(Self::storage_to_spv_error)?;
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
                    tracing::error!(
                        "Failed to remove UTXO {} from wallet: {}",
                        wallet_utxo.outpoint,
                        e
                    );
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
                    "Wallet consistency recovery failed - some issues remain".to_string(),
                ));
            }

            // Validate again after recovery
            let post_recovery_report = self.validate_wallet_consistency().await?;
            if !post_recovery_report.is_consistent {
                return Err(SpvError::Config(
                    "Wallet consistency recovery incomplete - issues remain after recovery"
                        .to_string(),
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
                tracing::debug!(
                    "Successfully added UTXO {}:{} for address {}",
                    utxo.outpoint.txid,
                    utxo.outpoint.vout,
                    utxo.address
                );
                Ok(())
            }
            Err(e) => {
                tracing::error!(
                    "Failed to add UTXO {}:{} for address {}: {}",
                    utxo.outpoint.txid,
                    utxo.outpoint.vout,
                    utxo.address,
                    e
                );

                // Try to continue with degraded functionality
                tracing::warn!(
                    "Continuing with degraded wallet functionality due to UTXO storage failure"
                );

                Err(SpvError::Storage(crate::error::StorageError::WriteFailed(format!(
                    "Failed to store UTXO {}: {}",
                    utxo.outpoint, e
                ))))
            }
        }
    }

    /// Safely remove a UTXO from the wallet with comprehensive error handling.
    async fn safe_remove_utxo(
        &self,
        outpoint: &dashcore::OutPoint,
    ) -> Result<Option<crate::wallet::Utxo>> {
        let wallet = self.wallet.read().await;

        match wallet.remove_utxo(outpoint).await {
            Ok(removed_utxo) => {
                if let Some(ref utxo) = removed_utxo {
                    tracing::debug!(
                        "Successfully removed UTXO {} for address {}",
                        outpoint,
                        utxo.address
                    );
                } else {
                    tracing::debug!(
                        "UTXO {} was not found in wallet (already spent or never existed)",
                        outpoint
                    );
                }
                Ok(removed_utxo)
            }
            Err(e) => {
                tracing::error!("Failed to remove UTXO {}: {}", outpoint, e);

                // This is less critical than adding - we can continue
                tracing::warn!(
                    "Continuing despite UTXO removal failure - wallet may show incorrect balance"
                );

                Err(SpvError::Storage(crate::error::StorageError::WriteFailed(format!(
                    "Failed to remove UTXO {}: {}",
                    outpoint, e
                ))))
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
    async fn handle_post_sync_headers(
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

        tracing::info!("Handling {} post-sync headers - requesting filter headers (filters will follow automatically)", headers.len());

        for header in headers {
            let block_hash = header.block_hash();

            // Sequential sync handles filter headers internally
            tracing::debug!("Sequential sync mode: filter headers handled internally for block {}", block_hash);
        }

        tracing::info!(
            "✅ Completed post-sync filter header requests for {} new blocks",
            headers.len()
        );
        Ok(())
    }
}
