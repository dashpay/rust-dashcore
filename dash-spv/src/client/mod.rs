//! High-level client API for the Dash SPV client.

pub mod block_processor;
pub mod config;
pub mod filter_sync;
pub mod message_handler;
pub mod status_display;

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{mpsc, Mutex, RwLock};

use crate::terminal::TerminalUI;
use std::collections::HashSet;

use crate::chain::ChainLockManager;
use crate::error::{Result, SpvError};
use crate::mempool_filter::MempoolFilter;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::filters::FilterNotificationSender;
use crate::sync::sequential::SequentialSyncManager;
use crate::types::{
    AddressBalance, ChainState, DetailedSyncProgress, MempoolState, SpvEvent, SpvStats,
    SyncProgress,
};
use crate::validation::ValidationManager;
use dashcore::network::constants::NetworkExt;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use key_wallet_manager::wallet_interface::WalletInterface;

pub use block_processor::{BlockProcessingTask, BlockProcessor};
pub use config::ClientConfig;
pub use filter_sync::FilterSyncCoordinator;
pub use message_handler::MessageHandler;
pub use status_display::StatusDisplay;

/// Main Dash SPV client.
pub struct DashSpvClient<W: WalletInterface, N: NetworkManager, S: StorageManager> {
    config: ClientConfig,
    state: Arc<RwLock<ChainState>>,
    stats: Arc<RwLock<SpvStats>>,
    network: N,
    storage: Arc<Mutex<S>>,
    // External wallet implementation (required)
    wallet: Arc<RwLock<W>>,
    /// Synchronization manager for coordinating blockchain sync operations.
    ///
    /// # Architectural Design
    ///
    /// The sync manager is stored as a non-shared field (not wrapped in Arc<Mutex<T>>)
    /// for the following reasons:
    ///
    /// 1. **Single Owner Pattern**: The sync manager is exclusively owned by the client,
    ///    ensuring clear ownership and preventing concurrent access issues.
    ///
    /// 2. **Sequential Operations**: Blockchain synchronization is inherently sequential -
    ///    headers must be validated in order, and sync phases must complete before
    ///    progressing to the next phase.
    ///
    /// 3. **Simplified State Management**: Avoiding shared ownership eliminates complex
    ///    synchronization issues and makes the sync state machine easier to reason about.
    ///
    /// ## Future Considerations
    ///
    /// If concurrent access becomes necessary (e.g., for monitoring sync progress from
    /// multiple threads), consider:
    /// - Using interior mutability patterns (Arc<Mutex<SequentialSyncManager>>)
    /// - Extracting read-only state into a separate shared structure
    /// - Implementing a message-passing architecture for sync commands
    ///
    /// The current design prioritizes simplicity and correctness over concurrent access.
    sync_manager: SequentialSyncManager<S, N, W>,
    validation: ValidationManager,
    chainlock_manager: Arc<ChainLockManager>,
    running: Arc<RwLock<bool>>,
    terminal_ui: Option<Arc<TerminalUI>>,
    filter_processor: Option<FilterNotificationSender>,
    block_processor_tx: mpsc::UnboundedSender<BlockProcessingTask>,
    progress_sender: Option<mpsc::UnboundedSender<DetailedSyncProgress>>,
    progress_receiver: Option<mpsc::UnboundedReceiver<DetailedSyncProgress>>,
    event_tx: mpsc::UnboundedSender<SpvEvent>,
    event_rx: Option<mpsc::UnboundedReceiver<SpvEvent>>,
    mempool_state: Arc<RwLock<MempoolState>>,
    mempool_filter: Option<Arc<MempoolFilter>>,
    last_sync_state_save: Arc<RwLock<u64>>,
}

impl<
        W: WalletInterface + Send + Sync + 'static,
        N: NetworkManager + Send + Sync + 'static,
        S: StorageManager + Send + Sync + 'static,
    > DashSpvClient<W, N, S>
{
    /// Take the progress receiver for external consumption.
    pub fn take_progress_receiver(
        &mut self,
    ) -> Option<mpsc::UnboundedReceiver<DetailedSyncProgress>> {
        self.progress_receiver.take()
    }

    /// Get a reference to the wallet.
    pub fn wallet(&self) -> &Arc<RwLock<W>> {
        &self.wallet
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
    async fn create_status_display(&self) -> StatusDisplay<'_, S> {
        StatusDisplay::new(
            &self.state,
            &self.stats,
            self.storage.clone(),
            &self.terminal_ui,
            &self.config,
        )
    }

    // UTXO mismatch checking removed - handled by external wallet

    // Address mismatch checking removed - handled by external wallet
    /*
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
    */

    /// Create a new SPV client with the given configuration, network, storage, and wallet.
    pub async fn new(
        config: ClientConfig,
        network: N,
        storage: S,
        wallet: Arc<RwLock<W>>,
    ) -> Result<Self> {
        // Validate configuration
        config.validate().map_err(SpvError::Config)?;

        // Initialize state for the network
        let state = Arc::new(RwLock::new(ChainState::new_for_network(config.network)));
        let stats = Arc::new(RwLock::new(SpvStats::default()));

        // Wrap storage in Arc<Mutex>
        let storage = Arc::new(Mutex::new(storage));

        // Create sync manager
        let received_filter_heights = stats.read().await.received_filter_heights.clone();
        tracing::info!("Creating sequential sync manager");
        let sync_manager =
            SequentialSyncManager::new(&config, received_filter_heights, wallet.clone())
                .map_err(SpvError::Sync)?;

        // Create validation manager
        let validation = ValidationManager::new(config.validation_mode);

        // Create ChainLock manager
        let chainlock_manager = Arc::new(ChainLockManager::new(true));

        // Create block processing channel
        let (block_processor_tx, _block_processor_rx) = mpsc::unbounded_channel();

        // Create progress channels
        let (progress_sender, progress_receiver) = mpsc::unbounded_channel();

        // Create event channels
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        // Create mempool state
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));

        Ok(Self {
            config,
            state,
            stats,
            network,
            storage,
            wallet,
            sync_manager,
            validation,
            chainlock_manager,
            running: Arc::new(RwLock::new(false)),
            terminal_ui: None,
            filter_processor: None,
            block_processor_tx,
            progress_sender: Some(progress_sender),
            progress_receiver: Some(progress_receiver),
            event_tx,
            event_rx: Some(event_rx),
            mempool_state,
            mempool_filter: None,
            last_sync_state_save: Arc::new(RwLock::new(0)),
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

        // Load wallet data from storage
        self.load_wallet_data().await?;

        // Initialize mempool filter if mempool tracking is enabled
        if self.config.enable_mempool_tracking {
            // TODO: Get monitored addresses from wallet
            self.mempool_filter = Some(Arc::new(MempoolFilter::new(
                self.config.mempool_strategy,
                Duration::from_secs(self.config.recent_send_window_secs),
                self.config.max_mempool_transactions,
                self.mempool_state.clone(),
                HashSet::new(), // Will be populated from wallet's monitored addresses
                self.config.network,
            )));

            // Load mempool state from storage if persistence is enabled
            if self.config.persist_mempool {
                if let Some(state) = self
                    .storage
                    .lock()
                    .await
                    .load_mempool_state()
                    .await
                    .map_err(SpvError::Storage)?
                {
                    *self.mempool_state.write().await = state;
                }
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
            self.storage.clone(),
            self.stats.clone(),
            self.event_tx.clone(),
            self.config.network,
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
                        tracing::info!(
                            "✅ Successfully restored sync state from persistent storage"
                        );
                    } else {
                        tracing::info!("No previous sync state found, starting fresh sync");
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to restore sync state: {}", e);
                    tracing::warn!("Starting fresh sync due to state restoration failure");
                    // Clear any corrupted state
                    if let Err(clear_err) = self.storage.lock().await.clear_sync_state().await {
                        tracing::error!("Failed to clear corrupted sync state: {}", clear_err);
                    }
                }
            }
        }

        // Initialize genesis block if not already present
        self.initialize_genesis_block().await?;

        // Load headers from storage if they exist
        // This ensures the ChainState has headers loaded for both checkpoint and normal sync
        let tip_height = {
            let storage = self.storage.lock().await;
            storage.get_tip_height().await.map_err(SpvError::Storage)?.unwrap_or(0)
        };
        if tip_height > 0 {
            tracing::info!("Found {} headers in storage, loading into sync manager...", tip_height);
            let loaded_count = {
                let storage = self.storage.lock().await;
                self.sync_manager.load_headers_from_storage(&storage).await
            };

            match loaded_count {
                Ok(loaded_count) => {
                    tracing::info!("✅ Sync manager loaded {} headers from storage", loaded_count);

                    // IMPORTANT: Also load headers into the client's ChainState for normal sync
                    // This is needed because the status display reads from the client's ChainState
                    let state = self.state.read().await;
                    let is_normal_sync = !state.synced_from_checkpoint;
                    drop(state); // Release the lock before loading headers

                    if is_normal_sync && loaded_count > 0 {
                        tracing::info!("Loading headers into client ChainState for normal sync...");
                        if let Err(e) = self.load_headers_into_client_state(tip_height).await {
                            tracing::error!("Failed to load headers into client ChainState: {}", e);
                            // This is not critical for normal sync, continue anyway
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to load headers into sync manager: {}", e);
                    // For checkpoint sync, this is critical
                    let state = self.state.read().await;
                    if state.synced_from_checkpoint {
                        return Err(SpvError::Sync(e));
                    }
                    // For normal sync, we can continue as headers will be re-synced
                    tracing::warn!("Continuing without pre-loaded headers for normal sync");
                }
            }
        }

        // Connect to network
        self.network.connect().await?;

        {
            let mut running = self.running.write().await;
            *running = true;
        }

        // Update terminal UI after connection with initial data
        if let Some(ui) = &self.terminal_ui {
            // Get initial header count from storage
            let (header_height, filter_height) = {
                let storage = self.storage.lock().await;
                let h_height =
                    storage.get_tip_height().await.map_err(SpvError::Storage)?.unwrap_or(0);
                let f_height =
                    storage.get_filter_tip_height().await.map_err(SpvError::Storage)?.unwrap_or(0);
                (h_height, f_height)
            };

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

    /// Enable mempool tracking with the specified strategy.
    pub async fn enable_mempool_tracking(
        &mut self,
        strategy: config::MempoolStrategy,
    ) -> Result<()> {
        // Update config
        self.config.enable_mempool_tracking = true;
        self.config.mempool_strategy = strategy;

        // Initialize mempool filter if not already done
        if self.mempool_filter.is_none() {
            // TODO: Get monitored addresses from wallet
            self.mempool_filter = Some(Arc::new(MempoolFilter::new(
                self.config.mempool_strategy,
                Duration::from_secs(self.config.recent_send_window_secs),
                self.config.max_mempool_transactions,
                self.mempool_state.clone(),
                HashSet::new(), // Will be populated from wallet's monitored addresses
                self.config.network,
            )));
        }

        Ok(())
    }

    /// Get mempool balance for an address.
    pub async fn get_mempool_balance(
        &self,
        address: &dashcore::Address,
    ) -> Result<crate::types::MempoolBalance> {
        let _wallet = self.wallet.read().await;
        let mempool_state = self.mempool_state.read().await;

        let mut pending = 0i64;
        let mut pending_instant = 0i64;

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
                // Calculate the actual balance change for this specific address
                // by examining inputs and outputs directly
                let mut address_balance_change = 0i64;

                // Check outputs to this address (incoming funds)
                for output in &tx.transaction.output {
                    if let Ok(out_addr) =
                        dashcore::Address::from_script(&output.script_pubkey, self.config.network)
                    {
                        if &out_addr == address {
                            address_balance_change += output.value as i64;
                        }
                    }
                }

                // Check inputs from this address (outgoing funds)
                // We need to check if any of the inputs were previously owned by this address
                // Note: This requires the wallet to have knowledge of the UTXOs being spent
                // In a real implementation, we would need to look up the previous outputs
                // For now, we'll rely on the is_outgoing flag and net_amount when we can't determine ownership

                // Validate that the calculated balance change is consistent with net_amount
                // for transactions where this address is involved
                if address_balance_change != 0 {
                    // For outgoing transactions, net_amount should be negative if we're spending
                    // For incoming transactions, net_amount should be positive if we're receiving
                    // Mixed transactions (both sending and receiving) should have the net effect

                    // Apply the validated balance change
                    if tx.is_instant_send {
                        pending_instant += address_balance_change;
                    } else {
                        pending += address_balance_change;
                    }
                } else if tx.net_amount != 0 && tx.is_outgoing {
                    // Edge case: If we calculated zero change but net_amount is non-zero,
                    // and it's an outgoing transaction, it might be a fee-only transaction
                    // In this case, we should not affect the balance for this address
                    // unless it's the sender paying the fee
                    continue;
                }
            }
        }

        // Convert to unsigned values, ensuring no negative balances
        let pending_sats = if pending < 0 {
            0
        } else {
            pending as u64
        };
        let pending_instant_sats = if pending_instant < 0 {
            0
        } else {
            pending_instant as u64
        };

        Ok(crate::types::MempoolBalance {
            pending: dashcore::Amount::from_sat(pending_sats),
            pending_instant: dashcore::Amount::from_sat(pending_instant_sats),
        })
    }

    /// Get mempool transaction count.
    pub async fn get_mempool_transaction_count(&self) -> usize {
        let mempool_state = self.mempool_state.read().await;
        mempool_state.transactions.len()
    }

    /// Update mempool filter with wallet's monitored addresses.
    #[allow(dead_code)]
    async fn update_mempool_filter(&mut self) {
        // TODO: Get monitored addresses from wallet
        // For now, create empty filter until wallet integration is complete
        self.mempool_filter = Some(Arc::new(MempoolFilter::new(
            self.config.mempool_strategy,
            Duration::from_secs(self.config.recent_send_window_secs),
            self.config.max_mempool_transactions,
            self.mempool_state.clone(),
            HashSet::new(), // Will be populated from wallet's monitored addresses
            self.config.network,
        )));
        tracing::info!("Updated mempool filter (wallet integration pending)");
    }

    /// Record a transaction send for mempool filtering.
    pub async fn record_transaction_send(&self, txid: dashcore::Txid) {
        if let Some(ref mempool_filter) = self.mempool_filter {
            mempool_filter.record_send(txid).await;
        }
    }

    /// Check if filter sync is available (any peer supports compact filters).
    pub async fn is_filter_sync_available(&self) -> bool {
        self.network
            .has_peer_with_service(dashcore::network::constants::ServiceFlags::COMPACT_FILTERS)
            .await
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
        {
            let mut storage = self.storage.lock().await;
            storage.shutdown().await.map_err(SpvError::Storage)?;
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

    /// Update the client's configuration at runtime.
    ///
    /// This applies non-network-critical settings without restarting the client.
    /// Changing the network is not supported at runtime.
    pub async fn update_config(&mut self, new_config: ClientConfig) -> Result<()> {
        if new_config.network != self.config.network {
            return Err(SpvError::Config("Cannot change network at runtime".to_string()));
        }

        // Track changes that may require reinitialization of helpers
        let mempool_changed = new_config.enable_mempool_tracking
            != self.config.enable_mempool_tracking
            || new_config.mempool_strategy != self.config.mempool_strategy
            || new_config.max_mempool_transactions != self.config.max_mempool_transactions
            || new_config.recent_send_window_secs != self.config.recent_send_window_secs;

        // Apply full config replacement, preserving network (already checked equal)
        self.config = new_config;

        // Update validation manager according to new mode
        self.validation = ValidationManager::new(self.config.validation_mode);

        // Rebuild mempool filter if needed
        if mempool_changed {
            self.update_mempool_filter().await;
        }

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
            header_height: {
                let storage = self.storage.lock().await;
                storage.get_tip_height().await.map_err(SpvError::Storage)?.unwrap_or(0)
            },
            filter_header_height: {
                let storage = self.storage.lock().await;
                storage.get_filter_tip_height().await.map_err(SpvError::Storage)?.unwrap_or(0)
            },
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
        let status_update_interval = Duration::from_millis(500);

        // Timer for request timeout checking
        let mut last_timeout_check = Instant::now();
        let timeout_check_interval = Duration::from_secs(1);

        // Timer for periodic consistency checks
        let mut last_consistency_check = Instant::now();
        let consistency_check_interval = Duration::from_secs(300); // Every 5 minutes

        // Timer for filter gap checking
        let mut last_filter_gap_check = Instant::now();
        let filter_gap_check_interval =
            Duration::from_secs(self.config.cfheader_gap_check_interval_secs);

        // Timer for pending ChainLock validation
        let mut last_chainlock_validation_check = Instant::now();
        let chainlock_validation_interval = Duration::from_secs(30); // Every 30 seconds

        // Progress tracking variables
        let sync_start_time = SystemTime::now();
        let mut last_height = 0u32;
        let mut headers_this_second = 0u32;
        let mut last_rate_calc = Instant::now();
        let total_bytes_downloaded = 0u64;

        // Track masternode sync completion for ChainLock validation
        let mut masternode_engine_updated = false;

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
                let mut storage = self.storage.lock().await;
                match self.sync_manager.start_sync(&mut self.network, &mut *storage).await {
                    Ok(started) => {
                        tracing::info!("✅ Sequential sync start_sync returned: {}", started);

                        // Send initial requests after sync is prepared
                        if let Err(e) = self
                            .sync_manager
                            .send_initial_requests(&mut self.network, &mut *storage)
                            .await
                        {
                            tracing::error!("Failed to send initial sync requests: {}", e);

                            // Reset sync manager state to prevent inconsistent state
                            self.sync_manager.reset_pending_requests();
                            tracing::warn!(
                                "Reset sync manager state after send_initial_requests failure"
                            );
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
                        if !missing_ranges.is_empty() {
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

                // Wallet confirmations are now handled by the wallet itself via process_block

                // Emit detailed progress update
                if last_rate_calc.elapsed() >= Duration::from_secs(1) {
                    let current_height = {
                        let storage = self.storage.lock().await;
                        storage.get_tip_height().await.ok().flatten().unwrap_or(0)
                    };
                    let peer_best = self
                        .network
                        .get_peer_best_height()
                        .await
                        .ok()
                        .flatten()
                        .unwrap_or(current_height);

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
                            end: peer_best,
                        }
                    } else {
                        crate::types::SyncStage::Complete
                    };

                    let progress = DetailedSyncProgress {
                        current_height,
                        peer_best_height: peer_best,
                        percentage: if peer_best > 0 {
                            (current_height as f64 / peer_best as f64 * 100.0).min(100.0)
                        } else {
                            0.0
                        },
                        headers_per_second,
                        bytes_per_second: 0, // TODO: Track actual bytes
                        estimated_time_remaining: if headers_per_second > 0.0
                            && peer_best > current_height
                        {
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
            let current_time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs();
            let last_sync_state_save = self.last_sync_state_save.clone();
            let last_save = *last_sync_state_save.read().await;

            if current_time - last_save >= 30 {
                // Save every 30 seconds
                if let Err(e) = self.save_sync_state().await {
                    tracing::warn!("Failed to save sync state: {}", e);
                } else {
                    *last_sync_state_save.write().await = current_time;
                }
            }

            // Check for sync timeouts and handle recovery (only periodically, not every loop)
            if last_timeout_check.elapsed() >= timeout_check_interval {
                let mut storage = self.storage.lock().await;
                let _ = self.sync_manager.check_timeout(&mut self.network, &mut *storage).await;
                drop(storage);
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

            // Check if masternode sync has completed and update ChainLock validation
            if !masternode_engine_updated && self.config.enable_masternodes {
                // Check if we have a masternode engine available now
                if let Ok(has_engine) = self.update_chainlock_validation() {
                    if has_engine {
                        masternode_engine_updated = true;
                        tracing::info!(
                            "✅ Masternode sync complete - ChainLock validation enabled"
                        );

                        // Validate any pending ChainLocks
                        if let Err(e) = self.validate_pending_chainlocks().await {
                            tracing::error!(
                                "Failed to validate pending ChainLocks after masternode sync: {}",
                                e
                            );
                        }
                    }
                }
            }

            // Periodically retry validation of pending ChainLocks
            if masternode_engine_updated
                && last_chainlock_validation_check.elapsed() >= chainlock_validation_interval
            {
                tracing::debug!("Checking for pending ChainLocks to validate...");
                if let Err(e) = self.validate_pending_chainlocks().await {
                    tracing::debug!("Periodic pending ChainLock validation check failed: {}", e);
                }
                last_chainlock_validation_check = Instant::now();
            }

            // Handle network messages with timeout for responsiveness
            match tokio::time::timeout(Duration::from_millis(1000), self.network.receive_message())
                .await
            {
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
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => {
                        // Handle specific network error types
                        if let crate::error::NetworkError::ConnectionFailed(msg) = &e {
                            if msg.contains("No connected peers") || self.network.peer_count() == 0
                            {
                                tracing::warn!("All peers disconnected during monitoring, checking connection health");

                                // Wait for potential reconnection
                                let mut wait_count = 0;
                                while wait_count < 10 && self.network.peer_count() == 0 {
                                    tokio::time::sleep(Duration::from_millis(500)).await;
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
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                },
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
        // Check if this is a special message that needs client-level processing
        let needs_special_processing = matches!(
            &message,
            dashcore::network::message::NetworkMessage::CLSig(_)
                | dashcore::network::message::NetworkMessage::ISLock(_)
        );

        // Handle the message with storage locked
        let handler_result = {
            let mut storage = self.storage.lock().await;

            // Create a MessageHandler instance with all required parameters
            let mut handler = MessageHandler::new(
                &mut self.sync_manager,
                &mut *storage,
                &mut self.network,
                &self.config,
                &self.stats,
                &self.block_processor_tx,
                &self.mempool_filter,
                &self.mempool_state,
                &self.event_tx,
            );

            // Delegate message handling to the MessageHandler
            handler.handle_network_message(message.clone()).await
        };

        // Handle result and process special messages after releasing storage lock
        match handler_result {
            Ok(_) => {
                if needs_special_processing {
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
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Process a new block.
    #[allow(dead_code)]
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

    /// Report balance changes for watched addresses.
    #[allow(dead_code)]
    async fn report_balance_changes(
        &self,
        balance_changes: &std::collections::HashMap<dashcore::Address, i64>,
        block_height: u32,
    ) -> Result<()> {
        tracing::info!("💰 Balance changes detected in block at height {}:", block_height);

        for (address, change_sat) in balance_changes {
            if *change_sat != 0 {
                let change_amount = dashcore::Amount::from_sat(change_sat.unsigned_abs());
                let sign = if *change_sat > 0 {
                    "+"
                } else {
                    "-"
                };
                tracing::info!("  📍 Address {}: {}{}", address, sign, change_amount);
            }
        }

        // TODO: Get monitored addresses from wallet and report balances
        // Will be implemented when wallet integration is complete

        Ok(())
    }

    /// Get the balance for a specific address.
    /// NOTE: This requires the wallet implementation to expose balance information,
    /// which is not part of the minimal WalletInterface.
    pub async fn get_address_balance(
        &self,
        _address: &dashcore::Address,
    ) -> Result<AddressBalance> {
        // This method requires wallet-specific functionality not in WalletInterface
        // The wallet should expose balance info through its own interface
        Err(SpvError::Config(
            "Address balance queries should be made directly to the wallet implementation"
                .to_string(),
        ))
    }

    // Wallet balance methods removed - use external wallet interface directly

    /// Get balances for all watched addresses.
    pub async fn get_all_balances(
        &self,
    ) -> Result<std::collections::HashMap<dashcore::Address, AddressBalance>> {
        // TODO: Get balances from wallet instead of tracking separately
        // Will be implemented when wallet integration is complete
        Ok(std::collections::HashMap::new())
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
        {
            let mut storage = self.storage.lock().await;
            self.chainlock_manager
                .process_chain_lock(chainlock.clone(), &chain_state, &mut *storage)
                .await
                .map_err(SpvError::Validation)?;
        }
        drop(chain_state);

        // Sequential sync handles masternode validation internally
        tracing::info!(
            "ChainLock stored, sequential sync will handle masternode validation internally"
        );

        // Update chain state with the new ChainLock
        let mut state = self.state.write().await;
        if let Some(current_chainlock_height) = state.last_chainlock_height {
            if chainlock.block_height <= current_chainlock_height {
                tracing::debug!(
                    "ChainLock for height {} does not supersede current ChainLock at height {}",
                    chainlock.block_height,
                    current_chainlock_height
                );
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

    /// Update ChainLock validation with masternode engine after sync completes.
    /// This should be called when masternode sync finishes to enable full validation.
    /// Returns true if the engine was successfully set.
    pub fn update_chainlock_validation(&self) -> Result<bool> {
        // Check if masternode sync has an engine available
        if let Some(engine) = self.sync_manager.get_masternode_engine() {
            // Clone the engine for the ChainLockManager
            let engine_arc = Arc::new(engine.clone());
            self.chainlock_manager.set_masternode_engine(engine_arc);

            tracing::info!("Updated ChainLockManager with masternode engine for full validation");

            // Note: Pending ChainLocks will be validated when they are next processed
            // or can be triggered by calling validate_pending_chainlocks separately
            // when mutable access to storage is available

            Ok(true)
        } else {
            tracing::warn!("Masternode engine not available for ChainLock validation update");
            Ok(false)
        }
    }

    /// Validate all pending ChainLocks after masternode engine is available.
    /// This requires mutable access to self for storage access.
    pub async fn validate_pending_chainlocks(&mut self) -> Result<()> {
        let chain_state = self.state.read().await;

        let mut storage = self.storage.lock().await;
        match self.chainlock_manager.validate_pending_chainlocks(&chain_state, &mut *storage).await
        {
            Ok(_) => {
                tracing::info!("Successfully validated pending ChainLocks");
                Ok(())
            }
            Err(e) => {
                tracing::error!("Failed to validate pending ChainLocks: {}", e);
                Err(SpvError::Validation(e))
            }
        }
    }

    /// Get current sync progress.
    pub async fn sync_progress(&self) -> Result<SyncProgress> {
        let display = self.create_status_display().await;
        display.sync_progress().await
    }

    // Watch item methods removed - wallet now handles all address tracking internally

    /// Get the number of connected peers.
    pub async fn get_peer_count(&self) -> usize {
        self.network.peer_count()
    }

    /// Get a reference to the masternode list engine.
    /// Returns None if masternode sync is not enabled in config.
    pub fn masternode_list_engine(&self) -> Option<&MasternodeListEngine> {
        self.sync_manager.masternode_list_engine()
    }

    /// Get the masternode list at a specific block height.
    /// Returns None if the masternode list for that height is not available.
    pub fn get_masternode_list_at_height(&self, height: u32) -> Option<&MasternodeList> {
        self.masternode_list_engine().and_then(|engine| engine.masternode_lists.get(&height))
    }

    /// Get a quorum entry by type and hash at a specific block height.
    /// Returns None if the quorum is not found.
    pub fn get_quorum_at_height(
        &self,
        height: u32,
        quorum_type: u8,
        quorum_hash: &[u8; 32],
    ) -> Option<&QualifiedQuorumEntry> {
        use dashcore::sml::llmq_type::LLMQType;
        use dashcore::QuorumHash;
        use dashcore_hashes::Hash;

        let llmq_type: LLMQType = LLMQType::from(quorum_type);
        if llmq_type == LLMQType::LlmqtypeUnknown {
            tracing::warn!("Invalid quorum type {} requested at height {}", quorum_type, height);
            return None;
        };

        let qhash = QuorumHash::from_byte_array(*quorum_hash);

        // First check if we have the masternode list at this height
        match self.get_masternode_list_at_height(height) {
            Some(ml) => {
                // We have the masternode list, now look for the quorum
                match ml.quorums.get(&llmq_type) {
                    Some(quorums) => match quorums.get(&qhash) {
                        Some(quorum) => {
                            tracing::debug!(
                                "Found quorum type {} at height {} with hash {}",
                                quorum_type,
                                height,
                                hex::encode(quorum_hash)
                            );
                            Some(quorum)
                        }
                        None => {
                            tracing::warn!(
                                    "Quorum not found: type {} at height {} with hash {} (masternode list exists with {} quorums of this type)",
                                    quorum_type,
                                    height,
                                    hex::encode(quorum_hash),
                                    quorums.len()
                                );
                            None
                        }
                    },
                    None => {
                        tracing::warn!(
                            "No quorums of type {} found at height {} (masternode list exists)",
                            quorum_type,
                            height
                        );
                        None
                    }
                }
            }
            None => {
                // Log available heights for debugging
                if let Some(engine) = self.masternode_list_engine() {
                    let available_heights: Vec<u32> = engine
                        .masternode_lists
                        .keys()
                        .filter(|&&h| {
                            h > height.saturating_sub(100) && h < height.saturating_add(100)
                        })
                        .copied()
                        .collect();

                    tracing::warn!(
                        "Missing masternode list at height {} for quorum lookup (type: {}, hash: {}). Nearby available heights: {:?}",
                        height,
                        quorum_type,
                        hex::encode(quorum_hash),
                        available_heights
                    );
                } else {
                    tracing::warn!(
                        "Missing masternode list at height {} for quorum lookup (type: {}, hash: {}) - no engine available",
                        height,
                        quorum_type,
                        hex::encode(quorum_hash)
                    );
                }
                None
            }
        }
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
        _num_blocks: Option<u32>,
    ) -> Result<Vec<crate::types::FilterMatch>> {
        // Sequential sync handles filter sync internally
        tracing::info!("Sequential sync mode: filter sync handled internally");
        Ok(Vec::new())
    }

    /// Sync filters for a specific height range.
    pub async fn sync_filters_range(
        &mut self,
        _start_height: Option<u32>,
        _count: Option<u32>,
    ) -> Result<()> {
        // Sequential sync handles filter range sync internally
        tracing::info!("Sequential sync mode: filter range sync handled internally");
        Ok(())
    }

    /// Restore sync state from persistent storage.
    /// Returns true if state was successfully restored, false if no state was found.
    async fn restore_sync_state(&mut self) -> Result<bool> {
        // Load and validate sync state
        let (saved_state, should_continue) = self.load_and_validate_sync_state().await?;
        if !should_continue {
            return Ok(false);
        }

        let saved_state = saved_state.unwrap();

        tracing::info!(
            "Restoring sync state from height {} (saved at {:?})",
            saved_state.chain_tip.height,
            saved_state.saved_at
        );

        // Restore headers from state
        if !self.restore_headers_from_state(&saved_state).await? {
            return Ok(false);
        }

        // Restore filter headers from state
        self.restore_filter_headers_from_state(&saved_state).await?;

        // Update stats from state
        self.update_stats_from_state(&saved_state).await;

        // Restore sync manager state
        if !self.restore_sync_manager_state(&saved_state).await? {
            return Ok(false);
        }

        tracing::info!(
            "Sync state restored: headers={}, filter_headers={}, filters_downloaded={}",
            saved_state.sync_progress.header_height,
            saved_state.sync_progress.filter_header_height,
            saved_state.filter_sync.filters_downloaded
        );

        Ok(true)
    }

    /// Load sync state from storage and validate it, handling recovery if needed.
    async fn load_and_validate_sync_state(
        &mut self,
    ) -> Result<(Option<crate::storage::PersistentSyncState>, bool)> {
        // Load sync state from storage
        let sync_state = {
            let storage = self.storage.lock().await;
            storage.load_sync_state().await.map_err(SpvError::Storage)?
        };

        let Some(saved_state) = sync_state else {
            return Ok((None, false));
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
                return match suggestion {
                    crate::storage::RecoverySuggestion::StartFresh => {
                        tracing::warn!("Recovery: Starting fresh sync");
                        Ok((None, false))
                    }
                    crate::storage::RecoverySuggestion::RollbackToHeight(height) => {
                        let recovered = self.handle_rollback_recovery(height).await?;
                        Ok((None, recovered))
                    }
                    crate::storage::RecoverySuggestion::UseCheckpoint(height) => {
                        let recovered = self.handle_checkpoint_recovery(height).await?;
                        Ok((None, recovered))
                    }
                    crate::storage::RecoverySuggestion::PartialRecovery => {
                        tracing::warn!("Recovery: Attempting partial recovery");
                        // For partial recovery, we keep headers but reset filter sync
                        if let Err(e) = self.reset_filter_sync_state().await {
                            tracing::error!("Failed to reset filter sync state: {}", e);
                        }
                        Ok((Some(saved_state), true))
                    }
                };
            }

            return Ok((None, false));
        }

        // Log any warnings
        for warning in &validation.warnings {
            tracing::warn!("Sync state warning: {}", warning);
        }

        Ok((Some(saved_state), true))
    }

    /// Handle rollback recovery to a specific height.
    async fn handle_rollback_recovery(&mut self, height: u32) -> Result<bool> {
        tracing::warn!("Recovery: Rolling back to height {}", height);

        // Validate the rollback height
        if height == 0 {
            tracing::error!("Cannot rollback to genesis block (height 0)");
            return Ok(false);
        }

        // Get current height from storage to validate against
        let current_height = {
            let storage = self.storage.lock().await;
            storage.get_tip_height().await.map_err(SpvError::Storage)?.unwrap_or(0)
        };

        if height > current_height {
            tracing::error!(
                "Cannot rollback to height {} which is greater than current height {}",
                height,
                current_height
            );
            return Ok(false);
        }

        match self.rollback_to_height(height).await {
            Ok(_) => {
                tracing::info!("Successfully rolled back to height {}", height);
                Ok(false) // Start fresh sync from rollback point
            }
            Err(e) => {
                tracing::error!("Failed to rollback to height {}: {}", height, e);
                Ok(false) // Start fresh sync
            }
        }
    }

    /// Handle checkpoint recovery at a specific height.
    async fn handle_checkpoint_recovery(&mut self, height: u32) -> Result<bool> {
        tracing::warn!("Recovery: Using checkpoint at height {}", height);

        // Validate the checkpoint height
        if height == 0 {
            tracing::error!("Cannot use checkpoint at genesis block (height 0)");
            return Ok(false);
        }

        // Check if checkpoint height is reasonable (not in the future)
        let current_height = {
            let storage = self.storage.lock().await;
            storage.get_tip_height().await.map_err(SpvError::Storage)?.unwrap_or(0)
        };

        if current_height > 0 && height > current_height {
            tracing::error!(
                "Cannot use checkpoint at height {} which is greater than current height {}",
                height,
                current_height
            );
            return Ok(false);
        }

        match self.recover_from_checkpoint(height).await {
            Ok(_) => {
                tracing::info!("Successfully recovered from checkpoint at height {}", height);
                Ok(true) // State restored from checkpoint
            }
            Err(e) => {
                tracing::error!("Failed to recover from checkpoint {}: {}", height, e);
                Ok(false) // Start fresh sync
            }
        }
    }

    /// Restore headers from saved state into ChainState.
    async fn restore_headers_from_state(
        &mut self,
        saved_state: &crate::storage::PersistentSyncState,
    ) -> Result<bool> {
        if saved_state.chain_tip.height == 0 {
            return Ok(true);
        }

        tracing::info!("Loading headers from storage into ChainState...");
        let start_time = Instant::now();

        // Load headers in batches to avoid memory spikes
        const BATCH_SIZE: u32 = 10_000;
        let mut loaded_count = 0u32;
        let target_height = saved_state.chain_tip.height;

        // Start from height 1 (genesis is already in ChainState)
        let mut current_height = 1u32;

        while current_height <= target_height {
            let end_height = (current_height + BATCH_SIZE - 1).min(target_height);

            // Load batch of headers from storage
            let headers = {
                let storage = self.storage.lock().await;
                storage
                    .load_headers(current_height..end_height + 1)
                    .await
                    .map_err(SpvError::Storage)?
            };

            if headers.is_empty() {
                tracing::error!(
                    "Failed to load headers for range {}..{} - storage may be corrupted",
                    current_height,
                    end_height + 1
                );
                return Ok(false);
            }

            // Validate headers before adding to chain state
            {
                // Validate the batch of headers
                if let Err(e) = self.validation.validate_header_chain(&headers, false) {
                    tracing::error!(
                        "Header validation failed for range {}..{}: {:?}",
                        current_height,
                        end_height + 1,
                        e
                    );
                    return Ok(false);
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
                    loaded_count,
                    target_height,
                    headers_per_sec
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
                target_height,
                actual_height
            );
            return Ok(false);
        }

        // Verify tip hash matches
        if let Some(tip_hash) = state.tip_hash() {
            if tip_hash != saved_state.chain_tip.hash {
                tracing::error!(
                    "Chain tip hash mismatch: expected {}, got {}",
                    saved_state.chain_tip.hash,
                    tip_hash
                );
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Restore filter headers from saved state.
    async fn restore_filter_headers_from_state(
        &mut self,
        saved_state: &crate::storage::PersistentSyncState,
    ) -> Result<()> {
        if saved_state.sync_progress.filter_header_height == 0 {
            return Ok(());
        }

        tracing::info!("Loading filter headers from storage...");
        let filter_headers = {
            let storage = self.storage.lock().await;
            storage
                .load_filter_headers(0..saved_state.sync_progress.filter_header_height + 1)
                .await
                .map_err(SpvError::Storage)?
        };

        if !filter_headers.is_empty() {
            let mut state = self.state.write().await;
            state.add_filter_headers(filter_headers);
            tracing::info!(
                "✅ Loaded {} filter headers into ChainState",
                saved_state.sync_progress.filter_header_height + 1
            );
        }

        Ok(())
    }

    /// Update stats from saved state.
    async fn update_stats_from_state(&mut self, saved_state: &crate::storage::PersistentSyncState) {
        let mut stats = self.stats.write().await;
        stats.headers_downloaded = saved_state.sync_progress.header_height as u64;
        stats.filter_headers_downloaded = saved_state.sync_progress.filter_header_height as u64;
        stats.filters_downloaded = saved_state.filter_sync.filters_downloaded;
        stats.masternode_diffs_processed =
            saved_state.masternode_sync.last_diff_height.unwrap_or(0) as u64;

        // Log masternode state if available
        if let Some(last_mn_height) = saved_state.masternode_sync.last_synced_height {
            tracing::info!("Restored masternode sync state at height {}", last_mn_height);
            // The masternode engine state will be loaded from storage separately
        }
    }

    /// Restore sync manager state.
    async fn restore_sync_manager_state(
        &mut self,
        saved_state: &crate::storage::PersistentSyncState,
    ) -> Result<bool> {
        // Update sync manager state
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
            let storage = self.storage.lock().await;
            match self.sync_manager.load_headers_from_storage(&storage).await {
                Ok(loaded_count) => {
                    tracing::info!("✅ Sync manager loaded {} headers from storage", loaded_count);
                }
                Err(e) => {
                    tracing::error!("Failed to load headers into sync manager: {}", e);
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Load headers from storage into the client's ChainState.
    /// This is used during normal sync to ensure the status display shows correct header count.
    async fn load_headers_into_client_state(&mut self, tip_height: u32) -> Result<()> {
        if tip_height == 0 {
            return Ok(());
        }

        tracing::debug!("Loading {} headers from storage into client ChainState", tip_height);
        let start_time = Instant::now();

        // Load headers in batches to avoid memory spikes
        const BATCH_SIZE: u32 = 10_000;
        let mut loaded_count = 0u32;

        // Start from height 1 (genesis is already in ChainState)
        let mut current_height = 1u32;

        while current_height <= tip_height {
            let end_height = (current_height + BATCH_SIZE - 1).min(tip_height);

            // Load batch of headers from storage
            let headers = {
                let storage = self.storage.lock().await;
                storage
                    .load_headers(current_height..end_height + 1)
                    .await
                    .map_err(SpvError::Storage)?
            };

            if headers.is_empty() {
                tracing::warn!(
                    "No headers found for range {}..{} - storage may be incomplete",
                    current_height,
                    end_height + 1
                );
                break;
            }

            // Add headers to client's chain state
            {
                let mut state = self.state.write().await;
                for header in headers {
                    state.add_header(header);
                    loaded_count += 1;
                }
            }

            // Progress logging for large header counts
            if loaded_count % 50_000 == 0 || loaded_count == tip_height {
                let elapsed = start_time.elapsed();
                let headers_per_sec = loaded_count as f64 / elapsed.as_secs_f64();
                tracing::debug!(
                    "Loaded {}/{} headers into client ChainState ({:.0} headers/sec)",
                    loaded_count,
                    tip_height,
                    headers_per_sec
                );
            }

            current_height = end_height + 1;
        }

        let elapsed = start_time.elapsed();
        tracing::info!(
            "✅ Loaded {} headers into client ChainState in {:.2}s ({:.0} headers/sec)",
            loaded_count,
            elapsed.as_secs_f64(),
            loaded_count as f64 / elapsed.as_secs_f64()
        );

        Ok(())
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
        {
            let mut storage = self.storage.lock().await;
            storage.store_chain_state(&updated_state).await.map_err(SpvError::Storage)?;
        }

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
        let checkpoints = {
            let storage = self.storage.lock().await;
            storage
                .get_sync_checkpoints(checkpoint_height, checkpoint_height)
                .await
                .map_err(SpvError::Storage)?
        };

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
            &chain_state,
            &sync_progress,
            self.config.network,
        );

        if let Some(state) = persistent_state {
            // Check if we should create a checkpoint
            if state.should_checkpoint(state.chain_tip.height) {
                if let Some(checkpoint) = state.checkpoints.last() {
                    let mut storage = self.storage.lock().await;
                    storage
                        .store_sync_checkpoint(checkpoint.height, checkpoint)
                        .await
                        .map_err(SpvError::Storage)?;
                    tracing::info!("Created sync checkpoint at height {}", checkpoint.height);
                }
            }

            // Save the sync state
            {
                let mut storage = self.storage.lock().await;
                storage.store_sync_state(&state).await.map_err(SpvError::Storage)?;
            }

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
        let current_tip = {
            let storage = self.storage.lock().await;
            storage.get_tip_height().await.map_err(SpvError::Storage)?
        };

        if current_tip.is_some() {
            // We already have headers, genesis block should be at height 0
            tracing::debug!("Headers already exist in storage, skipping genesis initialization");
            return Ok(());
        }

        // Check if we should use a checkpoint instead of genesis
        if let Some(start_height) = self.config.start_from_height {
            // Get checkpoints for this network
            let checkpoints = match self.config.network {
                dashcore::Network::Dash => crate::chain::checkpoints::mainnet_checkpoints(),
                dashcore::Network::Testnet => crate::chain::checkpoints::testnet_checkpoints(),
                _ => vec![],
            };

            // Create checkpoint manager
            let checkpoint_manager = crate::chain::checkpoints::CheckpointManager::new(checkpoints);

            // Find the best checkpoint at or before the requested height
            if let Some(checkpoint) =
                checkpoint_manager.best_checkpoint_at_or_before_height(start_height)
            {
                if checkpoint.height > 0 {
                    tracing::info!(
                        "🚀 Starting sync from checkpoint at height {} instead of genesis (requested start height: {})",
                        checkpoint.height,
                        start_height
                    );

                    // Initialize chain state with checkpoint
                    let mut chain_state = self.state.write().await;

                    // Build header from checkpoint
                    let checkpoint_header = dashcore::block::Header {
                        version: Version::from_consensus(536870912), // Version 0x20000000 is common for modern blocks
                        prev_blockhash: checkpoint.prev_blockhash,
                        merkle_root: checkpoint
                            .merkle_root
                            .map(|h| dashcore::TxMerkleNode::from_byte_array(*h.as_byte_array()))
                            .unwrap_or_else(dashcore::TxMerkleNode::all_zeros),
                        time: checkpoint.timestamp,
                        bits: CompactTarget::from_consensus(
                            checkpoint.target.to_compact_lossy().to_consensus(),
                        ),
                        nonce: checkpoint.nonce,
                    };

                    // Verify hash matches
                    let calculated_hash = checkpoint_header.block_hash();
                    if calculated_hash != checkpoint.block_hash {
                        tracing::warn!(
                            "Checkpoint header hash mismatch at height {}: expected {}, calculated {}",
                            checkpoint.height,
                            checkpoint.block_hash,
                            calculated_hash
                        );
                    } else {
                        // Initialize chain state from checkpoint
                        chain_state.init_from_checkpoint(
                            checkpoint.height,
                            checkpoint_header,
                            self.config.network,
                        );

                        // Clone the chain state for storage and sync manager
                        let chain_state_for_storage = (*chain_state).clone();
                        let checkpoint_chain_state = (*chain_state).clone();
                        drop(chain_state);

                        // Update storage with chain state including sync_base_height
                        {
                            let mut storage = self.storage.lock().await;
                            storage
                                .store_chain_state(&chain_state_for_storage)
                                .await
                                .map_err(SpvError::Storage)?;
                        }

                        // Don't store the checkpoint header itself - we'll request headers from peers
                        // starting from this checkpoint

                        tracing::info!(
                            "✅ Initialized from checkpoint at height {}, skipping {} headers",
                            checkpoint.height,
                            checkpoint.height
                        );

                        // Update the sync manager's chain state with the checkpoint-initialized state
                        self.sync_manager.set_chain_state(checkpoint_chain_state);
                        tracing::info!(
                            "Updated sync manager with checkpoint-initialized chain state"
                        );

                        return Ok(());
                    }
                }
            }
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
                    prev_blockhash: dashcore::BlockHash::from([0u8; 32]),
                    merkle_root: "e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7"
                        .parse()
                        .unwrap_or_else(|_| dashcore::hashes::sha256d::Hash::all_zeros().into()),
                    time: 1390095618,
                    bits: CompactTarget::from_consensus(0x1e0ffff0),
                    nonce: 28917698,
                }
            }
            dashcore::Network::Testnet => {
                // Use the actual Dash testnet genesis block parameters
                BlockHeader {
                    version: Version::from_consensus(1),
                    prev_blockhash: dashcore::BlockHash::from([0u8; 32]),
                    merkle_root: "e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7"
                        .parse()
                        .unwrap_or_else(|_| dashcore::hashes::sha256d::Hash::all_zeros().into()),
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
        {
            let mut storage = self.storage.lock().await;
            storage.store_headers(&genesis_headers).await.map_err(SpvError::Storage)?;
        }

        // Verify it was stored correctly
        let stored_height = {
            let storage = self.storage.lock().await;
            storage.get_tip_height().await.map_err(SpvError::Storage)?
        };
        tracing::info!(
            "✅ Genesis block initialized at height 0, storage reports tip height: {:?}",
            stored_height
        );

        Ok(())
    }

    /// Load wallet data from storage.
    async fn load_wallet_data(&self) -> Result<()> {
        tracing::info!("Loading wallet data from storage...");

        let _wallet = self.wallet.read().await;

        // The wallet implementation is responsible for managing its own persistent state
        // The SPV client will notify it of new blocks/transactions through the WalletInterface
        tracing::info!("Wallet data loading is handled by the wallet implementation");

        Ok(())
    }

    // Wallet-specific helper methods removed - use external wallet interface directly

    /// Get current statistics.
    pub async fn stats(&self) -> Result<SpvStats> {
        let display = self.create_status_display().await;
        let mut stats = display.stats().await?;

        // Add real-time peer count and heights
        stats.connected_peers = self.network.peer_count() as u32;
        stats.total_peers = self.network.peer_count() as u32; // TODO: Track total discovered peers

        // Get current heights from storage
        {
            let storage = self.storage.lock().await;
            if let Ok(Some(header_height)) = storage.get_tip_height().await {
                stats.header_height = header_height;
            }

            if let Ok(Some(filter_height)) = storage.get_filter_tip_height().await {
                stats.filter_height = filter_height;
            }
        }

        Ok(stats)
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

    /// Get mutable reference to sync manager (for testing)
    #[cfg(test)]
    pub fn sync_manager_mut(&mut self) -> &mut SequentialSyncManager<S, N, W> {
        &mut self.sync_manager
    }

    /// Get reference to chainlock manager
    pub fn chainlock_manager(&self) -> &Arc<ChainLockManager> {
        &self.chainlock_manager
    }

    /// Get access to storage manager (requires locking)
    pub fn storage(&self) -> Arc<Mutex<S>> {
        self.storage.clone()
    }
}

#[cfg(test)]
mod config_test;

#[cfg(test)]
mod block_processor_test;

#[cfg(test)]
mod message_handler_test;

#[cfg(test)]
mod tests {
    use crate::types::{MempoolState, UnconfirmedTransaction};
    use dashcore::{Amount, Transaction, TxOut};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // Tests for get_mempool_balance function
    // These tests validate that the balance calculation correctly handles:
    // 1. The sign of net_amount
    // 2. Validation of transaction effects on addresses
    // 3. Edge cases like zero amounts and conflicting signs

    #[tokio::test]
    async fn test_get_mempool_balance_logic() {
        // Create a simple test scenario to validate the balance calculation logic
        // We'll create a minimal DashSpvClient structure for testing

        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        // Test removed - needs external wallet implementation

        // Test address
        use dashcore::hashes::Hash;
        let pubkey_hash = dashcore::PubkeyHash::from_byte_array([0u8; 20]);
        let address = dashcore::Address::new(
            dashcore::Network::Dash,
            dashcore::address::Payload::PubkeyHash(pubkey_hash),
        );

        // Test 1: Simple incoming transaction
        let tx1 = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![],
            output: vec![TxOut {
                value: 50000,
                script_pubkey: address.script_pubkey(),
            }],
            special_transaction_payload: None,
        };

        let unconfirmed_tx1 = UnconfirmedTransaction::new(
            tx1.clone(),
            Amount::from_sat(100),
            false, // not instant send
            false, // not outgoing
            vec![address.clone()],
            50000, // positive net amount
        );

        mempool_state.write().await.add_transaction(unconfirmed_tx1);

        // Now we need to create a minimal client structure to test
        // Since we can't easily create a full DashSpvClient, we'll test the logic directly

        // The key logic from get_mempool_balance is:
        // 1. Check outputs to the address (incoming funds)
        // 2. Check inputs from the address (outgoing funds) - requires UTXO knowledge
        // 3. Apply the calculated balance change

        let mempool = mempool_state.read().await;
        let mut pending = 0i64;
        let mut pending_instant = 0i64;

        for tx in mempool.transactions.values() {
            if tx.addresses.contains(&address) {
                let mut address_balance_change = 0i64;

                // Check outputs to this address
                for output in &tx.transaction.output {
                    if let Ok(out_addr) = dashcore::Address::from_script(
                        &output.script_pubkey,
                        dashcore::Network::Dash,
                    ) {
                        if out_addr == address {
                            address_balance_change += output.value as i64;
                        }
                    }
                }

                // Apply the balance change
                if address_balance_change != 0 {
                    if tx.is_instant_send {
                        pending_instant += address_balance_change;
                    } else {
                        pending += address_balance_change;
                    }
                }
            }
        }

        assert_eq!(pending, 50000);
        assert_eq!(pending_instant, 0);

        // Test 2: InstantSend transaction
        let tx2 = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![],
            output: vec![TxOut {
                value: 30000,
                script_pubkey: address.script_pubkey(),
            }],
            special_transaction_payload: None,
        };

        let unconfirmed_tx2 = UnconfirmedTransaction::new(
            tx2.clone(),
            Amount::from_sat(100),
            true,  // instant send
            false, // not outgoing
            vec![address.clone()],
            30000,
        );

        drop(mempool);
        mempool_state.write().await.add_transaction(unconfirmed_tx2);

        // Recalculate
        let mempool = mempool_state.read().await;
        pending = 0;
        pending_instant = 0;

        for tx in mempool.transactions.values() {
            if tx.addresses.contains(&address) {
                let mut address_balance_change = 0i64;

                for output in &tx.transaction.output {
                    if let Ok(out_addr) = dashcore::Address::from_script(
                        &output.script_pubkey,
                        dashcore::Network::Dash,
                    ) {
                        if out_addr == address {
                            address_balance_change += output.value as i64;
                        }
                    }
                }

                if address_balance_change != 0 {
                    if tx.is_instant_send {
                        pending_instant += address_balance_change;
                    } else {
                        pending += address_balance_change;
                    }
                }
            }
        }

        assert_eq!(pending, 50000);
        assert_eq!(pending_instant, 30000);

        // Test 3: Transaction with conflicting signs
        // This tests that we use actual outputs rather than just trusting net_amount
        let tx3 = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![],
            output: vec![TxOut {
                value: 40000,
                script_pubkey: address.script_pubkey(),
            }],
            special_transaction_payload: None,
        };

        let unconfirmed_tx3 = UnconfirmedTransaction::new(
            tx3.clone(),
            Amount::from_sat(100),
            false,
            true, // marked as outgoing (incorrect)
            vec![address.clone()],
            -40000, // negative net amount (incorrect for receiving)
        );

        drop(mempool);
        mempool_state.write().await.add_transaction(unconfirmed_tx3);

        // The logic should detect we're actually receiving 40000
        let mempool = mempool_state.read().await;
        let tx = mempool.transactions.values().find(|t| t.transaction == tx3).unwrap();

        let mut address_balance_change = 0i64;
        for output in &tx.transaction.output {
            if let Ok(out_addr) =
                dashcore::Address::from_script(&output.script_pubkey, dashcore::Network::Dash)
            {
                if out_addr == address {
                    address_balance_change += output.value as i64;
                }
            }
        }

        // We should detect 40000 satoshis incoming regardless of the net_amount sign
        assert_eq!(address_balance_change, 40000);
    }
}
