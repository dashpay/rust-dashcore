//! Sync coordination and orchestration.
//!
//! This module contains the core sync orchestration logic:
//! - sync_to_tip: Initiate blockchain sync
//! - monitor_network: Main event loop for processing network messages
//! - Sync state persistence and restoration
//! - Filter sync coordination
//! - Block processing delegation
//! - Balance change reporting
//!
//! This is the largest module as it handles all coordination between network,
//! storage, and the sync manager.

use super::{BlockProcessingTask, DashSpvClient, MessageHandler};
use crate::client::interface::DashSpvClientCommand;
use crate::error::{Result, SpvError};
use crate::network::constants::MESSAGE_RECEIVE_TIMEOUT;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::headers::validate_headers;
use crate::types::{DetailedSyncProgress, SyncProgress};
use crate::ValidationMode;
use key_wallet_manager::wallet_interface::WalletInterface;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_util::sync::CancellationToken;

impl<
        W: WalletInterface + Send + Sync + 'static,
        N: NetworkManager + Send + Sync + 'static,
        S: StorageManager + Send + Sync + 'static,
    > DashSpvClient<W, N, S>
{
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
            ..SyncProgress::default()
        };

        // Update status display after initial sync
        self.update_status_display().await;

        tracing::info!(
            "✅ Prepared initial sync state - Headers: {}, Filter headers: {}",
            result.header_height,
            result.filter_header_height
        );
        tracing::info!("📊 Sync requests will be sent by the monitoring loop");

        Ok(result)
    }

    /// Run continuous monitoring for new blocks, ChainLocks, InstantLocks, etc.
    ///
    /// This is the sole network message receiver to prevent race conditions.
    /// All sync operations coordinate through this monitoring loop.
    pub async fn monitor_network(
        &mut self,
        mut command_receiver: UnboundedReceiver<DashSpvClientCommand>,
        token: CancellationToken,
    ) -> Result<()> {
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

        // Last emitted heights for filter headers progress to avoid duplicate events
        let mut last_emitted_header_height: u32 = 0;
        let mut last_emitted_filter_header_height: u32 = 0;
        let mut last_emitted_filters_downloaded: u64 = 0;
        let mut last_emitted_phase_name: Option<String> = None;

        loop {
            // Check if we should stop
            let running = self.running.read().await;
            if !*running {
                tracing::info!("Stopping network monitoring");
                break;
            }
            drop(running);

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
                    // Storage tip now represents the absolute blockchain height.
                    let current_tip_height = {
                        let storage = self.storage.lock().await;
                        storage.get_tip_height().await.ok().flatten().unwrap_or(0)
                    };
                    let current_height = current_tip_height;
                    let peer_best = self
                        .network
                        .get_peer_best_height()
                        .await
                        .ok()
                        .flatten()
                        .unwrap_or(current_height);

                    // Calculate headers downloaded this second
                    if current_tip_height > last_height {
                        headers_this_second = current_tip_height - last_height;
                        last_height = current_tip_height;
                    }

                    let headers_per_second = headers_this_second as f64;
                    let peer_count = self.network.peer_count() as u32;
                    let phase_snapshot = self.sync_manager.current_phase().clone();

                    let status_display = self.create_status_display().await;
                    let mut sync_progress = match status_display.sync_progress().await {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!("Failed to compute sync progress snapshot: {}", e);
                            SyncProgress::default()
                        }
                    };

                    // Update peer count with the latest network information.
                    sync_progress.peer_count = peer_count;
                    sync_progress.header_height = current_height;
                    sync_progress.filter_sync_available = self.config.enable_filters;

                    let sync_stage =
                        Self::map_phase_to_stage(&phase_snapshot, &sync_progress, peer_best);
                    let filters_downloaded = sync_progress.filters_downloaded;

                    let progress = DetailedSyncProgress {
                        sync_progress,
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
                        total_headers_processed: current_height as u64,
                        total_bytes_downloaded,
                        sync_start_time,
                        last_update_time: SystemTime::now(),
                    };

                    last_emitted_filters_downloaded = filters_downloaded;
                    self.emit_progress(progress);

                    headers_this_second = 0;
                    last_rate_calc = Instant::now();
                }

                // Emit filter headers progress only when heights change
                let (abs_header_height, filter_header_height) = {
                    let storage = self.storage.lock().await;
                    let storage_tip = storage.get_tip_height().await.ok().flatten().unwrap_or(0);
                    let filter_tip =
                        storage.get_filter_tip_height().await.ok().flatten().unwrap_or(0);
                    (storage_tip, filter_tip)
                };

                {
                    // Build and emit a fresh DetailedSyncProgress snapshot reflecting current filter progress
                    let peer_best = self
                        .network
                        .get_peer_best_height()
                        .await
                        .ok()
                        .flatten()
                        .unwrap_or(abs_header_height);

                    let phase_snapshot = self.sync_manager.current_phase().clone();
                    let status_display = self.create_status_display().await;
                    let mut sync_progress = match status_display.sync_progress().await {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(
                                "Failed to compute sync progress snapshot (filter): {}",
                                e
                            );
                            SyncProgress::default()
                        }
                    };
                    // Ensure we include up-to-date header height and peer count
                    let peer_count = self.network.peer_count() as u32;
                    sync_progress.peer_count = peer_count;
                    sync_progress.header_height = abs_header_height;
                    sync_progress.filter_sync_available = self.config.enable_filters;

                    let filters_downloaded = sync_progress.filters_downloaded;
                    let current_phase_name = phase_snapshot.name().to_string();
                    let phase_changed =
                        last_emitted_phase_name.as_ref() != Some(&current_phase_name);

                    if abs_header_height != last_emitted_header_height
                        || filter_header_height != last_emitted_filter_header_height
                        || filters_downloaded != last_emitted_filters_downloaded
                        || phase_changed
                    {
                        let sync_stage =
                            Self::map_phase_to_stage(&phase_snapshot, &sync_progress, peer_best);

                        let progress = DetailedSyncProgress {
                            sync_progress,
                            peer_best_height: peer_best,
                            percentage: if peer_best > 0 {
                                (abs_header_height as f64 / peer_best as f64 * 100.0).min(100.0)
                            } else {
                                0.0
                            },
                            headers_per_second: 0.0,
                            bytes_per_second: 0,
                            estimated_time_remaining: None,
                            sync_stage,
                            total_headers_processed: abs_header_height as u64,
                            total_bytes_downloaded,
                            sync_start_time,
                            last_update_time: SystemTime::now(),
                        };
                        last_emitted_header_height = abs_header_height;
                        last_emitted_filter_header_height = filter_header_height;
                        last_emitted_filters_downloaded = filters_downloaded;
                        last_emitted_phase_name = Some(current_phase_name.clone());

                        self.emit_progress(progress);
                    }
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

            tokio::select! {
                received = command_receiver.recv() => {
                    match received {
                    None => {tracing::warn!("DashSpvClientCommand channel closed.");},
                    Some(command) => {
                            self.handle_command(command).await.unwrap_or_else(|e| tracing::error!("Failed to handle command: {}", e));
                        }
                    }
                }
                received = self.network.receive_message() => {
                    match received {
                        Ok(None) => {
                            continue;
                        }
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
                        },
                        Err(err) => {
                            // Handle specific network error types
                            if let crate::error::NetworkError::ConnectionFailed(msg) = &err {
                                if msg.contains("No connected peers") || self.network.peer_count() == 0 {
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
                                        continue
                                    } else {
                                        tracing::warn!(
                                            "No peers available after waiting, will retry monitoring"
                                        );
                                    }
                                }
                            }

                            tracing::error!("Network error during monitoring: {}", err);
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    }
                }
                _ = tokio::time::sleep(MESSAGE_RECEIVE_TIMEOUT) => {}
                _ = token.cancelled() => {
                    log::debug!("DashSpvClient run loop cancelled");
                    break
                }
            }
        }

        Ok(())
    }

    pub async fn run(
        mut self,
        command_receiver: UnboundedReceiver<DashSpvClientCommand>,
        shutdown_token: CancellationToken,
    ) -> Result<()> {
        let client_token = shutdown_token.clone();

        let client_task = tokio::spawn(async move {
            let result = self.monitor_network(command_receiver, client_token).await;
            if let Err(e) = &result {
                tracing::error!("Error running client: {}", e);
            }
            if let Err(e) = self.stop().await {
                tracing::error!("Error stopping client: {}", e);
            }
            result
        });

        let shutdown_task = tokio::spawn(async move {
            if let Err(e) = tokio::signal::ctrl_c().await {
                tracing::error!("Error waiting for ctrl_c: {}", e);
            }
            tracing::debug!("Shutdown signal received");
            shutdown_token.cancel();
        });

        let (client_result, _) = tokio::join!(client_task, shutdown_task);
        client_result.map_err(|e| SpvError::General(format!("client_task panicked: {e}")))?
    }

    async fn handle_command(&mut self, command: DashSpvClientCommand) -> Result<()> {
        match command {
            DashSpvClientCommand::GetQuorumByHeight {
                height,
                quorum_type,
                quorum_hash,
                sender,
            } => {
                let result = self.get_quorum_at_height(height, quorum_type, quorum_hash);
                if sender.send(result).is_err() {
                    return Err(SpvError::ChannelFailure(
                        format!("GetQuorumByHeight({height}, {quorum_type}, {quorum_hash})"),
                        "Failed to send quorum result".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Handle incoming network messages during monitoring.
    pub(super) async fn handle_network_message(
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
                            // Only process InstantLocks when fully synced and masternode engine is available
                            if self.sync_manager.is_synced()
                                && self.sync_manager.get_masternode_engine().is_some()
                            {
                                self.process_instantsendlock(islock_msg.clone()).await?;
                            } else {
                                tracing::debug!(
                                    "Skipping InstantLock processing - not fully synced or masternode engine unavailable"
                                );
                            }
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
    pub(super) async fn process_new_block(&mut self, block: dashcore::Block) -> Result<()> {
        let block_hash = block.block_hash();

        tracing::info!("📦 Routing block {} to async block processor", block_hash);

        // Send block to the background processor without waiting for completion
        let (response_tx, _response_rx) = tokio::sync::oneshot::channel();
        let task = BlockProcessingTask::ProcessBlock {
            block: Box::new(block),
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
    pub(super) async fn report_balance_changes(
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

    // ============ Sync State Persistence and Restoration ============

    /// Restore sync state from persistent storage.
    /// Returns true if state was successfully restored, false if no state was found.
    pub(super) async fn restore_sync_state(&mut self) -> Result<bool> {
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
    pub(super) async fn load_and_validate_sync_state(
        &mut self,
    ) -> Result<(Option<crate::storage::SyncState>, bool)> {
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
    pub(super) async fn handle_rollback_recovery(&mut self, height: u32) -> Result<bool> {
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
    pub(super) async fn handle_checkpoint_recovery(&mut self, height: u32) -> Result<bool> {
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
    pub(super) async fn restore_headers_from_state(
        &mut self,
        saved_state: &crate::storage::SyncState,
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

        // Determine first height to load. Skip genesis (already present) unless we started from a checkpoint base.
        let mut current_height =
            if saved_state.synced_from_checkpoint && saved_state.sync_base_height > 0 {
                saved_state.sync_base_height
            } else {
                1u32
            };

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
                tracing::warn!(
                    "No headers found for range {}..{} when restoring from state",
                    current_height,
                    end_height + 1
                );
                break;
            }

            // Validate headers before adding to chain state
            {
                // Validate the batch of headers
                // Use basic validation only, the headers anyway are already validated since they
                // come from storage.
                if let Err(e) = validate_headers(&headers, ValidationMode::Basic) {
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
            if loaded_count.is_multiple_of(50_000) || loaded_count == target_height {
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
    pub(super) async fn restore_filter_headers_from_state(
        &mut self,
        saved_state: &crate::storage::SyncState,
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
    pub(super) async fn update_stats_from_state(
        &mut self,
        saved_state: &crate::storage::SyncState,
    ) {
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
    pub(super) async fn restore_sync_manager_state(
        &mut self,
        saved_state: &crate::storage::SyncState,
    ) -> Result<bool> {
        // Update sync manager state
        tracing::debug!("Sequential sync manager will resume from stored state");

        // Determine phase based on sync progress
        tracing::info!(
            "Resuming sequential sync; saved header height {} filter header height {}",
            saved_state.sync_progress.header_height,
            saved_state.sync_progress.filter_header_height
        );

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

    /// Rollback chain state to a specific height.
    pub(super) async fn rollback_to_height(&mut self, target_height: u32) -> Result<()> {
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
    pub(super) async fn recover_from_checkpoint(&mut self, checkpoint_height: u32) -> Result<()> {
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
    pub(super) async fn reset_filter_sync_state(&mut self) -> Result<()> {
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
    pub(super) async fn save_sync_state(&mut self) -> Result<()> {
        if !self.config.enable_persistence {
            return Ok(());
        }

        // Get current sync progress
        let sync_progress = self.sync_progress().await?;

        // Get current chain state
        let chain_state = self.state.read().await;

        // Create sync state
        let sync_state = crate::storage::SyncState::from_chain_state(
            &chain_state,
            &sync_progress,
            self.config.network,
        );

        if let Some(state) = sync_state {
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
}
