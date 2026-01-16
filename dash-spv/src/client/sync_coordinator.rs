//! Sync coordination and orchestration.
//!
//! This module contains the core sync orchestration logic:
//! - monitor_network: Main event loop for processing network messages
//! - Sync state persistence and restoration
//! - Filter sync coordination
//! - Block processing delegation
//! - Balance change reporting
//!
//! This is the largest module as it handles all coordination between network,
//! storage, and the sync manager.

use super::{DashSpvClient, MessageHandler};
use crate::client::interface::DashSpvClientCommand;
use crate::error::{Result, SpvError};
use crate::network::constants::MESSAGE_RECEIVE_TIMEOUT;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::types::{DetailedSyncProgress, SyncProgress};
use key_wallet_manager::wallet_interface::WalletInterface;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_util::sync::CancellationToken;

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
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
                        storage.get_tip_height().await.unwrap_or(0)
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
                    sync_progress.filter_sync_available = self.config.enable_filters();

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
                    let storage_tip = storage.get_tip_height().await.unwrap_or(0);
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
                    sync_progress.filter_sync_available = self.config.enable_filters();

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

            // Check for sync timeouts and handle recovery (only periodically, not every loop)
            if last_timeout_check.elapsed() >= timeout_check_interval {
                let mut storage = self.storage.lock().await;
                self.sync_manager.check_timeout(&mut self.network, &mut *storage).await?;
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
            if !masternode_engine_updated && self.config.enable_masternodes() {
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
                &self.mempool_filter,
                &self.mempool_state,
                &self.event_tx,
            );

            // Delegate message handling to the MessageHandler
            handler.handle_network_message(&message).await
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
}
