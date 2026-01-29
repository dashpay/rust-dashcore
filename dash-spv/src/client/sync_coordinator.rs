//! Sync coordination and orchestration.

use super::DashSpvClient;
use crate::client::interface::DashSpvClientCommand;
use crate::error::{Result, SpvError};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::SyncProgress;
use key_wallet_manager::wallet_interface::WalletInterface;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_util::sync::CancellationToken;

const SYNC_COORDINATOR_TICK_MS: Duration = Duration::from_millis(100);

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    /// Get current sync progress.
    pub fn sync_progress(&self) -> SyncProgress {
        self.sync_coordinator.progress().clone()
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

        let mut sync_coordinator_tick_interval = tokio::time::interval(SYNC_COORDINATOR_TICK_MS);
        let mut progress_updates = self.sync_coordinator.subscribe_progress();

        loop {
            // Check if we should stop
            let running = self.running.read().await;
            if !*running {
                tracing::info!("Stopping network monitoring");
                break;
            }
            drop(running);

            tokio::select! {
                received = command_receiver.recv() => {
                    match received {
                    None => {tracing::warn!("DashSpvClientCommand channel closed.");},
                    Some(command) => {
                            self.handle_command(command).await.unwrap_or_else(|e| tracing::error!("Failed to handle command: {}", e));
                        }
                    }
                }
                _ = progress_updates.changed() => {
                    tracing::info!("Sync progress:{}", *progress_updates.borrow());
                }
                _ = sync_coordinator_tick_interval.tick() => {
                    // Tick the sync coordinator to aggregate progress
                    if let Err(e) = self.sync_coordinator.tick().await {
                        tracing::warn!("Sync coordinator tick error: {}", e);
                    }
                }
                _ = token.cancelled() => {
                    tracing::debug!("DashSpvClient run loop cancelled");
                    break
                }
            }
        }

        // Shutdown the sync coordinator
        if let Err(e) = self.sync_coordinator.shutdown().await {
            tracing::warn!("Error shutting down sync coordinator: {}", e);
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
                let result = self.get_quorum_at_height(height, quorum_type, quorum_hash).await;
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
