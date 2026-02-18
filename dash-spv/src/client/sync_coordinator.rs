//! Sync coordination and orchestration.

use super::DashSpvClient;
use crate::error::{Result, SpvError};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::SyncProgress;
use key_wallet_manager::wallet_interface::WalletInterface;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const SYNC_COORDINATOR_TICK_MS: Duration = Duration::from_millis(100);

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    /// Get current sync progress.
    pub async fn sync_progress(&self) -> SyncProgress {
        self.sync_coordinator.lock().await.progress().clone()
    }

    /// Run continuous monitoring for new blocks, ChainLocks, InstantLocks, etc.
    ///
    /// This is the sole network message receiver to prevent race conditions.
    /// All sync operations coordinate through this monitoring loop.
    pub async fn monitor_network(&self, token: CancellationToken) -> Result<()> {
        let running = self.running.read().await;
        if !*running {
            return Err(SpvError::Config("Client not running".to_string()));
        }
        drop(running);

        tracing::info!("Starting continuous network monitoring...");

        let mut sync_coordinator_tick_interval = tokio::time::interval(SYNC_COORDINATOR_TICK_MS);
        let mut progress_updates = self.sync_coordinator.lock().await.subscribe_progress();

        loop {
            // Check if we should stop
            let running = self.running.read().await;
            if !*running {
                tracing::info!("Stopping network monitoring");
                break;
            }
            drop(running);

            tokio::select! {
                _ = progress_updates.changed() => {
                    tracing::info!("Sync progress:{}", *progress_updates.borrow());
                }
                _ = sync_coordinator_tick_interval.tick() => {
                    // Tick the sync coordinator to aggregate progress
                    if let Err(e) = self.sync_coordinator.lock().await.tick().await {
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
        if let Err(e) = self.sync_coordinator.lock().await.shutdown().await {
            tracing::warn!("Error shutting down sync coordinator: {}", e);
        }

        Ok(())
    }

    /// Run the client: spawns the monitoring loop and a ctrl-c handler.
    pub async fn run(&self, shutdown_token: CancellationToken) -> Result<()> {
        let client_token = shutdown_token.clone();
        let client = self.clone();

        let client_task = tokio::spawn(async move {
            let result = client.monitor_network(client_token).await;
            if let Err(e) = &result {
                tracing::error!("Error running client: {}", e);
            }
            if let Err(e) = client.stop().await {
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
}
