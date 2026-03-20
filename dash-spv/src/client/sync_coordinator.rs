//! Sync coordination and orchestration.

use super::DashSpvClient;
use crate::error::Result;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::SyncProgress;
use key_wallet::manager::WalletInterface;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const SYNC_COORDINATOR_TICK_MS: Duration = Duration::from_millis(100);

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    /// Get current sync progress.
    pub async fn sync_progress(&self) -> SyncProgress {
        self.sync_coordinator.lock().await.progress().clone()
    }

    /// Start the client and run the monitoring loop until the token is cancelled.
    ///
    /// Calls `start()` internally, runs continuous network monitoring for new
    /// blocks, ChainLocks, InstantLocks, etc., and calls `stop()` before returning.
    /// The caller is responsible for cancelling the token (e.g. on ctrl-c).
    pub async fn run(&self, token: CancellationToken) -> Result<()> {
        self.start().await?;

        tracing::info!("Starting continuous network monitoring...");

        let mut sync_coordinator_tick_interval = tokio::time::interval(SYNC_COORDINATOR_TICK_MS);
        let mut progress_updates = self.sync_coordinator.lock().await.subscribe_progress();
        let mut wallet_events = self.wallet.read().await.subscribe_events();

        let error = loop {
            // Check if we should stop
            let running = self.running.read().await;
            if !*running {
                tracing::info!("Stopping network monitoring");
                break None;
            }
            drop(running);

            let error = tokio::select! {
                result = progress_updates.changed() => {
                    match result {
                        Ok(()) => {
                            tracing::info!("Sync progress: {}", *progress_updates.borrow());
                            None
                        }
                        Err(_) => {
                            tracing::warn!("Progress channel closed.");
                            break None
                        }
                    }
                }
                result = wallet_events.recv() => {
                    match result {
                        Ok(event) => {
                            tracing::info!("Wallet event: {}", event.description());
                            None
                        }
                        Err(e) => {
                            tracing::warn!("Wallet events channel error: {e}");
                            break None
                        }
                    }
                }
                _ = sync_coordinator_tick_interval.tick() => {
                    self.sync_coordinator.lock().await.tick().await.err().map(Into::into)
                }
                _ = token.cancelled() => {
                    tracing::debug!("DashSpvClient run loop cancelled");
                    break None
                }
            };

            if error.is_some() {
                break error;
            }
        };

        // Always stop the client
        let stop_result = self.stop().await;

        match error {
            Some(e) => Err(e),
            None => stop_result,
        }
    }
}
