//! Sync coordination and orchestration.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::event_handler::{spawn_broadcast_monitor, spawn_progress_monitor};
use super::{DashSpvClient, EventHandler};
use crate::error::Result;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::SyncProgress;
use crate::SpvError;
use key_wallet::manager::WalletInterface;

const SYNC_COORDINATOR_TICK_MS: Duration = Duration::from_millis(100);

impl<W: WalletInterface, N: NetworkManager, S: StorageManager, H: EventHandler>
    DashSpvClient<W, N, S, H>
{
    /// Get current sync progress.
    pub async fn sync_progress(&self) -> SyncProgress {
        self.sync_coordinator.lock().await.progress().clone()
    }

    /// Start the client and run the sync loop until the token is cancelled.
    ///
    /// Subscribes to all event channels internally and dispatches events to the
    /// event handler provided at construction. Calls `start()` internally, runs
    /// continuous network monitoring, and calls `stop()` before returning.
    pub async fn run(&self, token: CancellationToken) -> Result<()> {
        let handler = self.event_handler.clone();

        if let Err(e) = self.start().await {
            handler.on_error(&e.to_string());
            return Err(e);
        }

        tracing::info!("Starting continuous network monitoring...");

        let monitor_shutdown = CancellationToken::new();

        // Subscribe to channels
        let sync_event_rx = self.subscribe_sync_events().await;
        let network_event_rx = self.subscribe_network_events().await;
        let progress_rx = self.subscribe_progress().await;
        let wallet_event_rx = self.wallet.read().await.subscribe_events();

        // Spawn monitoring tasks
        let sync_task = spawn_broadcast_monitor(
            "Sync event",
            sync_event_rx,
            handler.clone(),
            monitor_shutdown.clone(),
            |h, event| h.on_sync_event(event),
        );

        let network_task = spawn_broadcast_monitor(
            "Network event",
            network_event_rx,
            handler.clone(),
            monitor_shutdown.clone(),
            |h, event| h.on_network_event(event),
        );

        let wallet_task = spawn_broadcast_monitor(
            "Wallet event",
            wallet_event_rx,
            handler.clone(),
            monitor_shutdown.clone(),
            |h, event| h.on_wallet_event(event),
        );

        let progress_task =
            spawn_progress_monitor(progress_rx, handler.clone(), monitor_shutdown.clone());

        // Run the sync loop
        let mut sync_coordinator_tick_interval = tokio::time::interval(SYNC_COORDINATOR_TICK_MS);

        let error: Option<SpvError> = loop {
            let running = self.running.read().await;
            if !*running {
                tracing::info!("Stopping network monitoring");
                break None;
            }
            drop(running);

            let error: Option<SpvError> = tokio::select! {
                _ = sync_coordinator_tick_interval.tick() => {
                    self.sync_coordinator.lock().await.tick().await.err().map(Into::into)
                }
                _ = token.cancelled() => {
                    tracing::debug!("DashSpvClient run loop cancelled");
                    break None
                }
            };

            if let Some(ref e) = error {
                handler.on_error(&e.to_string());
                break error;
            }
        };

        // Cancel monitoring tasks and wait for them
        monitor_shutdown.cancel();
        let _ = tokio::join!(sync_task, network_task, wallet_task, progress_task);

        let stop_result = self.stop().await;

        match error {
            Some(e) => Err(e),
            None => stop_result,
        }
    }
}
