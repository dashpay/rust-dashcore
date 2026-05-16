//! Sync coordination and orchestration.

use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::event_handler::{
    spawn_broadcast_monitor, spawn_chainlock_wallet_dispatch, spawn_progress_monitor,
};
use super::DashSpvClient;
use crate::error::Result;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::SyncProgress;
use crate::SpvError;
use key_wallet_manager::WalletInterface;

const SYNC_COORDINATOR_TICK_MS: Duration = Duration::from_millis(100);

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    /// Get current sync progress.
    pub async fn sync_progress(&self) -> SyncProgress {
        self.sync_coordinator.lock().await.progress().clone()
    }

    /// Start the client and run the sync loop until `stop()` is called.
    ///
    /// Subscribes to all event channels internally and dispatches events to the
    /// event handler provided at construction. Calls `start()` internally, runs
    /// continuous network monitoring, and calls `stop()` before returning.
    pub async fn run(&self) -> Result<()> {
        let handlers = self.event_handlers.clone();
        let monitor_shutdown = CancellationToken::new();
        let (monitor_failure_tx, mut monitor_failure_rx) = mpsc::channel::<String>(1);

        // Subscribe before `start()` so a `stop()` that races startup is never
        // missed: the receiver records the version at subscription time, so any
        // later state change is observed even if it lands before the loop runs.
        let mut stop_rx = self.running.subscribe();

        // Subscribe and spawn monitors before startup so we don't miss early
        // connection events.
        let sync_event_rx = self.subscribe_sync_events().await;
        let chainlock_dispatch_rx = self.subscribe_sync_events().await;
        let network_event_rx = self.subscribe_network_events().await;
        let progress_rx = self.subscribe_progress().await;
        let wallet_event_rx = self.wallet.read().await.subscribe_events();

        let sync_task = spawn_broadcast_monitor(
            "SyncEvent",
            sync_event_rx,
            handlers.clone(),
            monitor_shutdown.clone(),
            monitor_failure_tx.clone(),
            |h, event| h.on_sync_event(event),
        );

        let chainlock_dispatch_task = spawn_chainlock_wallet_dispatch(
            chainlock_dispatch_rx,
            self.wallet.clone(),
            monitor_shutdown.clone(),
            monitor_failure_tx.clone(),
        );

        let network_task = spawn_broadcast_monitor(
            "NetworkEvent",
            network_event_rx,
            handlers.clone(),
            monitor_shutdown.clone(),
            monitor_failure_tx.clone(),
            |h, event| h.on_network_event(event),
        );

        let wallet_task = spawn_broadcast_monitor(
            "WalletEvent",
            wallet_event_rx,
            handlers.clone(),
            monitor_shutdown.clone(),
            monitor_failure_tx.clone(),
            |h, event| h.on_wallet_event(event),
        );

        let progress_task = spawn_progress_monitor(
            progress_rx,
            handlers.clone(),
            monitor_shutdown.clone(),
            monitor_failure_tx,
        );

        if let Err(e) = self.start().await {
            monitor_shutdown.cancel();
            let _ = tokio::join!(
                sync_task,
                chainlock_dispatch_task,
                network_task,
                wallet_task,
                progress_task
            );
            for handler in handlers.iter() {
                handler.on_error(&e.to_string());
            }
            return Err(e);
        }

        // `start()` flipped the state to `true`. Consume that edge so `changed()`
        // only fires on the subsequent transition to `false` (the stop request).
        // If a `stop()` already raced in, this reads `false` and the loop's first
        // guard breaks immediately.
        stop_rx.borrow_and_update();

        tracing::info!("Starting continuous network monitoring...");

        // Run the sync loop
        let mut sync_coordinator_tick_interval = tokio::time::interval(SYNC_COORDINATOR_TICK_MS);

        let error: Option<SpvError> = loop {
            if !self.is_running() {
                tracing::info!("Stopping network monitoring");
                break None;
            }

            let error: Option<SpvError> = tokio::select! {
                _ = sync_coordinator_tick_interval.tick() => {
                    self.sync_coordinator.lock().await.tick().await.err().map(Into::into)
                }
                _ = stop_rx.changed() => {
                    tracing::debug!("DashSpvClient run loop stop requested");
                    break None
                }
                Some(msg) = monitor_failure_rx.recv() => {
                    break Some(crate::SpvError::ChannelFailure(
                        "event monitor".into(),
                        msg,
                    ))
                }
            };

            if error.is_some() {
                break error;
            }
        };

        // Signal monitors to shut down before channels close
        monitor_shutdown.cancel();
        let _ = tokio::join!(
            sync_task,
            chainlock_dispatch_task,
            network_task,
            wallet_task,
            progress_task
        );

        if let Some(ref e) = error {
            for handler in handlers.iter() {
                handler.on_error(&e.to_string());
            }
        }

        let stop_result = self.stop().await;

        match error {
            Some(e) => Err(e),
            None => stop_result,
        }
    }
}
