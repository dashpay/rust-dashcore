//! Sync coordination and orchestration.

use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::core::SyncLoop;
use super::event_handler::{
    spawn_broadcast_monitor, spawn_chainlock_wallet_dispatch, spawn_progress_monitor,
    spawn_reservation_sweep,
};
use super::DashSpvClient;
use crate::error::Result;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::SyncEvent;
use crate::SpvError;
use key_wallet_manager::WalletInterface;

const SYNC_COORDINATOR_TICK_MS: Duration = Duration::from_millis(100);

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    /// Start the client and run the sync loop in the background until `stop()` is called.
    ///
    /// Subscribes to all event channels internally and dispatches events to the
    /// event handler provided at construction. Starts the storage, the sync
    /// managers and the network, and returns once the client is running. If the
    /// sync loop fails, it reports the error through `on_error` and stops the client.
    /// Does nothing if the client is already running.
    ///
    /// Starting can take a few seconds, e.g. when peers have to be discovered
    /// through DNS. If blocking the caller that long is a problem, call `run`
    /// from another task or thread.
    pub async fn run(&self) -> Result<()> {
        let mut sync_loop = self.sync_loop.lock().await;
        self.run_locked(&mut sync_loop).await
    }

    /// Start the client while the caller holds the lock on `sync_loop`.
    pub(super) async fn run_locked(&self, sync_loop: &mut Option<SyncLoop>) -> Result<()> {
        // A loop that failed and still waits for its own stop is done: tear it
        // down here, so the client really runs again.
        if let Some(failed) = sync_loop.take_if(|running| running.shutdown.is_cancelled()) {
            self.stop_locked(failed).await;
        }
        if sync_loop.is_some() {
            return Ok(());
        }

        let handlers = self.event_handlers.clone();
        let monitor_shutdown = CancellationToken::new();
        let (monitor_failure_tx, mut monitor_failure_rx) = mpsc::channel::<String>(1);

        // Subscribe and spawn monitors before startup so we don't miss early
        // connection events.
        let sync_event_rx = self.subscribe_sync_events().await;
        let mut fork_rx = self.subscribe_sync_events().await;
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

        if let Err(e) = self.start_sync().await {
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

        // Spawn the reservation sweep only after startup succeeds: it mutates
        // wallet state, so a slow or failing startup must not let it reclaim
        // reservations while `run()` is still on its way to returning an error.
        let reservation_sweep_task =
            self.config.read().await.reservation_sweep_ttl_secs.map(|ttl| {
                spawn_reservation_sweep(self.wallet.clone(), ttl, monitor_shutdown.clone())
            });

        let client = self.clone();
        let shutdown = monitor_shutdown.clone();

        let task = tokio::spawn(async move {
            tracing::info!("Starting continuous sync monitoring...");

            // Run the sync loop
            let mut sync_coordinator_tick_interval =
                tokio::time::interval(SYNC_COORDINATOR_TICK_MS);

            let error: Option<SpvError> = loop {
                let error: Option<SpvError> = tokio::select! {
                    _ = sync_coordinator_tick_interval.tick() => {
                        client.sync_coordinator.lock().await.tick().await.err().map(Into::into)
                    }
                    _ = monitor_shutdown.cancelled() => {
                        break None
                    }
                    Ok(SyncEvent::ForkDetected { fork_height }) = fork_rx.recv() => {
                        // Recovering stops this task, so it runs in a task of its own,
                        // which only acts on a loop whose token is cancelled.
                        monitor_shutdown.cancel();
                        let client = client.clone();

                        tokio::spawn(async move {
                            if let Err(e) = client.handle_fork(fork_height).await {
                                tracing::warn!("Error recovering from the fork: {}", e);
                            }
                        });

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
            tracing::info!("Stopping sync monitoring");

            let _ = tokio::join!(
                sync_task,
                chainlock_dispatch_task,
                network_task,
                wallet_task,
                progress_task
            );
            if let Some(task) = reservation_sweep_task {
                let _ = task.await;
            }

            if let Some(e) = error {
                for handler in handlers.iter() {
                    handler.on_error(&e.to_string());
                }
                // Stopping waits for this task, so it runs in a task of its own.
                tokio::spawn(async move { client.stop_failed().await });
            }
        });

        *sync_loop = Some(SyncLoop {
            task,
            shutdown,
        });

        Ok(())
    }
}
