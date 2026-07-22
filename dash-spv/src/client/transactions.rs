//! Transaction-related client APIs (e.g., broadcasting)

use std::time::Duration;

use crate::error::{NetworkError, Result, SpvError};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::{BroadcastResult, SyncEvent};
use dashcore::network::message::NetworkMessage;
use key_wallet_manager::WalletInterface;
use tokio::sync::broadcast::error::RecvError;

use super::DashSpvClient;

/// Extra wait beyond the manager's acceptance timeout so the resulting
/// `Uncertain` event has time to propagate through the event bus.
const AWAIT_GRACE: Duration = Duration::from_secs(5);

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    /// Broadcast a transaction to the network.
    ///
    /// With mempool tracking enabled (the default), the transaction is sent to
    /// a subset of connected peers while being withheld from the rest; an
    /// `inv` announcement from a withheld peer proves the transaction relayed
    /// through the network and fires
    /// [`SyncEvent::TransactionBroadcastResult`]. Use
    /// [`broadcast_transaction_and_wait`](Self::broadcast_transaction_and_wait)
    /// to await that outcome directly.
    ///
    /// With mempool tracking disabled there is no acceptance tracking and the
    /// transaction is simply sent to all connected peers.
    pub async fn broadcast_transaction(&self, tx: &dashcore::Transaction) -> Result<()> {
        let network_guard = self.network.lock().await;

        if network_guard.peer_count() == 0 {
            return Err(SpvError::Network(NetworkError::NotConnected));
        }

        if !self.config.read().await.enable_mempool_tracking {
            // Legacy untracked path: fan out to every peer.
            network_guard.broadcast(NetworkMessage::Tx(tx.clone())).await?;
        }

        // Inject locally so the mempool manager picks it up through handle_tx.
        // With tracking enabled the manager performs the actual (targeted)
        // network send when it processes this message.
        network_guard.dispatch_local(NetworkMessage::Tx(tx.clone())).await;

        Ok(())
    }

    /// Broadcast a transaction and wait for its network-level outcome.
    ///
    /// Resolves with [`BroadcastResult::Accepted`] once enough non-recipient
    /// peers announce the txid back (or it is InstantSend-locked/confirmed),
    /// and [`BroadcastResult::Uncertain`] when no acceptance signal arrives
    /// within the timeout (defaults to the configured acceptance timeout plus
    /// a small grace period). There is no negative signal on the p2p network
    /// — modern Dash Core removed the BIP61 `reject` message — so a refused
    /// transaction surfaces as `Uncertain`.
    ///
    /// Requires mempool tracking to be enabled.
    pub async fn broadcast_transaction_and_wait(
        &self,
        tx: &dashcore::Transaction,
        timeout: Option<Duration>,
    ) -> Result<BroadcastResult> {
        let config_timeout = {
            let config = self.config.read().await;
            if !config.enable_mempool_tracking {
                return Err(SpvError::Config(
                    "broadcast_transaction_and_wait requires mempool tracking".to_string(),
                ));
            }
            config.broadcast_acceptance_timeout
        };
        let wait = timeout.unwrap_or(config_timeout + AWAIT_GRACE);
        let txid = tx.txid();

        // Subscribe before dispatching so the outcome event cannot be missed.
        let mut events = self.subscribe_sync_events().await;
        self.broadcast_transaction(tx).await?;

        let deadline = tokio::time::Instant::now() + wait;
        loop {
            match tokio::time::timeout_at(deadline, events.recv()).await {
                Ok(Ok(SyncEvent::TransactionBroadcastResult {
                    txid: event_txid,
                    result,
                })) if event_txid == txid => return Ok(result),
                Ok(Ok(_)) => continue,
                Ok(Err(RecvError::Lagged(skipped))) => {
                    tracing::warn!(
                        "Sync event stream lagged by {} while awaiting broadcast result",
                        skipped
                    );
                    continue;
                }
                // Bus closed or deadline elapsed: no definitive outcome observed.
                Ok(Err(RecvError::Closed)) | Err(_) => return Ok(BroadcastResult::Uncertain),
            }
        }
    }
}
