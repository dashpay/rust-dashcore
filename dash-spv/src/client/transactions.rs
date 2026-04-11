//! Transaction-related client APIs (e.g., broadcasting)

use crate::error::{NetworkError, Result, SpvError};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use dashcore::network::message::NetworkMessage;
use key_wallet_manager::WalletInterface;

use super::{DashSpvClient, EventHandler};

impl<W: WalletInterface, N: NetworkManager, S: StorageManager, H: EventHandler>
    DashSpvClient<W, N, S, H>
{
    /// Broadcast a transaction to all connected peers.
    ///
    /// The transaction is also injected into the local message pipeline so that
    /// the mempool manager processes it immediately.
    pub async fn broadcast_transaction(&self, tx: &dashcore::Transaction) -> Result<()> {
        let network_guard = self.network.lock().await;

        if network_guard.peer_count() == 0 {
            return Err(SpvError::Network(NetworkError::NotConnected));
        }

        let message = NetworkMessage::Tx(tx.clone());
        network_guard.broadcast(message).await?;

        // Inject locally so the mempool manager picks it up through handle_tx.
        network_guard.dispatch_local(NetworkMessage::Tx(tx.clone())).await;

        Ok(())
    }
}
