//! Transaction-related client APIs (e.g., broadcasting)

use crate::error::{Result, SpvError};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use dashcore::network::message::NetworkMessage;
use key_wallet_manager::WalletInterface;

use super::{DashSpvClient, EventHandler};

impl<W: WalletInterface, N: NetworkManager, S: StorageManager, H: EventHandler>
    DashSpvClient<W, N, S, H>
{
    /// Broadcast a transaction to all connected peers.
    pub async fn broadcast_transaction(&self, tx: &dashcore::Transaction) -> Result<()> {
        let network_guard = self.network.lock().await;

        if network_guard.peer_count() == 0 {
            return Err(SpvError::Network(crate::error::NetworkError::NotConnected));
        }

        let message = NetworkMessage::Tx(tx.clone());
        Ok(network_guard.broadcast(message).await?)
    }
}
