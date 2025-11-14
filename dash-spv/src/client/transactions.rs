//! Transaction-related client APIs (e.g., broadcasting)

use crate::error::{Result, SpvError};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use dashcore::network::message::NetworkMessage;
use key_wallet_manager::wallet_interface::WalletInterface;

use super::DashSpvClient;

impl<
        W: WalletInterface + Send + Sync + 'static,
        N: NetworkManager + Send + Sync + 'static,
        S: StorageManager + Send + Sync + 'static,
    > DashSpvClient<W, N, S>
{
    /// Broadcast a transaction to all connected peers.
    pub async fn broadcast_transaction(&self, tx: &dashcore::Transaction) -> Result<()> {
        let network = self
            .network
            .as_any()
            .downcast_ref::<crate::network::multi_peer::MultiPeerNetworkManager>()
            .ok_or_else(|| {
                SpvError::Config("Network manager does not support broadcasting".to_string())
            })?;

        if network.peer_count() == 0 {
            return Err(SpvError::Network(crate::error::NetworkError::NotConnected));
        }

        let message = NetworkMessage::Tx(tx.clone());
        let results = network.broadcast(message).await;

        let mut success = false;
        let mut errors = Vec::new();
        for res in results {
            match res {
                Ok(_) => success = true,
                Err(err) => errors.push(err.to_string()),
            }
        }

        if success {
            Ok(())
        } else {
            Err(SpvError::Network(crate::error::NetworkError::ProtocolError(format!(
                "Broadcast failed: {}",
                errors.join(", ")
            ))))
        }
    }
}
