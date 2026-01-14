//! Transaction-related client APIs (e.g., broadcasting)

use crate::error::{Error, Result};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use dashcore::network::message::NetworkMessage;
use key_wallet_manager::wallet_interface::WalletInterface;

use super::DashSpvClient;

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    /// Broadcast a transaction to all connected peers.
    pub async fn broadcast_transaction(&self, tx: &dashcore::Transaction) -> Result<()> {
        let network = self
            .network
            .as_any()
            .downcast_ref::<crate::network::manager::PeerNetworkManager>()
            .ok_or_else(|| {
                Error::Config("Network manager does not support broadcasting".to_string())
            })?;

        if network.peer_count() == 0 {
            return Err(Error::Network(crate::error::NetworkError::NotConnected));
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
            Err(Error::Network(crate::error::NetworkError::ProtocolError(format!(
                "Broadcast failed: {}",
                errors.join(", ")
            ))))
        }
    }
}
