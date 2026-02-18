//! Query methods for peers, masternodes, and balances.
//!
//! This module contains:
//! - Peer queries (count, info, disconnect)
//! - Masternode queries (engine, list, quorums)
//! - Balance queries
//! - Filter availability checks

use crate::error::{Result, SpvError};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::QuorumHash;
use key_wallet_manager::wallet_interface::WalletInterface;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::DashSpvClient;

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    // ============ Peer Queries ============

    /// Get the number of connected peers.
    pub async fn peer_count(&self) -> usize {
        self.network.lock().await.peer_count()
    }

    /// Get the number of connected peers (async version).
    pub async fn get_peer_count(&self) -> usize {
        self.network.lock().await.peer_count()
    }

    /// Disconnect a specific peer.
    pub async fn disconnect_peer(&self, addr: &std::net::SocketAddr, reason: &str) -> Result<()> {
        // Cast network manager to PeerNetworkManager to access disconnect_peer
        let network_guard = self.network.lock().await;
        let network = network_guard
            .as_any()
            .downcast_ref::<crate::network::manager::PeerNetworkManager>()
            .ok_or_else(|| {
                SpvError::Config("Network manager does not support peer disconnection".to_string())
            })?;

        network.disconnect_peer(addr, reason).await
    }

    // ============ Masternode Queries ============

    /// Get a reference to the masternode list engine.
    /// Returns an error if the masternode engine is not initialized.
    pub fn masternode_list_engine(&self) -> Result<Arc<RwLock<MasternodeListEngine>>> {
        match self.masternode_engine {
            Some(ref masternode_engine) => Ok(masternode_engine.clone()),
            None => Err(SpvError::Config("Masternode list engine not initialized".to_string())),
        }
    }

    /// Get a quorum entry by type and hash at a specific block height.
    /// Returns `SpvError::QuorumLookupError` if the quorum is not found.
    pub async fn get_quorum_at_height(
        &self,
        height: u32,
        quorum_type: LLMQType,
        quorum_hash: QuorumHash,
    ) -> Result<QualifiedQuorumEntry> {
        let masternode_engine = self.masternode_list_engine()?;
        let masternode_engine_guard = masternode_engine.read().await;
        let (before, _after) = masternode_engine_guard.masternode_lists_around_height(height);
        if let Some(ml) = before {
            let list_height = ml.known_height;
            match ml.quorums.get(&quorum_type) {
                Some(quorums) => match quorums.get(&quorum_hash) {
                    Some(quorum) => {
                        tracing::debug!(
                            "Found quorum type {} at list height {} (requested {}) with hash {}",
                            quorum_type,
                            list_height,
                            height,
                            hex::encode(quorum_hash)
                        );
                        return Ok(quorum.clone());
                    }
                    None => {
                        let message = format!(
                            "Quorum not found: type {} at list height {} (requested {}) with hash {} (masternode list exists with {} quorums of this type)",
                            quorum_type,
                            list_height,
                            height,
                            hex::encode(quorum_hash),
                            quorums.len()
                        );
                        tracing::warn!(message);
                        return Err(SpvError::QuorumLookupError(message));
                    }
                },
                None => {
                    tracing::warn!(
                        "No quorums of type {} found at list height {} (requested {}) (masternode list exists)",
                        quorum_type,
                        list_height,
                        height
                    );
                    return Err(SpvError::QuorumLookupError(format!(
                        "No quorums of type {} found at list height {} (requested {})",
                        quorum_type, list_height, height
                    )));
                }
            }
        }

        tracing::warn!(
            "No masternode list found at or before height {} - cannot retrieve quorum",
            height
        );
        Err(SpvError::QuorumLookupError(format!(
            "No masternode list found at or before height {}",
            height
        )))
    }
}
