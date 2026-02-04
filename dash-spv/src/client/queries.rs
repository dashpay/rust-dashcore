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
    pub fn peer_count(&self) -> usize {
        self.network.peer_count()
    }

    /// Get the number of connected peers (async version).
    pub async fn get_peer_count(&self) -> usize {
        self.network.peer_count()
    }

    /// Disconnect a specific peer.
    pub async fn disconnect_peer(&self, addr: &std::net::SocketAddr, reason: &str) -> Result<()> {
        // Cast network manager to PeerNetworkManager to access disconnect_peer
        let network = self
            .network
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
        // First check if we have the masternode list at this height
        match masternode_engine_guard.masternode_lists.get(&height) {
            Some(ml) => {
                // We have the masternode list, now look for the quorum
                match ml.quorums.get(&quorum_type) {
                    Some(quorums) => match quorums.get(&quorum_hash) {
                        Some(quorum) => {
                            tracing::debug!(
                                "Found quorum type {} at height {} with hash {}",
                                quorum_type,
                                height,
                                hex::encode(quorum_hash)
                            );
                            Ok(quorum.clone())
                        }
                        None => {
                            let message = format!("Quorum not found: type {} at height {} with hash {} (masternode list exists with {} quorums of this type)",
                                                quorum_type,
                                                height,
                                                hex::encode(quorum_hash),
                                                quorums.len());
                            tracing::warn!(message);
                            Err(SpvError::QuorumLookupError(message))
                        }
                    },
                    None => {
                        tracing::warn!(
                            "No quorums of type {} found at height {} (masternode list exists)",
                            quorum_type,
                            height
                        );
                        Err(SpvError::QuorumLookupError(format!(
                            "No quorums of type {} found at height {}",
                            quorum_type, height
                        )))
                    }
                }
            }
            None => Err(SpvError::QuorumLookupError(format!(
                "No masternode list found at height {}",
                height
            ))),
        }
    }
}
