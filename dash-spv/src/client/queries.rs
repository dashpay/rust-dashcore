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
use crate::types::AddressBalance;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use key_wallet_manager::wallet_interface::WalletInterface;

use super::DashSpvClient;

impl<
        W: WalletInterface + Send + Sync + 'static,
        N: NetworkManager + Send + Sync + 'static,
        S: StorageManager + Send + Sync + 'static,
    > DashSpvClient<W, N, S>
{
    // ============ Peer Queries ============

    /// Get the number of connected peers.
    pub fn peer_count(&self) -> usize {
        self.network.peer_count()
    }

    /// Get information about connected peers.
    pub fn peer_info(&self) -> Vec<crate::types::PeerInfo> {
        self.network.peer_info()
    }

    /// Get the number of connected peers (async version).
    pub async fn get_peer_count(&self) -> usize {
        self.network.peer_count()
    }

    /// Disconnect a specific peer.
    pub async fn disconnect_peer(&self, addr: &std::net::SocketAddr, reason: &str) -> Result<()> {
        // Cast network manager to MultiPeerNetworkManager to access disconnect_peer
        let network = self
            .network
            .as_any()
            .downcast_ref::<crate::network::multi_peer::MultiPeerNetworkManager>()
            .ok_or_else(|| {
                SpvError::Config("Network manager does not support peer disconnection".to_string())
            })?;

        network.disconnect_peer(addr, reason).await
    }

    // ============ Masternode Queries ============

    /// Get a reference to the masternode list engine.
    /// Returns None if masternode sync is not enabled in config.
    pub fn masternode_list_engine(&self) -> Option<&MasternodeListEngine> {
        self.sync_manager.masternode_list_engine()
    }

    /// Get the masternode list at a specific block height.
    /// Returns None if the masternode list for that height is not available.
    pub fn get_masternode_list_at_height(&self, height: u32) -> Option<&MasternodeList> {
        self.masternode_list_engine().and_then(|engine| engine.masternode_lists.get(&height))
    }

    /// Get a quorum entry by type and hash at a specific block height.
    /// Returns None if the quorum is not found.
    pub fn get_quorum_at_height(
        &self,
        height: u32,
        quorum_type: u8,
        quorum_hash: &[u8; 32],
    ) -> Option<&QualifiedQuorumEntry> {
        use dashcore::sml::llmq_type::LLMQType;
        use dashcore::QuorumHash;
        use dashcore_hashes::Hash;

        let llmq_type: LLMQType = LLMQType::from(quorum_type);
        if llmq_type == LLMQType::LlmqtypeUnknown {
            tracing::warn!("Invalid quorum type {} requested at height {}", quorum_type, height);
            return None;
        };

        let qhash = QuorumHash::from_byte_array(*quorum_hash);

        // First check if we have the masternode list at this height
        match self.get_masternode_list_at_height(height) {
            Some(ml) => {
                // We have the masternode list, now look for the quorum
                match ml.quorums.get(&llmq_type) {
                    Some(quorums) => match quorums.get(&qhash) {
                        Some(quorum) => {
                            tracing::debug!(
                                "Found quorum type {} at height {} with hash {}",
                                quorum_type,
                                height,
                                hex::encode(quorum_hash)
                            );
                            Some(quorum)
                        }
                        None => {
                            tracing::warn!(
                                "Quorum not found: type {} at height {} with hash {} (masternode list exists with {} quorums of this type)",
                                quorum_type,
                                height,
                                hex::encode(quorum_hash),
                                quorums.len()
                            );
                            None
                        }
                    },
                    None => {
                        tracing::warn!(
                            "No quorums of type {} found at height {} (masternode list exists)",
                            quorum_type,
                            height
                        );
                        None
                    }
                }
            }
            None => {
                tracing::warn!(
                    "No masternode list found at height {} - cannot retrieve quorum",
                    height
                );
                None
            }
        }
    }

    // ============ Balance Queries ============

    /// Get balance for a specific address.
    ///
    /// This method is deprecated - use the wallet's balance query methods instead.
    pub async fn get_address_balance(
        &self,
        _address: &dashcore::Address,
    ) -> Result<AddressBalance> {
        // This method requires wallet-specific functionality not in WalletInterface
        // The wallet should expose balance info through its own interface
        Err(SpvError::Config(
            "Address balance queries should be made directly to the wallet implementation"
                .to_string(),
        ))
    }

    /// Get balances for all watched addresses.
    ///
    /// This method is deprecated - use the wallet's balance query methods instead.
    pub async fn get_all_balances(
        &self,
    ) -> Result<std::collections::HashMap<dashcore::Address, AddressBalance>> {
        // TODO: Get balances from wallet instead of tracking separately
        // Will be implemented when wallet integration is complete
        Ok(std::collections::HashMap::new())
    }

    // ============ Filter Queries ============

    /// Check if filter sync is available (any peer supports compact filters).
    pub async fn is_filter_sync_available(&self) -> bool {
        self.network
            .has_peer_with_service(dashcore::network::constants::ServiceFlags::COMPACT_FILTERS)
            .await
    }
}
