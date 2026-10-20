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
use dashcore::transaction::special_transaction::coinbase::CoinbasePayload;
use dashcore::QuorumHash;
use key_wallet_manager::WalletInterface;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::DashSpvClient;

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    // ============ Peer Queries ============

    /// Get the number of connected peers.
    pub async fn peer_count(&self) -> usize {
        self.network.lock().await.peer_count()
    }

    /// Disconnect a specific peer.
    pub async fn disconnect_peer(&self, addr: &std::net::SocketAddr, reason: &str) -> Result<()> {
        Ok(self.network.lock().await.disconnect_peer(addr, reason).await?)
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

    /// **Not secure, and temporary:** the unverified coinbase payload of the
    /// highest block an applied masternode list diff carried one for, replaced
    /// on the `dev` branch by a version that keeps only coinbases verified
    /// against their block (dashpay/rust-dashcore#1202).
    ///
    /// Nothing authenticates the payload, so a single peer can serve one of its
    /// choosing; see [`MasternodeListEngine::latest_coinbase`]. `None` while
    /// masternode sync is off, and after a restart until a diff whose coinbase
    /// carries one is applied.
    pub async fn latest_coinbase(&self) -> Option<CoinbasePayload> {
        let engine = self.masternode_engine.as_ref()?;
        engine.read().await.latest_coinbase().cloned()
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
        match masternode_engine_guard.quorum_entry_for_hash_at_or_before_height(
            quorum_type,
            quorum_hash,
            height,
        ) {
            Some((list_height, quorum)) => {
                tracing::debug!(
                    "Found quorum type {} at list height {} (requested {}) with hash {}",
                    quorum_type,
                    list_height,
                    height,
                    hex::encode(quorum_hash)
                );
                Ok(quorum.clone())
            }
            None => {
                let message = format!(
                    "Quorum not found: type {} at or before height {} with hash {}",
                    quorum_type,
                    height,
                    hex::encode(quorum_hash)
                );
                tracing::warn!("{}", message);
                Err(SpvError::QuorumLookupError(message))
            }
        }
    }
}
