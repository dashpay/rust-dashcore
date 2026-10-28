//! Query methods for peers, masternodes, and balances.
//!
//! This module contains:
//! - Peer queries (count, info, disconnect)
//! - Masternode queries (engine, list, quorums)
//! - Balance queries
//! - Filter availability checks

use crate::error::{Result, SpvError};
use crate::network::NetworkManager;
use crate::sml_engine::MasternodeListEngine;
use crate::storage::PersistentBlockHeaderStorage;
use dashcore::hashes::Hash;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::QuorumHash;
use key_wallet_manager::WalletInterface;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::DashSpvClient;
use hex_conservative::DisplayHex;

impl<W: WalletInterface, N: NetworkManager> DashSpvClient<W, N> {
    // ============ Peer Queries ============

    /// Get the number of connected peers.
    pub async fn peer_count(&self) -> usize {
        self.network.connected_count().await as usize
    }

    // ============ Masternode Queries ============

    /// Get a reference to the masternode list engine.
    /// Returns an error if the masternode engine is not initialized.
    pub(crate) fn masternode_list_engine(
        &self,
    ) -> Result<Arc<RwLock<MasternodeListEngine<PersistentBlockHeaderStorage>>>> {
        match self.masternode_engine {
            Some(ref masternode_engine) => Ok(masternode_engine.clone()),
            None => Err(SpvError::Config("Masternode list engine not initialized".to_string())),
        }
    }

    /// The newest masternode list, `None` while masternode sync is off or has
    /// not built a list yet.
    pub async fn latest_masternode_list(&self) -> Option<MasternodeList> {
        let engine = self.masternode_engine.as_ref()?;
        engine.read().await.latest_masternode_list().cloned()
    }

    /// Blocking twin of [`Self::latest_masternode_list`] for threads outside the
    /// async runtime, such as FFI callers.
    ///
    /// # Panics
    ///
    /// Panics when called from an async execution context, like
    /// [`RwLock::blocking_read`].
    pub fn latest_masternode_list_blocking(&self) -> Option<MasternodeList> {
        let engine = self.masternode_engine.as_ref()?;
        engine.blocking_read().latest_masternode_list().cloned()
    }

    /// Get a quorum entry by type and hash at a specific block height. Only
    /// heights within the lists the engine holds resolve.
    /// Returns `SpvError::QuorumLookupError` if the quorum is not found.
    pub async fn get_quorum_at_height(
        &self,
        height: u32,
        quorum_type: LLMQType,
        quorum_hash: QuorumHash,
    ) -> Result<QualifiedQuorumEntry> {
        let engine = self.masternode_list_engine()?;
        let quorum = engine
            .read()
            .await
            .quorum_entry_for_hash_at_or_before_height(quorum_type, quorum_hash, height)
            .map(|(_, quorum)| quorum.clone());

        quorum.ok_or_else(|| {
            let message = format!(
                "Quorum not found: type {} at or before height {} with hash {}",
                quorum_type,
                height,
                quorum_hash.as_byte_array().to_lower_hex_string()
            );
            tracing::warn!("{}", message);
            SpvError::QuorumLookupError(message)
        })
    }
}
