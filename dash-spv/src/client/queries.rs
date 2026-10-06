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
use crate::storage::{BlockHeaderStorage, PersistentBlockHeaderStorage, StorageManager};
use dashcore::hashes::Hash;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::{BlockHash, QuorumHash};
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

    /// Get a quorum entry by type and hash at a specific block height. A height
    /// whose lists the engine no longer holds is rebuilt from storage.
    /// Returns `SpvError::QuorumLookupError` if the quorum is not found.
    pub async fn get_quorum_at_height(
        &self,
        height: u32,
        quorum_type: LLMQType,
        quorum_hash: QuorumHash,
    ) -> Result<QualifiedQuorumEntry> {
        let (in_memory, oldest_list) = {
            let engine = self.masternode_list_engine()?;
            let engine = engine.read().await;
            let quorum = engine
                .quorum_entry_for_hash_at_or_before_height(quorum_type, quorum_hash, height)
                .map(|(_, quorum)| quorum.clone());
            (quorum, engine.masternode_lists.keys().next().copied())
        };

        let quorum = match in_memory {
            Some(quorum) => Some(quorum),
            None => {
                let (headers, masternodes) = {
                    let storage = self.storage.lock().await;
                    (storage.block_headers(), storage.masternodes())
                };
                let quorum_block = BlockHash::from_byte_array(quorum_hash.to_byte_array());
                let mined = headers.read().await.get_header_height_by_hash(&quorum_block).await?;
                if storage_may_hold(mined, height, oldest_list) {
                    let log = masternodes.read().await.message_log();
                    log.quorum_entry_at_or_before(quorum_type, quorum_hash, height).await
                } else {
                    None
                }
            }
        };

        quorum.ok_or_else(|| {
            let message = format!(
                "Quorum not found: type {} at or before height {} with hash {}",
                quorum_type,
                height,
                hex::encode(quorum_hash)
            );
            tracing::warn!("{}", message);
            SpvError::QuorumLookupError(message)
        })
    }
}

/// Whether the stored messages can resolve a quorum the engine missed. A
/// quorum's hash is the block it was mined in, so a hash outside the header
/// chain names no quorum, one mined above `height` was not active there, and
/// one mined at or above the engine's oldest list was held by every list the
/// engine kept since. Only a quorum mined below that list may sit in lists the
/// engine has pruned.
fn storage_may_hold(mined: Option<u32>, height: u32, oldest_list: Option<u32>) -> bool {
    mined.is_some_and(|mined| mined <= height && oldest_list.is_none_or(|oldest| mined < oldest))
}

#[cfg(test)]
mod tests {
    use super::storage_may_hold;

    #[test]
    fn only_a_quorum_mined_below_the_oldest_list_goes_to_storage() {
        assert!(!storage_may_hold(None, 1_000, Some(500)), "not a block in the header chain");
        assert!(!storage_may_hold(Some(1_001), 1_000, Some(500)), "mined above the lookup");
        assert!(!storage_may_hold(Some(600), 1_000, Some(500)), "the engine held all its lists");
        assert!(storage_may_hold(Some(400), 1_000, Some(500)), "its lists may be pruned");
        assert!(storage_may_hold(Some(400), 1_000, None), "the engine holds no list yet");
    }
}
