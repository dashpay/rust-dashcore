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
use dashcore::sml::llmq_entry_verification::{
    LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus,
};
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::{BlockHash, QuorumHash};
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
    /// not built a list yet. No verified ChainLock may cover it yet, so its
    /// entries and quorum statuses may come from headers a peer made up; see
    /// [`Self::latest_anchored_masternode_list`].
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

    /// The newest masternode list at or below the ChainLock anchor (the best
    /// verified ChainLock, or the checkpoint trust starts from), `None` while
    /// there is none. Unlike [`Self::latest_masternode_list`], what it holds is
    /// bound to a chain that is final, so it is the one to read for decisions
    /// that rely on a masternode's entry.
    pub async fn latest_anchored_masternode_list(&self) -> Option<MasternodeList> {
        let engine = self.masternode_engine.as_ref()?;
        engine.read().await.latest_anchored_list(u32::MAX).await.cloned()
    }

    /// Get a quorum entry by type and hash at a specific block height.
    ///
    /// Only heights the engine holds lists for resolve. It keeps lists within
    /// its retention window below its newest list, a few days of blocks, and
    /// right after a restart only up to the newest list it stored, until sync
    /// catches up with the tip.
    ///
    /// Returns `SpvError::QuorumLookupError` if the quorum is not found.
    ///
    /// The entry comes from the newest list holding it at or below both
    /// `height` and the ChainLock anchor (the best verified ChainLock, or the
    /// checkpoint trust starts from). A quorum only lists above the anchor hold
    /// is returned with `Skipped(MissingChainLock(list height, list block))`,
    /// whatever DIP-6 found: those lists may sit on headers a peer made up.
    /// Only a `Verified` entry is fit to verify signatures.
    pub async fn get_quorum_at_height(
        &self,
        height: u32,
        quorum_type: LLMQType,
        quorum_hash: QuorumHash,
    ) -> Result<QualifiedQuorumEntry> {
        let engine = self.masternode_list_engine()?;
        let engine = engine.read().await;
        let quorum = match engine.anchored_quorum(quorum_type, quorum_hash, height).await {
            Some((_, quorum)) => Some(quorum.clone()),
            None => engine
                .quorum_entry_for_hash_at_or_before_height(quorum_type, quorum_hash, height)
                .and_then(|(list_height, quorum)| {
                    let list = engine.masternode_lists.get(&list_height)?;
                    Some(not_chain_locked(quorum, list_height, list.block_hash))
                }),
        };
        drop(engine);

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

/// `quorum` as held by a list the ChainLock anchor does not cover yet.
fn not_chain_locked(
    quorum: &QualifiedQuorumEntry,
    list_height: u32,
    list_hash: BlockHash,
) -> QualifiedQuorumEntry {
    let mut quorum = quorum.clone();
    quorum.verified = LLMQEntryVerificationStatus::Skipped(
        LLMQEntryVerificationSkipStatus::MissingChainLock(list_height, list_hash),
    );
    quorum
}

#[cfg(test)]
mod tests {
    use crate::client::{ClientConfig, DashSpvClient};
    use crate::sml_engine::test_support::quorum_entry;
    use crate::sml_engine::{AnchorRoot, ChainLockAnchor};
    use crate::test_utils::MockNetworkManager;
    use dashcore::hashes::Hash;
    use dashcore::sml::llmq_entry_verification::{
        LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus,
    };
    use dashcore::sml::llmq_type::network::NetworkLLMQExt;
    use dashcore::sml::masternode_list::MasternodeList;
    use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
    use dashcore::{BlockHash, Network, QuorumHash};
    use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
    use key_wallet_manager::WalletManager;
    use std::sync::Arc;
    use tempfile::TempDir;
    use test_case::test_case;
    use tokio::sync::RwLock;

    /// The anchored entry comes back with its own status: anchoring only takes
    /// trust away, and a quorum DIP-6 verified in a list a checkpoint covers is
    /// fit to verify signatures.
    #[tokio::test]
    async fn a_quorum_an_anchored_list_holds_keeps_its_status() {
        let temp_dir = TempDir::new().unwrap();
        let config = ClientConfig::mainnet().without_filters().with_storage_path(temp_dir.path());
        let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(config.network)));
        let client = DashSpvClient::new(config, MockNetworkManager::new(), wallet, vec![])
            .await
            .expect("client construction must succeed");
        let tip = client.tip_header().await.expect("a stored tip");
        let (height, block_hash) = (tip.height(), *tip.hash());

        let platform_type = Network::Mainnet.platform_type();
        let quorum_hash = QuorumHash::from_byte_array([0x42; 32]);
        let mut quorum: QualifiedQuorumEntry =
            quorum_entry(platform_type, quorum_hash, None).into();
        quorum.verified = LLMQEntryVerificationStatus::Verified;
        let mut list = MasternodeList::empty(block_hash, height);
        Arc::make_mut(&mut list.quorums)
            .entry(platform_type)
            .or_default()
            .insert(quorum_hash, Arc::new(quorum));
        let engine = client.masternode_list_engine().expect("masternodes are enabled");
        {
            let mut engine = engine.write().await;
            engine.masternode_lists.insert(height, list);
            engine.set_root_anchor(ChainLockAnchor {
                height,
                block_hash,
                root: AnchorRoot::Checkpoint(height),
            });
        }

        let quorum = client
            .get_quorum_at_height(height + 100, platform_type, quorum_hash)
            .await
            .expect("the engine holds the quorum");

        assert_eq!(quorum.verified, LLMQEntryVerificationStatus::Verified);
        assert_eq!(
            client.latest_anchored_masternode_list().await.map(|list| list.known_height),
            Some(height)
        );
    }

    /// A quorum in a list no verified ChainLock covers is not `Verified` to a
    /// caller, whatever DIP-6 found: the list may sit on headers a peer made up,
    /// and DIP-6 checks the quorum against members from that same list.
    #[test_case(false; "without an anchor")]
    #[test_case(true; "above the anchor")]
    #[tokio::test]
    async fn a_quorum_no_verified_chain_lock_covers_is_not_reported_verified(anchored_below: bool) {
        let temp_dir = TempDir::new().unwrap();
        let config = ClientConfig::mainnet().without_filters().with_storage_path(temp_dir.path());
        let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(config.network)));
        let client = DashSpvClient::new(config, MockNetworkManager::new(), wallet, vec![])
            .await
            .expect("client construction must succeed");
        let tip = client.tip_header().await.expect("a stored tip");
        let height = tip.height() + 1;

        let platform_type = Network::Mainnet.platform_type();
        let quorum_hash = QuorumHash::from_byte_array([0x42; 32]);
        let mut quorum: QualifiedQuorumEntry =
            quorum_entry(platform_type, quorum_hash, None).into();
        quorum.verified = LLMQEntryVerificationStatus::Verified;
        let list_hash = BlockHash::from_byte_array([0x43; 32]);
        let mut list = MasternodeList::empty(list_hash, height);
        Arc::make_mut(&mut list.quorums)
            .entry(platform_type)
            .or_default()
            .insert(quorum_hash, Arc::new(quorum));
        let engine = client.masternode_list_engine().expect("masternodes are enabled");
        {
            let mut engine = engine.write().await;
            engine.masternode_lists.insert(height, list);
            if anchored_below {
                let anchored = MasternodeList::empty(*tip.hash(), tip.height());
                engine.masternode_lists.insert(tip.height(), anchored);
                engine.set_root_anchor(ChainLockAnchor {
                    height: tip.height(),
                    block_hash: *tip.hash(),
                    root: AnchorRoot::Checkpoint(tip.height()),
                });
            }
        }

        let quorum = client
            .get_quorum_at_height(height, platform_type, quorum_hash)
            .await
            .expect("the engine holds the quorum");

        assert_eq!(
            quorum.verified,
            LLMQEntryVerificationStatus::Skipped(
                LLMQEntryVerificationSkipStatus::MissingChainLock(height, list_hash)
            )
        );
    }
}
