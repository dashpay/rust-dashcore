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
use crate::validation::{InstantLockVerificationError, VerifiedInstantLock};
use dashcore::hashes::Hash;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::{InstantLock, QuorumHash};
use key_wallet_manager::WalletInterface;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::DashSpvClient;
use hex_conservative::DisplayHex;

impl<W: WalletInterface, N: NetworkManager> DashSpvClient<W, N> {
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

    /// Authenticates a lock using the client's synchronized quorum state.
    ///
    /// Returns `None` while its cycle or the masternode engine is unavailable.
    /// Malformed locks and invalid signatures return an error. No network request
    /// or wallet mutation is made; callers may retry after masternode sync advances.
    /// Fetch this evidence before acquiring wallet or persistence write locks.
    pub async fn verify_instant_lock(
        &self,
        instant_lock: &InstantLock,
    ) -> std::result::Result<Option<VerifiedInstantLock>, InstantLockVerificationError> {
        let Some(engine) = &self.masternode_engine else {
            return VerifiedInstantLock::verify::<PersistentBlockHeaderStorage>(instant_lock, None);
        };
        let engine = engine.read().await;
        VerifiedInstantLock::verify(instant_lock, Some(&*engine))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientConfig;
    use crate::test_utils::{InstantLockFixture, MockNetworkManager};
    use dashcore::{OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};
    use key_wallet_manager::test_utils::MockWallet;
    use tempfile::TempDir;

    #[tokio::test]
    async fn should_verify_instant_lock_after_cycle_arrives_without_wallet_arithmetic() {
        let directory = TempDir::new().unwrap();
        let config = ClientConfig::mainnet().without_filters().with_storage_path(directory.path());
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        let client = DashSpvClient::new(config, MockNetworkManager::new(), wallet.clone(), vec![])
            .await
            .unwrap();
        let transaction = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([3; 32]), 0),
                ..Default::default()
            }],
            output: vec![
                TxOut {
                    value: u64::MAX,
                    script_pubkey: ScriptBuf::new()
                };
                2
            ],
            special_transaction_payload: None,
        };
        let fixture = InstantLockFixture::new(&transaction).unwrap();
        let lock = fixture.instant_lock();
        assert!(client.verify_instant_lock(lock).await.unwrap().is_none());
        fixture.install(&client).await.unwrap();
        let proof = client.verify_instant_lock(lock).await.unwrap().unwrap();
        assert!(proof.matches_transaction(&transaction));
        assert_eq!(proof.instant_lock(), lock);
        assert_eq!(proof.txid(), transaction.txid());
        assert!(wallet.read().await.processed_instant_locks.lock().await.is_empty());

        let mut changed_body = transaction.clone();
        changed_body.output[0].value -= 1;
        assert!(!proof.matches_transaction(&changed_body));
        let mut wrong_txid = lock.clone();
        wrong_txid.txid = changed_body.txid();
        let mut wrong_input = lock.clone();
        wrong_input.inputs[0].vout += 1;
        let mut wrong_signature = lock.clone();
        wrong_signature.signature = dashcore::bls_sig_utils::BLSSignature::from([1; 96]);
        for invalid in [wrong_txid, wrong_input, wrong_signature] {
            assert!(matches!(
                client.verify_instant_lock(&invalid).await,
                Err(InstantLockVerificationError::InvalidSignature(_))
            ));
        }
    }

    #[tokio::test]
    async fn should_defer_instant_lock_when_masternodes_are_disabled() {
        let directory = TempDir::new().unwrap();
        let config = ClientConfig::mainnet()
            .without_filters()
            .without_masternodes()
            .with_storage_path(directory.path());
        let client = DashSpvClient::new(
            config,
            MockNetworkManager::new(),
            Arc::new(RwLock::new(MockWallet::new())),
            vec![],
        )
        .await
        .unwrap();
        assert!(client.verify_instant_lock(&InstantLock::dummy(0..1)).await.unwrap().is_none());
        assert!(matches!(
            client.verify_instant_lock(&InstantLock::default()).await,
            Err(InstantLockVerificationError::Malformed(_))
        ));
    }
}
