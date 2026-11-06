//! Signed fixtures for consumers testing authenticated InstantSend replay.

use std::collections::BTreeMap;

use dashcore::bls_sig_utils::{BLSPublicKey, BLSSignature, BlsError, BlsScheme, BlsSkBytes};
use dashcore::hash_types::QuorumVVecHash;
use dashcore::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use dashcore::sml::llmq_type::network::NetworkLLMQExt;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::transaction::special_transaction::quorum_commitment::QuorumEntry;
use dashcore::{BlockHash, InstantLock, Network, QuorumHash, Transaction};
use key_wallet_manager::WalletInterface;

use crate::client::DashSpvClient;
use crate::error::SpvError;
use crate::network::NetworkManager;

/// Failure to build a deterministic signed test fixture.
#[derive(Debug, thiserror::Error)]
pub enum InstantLockFixtureError {
    /// The fixture key could not sign.
    #[error("invalid fixture BLS key: {0}")]
    Key(#[from] BlsError),
    /// The lock signing digest could not be encoded.
    #[error("cannot encode fixture signing digest: {0}")]
    Encoding(#[from] std::io::Error),
}

/// A lock signed by a constant, public test key, and a synthetic quorum cycle for it.
///
/// `install` makes every lock signed by that key verify on the client it is installed
/// into, so use it only on throwaway test clients. It is never a network proof.
#[derive(Debug, Clone)]
pub struct InstantLockFixture {
    instant_lock: InstantLock,
    quorums: BTreeMap<u16, QualifiedQuorumEntry>,
}

impl InstantLockFixture {
    /// Signs the transaction's ID and ordered inputs with a quorum of `network`'s
    /// InstantSend quorum type.
    pub fn new(
        network: Network,
        transaction: &Transaction,
    ) -> Result<Self, InstantLockFixtureError> {
        let secret = BlsSkBytes::from_bytes([1; 32]);
        let key = secret.as_scheme(BlsScheme::Modern);
        let llmq_type = network.isd_llmq_type();
        let quorum_hash = QuorumHash::from_byte_array([9; 32]);
        let mut instant_lock = InstantLock {
            version: 1,
            inputs: transaction.input.iter().map(|input| input.previous_output).collect(),
            txid: transaction.txid(),
            cyclehash: BlockHash::from_byte_array([8; 32]),
            signature: BLSSignature::from([0; 96]),
        };
        let digest = instant_lock.sign_id(llmq_type, quorum_hash, None)?;
        instant_lock.signature = key.sign_digest(digest.as_byte_array())?;
        let quorum_public_key = BLSPublicKey::from(key.public_key()?);
        let quorums = (0..llmq_type.active_quorum_count() as u16)
            .map(|index| {
                let entry = QuorumEntry {
                    version: 2,
                    llmq_type,
                    quorum_hash,
                    quorum_index: Some(index as i16),
                    signers: vec![true; 4],
                    valid_members: vec![true; 4],
                    quorum_public_key,
                    quorum_vvec_hash: QuorumVVecHash::all_zeros(),
                    threshold_sig: instant_lock.signature,
                    all_commitment_aggregated_signature: instant_lock.signature,
                };
                let mut quorum = QualifiedQuorumEntry::from(entry);
                quorum.verified = LLMQEntryVerificationStatus::Verified;
                (index, quorum)
            })
            .collect();
        Ok(Self {
            instant_lock,
            quorums,
        })
    }

    /// Omits one quorum slot to model a cycle whose synchronization is incomplete.
    pub fn without_quorum(mut self, index: u16) -> Self {
        self.quorums.remove(&index);
        self
    }

    /// The signed payload to pass through the public verification query.
    pub fn instant_lock(&self) -> &InstantLock {
        &self.instant_lock
    }

    /// Installs this synthetic quorum cycle into the client's engine.
    pub async fn install<W: WalletInterface, N: NetworkManager>(
        &self,
        client: &DashSpvClient<W, N>,
    ) -> Result<(), SpvError> {
        let engine = client.masternode_list_engine()?;
        engine
            .write()
            .await
            .install_test_instant_lock_cycle(self.instant_lock.cyclehash, self.quorums.clone());
        Ok(())
    }
}
