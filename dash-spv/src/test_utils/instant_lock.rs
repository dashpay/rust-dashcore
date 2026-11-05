//! Signed fixtures for consumers testing authenticated InstantSend replay.

use std::collections::BTreeMap;

use dash_pkc::bls::{BlsError, BlsScIetf, BlsSecretKey};
use dashcore::bls_sig_utils::{BLSPublicKey, BLSSignature};
use dashcore::hash_types::QuorumVVecHash;
use dashcore::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::transaction::special_transaction::quorum_commitment::QuorumEntry;
use dashcore::{BlockHash, InstantLock, QuorumHash, Transaction};
use key_wallet_manager::WalletInterface;

use crate::client::DashSpvClient;
use crate::error::SpvError;
use crate::network::NetworkManager;

/// Failure to build a deterministic signed test fixture.
#[derive(Debug, thiserror::Error)]
pub enum InstantLockFixtureError {
    /// The fixture key could not be constructed.
    #[error("invalid fixture BLS key: {0}")]
    Key(#[from] BlsError),
    /// The lock signing digest could not be encoded.
    #[error("cannot encode fixture signing digest: {0}")]
    Encoding(#[from] std::io::Error),
}

/// A signed lock and synthetic quorum for isolated tests, never a network proof.
///
/// Install into a temporary test client's engine, then call the client's public
/// `verify_instant_lock` query. This fixture cannot construct a verified token.
#[derive(Debug, Clone)]
pub struct InstantLockFixture {
    instant_lock: InstantLock,
    quorums: BTreeMap<u16, QualifiedQuorumEntry>,
}

impl InstantLockFixture {
    /// Signs the transaction's ID and ordered inputs using a deterministic test key.
    pub fn new(transaction: &Transaction) -> Result<Self, InstantLockFixtureError> {
        let key = BlsSecretKey::<BlsScIetf>::from_bytes(&[1; 32])?;
        let llmq_type = LLMQType::LlmqtypeTestDIP0024;
        let quorum_hash = QuorumHash::from_byte_array([9; 32]);
        let mut instant_lock = InstantLock {
            version: 1,
            inputs: transaction.input.iter().map(|input| input.previous_output).collect(),
            txid: transaction.txid(),
            cyclehash: BlockHash::from_byte_array([8; 32]),
            signature: BLSSignature::from([0; 96]),
        };
        let digest = instant_lock.sign_id(llmq_type, quorum_hash, None)?;
        instant_lock.signature =
            BLSSignature::from(key.sign_digest(digest.as_byte_array()).to_bytes());
        let quorums = (0..llmq_type.active_quorum_count() as u16)
            .map(|index| {
                let entry = QuorumEntry {
                    version: 2,
                    llmq_type,
                    quorum_hash,
                    quorum_index: Some(index as i16),
                    signers: vec![true; 4],
                    valid_members: vec![true; 4],
                    quorum_public_key: BLSPublicKey::from(key.public_key().to_bytes()),
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

    /// Installs this synthetic quorum into an isolated test client's engine.
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
