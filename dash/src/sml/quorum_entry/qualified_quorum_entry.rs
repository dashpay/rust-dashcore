use crate::bls_sig_utils::BLSSignature;
use crate::hash_types::{QuorumCommitmentHash, QuorumEntryHash};
use crate::sml::llmq_entry_verification::{
    LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus,
};
use crate::sml::quorum_validation_error::QuorumValidationError;
use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;
#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[allow(clippy::large_enum_variant)]
pub enum VerifyingChainLockSignaturesType {
    Rotating([BLSSignature; 4]),
    NonRotating(BLSSignature),
}

/// A structured representation of a quorum entry with additional validation status and commitment hashes.
///
/// This struct wraps a `QuorumEntry` and includes additional metadata used to track the verification
/// status of the quorum, as well as its computed commitment and entry hashes.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct QualifiedQuorumEntry {
    /// The underlying quorum entry
    pub quorum_entry: QuorumEntry,
    /// The verification status of the quorum entry.
    pub verified: LLMQEntryVerificationStatus,
    /// The computed hash of the quorum commitment.
    pub commitment_hash: QuorumCommitmentHash,
    /// The computed hash of the quorum entry.
    pub entry_hash: QuorumEntryHash,
    /// The chain lock signature that can be used for the quorum entry
    pub verifying_chain_lock_signature: Option<VerifyingChainLockSignaturesType>,
}

impl From<QuorumEntry> for QualifiedQuorumEntry {
    fn from(value: QuorumEntry) -> Self {
        let commitment_hash = value.calculate_commitment_hash();
        let entry_hash = value.calculate_entry_hash();
        QualifiedQuorumEntry {
            quorum_entry: value,
            verified: LLMQEntryVerificationStatus::Skipped(
                LLMQEntryVerificationSkipStatus::NotMarkedForVerification,
            ), // Default to unverified
            commitment_hash,
            entry_hash,
            verifying_chain_lock_signature: None,
        }
    }
}

impl QualifiedQuorumEntry {
    /// Updates the verification status of the quorum based on a validation result.
    ///
    /// On `Ok`, sets `verified` to `Verified`. On `Err`, classifies the error
    /// via `From<QuorumValidationError> for LLMQEntryVerificationStatus`,
    /// which decides whether the failure is `Skipped` (missing infrastructure
    /// the caller should have provided) or `Invalid` (genuinely bad quorum
    /// data).
    pub fn update_quorum_status(&mut self, result: Result<(), QuorumValidationError>) {
        self.verified = match result {
            Ok(_) => LLMQEntryVerificationStatus::Verified,
            Err(e) => e.into(),
        };
    }
}

#[cfg(test)]
mod tests {
    use hashes::Hash;

    use super::*;
    use crate::QuorumHash;
    use crate::bls_sig_utils::{BLSPublicKey, BLSSignature};
    use crate::hash_types::QuorumVVecHash;
    use crate::sml::llmq_type::LLMQType;

    fn dummy_qualified_quorum_entry() -> QualifiedQuorumEntry {
        QuorumEntry {
            version: 2,
            llmq_type: LLMQType::LlmqtypeTestDIP0024,
            quorum_hash: QuorumHash::all_zeros(),
            quorum_index: Some(0),
            signers: vec![true; 4],
            valid_members: vec![true; 4],
            quorum_public_key: BLSPublicKey::from([1; 48]),
            quorum_vvec_hash: QuorumVVecHash::all_zeros(),
            threshold_sig: BLSSignature::from([1; 96]),
            all_commitment_aggregated_signature: BLSSignature::from([1; 96]),
        }
        .into()
    }

    #[test]
    fn update_quorum_status_delegates_to_classifier() {
        let mut entry = dummy_qualified_quorum_entry();
        entry.update_quorum_status(Ok(()));
        assert_eq!(entry.verified, LLMQEntryVerificationStatus::Verified);

        let snapshot_hash = QuorumHash::from_byte_array([7; 32]);
        let mut entry = dummy_qualified_quorum_entry();
        entry.update_quorum_status(Err(QuorumValidationError::RequiredSnapshotNotPresent(
            snapshot_hash,
        )));
        assert_eq!(
            entry.verified,
            LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::MissingSnapshot(
                snapshot_hash,
            )),
        );
    }
}
