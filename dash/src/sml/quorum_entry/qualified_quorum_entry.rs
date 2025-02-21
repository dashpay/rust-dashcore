#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use hashes::Hash;
use crate::hash_types::{QuorumCommitmentHash, QuorumEntryHash};
use crate::sml::llmq_entry_verification::{LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus};
use crate::sml::quorum_validation_error::QuorumValidationError;
use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct QualifiedQuorumEntry {
    pub quorum_entry: QuorumEntry,
    pub verified: LLMQEntryVerificationStatus,
    pub commitment_hash: QuorumCommitmentHash,
    pub entry_hash: QuorumEntryHash,
}

impl From<QuorumEntry> for QualifiedQuorumEntry {
    fn from(value: QuorumEntry) -> Self {
        let commitment_hash = value.calculate_commitment_hash();
        let entry_hash = value.calculate_entry_hash();
        QualifiedQuorumEntry {
            quorum_entry: value,
            verified: LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::NotMarkedForVerification), // Default to unverified
            commitment_hash,
            entry_hash,
        }
    }
}

impl QualifiedQuorumEntry {
    pub fn update_quorum_status(&mut self, result: Result<(), QuorumValidationError>) {
        match result {
            Err(QuorumValidationError::RequiredBlockNotPresent(block_hash)) => {
                self.verified = LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::UnknownBlock(block_hash.to_byte_array()));
            }
            Err(QuorumValidationError::RequiredMasternodeListNotPresent(block_height)) => {
                self.verified = LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::MissedList(block_height));
            }
            Err(e) => {
                self.verified = LLMQEntryVerificationStatus::Invalid(e);
            }
            Ok(_) => {
                self.verified = LLMQEntryVerificationStatus::Verified;
            }
        }
    }
}