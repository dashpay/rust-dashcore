use hashes::Hash;
use crate::sml::llmq_entry_verification::{LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus};
use crate::sml::quorum_validation_error::QuorumValidationError;
use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct QualifiedQuorumEntry {
    pub quorum_entry: QuorumEntry,
    pub verified: LLMQEntryVerificationStatus,
    pub commitment_hash: Option<[u8; 32]>,
    pub entry_hash: [u8;32],
}

impl QualifiedQuorumEntry {
    pub fn update_quorum_status(&mut self, result: Result<(), QuorumValidationError>) {
        match result {
            Err(QuorumValidationError::RequiredBlockNotPresent(block_hash)) => {
                self.verified = LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::UnknownBlock(block_hash.to_byte_array()));
            }
            Err(QuorumValidationError::RequiredMasternodeListNotPresent(block_height, block_hash)) => {
                self.verified = LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::MissedList(block_height, block_hash.to_byte_array()));
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