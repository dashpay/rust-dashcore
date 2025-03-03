#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};

use crate::hash_types::{QuorumCommitmentHash, QuorumEntryHash};
use crate::sml::llmq_entry_verification::{
    LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus,
};
use crate::sml::quorum_validation_error::QuorumValidationError;
use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;

/// A structured representation of a quorum entry with additional validation status and commitment hashes.
///
/// This struct wraps a `QuorumEntry` and includes additional metadata used to track the verification
/// status of the quorum, as well as its computed commitment and entry hashes.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "apple", ferment_macro::export)]
pub struct QualifiedQuorumEntry {
    /// The underlying quorum entry
    pub quorum_entry: QuorumEntry,
    /// The verification status of the quorum entry.
    pub verified: LLMQEntryVerificationStatus,
    /// The computed hash of the quorum commitment.
    pub commitment_hash: QuorumCommitmentHash,
    /// The computed hash of the quorum entry.
    pub entry_hash: QuorumEntryHash,
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
        }
    }
}

impl QualifiedQuorumEntry {
    /// Updates the verification status of the quorum based on a validation result.
    ///
    /// This method processes the result of a quorum validation and updates the `verified` field accordingly:
    /// - If validation succeeds (`Ok(_)`), the status is set to `Verified`.
    /// - If validation fails due to a missing block, it is marked as `Skipped` with `UnknownBlock`.
    /// - If validation fails due to a missing masternode list, it is marked as `Skipped` with `MissedList`.
    /// - Other errors result in the quorum being marked as `Invalid`.
    ///
    /// # Arguments
    ///
    /// * `result` - A `Result` containing either success (`Ok`) or a `QuorumValidationError`.
    pub fn update_quorum_status(&mut self, result: Result<(), QuorumValidationError>) {
        match result {
            Err(QuorumValidationError::RequiredBlockNotPresent(block_hash)) => {
                self.verified = LLMQEntryVerificationStatus::Skipped(
                    LLMQEntryVerificationSkipStatus::UnknownBlock(block_hash),
                );
            }
            Err(QuorumValidationError::RequiredMasternodeListNotPresent(block_height)) => {
                self.verified = LLMQEntryVerificationStatus::Skipped(
                    LLMQEntryVerificationSkipStatus::MissedList(block_height),
                );
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
