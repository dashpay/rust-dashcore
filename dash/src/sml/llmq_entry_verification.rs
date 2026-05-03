use core::fmt::{Display, Formatter};

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};

use crate::BlockHash;
use crate::prelude::CoreBlockHeight;
use crate::sml::quorum_validation_error::QuorumValidationError;

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LLMQEntryVerificationSkipStatus {
    NotMarkedForVerification,
    MissedList(CoreBlockHeight),
    UnknownBlock(BlockHash),
    /// The quorum entry came through without an attached
    /// `VerifyingChainLockSignaturesType::Rotating`. Typically happens when
    /// a QRInfo's historical diff covers a block range in which no rotating
    /// DKG successfully committed, so `apply_diff` extracts no
    /// `rotation_sig` and `feed_qr_info` can't populate the 4-sig tuple for
    /// the quorums in `lastCommitmentPerIndex`.
    MissingRotationChainLockSigs(BlockHash),
    OtherContext(String),
}

impl Display for LLMQEntryVerificationSkipStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            match self {
                LLMQEntryVerificationSkipStatus::NotMarkedForVerification => {
                    "NotMarkedForVerification".to_string()
                }
                LLMQEntryVerificationSkipStatus::MissedList(block_height) => {
                    format!("MissedList({})", block_height)
                }
                LLMQEntryVerificationSkipStatus::UnknownBlock(block_hash) => {
                    format!("UnknownBlock({})", block_hash)
                }
                LLMQEntryVerificationSkipStatus::MissingRotationChainLockSigs(quorum_hash) => {
                    format!("MissingRotationChainLockSigs({})", quorum_hash)
                }
                LLMQEntryVerificationSkipStatus::OtherContext(message) => {
                    format!("OtherContext({message})")
                }
            }
            .as_str(),
        )
    }
}

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LLMQEntryVerificationStatus {
    #[default]
    Unknown,
    Verified,
    Skipped(LLMQEntryVerificationSkipStatus),
    Invalid(QuorumValidationError),
}
impl From<QuorumValidationError> for LLMQEntryVerificationStatus {
    /// Classify a validation error as either `Skipped` (missing infrastructure
    /// data that the caller should have provided) or `Invalid` (the quorum
    /// data itself is genuinely bad).
    fn from(error: QuorumValidationError) -> Self {
        match error {
            QuorumValidationError::RequiredBlockNotPresent(block_hash, _) => {
                Self::Skipped(LLMQEntryVerificationSkipStatus::UnknownBlock(block_hash))
            }
            QuorumValidationError::RequiredMasternodeListNotPresent(height)
            | QuorumValidationError::RequiredBlockHeightNotPresent(height) => {
                Self::Skipped(LLMQEntryVerificationSkipStatus::MissedList(height))
            }
            QuorumValidationError::RequiredSnapshotNotPresent(hash) => {
                Self::Skipped(LLMQEntryVerificationSkipStatus::UnknownBlock(hash))
            }
            QuorumValidationError::RequiredRotatedChainLockSigsNotPresent(quorum_hash) => {
                Self::Skipped(LLMQEntryVerificationSkipStatus::MissingRotationChainLockSigs(
                    quorum_hash,
                ))
            }
            other => Self::Invalid(other),
        }
    }
}

impl Display for LLMQEntryVerificationStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            match self {
                LLMQEntryVerificationStatus::Unknown => "unknown".to_string(),
                LLMQEntryVerificationStatus::Verified => "verified".to_string(),
                LLMQEntryVerificationStatus::Invalid(error) => format!("Invalid({error})"),
                LLMQEntryVerificationStatus::Skipped(reason) => format!("Skipped({reason})"),
            }
            .as_str(),
        )
    }
}
