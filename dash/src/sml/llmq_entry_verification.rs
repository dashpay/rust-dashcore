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
    OtherContext(String),
    SignaturesUnavailable,
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
                LLMQEntryVerificationSkipStatus::OtherContext(message) => {
                    format!("OtherContext({message})")
                }
                LLMQEntryVerificationSkipStatus::SignaturesUnavailable => {
                    "SignaturesUnavailable".to_string()
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
