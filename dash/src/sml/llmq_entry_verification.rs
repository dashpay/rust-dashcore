use core::fmt::{Display, Formatter};
use crate::prelude::CoreBlockHeight;
use crate::sml::quorum_validation_error::QuorumValidationError;

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq, Hash, Debug)]
pub enum LLMQEntryVerificationSkipStatus {
    NotMarkedForVerification,
    MissedList(CoreBlockHeight, [u8; 32]),
    UnknownBlock([u8; 32]),
    OtherContext(String),
}

impl Display for LLMQEntryVerificationSkipStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LLMQEntryVerificationSkipStatus::NotMarkedForVerification => "NotMarkedForVerification".to_string(),
            LLMQEntryVerificationSkipStatus::MissedList(block_height, block_hash) => format!("MissedList({}, {})", block_height, hex::encode(block_hash)),
            LLMQEntryVerificationSkipStatus::UnknownBlock(block_hash) => format!("UnknownBlock({})", hex::encode(block_hash)),
            LLMQEntryVerificationSkipStatus::OtherContext(message) => format!("OtherContext({message})"),
        }.as_str())
    }
}

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq, Hash, Debug)]
pub enum LLMQEntryVerificationStatus {
    Unknown,
    Verified,
    Skipped(LLMQEntryVerificationSkipStatus),
    Invalid(QuorumValidationError),
}
impl Display for LLMQEntryVerificationStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LLMQEntryVerificationStatus::Unknown => "unknown".to_string(),
            LLMQEntryVerificationStatus::Verified => "verified".to_string(),
            LLMQEntryVerificationStatus::Invalid(error) => format!("Invalid({error})"),
            LLMQEntryVerificationStatus::Skipped(reason) => format!("Skipped({reason})"),
        }.as_str())
    }
}