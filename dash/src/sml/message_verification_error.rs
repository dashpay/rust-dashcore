#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use hashes::sha256d;
use thiserror::Error;

use crate::QuorumHash;
use crate::bls_sig_utils::{BLSPublicKey, BLSSignature};
use crate::hash_types::CycleHash;
use crate::prelude::CoreBlockHeight;
use crate::sml::llmq_type::LLMQType;
use crate::sml::quorum_validation_error::QuorumValidationError;

#[derive(Debug, Error, Clone, Ord, PartialOrd, PartialEq, Hash, Eq)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MessageVerificationError {
    #[error("Required cycle not present to verify instant send: {0}")]
    CycleHashNotPresent(CycleHash),

    #[error("Required cycle present but has no quorum: {0}")]
    CycleHashEmpty(CycleHash),

    #[error("Quorum with index {0} not found in cycle {1}")]
    QuorumIndexNotFound(u16, CycleHash),

    #[error("No masternode lists in engine")]
    NoMasternodeLists,

    #[error("Masternode list at height {0} has no quorums")]
    MasternodeListHasNoQuorums(CoreBlockHeight),

    #[error(
        "Threshold signature {0} is not valid for digest {1} using public key {2} for quorum {3} of type {4}, error is: {5}"
    )]
    ThresholdSignatureNotValid(
        Box<BLSSignature>,
        Box<sha256d::Hash>,
        Box<BLSPublicKey>,
        QuorumHash,
        LLMQType,
        String,
    ),

    #[error("Error: {0}")]
    Generic(String),

    #[error("Invalid BLS public key: {0}")]
    InvalidBLSPublicKey(String),

    #[error("Invalid BLS signature: {0}")]
    InvalidBLSSignature(String),
}

impl From<String> for MessageVerificationError {
    fn from(value: String) -> Self {
        MessageVerificationError::Generic(value)
    }
}

impl From<QuorumValidationError> for MessageVerificationError {
    fn from(value: QuorumValidationError) -> Self {
        match value {
            QuorumValidationError::InvalidBLSPublicKey(public_key) => {
                MessageVerificationError::InvalidBLSPublicKey(public_key)
            }
            QuorumValidationError::InvalidBLSSignature(signature) => {
                MessageVerificationError::InvalidBLSSignature(signature)
            }
            error => MessageVerificationError::Generic(error.to_string()),
        }
    }
}
