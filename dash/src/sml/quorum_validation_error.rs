#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use thiserror::Error;

use crate::prelude::CoreBlockHeight;
use crate::sml::error::SmlError;
use crate::sml::llmq_type::LLMQType;
use crate::sml::masternode_list_engine::RotationChainLockSignatureSlot;
use crate::{BlockHash, QuorumHash};

#[derive(Debug, Error, Clone, Ord, PartialOrd, PartialEq, Hash, Eq)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ClientDataRetrievalError {
    #[error("Required block not present: {0}")]
    RequiredBlockNotPresent(BlockHash),

    #[error("Coinbase not found on block: {0}")]
    CoinbaseNotFoundOnBlock(BlockHash),
}

#[derive(Debug, Error, Clone, Ord, PartialOrd, PartialEq, Hash, Eq)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum QuorumValidationError {
    #[error("Required block not present: {0} ({1})")]
    RequiredBlockNotPresent(BlockHash, String),

    #[error("Required block height not present: {0}")]
    RequiredBlockHeightNotPresent(CoreBlockHeight),

    #[error("The masternode list was not present at block height {0}")]
    VerifyingMasternodeListNotPresent(CoreBlockHeight),

    #[error("Required masternode list not present at block height {0}")]
    RequiredMasternodeListNotPresent(CoreBlockHeight),

    #[error("Required chain lock not present at block height {0}, block hash: {1}")]
    RequiredChainLockNotPresent(CoreBlockHeight, BlockHash),

    #[error(
        "Required rotated chain lock sig at h - {0} not present for masternode diff block hash: {1}"
    )]
    RequiredRotatedChainLockSigNotPresent(u8, BlockHash),

    #[error("Required rotated chain lock sigs not present for masternode diff block hash: {0}")]
    RequiredRotatedChainLockSigsNotPresent(BlockHash),

    #[error("Insufficient signers: required {required}, found {found}")]
    InsufficientSigners {
        required: u64,
        found: u64,
    },

    #[error("Insufficient valid members: required {required}, found {found}")]
    InsufficientValidMembers {
        required: u64,
        found: u64,
    },

    #[error(
        "Mismatched bitset lengths: signers length {signers_len}, valid members length {valid_members_len}"
    )]
    MismatchedBitsetLengths {
        signers_len: usize,
        valid_members_len: usize,
    },

    #[error("Invalid quorum public key")]
    InvalidQuorumPublicKey,

    #[error("Invalid BLS public key: {0}")]
    InvalidBLSPublicKey(String),

    #[error("Invalid BLS signature: {0}")]
    InvalidBLSSignature(String),

    #[error("Invalid quorum signature")]
    InvalidQuorumSignature,

    #[error("Invalid final signature")]
    InvalidFinalSignature,

    #[error("All commitment aggregated signature not valid: {0}")]
    AllCommitmentAggregatedSignatureNotValid(String),

    #[error("Threshold signature not valid: {0}")]
    ThresholdSignatureNotValid(String),

    #[error("Commitment hash not present")]
    CommitmentHashNotPresent,

    #[error("Required snapshot not present {0}")]
    RequiredSnapshotNotPresent(BlockHash),

    #[error("Simplified masternode list error {0}")]
    SMLError(SmlError),

    #[error("Required quorum index not present for quorum hash: {0}")]
    RequiredQuorumIndexNotPresent(QuorumHash),

    #[error(
        "Too many rotated quorums in cycle for {llmq_type}: cap is {cap}, attempted to insert another"
    )]
    TooManyRotatedQuorumsInCycle {
        llmq_type: LLMQType,
        cap: usize,
    },

    #[error("Corrupted code execution: {0}")]
    CorruptedCodeExecution(String),
    #[error("Expected only rotated quorums, but got quorum {0} of type {1}")]
    ExpectedOnlyRotatedQuorums(QuorumHash, LLMQType),

    #[error(transparent)]
    ClientDataRetrievalError(ClientDataRetrievalError),

    /// Error indicating that a required feature is not turned on.
    #[error("Feature not turned on: {0}")]
    FeatureNotTurnedOn(String),

    /// Returned by `feed_qr_info` when one or more rotation ChainLock signatures are
    /// absent for a QRInfo whose `last_commitment_per_index` contains quorums that need
    /// fresh validation. The `missing` vector lists every absent slot at once (rather
    /// than erroring on the first one) for diagnostic clarity.
    #[error("Missing rotation ChainLock signatures in QRInfo: {}", format_missing_slots(missing))]
    MissingRotationSignatures {
        missing: Vec<RotationChainLockSignatureSlot>,
    },
}

fn format_missing_slots(slots: &[RotationChainLockSignatureSlot]) -> String {
    slots.iter().map(|s| s.legacy_short_name()).collect::<Vec<_>>().join(", ")
}

impl From<SmlError> for QuorumValidationError {
    fn from(value: SmlError) -> Self {
        QuorumValidationError::SMLError(value)
    }
}

impl From<ClientDataRetrievalError> for QuorumValidationError {
    fn from(value: ClientDataRetrievalError) -> Self {
        QuorumValidationError::ClientDataRetrievalError(value)
    }
}
