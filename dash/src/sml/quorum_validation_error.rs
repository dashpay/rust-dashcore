use thiserror::Error;
use crate::BlockHash;
use crate::prelude::CoreBlockHeight;

#[derive(Debug, Error, Clone, Ord, PartialOrd, PartialEq, Hash, Eq)]
pub enum QuorumValidationError {
    #[error("Required block not present: {0}")]
    RequiredBlockNotPresent(BlockHash),

    #[error("Required masternode list not present at block height {0}, block hash: {1}")]
    RequiredMasternodeListNotPresent(CoreBlockHeight, BlockHash),

    #[error("Required chain lock not present at block height {0}, block hash: {1}")]
    RequiredChainLockNotPresent(CoreBlockHeight, BlockHash),

    #[error("Insufficient signers: required {required}, found {found}")]
    InsufficientSigners { required: u64, found: u64 },

    #[error("Insufficient valid members: required {required}, found {found}")]
    InsufficientValidMembers { required: u64, found: u64 },

    #[error("Mismatched bitset lengths: signers length {signers_len}, valid members length {valid_members_len}")]
    MismatchedBitsetLengths { signers_len: usize, valid_members_len: usize },

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
}