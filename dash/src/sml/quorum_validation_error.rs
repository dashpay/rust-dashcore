#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use thiserror::Error;

use crate::prelude::CoreBlockHeight;
use crate::sml::error::SmlError;
use crate::sml::llmq_type::LLMQType;
use crate::{BlockHash, QuorumHash};

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

    #[error("Invalid quorum index {index} for quorum hash: {quorum_hash}")]
    InvalidQuorumIndex {
        quorum_hash: QuorumHash,
        index: i16,
    },

    #[error("Corrupted code execution: {0}")]
    CorruptedCodeExecution(String),
    #[error("Expected only rotated quorums, but got quorum {0} of type {1}")]
    ExpectedOnlyRotatedQuorums(QuorumHash, LLMQType),

    /// Error indicating that a required feature is not turned on.
    #[error("Feature not turned on: {0}")]
    FeatureNotTurnedOn(String),

    // Keep new variants appended at the end: with `bincode` the discriminant is
    // the variant's ordinal, so inserting mid-enum shifts every later variant's
    // encoding and makes a persisted engine blob decode as the wrong error on
    // upgrade. This one was previously inserted between `InvalidQuorumIndex` and
    // `CorruptedCodeExecution`, silently re-numbering the three variants after
    // it; it now sits last so those keep their original discriminants. (#934)
    #[error("Cycle base height {0} is below the history a rotated quorum reconstruction needs")]
    CycleBaseHeightTooLow(CoreBlockHeight),
}

impl From<SmlError> for QuorumValidationError {
    fn from(value: SmlError) -> Self {
        QuorumValidationError::SMLError(value)
    }
}

#[cfg(all(test, feature = "bincode"))]
mod tests {
    use super::*;
    use bincode::{config, decode_from_slice, encode_to_vec};

    /// `bincode` encodes an enum variant by its ordinal, so a persisted
    /// `QuorumValidationError` blob is keyed to the variant order at write time.
    /// `CycleBaseHeightTooLow` was once inserted between `InvalidQuorumIndex` and
    /// `CorruptedCodeExecution`, shifting the three variants after it by one;
    /// moving it to the end restores their discriminants so an engine blob
    /// written before the shift still decodes as the variant it was saved as.
    /// (#934)
    #[test]
    fn later_variants_keep_their_legacy_discriminants() {
        // Legacy layout (before `CycleBaseHeightTooLow` existed) put
        // `CorruptedCodeExecution` at ordinal 22, encoded as `[22, len, bytes]`
        // under the standard config's varint tag.
        let legacy = [22u8, 1, b'x'];
        let (decoded, _): (QuorumValidationError, usize) =
            decode_from_slice(&legacy, config::standard()).expect("legacy blob must decode");
        assert_eq!(
            decoded,
            QuorumValidationError::CorruptedCodeExecution("x".to_string()),
            "ordinal 22 must still decode as CorruptedCodeExecution, not the appended variant"
        );

        // The current encoder still writes that same discriminant.
        let encoded = encode_to_vec(
            QuorumValidationError::CorruptedCodeExecution("x".to_string()),
            config::standard(),
        )
        .expect("encode");
        assert_eq!(encoded, legacy, "CorruptedCodeExecution must encode at its legacy ordinal 22");

        // The relocated variant sits last now and still round-trips.
        let relocated = QuorumValidationError::CycleBaseHeightTooLow(5);
        let bytes = encode_to_vec(&relocated, config::standard()).expect("encode");
        let (back, _): (QuorumValidationError, usize) =
            decode_from_slice(&bytes, config::standard()).expect("decode");
        assert_eq!(back, relocated);
    }
}
