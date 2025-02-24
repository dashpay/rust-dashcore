use bincode::{Decode, Encode};
use thiserror::Error;

use crate::BlockHash;

#[derive(Debug, Error, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub enum SmlError {
    /// Error indicating that the base block is not the genesis block.
    #[error("Base block is not the genesis block: {0}")]
    BaseBlockNotGenesis(BlockHash),

    /// Error indicating that a block hash lookup failed.
    #[error("Block hash lookup failed for block: {0}")]
    BlockHashLookupFailed(BlockHash),

    /// Error indicating that the `MnListDiff` is incomplete.
    #[error("The MnListDiff is incomplete and cannot be applied")]
    IncompleteMnListDiff,

    /// We are missing the start masternode list.
    #[error("Missing start masternode list for block: {0}")]
    MissingStartMasternodeList(BlockHash),

    /// The base block hash in the diff does not match the expected base block hash.
    #[error("Base block hash mismatch: expected {expected}, but found {found}")]
    BaseBlockHashMismatch { expected: BlockHash, found: BlockHash },

    /// Error indicating an unknown issue.
    #[error("An unknown SML error occurred")]
    UnknownError,

    /// Error indicating something that should never happen.
    #[error("Corrupted code execution: {0}")]
    CorruptedCodeExecution(String),

    /// Error indicating that a required feature is not turned on.
    #[error("Feature not turned on: {0}")]
    FeatureNotTurnedOn(String),
}
