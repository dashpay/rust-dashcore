#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use thiserror::Error;

use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
use crate::{BlockHash, TxMerkleNode};

#[derive(Debug, Error, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
    BaseBlockHashMismatch {
        expected: BlockHash,
        found: BlockHash,
    },

    /// Error indicating an unknown issue.
    #[error("An unknown SML error occurred")]
    UnknownError,

    /// Error indicating something that should never happen.
    #[error("Corrupted code execution: {0}")]
    CorruptedCodeExecution(String),

    /// Error indicating that a required feature is not turned on.
    #[error("Feature not turned on: {0}")]
    FeatureNotTurnedOn(String),

    /// Error indicating that an invalid index was provided in the signature set.
    #[error("Invalid index in quorum signature set: {0}")]
    InvalidIndexInSignatureSet(u16),

    /// Error indicating the quorum signature set is incomplete (some slots were not filled).
    #[error("Incomplete quorum signature set; not all slots were filled")]
    IncompleteSignatureSet,

    /// The diff's partial merkle tree is malformed.
    #[error("Invalid coinbase merkle proof in the diff for block {block_hash}: {reason}")]
    InvalidCoinbaseMerkleProof {
        block_hash: BlockHash,
        reason: String,
    },

    /// The diff's partial merkle tree does not lead to the merkle root of the block header.
    #[error(
        "Coinbase merkle proof for block {block_hash} leads to {computed}, but the block header commits to {expected}"
    )]
    CoinbaseMerkleRootMismatch {
        block_hash: BlockHash,
        expected: TxMerkleNode,
        computed: TxMerkleNode,
    },

    /// The diff's partial merkle tree does not prove exactly its coinbase transaction as the
    /// first transaction of the block.
    #[error("The merkle proof in the diff for block {0} does not prove its coinbase transaction")]
    CoinbaseNotProven(BlockHash),

    /// The diff's coinbase transaction carries no coinbase special transaction payload.
    #[error("The coinbase transaction in the diff for block {0} carries no coinbase payload")]
    MissingCoinbasePayload(BlockHash),

    /// The masternode list built from the diff does not match `merkleRootMNList` of the coinbase.
    #[error(
        "Masternode list merkle root at block {block_hash} is {computed}, but the coinbase commits to {expected}"
    )]
    MasternodeListMerkleRootMismatch {
        block_hash: BlockHash,
        expected: MerkleRootMasternodeList,
        computed: MerkleRootMasternodeList,
    },

    /// The quorums built from the diff do not match `merkleRootQuorums` of the coinbase.
    #[error(
        "Quorum merkle root at block {block_hash} is {computed}, but the coinbase commits to {expected}"
    )]
    QuorumMerkleRootMismatch {
        block_hash: BlockHash,
        expected: MerkleRootQuorums,
        computed: MerkleRootQuorums,
    },
}
