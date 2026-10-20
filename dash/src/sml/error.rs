#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use thiserror::Error;

use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
use crate::{BlockHash, QuorumHash, TxMerkleNode};

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

    /// Error indicating something that should never happen.
    #[error("Corrupted code execution: {0}")]
    CorruptedCodeExecution(String),

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
        "Coinbase merkle proof for block {block_hash} leads to {computed}, not to the merkle root of the block header"
    )]
    CoinbaseMerkleRootMismatch {
        block_hash: BlockHash,
        computed: TxMerkleNode,
    },

    /// The diff's partial merkle tree does not prove exactly its coinbase transaction as the
    /// first transaction of the block.
    #[error("The merkle proof in the diff for block {0} does not prove its coinbase transaction")]
    CoinbaseNotProven(BlockHash),

    /// The coinbase carries no coinbase payload while the list holds masternodes or quorums, or
    /// carries a payload of another type.
    #[error("The coinbase transaction in the diff for block {0} carries no coinbase payload")]
    MissingCoinbasePayload(BlockHash),

    /// The coinbase payload is version 0 or too short for its version.
    #[error("The coinbase payload in the diff for block {0} is invalid")]
    InvalidCoinbasePayload(BlockHash),

    /// The coinbase payload is for another height than the list built from the diff.
    #[error(
        "The coinbase of block {block_hash} is for height {found}, but its list is at {expected}"
    )]
    CoinbaseHeightMismatch {
        block_hash: BlockHash,
        expected: u32,
        found: u32,
    },

    /// The masternode list built from the diff does not match `merkleRootMNList` of the coinbase.
    #[error(
        "Masternode list merkle root at block {block_hash} is {computed}, not the one the coinbase commits to"
    )]
    MasternodeListMerkleRootMismatch {
        block_hash: BlockHash,
        computed: MerkleRootMasternodeList,
    },

    /// The quorums built from the diff do not match `merkleRootQuorums` of the coinbase.
    #[error(
        "Quorum merkle root at block {block_hash} is {computed}, not the one the coinbase commits to"
    )]
    QuorumMerkleRootMismatch {
        block_hash: BlockHash,
        computed: MerkleRootQuorums,
    },

    /// A QRInfo serves, as the last commitment of a quorum index, a commitment its tip list does
    /// not hold.
    #[error("The QRInfo serves a commitment of quorum {0} that its tip list does not hold")]
    CommitmentNotInTipList(QuorumHash),

    /// A diff of a QRInfo that has to end at a cycle's work block ends at another block.
    #[error("The QRInfo diff to block {block_hash} is not at the work block height {expected}")]
    QRInfoDiffAtWrongHeight {
        block_hash: BlockHash,
        expected: u32,
    },
}
