#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};

use crate::bls_sig_utils::BLSSignature;
use crate::hash_types::MerkleRootMasternodeList;
use crate::internal_macros::impl_consensus_encoding;
use crate::sml::llmq_type::LLMQType;
use crate::sml::masternode_list_entry::MasternodeListEntry;
use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;
use crate::{BlockHash, ChainLock, InstantLock, ProTxHash, QuorumHash, Transaction};

/// The `getmnlistd` message requests a `mnlistdiff` message that provides either:
/// - A full masternode list (if `base_block_hash` is all-zero)
/// - An update to a previously requested masternode list
///
/// https://docs.dash.org/en/stable/docs/core/reference/p2p-network-data-messages.html#getmnlistd
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct GetMnListDiff {
    /// Hash of a block the requester already has a valid masternode list of.
    /// Note: Can be all-zero to indicate that a full masternode list is requested.
    pub base_block_hash: BlockHash,
    /// Hash of the block for which the masternode list diff is requested
    pub block_hash: BlockHash,
}

impl_consensus_encoding!(GetMnListDiff, base_block_hash, block_hash);

/// The `mnlistdiff` message is a reply to a `getmnlistd` message which requested
/// either a full masternode list or a diff for a range of blocks.
///
/// https://docs.dash.org/en/stable/docs/core/reference/p2p-network-data-messages.html#mnlistdiff
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct MnListDiff {
    /// Version of the message (currently 1).
    /// In protocol versions 70225 through 70228 this field was located between the `coinbase_tx` and `deleted_masternodes` fields.
    pub version: u16,
    /// Hash of a block the requester already has a valid masternode list of. Can be all-zero to indicate that a full masternode list is requested.
    pub base_block_hash: BlockHash,
    /// Hash of the block for which the masternode list diff is requested
    pub block_hash: BlockHash,
    /// Number of total transactions in `block_hash`
    pub total_transactions: u32,
    /// Merkle hashes in depth-first order
    pub merkle_hashes: Vec<MerkleRootMasternodeList>,
    /// Merkle flag bits, packed per 8 in a byte, least significant bit first
    pub merkle_flags: Vec<u8>,
    /// The fully serialized coinbase transaction of blockHash
    pub coinbase_tx: Transaction,
    /// A list of `ProRegTx` hashes for masternode which were deleted after `base_block_hash`
    pub deleted_masternodes: Vec<ProTxHash>,
    /// The list of Simplified Masternode List (SML) entries which were added or updated since `base_block_hash`
    pub new_masternodes: Vec<MasternodeListEntry>,
    /// A list of LLMQ type and quorum hashes for LLMQs which were deleted after `base_block_hash`
    pub deleted_quorums: Vec<DeletedQuorum>,
    /// The list of LLMQ commitments for the LLMQs which were added since `base_block_hash`
    pub new_quorums: Vec<QuorumEntry>,
    /// ChainLock signature used to calculate members per quorum indexes (in `new_quorums`)
    pub quorums_chainlock_signatures: Vec<QuorumCLSigObject>,
}

impl_consensus_encoding!(
    MnListDiff,
    version,
    base_block_hash,
    block_hash,
    total_transactions,
    merkle_hashes,
    merkle_flags,
    coinbase_tx,
    deleted_masternodes,
    new_masternodes,
    deleted_quorums,
    new_quorums,
    quorums_chainlock_signatures
);

#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct QuorumCLSigObject {
    pub signature: BLSSignature,
    pub index_set: Vec<u16>,
}

impl_consensus_encoding!(QuorumCLSigObject, signature, index_set);

#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct DeletedQuorum {
    pub llmq_type: LLMQType,
    pub quorum_hash: QuorumHash,
}

impl_consensus_encoding!(DeletedQuorum, llmq_type, quorum_hash);

#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct CLSig {
    pub chain_lock: ChainLock,
}

impl_consensus_encoding!(CLSig, chain_lock);

#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct ISLock {
    pub instant_lock: InstantLock,
}

impl_consensus_encoding!(ISLock, instant_lock);

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{self, Read};

    use assert_matches::assert_matches;

    use crate::consensus::{deserialize, serialize};
    use crate::network::message::{NetworkMessage, RawNetworkMessage};
    use crate::network::message_sml::MnListDiff;

    fn read_binary_file(filename: &str) -> io::Result<Vec<u8>> {
        let mut file = File::open(filename)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    #[test]
    fn deserialize_mn_list_diff() {
        let block_hex = include_str!("../../tests/data/test_DML_diffs/DML_0_2221605.hex");
        let data = hex::decode(block_hex).expect("decode hex");
        let mn_list_diff: RawNetworkMessage = deserialize(&data).expect("deserialize MnListDiff");

        assert_matches!(mn_list_diff, RawNetworkMessage { magic, payload: NetworkMessage::MnListDiff(_) } if magic == 3177909439);
    }

    #[test]
    fn deserialize_serialize_mn_list_diff() {
        let block_hex = include_str!("../../tests/data/test_DML_diffs/DML_0_2221605.hex");
        let data = hex::decode(block_hex).expect("decode hex");
        let mn_list_diff: RawNetworkMessage = deserialize(&data).expect("deserialize MnListDiff");
        if let NetworkMessage::MnListDiff(diff) = mn_list_diff.payload {
            let serialized = serialize(&diff);
            let deserialized: MnListDiff =
                deserialize(serialized.as_slice()).expect("expected to deserialize");
        }
    }
}
