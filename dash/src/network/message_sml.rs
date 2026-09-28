#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};

use crate::bls_sig_utils::BLSSignature;
use crate::hash_types::MerkleRootMasternodeList;
use crate::internal_macros::impl_consensus_encoding;
use crate::merkle_tree::PartialMerkleTree;
use crate::sml::error::SmlError;
use crate::sml::llmq_type::LLMQType;
use crate::sml::masternode_list_entry::MasternodeListEntry;
use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;
use crate::{BlockHash, ProTxHash, QuorumHash, Transaction, TxMerkleNode};

/// The `getmnlistd` message requests a `mnlistdiff` message that provides either:
/// - A full masternode list (if `base_block_hash` is all-zero)
/// - An update to a previously requested masternode list
///
/// <https://docs.dash.org/en/stable/docs/core/reference/p2p-network-data-messages.html#getmnlistd>
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
/// <https://docs.dash.org/en/stable/docs/core/reference/p2p-network-data-messages.html#mnlistdiff>
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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

impl MnListDiff {
    /// Checks that `coinbase_tx` is the first transaction of the block whose header commits to
    /// `block_merkle_root`, the way Dash Core builds the proof in `BuildSimplifiedMNListDiff`:
    /// the partial merkle tree (`total_transactions`, `merkle_hashes`, `merkle_flags`) must lead
    /// to that root and match exactly one transaction, at position 0, whose txid is the
    /// coinbase's.
    ///
    /// Together with [`MasternodeList::verify_coinbase_merkle_roots`], which runs whenever a diff
    /// is applied, this ties the resulting masternode list to the block header.
    ///
    /// [`MasternodeList::verify_coinbase_merkle_roots`]: crate::sml::masternode_list::MasternodeList::verify_coinbase_merkle_roots
    ///
    /// # Errors
    ///
    /// - `SmlError::InvalidCoinbaseMerkleProof` if the partial merkle tree is malformed.
    /// - `SmlError::CoinbaseMerkleRootMismatch` if it leads to a different merkle root.
    /// - `SmlError::CoinbaseNotProven` if it does not match exactly the coinbase at position 0.
    pub fn verify_coinbase_merkle_proof(
        &self,
        block_merkle_root: TxMerkleNode,
    ) -> Result<(), SmlError> {
        let tree = PartialMerkleTree::from_parts(
            self.total_transactions,
            self.merkle_hashes
                .iter()
                .map(|hash| TxMerkleNode::from_raw_hash(hash.to_raw_hash()))
                .collect(),
            &self.merkle_flags,
        );
        let mut matches = Vec::new();
        let mut indexes = Vec::new();
        let computed = tree.extract_matches(&mut matches, &mut indexes).map_err(|error| {
            SmlError::InvalidCoinbaseMerkleProof {
                block_hash: self.block_hash,
                reason: error.to_string(),
            }
        })?;
        if computed != block_merkle_root {
            return Err(SmlError::CoinbaseMerkleRootMismatch {
                block_hash: self.block_hash,
                expected: block_merkle_root,
                computed,
            });
        }
        if indexes != [0] || matches != [self.coinbase_tx.txid()] {
            return Err(SmlError::CoinbaseNotProven(self.block_hash));
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct QuorumCLSigObject {
    pub signature: BLSSignature,
    pub index_set: Vec<u16>,
}

impl_consensus_encoding!(QuorumCLSigObject, signature, index_set);

#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeletedQuorum {
    pub llmq_type: LLMQType,
    pub quorum_hash: QuorumHash,
}

impl_consensus_encoding!(DeletedQuorum, llmq_type, quorum_hash);

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use hashes::Hash;

    use crate::block::Header;
    use crate::consensus::{deserialize, serialize};
    use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
    use crate::merkle_tree::PartialMerkleTree;
    use crate::network::message::{NetworkMessage, RawNetworkMessage};
    use crate::network::message_sml::MnListDiff;
    use crate::sml::error::SmlError;
    use crate::transaction::special_transaction::TransactionPayload;
    use crate::transaction::special_transaction::coinbase::CoinbasePayload;
    use crate::{TxMerkleNode, Txid};

    fn mainnet_diff_0_2221605() -> MnListDiff {
        let hex = include_str!("../../tests/data/test_DML_diffs/DML_0_2221605.hex");
        let message: RawNetworkMessage =
            deserialize(&hex::decode(hex).expect("hex")).expect("raw message");
        let NetworkMessage::MnListDiff(diff) = message.payload else {
            panic!("expected an mnlistdiff message");
        };
        diff
    }

    /// The fixture diffs with the headers of their blocks, as public block
    /// explorers serve them. Each header must hash to its diff's
    /// `block_hash`, which vouches for the merkle root it carries.
    fn fixtures_with_headers() -> Vec<(MnListDiff, Header)> {
        [
            (
                mainnet_diff_0_2221605(),
                "000000204ec775c3857587ed8ce3e6cf6eaf64bfb90db816033385f71d0000000000000068c9fe75363f12a93d2650265d79a2f7211a2cf8d05836e2f62c40a500cb379d3e3cad675c6a2619187b5901",
            ),
            (
                MnListDiff::mainnet_fixture_0_2227096(),
                "00000020e78c642c9c5eb8c74fed6b669804cd137c3b0962e42ad9c5020000000000000031f22fe6c6efe79702be25811d2bb599393a896996e9e560d01a1181a78585294f78ba67247728195c403c3b",
            ),
            (
                MnListDiff::mainnet_fixture_2227096_2241332(),
                "000000202996884499815938739e79ab0ddd74f3d29c8c0d14f552ab0d000000000000005880e9ed43f861deacd74ee245eb7e6c6c8e89c0cd67f792c4b35e08c4e471a9fdb6dc677e4621196c87ee9c",
            ),
            (
                MnListDiff::testnet_fixture_0_1296600(),
                "000000200433318ebbd848278dc2f76559d4567e18a3d90de3a87374c55cfca237010000bbcb40f521223cac77feef6223ecb62beeccbf78fd918b7f8c98f29c661d1914d0bf86680176021e0f4f0400",
            ),
        ]
        .into_iter()
        .map(|(diff, header)| {
            let header: Header = deserialize(&hex::decode(header).expect("hex")).expect("header");
            assert_eq!(header.block_hash(), diff.block_hash, "a header of another block");
            (diff, header)
        })
        .collect()
    }

    fn set_proof(diff: &mut MnListDiff, tree: &PartialMerkleTree) {
        diff.total_transactions = tree.num_transactions();
        diff.merkle_hashes = tree
            .hashes()
            .iter()
            .map(|hash| MerkleRootMasternodeList::from_raw_hash(hash.to_raw_hash()))
            .collect();
        let mut flags = vec![0u8; tree.bits().len().div_ceil(8)];
        for (position, bit) in tree.bits().iter().enumerate() {
            if *bit {
                flags[position / 8] |= 1 << (position % 8);
            }
        }
        diff.merkle_flags = flags;
    }

    fn root_of(tree: &PartialMerkleTree) -> TxMerkleNode {
        tree.extract_matches(&mut vec![], &mut vec![]).expect("a well-formed tree")
    }

    #[test]
    fn fixture_coinbases_are_proven_by_their_block_headers() {
        for (diff, header) in fixtures_with_headers() {
            diff.verify_coinbase_merkle_proof(header.merkle_root)
                .unwrap_or_else(|e| panic!("{}: {e}", diff.block_hash));
        }
    }

    #[test]
    fn an_edited_merkle_proof_is_refused() {
        let (diff, header) = fixtures_with_headers().swap_remove(0);
        assert!(diff.total_transactions > 2, "the fixture proves a block of several transactions");

        let mut edited = diff.clone();
        let last = edited.merkle_hashes.len() - 1;
        edited.merkle_hashes[last] = MerkleRootMasternodeList::from_byte_array([7; 32]);
        assert_matches!(
            edited.verify_coinbase_merkle_proof(header.merkle_root),
            Err(SmlError::CoinbaseMerkleRootMismatch { .. })
        );

        for bit in 0..2 {
            let mut edited = diff.clone();
            edited.merkle_flags[0] ^= 1 << bit;
            assert!(
                edited.verify_coinbase_merkle_proof(header.merkle_root).is_err(),
                "flag bit {bit} flipped"
            );
        }

        // A count that changes the height of the tree changes the path to the
        // coinbase. One of the same height leaves the leftmost path, and so
        // the proof, as it is.
        let mut edited = diff.clone();
        edited.total_transactions *= 2;
        assert!(edited.verify_coinbase_merkle_proof(header.merkle_root).is_err());
    }

    #[test]
    fn a_foreign_coinbase_or_header_is_refused() {
        let fixtures = fixtures_with_headers();
        let (diff, header) = &fixtures[0];
        let (other_diff, other_header) = &fixtures[1];

        assert_matches!(
            diff.verify_coinbase_merkle_proof(other_header.merkle_root),
            Err(SmlError::CoinbaseMerkleRootMismatch { .. })
        );

        let mut swapped = diff.clone();
        swapped.coinbase_tx = other_diff.coinbase_tx.clone();
        assert_matches!(
            swapped.verify_coinbase_merkle_proof(header.merkle_root),
            Err(SmlError::CoinbaseNotProven(_))
        );
    }

    /// Core's proof flags the coinbase and nothing else, so a proof of any
    /// other selection does not prove the coinbase.
    #[test]
    fn a_proof_that_does_not_select_only_the_coinbase_is_refused() {
        let diff = mainnet_diff_0_2221605();
        let txids = [
            diff.coinbase_tx.txid(),
            Txid::from_byte_array([1; 32]),
            Txid::from_byte_array([2; 32]),
        ];

        for selection in [[false, true, false], [true, true, false]] {
            let tree = PartialMerkleTree::from_txids(&txids, &selection);
            let mut proven = diff.clone();
            set_proof(&mut proven, &tree);
            assert_matches!(
                proven.verify_coinbase_merkle_proof(root_of(&tree)),
                Err(SmlError::CoinbaseNotProven(_)),
                "selection {selection:?}"
            );
        }
    }

    /// A version 1 coinbase payload carries only the height and
    /// `merkleRootMNList`, and is proven like any other.
    #[test]
    fn a_version_1_coinbase_is_proven_by_its_block() {
        let mut diff = mainnet_diff_0_2221605();
        let Some(TransactionPayload::CoinbasePayloadType(payload)) =
            &mut diff.coinbase_tx.special_transaction_payload
        else {
            panic!("the fixture's coinbase carries a payload");
        };
        *payload = CoinbasePayload {
            version: 1,
            height: payload.height,
            merkle_root_masternode_list: payload.merkle_root_masternode_list,
            merkle_root_quorums: MerkleRootQuorums::all_zeros(),
            best_cl_height: None,
            best_cl_signature: None,
            asset_locked_amount: None,
        };
        let tree = PartialMerkleTree::from_txids(
            &[diff.coinbase_tx.txid(), Txid::from_byte_array([1; 32])],
            &[true, false],
        );
        set_proof(&mut diff, &tree);

        let decoded: MnListDiff = deserialize(&serialize(&diff)).expect("round trip");
        assert_eq!(decoded, diff, "a version 1 payload survives the wire");
        decoded.verify_coinbase_merkle_proof(root_of(&tree)).expect("the proof holds");
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
            assert_eq!(deserialized, diff);
        }
    }
}
