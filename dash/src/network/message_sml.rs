use crate::bls_sig_utils::BLSSignature;
use crate::hash_types::MerkleRootMasternodeList;
use crate::internal_macros::impl_consensus_encoding;
use crate::sml::entry::MasternodeListEntry;
use crate::transaction::special_transaction::quorum_commitment::QuorumFinalizationCommitment;
use crate::{BlockHash, ProTxHash, Transaction};
use hashes::sha256::Hash;

/// The getmnlistd message requests a mnlistdiff message that provides either:
/// - A full masternode list (if baseBlockHash is all-zero)
/// - An update to a previously requested masternode list
///
/// https://docs.dash.org/en/stable/docs/core/reference/p2p-network-data-messages.html#getmnlistd
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct GetMnListDiff {
    pub base_block_hash: BlockHash,
    pub block_hash: BlockHash,
}

impl_consensus_encoding!(GetMnListDiff, base_block_hash, block_hash);

/// The mnlistdiff message is a reply to a getmnlistd message which requested
/// either a full masternode list or a diff for a range of blocks.
///
/// https://docs.dash.org/en/stable/docs/core/reference/p2p-network-data-messages.html#mnlistdiff
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MnListDiff {
    pub version: u16,
    pub base_block_hash: BlockHash,
    pub block_hash: BlockHash,
    pub total_transactions: u32,
    pub merkle_hashes: Vec<MerkleRootMasternodeList>,
    pub merkle_flags: Vec<u8>,
    pub coinbase_tx: Transaction,
    pub deleted_masternodes: Vec<ProTxHash>,
    pub new_masternodes: Vec<MasternodeListEntry>,
    pub deleted_quorums: Vec<DeletedQuorum>,
    pub new_quorums: Vec<QuorumFinalizationCommitment>,
    pub quorums_chainlock_signatures: Vec<BLSSignature>,
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
pub struct DeletedQuorum {
    // TODO: Make it enum
    pub llmq_type: u8,
    pub quorum_hash: Hash,
}

impl_consensus_encoding!(DeletedQuorum, llmq_type, quorum_hash);

// TODO: Add encoding tests with test vectors from Dash Core
// TODO: Add documentation

#[cfg(test)]
mod tests {

    use std::fs::File;
    use std::io::{self, Read};
    use assert_matches::assert_matches;
    use crate::consensus::deserialize;
    use crate::network::message::{NetworkMessage, RawNetworkMessage};

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

        assert_matches!(mn_list_diff, RawNetworkMessage { magic, payload: NetworkMessage::MnListDiff(_) } if magic == 1);
    }
}
