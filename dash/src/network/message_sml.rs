use hashes::sha256::Hash;
use crate::{BlockHash, ProTxHash, Transaction};
use crate::bls_sig_utils::BLSSignature;
use crate::internal_macros::impl_consensus_encoding;
use crate::transaction::special_transaction::quorum_commitment::{QuorumFinalizationCommitment};

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
pub struct MnListDiff {
    pub version: u16,
    pub base_block_hash: BlockHash,
    pub block_hash: BlockHash,
    pub total_transactions: u32,
    pub merkle_hashes: Vec<Hash>,
    pub merkle_flags: Vec<u8>,
    pub coinbase_tx: Transaction,
    pub deleted_masternodes: Vec<ProTxHash>,
    pub new_masternodes: Vec<MasternodeListEntry>,
    pub deleted_quorums: Vec<DeletedQuorum>,
    pub new_quorums: Vec<QuorumFinalizationCommitment>,
    pub quorums_chainlock_signatures: Vec<BLSSignature>,
}

impl_consensus_encoding!(MnListDiff, version, base_block_hash, block_hash, total_transactions, merkle_hashes, merkle_flags, coinbase_tx, deleted_masternodes, new_masternodes, deleted_quorums, new_quorums, quorums_chainlock_signatures);

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct DeletedQuorum {
    // TODO: Make it enum
    pub llmq_type: u8,
    pub quorum_hash: Hash,
}

impl_consensus_encoding!(DeletedQuorum, llmq_type, quorum_hash);

// TODO: Add encoding tests with test vectors from Dash Core
// TODO: Add documentation
