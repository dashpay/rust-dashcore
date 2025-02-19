mod debug_helpers;
mod merkle_roots;
mod rotated_quorums_info;
mod masternode_helpers;
mod quorum_helpers;
mod is_lock_methods;
mod peer_addresses;
pub mod from_diff;
mod apply_diff;
mod scores_for_quorum;
mod rotation;
mod valid_members_in_rotated_quorum;

use std::collections::BTreeMap;
#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
use crate::sml::llmq_type::LLMQType;
use crate::{BlockHash, ProTxHash, QuorumHash};
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct MasternodeList {
    pub block_hash: BlockHash,
    pub known_height: u32,
    pub masternode_merkle_root: Option<MerkleRootMasternodeList>,
    pub llmq_merkle_root: Option<MerkleRootQuorums>,
    // The pro_tx_hash here is reversed
    // todo, see if we should remove this reversal
    pub masternodes: BTreeMap<ProTxHash, QualifiedMasternodeListEntry>,
    pub quorums: BTreeMap<LLMQType, BTreeMap<QuorumHash, QualifiedQuorumEntry>>,
}

impl MasternodeList {
    pub fn empty(block_hash: BlockHash, block_height: u32, quorums_active: bool) -> Self {
        Self::new(BTreeMap::default(), BTreeMap::new(), block_hash, block_height, quorums_active)
    }
    pub fn new(
        masternodes: BTreeMap<ProTxHash, QualifiedMasternodeListEntry>,
        quorums: BTreeMap<LLMQType, BTreeMap<QuorumHash, QualifiedQuorumEntry>>,
        block_hash: BlockHash,
        block_height: u32,
        quorums_active: bool,
    ) -> Self {
        let mut list = Self {
            quorums,
            block_hash,
            known_height: block_height,
            masternode_merkle_root: None,
            llmq_merkle_root: None,
            masternodes,
        };
        list.masternode_merkle_root = list.calculate_masternodes_merkle_root(block_height);
        if quorums_active {
            list.llmq_merkle_root = list.calculate_llmq_merkle_root();
        }
        list
    }
    pub fn with_merkle_roots(
        masternodes: BTreeMap<ProTxHash, QualifiedMasternodeListEntry>,
        quorums: BTreeMap<LLMQType, BTreeMap<QuorumHash, QualifiedQuorumEntry>>,
        block_hash: BlockHash,
        block_height: u32,
        masternode_merkle_root: MerkleRootMasternodeList,
        llmq_merkle_root: Option<MerkleRootQuorums>,
    ) -> Self {
        Self {
            quorums,
            block_hash,
            known_height: block_height,
            masternode_merkle_root: Some(masternode_merkle_root),
            llmq_merkle_root,
            masternodes,
        }
    }
}