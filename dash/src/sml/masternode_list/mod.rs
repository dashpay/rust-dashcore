mod apply_diff;
mod builder;
mod debug_helpers;
pub mod from_diff;
mod masternode_helpers;
mod merkle_roots;
mod peer_addresses;
mod quorum_helpers;
mod rotated_quorums_info;
mod scores_for_quorum;

use std::collections::BTreeMap;

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
pub use builder::MasternodeListBuilder;

use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
use crate::sml::llmq_type::LLMQType;
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::{BlockHash, ProTxHash, QuorumHash};

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]

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
    pub fn empty(block_hash: BlockHash, block_height: u32) -> Self {
        Self::build(BTreeMap::default(), BTreeMap::new(), block_hash, block_height).build()
    }

    pub fn build(
        masternodes: BTreeMap<ProTxHash, QualifiedMasternodeListEntry>,
        quorums: BTreeMap<LLMQType, BTreeMap<QuorumHash, QualifiedQuorumEntry>>,
        block_hash: BlockHash,
        block_height: u32,
    ) -> MasternodeListBuilder {
        MasternodeListBuilder::new(masternodes, quorums, block_hash, block_height)
    }
}
