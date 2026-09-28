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
use std::sync::Arc;

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
    pub masternodes: Arc<MasternodeMap>,
    pub quorums: Arc<QuorumMap>,
}

/// Masternodes keyed by their reversed pro_tx_hash. Lists share the map until a
/// diff changes it, and a changed map still shares every entry it kept.
pub type MasternodeMap = BTreeMap<ProTxHash, Arc<QualifiedMasternodeListEntry>>;

/// Quorums by type and hash, shared between lists like [`MasternodeMap`] until a
/// diff or a verification status change touches them.
pub type QuorumMap = BTreeMap<LLMQType, BTreeMap<QuorumHash, Arc<QualifiedQuorumEntry>>>;

impl MasternodeList {
    pub fn empty(block_hash: BlockHash, block_height: u32) -> Self {
        Self::build(BTreeMap::default(), BTreeMap::new(), block_hash, block_height).build()
    }

    pub fn build(
        masternodes: impl Into<Arc<MasternodeMap>>,
        quorums: impl Into<Arc<QuorumMap>>,
        block_hash: BlockHash,
        block_height: u32,
    ) -> MasternodeListBuilder {
        MasternodeListBuilder::new(masternodes.into(), quorums.into(), block_hash, block_height)
    }
}
