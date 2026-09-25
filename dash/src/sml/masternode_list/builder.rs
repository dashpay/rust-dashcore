use std::sync::Arc;

use crate::BlockHash;
use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
use crate::sml::masternode_list::{MasternodeList, MasternodeMap, QuorumMap};

pub struct MasternodeListBuilder {
    pub block_hash: BlockHash,
    pub block_height: u32,
    pub masternode_merkle_root: Option<MerkleRootMasternodeList>,
    pub llmq_merkle_root: Option<MerkleRootQuorums>,
    pub masternodes: Arc<MasternodeMap>,
    pub quorums: Arc<QuorumMap>,
}

impl MasternodeListBuilder {
    pub fn new(
        masternodes: Arc<MasternodeMap>,
        quorums: Arc<QuorumMap>,
        block_hash: BlockHash,
        block_height: u32,
    ) -> Self {
        Self {
            quorums,
            block_hash,
            block_height,
            masternode_merkle_root: None,
            llmq_merkle_root: None,
            masternodes,
        }
    }

    pub fn with_merkle_roots(
        mut self,
        masternode_merkle_root: MerkleRootMasternodeList,
        llmq_merkle_root: Option<MerkleRootQuorums>,
    ) -> Self {
        self.masternode_merkle_root = Some(masternode_merkle_root);
        self.llmq_merkle_root = llmq_merkle_root;
        self
    }

    pub fn build(self) -> MasternodeList {
        let mut list = MasternodeList {
            block_hash: self.block_hash,
            known_height: self.block_height,
            masternode_merkle_root: self.masternode_merkle_root,
            llmq_merkle_root: self.llmq_merkle_root,
            masternodes: self.masternodes,
            quorums: self.quorums,
        };

        if self.masternode_merkle_root.is_none() {
            list.masternode_merkle_root = list.calculate_masternodes_merkle_root(self.block_height);
            list.llmq_merkle_root = list.calculate_llmq_merkle_root();
        }

        list
    }
}
