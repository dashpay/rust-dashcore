use std::sync::Arc;

use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
use crate::sml::error::SmlError;
use crate::sml::masternode_list::{MasternodeList, MasternodeMap, QuorumMap};
use crate::{BlockHash, Transaction};

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

    /// Builds the list once it matches the commitments of `coinbase_transaction`, see
    /// [`MasternodeList::verify_coinbase_merkle_roots`]. The roots are computed once, for the
    /// check and for the list, which then holds the ones the coinbase commits to.
    pub(crate) fn build_matching_coinbase(
        self,
        coinbase_transaction: &Transaction,
    ) -> Result<MasternodeList, SmlError> {
        let mut list = MasternodeList {
            block_hash: self.block_hash,
            known_height: self.block_height,
            masternode_merkle_root: None,
            llmq_merkle_root: None,
            masternodes: self.masternodes,
            quorums: self.quorums,
        };
        let (masternode_root, quorum_root) = list.coinbase_merkle_roots();
        list.check_coinbase_merkle_roots(coinbase_transaction, masternode_root, quorum_root)?;
        list.masternode_merkle_root = Some(masternode_root);
        list.llmq_merkle_root = Some(quorum_root);
        Ok(list)
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
