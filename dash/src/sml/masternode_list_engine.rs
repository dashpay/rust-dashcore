use std::collections::BTreeMap;
use crate::{BlockHash, Network};
use crate::network::message_sml::MnListDiff;
use crate::prelude::CoreBlockHeight;
use crate::sml::error::SmlError;
use crate::sml::masternode_list::from_diff::TryIntoWithBlockHashLookup;
use crate::sml::masternode_list::MasternodeList;

#[derive(Clone, Eq, PartialEq)]
pub struct MasternodeListEngine {
    pub block_hashes : BTreeMap<CoreBlockHeight, BlockHash>,
    pub block_heights : BTreeMap<BlockHash, CoreBlockHeight>,
    pub masternode_lists : BTreeMap<CoreBlockHeight, MasternodeList>,
}

impl MasternodeListEngine {
    pub fn initialize_with_diff_to_height(masternode_list_diff: MnListDiff, block_height: CoreBlockHeight, network: Network) -> Result<Self, SmlError> {
        let block_hash = masternode_list_diff.block_hash;
        let masternode_list = masternode_list_diff.try_into_with_block_hash_lookup(|block_hash| Some(block_height), network)?;
        Ok(Self {
            block_hashes: [(block_height, block_hash)].into(),
            block_heights: [(block_hash, block_height)].into(),
            masternode_lists: [(block_height, masternode_list)].into(),
        })
    }

    pub fn apply_diff(&mut self, masternode_list_diff: MnListDiff, diff_end_height: CoreBlockHeight, verify_quorums: bool) -> Result<(), SmlError> {
        let Some(base_height) = self.block_heights.get(&masternode_list_diff.base_block_hash) else {
            return Err(SmlError::MissingStartMasternodeList(masternode_list_diff.base_block_hash));
        };
        let Some(base_masternode_list) = self.masternode_lists.get(base_height) else {
            return Err(SmlError::MissingStartMasternodeList(masternode_list_diff.base_block_hash));
        };

        let block_hash = masternode_list_diff.block_hash;

        let masternode_list = base_masternode_list.apply_diff(masternode_list_diff, diff_end_height)?;
        self.masternode_lists.insert(diff_end_height, masternode_list);
        self.block_hashes.insert(diff_end_height, block_hash);
        self.block_heights.insert(block_hash, diff_end_height);
        Ok(())
    }
}