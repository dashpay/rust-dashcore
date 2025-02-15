#[cfg(feature = "quorum_validation")]
mod validation;

use std::collections::{BTreeMap, BTreeSet};
use crate::{BlockHash, Network, QuorumHash};
use crate::bls_sig_utils::BLSSignature;
use crate::network::message_sml::MnListDiff;
use crate::prelude::CoreBlockHeight;
use crate::sml::error::SmlError;
use crate::sml::error::SmlError::CorruptedCodeExecution;
use crate::sml::masternode_list::from_diff::TryIntoWithBlockHashLookup;
use crate::sml::masternode_list::MasternodeList;

#[derive(Clone, Eq, PartialEq)]
pub struct MasternodeListEngine {
    pub block_hashes : BTreeMap<CoreBlockHeight, BlockHash>,
    pub block_heights : BTreeMap<BlockHash, CoreBlockHeight>,
    pub masternode_lists : BTreeMap<CoreBlockHeight, MasternodeList>,
    pub known_chain_locks: BTreeMap<BlockHash, BLSSignature>,
    pub network: Network,
}

impl MasternodeListEngine {
    pub fn initialize_with_diff_to_height(masternode_list_diff: MnListDiff, block_height: CoreBlockHeight, network: Network) -> Result<Self, SmlError> {
        let block_hash = masternode_list_diff.block_hash;
        let masternode_list = masternode_list_diff.try_into_with_block_hash_lookup(|block_hash| Some(block_height), network)?;
        Ok(Self {
            block_hashes: [(block_height, block_hash)].into(),
            block_heights: [(block_hash, block_height)].into(),
            masternode_lists: [(block_height, masternode_list)].into(),
            known_chain_locks: Default::default(),
            network,
        })
    }

    pub fn latest_masternode_list(&self) -> Option<&MasternodeList> {
        self.masternode_lists.last_key_value().map(|(_, list)| list)
    }

    pub fn latest_masternode_list_quorum_hashes(&self) -> BTreeSet<QuorumHash> {
        self.latest_masternode_list()
            .map(|list| list.quorum_hashes())
            .unwrap_or_default()
    }

    pub fn masternode_list_and_height_for_block_hash_8_blocks_ago(
        &self,
        block_hash: &BlockHash,
    ) -> (Option<&MasternodeList>, Option<CoreBlockHeight>) {
        if let Some(height) = self.block_heights.get(block_hash) {
            (self.masternode_lists.get(&(height.saturating_sub(8))), Some(height.saturating_sub(8)))
        } else {
            (None, None)
        }
    }

    pub fn masternode_list_for_block_hash(&self, block_hash: &BlockHash) -> Option<&MasternodeList> {
        self.block_heights.get(block_hash).and_then(|height| self.masternode_lists.get(height))
    }

    pub fn apply_diff(&mut self, masternode_list_diff: MnListDiff, diff_end_height: CoreBlockHeight, verify_quorums: bool) -> Result<(), SmlError> {
        let Some(base_height) = self.block_heights.get(&masternode_list_diff.base_block_hash) else {
            return Err(SmlError::MissingStartMasternodeList(masternode_list_diff.base_block_hash));
        };
        let Some(base_masternode_list) = self.masternode_lists.get(base_height) else {
            return Err(SmlError::MissingStartMasternodeList(masternode_list_diff.base_block_hash));
        };

        let block_hash = masternode_list_diff.block_hash;

        let mut masternode_list = base_masternode_list.apply_diff(masternode_list_diff.clone(), diff_end_height)?;

        #[cfg(feature = "quorum_validation")]
        if verify_quorums {
            // We only need to verify new quorums
            for new_quorum in &masternode_list_diff.new_quorums {
                let quorum = masternode_list.quorum_entry_of_type_for_quorum_hash_mut(new_quorum.llmq_type, new_quorum.quorum_hash).ok_or(CorruptedCodeExecution("masternode list after diff does not contain new quorum".to_string()))?;
                self.validate_and_update_quorum_status(quorum);
            }
        }
        #[cfg(not(feature = "quorum_validation"))]
        if verify_quorums {
            return Err(SmlError::FeatureNotTurnedOn("quorum validation feature is not turned on".to_string()));
        }

        self.masternode_lists.insert(diff_end_height, masternode_list);
        self.block_hashes.insert(diff_end_height, block_hash);
        self.block_heights.insert(block_hash, diff_end_height);

        Ok(())
    }
}