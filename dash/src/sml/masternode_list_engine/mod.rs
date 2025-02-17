#[cfg(feature = "quorum_validation")]
mod validation;

use std::collections::{BTreeMap, BTreeSet};
#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use crate::{BlockHash, Network, QuorumHash};
use crate::bls_sig_utils::BLSSignature;
use crate::network::message_sml::MnListDiff;
use crate::prelude::CoreBlockHeight;
use crate::sml::error::SmlError;
use crate::sml::error::SmlError::CorruptedCodeExecution;
use crate::sml::llmq_type::LLMQType;
use crate::sml::masternode_list::from_diff::TryIntoWithBlockHashLookup;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::quorum_validation_error::QuorumValidationError;

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
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
        let base_block_hash = masternode_list_diff.base_block_hash;
        let masternode_list = masternode_list_diff.try_into_with_block_hash_lookup(|block_hash| Some(block_height), network)?;
        Ok(Self {
            block_hashes: [(0, base_block_hash), (block_height, block_hash)].into(),
            block_heights: [(base_block_hash, 0), (block_hash, block_height)].into(),
            masternode_lists: [(block_height, masternode_list)].into(),
            known_chain_locks: Default::default(),
            network,
        })
    }

    pub fn latest_masternode_list(&self) -> Option<&MasternodeList> {
        self.masternode_lists.last_key_value().map(|(_, list)| list)
    }

    pub fn latest_masternode_list_quorum_hashes(&self, exclude_quorum_types: &[LLMQType]) -> BTreeSet<QuorumHash> {
        self.latest_masternode_list()
            .map(|list| list.quorum_hashes(exclude_quorum_types))
            .unwrap_or_default()
    }

    pub fn latest_masternode_list_non_rotating_quorum_hashes(&self, exclude_quorum_types: &[LLMQType]) -> BTreeSet<QuorumHash> {
        self.latest_masternode_list()
            .map(|list| list.non_rotating_quorum_hashes(exclude_quorum_types))
            .unwrap_or_default()
    }

    pub fn masternode_list_and_height_for_block_hash_8_blocks_ago(
        &self,
        block_hash: &BlockHash,
    ) -> Result<(&MasternodeList, CoreBlockHeight), QuorumValidationError> {
        if let Some(height) = self.block_heights.get(block_hash) {
            if let Some(masternode_list) = self.masternode_lists.get(&(height.saturating_sub(8))) {
                Ok((masternode_list, height.saturating_sub(8)))
            } else {
                Err(QuorumValidationError::RequiredMasternodeListNotPresent(height.saturating_sub(8)))
            }
        } else {
            Err(QuorumValidationError::RequiredBlockNotPresent(*block_hash))
        }
    }

    pub fn masternode_list_for_block_hash(&self, block_hash: &BlockHash) -> Option<&MasternodeList> {
        self.block_heights.get(block_hash).and_then(|height| self.masternode_lists.get(height))
    }

    pub fn feed_block_height(&mut self, height: CoreBlockHeight, block_hash: BlockHash) {
        self.block_heights.insert(block_hash, height);
        self.block_hashes.insert(height, block_hash);
    }

    pub fn feed_chain_lock_sig(&mut self, block_hash: BlockHash, chain_lock_sig: BLSSignature) {
        self.known_chain_locks.insert(block_hash, chain_lock_sig);
    }

    pub fn apply_diff(&mut self, masternode_list_diff: MnListDiff, diff_end_height: CoreBlockHeight, verify_quorums: bool) -> Result<(), SmlError> {
        if let Some(known_genesis_block_hash) = self.network.known_genesis_block_hash().or_else(|| self.block_hashes.get(&0).cloned()) {
            if masternode_list_diff.base_block_hash == known_genesis_block_hash {
                // we are going from the start
                let block_hash = masternode_list_diff.block_hash;

                let masternode_list = masternode_list_diff.try_into_with_block_hash_lookup(|block_hash| Some(diff_end_height), self.network)?;

                self.masternode_lists.insert(diff_end_height, masternode_list);
                self.block_hashes.insert(diff_end_height, block_hash);
                self.block_heights.insert(block_hash, diff_end_height);
                return Ok(());
            }
        }

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

    #[cfg(feature = "quorum_validation")]
    pub fn verify_masternode_list_quorums(&mut self, block_height: CoreBlockHeight, exclude_quorum_types: &[LLMQType]) -> Result<(), QuorumValidationError>  {
        let masternode_list = self.masternode_lists.get(&block_height).ok_or(QuorumValidationError::VerifyingMasternodeListNotPresent(block_height))?;
        let mut results = BTreeMap::new();
        for (quorum_type, hash_to_quorum_entries) in masternode_list.quorums.iter() {
            if exclude_quorum_types.contains(quorum_type) {
                continue;
            }
            let mut inner = BTreeMap::new();

            for (quorum_hash, quorum_entry) in hash_to_quorum_entries.iter() {
                inner.insert(*quorum_hash, self.validate_quorum(quorum_entry));
            }
            results.insert(*quorum_type, inner);
        }
        let masternode_list = self.masternode_lists.get_mut(&block_height).ok_or(QuorumValidationError::VerifyingMasternodeListNotPresent(block_height))?;
        for (quorum_type, hash_to_quorum_entries) in masternode_list.quorums.iter_mut() {
            if exclude_quorum_types.contains(quorum_type) {
                continue;
            }

            for (quorum_hash, quorum_entry) in hash_to_quorum_entries.iter_mut() {
                quorum_entry.update_quorum_status(results.get_mut(quorum_type).unwrap().remove(quorum_hash).unwrap())
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::QuorumHash;
    use crate::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
    use crate::sml::llmq_type::LLMQType::{Llmqtype100_67, Llmqtype400_60, Llmqtype400_85, Llmqtype50_60};
    use crate::sml::masternode_list_engine::MasternodeListEngine;
    use std::str::FromStr;

    #[test]
    fn deserialize_mn_list_engine_and_validate_quorums() {
        let block_hex = include_str!("../../../tests/data/test_DML_diffs/masternode_list_engine3.hex");
        let data = hex::decode(block_hex).expect("decode hex");
        let mut mn_list_engine: MasternodeListEngine = bincode::decode_from_slice(&data, bincode::config::standard()).expect("expected to decode").0;

        assert_eq!(mn_list_engine.masternode_lists.len(), 27);

        let last_masternode_list_height = *mn_list_engine.masternode_lists.last_key_value().unwrap().0;

        mn_list_engine.verify_masternode_list_quorums(last_masternode_list_height, &[Llmqtype50_60, Llmqtype400_85]).expect("expected to verify quorums");

        let last_masternode_list = mn_list_engine.masternode_lists.last_key_value().unwrap().1;

        for (quorum_type, quorum_entries) in last_masternode_list.quorums.iter() {
            if *quorum_type == Llmqtype400_85 || *quorum_type == Llmqtype50_60 || *quorum_type == Llmqtype400_60 {
                continue;
            }
            for (quorum_hash, quorum) in quorum_entries.iter() {
                let (_, known_block_height) = mn_list_engine.masternode_list_and_height_for_block_hash_8_blocks_ago(&quorum.quorum_entry.quorum_hash).expect("expected to find validating masternode");
                assert_eq!(quorum.verified, LLMQEntryVerificationStatus::Verified, "could not verify quorum {} of type {} with masternode list {}", quorum_hash, quorum.quorum_entry.llmq_type, known_block_height);
            }
        }
    }

    #[test]
    fn deserialize_mn_list_engine_and_validate_single_quorum() {
        let block_hex = include_str!("../../../tests/data/test_DML_diffs/masternode_list_engine3.hex");
        let data = hex::decode(block_hex).expect("decode hex");
        let mn_list_engine: MasternodeListEngine = bincode::decode_from_slice(&data, bincode::config::standard()).expect("expected to decode").0;

        assert_eq!(mn_list_engine.masternode_lists.len(), 27);

        let last_masternode_list_height = *mn_list_engine.masternode_lists.last_key_value().unwrap().0;

        let last_masternode_list = mn_list_engine.masternode_lists.last_key_value().unwrap().1;

        let quorum = last_masternode_list.quorum_entry_of_type_for_quorum_hash(Llmqtype100_67, QuorumHash::from_str("000000000000001d4ebc43dbf9b25d2af6421641a84a1e04dd58f65d07b7ecf7").expect("expected to get quorum hash")).expect("expected to find quorum");

        println!("using {:?}", mn_list_engine.validate_quorum(quorum))
    }
}