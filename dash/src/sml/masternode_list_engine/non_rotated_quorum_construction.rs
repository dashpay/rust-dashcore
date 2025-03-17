use crate::BlockHash;
use crate::prelude::CoreBlockHeight;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list_engine::MasternodeListEngine;
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::sml::quorum_entry::quorum_modifier_type::LLMQModifierType;
use crate::sml::quorum_validation_error::QuorumValidationError;

impl MasternodeListEngine {
    pub(crate) fn masternode_list_and_height_for_block_hash_8_blocks_ago(
        &self,
        block_hash: &BlockHash,
    ) -> Result<(&MasternodeList, CoreBlockHeight), QuorumValidationError> {
        if let Some(height) = self.block_container.get_height(block_hash) {
            if let Some(masternode_list) = self.masternode_lists.get(&(height.saturating_sub(8))) {
                Ok((masternode_list, height.saturating_sub(8)))
            } else {
                Err(QuorumValidationError::RequiredMasternodeListNotPresent(
                    height.saturating_sub(8),
                ))
            }
        } else {
            Err(QuorumValidationError::RequiredBlockNotPresent(*block_hash))
        }
    }

    pub(in crate::sml::masternode_list_engine) fn find_non_rotated_masternodes_for_quorum(
        &self,
        quorum: &QualifiedQuorumEntry,
    ) -> Result<Vec<&QualifiedMasternodeListEntry>, QuorumValidationError> {
        let (masternode_list, known_block_height) = self
            .masternode_list_and_height_for_block_hash_8_blocks_ago(
                &quorum.quorum_entry.quorum_hash,
            )?;
        let quorum_modifier_type = LLMQModifierType::new_quorum_modifier_type(
            quorum.quorum_entry.llmq_type,
            masternode_list.block_hash,
            known_block_height,
            quorum.verifying_chain_lock_signature.ok_or(QuorumValidationError::RequiredChainLockNotPresent(known_block_height, masternode_list.block_hash))?,
            self.network,
        )?;
        let masternodes: Vec<&QualifiedMasternodeListEntry> = masternode_list
            .valid_masternodes_for_quorum(quorum, quorum_modifier_type, self.network);
        Ok(masternodes)
    }
}
