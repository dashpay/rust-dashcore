use std::collections::{BTreeMap, HashSet};
use hashes::Hash;
use crate::BlockHash;
use crate::prelude::CoreBlockHeight;
use crate::sml::llmq_entry_verification::{LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus};
use crate::sml::masternode_list_engine::MasternodeListEngine;
use crate::sml::masternode_list_entry::MasternodeListEntry;
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::sml::quorum_entry::quorum_modifier_type::LLMQModifierType;
use crate::sml::quorum_validation_error::QuorumValidationError;
use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;

impl MasternodeListEngine {
    //     pub fn valid_masternodes_for_quorum(
    //         &self,
    //         quorum: &QualifiedQuorumEntry,
    //         block_height: CoreBlockHeight,
    //         quorum_modifier: LLMQModifierType,
    //     ) -> Result<Vec<QualifiedMasternodeListEntry>, QuorumValidationError> {
    //         let masternode_list = self.masternode_lists.get(&block_height).ok_or(QuorumValidationError::RequiredMasternodeListNotPresent(block_height))?;
    //
    //         masternode_list.valid_masternodes_for_quorum(quorum, quorum_modifier, self.network);
    //     }
    //
    // fn get_non_rotated_masternodes_for_quorum(
    //     &self,
    //     llmq_type: LLMQType,
    //     block_hash: [u8; 32],
    //     block_height: u32,
    //     quorum: &LLMQEntry,
    //     masternodes: &BTreeMap<[u8; 32], MasternodeEntry>,
    // ) -> Result<Vec<MasternodeEntry>, CoreProviderError> {
    //     Ok(llmq::valid_masternodes(
    //         quorum,
    //         self.provider.chain_type(),
    //         masternodes,
    //         block_height - 8,
    //         self.llmq_modifier_type_for(llmq_type, block_hash, block_height - 8)))
    // }
    //
    // fn find_valid_masternodes_for_quorum(
    //     &self,
    //     quorum: &QualifiedQuorumEntry,
    //     skip_removed_masternodes: bool,
    //     masternodes: &BTreeMap<[u8; 32], QualifiedMasternodeListEntry>,
    // ) -> Result<Vec<MasternodeListEntry>, QuorumValidationError> {
    //     if quorum.index != u16::MAX {
    //         self.get_rotated_masternodes_for_quorum(quorum.llmq_type.clone(), quorum.llmq_hash, block_height, skip_removed_masternodes)
    //     } else {
    //         self.get_non_rotated_masternodes_for_quorum(quorum.llmq_type.clone(), quorum.llmq_hash, block_height, quorum, masternodes)
    //     }
    // }
    pub fn validate_and_update_quorum_status(&self, quorum: &mut QualifiedQuorumEntry) {
        match self.validate_quorum(quorum) {
            Err(QuorumValidationError::RequiredBlockNotPresent(block_hash)) => {
                quorum.verified = LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::UnknownBlock(block_hash.to_byte_array()));
            }
            Err(QuorumValidationError::RequiredMasternodeListNotPresent(block_height, block_hash)) => {
                quorum.verified = LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::MissedList(block_height, block_hash.to_byte_array()));
            }
            Err(e) => {
                quorum.verified = LLMQEntryVerificationStatus::Invalid(e);
            }
            Ok(_) => {
                quorum.verified = LLMQEntryVerificationStatus::Verified;
            }
        }
    }

    pub fn validate_quorum(&self, quorum: &QualifiedQuorumEntry) -> Result<(), QuorumValidationError> {
        // first let's do basic structure validation
        quorum.quorum_entry.validate_structure()?;

        let llmq_block_hash = quorum.quorum_entry.quorum_hash;
        let (maybe_masternode_list, maybe_known_block_height) = self.masternode_list_and_height_for_block_hash_8_blocks_ago(&llmq_block_hash);
        let Some(known_block_height) = maybe_known_block_height else {
            return Err(QuorumValidationError::RequiredBlockNotPresent(llmq_block_hash));
        };
        let Some(masternode_list) = maybe_masternode_list else {
            return Err(QuorumValidationError::RequiredMasternodeListNotPresent(known_block_height, llmq_block_hash));
        };
        quorum.validate(masternode_list.masternodes.values())
    }
}