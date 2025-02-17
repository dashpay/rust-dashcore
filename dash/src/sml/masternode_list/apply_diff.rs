use crate::network::message_sml::MnListDiff;
use crate::prelude::CoreBlockHeight;
use crate::sml::error::SmlError;
use crate::sml::llmq_entry_verification::{LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus};
use crate::sml::masternode_list::MasternodeList;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;

impl MasternodeList {
    pub fn apply_diff(
        &self,
        diff: MnListDiff,
        diff_end_height: CoreBlockHeight,
    ) -> Result<MasternodeList, SmlError> {
        // Ensure the base block hash matches
        if self.block_hash != diff.base_block_hash {
            return Err(SmlError::BaseBlockHashMismatch {
                expected: self.block_hash,
                found: diff.base_block_hash,
            });
        }

        // Create a new masternodes map by cloning the existing one
        let mut updated_masternodes = self.masternodes.clone();

        // Remove deleted masternodes
        for pro_tx_hash in diff.deleted_masternodes {
            updated_masternodes.remove(&pro_tx_hash.reverse());
        }

        // Add or update new masternodes
        for new_mn in diff.new_masternodes {
            updated_masternodes.insert(new_mn.pro_reg_tx_hash.reverse(), new_mn.into());
        }

        // Create a new quorums map by cloning the existing one
        let mut updated_quorums = self.quorums.clone();

        // Remove deleted quorums
        for deleted_quorum in diff.deleted_quorums {
            if let Some(quorum_map) = updated_quorums.get_mut(&deleted_quorum.llmq_type) {
                quorum_map.remove(&deleted_quorum.quorum_hash);
                if quorum_map.is_empty() {
                    updated_quorums.remove(&deleted_quorum.llmq_type);
                }
            }
        }

        // Add or update new quorums
        for new_quorum in diff.new_quorums {
            updated_quorums
                .entry(new_quorum.llmq_type)
                .or_default()
                .insert(new_quorum.quorum_hash, {
                    let commitment_hash = new_quorum.calculate_commitment_hash();
                    let entry_hash = new_quorum.calculate_entry_hash();
                    QualifiedQuorumEntry {
                        quorum_entry: new_quorum,
                        verified: LLMQEntryVerificationStatus::Skipped(LLMQEntryVerificationSkipStatus::NotMarkedForVerification), // Default to unverified
                        commitment_hash,
                        entry_hash,
                    }
                });
        }

        // Create and return the new MasternodeList
        Ok(MasternodeList::new(
            updated_masternodes,
            updated_quorums,
            diff.block_hash,
            diff_end_height,
            true, // Assume quorums are active
        ))
    }
}