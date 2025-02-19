use crate::sml::masternode_list_engine::MasternodeListEngine;
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::sml::quorum_validation_error::QuorumValidationError;

impl MasternodeListEngine {
    fn find_valid_masternodes_for_quorum<'a>(
        &'a self,
        quorum: &'a QualifiedQuorumEntry,
    ) -> Result<Vec<&'a QualifiedMasternodeListEntry>, QuorumValidationError> {
        if quorum.quorum_entry.llmq_type.is_rotating_quorum_type() {
            self.find_rotated_masternodes_for_quorum(quorum, true)
        } else {
            self.find_non_rotated_masternodes_for_quorum(quorum)
        }
    }
    pub fn validate_and_update_quorum_status(&self, quorum: &mut QualifiedQuorumEntry) {
        quorum.update_quorum_status(self.validate_quorum(quorum));
    }

    pub fn validate_quorum(&self, quorum: &QualifiedQuorumEntry) -> Result<(), QuorumValidationError> {
        // first let's do basic structure validation
        quorum.quorum_entry.validate_structure()?;
        let masternodes = self.find_valid_masternodes_for_quorum(quorum)?;

        quorum.validate(masternodes.iter().enumerate().filter_map(|(i, qualified_masternode_list_entry)| {
            if *quorum.quorum_entry.signers.get(i)? {
                // We probably don't need this check because normally you couldn't sign if you are not a valid member.
                if *quorum.quorum_entry.valid_members.get(i)? {
                    Some(&qualified_masternode_list_entry.masternode_list_entry)
                } else {
                    // println!("{} ({}) isn't a valid member", qualified_masternode_list_entry.masternode_list_entry.pro_reg_tx_hash, qualified_masternode_list_entry.masternode_list_entry.pro_reg_tx_hash.reverse());
                    None
                }
            } else {
                // println!("{} ({}) didn't sign", qualified_masternode_list_entry.masternode_list_entry.pro_reg_tx_hash, qualified_masternode_list_entry.masternode_list_entry.pro_reg_tx_hash.reverse());
                None
            }
        }))
    }
}