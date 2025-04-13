use std::collections::BTreeMap;

use crate::QuorumHash;
use crate::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
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
            self.find_rotated_masternodes_for_quorum(quorum)
        } else {
            self.find_non_rotated_masternodes_for_quorum(quorum)
        }
    }
    pub fn validate_and_update_quorum_status(&self, quorum: &mut QualifiedQuorumEntry) {
        quorum.update_quorum_status(self.validate_quorum(quorum));
    }

    pub fn validate_quorum(
        &self,
        quorum: &QualifiedQuorumEntry,
    ) -> Result<(), QuorumValidationError> {
        // first let's do basic structure validation
        quorum.quorum_entry.validate_structure()?;
        let masternodes = self.find_valid_masternodes_for_quorum(quorum)?;

        quorum.validate(masternodes.iter().enumerate().filter_map(
            |(i, qualified_masternode_list_entry)| {
                if *quorum.quorum_entry.signers.get(i)? {
                    Some(&qualified_masternode_list_entry.masternode_list_entry)
                } else {
                    None
                }
            },
        ))
    }

    pub fn validate_rotation_cycle_quorums(
        &self,
        quorums: &[&QualifiedQuorumEntry],
    ) -> Result<(), QuorumValidationError> {
        // first let's do basic structure validation
        for quorum in quorums {
            quorum.quorum_entry.validate_structure()?;
            if !quorum.quorum_entry.llmq_type.is_rotating_quorum_type() {
                return Err(QuorumValidationError::ExpectedOnlyRotatedQuorums(
                    quorum.quorum_entry.quorum_hash,
                    quorum.quorum_entry.llmq_type,
                ));
            }
        }

        let masternodes_by_quorum_hash = self.find_rotated_masternodes_for_quorums(quorums)?;

        for quorum in quorums {
            let masternodes = masternodes_by_quorum_hash
                .get(&quorum.quorum_entry.quorum_hash)
                .ok_or(QuorumValidationError::CorruptedCodeExecution(
                    "expected quorum hash not present".to_string(),
                ))?;
            quorum.validate(masternodes.iter().enumerate().filter_map(
                |(i, qualified_masternode_list_entry)| {
                    if *quorum.quorum_entry.signers.get(i)? {
                        Some(&qualified_masternode_list_entry.masternode_list_entry)
                    } else {
                        None
                    }
                },
            ))?;
        }
        Ok(())
    }

    pub fn validate_rotation_cycle_quorums_validation_statuses(
        &self,
        quorums: &[&QualifiedQuorumEntry],
    ) -> BTreeMap<QuorumHash, LLMQEntryVerificationStatus> {
        let mut return_statuses: BTreeMap<QuorumHash, LLMQEntryVerificationStatus> = quorums
            .iter()
            .map(|entry| (entry.quorum_entry.quorum_hash, LLMQEntryVerificationStatus::Unknown))
            .collect();

        // first let's do basic structure validation
        for quorum in quorums {
            if let Err(e) = quorum.quorum_entry.validate_structure() {
                return_statuses.insert(
                    quorum.quorum_entry.quorum_hash,
                    LLMQEntryVerificationStatus::Invalid(e),
                );
            } else if !quorum.quorum_entry.llmq_type.is_rotating_quorum_type() {
                return_statuses.insert(
                    quorum.quorum_entry.quorum_hash,
                    LLMQEntryVerificationStatus::Invalid(
                        QuorumValidationError::ExpectedOnlyRotatedQuorums(
                            quorum.quorum_entry.quorum_hash,
                            quorum.quorum_entry.llmq_type,
                        ),
                    ),
                );
            }
        }

        let masternodes_by_quorum_hash = match self.find_rotated_masternodes_for_quorums(quorums) {
            Ok(masternodes_by_quorum_hash) => masternodes_by_quorum_hash,
            Err(e) => {
                for quorum in quorums {
                    return_statuses.insert(
                        quorum.quorum_entry.quorum_hash,
                        LLMQEntryVerificationStatus::Invalid(e.clone()),
                    );
                }
                return return_statuses;
            }
        };

        for quorum in quorums {
            if matches!(
                return_statuses.get(&quorum.quorum_entry.quorum_hash),
                Some(LLMQEntryVerificationStatus::Invalid(_))
            ) {
                continue;
            }
            let masternodes = match masternodes_by_quorum_hash
                .get(&quorum.quorum_entry.quorum_hash)
                .ok_or(QuorumValidationError::CorruptedCodeExecution(
                    "expected quorum hash not present".to_string(),
                )) {
                Ok(masternodes) => masternodes,
                Err(e) => {
                    return_statuses.insert(
                        quorum.quorum_entry.quorum_hash,
                        LLMQEntryVerificationStatus::Invalid(e.clone()),
                    );
                    continue;
                }
            };
            match quorum.validate(masternodes.iter().enumerate().filter_map(
                |(i, qualified_masternode_list_entry)| {
                    if *quorum.quorum_entry.signers.get(i)? {
                        Some(&qualified_masternode_list_entry.masternode_list_entry)
                    } else {
                        None
                    }
                },
            )) {
                Ok(_) => {
                    return_statuses.insert(
                        quorum.quorum_entry.quorum_hash,
                        LLMQEntryVerificationStatus::Verified,
                    );
                }
                Err(e) => {
                    return_statuses.insert(
                        quorum.quorum_entry.quorum_hash,
                        LLMQEntryVerificationStatus::Invalid(e),
                    );
                }
            }
        }
        return_statuses
    }
}
