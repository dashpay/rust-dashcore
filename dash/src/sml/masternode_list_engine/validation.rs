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
                return_statuses.insert(quorum.quorum_entry.quorum_hash, e.into());
            } else if !quorum.quorum_entry.llmq_type.is_rotating_quorum_type() {
                return_statuses.insert(
                    quorum.quorum_entry.quorum_hash,
                    QuorumValidationError::ExpectedOnlyRotatedQuorums(
                        quorum.quorum_entry.quorum_hash,
                        quorum.quorum_entry.llmq_type,
                    )
                    .into(),
                );
            }
        }

        let masternodes_by_quorum_hash = match self.find_rotated_masternodes_for_quorums(quorums) {
            Ok(masternodes_by_quorum_hash) => masternodes_by_quorum_hash,
            Err(e) => {
                let status: LLMQEntryVerificationStatus = e.into();
                for quorum in quorums {
                    if matches!(
                        return_statuses.get(&quorum.quorum_entry.quorum_hash),
                        Some(LLMQEntryVerificationStatus::Invalid(_))
                    ) {
                        continue;
                    }
                    return_statuses.insert(quorum.quorum_entry.quorum_hash, status.clone());
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
                    return_statuses.insert(quorum.quorum_entry.quorum_hash, e.into());
                }
            }
        }
        return_statuses
    }
}

#[cfg(all(test, feature = "quorum_validation"))]
mod tests {
    use hashes::Hash;

    use super::*;
    use crate::bls_sig_utils::{BLSPublicKey, BLSSignature};
    use crate::hash_types::QuorumVVecHash;
    use crate::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
    use crate::sml::llmq_type::LLMQType;
    use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
    use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;

    fn rotating_quorum(
        quorum_hash: QuorumHash,
        quorum_index: i16,
        valid_structure: bool,
    ) -> QualifiedQuorumEntry {
        let (signers, valid_members, public_key, threshold_sig, agg_sig) = if valid_structure {
            (
                vec![true; 4],
                vec![true; 4],
                BLSPublicKey::from([1; 48]),
                BLSSignature::from([1; 96]),
                BLSSignature::from([1; 96]),
            )
        } else {
            (
                vec![false; 4],
                vec![false; 4],
                BLSPublicKey::from([0; 48]),
                BLSSignature::from([0; 96]),
                BLSSignature::from([0; 96]),
            )
        };
        QuorumEntry {
            version: 2,
            llmq_type: LLMQType::LlmqtypeTestDIP0024,
            quorum_hash,
            quorum_index: Some(quorum_index),
            signers,
            valid_members,
            quorum_public_key: public_key,
            quorum_vvec_hash: QuorumVVecHash::all_zeros(),
            threshold_sig,
            all_commitment_aggregated_signature: agg_sig,
        }
        .into()
    }

    #[test]
    fn rotation_cycle_statuses_classify_infra_error_as_skipped_and_preserve_invalid() {
        let engine = MasternodeListEngine::default();

        let broken_hash = QuorumHash::from_byte_array([1; 32]);
        let unknown_hash = QuorumHash::from_byte_array([2; 32]);
        let broken = rotating_quorum(broken_hash, 0, false);
        let unknown_block = rotating_quorum(unknown_hash, 1, true);

        let statuses =
            engine.validate_rotation_cycle_quorums_validation_statuses(&[&broken, &unknown_block]);

        assert!(
            matches!(statuses.get(&broken_hash), Some(LLMQEntryVerificationStatus::Invalid(_))),
            "structurally-broken quorum must keep an Invalid status, got {:?}",
            statuses.get(&broken_hash),
        );
        assert!(
            matches!(statuses.get(&unknown_hash), Some(LLMQEntryVerificationStatus::Skipped(_))),
            "infrastructure-error quorum must surface as Skipped, got {:?}",
            statuses.get(&unknown_hash),
        );
    }

    #[test]
    fn rotation_cycle_statuses_classify_all_quorums_as_skipped_when_no_pre_existing_invalid() {
        let engine = MasternodeListEngine::default();

        let hash_a = QuorumHash::from_byte_array([3; 32]);
        let hash_b = QuorumHash::from_byte_array([4; 32]);
        let quorum_a = rotating_quorum(hash_a, 0, true);
        let quorum_b = rotating_quorum(hash_b, 1, true);

        let statuses =
            engine.validate_rotation_cycle_quorums_validation_statuses(&[&quorum_a, &quorum_b]);

        for hash in [hash_a, hash_b] {
            assert!(
                matches!(statuses.get(&hash), Some(LLMQEntryVerificationStatus::Skipped(_))),
                "every quorum must be Skipped when find_rotated_masternodes_for_quorums errors and no entry was pre-marked Invalid, got {:?} for {:?}",
                statuses.get(&hash),
                hash,
            );
        }
    }
}
