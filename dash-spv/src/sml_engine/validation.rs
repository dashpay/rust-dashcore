use std::collections::BTreeMap;

use crate::sml_engine::MasternodeListEngine;
use crate::storage::BlockHeaderStorage;
use dashcore::bls_sig_utils::BlsScheme;
use dashcore::network::message_qrinfo::QuorumSnapshot;
use dashcore::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use dashcore::sml::llmq_type::QUORUM_MEMBER_LIST_OFFSET;
use dashcore::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use dashcore::sml::quorum_entry::qualified_quorum_entry::{
    QualifiedQuorumEntry, VerifyingChainLockSignaturesType,
};
use dashcore::sml::quorum_entry::quorum_modifier_type::LLMQModifierType;
use dashcore::sml::quorum_validation_error::QuorumValidationError;
use dashcore::{BlockHash, QuorumHash};

impl<H: BlockHeaderStorage> MasternodeListEngine<H> {
    /// Validates a non-rotating quorum against the members the list at its
    /// work block selects (DIP-6).
    pub(super) async fn validate_quorum(
        &self,
        quorum: &QualifiedQuorumEntry,
    ) -> Result<(), QuorumValidationError> {
        quorum.quorum_entry.validate_structure()?;
        let quorum_hash = quorum.quorum_entry.quorum_hash;
        let height = self.height_of(&quorum_hash).await.ok_or_else(|| {
            QuorumValidationError::RequiredBlockNotPresent(quorum_hash, "quorum height".to_string())
        })?;
        let work_height = height.saturating_sub(QUORUM_MEMBER_LIST_OFFSET);
        let masternode_list = self
            .masternode_lists
            .get(&work_height)
            .ok_or(QuorumValidationError::RequiredMasternodeListNotPresent(work_height))?;
        let Some(VerifyingChainLockSignaturesType::NonRotating(chain_lock_sig)) =
            quorum.verifying_chain_lock_signature
        else {
            return Err(QuorumValidationError::RequiredChainLockNotPresent(
                work_height,
                masternode_list.block_hash,
            ));
        };
        let quorum_modifier_type = LLMQModifierType::new_quorum_modifier_type(
            quorum.quorum_entry.llmq_type,
            masternode_list.block_hash,
            work_height,
            chain_lock_sig,
            self.network,
        )?;
        let members: Vec<_> = masternode_list.valid_masternodes_for_quorum(
            quorum,
            quorum_modifier_type,
            self.network,
        );
        validate_signed_by(quorum, &members)
    }

    /// The status of each rotated quorum, by quorum hash.
    pub(super) async fn rotated_quorum_statuses(
        &self,
        quorums: &[&QualifiedQuorumEntry],
        snapshots: &BTreeMap<BlockHash, QuorumSnapshot>,
    ) -> BTreeMap<QuorumHash, LLMQEntryVerificationStatus> {
        let members = self.find_rotated_masternodes_for_quorums(quorums, snapshots).await;
        quorums
            .iter()
            .zip(members)
            .map(|(quorum, members)| {
                let quorum_hash = quorum.quorum_entry.quorum_hash;
                let result = quorum.quorum_entry.validate_structure().and_then(|()| {
                    if !quorum.quorum_entry.llmq_type.is_rotating_quorum_type() {
                        return Err(QuorumValidationError::ExpectedOnlyRotatedQuorums(
                            quorum_hash,
                            quorum.quorum_entry.llmq_type,
                        ));
                    }
                    validate_signed_by(quorum, &members?)
                });
                let status = match result {
                    Ok(()) => LLMQEntryVerificationStatus::Verified,
                    Err(e) => e.into(),
                };
                (quorum_hash, status)
            })
            .collect()
    }
}

/// Checks `quorum`'s signatures against the `members` that signed it.
fn validate_signed_by(
    quorum: &QualifiedQuorumEntry,
    members: &[&QualifiedMasternodeListEntry],
) -> Result<(), QuorumValidationError> {
    let signers = members.iter().enumerate().filter_map(|(i, member)| {
        quorum.quorum_entry.signers.get(i)?.then_some(&member.masternode_list_entry)
    });
    quorum.validate(signers, BlsScheme::Modern)
}

#[cfg(test)]
mod tests {
    use dashcore::hashes::Hash;

    use super::*;
    use crate::sml_engine::test_support::{quorum_entry, TestEngine};
    use dashcore::bls_sig_utils::{BLSPublicKey, BLSSignature};
    use dashcore::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
    use dashcore::sml::llmq_type::LLMQType;
    use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
    use dashcore::Network;

    fn rotating_quorum(
        quorum_hash: QuorumHash,
        quorum_index: i16,
        valid_structure: bool,
    ) -> QualifiedQuorumEntry {
        let mut entry =
            quorum_entry(LLMQType::LlmqtypeTestDIP0024, quorum_hash, Some(quorum_index));
        if valid_structure {
            entry.signers = vec![true; 4];
            entry.valid_members = vec![true; 4];
            entry.quorum_public_key = BLSPublicKey::from([1; 48]);
            entry.threshold_sig = BLSSignature::from([1; 96]);
            entry.all_commitment_aggregated_signature = BLSSignature::from([1; 96]);
        }
        entry.into()
    }

    #[tokio::test]
    async fn rotation_cycle_statuses_classify_infra_error_as_skipped_and_preserve_invalid() {
        let engine = TestEngine::empty(Network::Testnet);

        let broken_hash = QuorumHash::from_byte_array([1; 32]);
        let unknown_hash = QuorumHash::from_byte_array([2; 32]);
        let second_unknown_hash = QuorumHash::from_byte_array([3; 32]);
        let broken = rotating_quorum(broken_hash, 0, false);
        let unknown_block = rotating_quorum(unknown_hash, 1, true);
        let second_unknown_block = rotating_quorum(second_unknown_hash, 2, true);

        let statuses = engine
            .rotated_quorum_statuses(
                &[&broken, &unknown_block, &second_unknown_block],
                &BTreeMap::new(),
            )
            .await;

        assert!(
            matches!(statuses.get(&broken_hash), Some(LLMQEntryVerificationStatus::Invalid(_))),
            "structurally-broken quorum must keep an Invalid status, got {:?}",
            statuses.get(&broken_hash),
        );
        for hash in [unknown_hash, second_unknown_hash] {
            assert!(
                matches!(statuses.get(&hash), Some(LLMQEntryVerificationStatus::Skipped(_))),
                "each unresolvable quorum must surface as Skipped on its own, got {:?} for {:?}",
                statuses.get(&hash),
                hash,
            );
        }
    }
}
