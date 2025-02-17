use std::collections::BTreeSet;
use crate::{Network, QuorumHash};
use crate::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use crate::sml::llmq_type::LLMQType;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;

impl MasternodeList {

    pub fn quorum_hashes(&self, exclude_quorum_types: &[LLMQType]) -> BTreeSet<QuorumHash> {
        if exclude_quorum_types.is_empty() {
            self.quorums
                .values()
                .flat_map(|quorum_map| quorum_map.keys().cloned())
                .collect()
        } else {
            self.quorums
                .iter()
                .filter(|(llmq_type, _)| !exclude_quorum_types.contains(llmq_type))
                .flat_map(|(_, quorums)| quorums.keys().cloned())
                .collect()
        }
    }

    pub fn non_rotating_quorum_hashes(&self, exclude_quorum_types: &[LLMQType]) -> BTreeSet<QuorumHash> {
        self.quorums
            .iter()
            .filter(|(llmq_type, _)| !llmq_type.is_rotating_quorum_type() && !exclude_quorum_types.contains(llmq_type))
            .flat_map(|(_, quorums)| quorums.keys().cloned())
            .collect()
    }

    pub fn rotating_quorum_hashes(&self, exclude_quorum_types: &[LLMQType]) -> BTreeSet<QuorumHash> {
        self.quorums
            .iter()
            .filter(|(llmq_type, _)| llmq_type.is_rotating_quorum_type() && !exclude_quorum_types.contains(llmq_type))
            .flat_map(|(_, quorums)| quorums.keys().cloned())
            .collect()
    }

    pub fn quorum_entry_of_type_for_quorum_hash(
        &self,
        llmq_type: LLMQType,
        quorum_hash: QuorumHash,
    ) -> Option<&QualifiedQuorumEntry> {
        self.quorums
            .get(&llmq_type)?.get(&quorum_hash)
    }

    pub fn quorum_entry_of_type_for_quorum_hash_mut(
        &mut self,
        llmq_type: LLMQType,
        quorum_hash: QuorumHash,
    ) -> Option<&mut QualifiedQuorumEntry> {
        self.quorums
            .get_mut(&llmq_type)?.get_mut(&quorum_hash)
    }

    pub fn quorums_count(&self) -> u64 {
        let mut count: u64 = 0;
        for entry in self.quorums.values() {
            count += entry.len() as u64;
        }
        count
    }

    pub fn platform_llmq_with_quorum_hash(&self, hash: QuorumHash, llmq_type: LLMQType) -> Option<QualifiedQuorumEntry> {
        self.quorum_entry_of_type_for_quorum_hash(llmq_type, hash)
            .cloned()
    }

    pub fn has_unverified_rotated_quorums(&self, network: Network) -> bool {
        let isd_llmq_type = network.isd_llmq_type();
        self.quorums.get(&isd_llmq_type)
            .map(|q| q.values().any(|llmq| llmq.verified != LLMQEntryVerificationStatus::Verified))
            .unwrap_or(false)
    }
    pub fn has_unverified_regular_quorums(&self, network: Network) -> bool {
        let isd_llmq_type = network.isd_llmq_type();
        self.quorums.get(&isd_llmq_type)
            .map(|q| q.values().any(|llmq| llmq.verified != LLMQEntryVerificationStatus::Verified))
            .unwrap_or(false)
    }
}