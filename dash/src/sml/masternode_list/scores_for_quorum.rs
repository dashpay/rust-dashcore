use std::collections::BTreeMap;
use crate::hash_types::{QuorumModifierHash, ScoreHash};
use crate::Network;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list_entry::MasternodeType;
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::sml::quorum_entry::quorum_modifier_type::LLMQModifierType;

impl MasternodeList {
    pub fn valid_masternodes_for_quorum<T>(
        &self,
        quorum: &QualifiedQuorumEntry,
        quorum_modifier: LLMQModifierType,
        network: Network,
    ) -> T
    where T: FromIterator<QualifiedMasternodeListEntry> {
        let llmq_type = quorum.quorum_entry.llmq_type;
        let hpmn_only = llmq_type == network.platform_type();
        let quorum_modifier = quorum_modifier.build_llmq_hash();
        let score_dictionary = self.scores_for_quorum(quorum_modifier, hpmn_only);
        score_dictionary.into_values().take(llmq_type.size() as usize).collect()
    }

    pub fn scores_for_quorum(
        &self,
        quorum_modifier: QuorumModifierHash,
        hpmn_only: bool,
    ) -> BTreeMap<ScoreHash, QualifiedMasternodeListEntry> {
        self.masternodes.values().filter_map(|entry| {
            if !hpmn_only || matches!(entry.masternode_list_entry.mn_type, MasternodeType::HighPerformance{..}) {
                entry.score(quorum_modifier)
                    .map(|score| (score, entry.clone()))
            } else {
                None
            }
        }).collect()
    }
}