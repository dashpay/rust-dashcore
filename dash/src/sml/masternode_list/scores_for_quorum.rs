use std::collections::BTreeMap;

use crate::Network;
use crate::hash_types::{QuorumModifierHash, ScoreHash};
use crate::network::message_qrinfo::QuorumSnapshot;
use crate::sml::llmq_type::LLMQType;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list_entry::MasternodeType;
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::sml::quorum_entry::quorum_modifier_type::LLMQModifierType;

impl MasternodeList {
    pub fn valid_masternodes_for_quorum<'a, T>(
        &'a self,
        quorum: &QualifiedQuorumEntry,
        quorum_modifier: LLMQModifierType,
        network: Network,
    ) -> T
    where
        T: FromIterator<&'a QualifiedMasternodeListEntry>,
    {
        let llmq_type = quorum.quorum_entry.llmq_type;
        let hpmn_only = llmq_type == network.platform_type();
        let quorum_modifier = quorum_modifier.build_llmq_hash();
        let score_dictionary = self.scores_for_quorum(quorum_modifier, hpmn_only);
        score_dictionary.into_values().rev().take(llmq_type.size() as usize).collect()
    }

    pub fn used_and_unused_masternodes_for_quorum(
        &self,
        quorum_llmq_type: LLMQType,
        quorum_modifier: LLMQModifierType,
        quorum_snapshot: &QuorumSnapshot,
        network: Network,
    ) -> (Vec<&QualifiedMasternodeListEntry>, Vec<&QualifiedMasternodeListEntry>) {
        let hpmn_only = quorum_llmq_type == network.platform_type();
        let quorum_modifier = quorum_modifier.build_llmq_hash();
        let score_dictionary = self.scores_for_quorum(quorum_modifier, hpmn_only);
        let masternode_entry_list: Vec<&QualifiedMasternodeListEntry> =
            score_dictionary.into_values().rev().collect();
        let mut i = 0;
        masternode_entry_list.into_iter().partition(|_| {
            let used = quorum_snapshot.active_quorum_members.get(i).copied().unwrap_or_default();
            i += 1;
            used
        })
    }

    pub fn scores_for_quorum_for_masternodes<'a, T>(
        entries: T,
        quorum_modifier: QuorumModifierHash,
        hpmn_only: bool,
    ) -> BTreeMap<ScoreHash, &'a QualifiedMasternodeListEntry>
    where
        T: IntoIterator<Item = &'a QualifiedMasternodeListEntry>,
    {
        entries
            .into_iter()
            .filter_map(|entry| {
                if !hpmn_only
                    || matches!(
                        entry.masternode_list_entry.mn_type,
                        MasternodeType::HighPerformance { .. }
                    )
                {
                    entry.score(quorum_modifier).map(|score| (score, entry))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn scores_for_quorum(
        &self,
        quorum_modifier: QuorumModifierHash,
        hpmn_only: bool,
    ) -> BTreeMap<ScoreHash, &QualifiedMasternodeListEntry> {
        Self::scores_for_quorum_for_masternodes(
            self.masternodes.values(),
            quorum_modifier,
            hpmn_only,
        )
    }
}
