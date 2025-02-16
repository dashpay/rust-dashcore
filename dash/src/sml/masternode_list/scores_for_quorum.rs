use std::collections::BTreeMap;
use hashes::Hash;
use crate::hash_types::{QuorumModifierHash, ScoreHash};
use crate::Network;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list_entry::MasternodeType;
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use crate::sml::order_option::LLMQOrderOption;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::sml::quorum_entry::quorum_modifier_type::LLMQModifierType;

impl MasternodeList {
    pub fn valid_masternodes_for_quorum<T>(
        &self,
        quorum: &QualifiedQuorumEntry,
        quorum_modifier: LLMQModifierType,
        network: Network,
        order_option: &LLMQOrderOption,
    ) -> T
    where T: FromIterator<QualifiedMasternodeListEntry> {
        let llmq_type = quorum.quorum_entry.llmq_type;
        let hpmn_only = llmq_type == network.platform_type();
        let quorum_modifier = quorum_modifier.build_llmq_hash();
        let score_dictionary = self.scores_for_quorum(quorum_modifier, hpmn_only);
        // if quorum.quorum_entry.quorum_hash.to_string() == "0000000000000010d1f1ab756f1f3223485fdc7bce1cbb0e7437383bf7600b06".to_string() {

        // } else {
        //     println!("trying {}", quorum.quorum_entry.quorum_hash)
        // }
            println!("quorum modifier {}", quorum_modifier.reverse());
        if order_option.reverse_sort_scores {
            let mut score_dictionary: Vec<_> = score_dictionary.into_iter().collect();
            score_dictionary.sort_by(|(s1, _), (s2, _)| {

                if order_option.reverse_sort_order {
                    s2.reverse().cmp(&s1.reverse())
                } else {
                    s1.reverse().cmp(&s2.reverse())
                }
            });
            for (score, list_entry) in score_dictionary.iter().take(5) {
                println!("score_hash {} {} -> {}", if order_option.reverse_sort_order { 1 } else { 2}, score, list_entry.masternode_list_entry.pro_reg_tx_hash);
            }
            score_dictionary.into_iter().take(llmq_type.size() as usize).map(|(a, b)| b).collect()
        } else {
            if order_option.reverse_sort_order {
                for (score, list_entry) in score_dictionary.iter().rev().take(5) {
                    println!("3 score_hash {} -> {}", score, list_entry.masternode_list_entry.pro_reg_tx_hash);
                }
                score_dictionary.into_values().rev().take(llmq_type.size() as usize).collect()
            } else {
                for (score, list_entry) in score_dictionary.iter().take(5) {
                    println!("4 score_hash {} -> {}", score, list_entry.masternode_list_entry.pro_reg_tx_hash);
                }
                score_dictionary.into_values().take(llmq_type.size() as usize).collect()
            }
        }
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