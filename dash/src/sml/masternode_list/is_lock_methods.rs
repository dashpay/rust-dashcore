use std::collections::BTreeMap;
use crate::sml::llmq_type::LLMQType;
use crate::sml::masternode_list::masternode_helpers::reverse_cmp_sup;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;

impl MasternodeList {
    pub fn ordered_quorums_for_is_lock(&self, quorum_type: LLMQType, request_id: [u8; 32]) -> Vec<QualifiedQuorumEntry> {
        use std::cmp::Ordering;
        let quorums_for_is = self.quorums
            .get(&quorum_type)
            .map(|inner_map| inner_map.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let ordered_quorum_map = quorums_for_is.into_iter()
            .fold(BTreeMap::new(), |mut acc, entry| {
                let mut ordering_hash = entry
                    .ordering_hash_for_request_id(request_id);
                ordering_hash.reverse();
                acc.insert(entry, ordering_hash);
                acc
            });
        let mut ordered_quorums: Vec<_> = ordered_quorum_map.into_iter().collect();
        ordered_quorums.sort_by(|(_, hash1), (_, hash2)| {
            if reverse_cmp_sup(*hash1, *hash2) {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        });
        ordered_quorums.into_iter().map(|(entry, _)| entry).collect()
    }

    pub fn lock_llmq_request_id(
        &self,
        request_id: [u8; 32],
        llmq_type: LLMQType,
    ) -> Option<QualifiedQuorumEntry> {
        self.quorum_entry_for_lock_request_id(request_id, llmq_type)
            .cloned()
    }

    pub fn quorum_entry_for_lock_request_id(
        &self,
        request_id: [u8; 32],
        llmq_type: LLMQType,
    ) -> Option<&QualifiedQuorumEntry> {
        let mut first_quorum: Option<&QualifiedQuorumEntry> = None;
        let mut lowest_value = [!0; 32];
        self.quorums.get(&llmq_type)?.values().for_each(|entry| {
            let mut ordering_hash = entry
                .ordering_hash_for_request_id(request_id);
            ordering_hash.reverse();
            if lowest_value > ordering_hash {
                lowest_value = ordering_hash;
                first_quorum = Some(entry);
            }
        });
        first_quorum
    }

}