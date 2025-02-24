use std::collections::BTreeMap;
use crate::sml::llmq_type::LLMQType;
use crate::sml::masternode_list::masternode_helpers::reverse_cmp_sup;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;

impl MasternodeList {
    /// Retrieves a list of qualified quorum entries ordered for InstantSend locks.
    ///
    /// This function fetches all quorums for the given `quorum_type`, computes an ordering
    /// hash based on the provided `request_id`, and sorts them in descending order.
    ///
    /// # Parameters
    ///
    /// - `quorum_type`: The type of quorum to retrieve.
    /// - `request_id`: A 32-byte identifier used to order the quorums.
    ///
    /// # Returns
    ///
    /// - A vector of `QualifiedQuorumEntry` instances ordered based on the computed hash.
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

    /// Retrieves the first valid quorum entry for a given InstantSend lock request.
    ///
    /// This function finds the most suitable quorum entry for a given `request_id` and `llmq_type`
    /// by selecting the quorum with the lowest computed ordering hash.
    ///
    /// # Parameters
    ///
    /// - `request_id`: A 32-byte identifier used to determine the quorum ordering.
    /// - `llmq_type`: The type of quorum to retrieve.
    ///
    /// # Returns
    ///
    /// - `Some(QualifiedQuorumEntry)`: The most suitable quorum entry.
    /// - `None`: If no quorum is found.
    pub fn lock_llmq_request_id(
        &self,
        request_id: [u8; 32],
        llmq_type: LLMQType,
    ) -> Option<QualifiedQuorumEntry> {
        self.quorum_entry_for_lock_request_id(request_id, llmq_type)
            .cloned()
    }

    /// Retrieves a reference to the best matching quorum entry for a given InstantSend lock request.
    ///
    /// This function iterates through all available quorums of the given `llmq_type`, calculates
    /// an ordering hash for each quorum based on the `request_id`, and returns a reference to the
    /// quorum with the lowest ordering hash value.
    ///
    /// # Parameters
    ///
    /// - `request_id`: A 32-byte identifier used for quorum selection.
    /// - `llmq_type`: The type of quorum to search for.
    ///
    /// # Returns
    ///
    /// - `Some(&QualifiedQuorumEntry)`: A reference to the best-matching quorum entry.
    /// - `None`: If no quorum matches the criteria.
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