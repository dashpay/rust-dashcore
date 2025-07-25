use std::collections::BTreeSet;

use crate::hash_types::QuorumOrderingHash;
use crate::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use crate::sml::llmq_type::{LLMQType, network::NetworkLLMQExt};
use crate::sml::masternode_list::MasternodeList;
use crate::sml::message_verification_error::MessageVerificationError;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::{Network, QuorumHash, QuorumSigningRequestId};

impl MasternodeList {
    pub fn quorum_for_request(
        &self,
        quorum_type: LLMQType,
        request_id: &QuorumSigningRequestId,
    ) -> Result<&QualifiedQuorumEntry, MessageVerificationError> {
        let quorums_of_type = self
            .quorums
            .get(&quorum_type)
            .ok_or(MessageVerificationError::MasternodeListHasNoQuorums(self.known_height))?;
        quorums_of_type
            .values()
            .min_by_key(|quorum| QuorumOrderingHash::create(&quorum.quorum_entry, request_id))
            .ok_or(MessageVerificationError::MasternodeListHasNoQuorums(self.known_height))
    }
    /// Returns a set of quorum hashes, optionally excluding specified quorum types.
    ///
    /// # Parameters
    /// - `exclude_quorum_types`: A slice of `LLMQType` values representing quorum types to exclude.
    ///
    /// # Returns
    /// - `BTreeSet<QuorumHash>`: A set of quorum hashes, excluding the specified types if provided.
    pub fn quorum_hashes(&self, exclude_quorum_types: &[LLMQType]) -> BTreeSet<QuorumHash> {
        if exclude_quorum_types.is_empty() {
            self.quorums.values().flat_map(|quorum_map| quorum_map.keys().cloned()).collect()
        } else {
            self.quorums
                .iter()
                .filter(|(llmq_type, _)| !exclude_quorum_types.contains(llmq_type))
                .flat_map(|(_, quorums)| quorums.keys().cloned())
                .collect()
        }
    }

    /// Returns a set of non-rotating quorum hashes, optionally excluding specified quorum types.
    ///
    /// # Parameters
    /// - `exclude_quorum_types`: A slice of `LLMQType` values representing quorum types to exclude.
    ///
    /// # Returns
    /// - `BTreeSet<QuorumHash>`: A set of quorum hashes for non-rotating quorums.
    pub fn non_rotating_quorum_hashes(
        &self,
        exclude_quorum_types: &[LLMQType],
    ) -> BTreeSet<QuorumHash> {
        self.quorums
            .iter()
            .filter(|(llmq_type, _)| {
                !llmq_type.is_rotating_quorum_type() && !exclude_quorum_types.contains(llmq_type)
            })
            .flat_map(|(_, quorums)| quorums.keys().cloned())
            .collect()
    }

    /// Returns a set of rotating quorum hashes, optionally excluding specified quorum types.
    ///
    /// # Parameters
    /// - `exclude_quorum_types`: A slice of `LLMQType` values representing quorum types to exclude.
    ///
    /// # Returns
    /// - `BTreeSet<QuorumHash>`: A set of quorum hashes for rotating quorums.
    pub fn rotating_quorum_hashes(
        &self,
        exclude_quorum_types: &[LLMQType],
    ) -> BTreeSet<QuorumHash> {
        self.quorums
            .iter()
            .filter(|(llmq_type, _)| {
                llmq_type.is_rotating_quorum_type() && !exclude_quorum_types.contains(llmq_type)
            })
            .flat_map(|(_, quorums)| quorums.keys().cloned())
            .collect()
    }

    /// Retrieves a reference to a quorum entry of a specific type for a given quorum hash.
    ///
    /// # Parameters
    /// - `llmq_type`: The `LLMQType` specifying the quorum type.
    /// - `quorum_hash`: The `QuorumHash` identifying the quorum.
    ///
    /// # Returns
    /// - `Option<&QualifiedQuorumEntry>`: A reference to the quorum entry if found.
    pub fn quorum_entry_of_type_for_quorum_hash(
        &self,
        llmq_type: LLMQType,
        quorum_hash: QuorumHash,
    ) -> Option<&QualifiedQuorumEntry> {
        // Debug logging to see all stored hashes for this quorum type
        if let Some(quorums_of_type) = self.quorums.get(&llmq_type) {
            tracing::debug!(
                "Looking for quorum hash {} in {} quorums of type {:?}",
                quorum_hash,
                quorums_of_type.len(),
                llmq_type
            );
            
            // Log all stored hashes for comparison
            for (stored_hash, _) in quorums_of_type {
                tracing::debug!(
                    "  Stored quorum hash: {} (matches: {})",
                    stored_hash,
                    stored_hash == &quorum_hash
                );
            }
            
            quorums_of_type.get(&quorum_hash)
        } else {
            tracing::debug!(
                "No quorums found for type {:?} (available types: {:?})",
                llmq_type,
                self.quorums.keys().collect::<Vec<_>>()
            );
            None
        }
    }

    /// Retrieves a mutable reference to a quorum entry of a specific type for a given quorum hash.
    ///
    /// # Parameters
    /// - `llmq_type`: The `LLMQType` specifying the quorum type.
    /// - `quorum_hash`: The `QuorumHash` identifying the quorum.
    ///
    /// # Returns
    /// - `Option<&mut QualifiedQuorumEntry>`: A mutable reference to the quorum entry if found.
    pub fn quorum_entry_of_type_for_quorum_hash_mut(
        &mut self,
        llmq_type: LLMQType,
        quorum_hash: QuorumHash,
    ) -> Option<&mut QualifiedQuorumEntry> {
        self.quorums.get_mut(&llmq_type)?.get_mut(&quorum_hash)
    }

    /// Returns the total number of quorums stored.
    ///
    /// # Returns
    /// - `u64`: The total number of quorums in the masternode list.
    pub fn quorums_count(&self) -> u64 {
        let mut count: u64 = 0;
        for entry in self.quorums.values() {
            count += entry.len() as u64;
        }
        count
    }

    /// Retrieves a cloned quorum entry for a given quorum hash and type.
    ///
    /// # Parameters
    /// - `hash`: The `QuorumHash` of the requested quorum.
    /// - `llmq_type`: The `LLMQType` specifying the quorum type.
    ///
    /// # Returns
    /// - `Option<QualifiedQuorumEntry>`: A cloned quorum entry if found.
    pub fn platform_llmq_with_quorum_hash(
        &self,
        hash: QuorumHash,
        llmq_type: LLMQType,
    ) -> Option<QualifiedQuorumEntry> {
        self.quorum_entry_of_type_for_quorum_hash(llmq_type, hash).cloned()
    }

    /// Checks if there are any unverified rotating quorums.
    ///
    /// # Parameters
    /// - `network`: The `Network` to check for rotating quorums.
    ///
    /// # Returns
    /// - `bool`: `true` if there are unverified rotating quorums, otherwise `false`.
    pub fn has_unverified_rotated_quorums(&self, network: Network) -> bool {
        let isd_llmq_type = network.isd_llmq_type();
        self.quorums
            .get(&isd_llmq_type)
            .map(|q| q.values().any(|llmq| llmq.verified != LLMQEntryVerificationStatus::Verified))
            .unwrap_or(false)
    }

    /// Checks if there are any unverified regular quorums.
    ///
    /// # Parameters
    /// - `network`: The `Network` to check for regular quorums.
    ///
    /// # Returns
    /// - `bool`: `true` if there are unverified regular quorums, otherwise `false`.
    pub fn has_unverified_regular_quorums(&self, network: Network) -> bool {
        let isd_llmq_type = network.isd_llmq_type();
        self.quorums
            .get(&isd_llmq_type)
            .map(|q| q.values().any(|llmq| llmq.verified != LLMQEntryVerificationStatus::Verified))
            .unwrap_or(false)
    }
}
