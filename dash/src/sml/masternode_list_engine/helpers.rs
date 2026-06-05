use crate::QuorumHash;
use crate::prelude::CoreBlockHeight;
use crate::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use crate::sml::llmq_type::LLMQType;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list_engine::MasternodeListEngine;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;

/// How many active windows below the lookup height [`MasternodeListEngine::quorum_entry_for_hash_at_or_before_height`]
/// searches before giving up. A signing quorum referenced by a proof was selected at a lagged
/// height that can exceed one active window (Platform selects roughly 4.5 DKG intervals back), so a
/// single window is too tight. Four windows covers that lag with wide margin while still bounding a
/// miss to a fixed span of lists rather than every list the engine has accumulated.
const QUORUM_WALK_BACK_ACTIVE_WINDOWS: u32 = 4;

impl MasternodeListEngine {
    /// Retrieves the closest masternode lists before and after a given core block height.
    ///
    /// This function searches the `masternode_lists` map to find the nearest masternode lists
    /// surrounding the provided `core_block_height`. It returns:
    /// - The highest masternode list at or below the given height.
    /// - The lowest masternode list above the given height.
    ///
    /// # Arguments
    ///
    /// * `core_block_height` - The core block height for which surrounding masternode lists are needed.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - `Some(MasternodeList)`: The masternode list at or just below the given height.
    /// - `Some(MasternodeList)`: The masternode list just above the given height.
    /// - `None` values if no corresponding lists exist.
    ///
    /// # Behavior
    ///
    /// - If `core_block_height` matches a key exactly, it may be included in the first return value.
    /// - The function does not mutate the underlying data structure.
    /// - Uses efficient `BTreeMap` traversal to find surrounding heights.
    pub fn masternode_lists_around_height(
        &self,
        core_block_height: CoreBlockHeight,
    ) -> (Option<&MasternodeList>, Option<&MasternodeList>) {
        let lower =
            self.masternode_lists.range(..=core_block_height).next_back().map(|(_, list)| list);

        let upper =
            self.masternode_lists.range(core_block_height + 1..).next().map(|(_, list)| list);

        (lower, upper)
    }

    /// Resolves a quorum entry by type and hash, searching masternode lists at or below
    /// `height` from the nearest downward and returning the first one that still holds it.
    ///
    /// The nearest list at or below `height` may no longer contain the quorum: once a quorum
    /// retires out of the active set, `apply_diff` drops it from every list built from that
    /// point on. A signing quorum selected at a lagged height can therefore be absent from the
    /// nearest list yet still present in an earlier, retained one. Walking backward returns that
    /// earlier full entry rather than failing the lookup. Entries marked `Invalid` are skipped.
    ///
    /// The returned `CoreBlockHeight` is the height of the list the entry was resolved from. The
    /// first match is the highest list still holding the quorum, so a hit stops a few cycles back at
    /// most. The walk is floored at `QUORUM_WALK_BACK_ACTIVE_WINDOWS` active windows below `height`
    /// (derived from the type's DKG interval and active quorum count): a legitimately referenced
    /// signing quorum cannot be older than that, so flooring it bounds a miss to a fixed span of
    /// lists rather than scanning every list the engine has accumulated.
    pub fn quorum_entry_for_hash_at_or_before_height(
        &self,
        llmq_type: LLMQType,
        quorum_hash: QuorumHash,
        height: CoreBlockHeight,
    ) -> Option<(CoreBlockHeight, &QualifiedQuorumEntry)> {
        let params = llmq_type.params();
        let active_window =
            params.signing_active_quorum_count.saturating_mul(params.dkg_params.interval);
        let floor =
            height.saturating_sub(active_window.saturating_mul(QUORUM_WALK_BACK_ACTIVE_WINDOWS));

        self.masternode_lists.range(floor..=height).rev().find_map(|(_, list)| {
            list.quorum_entry_of_type_for_quorum_hash(llmq_type, quorum_hash)
                .filter(|quorum| {
                    !matches!(quorum.verified, LLMQEntryVerificationStatus::Invalid(_))
                })
                .map(|quorum| (list.known_height, quorum))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::slice;

    use hashes::Hash;

    use super::*;
    use crate::BlockHash;
    use crate::bls_sig_utils::{BLSPublicKey, BLSSignature};
    use crate::hash_types::QuorumVVecHash;
    use crate::sml::quorum_validation_error::QuorumValidationError;
    use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;

    const PLATFORM_TYPE: LLMQType = LLMQType::LlmqtypeDevnetPlatform;

    fn quorum_entry(quorum_hash: QuorumHash, pubkey: u8) -> QualifiedQuorumEntry {
        let mut entry: QualifiedQuorumEntry = QuorumEntry {
            version: 2,
            llmq_type: PLATFORM_TYPE,
            quorum_hash,
            quorum_index: Some(0),
            signers: vec![true; 4],
            valid_members: vec![true; 4],
            quorum_public_key: BLSPublicKey::from([pubkey; 48]),
            quorum_vvec_hash: QuorumVVecHash::all_zeros(),
            threshold_sig: BLSSignature::from([1; 96]),
            all_commitment_aggregated_signature: BLSSignature::from([1; 96]),
        }
        .into();
        entry.verified = LLMQEntryVerificationStatus::Verified;
        entry
    }

    fn list_with_quorums(height: u32, quorums: &[QualifiedQuorumEntry]) -> MasternodeList {
        let mut list =
            MasternodeList::empty(BlockHash::from_byte_array([height as u8; 32]), height);
        let by_hash = list.quorums.entry(PLATFORM_TYPE).or_default();
        for quorum in quorums {
            by_hash.insert(quorum.quorum_entry.quorum_hash, quorum.clone());
        }
        list
    }

    /// A quorum retired out of the active set is dropped from the nearest list at or below the
    /// lookup height, but the backward walk resolves it from the earlier list that still holds it.
    #[test]
    fn resolves_retired_quorum_from_earlier_list() {
        let retired_hash = QuorumHash::from_byte_array([0xAB; 32]);
        let active_hash = QuorumHash::from_byte_array([0xCD; 32]);
        let retired = quorum_entry(retired_hash, 7);

        let mut engine = MasternodeListEngine::default();
        // Pre-retirement list still holds the retired quorum.
        engine.masternode_lists.insert(148, list_with_quorums(148, slice::from_ref(&retired)));
        // Post-retirement list holds only the then-active quorum, not the retired one.
        engine
            .masternode_lists
            .insert(208, list_with_quorums(208, &[quorum_entry(active_hash, 9)]));

        // The nearest list at or below the lookup height no longer holds the retired quorum.
        let nearest = engine.masternode_lists_around_height(208).0.unwrap();
        assert!(
            nearest.quorum_entry_of_type_for_quorum_hash(PLATFORM_TYPE, retired_hash).is_none()
        );

        // The walk resolves it from the earlier retained list, returning that list's height.
        let (resolved_height, resolved) = engine
            .quorum_entry_for_hash_at_or_before_height(PLATFORM_TYPE, retired_hash, 208)
            .expect("retired quorum resolves from earlier list");
        assert_eq!(resolved_height, 148);
        assert_eq!(resolved.quorum_entry.quorum_public_key, retired.quorum_entry.quorum_public_key);
    }

    /// While still in the active set the quorum resolves from the nearest list directly.
    #[test]
    fn resolves_active_quorum_from_nearest_list() {
        let hash = QuorumHash::from_byte_array([0xAB; 32]);
        let mut engine = MasternodeListEngine::default();
        engine.masternode_lists.insert(148, list_with_quorums(148, &[quorum_entry(hash, 7)]));

        let (resolved_height, _) = engine
            .quorum_entry_for_hash_at_or_before_height(PLATFORM_TYPE, hash, 148)
            .expect("active quorum resolves");
        assert_eq!(resolved_height, 148);
    }

    /// A lookup below every retained list, or for an unknown hash, finds nothing.
    #[test]
    fn returns_none_when_not_present() {
        let hash = QuorumHash::from_byte_array([0xAB; 32]);
        let mut engine = MasternodeListEngine::default();
        engine.masternode_lists.insert(148, list_with_quorums(148, &[quorum_entry(hash, 7)]));

        assert!(
            engine.quorum_entry_for_hash_at_or_before_height(PLATFORM_TYPE, hash, 100).is_none()
        );
        assert!(
            engine
                .quorum_entry_for_hash_at_or_before_height(
                    PLATFORM_TYPE,
                    QuorumHash::from_byte_array([0xEE; 32]),
                    208
                )
                .is_none()
        );
    }

    /// An `Invalid` entry is skipped, even when it is the only list holding the hash.
    #[test]
    fn skips_invalid_entries() {
        let hash = QuorumHash::from_byte_array([0xAB; 32]);
        let mut invalid = quorum_entry(hash, 7);
        invalid.verified =
            LLMQEntryVerificationStatus::Invalid(QuorumValidationError::InvalidQuorumPublicKey);

        let mut engine = MasternodeListEngine::default();
        engine.masternode_lists.insert(148, list_with_quorums(148, &[invalid]));

        assert!(
            engine.quorum_entry_for_hash_at_or_before_height(PLATFORM_TYPE, hash, 208).is_none()
        );
    }

    /// The walk is floored at a few active windows below the lookup height: a quorum that only
    /// survives in a list older than the floor is treated as not found, while one within the window
    /// still resolves. This bounds a miss instead of scanning every accumulated list.
    #[test]
    fn does_not_walk_below_active_window_floor() {
        let params = PLATFORM_TYPE.params();
        let span = params.signing_active_quorum_count
            * params.dkg_params.interval
            * QUORUM_WALK_BACK_ACTIVE_WINDOWS;
        let height = span + 5_000;
        let floor = height - span;

        let within_hash = QuorumHash::from_byte_array([0x11; 32]);
        let below_hash = QuorumHash::from_byte_array([0x22; 32]);

        let mut engine = MasternodeListEngine::default();
        // One list just above the floor and one well below it.
        engine
            .masternode_lists
            .insert(floor + 100, list_with_quorums(floor + 100, &[quorum_entry(within_hash, 7)]));
        engine
            .masternode_lists
            .insert(floor - 100, list_with_quorums(floor - 100, &[quorum_entry(below_hash, 9)]));

        let (resolved_height, _) = engine
            .quorum_entry_for_hash_at_or_before_height(PLATFORM_TYPE, within_hash, height)
            .expect("quorum within the window resolves");
        assert_eq!(resolved_height, floor + 100);

        assert!(
            engine
                .quorum_entry_for_hash_at_or_before_height(PLATFORM_TYPE, below_hash, height)
                .is_none(),
            "quorum below the floor must not be walked to"
        );
    }
}
