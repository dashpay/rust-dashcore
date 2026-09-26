use crate::prelude::CoreBlockHeight;
use crate::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use crate::sml::llmq_type::network::NetworkLLMQExt;
use crate::sml::llmq_type::{LLMQType, QUORUM_MEMBER_LIST_OFFSET};
use crate::sml::masternode_list::{MasternodeList, QuorumMap};
use crate::sml::masternode_list_engine::{
    MasternodeListEngine, MasternodeListEngineBlockContainer,
};
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::{BlockHash, QuorumHash};
use std::collections::BTreeSet;
use std::sync::Arc;

/// How many active windows below the lookup height [`MasternodeListEngine::quorum_entry_for_hash_at_or_before_height`]
/// searches before giving up. A signing quorum referenced by a proof was selected at a lagged
/// height that can exceed one active window (Platform selects roughly 4.5 DKG intervals back), so a
/// single window is too tight. Four windows covers that lag with wide margin while still bounding a
/// miss to a fixed span of lists rather than every list the engine has accumulated.
const QUORUM_WALK_BACK_ACTIVE_WINDOWS: u32 = 4;

/// Cycles below the tip cycle the oldest diff of a QRInfo requested with
/// `extraShare` reaches (h-4c, DIP-24). Its base must sit at or below that for
/// every diff to be served against it rather than against genesis.
const QRINFO_BASE_CYCLES_BEHIND: u32 = 4;

/// Blocks a quorum of `llmq_type` stays active for.
fn active_window(llmq_type: LLMQType) -> CoreBlockHeight {
    let params = llmq_type.params();
    params.signing_active_quorum_count.saturating_mul(params.dkg_params.interval)
}

impl MasternodeListEngine {
    /// The list the next QRInfo at `tip` diffs from: the newest one at or below
    /// the h-4c cycle its oldest diff reaches (DIP-24). `None` when no list is
    /// that old, and the request then carries no base.
    pub fn qr_info_base_list(&self, tip: CoreBlockHeight) -> Option<&MasternodeList> {
        let interval = self.network.isd_llmq_type().params().dkg_params.interval;
        if interval == 0 {
            return None;
        }
        let reach = (tip - tip % interval).checked_sub(QRINFO_BASE_CYCLES_BEHIND * interval)?;
        self.masternode_lists.range(..=reach).next_back().map(|(_, list)| list)
    }

    /// How far below the newest list the engine still reads a list: the QRInfo
    /// base and quarters, the work block of every active quorum, and Platform's
    /// walk-back.
    fn retention_window(&self) -> CoreBlockHeight {
        let rotation_interval = self.network.isd_llmq_type().params().dkg_params.interval;
        let qr_info = (QRINFO_BASE_CYCLES_BEHIND + 1).saturating_mul(rotation_interval);
        let platform = active_window(self.network.platform_type())
            .saturating_mul(QUORUM_WALK_BACK_ACTIVE_WINDOWS);
        let member_lists = self
            .network
            .enabled_llmq_types()
            .into_iter()
            .filter(|llmq_type| !llmq_type.is_rotating_quorum_type())
            .map(|llmq_type| active_window(llmq_type).saturating_add(QUORUM_MEMBER_LIST_OFFSET))
            .max()
            .unwrap_or_default();
        qr_info.max(platform).max(member_lists)
    }

    /// Drops the lists out of the retention window of the newest one, except the
    /// next QRInfo's base, and the state only they referenced. A diff requested
    /// from a dropped list no longer applies, so call this with none in flight.
    pub fn prune_old_lists(&mut self) {
        let Some(tip) = self.latest_masternode_list().map(|list| list.known_height) else {
            return;
        };
        let qr_info_base = self.qr_info_base_list(tip).map_or(tip, |list| list.known_height);
        let floor = tip.saturating_sub(self.retention_window()).min(qr_info_base);
        let before = self.masternode_lists.len();
        self.masternode_lists.retain(|height, _| *height >= floor);
        if self.masternode_lists.len() == before {
            return;
        }

        let below_floor = |container: &MasternodeListEngineBlockContainer, hash: &BlockHash| {
            container.get_height(hash).is_some_and(|height| height < floor)
        };
        let container = &self.block_container;
        self.known_snapshots.retain(|hash, _| !below_floor(container, hash));
        self.rotated_quorums_per_cycle.retain(|hash, _| !below_floor(container, hash));

        let lists = &self.masternode_lists;
        for statuses in self.quorum_statuses.values_mut() {
            statuses.retain(|_, (heights, _, _)| {
                heights.retain(|height| lists.contains_key(height));
                !heights.is_empty()
            });
        }
        self.quorum_statuses.retain(|_, statuses| !statuses.is_empty());

        let mut referenced: BTreeSet<BlockHash> = self.known_snapshots.keys().copied().collect();
        let mut previous: Option<&Arc<QuorumMap>> = None;
        for list in self.masternode_lists.values() {
            referenced.insert(list.block_hash);
            if previous.is_some_and(|quorums| Arc::ptr_eq(quorums, &list.quorums)) {
                continue;
            }
            referenced.extend(list.quorums.values().flat_map(|quorums| quorums.keys().copied()));
            previous = Some(&list.quorums);
        }
        for (cycle_hash, quorums) in &self.rotated_quorums_per_cycle {
            referenced.insert(*cycle_hash);
            referenced.extend(quorums.values().map(|quorum| quorum.quorum_entry.quorum_hash));
        }
        let MasternodeListEngineBlockContainer::BTreeMapContainer(container) =
            &mut self.block_container;
        container.block_hashes.retain(|height, hash| *height >= floor || referenced.contains(hash));
        let block_hashes = &container.block_hashes;
        container.block_heights.retain(|_, height| block_hashes.contains_key(height));
    }

    /// Sets the verification status of a quorum in the lists at `heights`.
    /// Lists that shared a quorum map keep sharing the updated one.
    #[cfg(feature = "quorum_validation")]
    pub(crate) fn set_quorum_status_in_lists(
        &mut self,
        heights: impl IntoIterator<Item = CoreBlockHeight>,
        llmq_type: LLMQType,
        quorum_hash: QuorumHash,
        status: &LLMQEntryVerificationStatus,
    ) {
        let mut replaced: Vec<(Arc<QuorumMap>, Arc<QuorumMap>)> = Vec::new();
        for height in heights {
            let Some(list) = self.masternode_lists.get_mut(&height) else {
                continue;
            };
            let current =
                list.quorums.get(&llmq_type).and_then(|quorums| quorums.get(&quorum_hash));
            if current.is_none_or(|quorum| &quorum.verified == status) {
                continue;
            }
            if let Some((_, updated)) =
                replaced.iter().find(|(old, _)| Arc::ptr_eq(old, &list.quorums))
            {
                list.quorums = Arc::clone(updated);
                continue;
            }
            let old = Arc::clone(&list.quorums);
            if let Some(quorum) = Arc::make_mut(&mut list.quorums)
                .get_mut(&llmq_type)
                .and_then(|quorums| quorums.get_mut(&quorum_hash))
                .map(Arc::make_mut)
            {
                quorum.verified = status.clone();
            }
            replaced.push((old, Arc::clone(&list.quorums)));
        }
    }

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
        let floor = height.saturating_sub(
            active_window(llmq_type).saturating_mul(QUORUM_WALK_BACK_ACTIVE_WINDOWS),
        );

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

    pub(super) const PLATFORM_TYPE: LLMQType = LLMQType::LlmqtypeDevnetPlatform;

    pub(super) fn quorum_entry(quorum_hash: QuorumHash, pubkey: u8) -> QualifiedQuorumEntry {
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
        let by_hash = std::sync::Arc::make_mut(&mut list.quorums).entry(PLATFORM_TYPE).or_default();
        for quorum in quorums {
            by_hash.insert(quorum.quorum_entry.quorum_hash, std::sync::Arc::new(quorum.clone()));
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

#[cfg(test)]
mod shared_map_tests {
    use super::tests::{PLATFORM_TYPE, quorum_entry};
    use crate::network::message_sml::MnListDiff;
    use crate::prelude::CoreBlockHeight;
    use crate::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
    use crate::sml::masternode_list_engine::MasternodeListEngine;
    use crate::{BlockHash, QuorumHash};
    use hashes::Hash;
    use std::sync::Arc;

    const TIP: CoreBlockHeight = 1_000_000;

    #[test]
    fn a_diff_that_changes_nothing_shares_the_lists_maps() {
        let mut engine = MasternodeListEngine::dummy_with_lists(&[TIP - 1]);
        engine.apply_diff(MnListDiff::dummy_between(TIP - 1, TIP), Some(TIP), false, None).unwrap();

        let base = &engine.masternode_lists[&(TIP - 1)];
        let next = &engine.masternode_lists[&TIP];
        assert!(Arc::ptr_eq(&base.masternodes, &next.masternodes));
        assert!(Arc::ptr_eq(&base.quorums, &next.quorums));
    }

    /// Once `Verified`, a non-rotating quorum is not validated again. This one
    /// would fail if it were: it has too few signers for its type and there is
    /// no list at its work block.
    #[test]
    #[cfg(feature = "quorum_validation")]
    fn a_verified_quorum_is_not_validated_again() {
        let quorum_height = TIP - 100;
        let quorum_hash =
            QuorumHash::from_byte_array(BlockHash::dummy(quorum_height).to_byte_array());
        let mut engine = MasternodeListEngine::dummy_with_lists(&[TIP]);
        engine.feed_block_height(quorum_height, BlockHash::dummy(quorum_height));
        Arc::make_mut(&mut engine.masternode_lists.get_mut(&TIP).unwrap().quorums)
            .entry(PLATFORM_TYPE)
            .or_default()
            .insert(quorum_hash, Arc::new(quorum_entry(quorum_hash, 1)));
        assert!(!engine.masternode_lists.contains_key(&(quorum_height - 8)));

        engine.verify_non_rotating_masternode_list_quorums(TIP, &[]).unwrap();

        assert_eq!(
            engine.masternode_lists[&TIP].quorums[&PLATFORM_TYPE][&quorum_hash].verified,
            LLMQEntryVerificationStatus::Verified
        );
    }

    #[test]
    #[cfg(feature = "quorum_validation")]
    fn a_status_change_keeps_the_lists_that_shared_a_quorum_map_sharing() {
        let quorum_hash = QuorumHash::from_byte_array([0x42; 32]);
        let mut engine = MasternodeListEngine::dummy_with_lists(&[TIP - 2]);
        let mut quorum = quorum_entry(quorum_hash, 1);
        quorum.verified = LLMQEntryVerificationStatus::Unknown;
        Arc::make_mut(&mut engine.masternode_lists.get_mut(&(TIP - 2)).unwrap().quorums)
            .entry(PLATFORM_TYPE)
            .or_default()
            .insert(quorum_hash, Arc::new(quorum));
        engine
            .apply_diff(MnListDiff::dummy_between(TIP - 2, TIP - 1), Some(TIP - 1), false, None)
            .unwrap();
        engine.apply_diff(MnListDiff::dummy_between(TIP - 1, TIP), Some(TIP), false, None).unwrap();

        engine.set_quorum_status_in_lists(
            [TIP - 2, TIP - 1, TIP],
            PLATFORM_TYPE,
            quorum_hash,
            &LLMQEntryVerificationStatus::Verified,
        );

        let lists: Vec<_> = engine.masternode_lists.values().collect();
        assert!(Arc::ptr_eq(&lists[0].quorums, &lists[1].quorums));
        assert!(Arc::ptr_eq(&lists[1].quorums, &lists[2].quorums));
        assert_eq!(
            lists[2].quorums[&PLATFORM_TYPE][&quorum_hash].verified,
            LLMQEntryVerificationStatus::Verified
        );
    }
}

#[cfg(test)]
mod prune_tests {
    use super::tests::PLATFORM_TYPE;
    use super::*;
    use crate::bls_sig_utils::BLSPublicKey;
    use crate::network::message_qrinfo::QuorumSnapshot;
    use crate::sml::masternode_list_engine::MasternodeListEngine;
    use crate::{BlockHash, Network};
    use hashes::Hash;

    const TIP: CoreBlockHeight = 1_000_000;
    /// Within the window at `TIP` and below the next QRInfo's h-4c reach.
    const QR_INFO_BASE: CoreBlockHeight = 998_000;

    fn heights(engine: &MasternodeListEngine) -> Vec<CoreBlockHeight> {
        engine.masternode_lists.keys().copied().collect()
    }

    /// 400_85's active window plus 8, beyond Platform's walk-back (2304) and
    /// the QRInfo reach (1440).
    #[test]
    fn the_mainnet_window_reaches_the_oldest_active_quorums_work_block() {
        let engine = MasternodeListEngine::default_for_network(Network::Mainnet);
        assert_eq!(engine.retention_window(), 4 * 576 + 8);
    }

    #[test]
    fn pruning_drops_the_lists_below_the_window() {
        let floor =
            TIP - MasternodeListEngine::default_for_network(Network::Mainnet).retention_window();
        let mut engine = MasternodeListEngine::dummy_with_lists(&[1_000, floor - 1, floor, TIP]);

        engine.prune_old_lists();

        assert_eq!(heights(&engine), vec![floor, TIP]);
    }

    #[test]
    fn the_next_qr_info_base_survives_a_sparse_history() {
        let base = TIP - 10_000;
        let mut engine = MasternodeListEngine::dummy_with_lists(&[base, TIP]);

        engine.prune_old_lists();

        assert_eq!(engine.qr_info_base_list(TIP).map(|list| list.known_height), Some(base));
    }

    #[test]
    fn pruning_drops_the_state_only_pruned_lists_referenced() {
        let old = 900_000;
        let kept = TIP - 100;
        let mut engine = MasternodeListEngine::dummy_with_lists(&[old, QR_INFO_BASE, kept, TIP]);
        for height in [old, kept] {
            engine.known_snapshots.insert(BlockHash::dummy(height), QuorumSnapshot::dummy());
            engine.rotated_quorums_per_cycle.insert(BlockHash::dummy(height), Default::default());
        }
        let quorum_hash = QuorumHash::from_byte_array([0x42; 32]);
        engine.quorum_statuses.entry(PLATFORM_TYPE).or_default().insert(
            quorum_hash,
            (BTreeSet::from([old]), BLSPublicKey::from([1; 48]), Default::default()),
        );

        engine.prune_old_lists();
        assert_eq!(heights(&engine), vec![QR_INFO_BASE, kept, TIP]);

        assert_eq!(
            engine.known_snapshots.keys().collect::<Vec<_>>(),
            vec![&BlockHash::dummy(kept)]
        );
        assert_eq!(
            engine.rotated_quorums_per_cycle.keys().collect::<Vec<_>>(),
            vec![&BlockHash::dummy(kept)]
        );
        assert!(engine.quorum_statuses.is_empty(), "no retained list holds the quorum");
        assert!(!engine.block_container.contains_hash(&BlockHash::dummy(old)));
        assert!(engine.block_container.contains_hash(&BlockHash::dummy(kept)));
    }

    /// The two ChainLocks of `chain_lock_verification`, after pruning its fixture.
    #[test]
    #[cfg(feature = "message_verification")]
    fn prune_keeps_what_chain_locks_near_the_tip_verify_against() {
        use crate::ChainLock;

        let mut engine = MasternodeListEngine::mainnet_fixture();
        let before = engine.masternode_lists.len();
        engine.prune_old_lists();
        assert!(engine.masternode_lists.len() < before);

        for chain_lock in ChainLock::mainnet_fixture_pair() {
            engine.verify_chain_lock(&chain_lock).unwrap();
        }
    }
}
