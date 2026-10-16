use crate::sml_engine::MasternodeListEngine;
use crate::storage::BlockHeaderStorage;
use dashcore::prelude::CoreBlockHeight;
use dashcore::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use dashcore::sml::llmq_type::network::NetworkLLMQExt;
use dashcore::sml::llmq_type::{LLMQType, QUORUM_MEMBER_LIST_OFFSET};
use dashcore::sml::masternode_list::{MasternodeList, QuorumMap};
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::QuorumHash;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Active windows [`MasternodeListEngine::quorum_entry_for_hash_at_or_before_height`]
/// walks back. Platform selects a signing quorum about 4.5 DKG intervals back,
/// more than one window, and four bound a miss with a wide margin.
const QUORUM_WALK_BACK_ACTIVE_WINDOWS: u32 = 4;

/// Cycles below the tip cycle the oldest diff of an `extraShare` QRInfo
/// reaches (h-4c, DIP-24), so its base must be at least that old.
const QRINFO_BASE_CYCLES_BEHIND: u32 = 4;

/// Blocks a quorum of `llmq_type` stays active for.
fn active_window(llmq_type: LLMQType) -> CoreBlockHeight {
    let params = llmq_type.params();
    params.signing_active_quorum_count.saturating_mul(params.dkg_params.interval)
}

impl<H: BlockHeaderStorage> MasternodeListEngine<H> {
    /// The list the next QRInfo at `tip` diffs from: the newest one at or below
    /// its h-4c cycle. `None` sends it without a base.
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

    /// Once a diff on `base` moved the tip, drops the lists below the retention
    /// window, keeping `base` and the next QRInfo's base, and their cycles.
    pub(super) async fn prune_after_extending(&mut self, base: CoreBlockHeight) {
        let Some(tip) =
            self.latest_masternode_list().map(|list| list.known_height).filter(|tip| *tip > base)
        else {
            return;
        };
        let qr_info_base = self.qr_info_base_list(tip).map_or(tip, |list| list.known_height);
        let floor = tip.saturating_sub(self.retention_window()).min(base).min(qr_info_base);
        let before = self.masternode_lists.len();
        self.masternode_lists.retain(|height, _| *height >= floor);
        if self.masternode_lists.len() == before {
            return;
        }

        let mut below_floor = BTreeSet::new();
        for cycle_hash in self.rotated_quorums_per_cycle.keys() {
            if self.height_of(cycle_hash).await.is_some_and(|height| height < floor) {
                below_floor.insert(*cycle_hash);
            }
        }
        self.rotated_quorums_per_cycle.retain(|hash, _| !below_floor.contains(hash));
    }

    /// Sets the verification status of a quorum in every list holding it.
    /// Lists that shared a quorum map keep sharing the updated one.
    pub(super) fn set_quorum_status(
        &mut self,
        llmq_type: LLMQType,
        quorum_hash: QuorumHash,
        status: &LLMQEntryVerificationStatus,
    ) {
        let mut replaced: Vec<(Arc<QuorumMap>, Arc<QuorumMap>)> = Vec::new();
        for list in self.masternode_lists.values_mut() {
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

    /// The quorum as the newest list at or below `height` still holding it has
    /// it, with that list's height. A retired quorum is gone from later lists,
    /// so the walk goes back, up to `QUORUM_WALK_BACK_ACTIVE_WINDOWS`.
    /// `Invalid` entries are skipped.
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

    use dashcore::hashes::Hash;

    use super::*;
    use crate::sml_engine::test_support::TestEngine;
    use dashcore::bls_sig_utils::{BLSPublicKey, BLSSignature};
    use dashcore::hash_types::QuorumVVecHash;
    use dashcore::sml::quorum_validation_error::QuorumValidationError;
    use dashcore::transaction::special_transaction::quorum_commitment::QuorumEntry;
    use dashcore::{BlockHash, Network};

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

        let mut engine = TestEngine::empty(Network::Mainnet);
        // Pre-retirement list still holds the retired quorum.
        engine.masternode_lists.insert(148, list_with_quorums(148, slice::from_ref(&retired)));
        // Post-retirement list holds only the then-active quorum, not the retired one.
        engine
            .masternode_lists
            .insert(208, list_with_quorums(208, &[quorum_entry(active_hash, 9)]));

        // The nearest list at or below the lookup height no longer holds the retired quorum.
        let nearest = &engine.masternode_lists[&208];
        assert!(nearest
            .quorum_entry_of_type_for_quorum_hash(PLATFORM_TYPE, retired_hash)
            .is_none());

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
        let mut engine = TestEngine::empty(Network::Mainnet);
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
        let mut engine = TestEngine::empty(Network::Mainnet);
        engine.masternode_lists.insert(148, list_with_quorums(148, &[quorum_entry(hash, 7)]));

        assert!(engine
            .quorum_entry_for_hash_at_or_before_height(PLATFORM_TYPE, hash, 100)
            .is_none());
        assert!(engine
            .quorum_entry_for_hash_at_or_before_height(
                PLATFORM_TYPE,
                QuorumHash::from_byte_array([0xEE; 32]),
                208
            )
            .is_none());
    }

    /// An `Invalid` entry is skipped, even when it is the only list holding the hash.
    #[test]
    fn skips_invalid_entries() {
        let hash = QuorumHash::from_byte_array([0xAB; 32]);
        let mut invalid = quorum_entry(hash, 7);
        invalid.verified =
            LLMQEntryVerificationStatus::Invalid(QuorumValidationError::InvalidQuorumPublicKey);

        let mut engine = TestEngine::empty(Network::Mainnet);
        engine.masternode_lists.insert(148, list_with_quorums(148, &[invalid]));

        assert!(engine
            .quorum_entry_for_hash_at_or_before_height(PLATFORM_TYPE, hash, 208)
            .is_none());
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

        let mut engine = TestEngine::empty(Network::Mainnet);
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
    use super::tests::{quorum_entry, PLATFORM_TYPE};
    use crate::sml_engine::test_support::TestEngine;
    use dashcore::hashes::Hash;
    use dashcore::network::message_sml::MnListDiff;
    use dashcore::prelude::CoreBlockHeight;
    use dashcore::sml::llmq_entry_verification::{
        LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus,
    };
    use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
    use dashcore::sml::quorum_validation_error::QuorumValidationError;
    use dashcore::{BlockHash, QuorumHash};
    use std::sync::Arc;

    const TIP: CoreBlockHeight = 1_000_000;

    fn insert_quorum(
        engine: &mut TestEngine,
        height: CoreBlockHeight,
        quorum: QualifiedQuorumEntry,
    ) {
        Arc::make_mut(&mut engine.masternode_lists.get_mut(&height).unwrap().quorums)
            .entry(PLATFORM_TYPE)
            .or_default()
            .insert(quorum.quorum_entry.quorum_hash, Arc::new(quorum));
    }

    /// Once `Verified`, a non-rotating quorum is not validated again. This one
    /// would fail if it were: it has too few signers for its type and there is
    /// no list at its work block.
    #[tokio::test]
    async fn a_verified_quorum_is_not_validated_again() {
        let quorum_height = TIP - 100;
        let quorum_hash =
            QuorumHash::from_byte_array(BlockHash::dummy(quorum_height).to_byte_array());
        let mut engine = TestEngine::dummy_with_lists(&[TIP]);
        engine.feed_block_height(quorum_height, BlockHash::dummy(quorum_height));
        insert_quorum(&mut engine, TIP, quorum_entry(quorum_hash, 1));
        assert!(!engine.masternode_lists.contains_key(&(quorum_height - 8)));

        engine.verify_newest_quorums().await;

        assert_eq!(
            engine.masternode_lists[&TIP].quorums[&PLATFORM_TYPE][&quorum_hash].verified,
            LLMQEntryVerificationStatus::Verified
        );
    }

    #[tokio::test]
    async fn applying_a_diff_verifies_the_newest_lists_quorums() {
        let quorum_hash = QuorumHash::from_byte_array([0x42; 32]);
        let mut engine = TestEngine::dummy_with_lists(&[TIP - 1]);
        engine.feed_block_height(TIP, BlockHash::dummy(TIP));
        let mut quorum = quorum_entry(quorum_hash, 1);
        quorum.verified = LLMQEntryVerificationStatus::Skipped(
            LLMQEntryVerificationSkipStatus::NotMarkedForVerification,
        );
        insert_quorum(&mut engine, TIP - 1, quorum);

        engine.apply_diff(MnListDiff::dummy_between(TIP - 1, TIP)).await.unwrap();

        assert_eq!(
            engine.masternode_lists[&TIP].quorums[&PLATFORM_TYPE][&quorum_hash].verified,
            LLMQEntryVerificationStatus::Invalid(QuorumValidationError::InsufficientSigners {
                required: 8,
                found: 4,
            })
        );
    }

    #[tokio::test]
    async fn a_status_change_keeps_the_lists_that_shared_a_quorum_map_sharing() {
        let quorum_hash = QuorumHash::from_byte_array([0x42; 32]);
        let mut engine = TestEngine::dummy_with_lists(&[TIP - 2]);
        let mut quorum = quorum_entry(quorum_hash, 1);
        quorum.verified = LLMQEntryVerificationStatus::Unknown;
        insert_quorum(&mut engine, TIP - 2, quorum);
        for height in [TIP - 1, TIP] {
            engine.feed_block_height(height, BlockHash::dummy(height));
            engine.apply_and_prune(MnListDiff::dummy_between(height - 1, height)).await.unwrap();
        }

        engine.set_quorum_status(
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
    use super::*;
    use crate::sml_engine::test_support::TestEngine;
    use dashcore::network::message_sml::MnListDiff;
    use dashcore::{BlockHash, Network};

    const TIP: CoreBlockHeight = 1_000_000;
    /// Within the window at `TIP` and below the next QRInfo's h-4c reach.
    const QR_INFO_BASE: CoreBlockHeight = 998_000;

    fn heights(engine: &TestEngine) -> Vec<CoreBlockHeight> {
        engine.masternode_lists.keys().copied().collect()
    }

    async fn extend(engine: &mut TestEngine, from: CoreBlockHeight, to: CoreBlockHeight) {
        engine.feed_block_height(to, BlockHash::dummy(to));
        engine.apply_diff(MnListDiff::dummy_between(from, to)).await.unwrap();
    }

    /// 400_85's active window plus 8, beyond Platform's walk-back (2304) and
    /// the QRInfo reach (1440).
    #[test]
    fn the_mainnet_window_reaches_the_oldest_active_quorums_work_block() {
        let engine = TestEngine::empty(Network::Mainnet);
        assert_eq!(engine.retention_window(), 4 * 576 + 8);
    }

    #[tokio::test]
    async fn a_diff_that_moves_the_tip_drops_the_lists_below_the_window() {
        let floor = TIP + 1 - TestEngine::dummy_with_lists(&[]).retention_window();
        let mut engine = TestEngine::dummy_with_lists(&[1_000, floor - 1, floor, TIP]);

        extend(&mut engine, TIP, TIP + 1).await;

        assert_eq!(heights(&engine), vec![floor, TIP, TIP + 1]);
    }

    /// As a legacy QRInfo or a batch of work-block lists does.
    #[tokio::test]
    async fn diffs_sharing_an_older_base_all_apply() {
        let base = TIP - 10_000;
        let mut engine = TestEngine::dummy_with_lists(&[base, QR_INFO_BASE]);

        for to in [TIP - 100, TIP] {
            extend(&mut engine, base, to).await;
        }
        assert_eq!(heights(&engine), vec![base, QR_INFO_BASE, TIP - 100, TIP]);

        extend(&mut engine, TIP, TIP + 1).await;
        assert_eq!(heights(&engine), vec![QR_INFO_BASE, TIP - 100, TIP, TIP + 1]);
    }

    /// After a catch-up diff spanning more than the window, the old list is the
    /// only one at or below the next QRInfo's h-4c reach.
    #[tokio::test]
    async fn the_next_qr_info_base_survives_a_sparse_history() {
        let base = TIP - 10_000;
        let mut engine = TestEngine::dummy_with_lists(&[base, TIP]);

        extend(&mut engine, TIP, TIP + 1).await;

        assert_eq!(engine.qr_info_base_list(TIP + 1).map(|list| list.known_height), Some(base));
    }

    #[tokio::test]
    async fn pruning_drops_the_cycles_of_pruned_lists() {
        let old = 900_000;
        let kept = TIP - 100;
        let mut engine = TestEngine::dummy_with_lists(&[old, QR_INFO_BASE, kept, TIP]);
        for height in [old, kept] {
            engine.rotated_quorums_per_cycle.insert(BlockHash::dummy(height), Default::default());
        }

        engine.prune_after_extending(kept).await;

        assert_eq!(heights(&engine), vec![QR_INFO_BASE, kept, TIP]);
        assert_eq!(
            engine.rotated_quorums_per_cycle.keys().collect::<Vec<_>>(),
            vec![&BlockHash::dummy(kept)]
        );
    }

    /// The two ChainLocks of `chain_lock_verification`, after pruning its fixture.
    #[tokio::test]
    async fn prune_keeps_what_chain_locks_near_the_tip_verify_against() {
        use dashcore::ChainLock;

        let mut engine = TestEngine::mainnet_fixture();
        let before = engine.masternode_lists.len();
        let tip = engine.latest_masternode_list().unwrap().known_height;
        engine.prune_after_extending(tip - 1).await;
        assert!(engine.masternode_lists.len() < before);

        for chain_lock in ChainLock::mainnet_fixture_pair() {
            engine.verify_chain_lock(&chain_lock).unwrap();
        }
    }
}
