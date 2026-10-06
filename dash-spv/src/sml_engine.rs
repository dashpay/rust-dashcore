mod helpers;
mod rotated_quorum_construction;
mod validation;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::storage::BlockHeaderStorage;
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::hashes::Hash;
use dashcore::network::constants::NetworkExt;
use dashcore::network::message_qrinfo::{QRInfo, QuorumSnapshot};
use dashcore::network::message_sml::{MnListDiff, QuorumCLSigObject};
use dashcore::prelude::CoreBlockHeight;
use dashcore::sml::error::SmlError;
use dashcore::sml::llmq_entry_verification::LLMQEntryVerificationSkipStatus;
use dashcore::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use dashcore::sml::llmq_type::devnet_isd_type_override;
use dashcore::sml::llmq_type::network::NetworkLLMQExt;
use dashcore::sml::llmq_type::{LLMQType, QUORUM_MEMBER_LIST_OFFSET};
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::sml::quorum_entry::qualified_quorum_entry::VerifyingChainLockSignaturesType;
use dashcore::sml::quorum_validation_error::QuorumValidationError;
use dashcore::transaction::special_transaction::quorum_commitment::QuorumEntry;
use dashcore::Network;
use dashcore::{BlockHash, QuorumHash};
use tokio::sync::RwLock;

/// Blocks between a rotation cycle's base and its work block (Dash Core's `WORK_DIFF_DEPTH`).
pub const WORK_DIFF_DEPTH: u32 = 8;

/// What a [`MasternodeListEngine::feed_qr_info`] call settled for the active
/// rotation set it served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QRInfoFeedResult {
    /// Rotated quorums in `last_commitment_per_index`.
    pub rotated_quorum_count: usize,
    /// Rotated quorums an active set of this network's rotation type holds.
    pub expected_rotated_quorum_count: usize,
    /// Rotated quorums that settled as `Verified`.
    pub fully_verified_count: usize,
    /// Height of the cycle this call stored, `None` when it stored none.
    pub stored_cycle_height: Option<CoreBlockHeight>,
}

impl QRInfoFeedResult {
    /// `true` when the QRInfo carried the whole active set and every quorum of
    /// it verified. A peer may serve fewer, which leaves the rest unproven.
    pub fn all_fully_verified(&self) -> bool {
        self.expected_rotated_quorum_count > 0
            && self.rotated_quorum_count == self.expected_rotated_quorum_count
            && self.fully_verified_count == self.rotated_quorum_count
    }
}

pub struct MasternodeListEngine<H: BlockHeaderStorage> {
    headers: Arc<RwLock<H>>,
    pub masternode_lists: BTreeMap<CoreBlockHeight, MasternodeList>,
    rotated_quorums_per_cycle: BTreeMap<BlockHash, BTreeMap<u16, QualifiedQuorumEntry>>,
    network: Network,
}

/// A cycle's quorums keyed by quorum index. Rejects a missing, out-of-range or
/// duplicate index. A cycle may lack indices: an IS lock selecting one fails
/// with `QuorumIndexNotFound`.
fn build_cycle_quorum_map(
    quorums: Vec<QualifiedQuorumEntry>,
    rotation_quorum_type: LLMQType,
) -> Result<BTreeMap<u16, QualifiedQuorumEntry>, QuorumValidationError> {
    let expected = rotation_quorum_type.active_quorum_count() as usize;
    let mut map = BTreeMap::new();
    for quorum in quorums {
        let quorum_index = quorum.quorum_entry.quorum_index.ok_or(
            QuorumValidationError::RequiredQuorumIndexNotPresent(quorum.quorum_entry.quorum_hash),
        )?;
        let key = u16::try_from(quorum_index).ok().filter(|key| (*key as usize) < expected).ok_or(
            QuorumValidationError::InvalidQuorumIndex {
                quorum_hash: quorum.quorum_entry.quorum_hash,
                index: quorum_index,
            },
        )?;
        if map.contains_key(&key) {
            return Err(QuorumValidationError::CorruptedCodeExecution(format!(
                "duplicate quorum_index {key} in rotation cycle"
            )));
        }
        map.insert(key, quorum);
    }
    Ok(map)
}

/// Every masternode list diff a QRInfo carries.
pub fn qr_info_diffs(qr_info: &QRInfo) -> Vec<&MnListDiff> {
    let mut diffs: Vec<&MnListDiff> = vec![
        &qr_info.mn_list_diff_tip,
        &qr_info.mn_list_diff_h,
        &qr_info.mn_list_diff_at_h_minus_c,
        &qr_info.mn_list_diff_at_h_minus_2c,
        &qr_info.mn_list_diff_at_h_minus_3c,
    ];
    if let Some((_, diff)) = &qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c {
        diffs.push(diff);
    }
    diffs.extend(&qr_info.mn_list_diff_list);
    diffs
}

/// Cycle base (the height of quorum index 0) of a rotated quorum mined at
/// `quorum_block_height`. The index comes from the wire, so it is accepted only
/// while it names an active slot and lands the base on a DKG interval boundary.
fn rotated_cycle_base_height(
    quorum: &QuorumEntry,
    quorum_block_height: CoreBlockHeight,
) -> Option<CoreBlockHeight> {
    let quorum_index = u32::try_from(quorum.quorum_index?).ok()?;
    if quorum_index >= quorum.llmq_type.active_quorum_count() {
        return None;
    }
    let cycle_base = quorum_block_height.checked_sub(quorum_index)?;
    (cycle_base % quorum.llmq_type.params().dkg_params.interval == 0).then_some(cycle_base)
}

/// The rotated quorums a `quorumsCLSigs` group of `diff` signs for.
fn signed_rotated_quorums<'a>(
    diff: &'a MnListDiff,
    group: &'a QuorumCLSigObject,
) -> impl Iterator<Item = &'a QuorumEntry> {
    group
        .index_set
        .iter()
        .filter_map(|index| diff.new_quorums.get(*index as usize))
        .filter(|quorum| quorum.llmq_type.is_rotating_quorum_type())
}

/// The quarter work block heights of the cycle based at `B` with DKG interval
/// `c`, oldest first: `[B-3c-8, B-2c-8, B-c-8, B-8]`. `None` below genesis.
fn cycle_quarter_work_heights(
    cycle_base: CoreBlockHeight,
    interval: u32,
) -> [Option<CoreBlockHeight>; 4] {
    [3, 2, 1, 0]
        .map(|cycles_back: u32| cycle_base.checked_sub(cycles_back * interval + WORK_DIFF_DEPTH))
}

impl<H: BlockHeaderStorage> MasternodeListEngine<H> {
    /// An empty engine for `network` that looks block heights up in `headers`.
    pub fn new(network: Network, headers: Arc<RwLock<H>>) -> Self {
        Self {
            headers,
            masternode_lists: BTreeMap::new(),
            rotated_quorums_per_cycle: BTreeMap::new(),
            network,
        }
    }

    /// The height of `block_hash` in the header chain. The genesis block, and
    /// the all-zero hash standing for it, is at 0 even when the chain starts
    /// at a checkpoint.
    pub async fn height_of(&self, block_hash: &BlockHash) -> Option<CoreBlockHeight> {
        if *block_hash == BlockHash::all_zeros()
            || self.network.known_genesis_block_hash() == Some(*block_hash)
        {
            return Some(0);
        }
        match self.headers.read().await.get_header_height_by_hash(block_hash).await {
            Ok(height) => height,
            Err(e) => {
                tracing::warn!("Could not look up the height of {block_hash}: {e}");
                None
            }
        }
    }

    /// The hash of the block at `height` in the header chain.
    async fn hash_at(&self, height: CoreBlockHeight) -> Option<BlockHash> {
        match self.headers.read().await.get_header(height).await {
            Ok(header) => header.map(|header| *header.hash()),
            Err(e) => {
                tracing::warn!("Could not look up the block at {height}: {e}");
                None
            }
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The list at or below `height` and the next one above it.
    pub fn masternode_lists_around_height(
        &self,
        height: CoreBlockHeight,
    ) -> (Option<&MasternodeList>, Option<&MasternodeList>) {
        (
            self.masternode_lists.range(..=height).next_back().map(|(_, list)| list),
            self.masternode_lists.range(height + 1..).next().map(|(_, list)| list),
        )
    }

    pub fn latest_masternode_list(&self) -> Option<&MasternodeList> {
        self.masternode_lists.last_key_value().map(|(_, list)| list)
    }

    /// The rotated quorums of the cycle `cycle_hash`, by quorum index.
    pub fn rotated_quorums_of_cycle(
        &self,
        cycle_hash: &BlockHash,
    ) -> Option<&BTreeMap<u16, QualifiedQuorumEntry>> {
        self.rotated_quorums_per_cycle.get(cycle_hash)
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn rotated_quorums_per_cycle(
        &self,
    ) -> &BTreeMap<BlockHash, BTreeMap<u16, QualifiedQuorumEntry>> {
        &self.rotated_quorums_per_cycle
    }

    /// The `(base, target)` diffs that bring the work-block list of every
    /// unverified non-rotating quorum of the newest list, oldest first. A
    /// retired quorum type is never validated, so it needs none.
    pub async fn missing_work_block_list_requests(&self) -> Vec<(BlockHash, BlockHash)> {
        let Some(newest) = self.latest_masternode_list() else {
            return Vec::new();
        };
        let mut work_heights = BTreeSet::new();
        for (llmq_type, quorums) in newest.quorums.iter() {
            if llmq_type.is_rotating_quorum_type()
                || self.network.should_skip_quorum_type(llmq_type, newest.known_height)
            {
                continue;
            }
            for (quorum_hash, quorum) in quorums {
                if quorum.verified == LLMQEntryVerificationStatus::Verified {
                    continue;
                }
                match self.height_of(quorum_hash).await {
                    Some(height) => {
                        work_heights.insert(height.saturating_sub(QUORUM_MEMBER_LIST_OFFSET));
                    }
                    None => tracing::warn!("No height for quorum {quorum_hash}, skipping it"),
                }
            }
        }
        let mut requests = Vec::new();
        for height in work_heights {
            if self.masternode_lists.contains_key(&height) {
                continue;
            }
            let Some(target) = self.hash_at(height).await else {
                tracing::warn!("No block at work height {height}, skipping it");
                continue;
            };
            let base = self
                .masternode_lists
                .range(..height)
                .next_back()
                .map_or(BlockHash::all_zeros(), |(_, list)| list.block_hash);
            requests.push((base, target));
        }
        requests
    }

    /// The stored rotated quorum `quorum_entry` commits to, if any.
    fn known_qualified_quorum_entry(
        &self,
        quorum_entry: &QuorumEntry,
    ) -> Option<QualifiedQuorumEntry> {
        self.rotated_quorums_per_cycle
            .values()
            .find_map(|qualified_entries| {
                qualified_entries.values().find(|qualified_entry| {
                    qualified_entry.quorum_entry.quorum_hash == quorum_entry.quorum_hash
                        && qualified_entry.quorum_entry.llmq_type == quorum_entry.llmq_type
                })
            })
            .cloned()
    }

    /// Stores the previous cycle, the active set of the list at the h work
    /// block, so IS locks of that cycle verify after a fresh sync. Best effort:
    /// a quorum that does not verify is left out on its own, and bad data is
    /// only rejected on the current-cycle path.
    async fn validate_and_store_previous_cycle_quorums(
        &mut self,
        work_height: CoreBlockHeight,
        sigs_by_work_height: &BTreeMap<CoreBlockHeight, BLSSignature>,
        inferred_work_heights: &BTreeSet<CoreBlockHeight>,
        snapshots: &BTreeMap<BlockHash, QuorumSnapshot>,
    ) {
        let isd_type = self.network.isd_llmq_type();
        let Some(quorums_of_type) =
            self.masternode_lists.get(&work_height).and_then(|list| list.quorums.get(&isd_type))
        else {
            return;
        };
        let Some(cycle_hash) =
            self.active_set_cycle_hash(quorums_of_type.values().map(|q| &**q).collect()).await
        else {
            return;
        };
        if self.is_cycle_fully_verified(&cycle_hash) {
            return;
        }
        let mut entries = Vec::with_capacity(quorums_of_type.len());
        for quorum in quorums_of_type.values() {
            let mut entry = (**quorum).clone();
            entry.verifying_chain_lock_signature =
                self.quarter_sigs(sigs_by_work_height, &entry.quorum_entry).await;
            entries.push(entry);
        }

        self.settle_rotated_quorums(&mut entries, inferred_work_heights, snapshots).await;
        entries.retain(|entry| {
            let verified = entry.verified == LLMQEntryVerificationStatus::Verified;
            if !verified {
                tracing::debug!(
                    "Previous-cycle quorum {} at cycle {cycle_hash} not validated ({}), leaving it out",
                    entry.quorum_entry.quorum_hash,
                    entry.verified
                );
            }
            verified
        });
        if entries.is_empty() {
            return;
        }
        for entry in &entries {
            self.set_quorum_status(isd_type, entry.quorum_entry.quorum_hash, &entry.verified);
        }
        if let Err(e) = self.store_cycle_if_fully_verified(cycle_hash, entries, isd_type).await {
            tracing::warn!("Previous cycle {cycle_hash} could not be stored: {e}");
        }
    }

    /// `true` when the stored cycle has a `Verified` quorum for every active
    /// slot. A partial cycle stays open so a later QRInfo can complete it.
    fn is_cycle_fully_verified(&self, cycle_hash: &BlockHash) -> bool {
        let expected = self.network.isd_llmq_type().active_quorum_count() as usize;
        self.rotated_quorums_per_cycle.get(cycle_hash).is_some_and(|existing| {
            existing.len() == expected
                && existing.values().all(|q| q.verified == LLMQEntryVerificationStatus::Verified)
        })
    }

    /// Merges the active set into its stored cycle when every quorum of it is
    /// `Verified` and the cycle is not complete yet, returning the cycle's
    /// height. IS locks are verified against these cycles only.
    async fn store_cycle_if_fully_verified(
        &mut self,
        cycle_key: BlockHash,
        qualified_last_commitment_per_index: Vec<QualifiedQuorumEntry>,
        rotation_quorum_type: LLMQType,
    ) -> Result<Option<CoreBlockHeight>, QuorumValidationError> {
        let all_entries_verified = qualified_last_commitment_per_index
            .iter()
            .all(|q| q.verified == LLMQEntryVerificationStatus::Verified);
        if !all_entries_verified || self.is_cycle_fully_verified(&cycle_key) {
            return Ok(None);
        }
        let cycle_map =
            build_cycle_quorum_map(qualified_last_commitment_per_index, rotation_quorum_type)?;
        self.rotated_quorums_per_cycle.entry(cycle_key).or_default().extend(cycle_map);
        Ok(self.height_of(&cycle_key).await)
    }

    /// The ChainLock signature of each rotation work block, from the
    /// `quorumsCLSigs` of every diff. Core keys a rotated quorum's signature to
    /// its own work block, so one diff can carry several cycles' signatures.
    ///
    /// A group whose quorum heights are all unknown is keyed by elimination:
    /// walking diffs oldest first, a non-zero signature already keying an older
    /// work block belongs to it, and a single remaining group is the diff's
    /// newest cycle. Exact keys win. The work heights keyed this way are
    /// returned too, see [`Self::settle_rotated_quorums`].
    async fn rotation_cl_sigs_by_work_height(
        &self,
        diffs: Vec<&MnListDiff>,
    ) -> (BTreeMap<CoreBlockHeight, BLSSignature>, BTreeSet<CoreBlockHeight>) {
        let mut diffs_by_end_height = Vec::new();
        for diff in diffs {
            diffs_by_end_height.push((self.height_of(&diff.block_hash).await, diff));
        }
        diffs_by_end_height.sort_by_key(|(end_height, _)| *end_height);

        let mut sigs_by_work_height = BTreeMap::new();
        for (_, diff) in &diffs_by_end_height {
            for sig_obj in &diff.quorums_chainlock_signatures {
                for quorum in signed_rotated_quorums(diff, sig_obj) {
                    if let Some(work_height) = self
                        .rotated_quorum_cycle_base(quorum)
                        .await
                        .and_then(|cycle_base| cycle_base.checked_sub(WORK_DIFF_DEPTH))
                    {
                        sigs_by_work_height.insert(work_height, sig_obj.signature);
                    }
                }
            }
        }

        let mut inferred_work_heights = BTreeSet::new();
        for (end_height, diff) in &diffs_by_end_height {
            let Some(newest_work_height) =
                end_height.and_then(|end_height| self.diff_newest_work_height(end_height))
            else {
                continue;
            };
            if sigs_by_work_height.contains_key(&newest_work_height) {
                continue;
            }
            let mut candidate_sigs: Vec<&BLSSignature> = Vec::new();
            for sig_obj in &diff.quorums_chainlock_signatures {
                let mut group_resolved = false;
                let mut group_has_unresolved_rotated = false;
                let mut hypothesis_mismatch = false;
                for quorum in signed_rotated_quorums(diff, sig_obj) {
                    if self.rotated_quorum_cycle_base(quorum).await.is_some() {
                        group_resolved = true;
                        continue;
                    }
                    group_has_unresolved_rotated = true;
                    // A known block at the presumed height disproves the
                    // newest-cycle presumption when it is another block.
                    let Some(quorum_index) =
                        quorum.quorum_index.and_then(|i| u32::try_from(i).ok())
                    else {
                        continue;
                    };
                    let Some(presumed_height) = WORK_DIFF_DEPTH
                        .checked_add(quorum_index)
                        .and_then(|offset| newest_work_height.checked_add(offset))
                    else {
                        continue;
                    };
                    if self
                        .hash_at(presumed_height)
                        .await
                        .is_some_and(|block_hash| block_hash != quorum.quorum_hash)
                    {
                        hypothesis_mismatch = true;
                    }
                }
                if group_resolved || !group_has_unresolved_rotated || hypothesis_mismatch {
                    continue;
                }
                // A zeroed signature stands for every work block without a
                // ChainLock, so only a non-zero repeat identifies a cycle.
                if !sig_obj.signature.is_zeroed()
                    && sigs_by_work_height.values().any(|sig| *sig == sig_obj.signature)
                {
                    continue;
                }
                candidate_sigs.push(&sig_obj.signature);
            }
            if let [only_group_sig] = candidate_sigs.as_slice() {
                sigs_by_work_height.insert(newest_work_height, **only_group_sig);
                inferred_work_heights.insert(newest_work_height);
            }
        }
        (sigs_by_work_height, inferred_work_heights)
    }

    /// For a diff ending at a work block, the work block of the newest cycle
    /// whose commitments it can carry: one interval below its end.
    fn diff_newest_work_height(&self, end_height: CoreBlockHeight) -> Option<CoreBlockHeight> {
        let interval = self.network.isd_llmq_type().params().dkg_params.interval;
        (end_height % interval == interval - WORK_DIFF_DEPTH)
            .then(|| end_height.checked_sub(interval))
            .flatten()
    }

    async fn rotated_quorum_cycle_base(&self, quorum: &QuorumEntry) -> Option<CoreBlockHeight> {
        rotated_cycle_base_height(quorum, self.height_of(&quorum.quorum_hash).await?)
    }

    async fn quarter_work_heights(&self, quorum: &QuorumEntry) -> Option<[CoreBlockHeight; 4]> {
        let cycle_base = self.rotated_quorum_cycle_base(quorum).await?;
        let interval = quorum.llmq_type.params().dkg_params.interval;
        let [h3, h2, h1, h0] = cycle_quarter_work_heights(cycle_base, interval);
        Some([h3?, h2?, h1?, h0?])
    }

    async fn quarter_sigs(
        &self,
        sigs_by_work_height: &BTreeMap<CoreBlockHeight, BLSSignature>,
        quorum: &QuorumEntry,
    ) -> Option<VerifyingChainLockSignaturesType> {
        let [h3, h2, h1, h0] = self.quarter_work_heights(quorum).await?;
        let sig_at = |work_height: CoreBlockHeight| sigs_by_work_height.get(&work_height).copied();
        Some(VerifyingChainLockSignaturesType::Rotating([
            sig_at(h3)?,
            sig_at(h2)?,
            sig_at(h1)?,
            sig_at(h0)?,
        ]))
    }

    async fn quarter_sigs_are_inferred(
        &self,
        inferred_work_heights: &BTreeSet<CoreBlockHeight>,
        quorum: &QuorumEntry,
    ) -> bool {
        self.quarter_work_heights(quorum).await.is_some_and(|work_heights| {
            work_heights.iter().any(|work_height| inferred_work_heights.contains(work_height))
        })
    }

    /// The configured rotation type, or on a devnet without an override, the
    /// rotating type the peer serves.
    fn rotation_quorum_type(&self, served: &[QuorumEntry]) -> LLMQType {
        let configured = self.network.isd_llmq_type();
        if self.network != Network::Devnet || devnet_isd_type_override().is_some() {
            return configured;
        }
        served
            .iter()
            .map(|quorum| quorum.llmq_type)
            .find(|llmq_type| llmq_type.is_rotating_quorum_type())
            .unwrap_or(configured)
    }

    /// The hash of the newest cycle base in an active set. A failed DKG leaves
    /// an older cycle's quorum at its index, so a set can span cycles, and the
    /// newest one is the cycle the set is active for.
    async fn active_set_cycle_hash(
        &self,
        entries: Vec<&QualifiedQuorumEntry>,
    ) -> Option<QuorumHash> {
        let mut newest_cycle_base = None;
        for entry in entries {
            let cycle_base = self.rotated_quorum_cycle_base(&entry.quorum_entry).await;
            newest_cycle_base = newest_cycle_base.max(cycle_base);
        }
        self.hash_at(newest_cycle_base?).await
    }

    /// Sets each rotated quorum's status. A quarter signature keyed by
    /// elimination may be another cycle's, so a quorum failing under one is
    /// skipped rather than invalid.
    async fn settle_rotated_quorums(
        &self,
        quorums: &mut [QualifiedQuorumEntry],
        inferred_work_heights: &BTreeSet<CoreBlockHeight>,
        snapshots: &BTreeMap<BlockHash, QuorumSnapshot>,
    ) {
        let statuses =
            self.rotated_quorum_statuses(&quorums.iter().collect::<Vec<_>>(), snapshots).await;
        for quorum in quorums.iter_mut() {
            let quorum_hash = quorum.quorum_entry.quorum_hash;
            quorum.verified = statuses.get(&quorum_hash).cloned().unwrap_or_default();
            if matches!(quorum.verified, LLMQEntryVerificationStatus::Invalid(_))
                && self.quarter_sigs_are_inferred(inferred_work_heights, &quorum.quorum_entry).await
            {
                tracing::warn!(
                    "Rotated quorum {quorum_hash} failed validation ({}) under inferred quarter signatures, skipping it",
                    quorum.verified
                );
                quorum.verified = LLMQEntryVerificationStatus::Skipped(
                    LLMQEntryVerificationSkipStatus::InferredRotationChainLockSigs(quorum_hash),
                );
            }
        }
    }

    /// Applies a QRInfo's diffs, then validates and stores its active rotation
    /// set and the previous cycle's. An invalid current-cycle quorum fails it.
    pub async fn feed_qr_info(
        &mut self,
        qr_info: QRInfo,
    ) -> Result<QRInfoFeedResult, QuorumValidationError> {
        let (rotation_sigs_by_work_height, inferred_work_heights) =
            self.rotation_cl_sigs_by_work_height(qr_info_diffs(&qr_info)).await;

        let QRInfo {
            quorum_snapshot_at_h_minus_c,
            quorum_snapshot_at_h_minus_2c,
            quorum_snapshot_at_h_minus_3c,
            mn_list_diff_tip,
            mn_list_diff_h,
            mn_list_diff_at_h_minus_c,
            mn_list_diff_at_h_minus_2c,
            mn_list_diff_at_h_minus_3c,
            quorum_snapshot_and_mn_list_diff_at_h_minus_4c,
            last_commitment_per_index,
            quorum_snapshot_list,
            mn_list_diff_list,
        } = qr_info;

        let can_verify_previous = quorum_snapshot_and_mn_list_diff_at_h_minus_4c.is_some();
        let h_block_hash = mn_list_diff_h.block_hash;
        let rotation_quorum_type = self.rotation_quorum_type(&last_commitment_per_index);
        let rotated_quorum_count = last_commitment_per_index.len();

        let mut snapshots = BTreeMap::new();
        for (snapshot, diff) in quorum_snapshot_list
            .into_iter()
            .zip(mn_list_diff_list)
            .chain(quorum_snapshot_and_mn_list_diff_at_h_minus_4c)
            .chain([
                (quorum_snapshot_at_h_minus_3c, mn_list_diff_at_h_minus_3c),
                (quorum_snapshot_at_h_minus_2c, mn_list_diff_at_h_minus_2c),
                (quorum_snapshot_at_h_minus_c, mn_list_diff_at_h_minus_c),
            ])
        {
            snapshots.insert(diff.block_hash, snapshot);
            self.apply_and_prune(diff).await?;
        }
        self.apply_and_prune(mn_list_diff_h).await?;
        self.apply_and_prune(mn_list_diff_tip).await?;

        // Only the h-4c share brings the oldest quarters of the list at h.
        if let Some(h_height) = self.height_of(&h_block_hash).await.filter(|_| can_verify_previous)
        {
            self.validate_and_store_previous_cycle_quorums(
                h_height,
                &rotation_sigs_by_work_height,
                &inferred_work_heights,
                &snapshots,
            )
            .await;
        }

        let mut qualified_last_commitment_per_index =
            Vec::with_capacity(last_commitment_per_index.len());
        for quorum_entry in last_commitment_per_index {
            if let Some(qualified_quorum_entry) = self.known_qualified_quorum_entry(&quorum_entry) {
                qualified_last_commitment_per_index.push(qualified_quorum_entry);
                continue;
            }
            let quarter_sigs =
                self.quarter_sigs(&rotation_sigs_by_work_height, &quorum_entry).await;
            let mut qualified_quorum_entry: QualifiedQuorumEntry = quorum_entry.into();
            qualified_quorum_entry.verifying_chain_lock_signature = quarter_sigs;
            qualified_last_commitment_per_index.push(qualified_quorum_entry);
        }

        let cycle_key =
            self.active_set_cycle_hash(qualified_last_commitment_per_index.iter().collect()).await;
        if cycle_key.is_none() && rotated_quorum_count > 0 {
            tracing::warn!(
                "None of the {} rotated quorums served resolves a cycle base, so the cycle cannot be stored under any key",
                rotated_quorum_count
            );
        }

        self.settle_rotated_quorums(
            &mut qualified_last_commitment_per_index,
            &inferred_work_heights,
            &snapshots,
        )
        .await;
        if let Some(LLMQEntryVerificationStatus::Invalid(e)) = qualified_last_commitment_per_index
            .iter()
            .map(|quorum| &quorum.verified)
            .find(|status| matches!(status, LLMQEntryVerificationStatus::Invalid(_)))
        {
            return Err(e.clone());
        }

        for quorum in &qualified_last_commitment_per_index {
            self.set_quorum_status(
                quorum.quorum_entry.llmq_type,
                quorum.quorum_entry.quorum_hash,
                &quorum.verified,
            );
        }
        let fully_verified_count = qualified_last_commitment_per_index
            .iter()
            .filter(|q| q.verified == LLMQEntryVerificationStatus::Verified)
            .count();
        let stored_cycle_height = match cycle_key {
            Some(key) => {
                self.store_cycle_if_fully_verified(
                    key,
                    qualified_last_commitment_per_index,
                    rotation_quorum_type,
                )
                .await?
            }
            None => None,
        };

        self.verify_newest_quorums().await;
        Ok(QRInfoFeedResult {
            rotated_quorum_count,
            expected_rotated_quorum_count: rotation_quorum_type.active_quorum_count() as usize,
            fully_verified_count,
            stored_cycle_height,
        })
    }

    /// Applies a diff, then verifies the newest list's non-rotating quorums: the
    /// diff may have brought one, or the work-block list one needs.
    pub async fn apply_diff(&mut self, masternode_list_diff: MnListDiff) -> Result<(), SmlError> {
        self.apply_and_prune(masternode_list_diff).await?;
        self.verify_newest_quorums().await;
        Ok(())
    }

    /// A diff on the newest list moves the tip and prunes, see
    /// [`Self::prune_after_extending`]. Others may share an older base.
    async fn apply_and_prune(&mut self, masternode_list_diff: MnListDiff) -> Result<(), SmlError> {
        let extended_tip = self
            .latest_masternode_list()
            .filter(|list| list.block_hash == masternode_list_diff.base_block_hash)
            .map(|list| list.known_height);
        self.apply_diff_to_base(masternode_list_diff).await?;
        if let Some(base) = extended_tip {
            self.prune_after_extending(base).await;
        }
        Ok(())
    }

    async fn apply_diff_to_base(
        &mut self,
        masternode_list_diff: MnListDiff,
    ) -> Result<(), SmlError> {
        let block_hash = masternode_list_diff.block_hash;
        let base_block_hash = masternode_list_diff.base_block_hash;
        let base_height = self
            .height_of(&base_block_hash)
            .await
            .ok_or(SmlError::BlockHashLookupFailed(base_block_hash))?;
        let diff_end_height =
            self.height_of(&block_hash).await.ok_or(SmlError::BlockHashLookupFailed(block_hash))?;
        if base_height == 0 {
            let masternode_list =
                MasternodeList::from_diff(masternode_list_diff, diff_end_height, self.network)?;
            self.masternode_lists.insert(diff_end_height, masternode_list);
            return Ok(());
        }

        let Some(base_masternode_list) = self.masternode_lists.get(&base_height) else {
            return Err(SmlError::MissingStartMasternodeList(base_block_hash));
        };
        let masternode_list =
            base_masternode_list.apply_diff(masternode_list_diff, diff_end_height, self.network)?;
        // A quorum the diff brings may already have a status in another list.
        let mut changes = Vec::new();
        for (quorum_type, quorums) in masternode_list.quorums.iter() {
            for quorum in quorums.values() {
                let known = self.masternode_lists.values().rev().find_map(|list| {
                    list.quorums.get(quorum_type)?.get(&quorum.quorum_entry.quorum_hash)
                });
                if let Some(known) = known.filter(|known| known.verified != quorum.verified) {
                    changes.push((
                        *quorum_type,
                        quorum.quorum_entry.quorum_hash,
                        known.verified.clone(),
                    ));
                }
            }
        }
        self.masternode_lists.insert(diff_end_height, masternode_list);
        for (quorum_type, quorum_hash, status) in changes {
            self.set_quorum_status(quorum_type, quorum_hash, &status);
        }
        Ok(())
    }

    /// Verifies the newest list's unverified non-rotating quorums against their
    /// work-block lists (DIP-6). Rotated ones are verified per QRInfo.
    async fn verify_newest_quorums(&mut self) {
        let Some(list) = self.latest_masternode_list() else {
            return;
        };
        let mut changes = Vec::new();
        for (quorum_type, quorums) in list.quorums.iter() {
            if quorum_type.is_rotating_quorum_type() {
                continue;
            }
            for (quorum_hash, quorum) in quorums {
                if quorum.verified == LLMQEntryVerificationStatus::Verified {
                    continue;
                }
                let status = match self.validate_quorum(quorum).await {
                    Ok(()) => LLMQEntryVerificationStatus::Verified,
                    Err(e) => e.into(),
                };
                if status != quorum.verified {
                    changes.push((*quorum_type, *quorum_hash, status));
                }
            }
        }
        for (quorum_type, quorum_hash, status) in changes {
            self.set_quorum_status(quorum_type, quorum_hash, &status);
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::HashMap;

    use super::*;
    use crate::test_utils::MockHeaderStorage;
    use dashcore::bls_sig_utils::BLSPublicKey;
    use dashcore::hash_types::QuorumVVecHash;

    pub(crate) type TestEngine = MasternodeListEngine<MockHeaderStorage>;

    /// The block container the engine kept before it read the header chain,
    /// as `block_container_*.dat` fixtures hold it.
    #[derive(bincode::Decode)]
    enum BlockContainer {
        BTreeMapContainer {
            block_hashes: BTreeMap<CoreBlockHeight, BlockHash>,
            _block_heights: BTreeMap<BlockHash, CoreBlockHeight>,
        },
    }

    /// Heights, lists and rotated cycles of `masternode_lists_2243493.bin`.
    type MainnetFixture = (
        BTreeMap<CoreBlockHeight, BlockHash>,
        BTreeMap<CoreBlockHeight, MasternodeList>,
        BTreeMap<BlockHash, BTreeMap<u16, QualifiedQuorumEntry>>,
    );

    fn decode<T: bincode::Decode<()>>(bytes: &[u8]) -> T {
        bincode::decode_from_slice(bytes, bincode::config::standard()).expect("decodes").0
    }

    fn heights_of(container: BlockContainer) -> HashMap<BlockHash, CoreBlockHeight> {
        let BlockContainer::BTreeMapContainer {
            block_hashes,
            ..
        } = container;
        block_hashes.into_iter().map(|(height, block_hash)| (block_hash, height)).collect()
    }

    /// A commitment with one signer and zeroed keys and signatures.
    pub(crate) fn quorum_entry(
        llmq_type: LLMQType,
        quorum_hash: QuorumHash,
        quorum_index: Option<i16>,
    ) -> QuorumEntry {
        QuorumEntry {
            version: 2,
            llmq_type,
            quorum_hash,
            quorum_index,
            signers: vec![true],
            valid_members: vec![true],
            quorum_public_key: BLSPublicKey::from([0; 48]),
            quorum_vvec_hash: QuorumVVecHash::all_zeros(),
            threshold_sig: BLSSignature::from([0; 96]),
            all_commitment_aggregated_signature: BLSSignature::from([0; 96]),
        }
    }

    /// The block heights of a `block_container_*.dat` fixture.
    pub(crate) fn fixture_heights(bytes: &[u8]) -> HashMap<BlockHash, CoreBlockHeight> {
        heights_of(decode(bytes))
    }

    impl TestEngine {
        /// An empty engine with an empty header chain.
        pub(crate) fn empty(network: Network) -> Self {
            Self::knowing(network, HashMap::new())
        }

        /// An empty engine whose header chain holds exactly `heights`.
        pub(crate) fn knowing(
            network: Network,
            heights: HashMap<BlockHash, CoreBlockHeight>,
        ) -> Self {
            Self::new(network, Arc::new(RwLock::new(MockHeaderStorage(heights))))
        }

        pub(crate) fn feed_block_height(&mut self, height: CoreBlockHeight, block_hash: BlockHash) {
            self.headers.try_write().expect("unlocked").0.insert(block_hash, height);
        }

        pub(crate) fn forget_block(&mut self, block_hash: &BlockHash) {
            self.headers.try_write().expect("unlocked").0.remove(block_hash);
        }

        pub(crate) fn block_height(&self, block_hash: &BlockHash) -> Option<CoreBlockHeight> {
            self.headers.try_read().expect("unlocked").0.get(block_hash).copied()
        }

        pub(crate) fn block_hash_at(&self, height: CoreBlockHeight) -> Option<BlockHash> {
            let headers = self.headers.try_read().expect("unlocked");
            headers.0.iter().find(|(_, h)| **h == height).map(|(block_hash, _)| *block_hash)
        }

        /// Verifies `chain_lock` as the ChainLock manager does.
        pub(crate) fn verify_chain_lock(
            &self,
            chain_lock: &dashcore::ChainLock,
        ) -> crate::error::ValidationResult<()> {
            use crate::validation::{ChainLockValidator, Validator};
            use dashcore::sml::llmq_type::network::NetworkLLMQExt;

            let (before, after) = self.masternode_lists_around_height(chain_lock.signing_height());
            ChainLockValidator::new(self.network.chain_locks_type(), before, after)
                .validate(chain_lock)
        }

        /// A mainnet engine with 29 lists up to 2243493 holding only their
        /// ChainLock quorums, and the rotation cycle of that tip.
        pub(crate) fn mainnet_fixture() -> Self {
            let (block_hashes, masternode_lists, rotated_quorums_per_cycle): MainnetFixture =
                decode(include_bytes!(
                    "../../dash/tests/data/test_DML_diffs/masternode_lists_2243493.bin"
                ));
            let heights = block_hashes.into_iter().map(|(height, hash)| (hash, height)).collect();
            let mut engine = Self::knowing(Network::Mainnet, heights);
            engine.masternode_lists = masternode_lists;
            engine.rotated_quorums_per_cycle = rotated_quorums_per_cycle;
            engine
        }

        /// A mainnet engine holding an empty list at each of `heights`.
        pub(crate) fn dummy_with_lists(heights: &[CoreBlockHeight]) -> Self {
            let mut engine = Self::empty(Network::Mainnet);
            for &height in heights {
                engine.feed_block_height(height, BlockHash::dummy(height));
                engine
                    .masternode_lists
                    .insert(height, MasternodeList::empty(BlockHash::dummy(height), height));
            }
            engine
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{fixture_heights, quorum_entry, TestEngine};
    use super::{build_cycle_quorum_map, WORK_DIFF_DEPTH};
    use bincode::{config, decode_from_slice, Decode};
    use dashcore::bls_sig_utils::BLSSignature;
    use dashcore::consensus::deserialize;
    use dashcore::hashes::Hash;
    use dashcore::network::message_qrinfo::QRInfo;
    use dashcore::network::message_sml::{MnListDiff, QuorumCLSigObject};
    use dashcore::prelude::CoreBlockHeight;
    use dashcore::sml::llmq_entry_verification::{
        LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus,
    };
    use dashcore::sml::llmq_type::devnet_isd_type_override;
    use dashcore::sml::llmq_type::network::NetworkLLMQExt;
    use dashcore::sml::llmq_type::LLMQType;
    use dashcore::sml::masternode_list::MasternodeList;
    use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
    use dashcore::sml::quorum_validation_error::QuorumValidationError;
    use dashcore::transaction::special_transaction::quorum_commitment::QuorumEntry;
    use dashcore::{BlockHash, Network, QuorumHash};
    use std::collections::{BTreeMap, BTreeSet};

    fn make_qualified_quorum_entry(
        llmq_type: LLMQType,
        quorum_index: Option<i16>,
    ) -> QualifiedQuorumEntry {
        quorum_entry(llmq_type, QuorumHash::all_zeros(), quorum_index).into()
    }

    /// A diff carrying only what the rotation signature keying reads: its end
    /// block, its rotating commitments, and its `quorumsCLSigs` groups.
    fn make_cl_sig_diff(
        end_hash: BlockHash,
        new_quorums: Vec<QuorumEntry>,
        groups: Vec<(BLSSignature, Vec<u16>)>,
    ) -> MnListDiff {
        let diff_bytes: &[u8] =
            include_bytes!("../../dash/tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin");
        let mut diff: MnListDiff = deserialize(diff_bytes).expect("expected to deserialize");
        diff.block_hash = end_hash;
        diff.new_quorums = new_quorums;
        diff.quorums_chainlock_signatures = groups
            .into_iter()
            .map(|(signature, index_set)| QuorumCLSigObject {
                signature,
                index_set,
            })
            .collect();
        diff
    }

    fn engine_knowing_blocks(blocks: &[(CoreBlockHeight, BlockHash)]) -> TestEngine {
        TestEngine::knowing(
            Network::Mainnet,
            blocks.iter().map(|(height, block_hash)| (*block_hash, *height)).collect(),
        )
    }

    /// Core keys every rotated quorum's ChainLock signature to that quorum's
    /// own work block and merges work blocks that share a signature, so the
    /// keying has to survive unknown quorum heights, ambiguity, and a
    /// signature that legitimately covers more than one cycle.
    #[tokio::test]
    async fn rotation_cl_sigs_by_work_height_keys_each_cycle_to_its_own_work_block() {
        let isd_type = Network::Mainnet.isd_llmq_type();
        let interval = isd_type.params().dkg_params.interval;
        assert_eq!(interval, 288, "the heights below assume the mainnet DKG interval");

        let cycle_base = interval * 100;
        let diff_end = cycle_base + interval - WORK_DIFF_DEPTH;
        let older_diff_end = diff_end - interval;
        let work_height = cycle_base - WORK_DIFF_DEPTH;
        let older_work_height = work_height - interval;

        let end_hash = BlockHash::from_byte_array([1; 32]);
        let older_end_hash = BlockHash::from_byte_array([2; 32]);
        let quorum_hash = QuorumHash::from_byte_array([3; 32]);
        let other_quorum_hash = QuorumHash::from_byte_array([4; 32]);
        let older_quorum_hash = QuorumHash::from_byte_array([5; 32]);
        let sig = BLSSignature::from([7; 96]);
        let other_sig = BLSSignature::from([8; 96]);
        let zero_sig = BLSSignature::from([0; 96]);

        let diff = make_cl_sig_diff(
            end_hash,
            vec![quorum_entry(isd_type, quorum_hash, Some(3))],
            vec![(sig, vec![0])],
        );

        // A known quorum height keys the signature exactly, no inference.
        let engine = engine_knowing_blocks(&[(diff_end, end_hash), (cycle_base + 3, quorum_hash)]);
        let (sigs, inferred) = engine.rotation_cl_sigs_by_work_height(vec![&diff]).await;
        assert_eq!(sigs, BTreeMap::from([(work_height, sig)]));
        assert!(inferred.is_empty(), "a known quorum height must key exactly");

        // Nothing on the wire ties a `quorum_index` to the block its
        // commitment was mined in. Index 4 moves the base one block off the
        // cycle boundary, index 3 + c moves it a whole cycle back onto the
        // older cycle's work block, and either one exactly-keying would
        // replace a genuine signature with this group's.
        for shifted_index in [4, 3 + interval as i16] {
            let shifted = make_cl_sig_diff(
                end_hash,
                vec![quorum_entry(isd_type, quorum_hash, Some(shifted_index))],
                vec![(sig, vec![0])],
            );
            let (sigs, inferred) = engine.rotation_cl_sigs_by_work_height(vec![&shifted]).await;
            assert_eq!(
                sigs,
                BTreeMap::from([(work_height, sig)]),
                "index {} must not key a work block of its own choosing",
                shifted_index
            );
            assert_eq!(
                inferred,
                BTreeSet::from([work_height]),
                "a rejected index leaves only the diff's own cycle to key by elimination"
            );
        }

        // Without that height the only remaining group is keyed by
        // elimination, and the caller is told the key was inferred.
        let engine = engine_knowing_blocks(&[(diff_end, end_hash)]);
        let (sigs, inferred) = engine.rotation_cl_sigs_by_work_height(vec![&diff]).await;
        assert_eq!(sigs, BTreeMap::from([(work_height, sig)]));
        assert_eq!(inferred, BTreeSet::from([work_height]));

        // Two unresolved groups leave the cycle ambiguous, so nothing is keyed.
        let ambiguous = make_cl_sig_diff(
            end_hash,
            vec![
                quorum_entry(isd_type, quorum_hash, Some(3)),
                quorum_entry(isd_type, other_quorum_hash, Some(5)),
            ],
            vec![(sig, vec![0]), (other_sig, vec![1])],
        );
        let (sigs, inferred) = engine.rotation_cl_sigs_by_work_height(vec![&ambiguous]).await;
        assert!(
            sigs.is_empty() && inferred.is_empty(),
            "two unresolved groups must resolve to nothing"
        );

        let engine =
            engine_knowing_blocks(&[(diff_end, end_hash), (older_diff_end, older_end_hash)]);

        // Work blocks without a ChainLock all carry the zeroed signature, so
        // its reappearance in a later diff says nothing about which cycle the
        // group belongs to and both work blocks must still be keyed.
        let older_zeroed = make_cl_sig_diff(
            older_end_hash,
            vec![quorum_entry(isd_type, older_quorum_hash, Some(3))],
            vec![(zero_sig, vec![0])],
        );
        let newer_zeroed = make_cl_sig_diff(
            end_hash,
            vec![quorum_entry(isd_type, quorum_hash, Some(3))],
            vec![(zero_sig, vec![0])],
        );
        let (sigs, inferred) =
            engine.rotation_cl_sigs_by_work_height(vec![&older_zeroed, &newer_zeroed]).await;
        assert_eq!(
            sigs,
            BTreeMap::from([(older_work_height, zero_sig), (work_height, zero_sig)]),
            "a zeroed signature repeated across cycles must key both work blocks"
        );
        assert_eq!(inferred, BTreeSet::from([older_work_height, work_height]));

        // A real ChainLock signature signs one block, so its reappearance does
        // identify the older cycle and the remaining group wins the newer one.
        let older = make_cl_sig_diff(
            older_end_hash,
            vec![quorum_entry(isd_type, older_quorum_hash, Some(3))],
            vec![(sig, vec![0])],
        );
        let newer = make_cl_sig_diff(
            end_hash,
            vec![
                quorum_entry(isd_type, quorum_hash, Some(3)),
                quorum_entry(isd_type, other_quorum_hash, Some(5)),
            ],
            vec![(sig, vec![0]), (other_sig, vec![1])],
        );
        let (sigs, _) = engine.rotation_cl_sigs_by_work_height(vec![&older, &newer]).await;
        assert_eq!(
            sigs,
            BTreeMap::from([(older_work_height, sig), (work_height, other_sig)]),
            "a repeated non-zero signature belongs to the cycle it already keys"
        );
    }

    /// Which rotation type an active set is keyed by decides which quorum
    /// indices exist at all, so a wrong one rejects genuine commitments. It
    /// comes from configuration wherever the deployment fixes it, and only a
    /// devnet that was never told its type reads it off the commitments.
    #[test]
    fn rotation_quorum_type_reads_the_served_type_only_on_an_unconfigured_devnet() {
        let served =
            [quorum_entry(LLMQType::LlmqtypeTestDIP0024, QuorumHash::all_zeros(), Some(0))];
        let non_rotating =
            [quorum_entry(LLMQType::Llmqtype50_60, QuorumHash::all_zeros(), Some(0))];

        for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            let engine = TestEngine::empty(network);
            assert_eq!(
                engine.rotation_quorum_type(&served),
                network.isd_llmq_type(),
                "a network with a deployed type must ignore what a peer serves"
            );
        }

        // The devnet override is a process-wide `OnceLock` another test in
        // this binary may have set, so the expectation follows it.
        let engine = TestEngine::empty(Network::Devnet);
        assert_eq!(
            engine.rotation_quorum_type(&served),
            devnet_isd_type_override().unwrap_or(LLMQType::LlmqtypeTestDIP0024)
        );
        assert_eq!(
            engine.rotation_quorum_type(&non_rotating),
            Network::Devnet.isd_llmq_type(),
            "only a rotating type may be adopted from the wire"
        );
    }

    #[test]
    fn build_cycle_quorum_map_edge_cases() {
        let ty = LLMQType::LlmqtypeTest;
        assert_eq!(ty.active_quorum_count(), 2, "test assumes active_quorum_count == 2");

        // Valid: two quorums with distinct indices
        let quorums = vec![
            make_qualified_quorum_entry(ty, Some(0)),
            make_qualified_quorum_entry(ty, Some(1)),
        ];
        let map = build_cycle_quorum_map(quorums, ty).expect("valid quorums should succeed");
        assert_eq!(map.len(), 2);
        assert!(map.contains_key(&0) && map.contains_key(&1));

        // Missing index is rejected
        let quorums =
            vec![make_qualified_quorum_entry(ty, Some(0)), make_qualified_quorum_entry(ty, None)];
        let err = build_cycle_quorum_map(quorums, ty).expect_err("missing index should fail");
        assert!(matches!(err, QuorumValidationError::RequiredQuorumIndexNotPresent(_)));

        // Negative index is rejected
        let quorums = vec![
            make_qualified_quorum_entry(ty, Some(0)),
            make_qualified_quorum_entry(ty, Some(-1)),
        ];
        let err = build_cycle_quorum_map(quorums, ty).expect_err("negative index should fail");
        assert!(matches!(
            err,
            QuorumValidationError::InvalidQuorumIndex {
                index: -1,
                ..
            }
        ));

        // Duplicate index is rejected
        let quorums = vec![
            make_qualified_quorum_entry(ty, Some(0)),
            make_qualified_quorum_entry(ty, Some(0)),
        ];
        let err = build_cycle_quorum_map(quorums, ty).expect_err("duplicate index should fail");
        assert!(matches!(err, QuorumValidationError::CorruptedCodeExecution(_)));

        // A partial set is allowed: unvalidatable quorums stay out of the
        // cycle map and IS locks selecting their index fail individually.
        let quorums = vec![make_qualified_quorum_entry(ty, Some(0))];
        let map = build_cycle_quorum_map(quorums, ty).expect("partial set should succeed");
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&0));

        // An index at or above the active quorum count is rejected
        let quorums = vec![make_qualified_quorum_entry(ty, Some(2))];
        let err = build_cycle_quorum_map(quorums, ty).expect_err("out-of-range index should fail");
        assert!(matches!(
            err,
            QuorumValidationError::InvalidQuorumIndex {
                index: 2,
                ..
            }
        ));
    }

    /// The cycle key of the active set a QRInfo serves.
    async fn served_cycle_key(engine: &TestEngine, qr_info: &QRInfo) -> BlockHash {
        let entries: Vec<QualifiedQuorumEntry> =
            qr_info.last_commitment_per_index.iter().cloned().map(Into::into).collect();
        engine
            .active_set_cycle_hash(entries.iter().collect())
            .await
            .expect("fixture must resolve the cycle key of its active set")
    }

    fn decode_fixture<T: Decode<()>>(bytes: &[u8]) -> T {
        decode_from_slice(bytes, config::standard()).expect("expected to decode").0
    }

    async fn load_qrinfo_2240504_fixture() -> (TestEngine, QRInfo) {
        let mut engine = TestEngine::knowing(
            Network::Mainnet,
            fixture_heights(include_bytes!(
                "../../dash/tests/data/test_DML_diffs/block_container_2240504.dat"
            )),
        );
        let diff: MnListDiff = deserialize(include_bytes!(
            "../../dash/tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin"
        ))
        .expect("expected to deserialize");
        engine.masternode_lists.insert(
            2227096,
            MasternodeList::from_diff(diff, 2227096, Network::Mainnet).expect("first list"),
        );

        let mn_list_diffs: BTreeMap<(CoreBlockHeight, CoreBlockHeight), MnListDiff> =
            decode_fixture(include_bytes!(
                "../../dash/tests/data/test_DML_diffs/mnlistdiffs_2240504.dat"
            ));
        let qr_info: QRInfo = decode_fixture(include_bytes!(
            "../../dash/tests/data/test_DML_diffs/qrinfo_2240504.dat"
        ));

        for ((base_height, height), diff) in mn_list_diffs {
            engine.feed_block_height(base_height, diff.base_block_hash);
            engine.feed_block_height(height, diff.block_hash);
            engine.apply_diff(diff).await.expect("expected to apply diff");
        }

        (engine, qr_info)
    }

    /// Captured 2026-08-09 from a fresh mainnet sync at tip 2518986 (cycle
    /// boundary 2518848). The active rotation set at that state carried a
    /// quorum whose latest commitment came from an older cycle, so the
    /// per-quorum quarter signatures differ within one QRInfo batch. The
    /// engine state mirrors production cold start: empty masternode lists
    /// over the captured header heights.
    fn load_qrinfo_2518986_fixture() -> (TestEngine, QRInfo) {
        let engine = TestEngine::knowing(
            Network::Mainnet,
            fixture_heights(include_bytes!(
                "../../dash/tests/data/test_DML_diffs/block_container_2518986.dat"
            )),
        );
        let qr_info: QRInfo = decode_fixture(include_bytes!(
            "../../dash/tests/data/test_DML_diffs/qrinfo_2518986.dat"
        ));
        (engine, qr_info)
    }

    #[tokio::test]
    async fn validate_first_qr_info_on_fresh_engine_with_mixed_cycle_quorums() {
        let (mut engine, qr_info) = load_qrinfo_2518986_fixture();

        // The fixture's active set mixes cycles: quorum index 0 carries the
        // previous cycle's commitment (its DKG failed in the current cycle),
        // the remaining 31 belong to the current cycle at 2518848. The pin
        // below keeps a fixture swap from silently dropping that property.
        let current_cycle_base = 2518848;
        let mut mixed_cycle_bases = BTreeSet::new();
        for quorum in &qr_info.last_commitment_per_index {
            mixed_cycle_bases.extend(engine.rotated_quorum_cycle_base(quorum).await);
        }
        assert!(
            mixed_cycle_bases.len() > 1 && mixed_cycle_bases.contains(&current_cycle_base),
            "fixture must carry a mixed-cycle active set, got cycle bases {:?}",
            mixed_cycle_bases
        );

        let h_block_hash = qr_info.mn_list_diff_h.block_hash;
        let feed_result = engine
            .feed_qr_info(qr_info)
            .await
            .expect("first QRInfo on a fresh engine must feed cleanly");

        assert_eq!(feed_result.rotated_quorum_count, 32);
        assert_eq!(
            feed_result.fully_verified_count, 32,
            "every active-set entry must verify under its own cycle's quarter signatures"
        );
        assert_eq!(
            feed_result.stored_cycle_height,
            Some(current_cycle_base),
            "the active set must be stored under the current cycle, not the straggler's"
        );

        let cycle_hash =
            engine.block_hash_at(current_cycle_base).expect("expected current cycle hash");
        let stored_cycle = engine
            .rotated_quorums_per_cycle
            .get(&cycle_hash)
            .expect("expected active set stored under the current cycle hash");
        assert_eq!(stored_cycle.len(), 32);
        assert!(
            stored_cycle.values().all(|q| q.verified == LLMQEntryVerificationStatus::Verified),
            "every stored quorum must be verified"
        );

        // The previous cycle's active set carries its own straggler at index
        // 20 (from one cycle further back), whose commitment block has no
        // height in the captured chain, so its cycle cannot be derived and it
        // settles as skipped. The verified rest of the set must still be
        // stored so IS locks referencing the previous cycle verify.
        let dkg_interval = engine.network.isd_llmq_type().params().dkg_params.interval;
        let previous_cycle_hash = engine
            .block_hash_at(current_cycle_base - dkg_interval)
            .expect("expected previous cycle hash");
        let previous_cycle = engine
            .rotated_quorums_per_cycle
            .get(&previous_cycle_hash)
            .expect("expected the previous cycle's verified subset stored");
        assert_eq!(previous_cycle.len(), 31);
        assert!(!previous_cycle.contains_key(&20), "the unverifiable straggler must be left out");
        assert!(
            previous_cycle.values().all(|q| q.verified == LLMQEntryVerificationStatus::Verified),
            "every stored previous-cycle quorum must be verified"
        );

        // The list at h holds the same previous-cycle quorums and must agree
        // with the stored cycle instead of reading them as skipped.
        let h_height =
            engine.height_of(&h_block_hash).await.expect("expected the height of the h block");
        let h_quorums =
            &engine.masternode_lists[&h_height].quorums[&engine.network.isd_llmq_type()];
        for quorum in previous_cycle.values() {
            let on_h = h_quorums
                .get(&quorum.quorum_entry.quorum_hash)
                .expect("the list at h holds every stored previous-cycle quorum");
            assert_eq!(
                on_h.verified,
                LLMQEntryVerificationStatus::Verified,
                "quorum {} on the list at h must read as verified",
                quorum.quorum_entry.quorum_hash
            );
        }

        // How many commitments a peer serves is up to the peer. A set one
        // entry short still verifies entry by entry, yet the index it omits
        // stays unproven, so the cycle must not read as fully validated.
        let (mut engine, mut qr_info) = load_qrinfo_2518986_fixture();
        qr_info.last_commitment_per_index.pop().expect("fixture must carry commitments");
        let feed_result = engine
            .feed_qr_info(qr_info)
            .await
            .expect("a truncated active set must still feed cleanly");
        assert_eq!(feed_result.rotated_quorum_count, 31);
        assert_eq!(
            feed_result.fully_verified_count, 31,
            "every served entry of the truncated set must still verify"
        );
        assert_eq!(feed_result.expected_rotated_quorum_count, 32);
        assert!(
            !feed_result.all_fully_verified(),
            "a set covering part of the cycle must not read as fully verified"
        );
    }

    #[tokio::test]
    async fn validate_from_qr_info_and_mn_list_diffs() {
        let (mut engine, qr_info) = load_qrinfo_2240504_fixture().await;

        // The 2240504 fixture exercises the current-cycle storage branch
        // (rotating quorums in `mn_list_diff_tip`). A fixture swap that flips
        // this assertion changes which code path the test covers.
        assert!(
            qr_info
                .mn_list_diff_tip
                .new_quorums
                .iter()
                .any(|q| q.llmq_type.is_rotating_quorum_type()),
            "fixture invariant: 2240504 QRInfo must have rotating quorums in mn_list_diff_tip; \
             swap fixture or update assertion if this changes"
        );

        engine.feed_qr_info(qr_info).await.expect("expected to feed_qr_info");

        // Both cycles must be stored: the current cycle from
        // `last_commitment_per_index` and the previous cycle from
        // `validate_and_store_previous_cycle_quorums`. The previous-cycle
        // path uses `masternode_lists[h]`, not `masternode_lists[h-c]`,
        // because the h-c cycle is only mined in the `(h-c, h]` diff range.
        assert_eq!(
            engine.rotated_quorums_per_cycle.len(),
            2,
            "expected both tip and previous rotation cycles stored"
        );

        let newest = engine.latest_masternode_list().expect("expected a newest list");
        for (quorum_type, quorums) in newest.quorums.iter() {
            if [LLMQType::Llmqtype400_85, LLMQType::Llmqtype50_60, LLMQType::Llmqtype400_60]
                .contains(quorum_type)
            {
                continue;
            }
            for (quorum_hash, quorum) in quorums.iter() {
                assert_eq!(
                    quorum.verified,
                    LLMQEntryVerificationStatus::Verified,
                    "quorum {quorum_hash} of type {quorum_type} is not verified"
                );
            }
        }
    }

    /// Storage gate: when a QRInfo carries no rotation chain-lock signatures
    /// and rotated quorums in `last_commitment_per_index` would need fresh
    /// validation, the cycle must NOT enter `rotated_quorums_per_cycle`.
    #[tokio::test]
    async fn feed_qr_info_does_not_store_cycle_when_rotation_sigs_missing() {
        let (mut engine, mut qr_info) = load_qrinfo_2240504_fixture().await;

        // The post-V20 strict check requires every `new_quorums` slot to have
        // a matching `quorums_chainlock_signatures` entry, so clearing both
        // keeps `apply_diff` happy while leaving no signature that could be
        // keyed to a quarter work height.
        let strip = |diff: &mut MnListDiff| {
            diff.new_quorums.clear();
            diff.quorums_chainlock_signatures.clear();
        };
        strip(&mut qr_info.mn_list_diff_tip);
        strip(&mut qr_info.mn_list_diff_h);
        strip(&mut qr_info.mn_list_diff_at_h_minus_c);
        strip(&mut qr_info.mn_list_diff_at_h_minus_2c);
        strip(&mut qr_info.mn_list_diff_at_h_minus_3c);
        if let Some((_, ref mut diff)) = qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c {
            strip(diff);
        }
        for diff in qr_info.mn_list_diff_list.iter_mut() {
            strip(diff);
        }

        let expected_cycle_key = served_cycle_key(&engine, &qr_info).await;

        let feed_result = engine
            .feed_qr_info(qr_info)
            .await
            .expect("feed_qr_info should succeed even when rotation sigs are missing");

        assert_eq!(feed_result.fully_verified_count, 0, "no entry can verify without its sigs");
        assert_eq!(feed_result.stored_cycle_height, None);
        assert!(
            !engine.rotated_quorums_per_cycle.contains_key(&expected_cycle_key),
            "Cycle {} must not be stored when rotation sigs are missing; current keys: {:?}",
            expected_cycle_key,
            engine.rotated_quorums_per_cycle.keys().collect::<Vec<_>>()
        );
    }

    /// An active set whose cycle base no entry resolves cannot be stored under
    /// any key, however well it verified, and must not abort the feed either.
    #[tokio::test]
    async fn feed_qr_info_stores_no_cycle_without_a_cycle_key() {
        let (mut engine, qr_info) = load_qrinfo_2240504_fixture().await;
        for quorum in qr_info.last_commitment_per_index.iter() {
            engine.forget_block(&quorum.quorum_hash);
        }

        let feed_result = engine
            .feed_qr_info(qr_info)
            .await
            .expect("an unresolvable cycle key must not abort the feed");

        assert!(
            feed_result.stored_cycle_height.is_none(),
            "a cycle without a key must not be stored"
        );
    }

    /// Another rotated commitment's aggregate signature: structurally sound,
    /// so it reaches the BLS check, where it does not verify.
    fn foreign_aggregate_signature(
        quorums: &[QuorumEntry],
        quorum_hash: QuorumHash,
    ) -> BLSSignature {
        quorums
            .iter()
            .find(|q| q.llmq_type.is_rotating_quorum_type() && q.quorum_hash != quorum_hash)
            .expect("fixture must carry a second rotated quorum")
            .all_commitment_aggregated_signature
    }

    /// A QRInfo whose rotated quorum carries a corrupt
    /// `all_commitment_aggregated_signature` must be rejected rather than
    /// stored: a fully-Verified entry with an invalid aggregate signature
    /// would let bogus signed messages pass IS lock verification.
    #[tokio::test]
    async fn feed_qr_info_rejects_corrupt_aggregate_signature() {
        let (mut engine, mut qr_info) = load_qrinfo_2240504_fixture().await;

        let target = qr_info.last_commitment_per_index[0].quorum_hash;
        // Member reconstruction must reach the aggregate-signature check
        // rather than skip for an unknown block.
        assert!(engine.block_height(&target).is_some(), "fixture must know {target}'s height");

        let cycle_key = served_cycle_key(&engine, &qr_info).await;

        qr_info.last_commitment_per_index[0].all_commitment_aggregated_signature =
            foreign_aggregate_signature(&qr_info.last_commitment_per_index, target);

        let err = engine.feed_qr_info(qr_info).await.expect_err("corrupt signature must reject");
        assert!(
            matches!(err, QuorumValidationError::AllCommitmentAggregatedSignatureNotValid(_)),
            "expected aggregate-signature rejection, got {:?}",
            err
        );
        assert!(
            !engine.rotated_quorums_per_cycle.contains_key(&cycle_key),
            "rejected QRInfo must not have stored its cycle"
        );
    }

    /// A quarter signature keyed by elimination can belong to another cycle,
    /// so a current-cycle quorum resting on one must settle as `Skipped` when
    /// it fails to verify. Aborting the feed there would turn a gap in the
    /// caller's context into a permanent sync stall.
    #[tokio::test]
    async fn feed_qr_info_skips_a_current_cycle_quorum_resting_on_an_inferred_signature() {
        let (mut engine, mut qr_info) = load_qrinfo_2240504_fixture().await;

        // The quorums of the cycle based at 2239488 are what exactly key the
        // current cycle's oldest quarter. Dropping their heights leaves that
        // quarter reachable only by elimination.
        for height in 2239488..2239488 + 32 {
            if let Some(block_hash) = engine.block_hash_at(height) {
                engine.forget_block(&block_hash);
            }
        }

        let target = qr_info.last_commitment_per_index[0].quorum_hash;
        let llmq_type = qr_info.last_commitment_per_index[0].llmq_type;
        qr_info.last_commitment_per_index[0].all_commitment_aggregated_signature =
            foreign_aggregate_signature(&qr_info.last_commitment_per_index, target);

        let feed_result = engine
            .feed_qr_info(qr_info)
            .await
            .expect("an inferred quarter signature must not abort the feed");

        let status = engine
            .masternode_lists
            .values()
            .rev()
            .find_map(|list| list.quorums.get(&llmq_type)?.get(&target))
            .map(|quorum| quorum.verified.clone())
            .expect("a list must hold the corrupted quorum");
        assert!(
            matches!(
                status,
                LLMQEntryVerificationStatus::Skipped(
                    LLMQEntryVerificationSkipStatus::InferredRotationChainLockSigs(hash)
                ) if hash == target
            ),
            "a failure under an inferred quarter signature must settle as Skipped, got {status}"
        );
        assert!(
            feed_result.stored_cycle_height.is_none(),
            "a cycle holding a skipped entry must not be stored"
        );
    }

    /// The previous-cycle path is best-effort enrichment, so a corrupt
    /// aggregated signature there must only leave that quorum out of the
    /// stored cycle, never abort the whole feed. The rest of the cycle and
    /// the current cycle must still land verified.
    #[tokio::test]
    async fn feed_qr_info_degrades_previous_cycle_on_corrupt_aggregate_signature() {
        let (mut engine, mut qr_info) = load_qrinfo_2240504_fixture().await;

        let corrupt_position = qr_info
            .mn_list_diff_h
            .new_quorums
            .iter()
            .position(|q| q.llmq_type.is_rotating_quorum_type())
            .expect("fixture must carry rotated quorums in the h diff");
        let corrupted_quorum_hash =
            qr_info.mn_list_diff_h.new_quorums[corrupt_position].quorum_hash;
        let cycle_base = engine
            .rotated_quorum_cycle_base(&qr_info.mn_list_diff_h.new_quorums[corrupt_position])
            .await
            .expect("fixture must carry the corrupted quorum's cycle base");
        let previous_cycle_key =
            engine.block_hash_at(cycle_base).expect("expected cycle base hash");
        let foreign_signature =
            foreign_aggregate_signature(&qr_info.mn_list_diff_h.new_quorums, corrupted_quorum_hash);
        qr_info.mn_list_diff_h.new_quorums[corrupt_position].all_commitment_aggregated_signature =
            foreign_signature;
        let h_block_hash = qr_info.mn_list_diff_h.block_hash;

        let feed_result = engine
            .feed_qr_info(qr_info)
            .await
            .expect("previous-cycle corruption must not abort the feed");

        let h_height = engine.block_height(&h_block_hash).expect("expected the h height");
        let rotating_at_h = engine
            .masternode_lists
            .get(&h_height)
            .and_then(|list| list.quorums.get(&engine.network.isd_llmq_type()))
            .expect("expected rotated quorums on the list at h")
            .len();
        let previous_cycle = engine
            .rotated_quorums_per_cycle
            .get(&previous_cycle_key)
            .expect("the rest of the previous cycle must still be stored");
        assert!(
            !previous_cycle.values().any(|q| q.quorum_entry.quorum_hash == corrupted_quorum_hash),
            "the corrupted quorum must be left out of the stored cycle"
        );
        assert_eq!(
            previous_cycle.len(),
            rotating_at_h - 1,
            "degradation must drop the corrupted quorum and nothing else"
        );
        assert!(
            previous_cycle.values().all(|q| q.verified == LLMQEntryVerificationStatus::Verified),
            "every stored previous-cycle quorum must be verified"
        );
        assert!(feed_result.all_fully_verified(), "the current cycle must still verify fully");
        assert!(
            feed_result.stored_cycle_height.is_some(),
            "the current cycle must still be stored"
        );
    }

    /// The storage gate must short-circuit with `Ok(None)` (and not write)
    /// when any input entry is not `Verified` or the target cycle is already
    /// fully `Verified`, and it only ever merges into a stored cycle.
    #[tokio::test]
    async fn store_cycle_if_fully_verified_short_circuits() {
        let (mut engine, qr_info) = load_qrinfo_2240504_fixture().await;
        engine.feed_qr_info(qr_info).await.expect("first feed should succeed");

        let cycle_key = *engine
            .rotated_quorums_per_cycle
            .keys()
            .next()
            .expect("first feed must store at least one rotation cycle");
        let original_cycle =
            engine.rotated_quorums_per_cycle.get(&cycle_key).expect("cycle present").clone();
        let rotation_quorum_type =
            original_cycle.values().next().expect("cycle non-empty").quorum_entry.llmq_type;

        let already_verified: Vec<QualifiedQuorumEntry> =
            original_cycle.values().cloned().collect();
        let result = engine
            .store_cycle_if_fully_verified(cycle_key, already_verified, rotation_quorum_type)
            .await
            .expect("gate must not error on already-verified cycle");
        assert!(
            result.is_none(),
            "gate must short-circuit when target cycle is already fully Verified, got {:?}",
            result
        );
        assert_eq!(
            engine.rotated_quorums_per_cycle.get(&cycle_key).unwrap(),
            &original_cycle,
            "gate must not mutate the stored cycle on the already-verified short-circuit"
        );

        // `make_qualified_quorum_entry` defaults `verified` to `Skipped`, so
        // the gate must refuse to write a degraded cycle.
        let fresh_key = BlockHash::from_byte_array([0xAB; 32]);
        let active_count = rotation_quorum_type.active_quorum_count() as i16;
        let degraded: Vec<QualifiedQuorumEntry> = (0..active_count)
            .map(|i| make_qualified_quorum_entry(rotation_quorum_type, Some(i)))
            .collect();
        let result = engine
            .store_cycle_if_fully_verified(fresh_key, degraded, rotation_quorum_type)
            .await
            .expect("gate must not error when no entries are verified");
        assert!(
            result.is_none(),
            "gate must short-circuit when not all entries are Verified, got {:?}",
            result
        );
        assert!(
            !engine.rotated_quorums_per_cycle.contains_key(&fresh_key),
            "gate must not write a degraded cycle"
        );

        // A cycle stored with only part of its set is not a cycle the gate may
        // protect: the entries it lacks are exactly what a later QRInfo is
        // expected to supply.
        let partial_key = BlockHash::from_byte_array([0xCD; 32]);
        let complete_cycle: Vec<QualifiedQuorumEntry> = original_cycle.values().cloned().collect();
        let partial_cycle: BTreeMap<u16, QualifiedQuorumEntry> =
            original_cycle.iter().skip(1).map(|(index, q)| (*index, q.clone())).collect();
        engine.rotated_quorums_per_cycle.insert(partial_key, partial_cycle);
        engine
            .store_cycle_if_fully_verified(
                partial_key,
                complete_cycle.clone(),
                rotation_quorum_type,
            )
            .await
            .expect("gate must not error when completing a partial cycle");
        assert_eq!(
            engine.rotated_quorums_per_cycle.get(&partial_key).map(|cycle| cycle.len()),
            Some(complete_cycle.len()),
            "a complete cycle must complete a partially stored one"
        );

        // Completion only ever adds: a verified set smaller than what is
        // already stored must leave the indices it does not carry in place.
        let shrink_key = BlockHash::from_byte_array([0xEF; 32]);
        let stored_before: BTreeMap<u16, QualifiedQuorumEntry> =
            original_cycle.iter().skip(1).map(|(index, q)| (*index, q.clone())).collect();
        engine.rotated_quorums_per_cycle.insert(shrink_key, stored_before.clone());
        let single_entry =
            vec![stored_before.values().next().expect("partial cycle non-empty").clone()];
        engine
            .store_cycle_if_fully_verified(shrink_key, single_entry, rotation_quorum_type)
            .await
            .expect("gate must not error when merging a smaller verified set");
        assert_eq!(
            engine.rotated_quorums_per_cycle.get(&shrink_key),
            Some(&stored_before),
            "a smaller verified set must not shrink a larger stored cycle"
        );
    }

    /// The non-rotating quorums of the newest list still to validate ask for
    /// the list at their work block, oldest first, each from the nearest lower
    /// list the engine holds.
    #[tokio::test]
    async fn missing_work_block_list_requests_target_unverified_non_rotating_quorums() {
        use dashcore::sml::llmq_type::QUORUM_MEMBER_LIST_OFFSET;
        use std::sync::Arc;

        let work = |mined: CoreBlockHeight| mined - QUORUM_MEMBER_LIST_OFFSET;
        let tip = 2_000_000;
        // Mined heights of the quorums of the tip list.
        let first = 1_000_008;
        let second = 1_999_008;
        let held = 1_995_008;
        let verified = 1_999_108;
        let rotating = 1_999_208;
        let retired = 1_999_308;
        let no_work_block = 1_999_408;
        let not_in_chain = BlockHash::dummy(42);
        let older_list = 1_500_000;

        let blocks: Vec<_> = [
            first,
            work(first),
            second,
            work(second),
            held,
            work(held),
            // The skipped quorums' work blocks are known, so only their filter
            // leaves them out.
            verified,
            work(verified),
            rotating,
            work(rotating),
            retired,
            work(retired),
            no_work_block,
            older_list,
            tip,
        ]
        .into_iter()
        .map(|height| (height, BlockHash::dummy(height)))
        .collect();
        let mut engine = engine_knowing_blocks(&blocks);
        assert!(engine.missing_work_block_list_requests().await.is_empty(), "no list, no request");

        let quorum = |llmq_type, block_hash, verified| {
            let mut entry: QualifiedQuorumEntry = quorum_entry(llmq_type, block_hash, None).into();
            entry.verified = verified;
            entry
        };
        let unknown = LLMQEntryVerificationStatus::Unknown;
        let quorums = [
            quorum(LLMQType::Llmqtype400_60, BlockHash::dummy(second), unknown.clone()),
            quorum(LLMQType::Llmqtype400_60, BlockHash::dummy(first), unknown.clone()),
            quorum(LLMQType::Llmqtype400_60, BlockHash::dummy(held), unknown.clone()),
            quorum(LLMQType::Llmqtype400_60, not_in_chain, unknown.clone()),
            quorum(LLMQType::Llmqtype400_60, BlockHash::dummy(no_work_block), unknown.clone()),
            // Mined in the same block as a 400_60 quorum: one request for both.
            quorum(LLMQType::Llmqtype100_67, BlockHash::dummy(second), unknown.clone()),
            quorum(
                LLMQType::Llmqtype400_85,
                BlockHash::dummy(verified),
                LLMQEntryVerificationStatus::Verified,
            ),
            quorum(LLMQType::Llmqtype60_75, BlockHash::dummy(rotating), unknown.clone()),
            // Retired on mainnet at this height.
            quorum(LLMQType::Llmqtype50_60, BlockHash::dummy(retired), unknown),
        ];
        let mut quorum_map: BTreeMap<LLMQType, BTreeMap<QuorumHash, Arc<QualifiedQuorumEntry>>> =
            BTreeMap::new();
        for entry in quorums {
            quorum_map
                .entry(entry.quorum_entry.llmq_type)
                .or_default()
                .insert(entry.quorum_entry.quorum_hash, Arc::new(entry));
        }
        engine
            .masternode_lists
            .insert(older_list, MasternodeList::empty(BlockHash::dummy(older_list), older_list));
        engine
            .masternode_lists
            .insert(work(held), MasternodeList::empty(BlockHash::dummy(work(held)), work(held)));
        engine.masternode_lists.insert(
            tip,
            MasternodeList::build(BTreeMap::new(), quorum_map, BlockHash::dummy(tip), tip).build(),
        );

        assert_eq!(
            engine.missing_work_block_list_requests().await,
            vec![
                (BlockHash::all_zeros(), BlockHash::dummy(work(first))),
                (BlockHash::dummy(work(held)), BlockHash::dummy(work(second))),
            ],
            "a work block below every list starts from the empty list"
        );
    }
}
