use crate::sml_engine::{
    cycle_quarter_work_heights, rotated_cycle_base_height, MasternodeListEngine,
};
use crate::storage::BlockHeaderStorage;
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::hash_types::QuorumModifierHash;
use dashcore::network::message_qrinfo::{MNSkipListMode, QuorumSnapshot};
use dashcore::prelude::CoreBlockHeight;
use dashcore::sml::llmq_type::rotation::{LLMQQuarterReconstructionType, LLMQQuarterUsageType};
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use dashcore::sml::quorum_entry::qualified_quorum_entry::{
    QualifiedQuorumEntry, VerifyingChainLockSignaturesType,
};
use dashcore::sml::quorum_entry::quorum_modifier_type::LLMQModifierType;
use dashcore::sml::quorum_validation_error::QuorumValidationError;
use dashcore::BlockHash;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

impl<H: BlockHeaderStorage> MasternodeListEngine<H> {
    /// The members of each rotated quorum, in order, each with its own result
    /// so one that cannot be resolved does not fail the others. The older
    /// quarters come from the QRInfo's `snapshots` by work block hash.
    pub(super) async fn find_rotated_masternodes_for_quorums<'a>(
        &'a self,
        quorums: &[&'a QualifiedQuorumEntry],
        snapshots: &BTreeMap<BlockHash, QuorumSnapshot>,
    ) -> Vec<Result<Vec<&'a QualifiedMasternodeListEntry>, QuorumValidationError>> {
        // Quorums of a cycle share its reconstruction. Only a successful one is
        // cached: a quorum without signatures must not fail its siblings.
        let mut cycles: BTreeMap<CoreBlockHeight, Vec<Vec<&QualifiedMasternodeListEntry>>> =
            BTreeMap::new();
        let mut members = Vec::with_capacity(quorums.len());
        for quorum in quorums {
            let quorum_hash = quorum.quorum_entry.quorum_hash;
            let invalid_index = |index| QuorumValidationError::InvalidQuorumIndex {
                quorum_hash,
                index,
            };
            let Some(height) = self.height_of(&quorum_hash).await else {
                members.push(Err(QuorumValidationError::RequiredBlockNotPresent(
                    quorum_hash,
                    "rotated quorum height".to_string(),
                )));
                continue;
            };
            let Some(quorum_index) = quorum.quorum_entry.quorum_index else {
                members
                    .push(Err(QuorumValidationError::RequiredQuorumIndexNotPresent(quorum_hash)));
                continue;
            };
            let Some(cycle_base) = rotated_cycle_base_height(&quorum.quorum_entry, height) else {
                members.push(Err(invalid_index(quorum_index)));
                continue;
            };
            let members_by_index = match cycles.entry(cycle_base) {
                Entry::Occupied(cached) => cached.into_mut(),
                Entry::Vacant(slot) => {
                    let Some(VerifyingChainLockSignaturesType::Rotating(sigs)) =
                        quorum.verifying_chain_lock_signature
                    else {
                        members.push(Err(
                            QuorumValidationError::RequiredRotatedChainLockSigsNotPresent(
                                quorum_hash,
                            ),
                        ));
                        continue;
                    };
                    match self.rotated_cycle_members(
                        quorum.quorum_entry.llmq_type,
                        cycle_base,
                        sigs,
                        snapshots,
                    ) {
                        Ok(members_by_index) => slot.insert(members_by_index),
                        Err(e) => {
                            members.push(Err(e));
                            continue;
                        }
                    }
                }
            };
            members.push(
                members_by_index
                    .get(quorum_index as usize)
                    .cloned()
                    .ok_or(invalid_index(quorum_index)),
            );
        }
        members
    }

    /// The members of every quorum of the cycle based at `cycle_base`, by
    /// quorum index: three quarters rebuilt from snapshots, the newest from
    /// the masternodes they left unused.
    fn rotated_cycle_members(
        &self,
        llmq_type: LLMQType,
        cycle_base: CoreBlockHeight,
        sigs: [BLSSignature; 4],
        snapshots: &BTreeMap<BlockHash, QuorumSnapshot>,
    ) -> Result<Vec<Vec<&QualifiedMasternodeListEntry>>, QuorumValidationError> {
        let params = llmq_type.params();
        let [h_3c, h_2c, h_c, h] =
            cycle_quarter_work_heights(cycle_base, params.dkg_params.interval).map(|height| {
                height.ok_or(QuorumValidationError::CycleBaseHeightTooLow(cycle_base))
            });
        let snapshot_quarter = |height, sig| {
            self.quarter_members(
                llmq_type,
                LLMQQuarterReconstructionType::Snapshot,
                height,
                sig,
                snapshots,
            )
        };
        let q_3c = snapshot_quarter(h_3c?, sigs[0])?;
        let q_2c = snapshot_quarter(h_2c?, sigs[1])?;
        let q_c = snapshot_quarter(h_c?, sigs[2])?;
        let q_h = self.quarter_members(
            llmq_type,
            LLMQQuarterReconstructionType::New {
                previous_quarters: [&q_c, &q_2c, &q_3c],
            },
            h?,
            sigs[3],
            snapshots,
        )?;

        let quorum_count = params.signing_active_quorum_count as usize;
        let mut members: Vec<Vec<&QualifiedMasternodeListEntry>> = vec![Vec::new(); quorum_count];
        for (index, quorum_members) in members.iter_mut().enumerate() {
            for quarter in [&q_3c, &q_2c, &q_c, &q_h] {
                quorum_members.extend(quarter.get(index).into_iter().flatten());
            }
        }
        Ok(members)
    }

    /// One quarter's members by quorum index, from the list at
    /// `work_block_height` and that work block's ChainLock signature.
    fn quarter_members<'a: 'b, 'b>(
        &'a self,
        llmq_type: LLMQType,
        reconstruction_type: LLMQQuarterReconstructionType<'a, 'b>,
        work_block_height: CoreBlockHeight,
        work_block_sig: BLSSignature,
        snapshots: &BTreeMap<BlockHash, QuorumSnapshot>,
    ) -> Result<Vec<Vec<&'a QualifiedMasternodeListEntry>>, QuorumValidationError> {
        let params = llmq_type.params();
        let masternode_list = self
            .masternode_lists
            .get(&work_block_height)
            .ok_or(QuorumValidationError::RequiredMasternodeListNotPresent(work_block_height))?;
        let work_block_hash = masternode_list.block_hash;
        let quorum_count = params.signing_active_quorum_count as usize;
        let quarter_size = params.size as usize / 4;
        let quorum_modifier_type = LLMQModifierType::new_quorum_modifier_type(
            llmq_type,
            work_block_hash,
            work_block_height,
            work_block_sig,
            self.network,
        )?;
        let quorum_modifier = quorum_modifier_type.build_llmq_hash();
        let (usage, used, unused) = match reconstruction_type {
            LLMQQuarterReconstructionType::New {
                previous_quarters,
            } => {
                let (used, unused, used_by_index) =
                    masternode_list.usage_info(previous_quarters, quorum_count);
                (LLMQQuarterUsageType::New(used_by_index), used, unused)
            }
            LLMQQuarterReconstructionType::Snapshot => {
                let snapshot = snapshots
                    .get(&work_block_hash)
                    .ok_or(QuorumValidationError::RequiredSnapshotNotPresent(work_block_hash))?;
                let (used, unused) = masternode_list.used_and_unused_masternodes_for_quorum(
                    llmq_type,
                    quorum_modifier_type,
                    snapshot,
                    self.network,
                );
                (LLMQQuarterUsageType::Snapshot(snapshot.clone()), used, unused)
            }
        };
        Ok(apply_skip_strategy_of_type(
            usage,
            used,
            unused,
            quorum_modifier,
            quorum_count,
            quarter_size,
        ))
    }
}

/// A quarter's members by quorum index: the masternodes sorted by score,
/// unused ones first, picked by the snapshot's skip list or, for the newest
/// quarter, skipping those each quorum already has.
fn apply_skip_strategy_of_type<'a>(
    skip_type: LLMQQuarterUsageType,
    used_at_h_masternodes: Vec<&'a QualifiedMasternodeListEntry>,
    unused_at_h_masternodes: Vec<&'a QualifiedMasternodeListEntry>,
    quorum_modifier: QuorumModifierHash,
    quorum_count: usize,
    quarter_size: usize,
) -> Vec<Vec<&'a QualifiedMasternodeListEntry>> {
    let sorted_used_mns_list = MasternodeList::scores_for_quorum_for_masternodes(
        used_at_h_masternodes,
        quorum_modifier,
        false,
    );
    let sorted_unused_mns_list = MasternodeList::scores_for_quorum_for_masternodes(
        unused_at_h_masternodes,
        quorum_modifier,
        false,
    );
    let sorted_combined_mns_list = Vec::from_iter(
        sorted_unused_mns_list.into_values().rev().chain(sorted_used_mns_list.into_values().rev()),
    );
    if sorted_combined_mns_list.is_empty() {
        return vec![Vec::new(); quorum_count];
    }
    match skip_type {
        LLMQQuarterUsageType::Snapshot(snapshot) => {
            match snapshot.skip_list_mode {
                // One cursor fills every quarter, wrapping around.
                MNSkipListMode::NoSkipping => {
                    let mut combined = sorted_combined_mns_list.iter().cycle();
                    (0..quorum_count)
                        .map(|_| (&mut combined).take(quarter_size).copied().collect())
                        .collect()
                }
                MNSkipListMode::SkipFirst => {
                    let mut first_entry_index = 0;
                    let processed_skip_list =
                        Vec::from_iter(snapshot.skip_list.into_iter().map(|s| {
                            if first_entry_index == 0 {
                                first_entry_index = s;
                                s
                            } else {
                                first_entry_index + s
                            }
                        }));
                    let mut idx = 0;
                    let mut skip_idx = 0;
                    (0..quorum_count)
                        .map(|_| {
                            let mut quarter = Vec::with_capacity(quarter_size);
                            while quarter.len() < quarter_size {
                                let index = (idx + 1) % sorted_combined_mns_list.len();
                                if skip_idx < processed_skip_list.len()
                                    && idx == processed_skip_list[skip_idx] as usize
                                {
                                    skip_idx += 1;
                                } else {
                                    quarter.push(sorted_combined_mns_list[idx]);
                                }
                                idx = index
                            }
                            quarter
                        })
                        .collect()
                }
                MNSkipListMode::SkipExcept => (0..quorum_count)
                    .map(|_| {
                        snapshot
                            .skip_list
                            .iter()
                            .filter_map(|not_skipped| {
                                sorted_combined_mns_list.get(*not_skipped as usize)
                            })
                            .take(quarter_size)
                            .copied()
                            .collect()
                    })
                    .collect(),
                MNSkipListMode::SkipAll => vec![Vec::new(); quorum_count],
            }
        }
        LLMQQuarterUsageType::New(mut used_indexed_masternodes) => {
            let mut quarter_quorum_members = vec![Vec::new(); quorum_count];
            let mut idx = 0u32;
            for i in 0..quorum_count {
                let masternodes_used_at_h_indexed_at_i = used_indexed_masternodes
                    .get_mut(i)
                    .expect("expected to get index i quorum used indexed masternodes");
                let used_mns_count = masternodes_used_at_h_indexed_at_i.len();
                let sorted_combined_mns_list_len = sorted_combined_mns_list.len();
                let mut updated = false;
                let initial_loop_idx = idx;
                while quarter_quorum_members[i].len() < quarter_size
                    && used_mns_count + quarter_quorum_members[i].len()
                        < sorted_combined_mns_list_len
                {
                    let mn = sorted_combined_mns_list[idx as usize];
                    if !masternodes_used_at_h_indexed_at_i.iter().any(|node| {
                        mn.masternode_list_entry.pro_reg_tx_hash
                            == node.masternode_list_entry.pro_reg_tx_hash
                    }) {
                        masternodes_used_at_h_indexed_at_i.push(mn);
                        quarter_quorum_members[i].push(mn);
                        updated = true;
                    }
                    idx += 1;
                    if idx == sorted_combined_mns_list_len as u32 {
                        idx = 0;
                    }
                    if idx == initial_loop_idx {
                        if !updated {
                            return quarter_quorum_members;
                        }
                        updated = false;
                    }
                }
            }
            quarter_quorum_members
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use dashcore::hashes::Hash;

    use super::*;
    use crate::sml_engine::test_support::{quorum_entry, TestEngine};
    use dashcore::bls_sig_utils::BLSPublicKey;
    use dashcore::hash_types::ConfirmedHash;
    use dashcore::network::message_qrinfo::QuorumSnapshot;
    use dashcore::sml::masternode_list_entry::{
        EntryMasternodeType, MasternodeListEntry, MasternodeNetInfo,
    };
    use dashcore::Network;
    use dashcore::{ProTxHash, PubkeyHash, QuorumHash};

    fn entry(byte: u8) -> QualifiedMasternodeListEntry {
        MasternodeListEntry {
            version: 2,
            pro_reg_tx_hash: ProTxHash::from_byte_array([byte; 32]),
            confirmed_hash: Some(ConfirmedHash::from_byte_array([byte; 32])),
            service_address: MasternodeNetInfo::Legacy(SocketAddr::from(([127, 0, 0, 1], 9999))),
            operator_public_key: BLSPublicKey::from([byte; 48]),
            key_id_voting: PubkeyHash::from_byte_array([byte; 20]),
            is_valid: true,
            mn_type: EntryMasternodeType::Regular,
        }
        .into()
    }

    /// Entries in the score order `apply_skip_strategy_of_type` sees them:
    /// descending scores under the given modifier, matching the combined
    /// unused-then-used list for an all-unused input.
    fn score_sorted(
        entries: &[QualifiedMasternodeListEntry],
        modifier: QuorumModifierHash,
    ) -> Vec<&QualifiedMasternodeListEntry> {
        MasternodeList::scores_for_quorum_for_masternodes(entries.iter(), modifier, false)
            .into_values()
            .rev()
            .collect()
    }

    fn snapshot(mode: MNSkipListMode, skip_list: Vec<i32>) -> QuorumSnapshot {
        QuorumSnapshot {
            skip_list_mode: mode,
            active_quorum_members: vec![],
            skip_list,
        }
    }

    fn pro_reg_tx_hashes(quarter: &[&QualifiedMasternodeListEntry]) -> Vec<ProTxHash> {
        quarter.iter().map(|entry| entry.masternode_list_entry.pro_reg_tx_hash).collect()
    }

    fn rotated_quorum(quorum_hash: QuorumHash, quorum_index: i16) -> QualifiedQuorumEntry {
        quorum_entry(LLMQType::Llmqtype60_75, quorum_hash, Some(quorum_index)).into()
    }

    #[tokio::test]
    async fn unusable_quorum_index_is_rejected_instead_of_underflowing_the_cycle_base() {
        let mut engine = TestEngine::empty(Network::Mainnet);
        let negative_index_hash = QuorumHash::from_byte_array([1; 32]);
        let index_above_height_hash = QuorumHash::from_byte_array([2; 32]);
        engine.feed_block_height(1000, negative_index_hash);
        engine.feed_block_height(3, index_above_height_hash);

        let quorums =
            [rotated_quorum(negative_index_hash, -1), rotated_quorum(index_above_height_hash, 5)];
        let borrowed: Vec<&QualifiedQuorumEntry> = quorums.iter().collect();
        let results =
            engine.find_rotated_masternodes_for_quorums(&borrowed, &BTreeMap::new()).await;
        assert_eq!(results.len(), 2);
        for result in &results {
            assert!(
                matches!(result, Err(QuorumValidationError::InvalidQuorumIndex { .. })),
                "expected an invalid index error, got {result:?}"
            );
        }
    }

    /// Every quorum of a cycle resolves the member sets from its own quarter
    /// signatures, and one that carries none cannot stand in for the cycle.
    /// Caching its failure would leave every sibling unverifiable on a
    /// commitment the sibling itself has everything to verify.
    #[tokio::test]
    async fn a_quorum_without_rotating_signatures_leaves_its_cycle_open() {
        let mut engine = TestEngine::empty(Network::Mainnet);
        let cycle_base = LLMQType::Llmqtype60_75.params().dkg_params.interval * 100;
        let without_sigs_hash = QuorumHash::from_byte_array([1; 32]);
        let with_sigs_hash = QuorumHash::from_byte_array([2; 32]);
        engine.feed_block_height(cycle_base, without_sigs_hash);
        engine.feed_block_height(cycle_base + 1, with_sigs_hash);

        let mut with_sigs = rotated_quorum(with_sigs_hash, 1);
        with_sigs.verifying_chain_lock_signature =
            Some(VerifyingChainLockSignaturesType::Rotating([BLSSignature::from([1; 96]); 4]));
        let quorums = [rotated_quorum(without_sigs_hash, 0), with_sigs];
        let borrowed: Vec<&QualifiedQuorumEntry> = quorums.iter().collect();

        let results =
            engine.find_rotated_masternodes_for_quorums(&borrowed, &BTreeMap::new()).await;
        assert!(
            matches!(
                results[0],
                Err(QuorumValidationError::RequiredRotatedChainLockSigsNotPresent(_))
            ),
            "a quorum without signatures must fail on its own account, got {:?}",
            results[0]
        );
        assert!(
            matches!(results[1], Err(QuorumValidationError::RequiredMasternodeListNotPresent(_))),
            "a sibling carrying signatures must reach the reconstruction, got {:?}",
            results[1]
        );
    }

    #[test]
    fn no_skipping_fills_quarters_with_circular_wrap_around() {
        let entries: Vec<QualifiedMasternodeListEntry> = (1..=6).map(entry).collect();
        let modifier = QuorumModifierHash::from_byte_array([9; 32]);
        let sorted = score_sorted(&entries, modifier);

        let quarters = apply_skip_strategy_of_type(
            LLMQQuarterUsageType::Snapshot(snapshot(MNSkipListMode::NoSkipping, vec![])),
            vec![],
            entries.iter().collect(),
            modifier,
            3,
            4,
        );

        assert_eq!(quarters.len(), 3);
        let expected: Vec<Vec<ProTxHash>> = vec![
            pro_reg_tx_hashes(&[sorted[0], sorted[1], sorted[2], sorted[3]]),
            pro_reg_tx_hashes(&[sorted[4], sorted[5], sorted[0], sorted[1]]),
            pro_reg_tx_hashes(&[sorted[2], sorted[3], sorted[4], sorted[5]]),
        ];
        let actual: Vec<Vec<ProTxHash>> =
            quarters.iter().map(|quarter| pro_reg_tx_hashes(quarter)).collect();
        assert_eq!(actual, expected, "one shared cursor must wrap around the combined list");
    }

    #[test]
    fn empty_masternode_list_yields_empty_quarters_for_every_mode() {
        let modifier = QuorumModifierHash::from_byte_array([9; 32]);
        for mode in [
            MNSkipListMode::NoSkipping,
            MNSkipListMode::SkipFirst,
            MNSkipListMode::SkipExcept,
            MNSkipListMode::SkipAll,
        ] {
            let quarters = apply_skip_strategy_of_type(
                LLMQQuarterUsageType::Snapshot(snapshot(mode, vec![])),
                vec![],
                vec![],
                modifier,
                4,
                2,
            );
            assert_eq!(quarters.len(), 4);
            assert!(
                quarters.iter().all(Vec::is_empty),
                "empty input must yield empty quarters in mode {:?}",
                mode
            );
        }
    }

    #[test]
    fn skip_first_decodes_relative_skip_list_entries() {
        let entries: Vec<QualifiedMasternodeListEntry> = (1..=8).map(entry).collect();
        let modifier = QuorumModifierHash::from_byte_array([9; 32]);
        let sorted = score_sorted(&entries, modifier);

        // The first skip entry is an absolute index. Every later entry is an
        // offset from that first skipped index, not from the preceding one, so
        // [3, 2, 3] skips absolute indexes 3, 5 and 6, which leaves the second
        // quarter one short and wraps it back to the front for its last member.
        // Reading the offsets cumulatively instead would skip 3, 5 and 8,
        // keeping index 6 and never reaching the wrap.
        let quarters = apply_skip_strategy_of_type(
            LLMQQuarterUsageType::Snapshot(snapshot(MNSkipListMode::SkipFirst, vec![3, 2, 3])),
            vec![],
            entries.iter().collect(),
            modifier,
            2,
            3,
        );

        let expected: Vec<Vec<ProTxHash>> = vec![
            pro_reg_tx_hashes(&[sorted[0], sorted[1], sorted[2]]),
            pro_reg_tx_hashes(&[sorted[4], sorted[7], sorted[0]]),
        ];
        let actual: Vec<Vec<ProTxHash>> =
            quarters.iter().map(|quarter| pro_reg_tx_hashes(quarter)).collect();
        assert_eq!(actual, expected, "skipped indexes must be excluded from quarter fill");
    }
}
