use crate::hash_types::QuorumModifierHash;
use crate::network::message_qrinfo::MNSkipListMode;
use crate::prelude::CoreBlockHeight;
use crate::sml::llmq_type::LLMQParams;
use crate::sml::llmq_type::rotation::{LLMQQuarterReconstructionType, LLMQQuarterUsageType};
use crate::sml::masternode_list_engine::MasternodeListEngine;
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use crate::sml::quorum_entry::quorum_modifier_type::LLMQModifierType;
use crate::sml::quorum_validation_error::QuorumValidationError;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;

impl MasternodeListEngine {

    /// Determine masternodes which is responsible for signing at this quorum index
    pub(in crate::sml::masternode_list_engine) fn find_rotated_masternodes_for_quorum<'a>(
        &'a self,
        quorum: &'a QualifiedQuorumEntry,
        skip_removed_masternodes: bool,
    ) -> Result<Vec<&'a QualifiedMasternodeListEntry>, QuorumValidationError> {
        let Some(quorum_block_height) = self.block_heights.get(&quorum.quorum_entry.quorum_hash) else {
            return Err(QuorumValidationError::RequiredBlockNotPresent(quorum.quorum_entry.quorum_hash));
        };
        let llmq_params = quorum.quorum_entry.llmq_type.params();
        let quorum_index = quorum_block_height % llmq_params.dkg_params.interval;
        let cycle_base_height = quorum_block_height - quorum_index;
        // let Some(cycle_base_hash) = self.block_hashes.get(&cycle_base_height) else {
        //     return Err(QuorumValidationError::RequiredBlockHeightNotPresent(cycle_base_height));
        // };
        //let mut llmq_indexed_members : BTreeMap<LLMQIndexedHash, Vec<QualifiedMasternodeListEntry>> = BTreeMap::new();
        let rotated_members = self.masternode_list_entry_members_for_rotated_quorum(quorum, cycle_base_height, llmq_params, skip_removed_masternodes)?.into_iter().flatten().collect();

        Ok(rotated_members)
    }

    fn masternode_list_entry_members_for_rotated_quorum<'a>(
        &'a self,
        quorum: &'a QualifiedQuorumEntry,
        cycle_base_height: u32,
        llmq_params: LLMQParams,
        skip_removed_masternodes: bool,
    ) -> Result<Vec<Vec<&'a QualifiedMasternodeListEntry>>, QuorumValidationError> {
        let num_quorums = llmq_params.signing_active_quorum_count as usize;
        let cycle_length = llmq_params.dkg_params.interval;
        let work_block_height_for_index = |index: u32| (cycle_base_height - index * cycle_length) - 8;
        // Reconstruct quorum members at h - 3c from snapshot
        let q_h_m_3c = self.quorum_quarter_members_by_reconstruction_type(quorum, LLMQQuarterReconstructionType::Snapshot, &llmq_params, work_block_height_for_index(3))?;
        // Reconstruct quorum members at h - 2c from snapshot
        let q_h_m_2c = self.quorum_quarter_members_by_reconstruction_type(quorum, LLMQQuarterReconstructionType::Snapshot, &llmq_params, work_block_height_for_index(2))?;
        // Reconstruct quorum members at h - c from snapshot
        let q_h_m_c = self.quorum_quarter_members_by_reconstruction_type(quorum, LLMQQuarterReconstructionType::Snapshot, &llmq_params, work_block_height_for_index(1))?;
        // Determine quorum members at new index
        let reconstruction_type = LLMQQuarterReconstructionType::New { previous_quarters:  [&q_h_m_c, &q_h_m_2c, &q_h_m_3c], skip_removed_masternodes };
        let quarter_new = self.quorum_quarter_members_by_reconstruction_type(quorum, reconstruction_type, &llmq_params, work_block_height_for_index(0))?;
        let mut quorum_members =
            Vec::<Vec<&QualifiedMasternodeListEntry>>::with_capacity(num_quorums);
        (0..num_quorums).for_each(|index| {
            Self::add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_3c, index);
            Self::add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_2c, index);
            Self::add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_c, index);
            Self::add_quorum_members_from_quarter(&mut quorum_members, &quarter_new, index);
        });
        Ok(quorum_members)
    }

    fn add_quorum_members_from_quarter<'a>(
        quorum_members: &mut Vec<Vec<&'a QualifiedMasternodeListEntry>>,
        quarter: &[Vec<&'a QualifiedMasternodeListEntry>],
        index: usize,
    ) {
        if let Some(indexed_quarter) = quarter.get(index) {
            quorum_members.resize_with(index + 1, Vec::new);
            quorum_members[index].extend(indexed_quarter.iter().cloned());
        }
    }

    fn quorum_quarter_members_by_reconstruction_type<'a: 'b, 'b>(
        &'a self,
        quorum: &'a QualifiedQuorumEntry,
        reconstruction_type: LLMQQuarterReconstructionType<'a, 'b>,
        llmq_params: &LLMQParams,
        work_block_height: CoreBlockHeight,
    ) -> Result<Vec<Vec<&'a QualifiedMasternodeListEntry>>, QuorumValidationError> {
        let Some(work_block_hash) = self.block_hashes.get(&work_block_height) else {
            return Err(QuorumValidationError::RequiredBlockHeightNotPresent(work_block_height));
        };
        let masternode_list = self.masternode_lists.get(&work_block_height).ok_or(QuorumValidationError::RequiredMasternodeListNotPresent(work_block_height))?;

        let llmq_type = llmq_params.quorum_type;
        let quorum_count = llmq_params.signing_active_quorum_count as usize;
        let quorum_size = llmq_params.size as usize;
        let quarter_size = quorum_size / 4;
        let quorum_modifier_type = LLMQModifierType::new_quorum_modifier_type(llmq_type, *work_block_hash, work_block_height, &self.known_chain_locks, self.network)?;
        let quorum_modifier = quorum_modifier_type.build_llmq_hash();
        match reconstruction_type {
            LLMQQuarterReconstructionType::New { previous_quarters, skip_removed_masternodes } => {
                let (used_at_h_masternodes, unused_at_h_masternodes, used_at_h_indexed_masternodes) =
                    masternode_list.usage_info(previous_quarters, skip_removed_masternodes, quorum_count);
                Ok(Self::apply_skip_strategy_of_type(LLMQQuarterUsageType::New(used_at_h_indexed_masternodes), used_at_h_masternodes, unused_at_h_masternodes, quorum_modifier, quorum_count, quarter_size))
            },
            LLMQQuarterReconstructionType::Snapshot => {
                if let Some(snapshot) = self.known_snapshots.get(work_block_hash) {
                    let (used_at_h_masternodes, unused_at_h_masternodes) = masternode_list.used_and_unused_masternodes_for_quorum(quorum, quorum_modifier_type, snapshot, self.network);
                    Ok(Self::apply_skip_strategy_of_type(LLMQQuarterUsageType::Snapshot(snapshot.clone()), used_at_h_masternodes, unused_at_h_masternodes, quorum_modifier, quorum_count, quarter_size))
                } else {
                    Err(QuorumValidationError::RequiredSnapshotNotPresent(*work_block_hash))
                }
            }
        }
    }

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
            quorum_modifier, false);
        let sorted_unused_mns_list = MasternodeList::scores_for_quorum_for_masternodes(
            unused_at_h_masternodes,
            quorum_modifier, false);
        let sorted_combined_mns_list = Vec::from_iter(sorted_unused_mns_list.into_values().rev().chain(sorted_used_mns_list.into_values().rev()));
        match skip_type {
            LLMQQuarterUsageType::Snapshot(snapshot) => {
                match snapshot.skip_list_mode {
                    MNSkipListMode::NoSkipping => {
                        sorted_combined_mns_list
                            .chunks(quarter_size)
                            .map(|chunk| chunk.to_vec())
                            .collect()
                    }
                    MNSkipListMode::SkipFirst => {
                        let mut first_entry_index = 0;
                        let processed_skip_list = Vec::from_iter(snapshot.skip_list.into_iter().map(|s| if first_entry_index == 0 {
                            first_entry_index = s;
                            s
                        } else {
                            first_entry_index + s
                        }));
                        let mut idx = 0;
                        let mut skip_idx = 0;
                        (0..quorum_count).map(|_| {
                            let mut quarter = Vec::with_capacity(quarter_size);
                            while quarter.len() < quarter_size {
                                let index = (idx + 1) % sorted_combined_mns_list.len();
                                if skip_idx < processed_skip_list.len() && idx == processed_skip_list[skip_idx] as usize {
                                    skip_idx += 1;
                                } else {
                                    quarter.push(sorted_combined_mns_list[idx]);
                                }
                                idx = index
                            }
                            quarter
                        }).collect()
                    }
                    MNSkipListMode::SkipExcept => {
                        (0..quorum_count)
                            .map(|i| snapshot.skip_list
                                .iter()
                                .filter_map(|unskipped| sorted_combined_mns_list.get(*unskipped as usize))
                                .take(quarter_size)
                                .cloned()
                                .collect())
                            .collect()
                    }
                    MNSkipListMode::SkipAll => {
                        // TODO: do we need to impl smth in this strategy ?
                        // warn!("skip_mode SkipAll not supported yet");
                        vec![Vec::<&QualifiedMasternodeListEntry>::new(); quorum_count]
                    }
                }
            },
            LLMQQuarterUsageType::New(mut used_at_h_indexed_masternodes) => {
                let mut quarter_quorum_members = vec![Vec::<&QualifiedMasternodeListEntry>::new(); quorum_count];
                let mut skip_list = Vec::<i32>::new();
                let mut first_skipped_index = 0i32;
                let mut idx = 0i32;
                for i in 0..quorum_count {
                    let masternodes_used_at_h_indexed_at_i = used_at_h_indexed_masternodes.get_mut(i).unwrap();
                    let used_mns_count = masternodes_used_at_h_indexed_at_i.len();
                    let sorted_combined_mns_list_len = sorted_combined_mns_list.len();
                    let mut updated = false;
                    let initial_loop_idx = idx;
                    while quarter_quorum_members[i].len() < quarter_size &&
                        used_mns_count + quarter_quorum_members[i].len() < sorted_combined_mns_list_len {
                        let mn = sorted_combined_mns_list.get(idx as usize).unwrap();
                        // TODO: replace masternodes with smart pointers to avoid cloning
                        if masternodes_used_at_h_indexed_at_i.iter().any(|node| mn.masternode_list_entry.pro_reg_tx_hash == node.masternode_list_entry.pro_reg_tx_hash) {
                            let skip_index = idx - first_skipped_index;
                            if first_skipped_index == 0 {
                                first_skipped_index = idx;
                            }
                            skip_list.push(idx);
                        } else {
                            masternodes_used_at_h_indexed_at_i.push(mn);
                            quarter_quorum_members[i].push(mn);
                            updated = true;
                        }
                        idx += 1;
                        if idx == sorted_combined_mns_list_len as i32 {
                            idx = 0;
                        }
                        if idx == initial_loop_idx {
                            if !updated {
                                // warn!("there are not enough MNs then required for quarter size: ({})", quarter_size);
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
}