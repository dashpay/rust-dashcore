use crate::hash_types::QuorumModifierHash;
use crate::network::message_qrinfo::MNSkipListMode;
use crate::prelude::CoreBlockHeight;
use crate::sml::llmq_type::LLMQParams;
use crate::sml::llmq_type::rotation::{LLMQQuarterReconstructionType, LLMQQuarterUsageType};
use crate::sml::masternode_list_engine::MasternodeListEngine;
use crate::sml::masternode_list_entry::MasternodeListEntry;
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use crate::sml::quorum_entry::quorum_modifier_type::LLMQModifierType;
use crate::sml::quorum_validation_error::QuorumValidationError;

impl MasternodeListEngine {
    fn quorum_quarter_members_by_reconstruction_type(
        &self,
        reconstruction_type: LLMQQuarterReconstructionType,
        llmq_params: &LLMQParams,
        work_block_height: CoreBlockHeight,
    ) -> Result<Vec<Vec<MasternodeListEntry>>, QuorumValidationError> {
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
                Ok(apply_skip_strategy_of_type(LLMQQuarterUsageType::New(used_at_h_indexed_masternodes), used_at_h_masternodes, unused_at_h_masternodes, work_block_height, quorum_modifier, quorum_count, quarter_size))
            },
            LLMQQuarterReconstructionType::Snapshot => {
                if let Some(snapshot) = self.cache.maybe_snapshot(work_block_hash) {
                    let (used_at_h_masternodes, unused_at_h_masternodes) =
                        usage_info_from_snapshot(&masternode_list.masternodes, &snapshot, quorum_modifier, work_block_height);
                    Ok(apply_skip_strategy_of_type(LLMQQuarterUsageType::Snapshot(snapshot), used_at_h_masternodes, unused_at_h_masternodes, work_block_height, quorum_modifier, quorum_count, quarter_size))
                } else {
                    Err(CoreProviderError::NoSnapshot)
                }

                // self.provider.find_snapshot(work_block_hash, &self.cache)
                //     .map(|snapshot| {
                //         let (used_at_h_masternodes, unused_at_h_masternodes) =
                //             usage_info_from_snapshot(masternode_list, &snapshot, quorum_modifier, work_block_height);
                //         apply_skip_strategy_of_type(LLMQQuarterUsageType::Snapshot(snapshot), used_at_h_masternodes, unused_at_h_masternodes, work_block_height, quorum_modifier, quorum_count, quarter_size)
                //     })
            }
        }
    }
}

fn apply_skip_strategy_of_type(
    skip_type: LLMQQuarterUsageType,
    used_at_h_masternodes: Vec<QualifiedMasternodeListEntry>,
    unused_at_h_masternodes: Vec<QualifiedMasternodeListEntry>,
    work_block_height: u32,
    quorum_modifier: QuorumModifierHash,
    quorum_count: usize,
    quarter_size: usize,
) -> Vec<Vec<MasternodeListEntry>> {
    let sorted_used_mns_list = valid_masternodes_for_rotated_quorum_map(
        used_at_h_masternodes,
        quorum_modifier,
        work_block_height);
    let sorted_unused_mns_list = valid_masternodes_for_rotated_quorum_map(
        unused_at_h_masternodes,
        quorum_modifier,
        work_block_height);
    let sorted_combined_mns_list = Vec::from_iter(sorted_unused_mns_list.into_iter().chain(sorted_used_mns_list.into_iter()));
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
                                quarter.push(sorted_combined_mns_list[idx].clone());
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
                    vec![Vec::<MasternodeListEntry>::new(); quorum_count]
                }
            }
        },
        LLMQQuarterUsageType::New(mut used_at_h_indexed_masternodes) => {
            let mut quarter_quorum_members = vec![Vec::<MasternodeListEntry>::new(); quorum_count];
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
                    if masternodes_used_at_h_indexed_at_i.iter().any(|node| mn.provider_registration_transaction_hash == node.masternode_list_entry.pro_reg_tx_hash) {
                        let skip_index = idx - first_skipped_index;
                        if first_skipped_index == 0 {
                            first_skipped_index = idx;
                        }
                        skip_list.push(idx);
                    } else {
                        masternodes_used_at_h_indexed_at_i.push(mn.clone());
                        quarter_quorum_members[i].push(mn.clone());
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