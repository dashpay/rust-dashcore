use std::collections::{BTreeMap, BTreeSet};

use crate::QuorumHash;
use crate::hash_types::QuorumModifierHash;
use crate::network::message_qrinfo::{MNSkipListMode, QRInfo};
use crate::prelude::CoreBlockHeight;
use crate::sml::llmq_type::LLMQType;
use crate::sml::llmq_type::rotation::{LLMQQuarterReconstructionType, LLMQQuarterUsageType};
use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list_engine::MasternodeListEngine;
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::sml::quorum_entry::quorum_modifier_type::LLMQModifierType;
use crate::sml::quorum_validation_error::QuorumValidationError;

impl MasternodeListEngine {
    /// Determines which masternodes are responsible for signing at the given quorum index.
    ///
    /// # Arguments
    ///
    /// * `quorum` - A reference to the `QualifiedQuorumEntry` for which the rotated masternodes are being determined.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<&QualifiedMasternodeListEntry>)` - A list of masternodes responsible for signing at the given quorum index.
    /// * `Err(QuorumValidationError)` - If the required block height is not present in the engine.
    pub(in crate::sml::masternode_list_engine) fn find_rotated_masternodes_for_quorum<'a>(
        &'a self,
        quorum: &'a QualifiedQuorumEntry,
    ) -> Result<Vec<&'a QualifiedMasternodeListEntry>, QuorumValidationError> {
        let Some(quorum_block_height) = self.block_heights.get(&quorum.quorum_entry.quorum_hash)
        else {
            return Err(QuorumValidationError::RequiredBlockNotPresent(
                quorum.quorum_entry.quorum_hash,
            ));
        };
        let llmq_type = quorum.quorum_entry.llmq_type;
        let Some(quorum_index) = quorum.quorum_entry.quorum_index else {
            return Err(QuorumValidationError::RequiredQuorumIndexNotPresent(
                quorum.quorum_entry.quorum_hash,
            ));
        };
        let cycle_base_height = quorum_block_height - quorum_index as u32;
        let rotated_members = self
            .masternode_list_entry_members_for_rotated_quorum(llmq_type, cycle_base_height)?
            .get(quorum_index as usize)
            .ok_or(QuorumValidationError::CorruptedCodeExecution(format!(
                "expected masternode list entry members for {}",
                quorum_index
            )))?
            .clone();

        Ok(rotated_members)
    }

    pub(in crate::sml::masternode_list_engine) fn find_rotated_masternodes_for_quorums<'a>(
        &'a self,
        quorums: &'a [&'a QualifiedQuorumEntry],
    ) -> Result<BTreeMap<QuorumHash, Vec<&'a QualifiedMasternodeListEntry>>, QuorumValidationError>
    {
        let mut return_btree_map = BTreeMap::new();
        let mut cycles: BTreeMap<CoreBlockHeight, Vec<Vec<&QualifiedMasternodeListEntry>>> =
            BTreeMap::new();
        for quorum in quorums {
            let Some(quorum_block_height) =
                self.block_heights.get(&quorum.quorum_entry.quorum_hash)
            else {
                return Err(QuorumValidationError::RequiredBlockNotPresent(
                    quorum.quorum_entry.quorum_hash,
                ));
            };
            let llmq_type = quorum.quorum_entry.llmq_type;
            let Some(quorum_index) = quorum.quorum_entry.quorum_index else {
                return Err(QuorumValidationError::RequiredQuorumIndexNotPresent(
                    quorum.quorum_entry.quorum_hash,
                ));
            };
            let cycle_base_height = quorum_block_height - quorum_index as u32;
            // Check if we already have the masternode list entries for this cycle base height
            let masternode_list_entries_by_index =
                if let Some(entries) = cycles.get(&cycle_base_height) {
                    entries
                } else {
                    // Fetch the masternode list entries
                    let new_entries = self.masternode_list_entry_members_for_rotated_quorum(
                        llmq_type,
                        cycle_base_height,
                    )?;
                    cycles.insert(cycle_base_height, new_entries);
                    cycles.get(&cycle_base_height).expect("Entry must exist")
                };

            let masternode_list_entries = masternode_list_entries_by_index
                .get(quorum_index as usize)
                .ok_or(QuorumValidationError::CorruptedCodeExecution(format!(
                    "expected masternode list entry members for {}",
                    quorum_index
                )))?
                .clone();
            return_btree_map.insert(quorum.quorum_entry.quorum_hash, masternode_list_entries);
        }

        Ok(return_btree_map)
    }

    /// Determines the required block heights for ChainLock signatures based on the provided `QRInfo`.
    ///
    /// # Arguments
    ///
    /// * `qr_info` - A reference to the `QRInfo` structure containing last commitments per index.
    ///
    /// # Returns
    ///
    /// * `Ok(BTreeSet<u32>)` - A set of block heights where ChainLock signatures are required.
    /// * `Err(QuorumValidationError)` - If a required block height is not present in the engine.
    pub fn required_cl_sig_heights(
        &self,
        qr_info: &QRInfo,
    ) -> Result<BTreeSet<u32>, QuorumValidationError> {
        let mut required_heights = BTreeSet::new();
        for quorum in &qr_info.last_commitment_per_index {
            let Some(quorum_block_height) = self.block_heights.get(&quorum.quorum_hash) else {
                return Err(QuorumValidationError::RequiredBlockNotPresent(quorum.quorum_hash));
            };
            let llmq_params = quorum.llmq_type.params();
            let quorum_index = quorum_block_height % llmq_params.dkg_params.interval;
            let cycle_base_height = quorum_block_height - quorum_index;
            let cycle_length = llmq_params.dkg_params.interval;
            for i in 0..=3 {
                required_heights.insert(cycle_base_height - i * cycle_length - 8);
            }
        }
        // We are going to validate the previous rotation as well
        if qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c.is_some() {
            for quorum in &qr_info.mn_list_diff_h.new_quorums {
                if quorum.llmq_type.is_rotating_quorum_type() {
                    let Some(quorum_block_height) = self.block_heights.get(&quorum.quorum_hash) else {
                        return Err(QuorumValidationError::RequiredBlockNotPresent(quorum.quorum_hash));
                    };
                    let llmq_params = quorum.llmq_type.params();
                    let quorum_index = quorum_block_height % llmq_params.dkg_params.interval;
                    let cycle_base_height = quorum_block_height - quorum_index;
                    let cycle_length = llmq_params.dkg_params.interval;
                    for i in 0..=3 {
                        required_heights.insert(cycle_base_height - i * cycle_length - 8);
                    }
                }
            }
        }
        Ok(required_heights)
    }

    /// Retrieves the masternode list members responsible for a rotated quorum at the given cycle base height.
    ///
    /// # Arguments
    ///
    /// * `quorum_llmq_type` - The LLMQ type for which the members are being retrieved.
    /// * `cycle_base_height` - The block height at which the cycle starts.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Vec<&QualifiedMasternodeListEntry>>)` - A list of quorum members, grouped by quorum index.
    /// * `Err(QuorumValidationError)` - If required snapshots or quorum reconstructions fail.
    fn masternode_list_entry_members_for_rotated_quorum(
        &self,
        quorum_llmq_type: LLMQType,
        cycle_base_height: u32,
    ) -> Result<Vec<Vec<&QualifiedMasternodeListEntry>>, QuorumValidationError> {
        let llmq_params = quorum_llmq_type.params();
        let num_quorums = llmq_params.signing_active_quorum_count as usize;
        let cycle_length = llmq_params.dkg_params.interval;
        let work_block_height_for_index =
            |index: u32| (cycle_base_height - index * cycle_length) - 8;
        // Reconstruct quorum members at h - 3c from snapshot
        let q_h_m_3c = self.quorum_quarter_members_by_reconstruction_type(
            quorum_llmq_type,
            LLMQQuarterReconstructionType::Snapshot,
            work_block_height_for_index(3),
        )?;
        // Reconstruct quorum members at h - 2c from snapshot
        let q_h_m_2c = self.quorum_quarter_members_by_reconstruction_type(
            quorum_llmq_type,
            LLMQQuarterReconstructionType::Snapshot,
            work_block_height_for_index(2),
        )?;
        // Reconstruct quorum members at h - c from snapshot
        let q_h_m_c = self.quorum_quarter_members_by_reconstruction_type(
            quorum_llmq_type,
            LLMQQuarterReconstructionType::Snapshot,
            work_block_height_for_index(1),
        )?;
        // Determine quorum members at new index
        let reconstruction_type = LLMQQuarterReconstructionType::New {
            previous_quarters: [&q_h_m_c, &q_h_m_2c, &q_h_m_3c],
        };
        let last_quarter = self.quorum_quarter_members_by_reconstruction_type(
            quorum_llmq_type,
            reconstruction_type,
            work_block_height_for_index(0),
        )?;
        let mut quorum_members =
            Vec::<Vec<&QualifiedMasternodeListEntry>>::with_capacity(num_quorums);

        (0..num_quorums).for_each(|index| {
            // println!("quarter 0 (-3c):");
            Self::add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_3c, index);
            // println!("quarter 1 (-2c):");
            Self::add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_2c, index);
            // println!("quarter 2 (-c):");
            Self::add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_c, index);
            // println!("quarter 3:");
            Self::add_quorum_members_from_quarter(&mut quorum_members, &last_quarter, index);
        });
        Ok(quorum_members)
    }

    /// Adds members from a specific quarter to the quorum member list.
    ///
    /// # Arguments
    ///
    /// * `quorum_members` - A mutable reference to a list of quorum members.
    /// * `quarter` - A reference to the quarter from which members are being added.
    /// * `index` - The quorum index at which members should be added.
    fn add_quorum_members_from_quarter<'a>(
        quorum_members: &mut Vec<Vec<&'a QualifiedMasternodeListEntry>>,
        quarter: &[Vec<&'a QualifiedMasternodeListEntry>],
        index: usize,
    ) {
        if let Some(indexed_quarter) = quarter.get(index) {
            quorum_members.resize_with(index + 1, Vec::new);
            quorum_members[index].extend(indexed_quarter);
        }
    }

    /// Retrieves the quorum quarter members based on the specified reconstruction type.
    ///
    /// # Arguments
    ///
    /// * `quorum_llmq_type` - The LLMQ type for which the members are being reconstructed.
    /// * `reconstruction_type` - The method of reconstruction (from snapshots or previous quarters).
    /// * `work_block_height` - The block height used for reconstruction.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Vec<&QualifiedMasternodeListEntry>>)` - A list of quorum members by quorum index.
    /// * `Err(QuorumValidationError)` - If required block heights, masternode lists, or snapshots are missing.
    fn quorum_quarter_members_by_reconstruction_type<'a: 'b, 'b>(
        &'a self,
        quorum_llmq_type: LLMQType,
        reconstruction_type: LLMQQuarterReconstructionType<'a, 'b>,
        work_block_height: CoreBlockHeight,
    ) -> Result<Vec<Vec<&'a QualifiedMasternodeListEntry>>, QuorumValidationError> {
        let llmq_params = quorum_llmq_type.params();
        let Some(work_block_hash) = self.block_hashes.get(&work_block_height) else {
            return Err(QuorumValidationError::RequiredBlockHeightNotPresent(work_block_height));
        };
        let masternode_list = self
            .masternode_lists
            .get(&work_block_height)
            .ok_or(QuorumValidationError::RequiredMasternodeListNotPresent(work_block_height))?;

        let llmq_type = llmq_params.quorum_type;
        let quorum_count = llmq_params.signing_active_quorum_count as usize;
        let quorum_size = llmq_params.size as usize;
        let quarter_size = quorum_size / 4;
        let quorum_modifier_type = LLMQModifierType::new_quorum_modifier_type(
            llmq_type,
            *work_block_hash,
            work_block_height,
            &self.known_chain_locks,
            self.network,
        )?;
        let quorum_modifier = quorum_modifier_type.build_llmq_hash();
        // println!("quorum modifier is {}", quorum_modifier);
        // println!("work block height is {}", work_block_height);
        // println!("work block hash is {}", work_block_hash);
        match reconstruction_type {
            LLMQQuarterReconstructionType::New { previous_quarters } => {
                let (used_masternodes, unused_masternodes, used_indexed_masternodes) =
                    masternode_list.usage_info(previous_quarters, quorum_count);
                Ok(Self::apply_skip_strategy_of_type(
                    LLMQQuarterUsageType::New(used_indexed_masternodes),
                    used_masternodes,
                    unused_masternodes,
                    quorum_modifier,
                    quorum_count,
                    quarter_size,
                ))
            }
            LLMQQuarterReconstructionType::Snapshot => {
                if let Some(snapshot) = self.known_snapshots.get(work_block_hash) {
                    let (used_masternodes, unused_masternodes) = masternode_list
                        .used_and_unused_masternodes_for_quorum(
                            quorum_llmq_type,
                            quorum_modifier_type,
                            snapshot,
                            self.network,
                        );
                    Ok(Self::apply_skip_strategy_of_type(
                        LLMQQuarterUsageType::Snapshot(snapshot.clone()),
                        used_masternodes,
                        unused_masternodes,
                        quorum_modifier,
                        quorum_count,
                        quarter_size,
                    ))
                } else {
                    Err(QuorumValidationError::RequiredSnapshotNotPresent(*work_block_hash))
                }
            }
        }
    }

    /// Applies the quorum skipping strategy based on the specified type.
    ///
    /// # Arguments
    ///
    /// * `skip_type` - The type of skipping strategy (snapshot-based or new quarter-based).
    /// * `used_at_h_masternodes` - Masternodes that were used in the quorum at height `h`.
    /// * `unused_at_h_masternodes` - Masternodes that were not used in the quorum at height `h`.
    /// * `quorum_modifier` - A unique hash that modifies quorum selection.
    /// * `quorum_count` - The number of quorums.
    /// * `quarter_size` - The size of each quarter.
    ///
    /// # Returns
    ///
    /// * `Vec<Vec<&QualifiedMasternodeListEntry>>` - The final list of quorum members by index.
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
        // if matches!(skip_type, LLMQQuarterUsageType::New(_)) {
        //     let used_masternodes_string = sorted_used_mns_list.values().rev().map(|m| m.masternode_list_entry.pro_reg_tx_hash.reverse().to_string().split_at(4).0.to_string()).collect::<Vec<_>>().join("|");
        //     let unused_masternodes_string = sorted_unused_mns_list.values().rev().map(|m| m.masternode_list_entry.pro_reg_tx_hash.reverse().to_string().split_at(4).0.to_string()).collect::<Vec<_>>().join("|");
        //
        //     println!("used masternodes [{}]", used_masternodes_string);
        //     println!("unused masternodes [{}]", unused_masternodes_string);
        // }
        let sorted_combined_mns_list = Vec::from_iter(
            sorted_unused_mns_list
                .into_values()
                .rev()
                .chain(sorted_used_mns_list.into_values().rev()),
        );
        match skip_type {
            LLMQQuarterUsageType::Snapshot(snapshot) => {
                match snapshot.skip_list_mode {
                    MNSkipListMode::NoSkipping => sorted_combined_mns_list
                        .chunks(quarter_size)
                        .map(|chunk| chunk.to_vec())
                        .collect(),
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
                        .map(|i| {
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
                    MNSkipListMode::SkipAll => {
                        // TODO: do we need to impl smth in this strategy ?
                        // warn!("skip_mode SkipAll not supported yet");
                        vec![Vec::<&QualifiedMasternodeListEntry>::new(); quorum_count]
                    }
                }
            }
            LLMQQuarterUsageType::New(mut used_indexed_masternodes) => {
                let mut quarter_quorum_members =
                    vec![Vec::<&QualifiedMasternodeListEntry>::new(); quorum_count];
                let mut skip_list = Vec::<u32>::new();
                let mut first_skipped_index = 0u32;
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
                        let mn = sorted_combined_mns_list.get(idx as usize).unwrap();
                        if masternodes_used_at_h_indexed_at_i.iter().any(|node| {
                            mn.masternode_list_entry.pro_reg_tx_hash
                                == node.masternode_list_entry.pro_reg_tx_hash
                        }) {
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
                        if idx == sorted_combined_mns_list_len as u32 {
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
