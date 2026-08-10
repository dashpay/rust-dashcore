use crate::QuorumHash;
use crate::bls_sig_utils::BLSSignature;
use crate::hash_types::QuorumModifierHash;
use crate::network::message_qrinfo::{MNSkipListMode, QRInfo};
use crate::prelude::CoreBlockHeight;
use crate::sml::llmq_type::LLMQType;
use crate::sml::llmq_type::rotation::{LLMQQuarterReconstructionType, LLMQQuarterUsageType};
use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list_engine::{
    MasternodeListEngine, WORK_DIFF_DEPTH, rotated_cycle_base_height,
};
use crate::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use crate::sml::quorum_entry::qualified_quorum_entry::{
    QualifiedQuorumEntry, VerifyingChainLockSignaturesType,
};
use crate::sml::quorum_entry::quorum_modifier_type::LLMQModifierType;
use crate::sml::quorum_validation_error::QuorumValidationError;
use std::collections::{BTreeMap, BTreeSet};

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
    #[allow(dead_code)]
    pub(in crate::sml::masternode_list_engine) fn find_rotated_masternodes_for_quorum<'a>(
        &'a self,
        quorum: &'a QualifiedQuorumEntry,
    ) -> Result<Vec<&'a QualifiedMasternodeListEntry>, QuorumValidationError> {
        let Some(quorum_block_height) =
            self.block_container.get_height(&quorum.quorum_entry.quorum_hash)
        else {
            return Err(QuorumValidationError::RequiredBlockNotPresent(
                quorum.quorum_entry.quorum_hash,
                "getting height when finding rotated masternodes for quorum".to_string(),
            ));
        };
        let llmq_type = quorum.quorum_entry.llmq_type;
        let Some(quorum_index) = quorum.quorum_entry.quorum_index else {
            return Err(QuorumValidationError::RequiredQuorumIndexNotPresent(
                quorum.quorum_entry.quorum_hash,
            ));
        };
        let Some(cycle_base_height) = rotated_cycle_base_height(quorum_block_height, quorum_index)
        else {
            return Err(QuorumValidationError::InvalidQuorumIndex {
                quorum_hash: quorum.quorum_entry.quorum_hash,
                index: quorum_index,
            });
        };

        let Some(VerifyingChainLockSignaturesType::Rotating(rotating)) =
            quorum.verifying_chain_lock_signature
        else {
            return Err(QuorumValidationError::RequiredRotatedChainLockSigsNotPresent(
                quorum.quorum_entry.quorum_hash,
            ));
        };

        let rotated_members = self
            .masternode_list_entry_members_for_rotated_quorum(
                llmq_type,
                cycle_base_height,
                rotating,
            )?
            .get(quorum_index as usize)
            .ok_or(QuorumValidationError::CorruptedCodeExecution(format!(
                "expected masternode list entry members for {}",
                quorum_index
            )))?
            .clone();

        Ok(rotated_members)
    }

    /// Resolves the signing member set for each rotated quorum, per quorum.
    ///
    /// Entries of an active rotated quorum set do not all belong to the same
    /// cycle (a failed DKG leaves the previous cycle's quorum in place at
    /// that index), and older cycles may lack the history or signatures the
    /// reconstruction needs. Each quorum therefore gets its own `Result`, so
    /// one unresolvable straggler cannot poison the rest of the set.
    #[allow(dead_code)]
    pub(in crate::sml::masternode_list_engine) fn find_rotated_masternodes_for_quorums<'a>(
        &'a self,
        quorums: &'a [&'a QualifiedQuorumEntry],
    ) -> BTreeMap<QuorumHash, Result<Vec<&'a QualifiedMasternodeListEntry>, QuorumValidationError>>
    {
        let mut members_by_quorum_hash = BTreeMap::new();
        let mut cycles: BTreeMap<
            CoreBlockHeight,
            Result<Vec<Vec<&QualifiedMasternodeListEntry>>, QuorumValidationError>,
        > = BTreeMap::new();
        for quorum in quorums {
            let quorum_hash = quorum.quorum_entry.quorum_hash;
            let Some(quorum_block_height) = self.block_container.get_height(&quorum_hash) else {
                members_by_quorum_hash.insert(
                    quorum_hash,
                    Err(QuorumValidationError::RequiredBlockNotPresent(
                        quorum_hash,
                        "getting height for a quorum hash when trying to find rotated masternodes for quorums".to_string(),
                    )),
                );
                continue;
            };
            let llmq_type = quorum.quorum_entry.llmq_type;
            let Some(quorum_index) = quorum.quorum_entry.quorum_index else {
                members_by_quorum_hash.insert(
                    quorum_hash,
                    Err(QuorumValidationError::RequiredQuorumIndexNotPresent(quorum_hash)),
                );
                continue;
            };
            let Some(cycle_base_height) =
                rotated_cycle_base_height(quorum_block_height, quorum_index)
            else {
                members_by_quorum_hash.insert(
                    quorum_hash,
                    Err(QuorumValidationError::InvalidQuorumIndex {
                        quorum_hash,
                        index: quorum_index,
                    }),
                );
                continue;
            };
            // Quorums of one cycle share their quarter signatures, so the
            // reconstruction result is cached per cycle base height.
            let members_by_index = cycles.entry(cycle_base_height).or_insert_with(|| {
                let Some(VerifyingChainLockSignaturesType::Rotating(rotating)) =
                    quorum.verifying_chain_lock_signature
                else {
                    return Err(QuorumValidationError::RequiredRotatedChainLockSigsNotPresent(
                        quorum_hash,
                    ));
                };
                self.masternode_list_entry_members_for_rotated_quorum(
                    llmq_type,
                    cycle_base_height,
                    rotating,
                )
            });
            let result = match members_by_index {
                Ok(members_by_index) => members_by_index.get(quorum_index as usize).cloned().ok_or(
                    QuorumValidationError::CorruptedCodeExecution(format!(
                        "expected masternode list entry members for {}",
                        quorum_index
                    )),
                ),
                Err(e) => Err(e.clone()),
            };
            members_by_quorum_hash.insert(quorum_hash, result);
        }

        members_by_quorum_hash
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
            let Some(quorum_block_height) = self.block_container.get_height(&quorum.quorum_hash)
            else {
                return Err(QuorumValidationError::RequiredBlockNotPresent(
                    quorum.quorum_hash,
                    "getting required cl_sig heights".to_string(),
                ));
            };
            let llmq_params = quorum.llmq_type.params();
            let quorum_index = quorum_block_height % llmq_params.dkg_params.interval;
            let cycle_base_height = quorum_block_height - quorum_index;
            let cycle_length = llmq_params.dkg_params.interval;
            for i in 0..=3 {
                if let Some(work_height) =
                    cycle_base_height.checked_sub(i * cycle_length + WORK_DIFF_DEPTH)
                {
                    required_heights.insert(work_height);
                }
            }
        }
        // We are going to validate the previous rotation as well
        if qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c.is_some() {
            for quorum in &qr_info.mn_list_diff_h.new_quorums {
                if quorum.llmq_type.is_rotating_quorum_type() {
                    let Some(quorum_block_height) =
                        self.block_container.get_height(&quorum.quorum_hash)
                    else {
                        return Err(QuorumValidationError::RequiredBlockNotPresent(
                            quorum.quorum_hash,
                            "getting height for quorum hash for diff at h minus 4c".to_string(),
                        ));
                    };
                    let llmq_params = quorum.llmq_type.params();
                    let quorum_index = quorum_block_height % llmq_params.dkg_params.interval;
                    let cycle_base_height = quorum_block_height - quorum_index;
                    let cycle_length = llmq_params.dkg_params.interval;
                    for i in 0..=3 {
                        if let Some(work_height) =
                            cycle_base_height.checked_sub(i * cycle_length + WORK_DIFF_DEPTH)
                        {
                            required_heights.insert(work_height);
                        }
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
    #[allow(dead_code)]
    fn masternode_list_entry_members_for_rotated_quorum(
        &self,
        quorum_llmq_type: LLMQType,
        cycle_base_height: u32,
        chain_lock_sigs: [BLSSignature; 4],
    ) -> Result<Vec<Vec<&QualifiedMasternodeListEntry>>, QuorumValidationError> {
        let llmq_params = quorum_llmq_type.params();
        let num_quorums = llmq_params.signing_active_quorum_count as usize;
        let cycle_length = llmq_params.dkg_params.interval;
        let work_block_height_for_index = |index: u32| {
            cycle_base_height
                .checked_sub(index * cycle_length + WORK_DIFF_DEPTH)
                .ok_or(QuorumValidationError::CycleBaseHeightTooLow(cycle_base_height))
        };
        // Reconstruct quorum members at h - 3c from snapshot
        let q_h_m_3c = self.quorum_quarter_members_by_reconstruction_type(
            quorum_llmq_type,
            LLMQQuarterReconstructionType::Snapshot,
            work_block_height_for_index(3)?,
            chain_lock_sigs[0],
        )?;
        // Reconstruct quorum members at h - 2c from snapshot
        let q_h_m_2c = self.quorum_quarter_members_by_reconstruction_type(
            quorum_llmq_type,
            LLMQQuarterReconstructionType::Snapshot,
            work_block_height_for_index(2)?,
            chain_lock_sigs[1],
        )?;
        // Reconstruct quorum members at h - c from snapshot
        let q_h_m_c = self.quorum_quarter_members_by_reconstruction_type(
            quorum_llmq_type,
            LLMQQuarterReconstructionType::Snapshot,
            work_block_height_for_index(1)?,
            chain_lock_sigs[2],
        )?;
        // Determine quorum members at new index
        let reconstruction_type = LLMQQuarterReconstructionType::New {
            previous_quarters: [&q_h_m_c, &q_h_m_2c, &q_h_m_3c],
        };
        let last_quarter = self.quorum_quarter_members_by_reconstruction_type(
            quorum_llmq_type,
            reconstruction_type,
            work_block_height_for_index(0)?,
            chain_lock_sigs[3],
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    fn quorum_quarter_members_by_reconstruction_type<'a: 'b, 'b>(
        &'a self,
        quorum_llmq_type: LLMQType,
        reconstruction_type: LLMQQuarterReconstructionType<'a, 'b>,
        work_block_height: CoreBlockHeight,
        best_cl_signature: BLSSignature,
    ) -> Result<Vec<Vec<&'a QualifiedMasternodeListEntry>>, QuorumValidationError> {
        let llmq_params = quorum_llmq_type.params();
        let Some(work_block_hash) = self.block_container.get_hash(&work_block_height) else {
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
            best_cl_signature,
            self.network,
        )?;
        let quorum_modifier = quorum_modifier_type.build_llmq_hash();
        match reconstruction_type {
            LLMQQuarterReconstructionType::New {
                previous_quarters,
            } => {
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
    #[allow(dead_code)]
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
            sorted_unused_mns_list
                .into_values()
                .rev()
                .chain(sorted_used_mns_list.into_values().rev()),
        );
        if sorted_combined_mns_list.is_empty() {
            return vec![Vec::new(); quorum_count];
        }
        match skip_type {
            LLMQQuarterUsageType::Snapshot(snapshot) => {
                match snapshot.skip_list_mode {
                    // One shared cursor fills every quarter and wraps back to
                    // the front when the list runs out, so quarters reuse
                    // masternodes once fewer than
                    // `quorum_count * quarter_size` are available.
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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use hashes::Hash;

    use super::*;
    use crate::Network;
    use crate::bls_sig_utils::BLSPublicKey;
    use crate::hash_types::{ConfirmedHash, QuorumVVecHash};
    use crate::network::message_qrinfo::QuorumSnapshot;
    use crate::sml::masternode_list_entry::{
        EntryMasternodeType, MasternodeListEntry, MasternodeNetInfo,
    };
    use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;
    use crate::{ProTxHash, PubkeyHash};

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
        QuorumEntry {
            version: 2,
            llmq_type: LLMQType::Llmqtype60_75,
            quorum_hash,
            quorum_index: Some(quorum_index),
            signers: vec![true],
            valid_members: vec![true],
            quorum_public_key: BLSPublicKey::from([0; 48]),
            quorum_vvec_hash: QuorumVVecHash::all_zeros(),
            threshold_sig: BLSSignature::from([0; 96]),
            all_commitment_aggregated_signature: BLSSignature::from([0; 96]),
        }
        .into()
    }

    #[test]
    fn unusable_quorum_index_is_rejected_instead_of_underflowing_the_cycle_base() {
        let mut engine = MasternodeListEngine::default_for_network(Network::Mainnet);
        let negative_index_hash = QuorumHash::from_byte_array([1; 32]);
        let index_above_height_hash = QuorumHash::from_byte_array([2; 32]);
        engine.block_container.feed_block_height(1000, negative_index_hash);
        engine.block_container.feed_block_height(3, index_above_height_hash);

        let quorums =
            [rotated_quorum(negative_index_hash, -1), rotated_quorum(index_above_height_hash, 5)];

        for quorum in quorums.iter() {
            let error = engine
                .find_rotated_masternodes_for_quorum(quorum)
                .expect_err("an index the cycle base cannot absorb must surface as an error");
            assert!(
                matches!(error, QuorumValidationError::InvalidQuorumIndex { .. }),
                "expected an invalid index error, got {error}"
            );
        }

        let borrowed: Vec<&QualifiedQuorumEntry> = quorums.iter().collect();
        let results = engine.find_rotated_masternodes_for_quorums(&borrowed);
        assert_eq!(results.len(), 2);
        for quorum in quorums.iter() {
            let result = results
                .get(&quorum.quorum_entry.quorum_hash)
                .expect("every quorum must get its own result");
            assert!(
                matches!(result, Err(QuorumValidationError::InvalidQuorumIndex { .. })),
                "expected an invalid index error, got {result:?}"
            );
        }
    }

    #[test]
    fn no_skipping_fills_quarters_with_circular_wrap_around() {
        let entries: Vec<QualifiedMasternodeListEntry> = (1..=6).map(entry).collect();
        let modifier = QuorumModifierHash::from_byte_array([9; 32]);
        let sorted = score_sorted(&entries, modifier);

        let quarters = MasternodeListEngine::apply_skip_strategy_of_type(
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
            let quarters = MasternodeListEngine::apply_skip_strategy_of_type(
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

        // The first skip entry is an absolute index, later entries are
        // relative to it: [3, 2] skips absolute indexes 3 and 5.
        let quarters = MasternodeListEngine::apply_skip_strategy_of_type(
            LLMQQuarterUsageType::Snapshot(snapshot(MNSkipListMode::SkipFirst, vec![3, 2])),
            vec![],
            entries.iter().collect(),
            modifier,
            2,
            2,
        );

        let expected: Vec<Vec<ProTxHash>> = vec![
            pro_reg_tx_hashes(&[sorted[0], sorted[1]]),
            pro_reg_tx_hashes(&[sorted[2], sorted[4]]),
        ];
        let actual: Vec<Vec<ProTxHash>> =
            quarters.iter().map(|quarter| pro_reg_tx_hashes(quarter)).collect();
        assert_eq!(actual, expected, "skipped indexes must be excluded from quarter fill");
    }
}
