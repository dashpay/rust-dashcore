use std::collections::BTreeMap;
use crate::sml::llmq_type::{LLMQParams, LLMQType};
use crate::sml::llmq_type::rotation::LLMQQuarterReconstructionType;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list_entry::MasternodeListEntry;
use crate::sml::quorum_validation_error::QuorumValidationError;

impl MasternodeList {
    fn quorum_quarter_members_by_reconstruction_type(
        &self,
        reconstruction_type: LLMQQuarterReconstructionType,
        llmq_params: &LLMQParams,
        work_block_height: u32,
    ) -> Result<Vec<Vec<MasternodeListEntry>>, QuorumValidationError> {
        let work_block_hash = self.provider.lookup_block_hash_by_height(work_block_height);
        if work_block_hash.is_zero() {
            warn!("quorum_quarter_members_by_reconstruction_type: empty work block hash for {work_block_height}")
        }
        let masternode_list = self.masternode_list_for_block_hash(work_block_hash)
            .ok_or(QuorumValidationError::RequiredMasternodeListNotPresent(work_block_hash))?;
        let llmq_type = llmq_params.r#type.clone();
        let quorum_count = llmq_params.signing_active_quorum_count as usize;
        let quorum_size = llmq_params.size as usize;
        let quarter_size = quorum_size / 4;
        let quorum_modifier_type = self.llmq_modifier_type_for(llmq_type, work_block_hash, work_block_height);
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


    fn rotate_members(
        &self,
        cycle_base_height: u32,
        llmq_params: LLMQParams,
        skip_removed_masternodes: bool,
        // cache: &Arc<RwLock<MasternodeProcessorCache>>
        // cached_mn_lists: &BTreeMap<UInt256, MasternodeList>,
        // cached_llmq_snapshots: &BTreeMap<UInt256, LLMQSnapshot>,
        // cached_cl_signatures: &BTreeMap<UInt256, UInt768>,
        // unknown_mn_lists: &mut Vec<UInt256>,
    ) -> Result<Vec<Vec<MasternodeListEntry>>, QuorumValidationError> {
        let num_quorums = llmq_params.signing_active_quorum_count as usize;
        let cycle_length = llmq_params.dkg_params.interval;
        let work_block_height_for_index = |index: u32| (cycle_base_height - index * cycle_length) - 8;
        // Reconstruct quorum members at h - 3c from snapshot
        let q_h_m_3c = self.quorum_quarter_members_by_reconstruction_type(LLMQQuarterReconstructionType::Snapshot, &llmq_params, work_block_height_for_index(3))?;
        // Reconstruct quorum members at h - 2c from snapshot
        let q_h_m_2c = self.quorum_quarter_members_by_reconstruction_type(LLMQQuarterReconstructionType::Snapshot, &llmq_params, work_block_height_for_index(2))?;
        // Reconstruct quorum members at h - c from snapshot
        let q_h_m_c = self.quorum_quarter_members_by_reconstruction_type(LLMQQuarterReconstructionType::Snapshot, &llmq_params, work_block_height_for_index(1))?;
        // Determine quorum members at new index
        let reconstruction_type = LLMQQuarterReconstructionType::New { previous_quarters:  [&q_h_m_c, &q_h_m_2c, &q_h_m_3c], skip_removed_masternodes };
        let quarter_new = self.quorum_quarter_members_by_reconstruction_type(reconstruction_type, &llmq_params, work_block_height_for_index(0))?;
        let mut quorum_members =
            Vec::<Vec<MasternodeListEntry>>::with_capacity(num_quorums);
        (0..num_quorums).for_each(|index| {
            add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_3c, index);
            add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_2c, index);
            add_quorum_members_from_quarter(&mut quorum_members, &q_h_m_c, index);
            add_quorum_members_from_quarter(&mut quorum_members, &quarter_new, index);
        });
        Ok(quorum_members)
    }

    /// Determine masternodes which is responsible for signing at this quorum index
    #[allow(clippy::too_many_arguments)]
    pub fn get_rotated_masternodes_for_quorum(
        &self,
        llmq_type: LLMQType,
        block_hash: [u8; 32],
        block_height: u32,
        skip_removed_masternodes: bool,
    ) -> Result<Vec<MasternodeListEntry>, CoreProviderError> {
        let mut llmq_members_lock = self.cache.llmq_members.write().unwrap();
        let cached_members_of_llmq_type_opt = llmq_members_lock.get_mut(&llmq_type);
        if cached_members_of_llmq_type_opt.is_some() {
            if let Some(cached_members) = cached_members_of_llmq_type_opt.as_ref().unwrap().get(&block_hash).cloned() {
                drop(llmq_members_lock);
                return Ok(cached_members);
            }
        } else {
            llmq_members_lock.insert(llmq_type.clone(), BTreeMap::new());
        }

        let cached_members_of_llmq_type = llmq_members_lock.get_mut(&llmq_type).unwrap();
        let llmq_params = llmq_type.params();
        let quorum_index = block_height % llmq_params.dkg_params.interval;
        let cycle_base_height = block_height - quorum_index;
        let cycle_base_hash = self.provider.lookup_block_hash_by_height(cycle_base_height);
        let mut llmq_indexed_members_lock = self.cache.llmq_indexed_members.write().unwrap();
        if let Some(map_by_type_indexed) = llmq_indexed_members_lock.get(&llmq_type) {
            let indexed_hash = LLMQIndexedHash::from((cycle_base_hash, quorum_index));
            if let Some(cached_members) = map_by_type_indexed.get(&indexed_hash).cloned() {
                cached_members_of_llmq_type.insert(block_hash, cached_members.clone());
                drop(llmq_members_lock);
                drop(llmq_indexed_members_lock);
                return Ok(cached_members);
            }
        } else {
            llmq_indexed_members_lock.insert(llmq_type.clone(), BTreeMap::new());
        }
        drop(llmq_indexed_members_lock);
        let rotated_members = self.rotate_members(cycle_base_height, llmq_params, skip_removed_masternodes)?;
        let result = if let Some(rotated_members_at_index) = rotated_members.get(quorum_index as usize) {
            cached_members_of_llmq_type.insert(block_hash, rotated_members_at_index.clone());
            Ok(rotated_members_at_index.clone())
        } else {
            Err(CoreProviderError::NullResult(format!("No rotated_members for llmq index {} ({})", quorum_index, block_hash.to_hex())))
        };
        drop(llmq_members_lock);

        self.cache.write_llmq_indexed_members(|lock| {
            lock.get_mut(&llmq_type)
                .unwrap()
                .extend(rotated_members.into_iter()
                    .enumerate()
                    .map(|(index, members)|
                        (LLMQIndexedHash::from((cycle_base_hash, index)), members)));
        });
        result
    }
}