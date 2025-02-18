use std::collections::BTreeMap;
use crate::BlockHash;
use crate::prelude::CoreBlockHeight;
use crate::sml::llmq_type::{LLMQParams, LLMQType};
use crate::sml::llmq_type::rotation::LLMQQuarterReconstructionType;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list_entry::MasternodeListEntry;
use crate::sml::quorum_validation_error::QuorumValidationError;

impl MasternodeList {
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
        block_hash: BlockHash,
        block_height: CoreBlockHeight,
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