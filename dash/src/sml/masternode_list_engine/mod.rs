mod helpers;
#[cfg(feature = "message_verification")]
mod message_request_verification;
mod non_rotated_quorum_construction;
mod rotated_quorum_construction;
#[cfg(feature = "quorum_validation")]
mod validation;

use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::bls_sig_utils::{BLSPublicKey, BLSSignature};
use crate::network::message_qrinfo::{QRInfo, QuorumSnapshot};
use crate::network::message_sml::MnListDiff;
use crate::prelude::CoreBlockHeight;
use crate::sml::error::SmlError;
use crate::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use crate::sml::llmq_type::LLMQType;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list::from_diff::TryIntoWithBlockHashLookup;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use crate::sml::quorum_validation_error::{ClientDataRetrievalError, QuorumValidationError};
use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;
use crate::{BlockHash, Network, QuorumHash};

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct MasternodeListEngine {
    pub block_hashes: BTreeMap<CoreBlockHeight, BlockHash>,
    pub block_heights: BTreeMap<BlockHash, CoreBlockHeight>,
    pub masternode_lists: BTreeMap<CoreBlockHeight, MasternodeList>,
    pub known_chain_locks: BTreeMap<BlockHash, BLSSignature>,
    pub known_snapshots: BTreeMap<BlockHash, QuorumSnapshot>,
    pub rotated_quorums_per_cycle: BTreeMap<BlockHash, Vec<QualifiedQuorumEntry>>,
    pub quorum_statuses: BTreeMap<
        LLMQType,
        BTreeMap<
            QuorumHash,
            (BTreeSet<CoreBlockHeight>, BLSPublicKey, LLMQEntryVerificationStatus),
        >,
    >,
    pub network: Network,
}

impl Default for MasternodeListEngine {
    fn default() -> Self {
        Self {
            block_hashes: Default::default(),
            block_heights: Default::default(),
            masternode_lists: Default::default(),
            known_chain_locks: Default::default(),
            known_snapshots: Default::default(),
            rotated_quorums_per_cycle: Default::default(),
            quorum_statuses: Default::default(),
            network: Network::Dash,
        }
    }
}

impl MasternodeListEngine {
    pub fn default_for_network(network: Network) -> Self { Self { network, ..Default::default() } }
    pub fn initialize_with_diff_to_height(
        masternode_list_diff: MnListDiff,
        block_height: CoreBlockHeight,
        network: Network,
    ) -> Result<Self, SmlError> {
        let block_hash = masternode_list_diff.block_hash;
        let base_block_hash = masternode_list_diff.base_block_hash;
        let masternode_list = masternode_list_diff
            .try_into_with_block_hash_lookup(|_block_hash| Some(block_height), network)?;
        Ok(Self {
            block_hashes: [(0, base_block_hash), (block_height, block_hash)].into(),
            block_heights: [(base_block_hash, 0), (block_hash, block_height)].into(),
            masternode_lists: [(block_height, masternode_list)].into(),
            known_chain_locks: Default::default(),
            known_snapshots: Default::default(),
            rotated_quorums_per_cycle: Default::default(),
            quorum_statuses: Default::default(),
            network,
        })
    }

    pub fn latest_masternode_list(&self) -> Option<&MasternodeList> {
        self.masternode_lists.last_key_value().map(|(_, list)| list)
    }

    pub fn latest_masternode_list_quorum_hashes(
        &self,
        exclude_quorum_types: &[LLMQType],
    ) -> BTreeSet<QuorumHash> {
        self.latest_masternode_list()
            .map(|list| list.quorum_hashes(exclude_quorum_types))
            .unwrap_or_default()
    }

    pub fn latest_masternode_list_non_rotating_quorum_hashes(
        &self,
        exclude_quorum_types: &[LLMQType],
        only_return_block_hashes_with_missing_masternode_lists_from_engine: bool,
    ) -> BTreeSet<QuorumHash> {
        self.latest_masternode_list()
            .map(|list| {
                if only_return_block_hashes_with_missing_masternode_lists_from_engine {
                    list.non_rotating_quorum_hashes(exclude_quorum_types)
                        .into_iter()
                        .filter(|quorum_hash| {
                            let Some(block_height) = self.block_heights.get(quorum_hash) else {
                                return true;
                            };
                            !self.masternode_lists.contains_key(block_height)
                        })
                        .collect()
                } else {
                    list.non_rotating_quorum_hashes(exclude_quorum_types)
                }
            })
            .unwrap_or_default()
    }

    pub fn masternode_list_non_rotating_quorum_hashes(
        &self,
        height: CoreBlockHeight,
        exclude_quorum_types: &[LLMQType],
        only_return_block_hashes_with_missing_masternode_lists_from_engine: bool,
    ) -> BTreeSet<QuorumHash> {
        self.masternode_lists
            .get(&height)
            .map(|list| {
                if only_return_block_hashes_with_missing_masternode_lists_from_engine {
                    list.non_rotating_quorum_hashes(exclude_quorum_types)
                        .into_iter()
                        .filter(|quorum_hash| {
                            let Some(block_height) = self.block_heights.get(quorum_hash) else {
                                return true;
                            };
                            !self.masternode_lists.contains_key(block_height)
                        })
                        .collect()
                } else {
                    list.non_rotating_quorum_hashes(exclude_quorum_types)
                }
            })
            .unwrap_or_default()
    }

    pub fn latest_masternode_list_rotating_quorum_hashes(
        &self,
        exclude_quorum_types: &[LLMQType],
    ) -> BTreeSet<QuorumHash> {
        self.latest_masternode_list()
            .map(|list| list.rotating_quorum_hashes(exclude_quorum_types))
            .unwrap_or_default()
    }

    pub fn masternode_list_for_block_hash(
        &self,
        block_hash: &BlockHash,
    ) -> Option<&MasternodeList> {
        self.block_heights.get(block_hash).and_then(|height| self.masternode_lists.get(height))
    }

    pub fn feed_block_height(&mut self, height: CoreBlockHeight, block_hash: BlockHash) {
        self.block_heights.insert(block_hash, height);
        self.block_hashes.insert(height, block_hash);
    }

    fn request_qr_info_block_heights<FH>(
        &mut self,
        qr_info: &QRInfo,
        fetch_block_height: &FH,
    ) -> Result<(), ClientDataRetrievalError>
    where
        FH: Fn(&BlockHash) -> Result<u32, ClientDataRetrievalError>,
    {
        let mn_list_diffs = [
            &qr_info.mn_list_diff_tip,
            &qr_info.mn_list_diff_h,
            &qr_info.mn_list_diff_at_h_minus_c,
            &qr_info.mn_list_diff_at_h_minus_2c,
            &qr_info.mn_list_diff_at_h_minus_3c,
        ];

        let should_request_for_previous_validation =
            qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c.is_some();

        // If h-4c exists, add it to the list
        if let Some((_, mn_list_diff_h_minus_4c)) =
            &qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c
        {
            mn_list_diffs.iter().try_for_each(|&mn_list_diff| {
                self.request_mn_list_diff_heights(mn_list_diff, fetch_block_height)
            })?;

            // Feed h-4c separately
            self.request_mn_list_diff_heights(mn_list_diff_h_minus_4c, fetch_block_height)?;
        } else {
            mn_list_diffs.iter().try_for_each(|&mn_list_diff| {
                self.request_mn_list_diff_heights(mn_list_diff, fetch_block_height)
            })?;
        }

        // Process `last_commitment_per_index` quorum hashes
        qr_info.last_commitment_per_index.iter().try_for_each(|quorum_entry| {
            self.request_quorum_entry_height(quorum_entry, fetch_block_height)
        })?;

        if should_request_for_previous_validation {
            qr_info.mn_list_diff_h.new_quorums.iter().try_for_each(|quorum_entry| {
                if quorum_entry.llmq_type.is_rotating_quorum_type() {
                    self.request_quorum_entry_height(quorum_entry, fetch_block_height)
                } else {
                    Ok(())
                }
            })?;
        }

        // Process `mn_list_diff_list` (extra diffs)
        qr_info.mn_list_diff_list.iter().try_for_each(|mn_list_diff| {
            self.request_mn_list_diff_heights(mn_list_diff, fetch_block_height)
        })
    }

    /// **Helper function:** Feeds the quorum hash height of a `QuorumEntry`
    fn request_quorum_entry_height<FH>(
        &mut self,
        quorum_entry: &QuorumEntry,
        fetch_block_height: &FH,
    ) -> Result<(), ClientDataRetrievalError>
    where
        FH: Fn(&BlockHash) -> Result<u32, ClientDataRetrievalError>,
    {
        if !self.block_heights.contains_key(&quorum_entry.quorum_hash) {
            let height = fetch_block_height(&quorum_entry.quorum_hash)?;
            self.feed_block_height(height, quorum_entry.quorum_hash);
        }
        Ok(())
    }

    /// **Helper function:** Requests the base and block hash heights of an `MnListDiff`
    fn request_mn_list_diff_heights<FH>(
        &mut self,
        mn_list_diff: &MnListDiff,
        fetch_block_height: &FH,
    ) -> Result<(), ClientDataRetrievalError>
    where
        FH: Fn(&BlockHash) -> Result<u32, ClientDataRetrievalError>,
    {
        if !self.block_heights.contains_key(&mn_list_diff.base_block_hash) {
            // Feed base block hash height
            let base_height = fetch_block_height(&mn_list_diff.base_block_hash)?;
            self.feed_block_height(base_height, mn_list_diff.base_block_hash);
        }

        if !self.block_heights.contains_key(&mn_list_diff.block_hash) {
            // Feed block hash height
            let block_height = fetch_block_height(&mn_list_diff.block_hash)?;
            self.feed_block_height(block_height, mn_list_diff.block_hash);
        }
        Ok(())
    }

    fn request_qr_info_cl_sigs<FS>(
        &mut self,
        qr_info: &QRInfo,
        fetch_chain_lock_sigs: &FS,
    ) -> Result<(), QuorumValidationError>
    where
        FS: Fn(&BlockHash) -> Result<Option<BLSSignature>, ClientDataRetrievalError>,
    {
        let heights = self.required_cl_sig_heights(qr_info)?;
        for height in heights {
            let block_hash = self
                .block_hashes
                .get(&height)
                .ok_or(QuorumValidationError::RequiredBlockHeightNotPresent(height))?;
            let maybe_chain_lock_sig = fetch_chain_lock_sigs(block_hash)?;
            if let Some(maybe_chain_lock_sig) = maybe_chain_lock_sig {
                self.feed_chain_lock_sig(*block_hash, maybe_chain_lock_sig);
            }
        }
        Ok(())
    }

    pub fn feed_qr_info<FH, FS>(
        &mut self,
        qr_info: QRInfo,
        verify_rotated_quorums: bool,
        fetch_block_height: Option<FH>,
        fetch_chain_lock_sigs: Option<FS>,
    ) -> Result<(), QuorumValidationError>
    where
        FH: Fn(&BlockHash) -> Result<u32, ClientDataRetrievalError>,
        FS: Fn(&BlockHash) -> Result<Option<BLSSignature>, ClientDataRetrievalError>,
    {
        // Fetch and process block heights using the provided callback
        if let Some(fetch_height) = fetch_block_height {
            self.request_qr_info_block_heights(&qr_info, &fetch_height)?;
        }

        // Fetch and process chain lock signatures using the provided callback
        if let Some(fetch_chain_lock_sigs) = fetch_chain_lock_sigs {
            self.request_qr_info_cl_sigs(&qr_info, &fetch_chain_lock_sigs)?;
        }

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

        // Apply quorum snapshots and masternode list diffs
        for (snapshot, diff) in quorum_snapshot_list.into_iter().zip(mn_list_diff_list.into_iter())
        {
            self.known_snapshots.insert(diff.block_hash, snapshot);
            self.apply_diff(diff, None, false)?;
        }

        let can_verify_previous = quorum_snapshot_and_mn_list_diff_at_h_minus_4c.is_some();

        let h_height = self
            .block_heights
            .get(&mn_list_diff_h.block_hash)
            .copied()
            .ok_or(QuorumValidationError::RequiredBlockNotPresent(mn_list_diff_h.block_hash))?;
        let tip_height =
            self.block_heights.get(&mn_list_diff_tip.block_hash).copied().ok_or(
                QuorumValidationError::RequiredBlockNotPresent(mn_list_diff_tip.block_hash),
            )?;
        let rotation_quorum_type = last_commitment_per_index
            .first()
            .map(|quorum_entry| quorum_entry.llmq_type)
            .unwrap_or(self.network.isd_llmq_type());

        if let Some((quorum_snapshot_at_h_minus_4c, mn_list_diff_at_h_minus_4c)) =
            quorum_snapshot_and_mn_list_diff_at_h_minus_4c
        {
            self.known_snapshots
                .insert(mn_list_diff_at_h_minus_4c.block_hash, quorum_snapshot_at_h_minus_4c);
            self.apply_diff(mn_list_diff_at_h_minus_4c, None, false)?;
        }

        self.known_snapshots
            .insert(mn_list_diff_at_h_minus_3c.block_hash, quorum_snapshot_at_h_minus_3c);
        self.apply_diff(mn_list_diff_at_h_minus_3c, None, false)?;
        self.known_snapshots
            .insert(mn_list_diff_at_h_minus_2c.block_hash, quorum_snapshot_at_h_minus_2c);
        self.apply_diff(mn_list_diff_at_h_minus_2c, None, false)?;
        self.known_snapshots
            .insert(mn_list_diff_at_h_minus_c.block_hash, quorum_snapshot_at_h_minus_c);
        self.apply_diff(mn_list_diff_at_h_minus_c, None, false)?;
        self.apply_diff(mn_list_diff_h, None, false)?;
        self.apply_diff(mn_list_diff_tip, None, false)?;

        let qualified_last_commitment_per_index = last_commitment_per_index
            .into_iter()
            .map(|quorum_entry| quorum_entry.into())
            .collect::<Vec<QualifiedQuorumEntry>>();

        #[cfg(feature = "quorum_validation")]
        if verify_rotated_quorums {
            let validation_statuses = self.validate_rotation_cycle_quorums_validation_statuses(
                qualified_last_commitment_per_index.iter().collect::<Vec<_>>().as_slice(),
            );

            let mut updates: Vec<(
                BTreeSet<CoreBlockHeight>,
                LLMQType,
                QuorumHash,
                LLMQEntryVerificationStatus,
            )> = Vec::new();

            let mut qualified_rotated_quorums_per_cycle =
                qualified_last_commitment_per_index.first().map(|quorum_entry| {
                    self.rotated_quorums_per_cycle
                        .entry(quorum_entry.quorum_entry.quorum_hash)
                        .or_default()
                });

            for mut rotated_quorum in qualified_last_commitment_per_index {
                rotated_quorum.verified = validation_statuses
                    .get(&rotated_quorum.quorum_entry.quorum_hash)
                    .cloned()
                    .unwrap_or_default();

                qualified_rotated_quorums_per_cycle.as_mut().unwrap().push(rotated_quorum.clone());

                // Store status updates separately to prevent multiple mutable borrows
                let masternode_lists_having_quorum_hash_for_quorum_type =
                    self.quorum_statuses.entry(rotated_quorum.quorum_entry.llmq_type).or_default();
                let (heights, _, status) = masternode_lists_having_quorum_hash_for_quorum_type
                    .entry(rotated_quorum.quorum_entry.quorum_hash)
                    .or_insert((
                        BTreeSet::default(),
                        rotated_quorum.quorum_entry.quorum_public_key,
                        LLMQEntryVerificationStatus::Unknown,
                    ));

                updates.push((
                    heights.clone(),
                    rotated_quorum.quorum_entry.llmq_type,
                    rotated_quorum.quorum_entry.quorum_hash,
                    rotated_quorum.verified.clone(),
                ));
                heights.insert(tip_height);
                *status = rotated_quorum.verified.clone();
            }

            // Apply collected updates after iteration to avoid borrow conflicts
            for (heights, quorum_type, quorum_hash, new_status) in updates {
                for height in heights {
                    if let Some(masternode_list_at_height) = self.masternode_lists.get_mut(&height)
                    {
                        if let Some(quorum_entry_at_height) = masternode_list_at_height
                            .quorums
                            .get_mut(&quorum_type)
                            .and_then(|quorums| quorums.get_mut(&quorum_hash))
                        {
                            quorum_entry_at_height.verified = new_status.clone();
                        }
                    }
                }
            }

            // if we can verify previous we should also verify the previous rotation
            if can_verify_previous {
                let validation_statuses = {
                    let masternode_list = self
                        .masternode_lists
                        .get(&h_height)
                        .ok_or(QuorumValidationError::RequiredMasternodeListNotPresent(h_height))?;

                    if let Some(rotated_quorums_at_h) =
                        masternode_list.quorums.get(&rotation_quorum_type)
                    {
                        let quorums = rotated_quorums_at_h.values().collect::<Vec<_>>();

                        self.validate_rotation_cycle_quorums_validation_statuses(quorums.as_slice())
                    } else {
                        BTreeMap::new()
                    }
                };

                let mut updates: Vec<(
                    BTreeSet<CoreBlockHeight>,
                    LLMQType,
                    QuorumHash,
                    LLMQEntryVerificationStatus,
                )> = Vec::new();

                if let Some(masternode_list_at_h) = self.masternode_lists.get_mut(&h_height) {
                    if let Some(rotated_quorums_at_h) =
                        masternode_list_at_h.quorums.get_mut(&rotation_quorum_type)
                    {
                        for (quorum_hash, quorum_entry) in rotated_quorums_at_h.iter_mut() {
                            if let Some(new_status) = validation_statuses.get(quorum_hash) {
                                if &quorum_entry.verified != new_status {
                                    quorum_entry.verified = new_status.clone();
                                    let masternode_lists_having_quorum_hash_for_quorum_type = self
                                        .quorum_statuses
                                        .entry(rotation_quorum_type)
                                        .or_default();

                                    let (heights, _, status) =
                                        masternode_lists_having_quorum_hash_for_quorum_type
                                            .entry(*quorum_hash)
                                            .or_insert((
                                                BTreeSet::default(),
                                                quorum_entry.quorum_entry.quorum_public_key,
                                                LLMQEntryVerificationStatus::Unknown,
                                            ));

                                    updates.push((
                                        heights.clone(),
                                        rotation_quorum_type,
                                        *quorum_hash,
                                        new_status.clone(),
                                    ));

                                    heights.insert(h_height);
                                    *status = new_status.clone();
                                }
                            }
                        }
                    }
                }

                // Apply collected updates after iteration to avoid borrow conflicts
                for (heights, quorum_type, quorum_hash, new_status) in updates {
                    for height in heights {
                        if let Some(masternode_list_at_height) =
                            self.masternode_lists.get_mut(&height)
                        {
                            if let Some(quorum_entry_at_height) = masternode_list_at_height
                                .quorums
                                .get_mut(&quorum_type)
                                .and_then(|quorums| quorums.get_mut(&quorum_hash))
                            {
                                quorum_entry_at_height.verified = new_status.clone();
                            }
                        }
                    }
                }
            }
        } else {
            if let Some(qualified_rotated_quorums_per_cycle) =
                qualified_last_commitment_per_index.first().map(|quorum_entry| {
                    self.rotated_quorums_per_cycle
                        .entry(quorum_entry.quorum_entry.quorum_hash)
                        .or_default()
                })
            {
                *qualified_rotated_quorums_per_cycle = qualified_last_commitment_per_index;
            }
        }

        #[cfg(not(feature = "quorum_validation"))]
        if verify_rotated_quorums {
            return Err(QuorumValidationError::FeatureNotTurnedOn(
                "quorum validation feature is not turned on".to_string(),
            ));
        }

        Ok(())
    }

    pub fn feed_chain_lock_sig(&mut self, block_hash: BlockHash, chain_lock_sig: BLSSignature) {
        self.known_chain_locks.insert(block_hash, chain_lock_sig);
    }

    pub fn apply_diff(
        &mut self,
        masternode_list_diff: MnListDiff,
        diff_end_height: Option<CoreBlockHeight>,
        verify_quorums: bool,
    ) -> Result<(), SmlError> {
        if let Some(known_genesis_block_hash) =
            self.network.known_genesis_block_hash().or_else(|| self.block_hashes.get(&0).cloned())
        {
            if masternode_list_diff.base_block_hash == known_genesis_block_hash {
                // we are going from the start
                let block_hash = masternode_list_diff.block_hash;

                let masternode_list = masternode_list_diff.try_into_with_block_hash_lookup(
                    |block_hash| diff_end_height.or(self.block_heights.get(block_hash).copied()),
                    self.network,
                )?;

                let diff_end_height = match diff_end_height {
                    None => self
                        .block_heights
                        .get(&block_hash)
                        .ok_or(SmlError::BlockHashLookupFailed(block_hash))
                        .cloned()?,
                    Some(diff_end_height) => {
                        self.block_hashes.insert(diff_end_height, block_hash);
                        self.block_heights.insert(block_hash, diff_end_height);
                        diff_end_height
                    }
                };
                self.masternode_lists.insert(diff_end_height, masternode_list);
                return Ok(());
            }
        }

        let Some(base_height) = self.block_heights.get(&masternode_list_diff.base_block_hash)
        else {
            return Err(SmlError::MissingStartMasternodeList(masternode_list_diff.base_block_hash));
        };
        let Some(base_masternode_list) = self.masternode_lists.get(base_height) else {
            return Err(SmlError::MissingStartMasternodeList(masternode_list_diff.base_block_hash));
        };

        let block_hash = masternode_list_diff.block_hash;

        let diff_end_height = match diff_end_height {
            None => self
                .block_heights
                .get(&block_hash)
                .ok_or(SmlError::BlockHashLookupFailed(block_hash))
                .cloned()?,
            Some(diff_end_height) => diff_end_height,
        };

        #[cfg(feature = "quorum_validation")]
        {
            let mut masternode_list =
                base_masternode_list.apply_diff(masternode_list_diff.clone(), diff_end_height)?;
            if verify_quorums {
                // We should go through all quorums of the masternode list to update those that were not yet verified
                for (quorum_type, quorums) in masternode_list.quorums.iter_mut() {
                    for quorum in quorums.values_mut() {
                        let mut status_changed = false;
                        let old_status = quorum.verified.clone();
                        if quorum.verified != LLMQEntryVerificationStatus::Verified {
                            self.validate_and_update_quorum_status(quorum);
                            status_changed = old_status != quorum.verified;
                        }
                        let masternode_lists_having_quorum_hash_for_quorum_type =
                            self.quorum_statuses.entry(*quorum_type).or_default();
                        let (heights, _, status) =
                            masternode_lists_having_quorum_hash_for_quorum_type
                                .entry(quorum.quorum_entry.quorum_hash)
                                .or_insert((
                                    BTreeSet::default(),
                                    quorum.quorum_entry.quorum_public_key,
                                    LLMQEntryVerificationStatus::Unknown,
                                ));
                        if status_changed {
                            for height in heights.iter() {
                                if let Some(masternode_list_at_height) =
                                    self.masternode_lists.get_mut(height)
                                {
                                    if let Some(quorum_entry) = masternode_list_at_height
                                        .quorums
                                        .get_mut(quorum_type)
                                        .and_then(|quorums| {
                                            quorums.get_mut(&quorum.quorum_entry.quorum_hash)
                                        })
                                    {
                                        quorum_entry.verified = quorum.verified.clone();
                                    }
                                }
                            }
                        }
                        heights.insert(diff_end_height);
                        *status = quorum.verified.clone();
                    }
                }
            } else {
                for (quorum_type, quorums) in masternode_list.quorums.iter_mut() {
                    for quorum in quorums.values_mut() {
                        let masternode_lists_having_quorum_hash_for_quorum_type =
                            self.quorum_statuses.entry(*quorum_type).or_default();
                        let (heights, _, status) =
                            masternode_lists_having_quorum_hash_for_quorum_type
                                .entry(quorum.quorum_entry.quorum_hash)
                                .or_insert((
                                    BTreeSet::default(),
                                    quorum.quorum_entry.quorum_public_key,
                                    LLMQEntryVerificationStatus::Unknown,
                                ));
                        quorum.verified = status.clone();
                        heights.insert(diff_end_height);
                    }
                }
            }

            self.masternode_lists.insert(diff_end_height, masternode_list);
        }

        #[cfg(not(feature = "quorum_validation"))]
        {
            let masternode_list =
                base_masternode_list.apply_diff(masternode_list_diff.clone(), diff_end_height)?;
            if verify_quorums {
                return Err(SmlError::FeatureNotTurnedOn(
                    "quorum validation feature is not turned on".to_string(),
                ));
            }
            for (quorum_type, quorums) in &masternode_list.quorums {
                let masternode_lists_having_quorum_hash_for_quorum_type =
                    self.quorum_statuses.entry(*quorum_type).or_default();
                for (quorum_hash, quorum_entry) in quorums {
                    let (heights, _, _) = masternode_lists_having_quorum_hash_for_quorum_type
                        .entry(*quorum_hash)
                        .or_insert((
                            BTreeSet::default(),
                            quorum_entry.quorum_entry.quorum_public_key,
                            LLMQEntryVerificationStatus::Unknown,
                        ));
                    heights.insert(diff_end_height);
                }
            }
            self.masternode_lists.insert(diff_end_height, masternode_list);
        }

        self.block_hashes.insert(diff_end_height, block_hash);
        self.block_heights.insert(block_hash, diff_end_height);

        Ok(())
    }

    #[cfg(feature = "quorum_validation")]
    pub fn verify_non_rotating_masternode_list_quorums(
        &mut self,
        block_height: CoreBlockHeight,
        exclude_quorum_types: &[LLMQType],
    ) -> Result<(), QuorumValidationError> {
        let Some(masternode_list) = self.masternode_lists.get(&block_height) else {
            return Err(QuorumValidationError::VerifyingMasternodeListNotPresent(block_height));
        };

        let mut results = BTreeMap::new();
        for (quorum_type, hash_to_quorum_entries) in &masternode_list.quorums {
            if exclude_quorum_types.contains(quorum_type) || quorum_type.is_rotating_quorum_type() {
                continue;
            }

            let mut inner = BTreeMap::new();
            for (quorum_hash, quorum_entry) in hash_to_quorum_entries {
                inner.insert(*quorum_hash, self.validate_quorum(quorum_entry));
            }
            results.insert(*quorum_type, inner);
        }

        // Collect updates to avoid mutable borrow conflicts
        let mut updates: Vec<(CoreBlockHeight, LLMQType, QuorumHash, LLMQEntryVerificationStatus)> =
            Vec::new();

        let Some(masternode_list) = self.masternode_lists.get_mut(&block_height) else {
            return Err(QuorumValidationError::VerifyingMasternodeListNotPresent(block_height));
        };

        for (quorum_type, hash_to_quorum_entries) in &mut masternode_list.quorums {
            if exclude_quorum_types.contains(quorum_type) {
                continue;
            }

            let masternode_lists_having_quorum_hash_for_quorum_type =
                self.quorum_statuses.entry(*quorum_type).or_default();

            if quorum_type.is_rotating_quorum_type() {
                if let Some(cycle_hash) = hash_to_quorum_entries
                    .values()
                    .find(|quorum_entry| quorum_entry.quorum_entry.quorum_index == Some(0))
                    .map(|quorum_entry| quorum_entry.quorum_entry.quorum_hash)
                {
                    if let Some(cycle_quorums) = self.rotated_quorums_per_cycle.get(&cycle_hash) {
                        // Only update rotating quorum statuses based on last commitment entries
                        for quorum in cycle_quorums {
                            if let Some(quorum_entry) =
                                hash_to_quorum_entries.get_mut(&quorum.quorum_entry.quorum_hash)
                            {
                                quorum_entry.verified = quorum.verified.clone();
                            }

                            let (heights, _, status) =
                                masternode_lists_having_quorum_hash_for_quorum_type
                                    .entry(quorum.quorum_entry.quorum_hash)
                                    .or_insert((
                                        BTreeSet::default(),
                                        quorum.quorum_entry.quorum_public_key,
                                        LLMQEntryVerificationStatus::Unknown,
                                    ));

                            heights.insert(block_height);
                            *status = quorum.verified.clone();
                        }
                    }
                }
            } else {
                for (quorum_hash, quorum_entry) in hash_to_quorum_entries.iter_mut() {
                    let old_status = quorum_entry.verified.clone();
                    quorum_entry.update_quorum_status(
                        results.get_mut(quorum_type).unwrap().remove(quorum_hash).unwrap(),
                    );

                    let (heights, _, status) = masternode_lists_having_quorum_hash_for_quorum_type
                        .entry(*quorum_hash)
                        .or_insert((
                            BTreeSet::default(),
                            quorum_entry.quorum_entry.quorum_public_key,
                            LLMQEntryVerificationStatus::Unknown,
                        ));

                    if old_status != quorum_entry.verified {
                        for height in heights.iter() {
                            updates.push((
                                *height,
                                *quorum_type,
                                *quorum_hash,
                                quorum_entry.verified.clone(),
                            ));
                        }
                    }

                    heights.insert(block_height);
                    *status = quorum_entry.verified.clone();
                }
            }
        }

        for (height, quorum_type, quorum_hash, new_status) in updates {
            if let Some(masternode_list_at_height) = self.masternode_lists.get_mut(&height) {
                if let Some(quorum_entry_at_height) = masternode_list_at_height
                    .quorums
                    .get_mut(&quorum_type)
                    .and_then(|quorums| quorums.get_mut(&quorum_hash))
                {
                    quorum_entry_at_height.verified = new_status;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
    use crate::sml::llmq_type::LLMQType;
    use crate::sml::llmq_type::LLMQType::{Llmqtype50_60, Llmqtype400_60, Llmqtype400_85};
    use crate::sml::masternode_list_engine::MasternodeListEngine;

    #[test]
    fn deserialize_mn_list_engine_and_validate_non_rotated_quorums() {
        let block_hex =
            include_str!("../../../tests/data/test_DML_diffs/masternode_list_engine.hex");
        let data = hex::decode(block_hex).expect("decode hex");
        let mut mn_list_engine: MasternodeListEngine =
            bincode::decode_from_slice(&data, bincode::config::standard())
                .expect("expected to decode")
                .0;

        assert_eq!(mn_list_engine.masternode_lists.len(), 29);

        let last_masternode_list_height =
            *mn_list_engine.masternode_lists.last_key_value().unwrap().0;

        mn_list_engine
            .verify_non_rotating_masternode_list_quorums(
                last_masternode_list_height,
                &[Llmqtype50_60, Llmqtype400_85],
            )
            .expect("expected to verify quorums");

        let last_masternode_list = mn_list_engine.masternode_lists.last_key_value().unwrap().1;

        for (quorum_type, quorum_entries) in last_masternode_list.quorums.iter() {
            if *quorum_type == Llmqtype400_85
                || *quorum_type == Llmqtype50_60
                || *quorum_type == Llmqtype400_60
                || *quorum_type == LLMQType::Llmqtype60_75
            {
                continue;
            }
            for (quorum_hash, quorum) in quorum_entries.iter() {
                let (_, known_block_height) = mn_list_engine
                    .masternode_list_and_height_for_block_hash_8_blocks_ago(
                        &quorum.quorum_entry.quorum_hash,
                    )
                    .expect("expected to find validating masternode");
                assert_eq!(
                    quorum.verified,
                    LLMQEntryVerificationStatus::Verified,
                    "could not verify quorum {} of type {} with masternode list {}",
                    quorum_hash,
                    quorum.quorum_entry.llmq_type,
                    known_block_height
                );
            }
        }
    }

    // These are no longer needed and would slow down the CI, however we keep them here in case we would ever need to debug
    // an issue.
    //
    // #[test]
    // fn deserialize_mn_list_engine_and_validate_single_quorum_all_signed_all_members_valid() {
    //     let block_hex = include_str!("../../../tests/data/test_DML_diffs/masternode_list_engine.hex");
    //     let data = hex::decode(block_hex).expect("decode hex");
    //     let mn_list_engine: MasternodeListEngine = bincode::decode_from_slice(&data, bincode::config::standard()).expect("expected to decode").0;
    //
    //     let last_masternode_list_height = *mn_list_engine.masternode_lists.last_key_value().unwrap().0;
    //
    //     let last_masternode_list = mn_list_engine.masternode_lists.last_key_value().unwrap().1;
    //
    //     let quorum = last_masternode_list.quorum_entry_of_type_for_quorum_hash(Llmqtype100_67, QuorumHash::from_str("000000000000001d4ebc43dbf9b25d2af6421641a84a1e04dd58f65d07b7ecf7").expect("expected to get quorum hash")).expect("expected to find quorum");
    //
    //     assert_eq!(mn_list_engine.validate_quorum(quorum), Ok(()));
    // }
    //
    // #[test]
    // fn deserialize_mn_list_engine_and_validate_single_quorum_one_didnt_sign_all_members_valid() {
    //     let block_hex = include_str!("../../../tests/data/test_DML_diffs/masternode_list_engine.hex");
    //     let data = hex::decode(block_hex).expect("decode hex");
    //     let mn_list_engine: MasternodeListEngine = bincode::decode_from_slice(&data, bincode::config::standard()).expect("expected to decode").0;
    //
    //     let last_masternode_list_height = *mn_list_engine.masternode_lists.last_key_value().unwrap().0;
    //
    //     let last_masternode_list = mn_list_engine.masternode_lists.last_key_value().unwrap().1;
    //
    //     let quorum = last_masternode_list.quorum_entry_of_type_for_quorum_hash(Llmqtype100_67, QuorumHash::from_str("0000000000000003e463cb405c672f2daaacf461fe733c33d5de8298ae6040a2").expect("expected to get quorum hash")).expect("expected to find quorum");
    //
    //     assert_eq!(mn_list_engine.validate_quorum(quorum), Ok(()));
    // }
    //
    // #[test]
    // fn deserialize_mn_list_engine_and_validate_single_quorum_one_didnt_sign_one_member_not_valid_valid() {
    //     let block_hex = include_str!("../../../tests/data/test_DML_diffs/masternode_list_engine.hex");
    //     let data = hex::decode(block_hex).expect("decode hex");
    //     let mn_list_engine: MasternodeListEngine = bincode::decode_from_slice(&data, bincode::config::standard()).expect("expected to decode").0;
    //
    //     let last_masternode_list_height = *mn_list_engine.masternode_lists.last_key_value().unwrap().0;
    //
    //     let last_masternode_list = mn_list_engine.masternode_lists.last_key_value().unwrap().1;
    //
    //     let quorum = last_masternode_list.quorum_entry_of_type_for_quorum_hash(Llmqtype100_67, QuorumHash::from_str("0000000000000009d64e57a20b56af7fe8cf8cdff1eea78fdf30ef8429c35d43").expect("expected to get quorum hash")).expect("expected to find quorum");
    //
    //     assert_eq!(mn_list_engine.validate_quorum(quorum), Ok(()));
    // }

    #[test]
    fn deserialize_mn_list_engine_and_validate_rotated_quorums_individually() {
        let block_hex =
            include_str!("../../../tests/data/test_DML_diffs/masternode_list_engine.hex");
        let data = hex::decode(block_hex).expect("decode hex");
        let mn_list_engine: MasternodeListEngine =
            bincode::decode_from_slice(&data, bincode::config::standard())
                .expect("expected to decode")
                .0;

        for (cycle_hash, quorums) in mn_list_engine.rotated_quorums_per_cycle.iter() {
            for (i, quorum) in quorums.iter().enumerate() {
                mn_list_engine.validate_quorum(quorum).expect(
                    format!("expected to validate quorum {} in cycle hash {}", i, cycle_hash)
                        .as_str(),
                );
            }
        }
    }

    #[test]
    fn deserialize_mn_list_engine_and_validate_rotated_quorums_collectively() {
        let block_hex =
            include_str!("../../../tests/data/test_DML_diffs/masternode_list_engine.hex");
        let data = hex::decode(block_hex).expect("decode hex");
        let mn_list_engine: MasternodeListEngine =
            bincode::decode_from_slice(&data, bincode::config::standard())
                .expect("expected to decode")
                .0;

        for quorums in mn_list_engine.rotated_quorums_per_cycle.values() {
            mn_list_engine
                .validate_rotation_cycle_quorums(quorums.iter().collect::<Vec<_>>().as_slice())
                .expect("expected to validated quorums");
        }
    }
}
