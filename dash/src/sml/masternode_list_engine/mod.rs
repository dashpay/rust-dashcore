mod helpers;
#[cfg(feature = "message_verification")]
mod message_request_verification;
mod non_rotated_quorum_construction;
mod rotated_quorum_construction;
#[cfg(feature = "quorum_validation")]
mod validation;

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::Network;
use crate::bls_sig_utils::{BLSPublicKey, BLSSignature};
use crate::network::constants::NetworkExt;
use crate::network::message_qrinfo::{QRInfo, QuorumSnapshot};
use crate::network::message_sml::MnListDiff;
use crate::prelude::CoreBlockHeight;
use crate::sml::error::SmlError;
use crate::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use crate::sml::llmq_type::LLMQType;
#[cfg(feature = "quorum_validation")]
use crate::sml::llmq_type::network::NetworkLLMQExt;
use crate::sml::masternode_list::MasternodeList;
use crate::sml::masternode_list::from_diff::TryIntoWithBlockHashLookup;
use crate::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
#[cfg(feature = "quorum_validation")]
use crate::sml::quorum_entry::qualified_quorum_entry::VerifyingChainLockSignaturesType;
use crate::sml::quorum_validation_error::QuorumValidationError;
use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;
use crate::{BlockHash, QuorumHash};
#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use hashes::Hash;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Depth offset between cycle boundary and work block (matches Dash Core WORK_DIFF_DEPTH)
/// The mnListDiffH in QRInfo is at (cycle_height - WORK_DIFF_DEPTH), not at the cycle boundary itself
pub const WORK_DIFF_DEPTH: u32 = 8;

/// Identifies one of the rotation ChainLock signature slots carried by a QRInfo
/// response. Each slot corresponds to one per-cycle diff in the rotation quorum
/// formation proof: three historical cycles, the h diff, and the tip.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub(crate) enum RotationChainLockSignatureSlot {
    HMinus3c,
    HMinus2c,
    HMinusC,
    H,
    Tip,
}

impl fmt::Display for RotationChainLockSignatureSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::HMinus3c => "h-3c",
            Self::HMinus2c => "h-2c",
            Self::HMinusC => "h-c",
            Self::H => "h",
            Self::Tip => "tip",
        };
        f.write_str(name)
    }
}

/// Transient observability report returned from [`MasternodeListEngine::feed_qr_info`].
/// Not persisted; lives only for the duration of the call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QRInfoFeedResult {
    /// Total number of rotated quorums in `last_commitment_per_index`.
    pub rotated_quorum_count: usize,
    /// Rotated quorums for which no cached `QualifiedQuorumEntry` existed and one
    /// was constructed fresh. Incremented independently of `verify_rotated_quorums`
    /// and the final verification outcome. Pair with `fully_verified_count` to
    /// distinguish cache-hit observability from a trust signal.
    pub newly_qualified_count: usize,
    /// Rotated quorums whose `.verified` is `LLMQEntryVerificationStatus::Verified`
    /// after this call settled. Always `0` when `verify_rotated_quorums == false`.
    /// A cycle is only stored in `rotated_quorums_per_cycle` when every entry is
    /// `Verified`.
    pub fully_verified_count: usize,
    /// Height of the cycle from `last_commitment_per_index` if (and only if)
    /// the storage gate fired and the cycle was inserted into
    /// `rotated_quorums_per_cycle`. `None` when storage was skipped because
    /// `last_commitment_per_index` was empty, the gate blocked the write, or
    /// the cycle hash had no resolvable height. The cycle stored by
    /// `validate_and_store_previous_cycle_quorums` is not reflected here.
    pub stored_cycle_height: Option<CoreBlockHeight>,
}

impl QRInfoFeedResult {
    /// Returns true when every rotated quorum in this QRInfo settled as
    /// `LLMQEntryVerificationStatus::Verified`, the exact condition under which
    /// `feed_qr_info` stores the cycle in `rotated_quorums_per_cycle`. Use this
    /// as the trust gate for callers that need to know the cycle is fully
    /// validated.
    pub fn all_fully_verified(&self) -> bool {
        self.rotated_quorum_count > 0 && self.fully_verified_count == self.rotated_quorum_count
    }
}

/// Returns the 4 rotation CL signatures when every slot is present, or `None`
/// when any slot is missing. On a miss, logs which slots were absent at debug
/// level under the given `cycle_label`.
#[cfg(feature = "quorum_validation")]
fn collect_rotation_sigs(
    slots: [(Option<BLSSignature>, RotationChainLockSignatureSlot); 4],
    cycle_label: &str,
) -> Option<[BLSSignature; 4]> {
    let missing: Vec<RotationChainLockSignatureSlot> =
        slots.iter().filter_map(|(sig, slot)| sig.is_none().then_some(*slot)).collect();
    if !missing.is_empty() {
        tracing::debug!(
            "QRInfo missing rotation ChainLock signatures: {:?}; \
             {} rotated quorums will not be stored",
            missing,
            cycle_label
        );
        return None;
    }
    let [a, b, c, d] = slots.map(|(sig, _)| sig);
    Some([a?, b?, c?, d?])
}

#[derive(Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct MasternodeListEngineBTreeMapBlockContainer {
    pub block_hashes: BTreeMap<CoreBlockHeight, BlockHash>,
    pub block_heights: BTreeMap<BlockHash, CoreBlockHeight>,
}

impl MasternodeListEngineBTreeMapBlockContainer {
    /// Stores a block height and its corresponding block hash in the container.
    ///
    /// # Parameters
    /// - `height`: The blockchain height (block number)
    /// - `block_hash`: The hash of the block at that height
    pub fn feed_block_height(&mut self, height: CoreBlockHeight, block_hash: BlockHash) {
        self.block_heights.insert(block_hash, height);
        self.block_hashes.insert(height, block_hash);
    }
}

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum MasternodeListEngineBlockContainer {
    BTreeMapContainer(MasternodeListEngineBTreeMapBlockContainer),
}

impl Default for MasternodeListEngineBlockContainer {
    fn default() -> Self {
        MasternodeListEngineBTreeMapBlockContainer::default().into()
    }
}

impl From<MasternodeListEngineBTreeMapBlockContainer> for MasternodeListEngineBlockContainer {
    fn from(value: MasternodeListEngineBTreeMapBlockContainer) -> Self {
        MasternodeListEngineBlockContainer::BTreeMapContainer(value)
    }
}

impl MasternodeListEngineBlockContainer {
    /// Retrieves the block height for a given block hash.
    ///
    /// # Parameters
    /// - `block_hash`: The hash of the block to look up
    ///
    /// # Returns
    /// The block height if found, or `None` if not in the container.
    /// Returns `Some(0)` for the genesis block (all zeros hash).
    pub fn get_height(&self, block_hash: &BlockHash) -> Option<CoreBlockHeight> {
        if block_hash.as_byte_array() == &[0; 32] {
            // rep
            Some(0)
        } else {
            match self {
                MasternodeListEngineBlockContainer::BTreeMapContainer(map) => {
                    map.block_heights.get(block_hash).copied()
                }
            }
        }
    }

    /// Retrieves the block hash for a given block height.
    ///
    /// # Parameters
    /// - `height`: The blockchain height to look up
    ///
    /// # Returns
    /// A reference to the block hash if found, or `None` if not in the container.
    pub fn get_hash(&self, height: &CoreBlockHeight) -> Option<&BlockHash> {
        match self {
            MasternodeListEngineBlockContainer::BTreeMapContainer(map) => {
                map.block_hashes.get(height)
            }
        }
    }

    /// Checks if the container has a block hash stored.
    ///
    /// # Parameters
    /// - `block`: The block hash to check for
    ///
    /// # Returns
    /// `true` if the block hash exists in the container, `false` otherwise.
    pub fn contains_hash(&self, block: &BlockHash) -> bool {
        match self {
            MasternodeListEngineBlockContainer::BTreeMapContainer(map) => {
                map.block_heights.contains_key(block)
            }
        }
    }

    /// Checks if the container has a block height stored.
    ///
    /// # Parameters
    /// - `height`: The block height to check for
    ///
    /// # Returns
    /// `true` if the block height exists in the container, `false` otherwise.
    pub fn contains_height(&self, height: &CoreBlockHeight) -> bool {
        match self {
            MasternodeListEngineBlockContainer::BTreeMapContainer(map) => {
                map.block_hashes.contains_key(height)
            }
        }
    }

    /// Stores a block height and its corresponding block hash in the container.
    ///
    /// # Parameters
    /// - `height`: The blockchain height (block number)
    /// - `block_hash`: The hash of the block at that height
    pub fn feed_block_height(&mut self, height: CoreBlockHeight, block_hash: BlockHash) {
        match self {
            MasternodeListEngineBlockContainer::BTreeMapContainer(map) => {
                map.feed_block_height(height, block_hash)
            }
        }
    }

    /// Returns the total number of blocks stored in the container.
    ///
    /// # Returns
    /// The count of block height/hash pairs stored.
    pub fn known_block_count(&self) -> usize {
        match self {
            MasternodeListEngineBlockContainer::BTreeMapContainer(map) => map.block_hashes.len(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct MasternodeListEngine {
    pub block_container: MasternodeListEngineBlockContainer,
    pub masternode_lists: BTreeMap<CoreBlockHeight, MasternodeList>,
    pub known_snapshots: BTreeMap<BlockHash, QuorumSnapshot>,
    pub rotated_quorums_per_cycle: BTreeMap<BlockHash, BTreeMap<u16, QualifiedQuorumEntry>>,
    #[allow(clippy::type_complexity)]
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
            block_container: Default::default(),
            masternode_lists: Default::default(),
            known_snapshots: Default::default(),
            rotated_quorums_per_cycle: Default::default(),
            quorum_statuses: Default::default(),
            network: Network::Mainnet,
        }
    }
}

/// Builds a per-cycle quorum map keyed by `quorum_index`.
/// Rejects missing, negative, or duplicate indices and validates the final count.
#[cfg(feature = "quorum_validation")]
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
        let key =
            u16::try_from(quorum_index).map_err(|_| QuorumValidationError::InvalidQuorumIndex {
                quorum_hash: quorum.quorum_entry.quorum_hash,
                index: quorum_index,
            })?;
        if (key as usize) >= expected {
            return Err(QuorumValidationError::InvalidQuorumIndex {
                quorum_hash: quorum.quorum_entry.quorum_hash,
                index: quorum_index,
            });
        }
        if map.contains_key(&key) {
            return Err(QuorumValidationError::CorruptedCodeExecution(format!(
                "duplicate quorum_index {key} in rotation cycle"
            )));
        }
        map.insert(key, quorum);
    }
    if map.len() != expected {
        return Err(QuorumValidationError::CorruptedCodeExecution(format!(
            "rotated quorums per cycle count mismatch: expected {expected}, got {}",
            map.len()
        )));
    }
    Ok(map)
}

impl MasternodeListEngine {
    /// Creates a new MasternodeListEngine with the specified network configuration.
    ///
    /// # Parameters
    /// - `network`: The Dash network (mainnet, testnet, etc.)
    ///
    /// # Returns
    /// A new MasternodeListEngine instance configured for the specified network.
    pub fn default_for_network(network: Network) -> Self {
        Self {
            network,
            ..Default::default()
        }
    }
    /// Initializes a new MasternodeListEngine with a masternode list diff.
    ///
    /// # Parameters
    /// - `masternode_list_diff`: The initial masternode list diff to apply
    /// - `block_height`: The block height where this diff applies
    /// - `network`: The Dash network configuration
    ///
    /// # Returns
    /// A new MasternodeListEngine instance or an error if initialization fails.
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
            block_container: MasternodeListEngineBTreeMapBlockContainer {
                block_hashes: [(0, base_block_hash), (block_height, block_hash)].into(),
                block_heights: [(base_block_hash, 0), (block_hash, block_height)].into(),
            }
            .into(),
            masternode_lists: [(block_height, masternode_list)].into(),
            known_snapshots: Default::default(),
            rotated_quorums_per_cycle: Default::default(),
            quorum_statuses: Default::default(),
            network,
        })
    }

    /// Gets the most recent masternode list.
    ///
    /// # Returns
    /// A reference to the latest masternode list, or `None` if no lists are stored.
    pub fn latest_masternode_list(&self) -> Option<&MasternodeList> {
        self.masternode_lists.last_key_value().map(|(_, list)| list)
    }

    /// Gets all quorum hashes from the latest masternode list.
    ///
    /// # Parameters
    /// - `exclude_quorum_types`: Types of quorums to exclude from the result
    ///
    /// # Returns
    /// A set of quorum hashes from the latest masternode list.
    pub fn latest_masternode_list_quorum_hashes(
        &self,
        exclude_quorum_types: &[LLMQType],
    ) -> BTreeSet<QuorumHash> {
        self.latest_masternode_list()
            .map(|list| list.quorum_hashes(exclude_quorum_types))
            .unwrap_or_default()
    }

    /// Gets non-rotating quorum hashes from the latest masternode list.
    ///
    /// # Parameters
    /// - `exclude_quorum_types`: Types of quorums to exclude
    /// - `only_return_block_hashes_with_missing_masternode_lists_from_engine`: If true, only returns hashes for blocks missing from the engine
    ///
    /// # Returns
    /// A set of non-rotating quorum hashes.
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
                            let Some(block_height) = self.block_container.get_height(quorum_hash)
                            else {
                                return true;
                            };
                            !self.masternode_lists.contains_key(&block_height)
                        })
                        .collect()
                } else {
                    list.non_rotating_quorum_hashes(exclude_quorum_types)
                }
            })
            .unwrap_or_default()
    }

    /// Gets non-rotating quorum hashes from a masternode list at a specific height.
    ///
    /// # Parameters
    /// - `height`: The block height to get quorum hashes for
    /// - `exclude_quorum_types`: Types of quorums to exclude
    /// - `only_return_block_hashes_with_missing_masternode_lists_from_engine`: If true, only returns hashes for blocks missing from the engine
    ///
    /// # Returns
    /// A set of non-rotating quorum hashes at the specified height.
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
                            let Some(block_height) = self.block_container.get_height(quorum_hash)
                            else {
                                return true;
                            };
                            !self.masternode_lists.contains_key(&block_height)
                        })
                        .collect()
                } else {
                    list.non_rotating_quorum_hashes(exclude_quorum_types)
                }
            })
            .unwrap_or_default()
    }

    /// Gets rotating quorum hashes from the latest masternode list.
    ///
    /// # Parameters
    /// - `exclude_quorum_types`: Types of quorums to exclude from the result
    ///
    /// # Returns
    /// A set of rotating quorum hashes from the latest masternode list.
    pub fn latest_masternode_list_rotating_quorum_hashes(
        &self,
        exclude_quorum_types: &[LLMQType],
    ) -> BTreeSet<QuorumHash> {
        self.latest_masternode_list()
            .map(|list| list.rotating_quorum_hashes(exclude_quorum_types))
            .unwrap_or_default()
    }

    /// Gets the masternode list for a specific block hash.
    ///
    /// # Parameters
    /// - `block_hash`: The block hash to look up
    ///
    /// # Returns
    /// A reference to the masternode list for that block, or `None` if not found.
    pub fn masternode_list_for_block_hash(
        &self,
        block_hash: &BlockHash,
    ) -> Option<&MasternodeList> {
        self.block_container
            .get_height(block_hash)
            .and_then(|height| self.masternode_lists.get(&height))
    }

    /// Finds a known qualified quorum entry matching the given quorum entry.
    ///
    /// # Parameters
    /// - `quorum_entry`: The quorum entry to search for
    ///
    /// # Returns
    /// The qualified quorum entry if found, or `None` if not found.
    pub fn known_qualified_quorum_entry(
        &self,
        quorum_entry: &QuorumEntry,
    ) -> Option<QualifiedQuorumEntry> {
        // Iterate over rotated_quorums_per_cycle to find the quorum_entry with the same hash
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

    /// Stores a block height and hash mapping in the engine's block container.
    ///
    /// # Parameters
    /// - `height`: The blockchain height (block number)
    /// - `block_hash`: The hash of the block at that height
    pub fn feed_block_height(&mut self, height: CoreBlockHeight, block_hash: BlockHash) {
        self.block_container.feed_block_height(height, block_hash)
    }

    /// Loads the rotation quorums from the MN list at the h work block, attaches
    /// the captured CL signatures, and returns them along with the cycle hash
    /// they should be stored under. Returns `None` when prerequisite state is
    /// not yet loaded, when the MN list carries no rotating quorums, or when
    /// the cycle is already stored. All three cases are expected on a fresh
    /// sync and not errors.
    #[cfg(feature = "quorum_validation")]
    fn try_load_previous_cycle_entries(
        &self,
        work_block_hash: BlockHash,
        isd_type: LLMQType,
        sigs: [BLSSignature; 4],
    ) -> Option<(QuorumHash, Vec<QualifiedQuorumEntry>)> {
        let work_height = self.block_container.get_height(&work_block_hash)?;
        let mn_list = self.masternode_lists.get(&work_height)?;
        let quorums_of_type = mn_list.quorums.get(&isd_type)?;
        let cycle_hash = quorums_of_type
            .values()
            .find(|q| q.quorum_entry.quorum_index == Some(0))
            .map(|q| q.quorum_entry.quorum_hash)?;
        if self.rotated_quorums_per_cycle.contains_key(&cycle_hash) {
            return None;
        }
        let entries: Vec<QualifiedQuorumEntry> = quorums_of_type
            .values()
            .cloned()
            .map(|mut q| {
                q.verifying_chain_lock_signature =
                    Some(VerifyingChainLockSignaturesType::Rotating(sigs));
                q
            })
            .collect();
        Some((cycle_hash, entries))
    }

    /// Validate and store rotated quorums from the MN list at the h work block
    /// under their cycle boundary hash. This enables IS lock verification for
    /// the previous cycle after a fresh sync where `lastCommitmentPerIndex`
    /// only provides the current cycle's quorums.
    ///
    /// The 4 CL sigs `[sig_h_minus_3c, sig_h_minus_2c, sig_h_minus_c, sig_h]`
    /// captured by `feed_qr_info` align with the h-c cycle's quarters: the
    /// per-diff extraction yields sig_h_minus_3c from h-4c work block (quarter
    /// 0), sig_h_minus_2c from h-3c (quarter 1), sig_h_minus_c from h-2c
    /// (quarter 2), sig_h from h-c (quarter 3).
    #[cfg(feature = "quorum_validation")]
    fn validate_and_store_previous_cycle_quorums(
        &mut self,
        work_block_hash: BlockHash,
        sigs: [BLSSignature; 4],
    ) -> Result<(), QuorumValidationError> {
        let isd_type = self.network.isd_llmq_type();
        let Some((cycle_hash, mut entries)) =
            self.try_load_previous_cycle_entries(work_block_hash, isd_type, sigs)
        else {
            return Ok(());
        };

        let validation_statuses = self.validate_rotation_cycle_quorums_validation_statuses(
            entries.iter().collect::<Vec<_>>().as_slice(),
        );
        let mut all_verified = true;
        for entry in entries.iter_mut() {
            entry.verified = validation_statuses
                .get(&entry.quorum_entry.quorum_hash)
                .cloned()
                .unwrap_or_default();
            match entry.verified {
                LLMQEntryVerificationStatus::Verified => {}
                LLMQEntryVerificationStatus::Invalid(ref e) => return Err(e.clone()),
                _ => {
                    // Can't fully validate (e.g. MN list at a required work
                    // block is missing because it's deeper than the QRInfo's
                    // diff range). Don't store unverified quorums: IS lock
                    // verification for this cycle will fail, which is correct.
                    tracing::debug!(
                        "Previous-cycle quorum {} at cycle {} could not be validated ({}); skipping storage",
                        entry.quorum_entry.quorum_hash,
                        cycle_hash,
                        entry.verified
                    );
                    all_verified = false;
                    break;
                }
            }
        }
        if !all_verified {
            return Ok(());
        }

        // Mirror statuses into `quorum_statuses` and the MN list.
        let mut updates: Vec<(BTreeSet<CoreBlockHeight>, QuorumHash, LLMQEntryVerificationStatus)> =
            Vec::new();
        {
            let statuses_for_type = self.quorum_statuses.entry(isd_type).or_default();
            for entry in entries.iter() {
                let (heights, _, status) =
                    statuses_for_type.entry(entry.quorum_entry.quorum_hash).or_insert((
                        BTreeSet::default(),
                        entry.quorum_entry.quorum_public_key,
                        LLMQEntryVerificationStatus::Unknown,
                    ));
                updates.push((
                    heights.clone(),
                    entry.quorum_entry.quorum_hash,
                    entry.verified.clone(),
                ));
                *status = entry.verified.clone();
            }
        }
        for (heights, quorum_hash, new_status) in updates {
            for height in heights {
                if let Some(list_at_height) = self.masternode_lists.get_mut(&height)
                    && let Some(quorum_at_height) = list_at_height
                        .quorums
                        .get_mut(&isd_type)
                        .and_then(|qs| qs.get_mut(&quorum_hash))
                {
                    quorum_at_height.verified = new_status.clone();
                }
            }
        }

        let cycle_map = build_cycle_quorum_map(entries, isd_type)?;
        self.rotated_quorums_per_cycle.insert(cycle_hash, cycle_map);
        tracing::debug!(
            "Validated and stored previous-cycle rotated quorums under cycle hash {}",
            cycle_hash
        );
        Ok(())
    }

    /// Block hashes referenced by a QRInfo message that the engine needs heights for.
    ///
    /// Covers every diff endpoint (base and target) and every rotating commitment hash
    /// carried in the QRInfo. When an h-4c diff is present, rotating quorums in
    /// `mn_list_diff_h.new_quorums` are also included so the previous cycle can be
    /// revalidated.
    pub fn qr_info_referenced_block_hashes(qr_info: &QRInfo) -> BTreeSet<BlockHash> {
        let mut hashes = BTreeSet::new();

        for diff in [
            &qr_info.mn_list_diff_tip,
            &qr_info.mn_list_diff_h,
            &qr_info.mn_list_diff_at_h_minus_c,
            &qr_info.mn_list_diff_at_h_minus_2c,
            &qr_info.mn_list_diff_at_h_minus_3c,
        ] {
            hashes.insert(diff.base_block_hash);
            hashes.insert(diff.block_hash);
        }

        if let Some((_, diff)) = &qr_info.quorum_snapshot_and_mn_list_diff_at_h_minus_4c {
            hashes.insert(diff.base_block_hash);
            hashes.insert(diff.block_hash);

            for quorum_entry in &qr_info.mn_list_diff_h.new_quorums {
                if quorum_entry.llmq_type.is_rotating_quorum_type() {
                    hashes.insert(quorum_entry.quorum_hash);
                }
            }
        }

        for diff in &qr_info.mn_list_diff_list {
            hashes.insert(diff.base_block_hash);
            hashes.insert(diff.block_hash);
        }

        for quorum_entry in &qr_info.last_commitment_per_index {
            hashes.insert(quorum_entry.quorum_hash);
        }

        hashes
    }

    /// Processes and applies a QRInfo message to the masternode list engine.
    ///
    /// The caller is expected to pre-populate [`Self::block_container`] with heights
    /// for every hash referenced by the QRInfo before calling this; missing heights
    /// surface as `QuorumValidationError::RequiredBlockNotPresent` once they are
    /// actually needed.
    ///
    /// # Parameters
    /// - `qr_info`: The QRInfo message containing quorum snapshots and diffs
    /// - `verify_tip_non_rotated_quorums`: Whether to verify non-rotating quorums at the tip
    /// - `verify_rotated_quorums`: Whether to verify rotating quorums
    ///
    /// # Returns
    /// Result indicating success or a quorum validation error.
    pub fn feed_qr_info(
        &mut self,
        qr_info: QRInfo,
        verify_tip_non_rotated_quorums: bool,
        verify_rotated_quorums: bool,
    ) -> Result<Option<QRInfoFeedResult>, QuorumValidationError> {
        #[allow(unused_variables)]
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

        // When the tip is mid-cycle (before the DKG commitment is mined),
        // `sig_tip` will naturally be `None` but isn't needed for validating
        // the historical rotation quorums in `last_commitment_per_index`.
        // The check below selects which 4-sig tuple `rotation_sigs` aligns
        // to: current cycle when this is true, previous cycle otherwise.
        #[cfg(feature = "quorum_validation")]
        let tip_diff_has_rotating_quorums =
            mn_list_diff_tip.new_quorums.iter().any(|q| q.llmq_type.is_rotating_quorum_type());

        // Apply quorum snapshots and masternode list diffs
        for (snapshot, diff) in quorum_snapshot_list.into_iter().zip(mn_list_diff_list) {
            self.known_snapshots.insert(diff.block_hash, snapshot);
            self.apply_diff(diff, None, false, None)?;
        }

        #[cfg(feature = "quorum_validation")]
        let can_verify_previous = quorum_snapshot_and_mn_list_diff_at_h_minus_4c.is_some();

        #[cfg(feature = "quorum_validation")]
        let h_height = self.block_container.get_height(&mn_list_diff_h.block_hash).ok_or(
            QuorumValidationError::RequiredBlockNotPresent(
                mn_list_diff_h.block_hash,
                "getting height at diff h".to_string(),
            ),
        )?;

        #[cfg(feature = "quorum_validation")]
        let tip_height = self.block_container.get_height(&mn_list_diff_tip.block_hash).ok_or(
            QuorumValidationError::RequiredBlockNotPresent(
                mn_list_diff_tip.block_hash,
                "getting height at diff tip".to_string(),
            ),
        )?;

        #[cfg(feature = "quorum_validation")]
        let rotation_quorum_type = last_commitment_per_index
            .first()
            .map(|quorum_entry| quorum_entry.llmq_type)
            .unwrap_or(self.network.isd_llmq_type());

        #[cfg(feature = "quorum_validation")]
        let mut stored_cycle_height: Option<CoreBlockHeight> = None;
        #[cfg(feature = "quorum_validation")]
        let rotated_quorum_count = last_commitment_per_index.len();
        #[cfg(feature = "quorum_validation")]
        let mut newly_qualified_count: usize = 0;
        #[cfg(feature = "quorum_validation")]
        let mut fully_verified_count: usize = 0;
        if let Some((quorum_snapshot_at_h_minus_4c, mn_list_diff_at_h_minus_4c)) =
            quorum_snapshot_and_mn_list_diff_at_h_minus_4c
        {
            self.known_snapshots
                .insert(mn_list_diff_at_h_minus_4c.block_hash, quorum_snapshot_at_h_minus_4c);
            self.apply_diff(mn_list_diff_at_h_minus_4c, None, false, None)?;
        }

        self.known_snapshots
            .insert(mn_list_diff_at_h_minus_3c.block_hash, quorum_snapshot_at_h_minus_3c);
        let maybe_sig_h_minus_3c =
            self.apply_diff(mn_list_diff_at_h_minus_3c, None, false, None)?;
        self.known_snapshots
            .insert(mn_list_diff_at_h_minus_2c.block_hash, quorum_snapshot_at_h_minus_2c);
        let maybe_sig_h_minus_2c =
            self.apply_diff(mn_list_diff_at_h_minus_2c, None, false, None)?;
        self.known_snapshots
            .insert(mn_list_diff_at_h_minus_c.block_hash, quorum_snapshot_at_h_minus_c);
        let maybe_sig_h_minus_c = self.apply_diff(mn_list_diff_at_h_minus_c, None, false, None)?;
        // The h-c cycle's rotated quorums live on `masternode_lists[h]` (mined
        // in the `(h-c, h]` diff range), not on `masternode_lists[h-c]` where
        // the cycle two back resides; using h here is load-bearing for the
        // sig alignment in `validate_and_store_previous_cycle_quorums`.
        let work_block_hash_h = mn_list_diff_h.block_hash;
        let maybe_sig_h = self.apply_diff(mn_list_diff_h, None, false, None)?;

        let sigs = match (maybe_sig_h_minus_2c, maybe_sig_h_minus_c, maybe_sig_h) {
            (Some(s2), Some(s1), Some(s0)) => Some([s2, s1, s0]),
            _ => None,
        };

        let maybe_sig_tip =
            self.apply_diff(mn_list_diff_tip, None, verify_tip_non_rotated_quorums, sigs)?;

        // The 4 historical sigs `[sig_h_minus_3c..sig_h]` align with the h-c
        // cycle's 4 quarters (work blocks h-4c-8, h-3c-8, h-2c-8, h-c-8).
        #[cfg(feature = "quorum_validation")]
        if let (Some(s3), Some(s2), Some(s1), Some(s0)) =
            (maybe_sig_h_minus_3c, maybe_sig_h_minus_2c, maybe_sig_h_minus_c, maybe_sig_h)
        {
            self.validate_and_store_previous_cycle_quorums(work_block_hash_h, [s3, s2, s1, s0])?;
        }

        // Missing CL sigs are a legitimate state when a diff spans a range
        // with no successful rotating DKG: Dash Core's `BuildQuorumsDiff` only
        // emits mined-AND-active commitments into `new_quorums`, so failed
        // or null DKG commits leave `new_quorums` empty for that diff and
        // `apply_diff` returns no rotating sig for it. We log once and leave
        // `rotation_sigs = None`. Affected entries in `last_commitment_per_index`
        // are recorded without `VerifyingChainLockSignaturesType::Rotating` and
        // end up `Skipped(MissingRotationChainLockSigs)`, which keeps
        // them out of `rotated_quorums_per_cycle`. IS locks signed under such a
        // cycle cannot be verified by this SPV until a later QRInfo arrives
        // with complete sigs.
        #[cfg(feature = "quorum_validation")]
        let rotation_sigs: Option<[BLSSignature; 4]> = {
            let any_rotated_quorum_needs_fresh_validation = last_commitment_per_index
                .iter()
                .any(|quorum_entry| self.known_qualified_quorum_entry(quorum_entry).is_none());
            if !any_rotated_quorum_needs_fresh_validation {
                None
            } else if tip_diff_has_rotating_quorums {
                // Tip has new rotating quorums: `lastCommitmentPerIndex` is
                // from the current cycle. The 4 sigs align as
                // `[sig_h_minus_2c, sig_h_minus_c, sig_h, sig_tip]`.
                collect_rotation_sigs(
                    [
                        (maybe_sig_h_minus_2c, RotationChainLockSignatureSlot::HMinus2c),
                        (maybe_sig_h_minus_c, RotationChainLockSignatureSlot::HMinusC),
                        (maybe_sig_h, RotationChainLockSignatureSlot::H),
                        (maybe_sig_tip, RotationChainLockSignatureSlot::Tip),
                    ],
                    "current-cycle",
                )
            } else {
                // Tip has no new rotating quorums: `lastCommitmentPerIndex`
                // is from the previous cycle. The 4 sigs come from the
                // historical diffs `[sig_h_minus_3c, sig_h_minus_2c, sig_h_minus_c, sig_h]`.
                collect_rotation_sigs(
                    [
                        (maybe_sig_h_minus_3c, RotationChainLockSignatureSlot::HMinus3c),
                        (maybe_sig_h_minus_2c, RotationChainLockSignatureSlot::HMinus2c),
                        (maybe_sig_h_minus_c, RotationChainLockSignatureSlot::HMinusC),
                        (maybe_sig_h, RotationChainLockSignatureSlot::H),
                    ],
                    "previous-cycle",
                )
            }
        };

        #[cfg(feature = "quorum_validation")]
        let mut qualified_last_commitment_per_index = last_commitment_per_index
            .into_iter()
            .map(|quorum_entry| {
                if let Some(qualified_quorum_entry) =
                    self.known_qualified_quorum_entry(&quorum_entry)
                {
                    Ok(qualified_quorum_entry)
                } else {
                    newly_qualified_count += 1;
                    let mut qualified_quorum_entry: QualifiedQuorumEntry = quorum_entry.into();
                    if let Some([sig_h_minus_2c, sig_h_minus_c, sig_h, sig_tip]) = rotation_sigs {
                        qualified_quorum_entry.verifying_chain_lock_signature =
                            Some(VerifyingChainLockSignaturesType::Rotating([
                                sig_h_minus_2c,
                                sig_h_minus_c,
                                sig_h,
                                sig_tip,
                            ]));
                    }
                    Ok(qualified_quorum_entry)
                }
            })
            .collect::<Result<Vec<QualifiedQuorumEntry>, QuorumValidationError>>()?;

        #[cfg(feature = "quorum_validation")]
        if verify_rotated_quorums {
            let mut updates: Vec<(
                BTreeSet<CoreBlockHeight>,
                LLMQType,
                QuorumHash,
                LLMQEntryVerificationStatus,
            )> = Vec::new();

            let validation_statuses = self.validate_rotation_cycle_quorums_validation_statuses(
                qualified_last_commitment_per_index.iter().collect::<Vec<_>>().as_slice(),
            );

            for rotated_quorum in qualified_last_commitment_per_index.iter_mut() {
                tracing::debug!(
                    "  Current cycle quorum: hash={}, raw_quorum_index={:?}, map_key={:?}",
                    rotated_quorum.quorum_entry.quorum_hash,
                    rotated_quorum.quorum_entry.quorum_index,
                    rotated_quorum.quorum_entry.quorum_index.and_then(|i| u16::try_from(i).ok())
                );

                rotated_quorum.verified = validation_statuses
                    .get(&rotated_quorum.quorum_entry.quorum_hash)
                    .cloned()
                    .unwrap_or_default();

                if let LLMQEntryVerificationStatus::Invalid(ref e) = rotated_quorum.verified {
                    return Err(e.clone());
                }
            }

            let cycle_key =
                qualified_last_commitment_per_index.first().map(|q| q.quorum_entry.quorum_hash);

            for rotated_quorum in qualified_last_commitment_per_index.iter() {
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

            fully_verified_count = qualified_last_commitment_per_index
                .iter()
                .filter(|q| matches!(q.verified, LLMQEntryVerificationStatus::Verified))
                .count();

            if let Some(key) = cycle_key {
                // `rotated_quorums_per_cycle` is the authoritative map for IS
                // lock verification, so only store a cycle when every entry is
                // `Verified`. Skipped entries (e.g. from incomplete CL sigs or
                // missing context) cannot sign and must not enter the map. A
                // later QRInfo with complete context will store the cycle.
                // Also preserve an already-fully-Verified cycle across
                // subsequent QRInfo responses: a thin `mn_list_diff_h` can
                // produce Skipped entries that must not downgrade it.
                let already_fully_verified =
                    self.rotated_quorums_per_cycle.get(&key).is_some_and(|existing| {
                        !existing.is_empty()
                            && existing.values().all(|q| {
                                matches!(q.verified, LLMQEntryVerificationStatus::Verified)
                            })
                    });
                let all_entries_verified = qualified_last_commitment_per_index
                    .iter()
                    .all(|q| matches!(q.verified, LLMQEntryVerificationStatus::Verified));
                if all_entries_verified && !already_fully_verified {
                    let cycle_map = build_cycle_quorum_map(
                        qualified_last_commitment_per_index,
                        rotation_quorum_type,
                    )?;
                    *self.rotated_quorums_per_cycle.entry(key).or_default() = cycle_map;
                    stored_cycle_height = self.block_container.get_height(&key);
                }
            }

            // Apply collected updates after iteration to avoid borrow conflicts
            for (heights, quorum_type, quorum_hash, new_status) in updates {
                for height in heights {
                    if let Some(masternode_list_at_height) = self.masternode_lists.get_mut(&height)
                        && let Some(quorum_entry_at_height) = masternode_list_at_height
                            .quorums
                            .get_mut(&quorum_type)
                            .and_then(|quorums| quorums.get_mut(&quorum_hash))
                    {
                        quorum_entry_at_height.verified = new_status.clone();
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

                if let Some(masternode_list_at_h) = self.masternode_lists.get_mut(&h_height)
                    && let Some(rotated_quorums_at_h) =
                        masternode_list_at_h.quorums.get_mut(&rotation_quorum_type)
                {
                    for (quorum_hash, quorum_entry) in rotated_quorums_at_h.iter_mut() {
                        if let Some(new_status) = validation_statuses.get(quorum_hash)
                            && &quorum_entry.verified != new_status
                        {
                            quorum_entry.verified = new_status.clone();
                            let masternode_lists_having_quorum_hash_for_quorum_type =
                                self.quorum_statuses.entry(rotation_quorum_type).or_default();

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

                // Apply collected updates after iteration to avoid borrow conflicts
                for (heights, quorum_type, quorum_hash, new_status) in updates {
                    for height in heights {
                        if let Some(masternode_list_at_height) =
                            self.masternode_lists.get_mut(&height)
                            && let Some(quorum_entry_at_height) = masternode_list_at_height
                                .quorums
                                .get_mut(&quorum_type)
                                .and_then(|quorums| quorums.get_mut(&quorum_hash))
                        {
                            quorum_entry_at_height.verified = new_status.clone();
                        }
                    }
                }
            }
        } else if let Some(cycle_key) =
            qualified_last_commitment_per_index.first().map(|q| q.quorum_entry.quorum_hash)
        {
            fully_verified_count = qualified_last_commitment_per_index
                .iter()
                .filter(|q| matches!(q.verified, LLMQEntryVerificationStatus::Verified))
                .count();
            // Never overwrite an already-fully-Verified cycle with unverified entries from a
            // `verify_rotated_quorums == false` call.
            let already_fully_verified =
                self.rotated_quorums_per_cycle.get(&cycle_key).is_some_and(|existing| {
                    !existing.is_empty()
                        && existing
                            .values()
                            .all(|q| matches!(q.verified, LLMQEntryVerificationStatus::Verified))
                });
            let all_entries_verified = qualified_last_commitment_per_index
                .iter()
                .all(|q| matches!(q.verified, LLMQEntryVerificationStatus::Verified));
            if all_entries_verified && !already_fully_verified {
                let cycle_map = build_cycle_quorum_map(
                    qualified_last_commitment_per_index,
                    rotation_quorum_type,
                )?;
                *self.rotated_quorums_per_cycle.entry(cycle_key).or_default() = cycle_map;
                stored_cycle_height = self.block_container.get_height(&cycle_key);
            }
        }

        #[cfg(not(feature = "quorum_validation"))]
        if verify_rotated_quorums {
            return Err(QuorumValidationError::FeatureNotTurnedOn(
                "quorum validation feature is not turned on".to_string(),
            ));
        }

        #[cfg(feature = "quorum_validation")]
        {
            Ok(Some(QRInfoFeedResult {
                rotated_quorum_count,
                newly_qualified_count,
                fully_verified_count,
                stored_cycle_height,
            }))
        }
        #[cfg(not(feature = "quorum_validation"))]
        {
            Ok(None)
        }
    }

    /// Applies a masternode list diff to create or update a masternode list.
    ///
    /// # Parameters
    /// - `masternode_list_diff`: The diff to apply
    /// - `diff_end_height`: Optional height where the diff applies (will be looked up if None)
    /// - `verify_quorums`: Whether to verify quorums in the resulting list
    /// - `previous_chain_lock_sigs`: Optional previous chain lock signatures for rotation validation
    ///
    /// # Returns
    /// Result containing an optional BLS signature for rotation cycles, or an error.
    #[allow(unused_variables)]
    pub fn apply_diff(
        &mut self,
        masternode_list_diff: MnListDiff,
        diff_end_height: Option<CoreBlockHeight>,
        verify_quorums: bool,
        previous_chain_lock_sigs: Option<[BLSSignature; 3]>,
    ) -> Result<Option<BLSSignature>, SmlError> {
        if let Some(known_genesis_block_hash) = self
            .network
            .known_genesis_block_hash()
            .or_else(|| self.block_container.get_hash(&0).cloned())
            && (masternode_list_diff.base_block_hash == known_genesis_block_hash
                || masternode_list_diff.base_block_hash.as_byte_array() == &[0; 32])
        {
            // we are going from the start
            let block_hash = masternode_list_diff.block_hash;

            let masternode_list = masternode_list_diff.try_into_with_block_hash_lookup(
                |block_hash| diff_end_height.or(self.block_container.get_height(block_hash)),
                self.network,
            )?;

            let diff_end_height = match diff_end_height {
                None => self
                    .block_container
                    .get_height(&block_hash)
                    .ok_or(SmlError::BlockHashLookupFailed(block_hash))?,
                Some(diff_end_height) => {
                    self.block_container.feed_block_height(diff_end_height, block_hash);
                    diff_end_height
                }
            };
            self.masternode_lists.insert(diff_end_height, masternode_list);
            return Ok(None);
        }

        let Some(base_height) =
            self.block_container.get_height(&masternode_list_diff.base_block_hash)
        else {
            return Err(SmlError::BlockHashLookupFailed(masternode_list_diff.base_block_hash));
        };
        let Some(base_masternode_list) = self.masternode_lists.get(&base_height) else {
            return Err(SmlError::MissingStartMasternodeList(masternode_list_diff.base_block_hash));
        };

        let block_hash = masternode_list_diff.block_hash;

        let diff_end_height = match diff_end_height {
            None => self
                .block_container
                .get_height(&block_hash)
                .ok_or(SmlError::BlockHashLookupFailed(block_hash))?,
            Some(diff_end_height) => diff_end_height,
        };

        #[cfg(feature = "quorum_validation")]
        let rotation_sig = {
            let (mut masternode_list, rotation_sig) = base_masternode_list.apply_diff(
                masternode_list_diff.clone(),
                diff_end_height,
                previous_chain_lock_sigs,
                self.network,
            )?;
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
                                    && let Some(quorum_entry) = masternode_list_at_height
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
            rotation_sig
        };

        #[cfg(not(feature = "quorum_validation"))]
        let rotation_sig = {
            let (masternode_list, rotation_sig) = base_masternode_list.apply_diff(
                masternode_list_diff.clone(),
                diff_end_height,
                None,
                self.network,
            )?;
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
            rotation_sig
        };

        self.block_container.feed_block_height(diff_end_height, block_hash);

        Ok(rotation_sig)
    }

    /// Verifies non-rotating quorums in a masternode list at a specific block height.
    ///
    /// This function is only available when the `quorum_validation` feature is enabled.
    ///
    /// # Parameters
    /// - `block_height`: The block height containing the masternode list to verify
    /// - `exclude_quorum_types`: Types of quorums to exclude from verification
    ///
    /// # Returns
    /// Result indicating success or a quorum validation error.
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
                    && let Some(cycle_quorums) = self.rotated_quorums_per_cycle.get(&cycle_hash)
                {
                    // Only update rotating quorum statuses based on last commitment entries
                    for quorum in cycle_quorums.values() {
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
            if let Some(masternode_list_at_height) = self.masternode_lists.get_mut(&height)
                && let Some(quorum_entry_at_height) = masternode_list_at_height
                    .quorums
                    .get_mut(&quorum_type)
                    .and_then(|quorums| quorums.get_mut(&quorum_hash))
            {
                quorum_entry_at_height.verified = new_status;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::Network;
    use crate::consensus::deserialize;
    use crate::hashes::Hash;
    use crate::network::message_qrinfo::QRInfo;
    use crate::network::message_sml::MnListDiff;
    use crate::prelude::CoreBlockHeight;
    use crate::sml::llmq_entry_verification::{
        LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus,
    };
    use crate::sml::llmq_type::LLMQType;
    use crate::sml::llmq_type::LLMQType::{
        Llmqtype50_60, Llmqtype60_75, Llmqtype400_60, Llmqtype400_85,
    };
    use crate::sml::llmq_type::network::NetworkLLMQExt;
    use crate::sml::masternode_list::MasternodeList;
    use crate::sml::masternode_list_engine::{
        MasternodeListEngine, MasternodeListEngineBlockContainer,
    };
    use crate::sml::quorum_entry::qualified_quorum_entry::{
        QualifiedQuorumEntry, VerifyingChainLockSignaturesType,
    };
    #[cfg(feature = "quorum_validation")]
    use crate::sml::quorum_validation_error::QuorumValidationError;
    use std::collections::BTreeMap;

    #[cfg(feature = "quorum_validation")]
    use {
        super::build_cycle_quorum_map,
        crate::BlockHash,
        crate::QuorumHash,
        crate::Transaction,
        crate::bls_sig_utils::{BLSPublicKey, BLSSignature},
        crate::hash_types::QuorumVVecHash,
        crate::network::message_qrinfo::{MNSkipListMode, QuorumSnapshot},
        crate::transaction::special_transaction::quorum_commitment::QuorumEntry,
    };

    #[cfg(feature = "quorum_validation")]
    fn make_qualified_quorum_entry(
        llmq_type: LLMQType,
        quorum_index: Option<i16>,
    ) -> QualifiedQuorumEntry {
        QuorumEntry {
            version: 2,
            llmq_type,
            quorum_hash: QuorumHash::all_zeros(),
            quorum_index,
            signers: vec![true],
            valid_members: vec![true],
            quorum_public_key: BLSPublicKey::from([0; 48]),
            quorum_vvec_hash: QuorumVVecHash::all_zeros(),
            threshold_sig: BLSSignature::from([0; 96]),
            all_commitment_aggregated_signature: BLSSignature::from([0; 96]),
        }
        .into()
    }

    #[cfg(feature = "quorum_validation")]
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

        // Wrong count is rejected
        let quorums = vec![make_qualified_quorum_entry(ty, Some(0))];
        let err = build_cycle_quorum_map(quorums, ty).expect_err("wrong count should fail");
        assert!(matches!(err, QuorumValidationError::CorruptedCodeExecution(_)));
    }

    fn verify_masternode_list_quorums(
        mn_list_engine: &MasternodeListEngine,
        masternode_list: &MasternodeList,
        exclude_quorum_types: &[LLMQType],
    ) {
        for (quorum_type, quorum_entries) in masternode_list.quorums.iter() {
            if exclude_quorum_types.contains(quorum_type) {
                continue;
            }
            for (quorum_hash, quorum) in quorum_entries.iter() {
                if !quorum_type.is_rotating_quorum_type() {
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
                } else {
                    assert_eq!(
                        quorum.verified,
                        LLMQEntryVerificationStatus::Verified,
                        "could not verify rotating quorum {} of type {}",
                        quorum_hash,
                        quorum.quorum_entry.llmq_type,
                    );
                }
            }
        }
    }

    #[test]
    fn validate_from_mn_list_diff_chain_locks() {
        let mn_list_diff_bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin");
        // This one is serialized not with bincode, but with core consensus
        let diff: MnListDiff = deserialize(mn_list_diff_bytes).expect("expected to deserialize");
        let mut masternode_list_engine =
            MasternodeListEngine::initialize_with_diff_to_height(diff, 2227096, Network::Mainnet)
                .expect("expected to start engine");

        let mn_list_diff_bytes_2: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/mn_list_diff_2227096_2241332.bin");
        // This one is serialized not with bincode, but with core consensus
        let diff_2: MnListDiff =
            deserialize(mn_list_diff_bytes_2).expect("expected to deserialize");

        masternode_list_engine
            .apply_diff(diff_2, Some(2241332), false, None)
            .expect("expected to apply diff");

        // Map of expected quorum_hash -> expected_signature
        let expected_signatures: BTreeMap<&str, Vec<u8>> = BTreeMap::from([
            ("000000000000000fcc3b58235989afa1962b6d6f238a2201190452123231a704", hex::decode("8ba84befb59e4f16160ca69a5a4785b314bd3f2ed9ae435daacdba23b3079b0fabc909f159ec80243b8ccc4c95f63bdb1176749b83fffc429be426e899982bc50e15f4d923df91b341c2cfdf47620a7ee35502593b1484b9f444466e04da52fd").unwrap()),
            ("000000000000000887fa15abc502ec49ec3b318fd79fc7fdfda514f67b895009", hex::decode("b03d75ae15fdaa3fbc72cf548f3cece8be6ad266ae7f4f79755537c80fe0a4b641cf6391ac17105d97d602e86e81d4e80331f9b5fb616cec399230d4b9b7ef9896885b1ad78109973ad5855ea5684994740b7ed710b4b72173c5e170b3df2a46").unwrap()),
            ("00000000000000133c9d6e64823bdfd80d7640b255faea18ce1d6419b55e3314", hex::decode("909ca60a8923b631d7d939d005431097a6974eef0e03a09a58c8e6a846c74ca94720eeda407cb20271e8f6e12ec23d0905da732fd1a50e8d1df414aad2094e28eb6dc24b64338add8e6085590c4c5849a9003eeaee91408f5bd4b41eaf1039e3").unwrap()),
            ("00000000000000179e5ed3711a8257dcbb0d17f7d5c52c92a9a122ca574f7b1c", hex::decode("885a2ba9ad907d9421c38af7aec35dff7be85d1788ccaef760056e1eef890b83b8a8e1e898dade5d3f52cfbc3b7b9eb5188d15283a43b68fcc1c75920727597ab905a0c18d9d9c335dc66a5cbeb1874f5bb54c4219096800ccfe3dacf3240fe6").unwrap()),
            ("0000000000000014a54ccad3b51e1fc6fded48dea59c5dbc17bcb58b5aa95320", hex::decode("8d9bc1065ff57b53302667a1564955ec32e823c0e74272e2e6f45e9bce3f9555bc772ce636cdc0e7ba15bd2f181f669a17e8893f0327fdb6e1af7e74cbdfaa96a630acbd161e110ee3e22dc788c96564ed754594f6d7b02447bf8ef0dae5a93c").unwrap()),
            ("000000000000000e7463a65d312855272e68bb03acd989ef36027d584951ca27", hex::decode("802f1cc00ded6f81d1904de5b5d8cfbf28a3165cc9f8f8569720293f400dc81a8427af171c31c63cc29d943c40a1545c03c8a3e3154573f166305f05dd8c7fac2b8abff00d950c042713a2b913748931e9a04fc757a7597f175dca96b753c4e8").unwrap()),
            ("00000000000000194f5c21458d718d8b1a2e11a6d4b3a1c1183d70123b8deb36", hex::decode("a46a067f15cb6525cfaa702b585f77115d59642a04032206430325db517522ce4076885859b591b5abcbe6843c1f08e502e4aad1f8124c1bab95ad0feaabe16dff1b0181dd8d7869d6be4e5cf82480cedb76471377c760016d56e5446fe9dc40").unwrap()),
            ("0000000000000009bd850bce5941826fdce7a2583644d6c197348b15151cb33c", hex::decode("97f84875bbe040af2ddd38e10c9df84cd2e0ddbc1caa693de2807e42209997f3ed9a6d2a23da02e255de409ae430d7fa121c61ae650b6654e0cabe6e3fe3e1bb557c48fdefb8a6a60d68d2d4ded7b6e4799567942529f3caafbc98a74d4359b8").unwrap()),
            ("0000000000000004d810f16edf5e672ee7fb4fe46342a9c28de54db62802334e", hex::decode("879326d10acd1f4299c87e5dfd7832913631afa90ef4aaa31e61d8e5d74b5ed3f1f461918b17cbf1a9a124667ceba0b00745f67b1eb127f5156fbf43145b973bf7ce56da3b3e6f99e5fee0fb863fdafeaa13bad78204933edf5dd74963d22c6b").unwrap()),
            ("0000000000000027727e5c45130cef688c056ad1ce1740b6eeb5e7a8a556d24f", hex::decode("829e508a99823b607256ab4297cacc1b7580d49e1e18a2af24aacf157c25f4195be9f7600507e3f5f4a502f08beeb75a048ff280a555705b899733431a7997ac6f98f63c259f83f65fa2548d23b42dbcbd3fcaf17fcdaee183c354f1cb046942").unwrap()),
            ("000000000000000e6d139ec023a1fbb12a7a19d7ab5db1c34322445494685b52", hex::decode("8d230edbed207dcb3ff28c72c14a72f1d79f6e8b8345ff6e7b71caa063750193dac0d8047fa89889f517d3579505282115b9078c6ca85cc66a91db407001c9247902456b239a721975f1930cea8e489fae5e2bc714445e86d3d7d58c6b86aa9f").unwrap()),
            ("000000000000002910000426717f2e2fe13659de4199ebd2ad0df8acaa40ec55", hex::decode("b82ac105dadd8f22edc80be0d9a3f0565735aec0f5350bd961d01e3b95ad8b6410a15cb97b99fc04e5cbc11e315c2af50eca9ac3829b2321c2c3043eed03f31a8ed91ca1dc25c45c06f74ad6ca399c7e6462bd96c75e4f688ae5fa28e09591db").unwrap()),
            ("00000000000000034d13700c17a966c7d4da13134d3928460922dc2122934d5f", hex::decode("aeabf173f885c401dd859d5e743dfa60106ac416e57d2870aa06241ad0133397b88484d7e9f95154a9167537e1dd524f18127854aa270088007b23155c22f6dd07d6696b2fea4599ed72b7be62e0bad519e296da38cd9db0b29dbcde5888be0c").unwrap()),
            ("00000000000000059bbc2b37c8d846653c3c7e213ca2507b74b1139fee57346b", hex::decode("b867cacbf145215502344a36a46839255b39c44129da259ad1eb1dab1c33b5ad6cd4e9a34f083590ed7a8153c12ed05c03f170b87dc16cff6a031519dbc60ae83a4713f8fdfeef7b1be66258b053b2865957b61a4d4cea445799a4cfe8ca7590").unwrap()),
            ("000000000000003c41c3b18552e0dbddd59ca4e9235ae6799c0f88d5d39b3375", hex::decode("b05f472ea28f41961dbadd4bfc33ad46120a8a5c082b46f88598f263f47033b252f5eb5fb10fd67cb9ca8790c56848550a06661332abc72cd1e1e9bb2e6cc63219f0b05faa981589cddc5dec57118db637c1819f5da023e78db930c4347e3799").unwrap()),
            ("0000000000000004beb237cb0c284418129d337ccbacf0ce4bcacaef052aa17b", hex::decode("8305847336eea1f9f502216ba03203b7614a4e6038b315a5342bc100a3bb9fc075df88415c5f9dcb88c35145e7ee44ba178012da65826fb4c6ab7c986dc50daccf383a57d8c8476dd864c24fb8a7c7c040a6dc57c238ee499733b6006b0611b4").unwrap()),
            ("0000000000000028c15e263548139cef64e9fcebc6d793bd9448d30797c14f80", hex::decode("a3c7d6d59248387269a928f4b37dad3f6559cae800acecf8e1502c5a7e2862d501013a91f30e7d7f2a63055adefeb7ae16de6020d4b6281c69b80381ee2e8c93b6a148d1934ac10cc71b5dd441bee988b2ee51022c345286ae4b241b149446bd").unwrap()),
            ("000000000000000ff31a80c31e6773c572e797cae876b6603b587915d738dc89", hex::decode("b8bbddd9f5214880d65cf7d096cb213b1f5bdd991669487e45812e4efaea8fe0cdc9642c7e9e9d4f8ebc0c1dd607c9eb19bdab1aed6eb4c52789ad7c41e2ce80fd1b8bef393b421089c9ab8b156b7917e3bd39c6b28b8e720212d94c2f7cf857").unwrap()),
            ("0000000000000019e3f9a338f32411d2f3e91e623b0bcbf327bca32b9ded4b9d", hex::decode("a12e8c68461a3248cc038ce50fc23ebfeae3718e10ee949e763deee0cde0b9e1a637b19ab18765604ef98be4a49ce6bc0525acb92db0defcfb57d993d0cf63ccc9f4378a11ed5a6707f791ded468a04daf4fa650a0e95689261615360faf80d3").unwrap()),
            ("0000000000000025b0f8b6cd855cab58429ee158ddfd32358ab55b98e53feaa2", hex::decode("b0f7402bd4c6c3926431d7c3bcb56ef52caf1d4edc7ab5d01ddd10ac6023aaccc9f336d22eb5c8e2930339875e9159cc0b54de90e5aa28d9bc4db4b3a7e5d6ea1c3c84b6817a5f13557d57b9f841494a831d8e58114710e853454847d1ab53d5").unwrap()),
            ("000000000000001912a0ac17300c5b7bfd1385a418137c3bc8d273ac3d9f85d7", hex::decode("ab751a79ea12c823745cccb7600b8aad50b72c0ac0d090e156a84755fe8a8eee9a8e57d076728428fa9d98f571be99d20a93090f1f310a78b66d26668672448b5e564a110640487ec508677faf1f79c14dcee34404e6d8c1c8037151f4ec7e4d").unwrap()),
            ("000000000000001d3789f5d1e7318b4350f20bdf1ea4beeeedf26780312114db", hex::decode("ac6edba765e86f2d3c86083c2919bd285e3a635413f2783a7261a0447a135827c73b635277265255cb678df3aa275986198a174c9fa39e499d0a26f45a7a8e3a7559ddebe200c13a96c060a5f7bc689d5fb93f68be9d6113d94acbbab714c52c").unwrap()),
            ("0000000000000010b28f1ea61bf3ff88cd2fef7e33a5f1868fb555ec682636eb", hex::decode("b96908533c42ecb7e540cec408f5d2aec93d97df37de695b9e92b50145a001153b3392c7aeab697a168e813c566dace007410e6159db92453732b067c0f22a2df413b113c47e43ace3906572db46b451565531c0a39a6ad9f5fb7e761273d7bb").unwrap()),
            ("0000000000000026d8a2480f338951dfedc5e7abdd3704500a10b4a188c89bf8", hex::decode("af13e196c300afce6ced40fa32851d1ff8646e2a1c0f03fc83cce88a44291a400fe8026dcb95edc9f2485b2596731c8e092fd313265269ffb5c5b0d13c4f0cda75ae69db27829c400cd25c2b55ca929ab8ac7a2b29f859e69800796c3d98c5a2").unwrap())
        ]);

        let masternode_list = masternode_list_engine
            .masternode_lists
            .get(&2241332)
            .expect("expected masternode list");

        let quorums = masternode_list
            .quorums
            .get(&LLMQType::Llmqtype100_67)
            .expect("expected quorums of type Llmqtype100_67");

        assert!(!quorums.is_empty(), "Expected at least one quorum");

        for (quorum_hash, quorum) in quorums {
            let quorum_hash_hex = format!("{:x}", quorum_hash);
            let Some(VerifyingChainLockSignaturesType::NonRotating(actual_signature)) =
                quorum.verifying_chain_lock_signature
            else {
                panic!("expected non rotating");
            };

            if let Some(expected_signature) = expected_signatures.get(quorum_hash_hex.as_str()) {
                let actual_sig_bytes = actual_signature.as_bytes();

                assert_eq!(
                    &actual_sig_bytes[..],
                    *expected_signature,
                    "Signature mismatch for quorum {}",
                    quorum_hash_hex
                );
            } else {
                panic!(
                    "Unexpected quorum hash {} found in test but not in expected values!",
                    quorum_hash_hex
                );
            }
        }
    }

    #[cfg(feature = "quorum_validation")]
    fn load_qrinfo_2240504_fixture() -> (MasternodeListEngine, QRInfo) {
        let mn_list_diff_bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin");
        let diff: MnListDiff = deserialize(mn_list_diff_bytes).expect("expected to deserialize");
        let mut engine =
            MasternodeListEngine::initialize_with_diff_to_height(diff, 2227096, Network::Mainnet)
                .expect("expected to start engine");

        let block_container_bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/block_container_2240504.dat");
        let block_container: MasternodeListEngineBlockContainer =
            bincode::decode_from_slice(block_container_bytes, bincode::config::standard())
                .expect("expected to decode")
                .0;
        let mn_list_diffs_bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/mnlistdiffs_2240504.dat");
        let mn_list_diffs: BTreeMap<(CoreBlockHeight, CoreBlockHeight), MnListDiff> =
            bincode::decode_from_slice(mn_list_diffs_bytes, bincode::config::standard())
                .expect("expected to decode")
                .0;
        let qr_info_bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/qrinfo_2240504.dat");
        let qr_info: QRInfo =
            bincode::decode_from_slice(qr_info_bytes, bincode::config::standard())
                .expect("expected to decode")
                .0;

        engine.block_container = block_container;
        for ((_start_height, height), diff) in mn_list_diffs.into_iter() {
            engine.apply_diff(diff, Some(height), false, None).expect("expected to apply diff");
        }

        (engine, qr_info)
    }

    #[test]
    fn validate_from_qr_info_and_mn_list_diffs() {
        let (mut masternode_list_engine, qr_info) = load_qrinfo_2240504_fixture();

        // The 2240504 fixture exercises the current-cycle storage branch
        // (rotating quorums in `mn_list_diff_tip`). A fixture swap that flips
        // this assertion changes which code path the test covers.
        let tip_diff_has_rotating_quorums = qr_info
            .mn_list_diff_tip
            .new_quorums
            .iter()
            .any(|q| q.llmq_type.is_rotating_quorum_type());
        assert!(
            tip_diff_has_rotating_quorums,
            "fixture invariant: 2240504 QRInfo must have rotating quorums in mn_list_diff_tip; \
             swap fixture or update assertion if this changes"
        );

        masternode_list_engine.feed_qr_info(qr_info, true, true).expect("expected to feed_qr_info");

        // Both cycles must be stored: the current cycle from
        // `last_commitment_per_index` and the previous cycle from
        // `validate_and_store_previous_cycle_quorums`. The previous-cycle
        // path uses `masternode_lists[h]`, not `masternode_lists[h-c]`,
        // because the h-c cycle is only mined in the `(h-c, h]` diff range.
        assert_eq!(
            masternode_list_engine.rotated_quorums_per_cycle.len(),
            2,
            "expected both tip and previous rotation cycles stored"
        );

        verify_masternode_list_quorums(
            &masternode_list_engine,
            masternode_list_engine
                .masternode_lists
                .last_key_value()
                .expect("expected a last master node list")
                .1,
            &[Llmqtype400_85, Llmqtype50_60, Llmqtype400_60],
        );

        // Every stored rotated quorum must re-validate under its captured CL
        // sigs. If the previous-cycle path picked the wrong work block, the
        // reconstructed members would not match the real signers and
        // `validate_quorum` would return `AllCommitmentAggregatedSignatureNotValid`.
        for (cycle_hash, quorums) in masternode_list_engine.rotated_quorums_per_cycle.iter() {
            for (index, quorum) in quorums.iter() {
                masternode_list_engine.validate_quorum(quorum).unwrap_or_else(|e| {
                    panic!(
                        "stored rotated quorum at index {} in cycle {} failed re-validation: {}",
                        index, cycle_hash, e
                    )
                });
            }
        }
    }

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

        let _last_masternode_list = mn_list_engine.masternode_lists.last_key_value().unwrap().1;

        verify_masternode_list_quorums(
            &mn_list_engine,
            mn_list_engine
                .masternode_lists
                .last_key_value()
                .expect("expected a last master node list")
                .1,
            &[Llmqtype400_85, Llmqtype50_60, Llmqtype400_60, Llmqtype60_75],
        );
    }

    #[test]
    fn deserialize_mn_list_engine_and_validate_non_rotated_quorums_when_reconstructing_chain_locks()
    {
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

        let _last_masternode_list = mn_list_engine.masternode_lists.last_key_value().unwrap().1;

        verify_masternode_list_quorums(
            &mn_list_engine,
            mn_list_engine
                .masternode_lists
                .last_key_value()
                .expect("expected a last master node list")
                .1,
            &[Llmqtype400_85, Llmqtype50_60, Llmqtype400_60, Llmqtype60_75],
        );
    }

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
            for (index, quorum) in quorums.iter() {
                mn_list_engine.validate_quorum(quorum).unwrap_or_else(|_| {
                    panic!(
                        "expected to validate quorum at index {} in cycle hash {}",
                        index, cycle_hash
                    )
                });
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
                .validate_rotation_cycle_quorums(quorums.values().collect::<Vec<_>>().as_slice())
                .expect("expected to validated quorums");
        }
    }

    #[test]
    fn feed_qr_info_rejects_post_v20_with_missing_chainlock_signatures() {
        let (mut masternode_list_engine, mut qr_info) = load_qrinfo_2240504_fixture();

        // Clear chainlock signatures to simulate missing data for post-V20 block
        qr_info.mn_list_diff_at_h_minus_2c.quorums_chainlock_signatures.clear();

        // feed_qr_info should fail for post-V20 blocks with missing signatures
        let result = masternode_list_engine.feed_qr_info(qr_info, false, false);

        assert!(
            result.is_err(),
            "Post-V20 feed_qr_info should reject missing chainlock signatures"
        );
        assert!(
            masternode_list_engine.rotated_quorums_per_cycle.is_empty(),
            "Rejected QRInfo must not have stored any rotation cycle"
        );
    }

    /// Storage gate: when a QRInfo carries no rotation chain-lock signatures
    /// and rotated quorums in `last_commitment_per_index` would need fresh
    /// validation, the cycle must NOT enter `rotated_quorums_per_cycle`. The
    /// validated entries are recorded as `Skipped` and storage is skipped.
    #[cfg(feature = "quorum_validation")]
    #[test]
    fn feed_qr_info_does_not_store_cycle_when_rotation_sigs_missing() {
        let (mut engine, mut qr_info) = load_qrinfo_2240504_fixture();

        // The post-V20 strict check requires every `new_quorums` slot to have
        // a matching `quorums_chainlock_signatures` entry; clearing both keeps
        // `apply_diff` happy while ensuring no per-diff rotating sig is captured.
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

        // The cycle key from `last_commitment_per_index` must still be present
        // so the post-feed assertion is meaningful.
        let expected_cycle_key = qr_info
            .last_commitment_per_index
            .first()
            .map(|q| q.quorum_hash)
            .expect("fixture has rotation commitments");

        let isd_type = engine.network.isd_llmq_type();

        engine
            .feed_qr_info(qr_info, false, true)
            .expect("feed_qr_info should succeed even when rotation sigs are missing");

        assert!(
            !engine.rotated_quorums_per_cycle.contains_key(&expected_cycle_key),
            "Cycle {} must not be stored when rotation sigs are missing; current keys: {:?}",
            expected_cycle_key,
            engine.rotated_quorums_per_cycle.keys().collect::<Vec<_>>()
        );

        // The skip status must be `MissingRotationChainLockSigs` specifically.
        // Storage could be blocked for unrelated reasons (e.g. a different
        // skip variant from missing context); this assertion proves the test
        // exercises the intended soft-skip path.
        let entry_status = engine
            .quorum_statuses
            .get(&isd_type)
            .and_then(|m| m.get(&expected_cycle_key))
            .map(|(_, _, status)| status.clone());
        assert!(
            matches!(
                entry_status,
                Some(LLMQEntryVerificationStatus::Skipped(
                    LLMQEntryVerificationSkipStatus::MissingRotationChainLockSigs(_)
                ))
            ),
            "expected MissingRotationChainLockSigs skip for {}, got {:?}",
            expected_cycle_key,
            entry_status
        );
    }

    /// A QRInfo whose rotated quorum carries a corrupt
    /// `all_commitment_aggregated_signature` must be rejected with
    /// `AllCommitmentAggregatedSignatureNotValid` rather than silently
    /// stored: a fully-Verified entry with an invalid aggregate signature
    /// would let bogus signed messages pass IS lock verification.
    #[cfg(feature = "quorum_validation")]
    #[test]
    fn feed_qr_info_rejects_corrupt_aggregate_signature() {
        let (mut engine, mut qr_info) = load_qrinfo_2240504_fixture();

        // Capture the target cycle key before mutation so we can assert it
        // never makes it into `rotated_quorums_per_cycle`. Other cycles (e.g.
        // the previous cycle from `validate_and_store_previous_cycle_quorums`)
        // may remain since they are stored before the rejection point.
        let target_key = qr_info
            .last_commitment_per_index
            .first()
            .map(|q| q.quorum_hash)
            .expect("fixture must carry at least one rotation commitment");

        // Precondition: the engine must know the height for `target_key` so
        // member reconstruction reaches the aggregate-signature check rather
        // than skipping for `RequiredBlockNotPresent`. Without this guard a
        // fixture change could mask a real signature-validation regression.
        assert!(
            engine.block_container.get_height(&target_key).is_some(),
            "fixture must carry block height for {} so the test exercises aggregate-signature validation",
            target_key
        );

        // Every other field stays intact so the entry still parses and reaches
        // signature validation.
        qr_info.last_commitment_per_index[0].all_commitment_aggregated_signature =
            BLSSignature::from([0u8; 96]);

        let result = engine.feed_qr_info(qr_info, false, true);

        // Both `AllCommitmentAggregatedSignatureNotValid` (per-quorum check)
        // and `InvalidFinalSignature` (rotation-cycle aggregate) are valid
        // rejection signals; what matters is that we don't silently store.
        let err = result.expect_err("corrupt aggregate signature must reject");
        assert!(
            matches!(
                err,
                QuorumValidationError::AllCommitmentAggregatedSignatureNotValid(_)
                    | QuorumValidationError::InvalidFinalSignature
            ),
            "expected aggregate-signature rejection, got {:?}",
            err
        );
        let corrupted_cycle_key =
            engine.rotated_quorums_per_cycle.keys().copied().collect::<Vec<_>>();
        assert!(
            !corrupted_cycle_key.contains(&target_key),
            "rejected QRInfo must not have stored cycle keyed at {} (stored keys: {:?})",
            target_key,
            corrupted_cycle_key
        );
    }

    /// Anti-clobber: a thin/incomplete second QRInfo where rotated entries
    /// land as `Skipped` (no rotation CL sigs reachable) must not downgrade
    /// an already-fully-Verified rotation cycle. Feeds the mainnet fixture
    /// once to populate `rotated_quorums_per_cycle[K]` with all entries
    /// `Verified`, then feeds a synthetic self-loop QRInfo whose diffs do
    /// not carry rotation sigs, with `last_commitment_per_index` matching
    /// the existing cycle's first quorum hash plus a fresh fake quorum
    /// that needs new validation. Asserts the existing cycle's entries
    /// remain `Verified`.
    #[cfg(feature = "quorum_validation")]
    #[test]
    fn feed_qr_info_does_not_downgrade_already_verified_cycle() {
        let (mut engine, qr_info) = load_qrinfo_2240504_fixture();

        engine.feed_qr_info(qr_info, false, true).expect("first feed should succeed");

        let cycle_key = *engine
            .rotated_quorums_per_cycle
            .keys()
            .next()
            .expect("first feed must have stored at least one rotation cycle");

        let original_cycle =
            engine.rotated_quorums_per_cycle.get(&cycle_key).expect("cycle present").clone();
        assert!(
            !original_cycle.is_empty()
                && original_cycle
                    .values()
                    .all(|q| matches!(q.verified, LLMQEntryVerificationStatus::Verified)),
            "first feed must leave the cycle fully Verified"
        );

        let known_quorum = original_cycle
            .values()
            .find(|q| q.quorum_entry.quorum_hash == cycle_key)
            .expect("cycle map must contain its key entry")
            .clone();
        let rotation_quorum_type = known_quorum.quorum_entry.llmq_type;
        let active_count = rotation_quorum_type.active_quorum_count() as i16;

        // Build `last_commitment_per_index`: first entry is the existing
        // cycle key (so cycle_key matches, exercising the gate), rest are
        // fresh fakes that need new validation.
        let mut last_commitment_per_index = vec![known_quorum.quorum_entry.clone()];
        for i in 1..active_count {
            last_commitment_per_index.push(QuorumEntry {
                version: 2,
                llmq_type: rotation_quorum_type,
                quorum_hash: QuorumHash::from_byte_array([0xCC; 32].map(|b| b ^ i as u8)),
                quorum_index: Some(i),
                signers: vec![true],
                valid_members: vec![true],
                quorum_public_key: BLSPublicKey::from([0; 48]),
                quorum_vvec_hash: QuorumVVecHash::all_zeros(),
                threshold_sig: BLSSignature::from([0; 96]),
                all_commitment_aggregated_signature: BLSSignature::from([0; 96]),
            });
        }

        // Self-loop diffs at the engine's current tip make the second feed a
        // no-op for masternode-list state while still exercising the QRInfo
        // verification pipeline.
        let tip_hash = engine
            .masternode_lists
            .iter()
            .next_back()
            .map(|(_, list)| list.block_hash)
            .expect("engine has a tip list after first feed");
        let make_self_loop = |hash: BlockHash| MnListDiff {
            version: 1,
            base_block_hash: hash,
            block_hash: hash,
            total_transactions: 0,
            merkle_hashes: vec![],
            merkle_flags: vec![],
            coinbase_tx: Transaction {
                version: 1,
                lock_time: 0,
                input: vec![],
                output: vec![],
                special_transaction_payload: None,
            },
            deleted_masternodes: vec![],
            new_masternodes: vec![],
            deleted_quorums: vec![],
            new_quorums: vec![],
            quorums_chainlock_signatures: vec![],
        };
        let empty_snapshot = || QuorumSnapshot {
            skip_list_mode: MNSkipListMode::NoSkipping,
            active_quorum_members: vec![],
            skip_list: vec![],
        };

        let thin_qr_info = QRInfo {
            quorum_snapshot_at_h_minus_c: empty_snapshot(),
            quorum_snapshot_at_h_minus_2c: empty_snapshot(),
            quorum_snapshot_at_h_minus_3c: empty_snapshot(),
            mn_list_diff_tip: make_self_loop(tip_hash),
            mn_list_diff_h: make_self_loop(tip_hash),
            mn_list_diff_at_h_minus_c: make_self_loop(tip_hash),
            mn_list_diff_at_h_minus_2c: make_self_loop(tip_hash),
            mn_list_diff_at_h_minus_3c: make_self_loop(tip_hash),
            quorum_snapshot_and_mn_list_diff_at_h_minus_4c: None,
            last_commitment_per_index,
            quorum_snapshot_list: vec![],
            mn_list_diff_list: vec![],
        };

        let _ = engine.feed_qr_info(thin_qr_info, false, true);

        let after_cycle = engine
            .rotated_quorums_per_cycle
            .get(&cycle_key)
            .expect("cycle must still exist after thin second feed");
        assert_eq!(
            after_cycle.len(),
            original_cycle.len(),
            "thin second feed must not change cycle entry count"
        );
        for (idx, entry) in after_cycle {
            assert!(
                matches!(entry.verified, LLMQEntryVerificationStatus::Verified),
                "cycle quorum at index {} (hash {}) must remain Verified after thin second feed, got {}",
                idx,
                entry.quorum_entry.quorum_hash,
                entry.verified
            );
        }
    }
}
