mod helpers;
#[cfg(feature = "message_verification")]
mod message_request_verification;
mod non_rotated_quorum_construction;
mod rotated_quorum_construction;
#[cfg(feature = "quorum_validation")]
mod validation;

use std::collections::{BTreeMap, BTreeSet};

use crate::Network;
use crate::bls_sig_utils::{BLSPublicKey, BLSSignature};
use crate::network::constants::NetworkExt;
use crate::network::message_qrinfo::{QRInfo, QuorumSnapshot};
use crate::network::message_sml::MnListDiff;
use crate::prelude::CoreBlockHeight;
use crate::sml::error::SmlError;
#[cfg(feature = "quorum_validation")]
use crate::sml::llmq_entry_verification::LLMQEntryVerificationSkipStatus;
use crate::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use crate::sml::llmq_type::LLMQType;
#[cfg(feature = "quorum_validation")]
use crate::sml::llmq_type::devnet_isd_type_override;
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
#[cfg(feature = "qrinfo-capture")]
use bincode::{config, encode_to_vec};
use hashes::Hash;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "qrinfo-capture")]
use std::{env, fs};

/// Depth offset between cycle boundary and work block (matches Dash Core WORK_DIFF_DEPTH)
/// The mnListDiffH in QRInfo is at (cycle_height - WORK_DIFF_DEPTH), not at the cycle boundary itself
pub const WORK_DIFF_DEPTH: u32 = 8;

/// Transient observability report returned from [`MasternodeListEngine::feed_qr_info`].
/// Not persisted; lives only for the duration of the call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QRInfoFeedResult {
    /// Total number of rotated quorums in `last_commitment_per_index`.
    pub rotated_quorum_count: usize,
    /// Rotated quorums an active set of this network's rotation quorum type
    /// holds. The length a peer serves is peer-controlled, so a set shorter
    /// than this covers only part of the cycle however well it verifies.
    pub expected_rotated_quorum_count: usize,
    /// Rotated quorums for which no cached `QualifiedQuorumEntry` existed and one
    /// was constructed fresh. Incremented independently of `verify_rotated_quorums`
    /// and the final verification outcome. Pair with `fully_verified_count` to
    /// distinguish cache-hit observability from a trust signal.
    pub newly_qualified_count: usize,
    /// Rotated quorums whose `.verified` is `LLMQEntryVerificationStatus::Verified`
    /// after this call settled. May be non-zero even when
    /// `verify_rotated_quorums == false` because cached entries returned by
    /// `known_qualified_quorum_entry` retain their prior `Verified` status.
    /// A cycle is only stored in `rotated_quorums_per_cycle` when every entry
    /// is `Verified`.
    pub fully_verified_count: usize,
    /// Height of the cycle from `last_commitment_per_index` if (and only if)
    /// the storage gate fired and the cycle was inserted into
    /// `rotated_quorums_per_cycle`. `None` when storage was skipped because
    /// `last_commitment_per_index` was empty, the gate blocked the write, or
    /// the cycle key was unresolvable, which `cycle_key_unresolved`
    /// distinguishes from the other two. The cycle stored by
    /// `validate_and_store_previous_cycle_quorums` is not reflected here.
    pub stored_cycle_height: Option<CoreBlockHeight>,
    /// `true` when the served active set has no resolvable cycle base, which
    /// leaves the feed without a key to store the cycle under however well it
    /// verified. Distinguishes that from a `stored_cycle_height` of `None`
    /// caused by the storage gate refusing the write.
    pub cycle_key_unresolved: bool,
    /// Previous-cycle rotated quorums that failed validation outright and were
    /// left out of the cycle stored by
    /// `validate_and_store_previous_cycle_quorums`. That path is best-effort
    /// enrichment and never fails the feed, so this is the only signal a
    /// caller gets that a peer served rotated commitments which do not verify.
    /// Entries left out for missing or inferred context are not counted, and
    /// `all_fully_verified` is unaffected: it reports on the current cycle.
    pub previous_cycle_invalid_count: usize,
}

impl QRInfoFeedResult {
    /// Returns true when this QRInfo proved the whole active rotation set:
    /// it carried every quorum of the set and each one settled as
    /// `LLMQEntryVerificationStatus::Verified`. Use this as the trust gate for
    /// callers that need to know the cycle is fully validated.
    ///
    /// A peer serving a shorter set leaves the omitted indices unproven, and
    /// treating that as a validated cycle would stop a caller from asking for
    /// the rest until the next cycle, so the length is part of the gate.
    pub fn all_fully_verified(&self) -> bool {
        self.expected_rotated_quorum_count > 0
            && self.rotated_quorum_count == self.expected_rotated_quorum_count
            && self.fully_verified_count == self.rotated_quorum_count
    }
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
/// Rejects missing, negative, out-of-range, or duplicate indices. The map may
/// hold fewer entries than the active quorum count: a quorum whose commitment
/// cannot be validated is left out, and IS lock verification fails cleanly
/// with `QuorumIndexNotFound` when a lock selects an absent index.
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
    Ok(map)
}

/// Every masternode list diff a QRInfo carries: the five named diffs, the
/// optional h-4c diff, and the trailing diff list.
///
/// [`MasternodeListEngine::qr_info_referenced_block_hashes`] exists to tell a
/// caller which heights to feed before [`MasternodeListEngine::feed_qr_info`]
/// needs them, so both must walk the same set of diffs.
fn qr_info_diffs(qr_info: &QRInfo) -> Vec<&MnListDiff> {
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

/// Cycle base height, the height of the quorum-index-0 block, for a rotated
/// quorum whose commitment sits at `quorum_block_height`.
///
/// `quorum_index` arrives from the wire as a signed value nothing bounds, so a
/// negative or oversized index yields `None` instead of sign-extending into a
/// wrapping subtraction.
fn rotated_cycle_base_height(
    quorum_block_height: CoreBlockHeight,
    quorum_index: i16,
) -> Option<CoreBlockHeight> {
    quorum_block_height.checked_sub(u32::try_from(quorum_index).ok()?)
}

/// The four quarter work block heights of the rotation cycle based at
/// `cycle_base`, ordered oldest quarter first: `[B-3c-8, B-2c-8, B-c-8, B-8]`
/// for cycle base `B` and DKG interval `c`.
///
/// A quarter reaching below the genesis block is `None`. Callers differ on
/// what that means, so none is applied here: the required-height survey takes
/// whichever quarters exist, while a reconstruction needs all four.
fn cycle_quarter_work_heights(
    cycle_base: CoreBlockHeight,
    interval: u32,
) -> [Option<CoreBlockHeight>; 4] {
    [3, 2, 1, 0]
        .map(|cycles_back: u32| cycle_base.checked_sub(cycles_back * interval + WORK_DIFF_DEPTH))
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

    /// Loads the rotation quorums from the MN list at the h work block,
    /// attaches each quorum's own cycle quarter signatures, and returns them
    /// along with the cycle hash they should be stored under. Returns `None`
    /// when prerequisite state is not yet loaded, when the MN list carries no
    /// rotating quorums, or when the cycle is already fully verified. All
    /// three cases are expected on a fresh sync and not errors.
    #[cfg(feature = "quorum_validation")]
    fn try_load_previous_cycle_entries(
        &self,
        work_block_hash: BlockHash,
        isd_type: LLMQType,
        sigs_by_work_height: &BTreeMap<CoreBlockHeight, BLSSignature>,
    ) -> Option<(QuorumHash, Vec<QualifiedQuorumEntry>)> {
        let work_height = self.block_container.get_height(&work_block_hash)?;
        let mn_list = self.masternode_lists.get(&work_height)?;
        let quorums_of_type = mn_list.quorums.get(&isd_type)?;
        let cycle_hash = self.active_set_cycle_hash(quorums_of_type.values())?;
        if self.is_cycle_fully_verified(&cycle_hash) {
            return None;
        }
        let entries: Vec<QualifiedQuorumEntry> = quorums_of_type
            .values()
            .cloned()
            .map(|mut q| {
                q.verifying_chain_lock_signature = self
                    .quarter_sigs_for_quorum(sigs_by_work_height, &q.quorum_entry)
                    .map(VerifyingChainLockSignaturesType::Rotating);
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
    /// This is a best-effort enrichment step: only entries that verify are
    /// stored, and any that do not, whether skipped for missing context or
    /// cryptographically invalid, are left out individually. A straggler from
    /// a cycle older than the QRInfo's diff range can never verify here (its
    /// quarter masternode lists are not shipped), and leaving it out means
    /// only IS locks selecting exactly that quorum index fail while the rest
    /// of the cycle verifies. The authoritative rejection of bad
    /// current-cycle data happens on the `lastCommitmentPerIndex` path.
    ///
    /// Returns how many entries were left out for failing validation outright,
    /// as opposed to lacking the context to be validated at all, so the caller
    /// can judge the peer that served them. A failure under a quarter
    /// signature keyed by elimination is a gap in that context too and is not
    /// counted.
    #[cfg(feature = "quorum_validation")]
    fn validate_and_store_previous_cycle_quorums(
        &mut self,
        work_block_hash: BlockHash,
        sigs_by_work_height: &BTreeMap<CoreBlockHeight, BLSSignature>,
        inferred_work_heights: &BTreeSet<CoreBlockHeight>,
    ) -> usize {
        let isd_type = self.network.isd_llmq_type();
        let Some((cycle_hash, mut entries)) =
            self.try_load_previous_cycle_entries(work_block_hash, isd_type, sigs_by_work_height)
        else {
            return 0;
        };

        let validation_statuses = self.validate_rotation_cycle_quorums_validation_statuses(
            entries.iter().collect::<Vec<_>>().as_slice(),
        );
        let mut invalid_count = 0;
        for entry in entries.iter_mut() {
            entry.verified = validation_statuses
                .get(&entry.quorum_entry.quorum_hash)
                .cloned()
                .unwrap_or_default();
            match entry.verified {
                LLMQEntryVerificationStatus::Verified => {}
                // A quarter signature keyed by elimination may belong to
                // another cycle, which reconstructs the wrong member set and
                // fails the aggregate check. That is a gap in the supplied
                // context rather than something the peer can be blamed for.
                LLMQEntryVerificationStatus::Invalid(_)
                    if self
                        .quarter_sigs_are_inferred(inferred_work_heights, &entry.quorum_entry) =>
                {
                    tracing::debug!(
                        "Previous-cycle quorum {} at cycle {} failed validation ({}) under inferred quarter signatures, leaving it out",
                        entry.quorum_entry.quorum_hash,
                        cycle_hash,
                        entry.verified
                    );
                    entry.verified = LLMQEntryVerificationStatus::Skipped(
                        LLMQEntryVerificationSkipStatus::InferredRotationChainLockSigs(
                            entry.quorum_entry.quorum_hash,
                        ),
                    );
                }
                LLMQEntryVerificationStatus::Invalid(_) => {
                    invalid_count += 1;
                    tracing::warn!(
                        "Previous-cycle quorum {} at cycle {} failed validation ({}), leaving it out",
                        entry.quorum_entry.quorum_hash,
                        cycle_hash,
                        entry.verified
                    );
                }
                _ => {
                    tracing::debug!(
                        "Previous-cycle quorum {} at cycle {} could not be validated ({}), leaving it out",
                        entry.quorum_entry.quorum_hash,
                        cycle_hash,
                        entry.verified
                    );
                }
            }
        }
        entries.retain(|entry| matches!(entry.verified, LLMQEntryVerificationStatus::Verified));
        if entries.is_empty() {
            return invalid_count;
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

        let cycle_map = match build_cycle_quorum_map(entries, isd_type) {
            Ok(cycle_map) => cycle_map,
            Err(e) => {
                tracing::warn!(
                    "Previous-cycle rotated quorums at cycle {} could not be keyed by quorum index ({}), leaving the cycle unstored",
                    cycle_hash,
                    e
                );
                return invalid_count;
            }
        };
        self.rotated_quorums_per_cycle.entry(cycle_hash).or_default().extend(cycle_map);
        tracing::debug!(
            "Validated and stored previous-cycle rotated quorums under cycle hash {}",
            cycle_hash
        );
        invalid_count
    }

    /// Block hashes referenced by a QRInfo message that the engine needs heights for.
    ///
    /// Covers every diff endpoint (base and target) and every rotating commitment hash
    /// carried in the QRInfo. Rotating quorum hashes from every diff are included
    /// because each quorum's cycle base, and with it the work block its ChainLock
    /// signature belongs to, is derived from that hash's height.
    ///
    /// These hashes are what the QRInfo itself names, which is not everything
    /// the feed can need. The cycle base block of a straggler from an older
    /// cycle keys that cycle in storage, yet the QRInfo carries no hash for
    /// it, so no enumeration over the message can produce it. A caller
    /// holding its own header chain should additionally feed the heights
    /// around each work block, as dash-spv does with
    /// `work_height + WORK_DIFF_DEPTH`.
    pub fn qr_info_referenced_block_hashes(qr_info: &QRInfo) -> BTreeSet<BlockHash> {
        let mut hashes = BTreeSet::new();

        for diff in qr_info_diffs(qr_info) {
            hashes.insert(diff.base_block_hash);
            hashes.insert(diff.block_hash);
            for quorum_entry in &diff.new_quorums {
                if quorum_entry.llmq_type.is_rotating_quorum_type() {
                    hashes.insert(quorum_entry.quorum_hash);
                }
            }
        }

        for quorum_entry in &qr_info.last_commitment_per_index {
            hashes.insert(quorum_entry.quorum_hash);
        }

        hashes
    }

    /// `true` iff `rotated_quorums_per_cycle` already holds a complete cycle
    /// for `cycle_hash`: one `Verified` entry for every active rotation slot.
    /// Used by the storage gate to refuse downgrading a cycle and by the
    /// previous-cycle revalidation path to skip work that would not improve
    /// trust.
    ///
    /// A cycle stored with only part of its set stays open on both counts. The
    /// entries it lacks are the ones whose context the QRInfo that stored it
    /// did not carry, and a later QRInfo carrying that context must be able to
    /// complete the cycle rather than be refused as a downgrade.
    #[cfg(feature = "quorum_validation")]
    fn is_cycle_fully_verified(&self, cycle_hash: &BlockHash) -> bool {
        let expected = self.network.isd_llmq_type().active_quorum_count() as usize;
        self.rotated_quorums_per_cycle.get(cycle_hash).is_some_and(|existing| {
            existing.len() == expected
                && existing
                    .values()
                    .all(|q| matches!(q.verified, LLMQEntryVerificationStatus::Verified))
        })
    }

    /// `rotated_quorums_per_cycle` is the authoritative map for IS lock
    /// verification, so only store a cycle when every entry is `Verified`.
    /// Skipped entries (e.g. from incomplete CL sigs or missing context) cannot
    /// sign and must not enter the map. A later QRInfo with complete context
    /// will store the cycle. Also preserve an already-fully-Verified cycle
    /// across subsequent QRInfo responses: a thin `mn_list_diff_h` can produce
    /// Skipped entries, and a `verify_rotated_quorums == false` call can leave
    /// entries unverified, neither of which must downgrade it.
    ///
    /// The number of entries a peer serves is not fixed, so verified entries
    /// merge into the stored cycle per quorum index instead of replacing it.
    /// A response carrying a subset completes the cycle, it never drops the
    /// indices an earlier response already proved.
    ///
    /// Returns the height of the stored cycle, or `None` if storage was
    /// skipped because the gate did not fire.
    #[cfg(feature = "quorum_validation")]
    fn store_cycle_if_fully_verified(
        &mut self,
        cycle_key: BlockHash,
        qualified_last_commitment_per_index: Vec<QualifiedQuorumEntry>,
        rotation_quorum_type: LLMQType,
    ) -> Result<Option<CoreBlockHeight>, QuorumValidationError> {
        let all_entries_verified = qualified_last_commitment_per_index
            .iter()
            .all(|q| matches!(q.verified, LLMQEntryVerificationStatus::Verified));
        if !all_entries_verified || self.is_cycle_fully_verified(&cycle_key) {
            return Ok(None);
        }
        let cycle_map =
            build_cycle_quorum_map(qualified_last_commitment_per_index, rotation_quorum_type)?;
        self.rotated_quorums_per_cycle.entry(cycle_key).or_default().extend(cycle_map);
        Ok(self.block_container.get_height(&cycle_key))
    }

    /// Best-effort capture of the pre-feed block container and the raw QRInfo
    /// for offline reproduction of validation failures. Compiled in only under
    /// the `qrinfo-capture` feature, and active only while the environment
    /// variable `DASH_SML_DUMP_QRINFO_DIR` names a directory to write into.
    ///
    /// Each capture writes two bincode encoded files into that directory,
    /// `block_container_<tip height>.dat` and `qrinfo_<tip height>.dat`, both
    /// decodable with `bincode::config::standard()`. A QRInfo whose tip height
    /// the block container cannot resolve is not captured at all, since every
    /// such capture would land on the same pair of names and overwrite the
    /// previous one.
    #[cfg(feature = "qrinfo-capture")]
    fn dump_qr_info_capture(&self, qr_info: &QRInfo) {
        let Ok(dir) = env::var("DASH_SML_DUMP_QRINFO_DIR") else {
            return;
        };
        let Some(tip_height) =
            self.block_container.get_height(&qr_info.mn_list_diff_tip.block_hash)
        else {
            return;
        };
        if fs::create_dir_all(&dir).is_err() {
            return;
        }
        if let Ok(bytes) = encode_to_vec(&self.block_container, config::standard()) {
            let _ = fs::write(format!("{dir}/block_container_{tip_height}.dat"), bytes);
        }
        if let Ok(bytes) = encode_to_vec(qr_info, config::standard()) {
            let _ = fs::write(format!("{dir}/qrinfo_{tip_height}.dat"), bytes);
        }
    }

    /// Best ChainLock signature per rotation work block, extracted from the
    /// per-quorum `quorumsCLSigs` mapping of every diff in a QRInfo.
    ///
    /// Core keys each rotated quorum's ChainLock signature to that quorum's
    /// own work block (cycle base minus [`WORK_DIFF_DEPTH`]). The active
    /// rotation set can span several cycles at once, because a failed DKG
    /// leaves the previous cycle's quorum in place at that index, so one
    /// diff can carry signatures for more than one cycle and a single
    /// per-diff signature cannot represent them all.
    ///
    /// A signature group whose quorum hash heights are all unknown is keyed
    /// by elimination: walking diffs oldest first, a group carrying a
    /// non-zero signature that already keys an earlier work block belongs to
    /// that older cycle, and when a single group remains it is the diff's
    /// newest cycle, keyed at the newest work block the diff can carry. Exact
    /// keys always win.
    ///
    /// Returns the map alongside the work heights the elimination pass keyed,
    /// so callers can tell an inferred key from an exact one. An inferred key
    /// can be wrong, which yields a wrong quorum modifier and a failing
    /// aggregate signature check, so a quorum resting on one must degrade
    /// rather than count as proof of corrupt data.
    #[cfg(feature = "quorum_validation")]
    fn rotation_cl_sigs_by_work_height<'a>(
        &self,
        diffs: impl IntoIterator<Item = &'a MnListDiff>,
    ) -> (BTreeMap<CoreBlockHeight, BLSSignature>, BTreeSet<CoreBlockHeight>) {
        let mut diffs: Vec<&MnListDiff> = diffs.into_iter().collect();
        diffs.sort_by_key(|diff| self.block_container.get_height(&diff.block_hash));

        let mut sigs_by_work_height = BTreeMap::new();
        for diff in &diffs {
            for sig_obj in &diff.quorums_chainlock_signatures {
                for &index in &sig_obj.index_set {
                    let Some(quorum) = diff.new_quorums.get(index as usize) else {
                        continue;
                    };
                    if !quorum.llmq_type.is_rotating_quorum_type() {
                        continue;
                    }
                    if let Some(work_height) = self
                        .rotated_quorum_cycle_base(quorum)
                        .and_then(|cycle_base| cycle_base.checked_sub(WORK_DIFF_DEPTH))
                    {
                        sigs_by_work_height.insert(work_height, sig_obj.signature);
                    }
                }
            }
        }

        let mut inferred_work_heights = BTreeSet::new();
        for diff in &diffs {
            let Some(newest_work_height) = self.diff_newest_work_height(diff) else {
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
                for &index in &sig_obj.index_set {
                    let Some(quorum) = diff.new_quorums.get(index as usize) else {
                        continue;
                    };
                    if !quorum.llmq_type.is_rotating_quorum_type() {
                        continue;
                    }
                    if self.rotated_quorum_cycle_base(quorum).is_some() {
                        group_resolved = true;
                        continue;
                    }
                    group_has_unresolved_rotated = true;
                    // The fallback presumes the group belongs to the diff's
                    // newest cycle. Where the container knows the true block
                    // at the presumed quorum height, a hash mismatch
                    // disproves that presumption.
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
                    if let Some(block_hash) = self.block_container.get_hash(&presumed_height)
                        && *block_hash != quorum.quorum_hash
                    {
                        hypothesis_mismatch = true;
                    }
                }
                if group_resolved || !group_has_unresolved_rotated || hypothesis_mismatch {
                    continue;
                }
                // A ChainLock signature signs one specific block, so a
                // non-zero value already keying a work block identifies that
                // same older work block here. A zeroed value carries no such
                // identity: Core merges every work block without a ChainLock
                // under it, so repetition says nothing about which cycle the
                // group belongs to.
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

    /// The newest work block whose cycle a diff can carry, defined only for
    /// diffs ending at a work block: the cycle starting at `end + 8 - c` is
    /// mined a few blocks into its own cycle, so it is the newest one whose
    /// commitment fits inside `(base, end]`, and its work block sits one
    /// interval below the diff end.
    #[cfg(feature = "quorum_validation")]
    fn diff_newest_work_height(&self, diff: &MnListDiff) -> Option<CoreBlockHeight> {
        let end_height = self.block_container.get_height(&diff.block_hash)?;
        let interval = self.network.isd_llmq_type().params().dkg_params.interval;
        (end_height % interval == interval - WORK_DIFF_DEPTH)
            .then(|| end_height.checked_sub(interval))
            .flatten()
    }

    /// Cycle base height (the height of the quorum-index-0 block) for a
    /// rotated quorum, derived from the quorum's own hash and index.
    ///
    /// The index arrives from the wire and nothing ties it to the block the
    /// commitment was mined in, so it is only accepted while it names a slot
    /// of the active set and lands the base on a DKG interval boundary. Any
    /// other index shifts the base into a cycle the quorum does not belong
    /// to, and a base derived from that keys another cycle's work block.
    #[cfg(feature = "quorum_validation")]
    fn rotated_quorum_cycle_base(&self, quorum: &QuorumEntry) -> Option<CoreBlockHeight> {
        let height = self.block_container.get_height(&quorum.quorum_hash)?;
        let quorum_index = quorum.quorum_index?;
        if u32::try_from(quorum_index).ok()? >= quorum.llmq_type.active_quorum_count() {
            return None;
        }
        let cycle_base = rotated_cycle_base_height(height, quorum_index)?;
        (cycle_base % quorum.llmq_type.params().dkg_params.interval == 0).then_some(cycle_base)
    }

    /// The four quarter work block heights for the cycle a rotated quorum
    /// belongs to, ordered oldest quarter first: `[B-3c-8, B-2c-8, B-c-8,
    /// B-8]` for cycle base `B` and DKG interval `c`.
    #[cfg(feature = "quorum_validation")]
    fn quarter_work_heights(&self, quorum: &QuorumEntry) -> Option<[CoreBlockHeight; 4]> {
        let cycle_base = self.rotated_quorum_cycle_base(quorum)?;
        let interval = quorum.llmq_type.params().dkg_params.interval;
        let [h3, h2, h1, h0] = cycle_quarter_work_heights(cycle_base, interval);
        Some([h3?, h2?, h1?, h0?])
    }

    /// The four quarter ChainLock signatures for the cycle a rotated quorum
    /// belongs to, ordered oldest quarter first.
    #[cfg(feature = "quorum_validation")]
    fn quarter_sigs_for_quorum(
        &self,
        sigs_by_work_height: &BTreeMap<CoreBlockHeight, BLSSignature>,
        quorum: &QuorumEntry,
    ) -> Option<[BLSSignature; 4]> {
        let [h3, h2, h1, h0] = self.quarter_work_heights(quorum)?;
        let sig_at = |work_height: CoreBlockHeight| sigs_by_work_height.get(&work_height).copied();
        Some([sig_at(h3)?, sig_at(h2)?, sig_at(h1)?, sig_at(h0)?])
    }

    /// `true` when any of a quorum's quarter signatures was keyed by the
    /// elimination pass rather than derived from a known quorum height.
    #[cfg(feature = "quorum_validation")]
    fn quarter_sigs_are_inferred(
        &self,
        inferred_work_heights: &BTreeSet<CoreBlockHeight>,
        quorum: &QuorumEntry,
    ) -> bool {
        self.quarter_work_heights(quorum).is_some_and(|work_heights| {
            work_heights.iter().any(|work_height| inferred_work_heights.contains(work_height))
        })
    }

    /// The rotation quorum type an active set is keyed by.
    ///
    /// Configuration wins wherever the deployed type is fixed: wire data must
    /// never decide which type this engine trusts. A devnet is deployed with
    /// whichever DIP24 type it was launched with, so without an explicit
    /// override there is no configured type to hold against the commitments
    /// and the served ones name it instead. Guessing there rejects every
    /// quorum index the guessed type has no slot for.
    #[cfg(feature = "quorum_validation")]
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

    /// Cycle hash for an active rotated quorum set: the block hash at the
    /// newest cycle base among the entries. The entry at quorum index 0 does
    /// not necessarily belong to the set's own cycle (a failed DKG leaves an
    /// older cycle's quorum in the set at that index), but the newest cycle
    /// base always identifies the cycle the set is active for.
    #[cfg(feature = "quorum_validation")]
    fn active_set_cycle_hash<'a>(
        &self,
        entries: impl IntoIterator<Item = &'a QualifiedQuorumEntry>,
    ) -> Option<QuorumHash> {
        let newest_cycle_base = entries
            .into_iter()
            .filter_map(|entry| self.rotated_quorum_cycle_base(&entry.quorum_entry))
            .max()?;
        self.block_container.get_hash(&newest_cycle_base).copied()
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
        #[cfg(feature = "qrinfo-capture")]
        self.dump_qr_info_capture(&qr_info);

        #[cfg(feature = "quorum_validation")]
        let (rotation_sigs_by_work_height, inferred_work_heights) =
            self.rotation_cl_sigs_by_work_height(qr_info_diffs(&qr_info));

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
        let rotation_quorum_type = self.rotation_quorum_type(&last_commitment_per_index);

        #[cfg(feature = "quorum_validation")]
        let mut stored_cycle_height: Option<CoreBlockHeight> = None;
        #[cfg(feature = "quorum_validation")]
        let rotated_quorum_count = last_commitment_per_index.len();
        #[cfg(feature = "quorum_validation")]
        let mut newly_qualified_count: usize = 0;
        #[cfg(feature = "quorum_validation")]
        let mut fully_verified_count: usize = 0;
        #[cfg(feature = "quorum_validation")]
        let mut previous_cycle_invalid_count: usize = 0;
        if let Some((quorum_snapshot_at_h_minus_4c, mn_list_diff_at_h_minus_4c)) =
            quorum_snapshot_and_mn_list_diff_at_h_minus_4c
        {
            self.known_snapshots
                .insert(mn_list_diff_at_h_minus_4c.block_hash, quorum_snapshot_at_h_minus_4c);
            self.apply_diff(mn_list_diff_at_h_minus_4c, None, false, None)?;
        }

        self.known_snapshots
            .insert(mn_list_diff_at_h_minus_3c.block_hash, quorum_snapshot_at_h_minus_3c);
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
        // the cycle two back resides.
        #[cfg(feature = "quorum_validation")]
        let work_block_hash_h = mn_list_diff_h.block_hash;
        let maybe_sig_h = self.apply_diff(mn_list_diff_h, None, false, None)?;

        let sigs = match (maybe_sig_h_minus_2c, maybe_sig_h_minus_c, maybe_sig_h) {
            (Some(s2), Some(s1), Some(s0)) => Some([s2, s1, s0]),
            _ => None,
        };

        self.apply_diff(mn_list_diff_tip, None, verify_tip_non_rotated_quorums, sigs)?;

        // The active set at the h work block can only be validated when the
        // h-4c diff supplies the masternode lists and snapshots for its
        // oldest quarters. Entries whose quarter signatures or history are
        // still missing settle as `Skipped` individually.
        #[cfg(feature = "quorum_validation")]
        if can_verify_previous {
            previous_cycle_invalid_count = self.validate_and_store_previous_cycle_quorums(
                work_block_hash_h,
                &rotation_sigs_by_work_height,
                &inferred_work_heights,
            );
        }

        // Each entry gets the quarter signatures of its own cycle. A failed
        // DKG leaves an older cycle's quorum in the active set at that
        // index, so entries in `last_commitment_per_index` do not all
        // belong to the same cycle. An entry whose signatures are missing
        // stays without `VerifyingChainLockSignaturesType::Rotating` and
        // settles as `Skipped(MissingRotationChainLockSigs)`, which keeps
        // it out of `rotated_quorums_per_cycle`. IS locks signed by such a
        // quorum cannot be verified by this SPV until a later QRInfo
        // arrives with complete data.
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
                    let quarter_sigs =
                        self.quarter_sigs_for_quorum(&rotation_sigs_by_work_height, &quorum_entry);
                    let mut qualified_quorum_entry: QualifiedQuorumEntry = quorum_entry.into();
                    qualified_quorum_entry.verifying_chain_lock_signature =
                        quarter_sigs.map(VerifyingChainLockSignaturesType::Rotating);
                    Ok(qualified_quorum_entry)
                }
            })
            .collect::<Result<Vec<QualifiedQuorumEntry>, QuorumValidationError>>()?;

        #[cfg(feature = "quorum_validation")]
        let cycle_key = self.active_set_cycle_hash(qualified_last_commitment_per_index.iter());
        #[cfg(feature = "quorum_validation")]
        let cycle_key_unresolved = cycle_key.is_none() && rotated_quorum_count > 0;
        #[cfg(feature = "quorum_validation")]
        if cycle_key_unresolved {
            tracing::warn!(
                "None of the {} rotated quorums served resolves a cycle base, so the cycle cannot be stored under any key",
                rotated_quorum_count
            );
        }

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
                    // A quarter signature keyed by elimination may belong to
                    // another cycle, which reconstructs the wrong member set
                    // and fails the aggregate check. That is a gap in the
                    // supplied context, not proof of corrupt data, so the
                    // entry degrades on its own instead of aborting the feed.
                    if self.quarter_sigs_are_inferred(
                        &inferred_work_heights,
                        &rotated_quorum.quorum_entry,
                    ) {
                        tracing::warn!(
                            "Rotated quorum {} failed validation ({}) under inferred quarter signatures, skipping it",
                            rotated_quorum.quorum_entry.quorum_hash,
                            e
                        );
                        rotated_quorum.verified = LLMQEntryVerificationStatus::Skipped(
                            LLMQEntryVerificationSkipStatus::InferredRotationChainLockSigs(
                                rotated_quorum.quorum_entry.quorum_hash,
                            ),
                        );
                    } else {
                        return Err(e.clone());
                    }
                }
            }

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
                stored_cycle_height = self.store_cycle_if_fully_verified(
                    key,
                    qualified_last_commitment_per_index,
                    rotation_quorum_type,
                )?;
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
        } else if let Some(cycle_key) = cycle_key {
            fully_verified_count = qualified_last_commitment_per_index
                .iter()
                .filter(|q| matches!(q.verified, LLMQEntryVerificationStatus::Verified))
                .count();
            stored_cycle_height = self.store_cycle_if_fully_verified(
                cycle_key,
                qualified_last_commitment_per_index,
                rotation_quorum_type,
            )?;
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
                expected_rotated_quorum_count: rotation_quorum_type.active_quorum_count() as usize,
                cycle_key_unresolved,
                newly_qualified_count,
                fully_verified_count,
                stored_cycle_height,
                previous_cycle_invalid_count,
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
    #[cfg(feature = "quorum_validation")]
    use crate::network::message_sml::QuorumCLSigObject;
    use crate::prelude::CoreBlockHeight;
    use crate::sml::llmq_entry_verification::{
        LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus,
    };
    use crate::sml::llmq_type::LLMQType;
    use crate::sml::llmq_type::LLMQType::{
        Llmqtype50_60, Llmqtype60_75, Llmqtype400_60, Llmqtype400_85,
    };
    #[cfg(feature = "quorum_validation")]
    use crate::sml::llmq_type::devnet_isd_type_override;
    use crate::sml::llmq_type::network::NetworkLLMQExt;
    use crate::sml::masternode_list::MasternodeList;
    #[cfg(feature = "quorum_validation")]
    use crate::sml::masternode_list_engine::WORK_DIFF_DEPTH;
    use crate::sml::masternode_list_engine::{
        MasternodeListEngine, MasternodeListEngineBlockContainer,
    };
    use crate::sml::quorum_entry::qualified_quorum_entry::{
        QualifiedQuorumEntry, VerifyingChainLockSignaturesType,
    };
    #[cfg(feature = "quorum_validation")]
    use crate::sml::quorum_validation_error::QuorumValidationError;
    use bincode::{Decode, config, decode_from_slice};
    use std::collections::BTreeMap;
    #[cfg(feature = "quorum_validation")]
    use std::collections::BTreeSet;

    #[cfg(feature = "quorum_validation")]
    use {
        super::build_cycle_quorum_map,
        super::qr_info_diffs,
        crate::BlockHash,
        crate::QuorumHash,
        crate::bls_sig_utils::{BLSPublicKey, BLSSignature},
        crate::hash_types::QuorumVVecHash,
        crate::transaction::special_transaction::quorum_commitment::QuorumEntry,
    };

    #[cfg(feature = "quorum_validation")]
    fn make_quorum_entry(
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

    #[cfg(feature = "quorum_validation")]
    fn make_qualified_quorum_entry(
        llmq_type: LLMQType,
        quorum_index: Option<i16>,
    ) -> QualifiedQuorumEntry {
        make_quorum_entry(llmq_type, QuorumHash::all_zeros(), quorum_index).into()
    }

    /// A diff carrying only what the rotation signature keying reads: its end
    /// block, its rotating commitments, and its `quorumsCLSigs` groups.
    #[cfg(feature = "quorum_validation")]
    fn make_cl_sig_diff(
        end_hash: BlockHash,
        new_quorums: Vec<QuorumEntry>,
        groups: Vec<(BLSSignature, Vec<u16>)>,
    ) -> MnListDiff {
        let diff_bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin");
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

    #[cfg(feature = "quorum_validation")]
    fn engine_knowing_blocks(blocks: &[(CoreBlockHeight, BlockHash)]) -> MasternodeListEngine {
        let mut engine = MasternodeListEngine::default_for_network(Network::Mainnet);
        for (height, block_hash) in blocks {
            engine.feed_block_height(*height, *block_hash);
        }
        engine
    }

    /// Core keys every rotated quorum's ChainLock signature to that quorum's
    /// own work block and merges work blocks that share a signature, so the
    /// keying has to survive unknown quorum heights, ambiguity, and a
    /// signature that legitimately covers more than one cycle.
    #[cfg(feature = "quorum_validation")]
    #[test]
    fn rotation_cl_sigs_by_work_height_keys_each_cycle_to_its_own_work_block() {
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
            vec![make_quorum_entry(isd_type, quorum_hash, Some(3))],
            vec![(sig, vec![0])],
        );

        // A known quorum height keys the signature exactly, no inference.
        let engine = engine_knowing_blocks(&[(diff_end, end_hash), (cycle_base + 3, quorum_hash)]);
        let (sigs, inferred) = engine.rotation_cl_sigs_by_work_height([&diff]);
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
                vec![make_quorum_entry(isd_type, quorum_hash, Some(shifted_index))],
                vec![(sig, vec![0])],
            );
            let (sigs, inferred) = engine.rotation_cl_sigs_by_work_height([&shifted]);
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
        let (sigs, inferred) = engine.rotation_cl_sigs_by_work_height([&diff]);
        assert_eq!(sigs, BTreeMap::from([(work_height, sig)]));
        assert_eq!(inferred, BTreeSet::from([work_height]));

        // Two unresolved groups leave the cycle ambiguous, so nothing is keyed.
        let ambiguous = make_cl_sig_diff(
            end_hash,
            vec![
                make_quorum_entry(isd_type, quorum_hash, Some(3)),
                make_quorum_entry(isd_type, other_quorum_hash, Some(5)),
            ],
            vec![(sig, vec![0]), (other_sig, vec![1])],
        );
        let (sigs, inferred) = engine.rotation_cl_sigs_by_work_height([&ambiguous]);
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
            vec![make_quorum_entry(isd_type, older_quorum_hash, Some(3))],
            vec![(zero_sig, vec![0])],
        );
        let newer_zeroed = make_cl_sig_diff(
            end_hash,
            vec![make_quorum_entry(isd_type, quorum_hash, Some(3))],
            vec![(zero_sig, vec![0])],
        );
        let (sigs, inferred) =
            engine.rotation_cl_sigs_by_work_height([&older_zeroed, &newer_zeroed]);
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
            vec![make_quorum_entry(isd_type, older_quorum_hash, Some(3))],
            vec![(sig, vec![0])],
        );
        let newer = make_cl_sig_diff(
            end_hash,
            vec![
                make_quorum_entry(isd_type, quorum_hash, Some(3)),
                make_quorum_entry(isd_type, other_quorum_hash, Some(5)),
            ],
            vec![(sig, vec![0]), (other_sig, vec![1])],
        );
        let (sigs, _) = engine.rotation_cl_sigs_by_work_height([&older, &newer]);
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
    #[cfg(feature = "quorum_validation")]
    #[test]
    fn rotation_quorum_type_reads_the_served_type_only_on_an_unconfigured_devnet() {
        let served =
            [make_quorum_entry(LLMQType::LlmqtypeTestDIP0024, QuorumHash::all_zeros(), Some(0))];
        let non_rotating =
            [make_quorum_entry(LLMQType::Llmqtype50_60, QuorumHash::all_zeros(), Some(0))];

        for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            let engine = MasternodeListEngine::default_for_network(network);
            assert_eq!(
                engine.rotation_quorum_type(&served),
                network.isd_llmq_type(),
                "a network with a deployed type must ignore what a peer serves"
            );
        }

        // The devnet override is a process-wide `OnceLock` another test in
        // this binary may have set, so the expectation follows it.
        let engine = MasternodeListEngine::default_for_network(Network::Devnet);
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

    fn decode_fixture<T: Decode<()>>(bytes: &[u8]) -> T {
        decode_from_slice(bytes, config::standard()).expect("expected to decode").0
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
            decode_fixture(block_container_bytes);
        let mn_list_diffs_bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/mnlistdiffs_2240504.dat");
        let mn_list_diffs: BTreeMap<(CoreBlockHeight, CoreBlockHeight), MnListDiff> =
            decode_fixture(mn_list_diffs_bytes);
        let qr_info_bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/qrinfo_2240504.dat");
        let qr_info: QRInfo = decode_fixture(qr_info_bytes);

        engine.block_container = block_container;
        for ((_start_height, height), diff) in mn_list_diffs.into_iter() {
            engine.apply_diff(diff, Some(height), false, None).expect("expected to apply diff");
        }

        (engine, qr_info)
    }

    /// Captured 2026-08-09 from a fresh mainnet sync at tip 2518986 (cycle
    /// boundary 2518848). The active rotation set at that state carried a
    /// quorum whose latest commitment came from an older cycle, so the
    /// per-quorum quarter signatures differ within one QRInfo batch. The
    /// engine state mirrors production cold start: empty masternode lists,
    /// only the block container pre-fed.
    #[cfg(feature = "quorum_validation")]
    fn load_qrinfo_2518986_fixture() -> (MasternodeListEngine, QRInfo) {
        let block_container_bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/block_container_2518986.dat");
        let block_container: MasternodeListEngineBlockContainer =
            decode_fixture(block_container_bytes);
        let qr_info_bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/qrinfo_2518986.dat");
        let qr_info: QRInfo = decode_fixture(qr_info_bytes);

        let mut engine = MasternodeListEngine {
            network: Network::Mainnet,
            ..Default::default()
        };
        engine.block_container = block_container;
        (engine, qr_info)
    }

    #[test]
    #[cfg(feature = "quorum_validation")]
    fn validate_first_qr_info_on_fresh_engine_with_mixed_cycle_quorums() {
        let (mut engine, qr_info) = load_qrinfo_2518986_fixture();

        // The fixture's active set mixes cycles: quorum index 0 carries the
        // previous cycle's commitment (its DKG failed in the current cycle),
        // the remaining 31 belong to the current cycle at 2518848. The pin
        // below keeps a fixture swap from silently dropping that property.
        let current_cycle_base = 2518848;
        let mixed_cycle_bases: BTreeSet<CoreBlockHeight> = qr_info
            .last_commitment_per_index
            .iter()
            .filter_map(|q| engine.rotated_quorum_cycle_base(q))
            .collect();
        assert!(
            mixed_cycle_bases.len() > 1 && mixed_cycle_bases.contains(&current_cycle_base),
            "fixture must carry a mixed-cycle active set, got cycle bases {:?}",
            mixed_cycle_bases
        );

        let result = engine.feed_qr_info(qr_info, true, true);
        let feed_result = match result {
            Ok(feed_result) => feed_result.expect("expected a feed result"),
            Err(e) => panic!("first QRInfo on a fresh engine must feed cleanly: {}", e),
        };

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

        let cycle_hash = *engine
            .block_container
            .get_hash(&current_cycle_base)
            .expect("expected current cycle hash");
        let stored_cycle = engine
            .rotated_quorums_per_cycle
            .get(&cycle_hash)
            .expect("expected active set stored under the current cycle hash");
        assert_eq!(stored_cycle.len(), 32);
        assert!(
            stored_cycle
                .values()
                .all(|q| matches!(q.verified, LLMQEntryVerificationStatus::Verified)),
            "every stored quorum must be verified"
        );

        // The previous cycle's active set carries its own straggler at index
        // 20 (from one cycle further back), whose commitment block has no
        // height in the captured container, so its cycle cannot be derived and
        // it settles as skipped. The verified rest of the set must still be
        // stored so IS locks referencing the previous cycle verify.
        let dkg_interval = engine.network.isd_llmq_type().params().dkg_params.interval;
        let previous_cycle_hash = *engine
            .block_container
            .get_hash(&(current_cycle_base - dkg_interval))
            .expect("expected previous cycle hash");
        let previous_cycle = engine
            .rotated_quorums_per_cycle
            .get(&previous_cycle_hash)
            .expect("expected the previous cycle's verified subset stored");
        assert_eq!(previous_cycle.len(), 31);
        assert!(!previous_cycle.contains_key(&20), "the unverifiable straggler must be left out");
        assert!(
            previous_cycle
                .values()
                .all(|q| matches!(q.verified, LLMQEntryVerificationStatus::Verified)),
            "every stored previous-cycle quorum must be verified"
        );

        // How many commitments a peer serves is up to the peer. A set one
        // entry short still verifies entry by entry, yet the index it omits
        // stays unproven, so the cycle must not read as fully validated.
        let (mut engine, mut qr_info) = load_qrinfo_2518986_fixture();
        qr_info.last_commitment_per_index.pop().expect("fixture must carry commitments");
        let feed_result = engine
            .feed_qr_info(qr_info, true, true)
            .expect("a truncated active set must still feed cleanly")
            .expect("expected a feed result");
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

    /// A rotated quorum's ChainLock signature is keyed by its own cycle base,
    /// which is derived from the height of its commitment block, so a caller
    /// that pre-feeds exactly what this preview lists must come away with a
    /// height for every rotated quorum in every diff. The 2518986 fixture's
    /// previous-cycle straggler at index 20 sits in the h-c diff, so a preview
    /// that only walked `mn_list_diff_h` would leave its cycle underivable.
    #[cfg(feature = "quorum_validation")]
    #[test]
    fn qr_info_referenced_block_hashes_cover_rotated_quorums_outside_the_h_diff() {
        let (_engine, qr_info) = load_qrinfo_2518986_fixture();

        let straggler = qr_info
            .mn_list_diff_at_h_minus_c
            .new_quorums
            .iter()
            .find(|q| q.llmq_type.is_rotating_quorum_type() && q.quorum_index == Some(20))
            .expect("fixture must carry the previous cycle's index 20 quorum in the h-c diff")
            .quorum_hash;
        assert!(
            !qr_info
                .mn_list_diff_h
                .new_quorums
                .iter()
                .any(|q| q.llmq_type.is_rotating_quorum_type() && q.quorum_hash == straggler),
            "fixture invariant: the straggler must sit outside the h diff or this covers nothing"
        );

        assert!(
            MasternodeListEngine::qr_info_referenced_block_hashes(&qr_info).contains(&straggler),
            "the commitment block of a rotated quorum outside the h diff must be listed"
        );
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
        let mut mn_list_engine: MasternodeListEngine = decode_fixture(&data);

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
        let mut mn_list_engine: MasternodeListEngine = decode_fixture(&data);

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
        let mn_list_engine: MasternodeListEngine = decode_fixture(&data);

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
        let mn_list_engine: MasternodeListEngine = decode_fixture(&data);

        for quorums in mn_list_engine.rotated_quorums_per_cycle.values() {
            mn_list_engine
                .validate_rotation_cycle_quorums(quorums.values().collect::<Vec<_>>().as_slice())
                .expect("expected to validated quorums");
        }
    }

    #[cfg(feature = "quorum_validation")]
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

        let entries: Vec<QualifiedQuorumEntry> =
            qr_info.last_commitment_per_index.iter().cloned().map(Into::into).collect();
        let expected_cycle_key = engine
            .active_set_cycle_hash(entries.iter())
            .expect("fixture must resolve the cycle key of its active set");
        let entry_hash =
            entries.first().expect("fixture has rotation commitments").quorum_entry.quorum_hash;

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
            .and_then(|m| m.get(&entry_hash))
            .map(|(_, _, status)| status.clone());
        assert!(
            matches!(
                entry_status,
                Some(LLMQEntryVerificationStatus::Skipped(
                    LLMQEntryVerificationSkipStatus::MissingRotationChainLockSigs(_)
                ))
            ),
            "expected MissingRotationChainLockSigs skip for {}, got {:?}",
            entry_hash,
            entry_status
        );
    }

    /// An active set whose cycle base no entry resolves cannot be stored under
    /// any key, however well it verified. The caller has to be able to tell
    /// that apart from the storage gate refusing a degraded cycle, because
    /// only the former is fixed by feeding more block heights.
    #[cfg(feature = "quorum_validation")]
    #[test]
    fn feed_qr_info_reports_an_unresolvable_cycle_key() {
        let (mut engine, qr_info) = load_qrinfo_2240504_fixture();

        let MasternodeListEngineBlockContainer::BTreeMapContainer(container) =
            &mut engine.block_container;
        for quorum in qr_info.last_commitment_per_index.iter() {
            if let Some(height) = container.block_heights.remove(&quorum.quorum_hash) {
                container.block_hashes.remove(&height);
            }
        }

        let feed_result = engine
            .feed_qr_info(qr_info, false, false)
            .expect("an unresolvable cycle key must not abort the feed")
            .expect("expected a feed result");

        assert!(feed_result.cycle_key_unresolved, "the unresolvable cycle key must be reported");
        assert!(
            feed_result.stored_cycle_height.is_none(),
            "a cycle without a key must not be stored"
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

    /// A quarter signature keyed by elimination can belong to another cycle,
    /// so a current-cycle quorum resting on one must settle as `Skipped` when
    /// it fails to verify. Aborting the feed there would turn a gap in the
    /// caller's context into a permanent sync stall.
    #[cfg(feature = "quorum_validation")]
    #[test]
    fn feed_qr_info_skips_a_current_cycle_quorum_resting_on_an_inferred_signature() {
        let (mut engine, mut qr_info) = load_qrinfo_2240504_fixture();

        // The quorums of the cycle based at 2239488 are what exactly key the
        // current cycle's oldest quarter. Dropping their heights leaves that
        // quarter reachable only by elimination.
        let MasternodeListEngineBlockContainer::BTreeMapContainer(container) =
            &mut engine.block_container;
        for height in 2239488..2239488 + 32 {
            if let Some(block_hash) = container.block_hashes.remove(&height) {
                container.block_heights.remove(&block_hash);
            }
        }

        let target = qr_info
            .last_commitment_per_index
            .first()
            .expect("fixture must carry at least one rotation commitment")
            .quorum_hash;
        let llmq_type = qr_info.last_commitment_per_index[0].llmq_type;
        qr_info.last_commitment_per_index[0].all_commitment_aggregated_signature =
            BLSSignature::from([0u8; 96]);

        let feed_result = engine
            .feed_qr_info(qr_info, false, true)
            .expect("an inferred quarter signature must not abort the feed")
            .expect("expected a feed result");

        let (_, _, status) = engine
            .quorum_statuses
            .get(&llmq_type)
            .and_then(|statuses| statuses.get(&target))
            .expect("the corrupted quorum must have a recorded status");
        assert!(
            matches!(
                status,
                LLMQEntryVerificationStatus::Skipped(
                    LLMQEntryVerificationSkipStatus::InferredRotationChainLockSigs(hash)
                ) if *hash == target
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
    #[cfg(feature = "quorum_validation")]
    #[test]
    fn feed_qr_info_degrades_previous_cycle_on_corrupt_aggregate_signature() {
        let (mut engine, mut qr_info) = load_qrinfo_2240504_fixture();

        let corrupt_position = qr_info
            .mn_list_diff_h
            .new_quorums
            .iter()
            .position(|q| q.llmq_type.is_rotating_quorum_type())
            .expect("fixture must carry rotated quorums in the h diff");
        let corrupted_quorum_hash =
            qr_info.mn_list_diff_h.new_quorums[corrupt_position].quorum_hash;
        let previous_cycle_key = {
            let quorum = &qr_info.mn_list_diff_h.new_quorums[corrupt_position];
            let cycle_base = engine
                .rotated_quorum_cycle_base(quorum)
                .expect("fixture must carry the corrupted quorum's cycle base");
            *engine.block_container.get_hash(&cycle_base).expect("expected cycle base hash")
        };
        // A zeroed signature would be rejected by the structural check before
        // any aggregate verification runs. Another quorum's signature is
        // structurally sound and simply does not verify against this
        // commitment.
        let foreign_signature = qr_info
            .mn_list_diff_h
            .new_quorums
            .iter()
            .find(|q| {
                q.llmq_type.is_rotating_quorum_type() && q.quorum_hash != corrupted_quorum_hash
            })
            .expect("fixture must carry a second rotated quorum in the h diff")
            .all_commitment_aggregated_signature;
        qr_info.mn_list_diff_h.new_quorums[corrupt_position].all_commitment_aggregated_signature =
            foreign_signature;
        let h_block_hash = qr_info.mn_list_diff_h.block_hash;

        // The captured container has no height for the commitments of the
        // cycle that keys the corrupted quorum's oldest quarter, leaving that
        // quarter to the elimination pass. Feeding the height of that cycle's
        // index 0 commitment keys it exactly, so the failure below is the
        // peer's and not a guess of ours.
        let [oldest_quarter, ..] = engine
            .quarter_work_heights(&qr_info.mn_list_diff_h.new_quorums[corrupt_position])
            .expect("fixture must resolve the corrupted quorum's quarter work heights");
        let interval = engine.network.isd_llmq_type().params().dkg_params.interval;
        let keying_commitment = qr_info_diffs(&qr_info)
            .into_iter()
            .find(|diff| {
                engine.block_container.get_height(&diff.block_hash)
                    == Some(oldest_quarter + interval)
            })
            .expect("fixture must carry the diff holding that cycle's commitments")
            .new_quorums
            .iter()
            .find(|q| q.llmq_type.is_rotating_quorum_type() && q.quorum_index == Some(0))
            .expect("that diff must carry the cycle's index 0 commitment")
            .quorum_hash;
        engine.feed_block_height(oldest_quarter + WORK_DIFF_DEPTH, keying_commitment);

        let feed_result = engine
            .feed_qr_info(qr_info, true, true)
            .expect("previous-cycle corruption must not abort the feed")
            .expect("expected a feed result");

        let h_height =
            engine.block_container.get_height(&h_block_hash).expect("expected the h height");
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
            previous_cycle
                .values()
                .all(|q| matches!(q.verified, LLMQEntryVerificationStatus::Verified)),
            "every stored previous-cycle quorum must be verified"
        );
        assert_eq!(
            feed_result.previous_cycle_invalid_count, 1,
            "the dropped previous-cycle quorum must be reported back to the caller"
        );
        assert!(feed_result.all_fully_verified(), "the current cycle must still verify fully");
        assert!(
            feed_result.stored_cycle_height.is_some(),
            "the current cycle must still be stored"
        );

        // Without that height the same quarter is keyed by elimination, and a
        // signature that may belong to another cycle rebuilds the wrong member
        // set on its own. The identical corruption must then leave the quorum
        // out without blaming the peer for it.
        let (mut engine, mut qr_info) = load_qrinfo_2240504_fixture();
        qr_info.mn_list_diff_h.new_quorums[corrupt_position].all_commitment_aggregated_signature =
            foreign_signature;
        let feed_result = engine
            .feed_qr_info(qr_info, true, true)
            .expect("previous-cycle corruption must not abort the feed")
            .expect("expected a feed result");
        assert_eq!(
            feed_result.previous_cycle_invalid_count, 0,
            "a failure under an inferred quarter signature is a gap in our context, not the peer's fault"
        );
        assert_eq!(
            engine.rotated_quorums_per_cycle.get(&previous_cycle_key).map(|cycle| cycle.len()),
            Some(rotating_at_h - 1),
            "the quorum must still be left out of the stored cycle"
        );
    }

    /// Direct coverage for the `store_cycle_if_fully_verified` storage gate.
    /// The gate must short-circuit with `Ok(None)` (and not write) in two
    /// cases: any input entry is not `Verified`, or the target cycle is
    /// already fully `Verified`.
    #[cfg(feature = "quorum_validation")]
    #[test]
    fn store_cycle_if_fully_verified_short_circuits() {
        let (mut engine, qr_info) = load_qrinfo_2240504_fixture();
        engine.feed_qr_info(qr_info, false, true).expect("first feed should succeed");

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

        // Use a fresh cycle_key so the already-verified short-circuit cannot
        // fire. `make_qualified_quorum_entry` defaults `verified` to `Skipped`,
        // so the gate must refuse to write a degraded cycle.
        let fresh_key = BlockHash::from_byte_array([0xAB; 32]);
        let active_count = rotation_quorum_type.active_quorum_count() as i16;
        let degraded: Vec<QualifiedQuorumEntry> = (0..active_count)
            .map(|i| make_qualified_quorum_entry(rotation_quorum_type, Some(i)))
            .collect();
        let result = engine
            .store_cycle_if_fully_verified(fresh_key, degraded, rotation_quorum_type)
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
        assert_eq!(
            partial_cycle.len() + 1,
            complete_cycle.len(),
            "the partial cycle must be missing exactly one entry"
        );
        engine.rotated_quorums_per_cycle.insert(partial_key, partial_cycle);
        engine
            .store_cycle_if_fully_verified(
                partial_key,
                complete_cycle.clone(),
                rotation_quorum_type,
            )
            .expect("gate must not error when completing a partial cycle");
        assert_eq!(
            engine.rotated_quorums_per_cycle.get(&partial_key).map(|cycle| cycle.len()),
            Some(complete_cycle.len()),
            "a complete cycle must complete a partially stored one"
        );

        // Completion only ever adds: a verified set smaller than what is
        // already stored must leave the indices it does not carry in place,
        // otherwise one genuine commitment served by a peer degrades the rest
        // of the cycle.
        let shrink_key = BlockHash::from_byte_array([0xEF; 32]);
        let stored_before: BTreeMap<u16, QualifiedQuorumEntry> =
            original_cycle.iter().skip(1).map(|(index, q)| (*index, q.clone())).collect();
        engine.rotated_quorums_per_cycle.insert(shrink_key, stored_before.clone());
        let single_entry =
            vec![stored_before.values().next().expect("partial cycle non-empty").clone()];
        engine
            .store_cycle_if_fully_verified(shrink_key, single_entry, rotation_quorum_type)
            .expect("gate must not error when merging a smaller verified set");
        assert_eq!(
            engine.rotated_quorums_per_cycle.get(&shrink_key),
            Some(&stored_before),
            "a smaller verified set must not shrink a larger stored cycle"
        );
    }
}
