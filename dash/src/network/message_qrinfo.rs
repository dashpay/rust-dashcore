use std::io;
use crate::BlockHash;
use crate::consensus::{encode, Decodable, Encodable};
use crate::consensus::encode::{read_compact_size, read_fixed_bitset, write_fixed_bitset};
use crate::internal_macros::impl_consensus_encoding;
use crate::network::message_sml::MnListDiff;

/// The `getqrinfo` message requests a `qrinfo` message that provides the information
/// required to verify quorum details for quorums formed using the quorum rotation process.
///
/// Fields:
/// - `base_block_hashes`: Array of base block hashes for the masternode lists the light client already knows
/// - `block_request_hash`: Hash of the block for which the masternode list diff is requested
/// - `extra_share`: Optional flag to indicate if an extra share is requested (defaults to false)
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetQrInfo {
    pub base_block_hashes: Vec<BlockHash>,
    pub block_request_hash: BlockHash,
    pub extra_share: bool,
}

impl_consensus_encoding!(GetQrInfo,
    base_block_hashes,
    block_request_hash,
    extra_share
);

/// The `qrinfo` message sends quorum rotation information for a given block height.
///
/// All fields are required except the h-4c fields, which are only present when `extra_share` is true.
///
/// Note: The “compact size” integers that prefix some arrays are handled by your consensus encoding routines.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct QrInfo {
    // Quorum snapshots for heights h-c, h-2c, h-3c.
    pub quorum_snapshot_at_h_minus_c: QuorumSnapshot,
    pub quorum_snapshot_at_h_minus_2c: QuorumSnapshot,
    pub quorum_snapshot_at_h_minus_3c: QuorumSnapshot,

    // Masternode list diffs.
    pub mn_list_diff_tip: MnListDiff,
    pub mn_list_diff_h: MnListDiff,
    pub mn_list_diff_at_h_minus_c: MnListDiff,
    pub mn_list_diff_at_h_minus_2c: MnListDiff,
    pub mn_list_diff_at_h_minus_3c: MnListDiff,

    // These fields are present only if extra_share is true.
    pub quorum_snapshot_and_mn_list_diff_at_h_minus_4c: Option<(QuorumSnapshot, MnListDiff)>,

    // lastQuorumHashPerIndex:
    // A compact size uint (the count) followed by that many 32-byte hashes.
    pub last_commitment_per_index: Vec<BlockHash>,

    // quorumSnapshotList:
    // A compact size uint count followed by that many CQuorumSnapshot entries.
    pub quorum_snapshot_list: Vec<QuorumSnapshot>,

    // mnListDiffList:
    // A compact size uint count followed by that many CSimplifiedMNListDiff entries.
    pub mn_list_diff_list: Vec<MnListDiff>,
}

impl Encodable for QrInfo {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        // Encode the three required quorum snapshots.
        len += self.quorum_snapshot_at_h_minus_c.consensus_encode(w)?;
        len += self.quorum_snapshot_at_h_minus_2c.consensus_encode(w)?;
        len += self.quorum_snapshot_at_h_minus_3c.consensus_encode(w)?;

        // Encode the five required masternode list diffs.
        len += self.mn_list_diff_tip.consensus_encode(w)?;
        len += self.mn_list_diff_h.consensus_encode(w)?;
        len += self.mn_list_diff_at_h_minus_c.consensus_encode(w)?;
        len += self.mn_list_diff_at_h_minus_2c.consensus_encode(w)?;
        len += self.mn_list_diff_at_h_minus_3c.consensus_encode(w)?;

        if let Some((qs4c, mnd4c)) = &self.quorum_snapshot_and_mn_list_diff_at_h_minus_4c {
            len += 1u8.consensus_encode(w)?;
            len += qs4c.consensus_encode(w)?;
            len += mnd4c.consensus_encode(w)?;
        } else {
            len += 0u8.consensus_encode(w)?;
        }
        len += self.last_commitment_per_index.consensus_encode(w)?;
        len += self.quorum_snapshot_list.consensus_encode(w)?;
        len += self.mn_list_diff_list.consensus_encode(w)?;

        Ok(len)
    }
}

impl Decodable for QrInfo {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        // Decode the three quorum snapshots.
        let quorum_snapshot_at_h_minus_c = QuorumSnapshot::consensus_decode(r)?;
        let quorum_snapshot_at_h_minus_2c = QuorumSnapshot::consensus_decode(r)?;
        let quorum_snapshot_at_h_minus_3c = QuorumSnapshot::consensus_decode(r)?;

        // Decode the five masternode list diffs.
        let mn_list_diff_tip = MnListDiff::consensus_decode(r)?;
        let mn_list_diff_h = MnListDiff::consensus_decode(r)?;
        let mn_list_diff_at_h_minus_c = MnListDiff::consensus_decode(r)?;
        let mn_list_diff_at_h_minus_2c = MnListDiff::consensus_decode(r)?;
        let mn_list_diff_at_h_minus_3c = MnListDiff::consensus_decode(r)?;

        // Decode extra_share.
        let extra_share: bool = Decodable::consensus_decode(r)?;
        // If extra_share is true, then decode the optional fields.
        let (quorum_snapshot_and_mn_list_diff_at_h_minus_4c) = if extra_share {
            let qs4c = QuorumSnapshot::consensus_decode(r)?;
            let mnd4c = MnListDiff::consensus_decode(r)?;
            Some((qs4c, mnd4c))
        } else {
            None
        };

        let last_commitment_per_index = Vec::consensus_decode(r)?;
        let quorum_snapshot_list = Vec::consensus_decode(r)?;
        let mn_list_diff_list = Vec::consensus_decode(r)?;

        Ok(QrInfo {
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
        })
    }
}


/// A snapshot of quorum-related information at a given cycle height.
///
/// Fields:
/// - `mn_skip_list_mode`: A 4-byte signed integer representing the mode of the skip list.
/// - `active_quorum_members_count`: A compact-size unsigned integer representing the number of active quorum members.
/// - `active_quorum_members`: A bitset (stored as a Vec<u8>) with length =
///    (active_quorum_members_count + 7) / 8.
/// - `mn_skip_list_size`: A compact-size unsigned integer representing the number of skip list entries.
/// - `mn_skip_list`: An array of 4-byte signed integers, one per skip list entry.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct QuorumSnapshot {
    pub mn_skip_list_mode: MnSkipListMode,
    pub active_quorum_members: Vec<bool>,   // Bitset, length = (active_quorum_members_count + 7) / 8
    pub mn_skip_list: Vec<u32>,           // Array of int32_t
}

impl Encodable for QuorumSnapshot {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.mn_skip_list_mode.consensus_encode(w)?;
        len +=
            write_fixed_bitset(w, self.active_quorum_members.as_slice(), self.active_quorum_members.iter().len())?;
        len += self.mn_skip_list.consensus_encode(w)?;
        Ok(len)
    }
}


impl Decodable for QuorumSnapshot {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let mn_skip_list_mode = MnSkipListMode::consensus_decode(r)?;
        let active_quorum_members_count = read_compact_size(r)?;
        let active_quorum_members = read_fixed_bitset(r, active_quorum_members_count as usize)?;
        let mn_skip_list = Vec::consensus_decode(r)?;
        Ok(QuorumSnapshot {
            mn_skip_list_mode,
            active_quorum_members,
            mn_skip_list,
        })
    }
}


#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
pub enum MnSkipListMode {
    /// Mode 0: No skipping – the skip list is empty.
    NoSkipping = 0,
    /// Mode 1: Skip the first entry; subsequent entries contain relative skips.
    SkipFirstEntry = 1,
    /// Mode 2: Contains the entries which were not skipped.
    NotSkippedEntries = 2,
    /// Mode 3: Every node was skipped – the skip list is empty (no DKG sessions attempted).
    AllNodesSkipped = 3,
}

impl Default for MnSkipListMode {
    fn default() -> Self {
        MnSkipListMode::NoSkipping
    }
}

impl Encodable for MnSkipListMode {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (*self as u32).consensus_encode(w)
    }
}

impl Decodable for MnSkipListMode {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let value = i32::consensus_decode(r)?;
        match value {
            0 => Ok(MnSkipListMode::NoSkipping),
            1 => Ok(MnSkipListMode::SkipFirstEntry),
            2 => Ok(MnSkipListMode::NotSkippedEntries),
            3 => Ok(MnSkipListMode::AllNodesSkipped),
            _ => Err(encode::Error::ParseFailed("Invalid MnSkipListMode")),
        }
    }
}