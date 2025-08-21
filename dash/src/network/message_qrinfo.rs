use core::fmt::{Display, Formatter};
use std::{fmt, io};

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};

use crate::BlockHash;
use crate::consensus::encode::{read_compact_size, read_fixed_bitset, write_fixed_bitset};
use crate::consensus::{Decodable, Encodable, encode};
use crate::internal_macros::impl_consensus_encoding;
use crate::network::message_sml::MnListDiff;
use crate::transaction::special_transaction::quorum_commitment::QuorumEntry;

/// The `getqrinfo` message requests a `qrinfo` message that provides the information
/// required to verify quorum details for quorums formed using the quorum rotation process.
///
/// Fields:
/// - `base_block_hashes`: Array of base block hashes for the masternode lists the light client already knows
/// - `block_request_hash`: Hash of the block for which the masternode list diff is requested
/// - `extra_share`: Optional flag to indicate if an extra share is requested (defaults to false)
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GetQRInfo {
    pub base_block_hashes: Vec<BlockHash>,
    pub block_request_hash: BlockHash,
    pub extra_share: bool,
}

impl_consensus_encoding!(GetQRInfo, base_block_hashes, block_request_hash, extra_share);

/// The `qrinfo` message sends quorum rotation information for a given block height.
///
/// All fields are required except the h-4c fields, which are only present when `extra_share` is true.
///
/// Note: The “compact size” integers that prefix some arrays are handled by your consensus encoding routines.
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct QRInfo {
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
    // A compact size uint (the count) followed by quorum entries.
    pub last_commitment_per_index: Vec<QuorumEntry>,

    // quorumSnapshotList:
    // A compact size uint count followed by that many CQuorumSnapshot entries.
    pub quorum_snapshot_list: Vec<QuorumSnapshot>,

    // mnListDiffList:
    // A compact size uint count followed by that many CSimplifiedMNListDiff entries.
    pub mn_list_diff_list: Vec<MnListDiff>,
}

impl Encodable for QRInfo {
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

impl Decodable for QRInfo {
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
        let quorum_snapshot_and_mn_list_diff_at_h_minus_4c = if extra_share {
            let qs4c = QuorumSnapshot::consensus_decode(r)?;
            let mnd4c = MnListDiff::consensus_decode(r)?;
            Some((qs4c, mnd4c))
        } else {
            None
        };

        let last_commitment_per_index = Vec::consensus_decode(r)?;
        let quorum_snapshot_list = Vec::consensus_decode(r)?;
        let mn_list_diff_list = Vec::consensus_decode(r)?;

        Ok(QRInfo {
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
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]

pub struct QuorumSnapshot {
    pub skip_list_mode: MNSkipListMode,
    pub active_quorum_members: Vec<bool>, // Bitset, length = (active_quorum_members_count + 7) / 8
    pub skip_list: Vec<i32>,              // Array of uint32_t
}

impl Display for QuorumSnapshot {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let active_members_display: String = self
            .active_quorum_members
            .iter()
            .map(|&member| {
                if member {
                    '■'
                } else {
                    'x'
                }
            }) // Use `■` for true, `x` for false
            .collect();

        let skip_list = self.skip_list.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");

        write!(
            f,
            "mode: {} members: [{}] skip_list: [{}]",
            active_members_display, self.skip_list_mode, skip_list
        )
    }
}

impl Encodable for QuorumSnapshot {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.skip_list_mode.consensus_encode(w)?;
        len += write_fixed_bitset(
            w,
            self.active_quorum_members.as_slice(),
            self.active_quorum_members.iter().len(),
        )?;
        len += self.skip_list.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for QuorumSnapshot {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let mn_skip_list_mode = MNSkipListMode::consensus_decode(r)?;
        let active_quorum_members_count = read_compact_size(r)?;
        let active_quorum_members = read_fixed_bitset(r, active_quorum_members_count as usize)?;
        let mn_skip_list = Vec::consensus_decode(r)?;
        Ok(QuorumSnapshot {
            skip_list_mode: mn_skip_list_mode,
            active_quorum_members,
            skip_list: mn_skip_list,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]

pub enum MNSkipListMode {
    /// Mode 0: No skipping – the skip list is empty.
    NoSkipping = 0,
    /// Mode 1: Skip the first entry; subsequent entries contain relative skips.
    ///
    /// The following entries contain the relative position of subsequent skips.
    /// For example, if during the initialization phase you skip entries x, y and z of the models
    /// list, the skip list will contain x, y-x and z-y in this mode.
    SkipFirst = 1,
    /// Mode 2: Contains the entries which were not skipped.
    ///
    ///
    /// This is better when there are many skips.
    /// Mode 2 is more efficient and should be used when 3/4*quorumSize ≥ 1/2*masternodeNb or
    /// quorumsize ≥ 2/3*masternodeNb
    SkipExcept = 2,
    /// Mode 3: Every node was skipped – the skip list is empty (no DKG sessions attempted).
    SkipAll = 3,
}

impl From<u32> for MNSkipListMode {
    fn from(orig: u32) -> Self {
        match orig {
            0 => MNSkipListMode::NoSkipping,
            1 => MNSkipListMode::SkipFirst,
            2 => MNSkipListMode::SkipExcept,
            3 => MNSkipListMode::SkipAll,
            _ => MNSkipListMode::NoSkipping,
        }
    }
}
impl From<MNSkipListMode> for u32 {
    fn from(orig: MNSkipListMode) -> Self {
        match orig {
            MNSkipListMode::NoSkipping => 0,
            MNSkipListMode::SkipFirst => 1,
            MNSkipListMode::SkipExcept => 2,
            MNSkipListMode::SkipAll => 3,
        }
    }
}
impl MNSkipListMode {
    pub fn index(&self) -> u32 {
        u32::from(self.clone())
    }
}
pub fn from_index(index: u32) -> MNSkipListMode {
    MNSkipListMode::from(index)
}

impl Display for MNSkipListMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let description = match self {
            MNSkipListMode::NoSkipping => "No Skipping (empty list)",
            MNSkipListMode::SkipFirst => "Skip First Entry (relative skips)",
            MNSkipListMode::SkipExcept => "Not Skipped Entries (explicit list)",
            MNSkipListMode::SkipAll => "All Nodes Skipped (empty list, no DKG)",
        };
        write!(f, "{}", description)
    }
}

impl Default for MNSkipListMode {
    fn default() -> Self {
        MNSkipListMode::NoSkipping
    }
}

impl Encodable for MNSkipListMode {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (*self as u32).consensus_encode(w)
    }
}

impl Decodable for MNSkipListMode {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let value = i32::consensus_decode(r)?;
        match value {
            0 => Ok(MNSkipListMode::NoSkipping),
            1 => Ok(MNSkipListMode::SkipFirst),
            2 => Ok(MNSkipListMode::SkipExcept),
            3 => Ok(MNSkipListMode::SkipAll),
            _ => Err(encode::Error::ParseFailed("Invalid MnSkipListMode")),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{self, Read};

    use crate::consensus::deserialize;
    use crate::network::message::{NetworkMessage, RawNetworkMessage};

    fn read_binary_file(filename: &str) -> io::Result<Vec<u8>> {
        let mut file = File::open(filename)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    #[test]
    fn deserialize_qr_info() {
        let block_hex = include_str!("../../tests/data/test_DML_diffs/QR_INFO_0_2224359.hex");
        let data = hex::decode(block_hex).expect("decode hex");
        let network_qr_info: RawNetworkMessage = deserialize(&data).expect("deserialize QR_INFO");

        let RawNetworkMessage {
            magic,
            payload: NetworkMessage::QRInfo(_qr_info),
        } = network_qr_info
        else {
            panic!("expected qr_info message");
        };
        assert_eq!(magic, 3177909439);
    }
}
