pub mod network;
pub mod rotation;

use std::fmt::{Display, Formatter};
use std::io;

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};

use crate::consensus::{Decodable, Encodable, encode};
use dash_network::Network;

/// Represents a DKG (Distributed Key Generation) mining window
/// This is the range of blocks where a quorum commitment can be mined
#[derive(Clone, Debug, PartialEq)]
pub struct DKGWindow {
    /// The first block of the DKG cycle (e.g., 0, 24, 48, 72...)
    pub cycle_start: u32,
    /// First block where mining can occur (cycle_start + mining_window_start)
    pub mining_start: u32,
    /// Last block where mining can occur (cycle_start + mining_window_end)
    pub mining_end: u32,
    /// The quorum type this window is for
    pub llmq_type: LLMQType,
}

#[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)]
pub struct DKGParams {
    pub interval: u32, // one DKG per hour
    pub phase_blocks: u32,
    pub mining_window_start: u32, // dkg_phase_blocks * 5 = after finalization
    pub mining_window_end: u32,
    pub bad_votes_threshold: u32,
}

#[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)]
pub struct LLMQParams {
    pub quorum_type: LLMQType,
    pub name: &'static str,
    pub size: u32,
    pub min_size: u32,
    pub threshold: u32,
    pub dkg_params: DKGParams,
    pub signing_active_quorum_count: u32, // just a few ones to allow easier testing
    pub keep_old_connections: u32,
    pub recovery_members: u32,
}

pub const DKG_TEST: DKGParams = DKGParams {
    interval: 24,
    phase_blocks: 2,
    mining_window_start: 10,
    mining_window_end: 18,
    bad_votes_threshold: 2,
};

pub const DKG_DEVNET: DKGParams = DKGParams {
    interval: 24,
    phase_blocks: 2,
    mining_window_start: 10,
    mining_window_end: 18,
    bad_votes_threshold: 7,
};
pub const DKG_DEVNET_DIP_0024: DKGParams = DKGParams {
    interval: 48,
    phase_blocks: 2,
    mining_window_start: 10,
    mining_window_end: 18,
    bad_votes_threshold: 7,
};
pub const DKG_50_60: DKGParams = DKGParams {
    interval: 24,
    phase_blocks: 2,
    mining_window_start: 10,
    mining_window_end: 18,
    bad_votes_threshold: 40,
};
pub const DKG_400_60: DKGParams = DKGParams {
    interval: 24 * 12,
    phase_blocks: 4,
    mining_window_start: 20,
    mining_window_end: 28,
    bad_votes_threshold: 300,
};
pub const DKG_400_85: DKGParams = DKGParams {
    interval: 24 * 24,
    phase_blocks: 4,
    mining_window_start: 20,
    mining_window_end: 48,
    bad_votes_threshold: 300,
};
pub const DKG_100_67: DKGParams = DKGParams {
    interval: 24,
    phase_blocks: 2,
    mining_window_start: 10,
    mining_window_end: 18,
    bad_votes_threshold: 80,
};

pub const DKG_60_75: DKGParams = DKGParams {
    interval: 24 * 12,
    phase_blocks: 2,
    mining_window_start: 42,
    mining_window_end: 50,
    bad_votes_threshold: 48,
};

pub const DKG_25_67: DKGParams = DKGParams {
    interval: 24,
    phase_blocks: 2,
    mining_window_start: 10,
    mining_window_end: 18,
    bad_votes_threshold: 22,
};

pub const DKG_PLATFORM_TESTNET: DKGParams = DKGParams {
    interval: 24 * 12,
    phase_blocks: 2,
    mining_window_start: 10,
    mining_window_end: 18,
    bad_votes_threshold: 2,
};

pub const DKG_PLATFORM_DEVNET: DKGParams = DKGParams {
    interval: 24 * 12,
    phase_blocks: 2,
    mining_window_start: 10,
    mining_window_end: 18,
    bad_votes_threshold: 7,
};

pub const LLMQ_TEST: LLMQParams = LLMQParams {
    quorum_type: LLMQType::LlmqtypeTest,
    name: "llmq_test",
    size: 4,
    min_size: 2,
    threshold: 2,
    dkg_params: DKG_TEST,
    signing_active_quorum_count: 2,
    keep_old_connections: 3,
    recovery_members: 3,
};
pub const LLMQ_V017: LLMQParams = LLMQParams {
    quorum_type: LLMQType::LlmqtypeTestV17,
    name: "llmq_test_v17",
    size: 3,
    min_size: 2,
    threshold: 2,
    dkg_params: DKG_TEST,
    signing_active_quorum_count: 2,
    keep_old_connections: 3,
    recovery_members: 3,
};
pub const LLMQ_0024: LLMQParams = LLMQParams {
    quorum_type: LLMQType::LlmqtypeDevnetDIP0024,
    name: "llmq_devnet_dip0024",
    size: 8,
    min_size: 6,
    threshold: 4,
    dkg_params: DKG_DEVNET_DIP_0024,
    signing_active_quorum_count: 2,
    keep_old_connections: 4,
    recovery_members: 4,
};
pub const LLMQ_TEST_DIP00024: LLMQParams = LLMQParams {
    quorum_type: LLMQType::LlmqtypeTestDIP0024,
    name: "llmq_test_dip0024",
    size: 4,
    min_size: 3,
    threshold: 2,
    dkg_params: DKG_TEST,
    signing_active_quorum_count: 2,
    keep_old_connections: 3,
    recovery_members: 3,
};
pub const LLMQ_TEST_INSTANT_SEND: LLMQParams = LLMQParams {
    quorum_type: LLMQType::LlmqtypeTestInstantSend,
    name: "llmq_test_instantsend",
    size: 3,
    min_size: 2,
    threshold: 2,
    dkg_params: DKG_TEST,
    signing_active_quorum_count: 2,
    keep_old_connections: 3,
    recovery_members: 3,
};

pub const LLMQ_DEVNET: LLMQParams = LLMQParams {
    quorum_type: LLMQType::LlmqtypeDevnet,
    name: "llmq_devnet",
    size: 12,
    min_size: 7,
    threshold: 6,
    dkg_params: DKG_DEVNET,
    signing_active_quorum_count: 4,
    keep_old_connections: 4,
    recovery_members: 6,
};

pub const LLMQ_50_60: LLMQParams = LLMQParams {
    quorum_type: LLMQType::Llmqtype50_60,
    name: "llmq_50_60",
    size: 50,
    min_size: 40,
    threshold: 30,
    dkg_params: DKG_50_60,
    signing_active_quorum_count: 24,
    keep_old_connections: 25,
    recovery_members: 25,
};
pub const LLMQ_400_60: LLMQParams = LLMQParams {
    quorum_type: LLMQType::Llmqtype400_60,
    name: "llmq_400_60",
    size: 400,
    min_size: 300,
    threshold: 240,
    dkg_params: DKG_400_60,
    signing_active_quorum_count: 4,
    keep_old_connections: 5,
    recovery_members: 100,
};
pub const LLMQ_400_85: LLMQParams = LLMQParams {
    quorum_type: LLMQType::Llmqtype400_85,
    name: "llmq_400_85",
    size: 400,
    min_size: 350,
    threshold: 340,
    dkg_params: DKG_400_85,
    signing_active_quorum_count: 4,
    keep_old_connections: 5,
    recovery_members: 100,
};
pub const LLMQ_100_67: LLMQParams = LLMQParams {
    quorum_type: LLMQType::Llmqtype100_67,
    name: "llmq_100_67",
    size: 100,
    min_size: 80,
    threshold: 67,
    dkg_params: DKG_100_67,
    signing_active_quorum_count: 24,
    keep_old_connections: 25,
    recovery_members: 50,
};
pub const LLMQ_60_75: LLMQParams = LLMQParams {
    quorum_type: LLMQType::Llmqtype60_75,
    name: "llmq_60_75",
    size: 60,
    min_size: 50,
    threshold: 45,
    dkg_params: DKG_60_75,
    signing_active_quorum_count: 32,
    keep_old_connections: 64,
    recovery_members: 25,
};

pub const LLMQ_25_67: LLMQParams = LLMQParams {
    quorum_type: LLMQType::Llmqtype25_67,
    name: "llmq_25_67",
    size: 25,
    min_size: 22,
    threshold: 17,
    dkg_params: DKG_25_67,
    signing_active_quorum_count: 24,
    keep_old_connections: 25,
    recovery_members: 12,
};

pub const LLMQ_TEST_PLATFORM: LLMQParams = LLMQParams {
    quorum_type: LLMQType::LlmqtypeTestnetPlatform,
    name: "llmq_test_platform",
    size: 3,
    min_size: 2,
    threshold: 2,
    dkg_params: DKG_PLATFORM_TESTNET,
    signing_active_quorum_count: 2,
    keep_old_connections: 4,
    recovery_members: 3,
};

pub const LLMQ_DEV_PLATFORM: LLMQParams = LLMQParams {
    quorum_type: LLMQType::LlmqtypeDevnetPlatform,
    name: "llmq_dev_platform",
    size: 12,
    min_size: 9,
    threshold: 8,
    dkg_params: DKG_PLATFORM_DEVNET,
    signing_active_quorum_count: 4,
    keep_old_connections: 4,
    recovery_members: 3,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum LLMQType {
    LlmqtypeUnknown = 0, // other kind of
    Llmqtype50_60 = 1,   // 50 members,  30  (60%) threshold, 24 / day
    Llmqtype400_60 = 2,  // 400 members, 240 (60%) threshold, 2  / day
    Llmqtype400_85 = 3,  // 400 members, 340 (85%) threshold, 1  / day
    Llmqtype100_67 = 4,  // 100 members, 67  (67%) threshold, 24 / day
    Llmqtype60_75 = 5,   // 60 members,  45  (75%) threshold, 2  / day
    Llmqtype25_67 = 6,   // 25 members,  67  (67%) threshold, 24 / day

    // dev-only
    LlmqtypeTest = 100,            // 3 members, 2 (66%) threshold, one per hour
    LlmqtypeDevnet = 101,          // 10 members, 6 (60%) threshold, one per hour
    LlmqtypeTestV17 = 102, // 3 members, 2 (66%) threshold, one per hour. Params might differ when -llmqtestparams is used
    LlmqtypeTestDIP0024 = 103, // 4 members, 2 (66%) threshold, one per hour. Params might differ when -llmqtestparams is used
    LlmqtypeTestInstantSend = 104, // 3 members, 2 (66%) threshold, one per hour. Params might differ when -llmqtestparams is used
    LlmqtypeDevnetDIP0024 = 105, // 8 members, 4 (50%) threshold, one per hour. Params might differ when -llmqdevnetparams is used
    LlmqtypeTestnetPlatform = 106, // 8 members, 4 (50%) threshold, one per hour. Params might differ when -llmqdevnetparams is used
    LlmqtypeDevnetPlatform = 107, // 8 members, 4 (50%) threshold, one per hour. Params might differ when -llmqdevnetparams is used
}

impl Display for LLMQType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                LLMQType::LlmqtypeUnknown => "0_Unknown",
                LLMQType::Llmqtype50_60 => "1_50/60",
                LLMQType::Llmqtype400_60 => "2_400/60",
                LLMQType::Llmqtype400_85 => "3_400/85",
                LLMQType::Llmqtype100_67 => "4_100/67",
                LLMQType::Llmqtype60_75 => "5_60/75",
                LLMQType::Llmqtype25_67 => "6_25/67",
                LLMQType::LlmqtypeTest => "100_Test",
                LLMQType::LlmqtypeDevnet => "101_Dev",
                LLMQType::LlmqtypeTestV17 => "102_Test-v17",
                LLMQType::LlmqtypeTestDIP0024 => "103_Test-dip-24",
                LLMQType::LlmqtypeTestInstantSend => "104_Test-IS",
                LLMQType::LlmqtypeDevnetDIP0024 => "105_Dev-dip-24",
                LLMQType::LlmqtypeTestnetPlatform => "106_Test-Platform",
                LLMQType::LlmqtypeDevnetPlatform => "107_Dev-Platform",
            }
        )
    }
}

impl LLMQType {
    pub fn params(&self) -> LLMQParams {
        match self {
            LLMQType::Llmqtype50_60 => LLMQ_50_60,
            LLMQType::Llmqtype400_60 => LLMQ_400_60,
            LLMQType::Llmqtype400_85 => LLMQ_400_85,
            LLMQType::Llmqtype100_67 => LLMQ_100_67,
            LLMQType::Llmqtype60_75 => LLMQ_60_75,
            LLMQType::Llmqtype25_67 => LLMQ_25_67,
            LLMQType::LlmqtypeTest => LLMQ_TEST,
            LLMQType::LlmqtypeDevnet => LLMQ_DEVNET,
            LLMQType::LlmqtypeTestV17 => LLMQ_V017,
            LLMQType::LlmqtypeTestDIP0024 => LLMQ_TEST_DIP00024,
            LLMQType::LlmqtypeTestInstantSend => LLMQ_TEST_INSTANT_SEND,
            LLMQType::LlmqtypeDevnetDIP0024 => LLMQ_0024,
            LLMQType::LlmqtypeTestnetPlatform => LLMQ_TEST_PLATFORM,
            LLMQType::LlmqtypeDevnetPlatform => LLMQ_DEV_PLATFORM,
            LLMQType::LlmqtypeUnknown => LLMQ_DEVNET,
        }
    }
    pub fn size(&self) -> u32 {
        self.params().size
    }

    pub fn threshold(&self) -> u32 {
        self.params().threshold
    }

    pub fn active_quorum_count(&self) -> u32 {
        self.params().signing_active_quorum_count
    }
}

impl From<u8> for LLMQType {
    fn from(orig: u8) -> Self {
        match orig {
            1 => LLMQType::Llmqtype50_60,
            2 => LLMQType::Llmqtype400_60,
            3 => LLMQType::Llmqtype400_85,
            4 => LLMQType::Llmqtype100_67,
            5 => LLMQType::Llmqtype60_75,
            6 => LLMQType::Llmqtype25_67,
            100 => LLMQType::LlmqtypeTest,
            101 => LLMQType::LlmqtypeDevnet,
            102 => LLMQType::LlmqtypeTestV17,
            103 => LLMQType::LlmqtypeTestDIP0024,
            104 => LLMQType::LlmqtypeTestInstantSend,
            105 => LLMQType::LlmqtypeDevnetDIP0024,
            106 => LLMQType::LlmqtypeTestnetPlatform,
            107 => LLMQType::LlmqtypeDevnetPlatform,
            _ => LLMQType::LlmqtypeUnknown,
        }
    }
}

impl From<LLMQType> for u8 {
    fn from(value: LLMQType) -> Self {
        match value {
            LLMQType::LlmqtypeUnknown => 0,
            LLMQType::Llmqtype50_60 => 1,
            LLMQType::Llmqtype400_60 => 2,
            LLMQType::Llmqtype400_85 => 3,
            LLMQType::Llmqtype100_67 => 4,
            LLMQType::Llmqtype60_75 => 5,
            LLMQType::Llmqtype25_67 => 6,
            LLMQType::LlmqtypeTest => 100,
            LLMQType::LlmqtypeDevnet => 101,
            LLMQType::LlmqtypeTestV17 => 102,
            LLMQType::LlmqtypeTestDIP0024 => 103,
            LLMQType::LlmqtypeTestInstantSend => 104,
            LLMQType::LlmqtypeDevnetDIP0024 => 105,
            LLMQType::LlmqtypeTestnetPlatform => 106,
            LLMQType::LlmqtypeDevnetPlatform => 107,
        }
    }
}
impl From<&LLMQType> for u64 {
    fn from(value: &LLMQType) -> Self {
        match value {
            LLMQType::LlmqtypeUnknown => 0,
            LLMQType::Llmqtype50_60 => 1,
            LLMQType::Llmqtype400_60 => 2,
            LLMQType::Llmqtype400_85 => 3,
            LLMQType::Llmqtype100_67 => 4,
            LLMQType::Llmqtype60_75 => 5,
            LLMQType::Llmqtype25_67 => 6,
            LLMQType::LlmqtypeTest => 100,
            LLMQType::LlmqtypeDevnet => 101,
            LLMQType::LlmqtypeTestV17 => 102,
            LLMQType::LlmqtypeTestDIP0024 => 103,
            LLMQType::LlmqtypeTestInstantSend => 104,
            LLMQType::LlmqtypeDevnetDIP0024 => 105,
            LLMQType::LlmqtypeTestnetPlatform => 106,
            LLMQType::LlmqtypeDevnetPlatform => 107,
        }
    }
}

impl Encodable for LLMQType {
    fn consensus_encode<S: io::Write + ?Sized>(&self, mut s: &mut S) -> Result<usize, io::Error> {
        u8::consensus_encode(&self.index(), &mut s)
    }
}

impl Decodable for LLMQType {
    fn consensus_decode<D: io::Read + ?Sized>(mut d: &mut D) -> Result<LLMQType, encode::Error> {
        u8::consensus_decode(&mut d).map(LLMQType::from)
    }
}

pub fn dkg_rotation_params(network: Network) -> DKGParams {
    if network == Network::Devnet {
        DKG_DEVNET_DIP_0024
    } else {
        DKG_60_75
    }
}

impl LLMQType {
    pub fn index(&self) -> u8 {
        u8::from(self.clone())
    }
    pub fn from_u16(index: u16) -> LLMQType {
        LLMQType::from(index as u8)
    }
    pub fn from_u8(index: u8) -> LLMQType {
        LLMQType::from(index)
    }

    pub fn is_rotating_quorum_type(&self) -> bool {
        match self {
            LLMQType::Llmqtype60_75
            | LLMQType::LlmqtypeDevnetDIP0024
            | LLMQType::LlmqtypeTestDIP0024 => true,
            _ => false,
        }
    }

    /// Calculate the cycle base height for a given block height
    pub fn get_cycle_base_height(&self, height: u32) -> u32 {
        let interval = self.params().dkg_params.interval;
        (height / interval) * interval
    }

    /// Get the DKG window that would contain a commitment mined at the given height
    pub fn get_dkg_window_for_height(&self, height: u32) -> DKGWindow {
        let params = self.params();
        let cycle_start = self.get_cycle_base_height(height);

        // For rotating quorums, the mining window calculation is different
        let mining_start = if self.is_rotating_quorum_type() {
            // For rotating quorums: signingActiveQuorumCount + dkgPhaseBlocks * 5
            cycle_start + params.signing_active_quorum_count + params.dkg_params.phase_blocks * 5
        } else {
            // For non-rotating quorums: use the standard mining window start
            cycle_start + params.dkg_params.mining_window_start
        };

        let mining_end = cycle_start + params.dkg_params.mining_window_end;

        DKGWindow {
            cycle_start,
            mining_start,
            mining_end,
            llmq_type: *self,
        }
    }

    /// Get all DKG windows that could have mining activity in the given range
    ///
    /// Example: If range is 100-200 and DKG interval is 24:
    /// - Cycles: 96, 120, 144, 168, 192
    /// - For each cycle, check if its mining window (e.g., cycle+10 to cycle+18)
    ///   overlaps with our range [100, 200]
    /// - Return only windows where mining could occur within our range
    pub fn get_dkg_windows_in_range(&self, start: u32, end: u32) -> Vec<DKGWindow> {
        let params = self.params();
        let interval = params.dkg_params.interval;

        let mut windows = Vec::new();

        // Start from the cycle that could contain 'start'
        // Go back one full cycle to catch windows that might extend into our range
        let first_possible_cycle =
            ((start.saturating_sub(params.dkg_params.mining_window_end)) / interval) * interval;

        log::trace!(
            "get_dkg_windows_in_range for {:?}: start={}, end={}, interval={}, first_cycle={}",
            self,
            start,
            end,
            interval,
            first_possible_cycle
        );

        let mut cycle_start = first_possible_cycle;
        let mut _cycles_checked = 0;
        while cycle_start <= end {
            let window = self.get_dkg_window_for_height(cycle_start);

            // Include this window if its mining period overlaps with [start, end]
            if window.mining_end >= start && window.mining_start <= end {
                windows.push(window.clone());
                log::trace!(
                    "  Added window: cycle={}, mining={}-{}",
                    window.cycle_start,
                    window.mining_start,
                    window.mining_end
                );
            }

            cycle_start += interval;
            _cycles_checked += 1;
        }

        log::trace!(
            "get_dkg_windows_in_range for {:?}: checked {} cycles, found {} windows",
            self,
            _cycles_checked,
            windows.len()
        );

        windows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_cycle_base_height() {
        let llmq = LLMQType::Llmqtype50_60; // interval 24
        assert_eq!(llmq.get_cycle_base_height(0), 0);
        assert_eq!(llmq.get_cycle_base_height(23), 0);
        assert_eq!(llmq.get_cycle_base_height(24), 24);
        assert_eq!(llmq.get_cycle_base_height(50), 48);
        assert_eq!(llmq.get_cycle_base_height(100), 96);
    }

    #[test]
    fn test_dkg_window_for_non_rotating_quorum() {
        let llmq = LLMQType::Llmqtype50_60; // non-rotating, interval 24
        let window = llmq.get_dkg_window_for_height(48);

        assert_eq!(window.cycle_start, 48);
        assert_eq!(window.mining_start, 58); // 48 + 10 (mining_window_start)
        assert_eq!(window.mining_end, 66); // 48 + 18 (mining_window_end)
        assert_eq!(window.llmq_type, LLMQType::Llmqtype50_60);
    }

    #[test]
    fn test_dkg_window_for_rotating_quorum() {
        let llmq = LLMQType::Llmqtype60_75; // rotating quorum
        let window = llmq.get_dkg_window_for_height(288);

        // For rotating: cycle_start + signingActiveQuorumCount + dkgPhaseBlocks * 5
        // 288 + 32 + 2 * 5 = 330
        assert_eq!(window.cycle_start, 288);
        assert_eq!(window.mining_start, 330);
        assert_eq!(window.mining_end, 338); // 288 + 50 (mining_window_end)
        assert_eq!(window.llmq_type, LLMQType::Llmqtype60_75);
    }

    #[test]
    fn test_get_dkg_windows_in_range() {
        let llmq = LLMQType::Llmqtype50_60; // interval 24

        // Range from 100 to 200
        let windows = llmq.get_dkg_windows_in_range(100, 200);

        // Expected cycles: 96, 120, 144, 168, 192
        // Mining windows: 96+10..96+18, 120+10..120+18, etc.
        // Windows that overlap with [100, 200]:
        // - 96: mining 106-114 (overlaps)
        // - 120: mining 130-138 (included)
        // - 144: mining 154-162 (included)
        // - 168: mining 178-186 (included)
        // - 192: mining 202-210 (mining_start > 200, excluded)

        assert_eq!(windows.len(), 4);
        assert_eq!(windows[0].cycle_start, 96);
        assert_eq!(windows[1].cycle_start, 120);
        assert_eq!(windows[2].cycle_start, 144);
        assert_eq!(windows[3].cycle_start, 168);
    }

    #[test]
    fn test_get_dkg_windows_edge_cases() {
        let llmq = LLMQType::Llmqtype50_60;

        // Empty range
        let windows = llmq.get_dkg_windows_in_range(100, 100);
        assert_eq!(windows.len(), 0);

        // Range smaller than one interval
        let windows = llmq.get_dkg_windows_in_range(100, 110);
        assert_eq!(windows.len(), 1); // Only cycle 96 overlaps

        // Range starting at cycle boundary
        let windows = llmq.get_dkg_windows_in_range(120, 144);
        assert_eq!(windows.len(), 1); // Only cycle 120, since 144's mining window (154-162) starts after range end
    }

    #[test]
    fn test_platform_quorum_dkg_params() {
        let llmq = LLMQType::Llmqtype100_67; // Platform consensus
        let params = llmq.params();

        assert_eq!(params.dkg_params.interval, 24);
        assert_eq!(params.size, 100);
        assert_eq!(params.threshold, 67);
        assert_eq!(params.signing_active_quorum_count, 24);
    }
}
