mod network;
// pub mod rotation;
// pub mod snapshot;
// pub mod quorum_snapshot_skip_mode;

use std::fmt::{Display, Formatter};
use std::io;
use crate::bip152::BlockTransactionsRequest;
use crate::consensus::{Decodable, Encodable, encode};
use crate::Network;

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
    pub r#type: LLMQType,
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
    interval: 2,
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
    r#type: LLMQType::LlmqtypeTest,
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
    r#type: LLMQType::LlmqtypeTestV17,
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
    r#type: LLMQType::LlmqtypeDevnetDIP0024,
    name: "llmq_devnet_dip0024",
    size: 8,
    min_size: 6,
    threshold: 4,
    dkg_params: DKG_DEVNET_DIP_0024,
    signing_active_quorum_count: 2,
    keep_old_connections: 4,
    recovery_members: 4,
};
pub const LLMQ_0024_333: LLMQParams = LLMQParams {
    r#type: LLMQType::LlmqtypeDevnetDIP0024,
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
    r#type: LLMQType::LlmqtypeTestDIP0024,
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
    r#type: LLMQType::LlmqtypeTestInstantSend,
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
    r#type: LLMQType::LlmqtypeDevnet,
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
    r#type: LLMQType::Llmqtype50_60,
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
    r#type: LLMQType::Llmqtype400_60,
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
    r#type: LLMQType::Llmqtype400_60,
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
    r#type: LLMQType::Llmqtype100_67,
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
    r#type: LLMQType::Llmqtype60_75,
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
    r#type: LLMQType::Llmqtype25_67,
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
    r#type: LLMQType::LlmqtypeTestnetPlatform,
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
    r#type: LLMQType::LlmqtypeDevnetPlatform,
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
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub enum LLMQType {
    LlmqtypeUnknown = 0,    // other kind of
    Llmqtype50_60 = 1,      // 50 members,  30  (60%) threshold, 24 / day
    Llmqtype400_60 = 2,     // 400 members, 240 (60%) threshold, 2  / day
    Llmqtype400_85 = 3,     // 400 members, 340 (85%) threshold, 1  / day
    Llmqtype100_67 = 4,     // 100 members, 67  (67%) threshold, 24 / day
    Llmqtype60_75 = 5,      // 60 members,  45  (75%) threshold, 2  / day
    Llmqtype25_67 = 6,      // 25 members,  67  (67%) threshold, 24 / day

    // dev-only
    LlmqtypeTest = 100,             // 3 members, 2 (66%) threshold, one per hour
    LlmqtypeDevnet = 101,           // 10 members, 6 (60%) threshold, one per hour
    LlmqtypeTestV17 = 102, // 3 members, 2 (66%) threshold, one per hour. Params might differ when -llmqtestparams is used
    LlmqtypeTestDIP0024 = 103, // 4 members, 2 (66%) threshold, one per hour. Params might differ when -llmqtestparams is used
    LlmqtypeTestInstantSend = 104, // 3 members, 2 (66%) threshold, one per hour. Params might differ when -llmqtestparams is used
    LlmqtypeDevnetDIP0024 = 105, // 8 members, 4 (50%) threshold, one per hour. Params might differ when -llmqdevnetparams is used
    LlmqtypeTestnetPlatform = 106, // 8 members, 4 (50%) threshold, one per hour. Params might differ when -llmqdevnetparams is used
    LlmqtypeDevnetPlatform = 107, // 8 members, 4 (50%) threshold, one per hour. Params might differ when -llmqdevnetparams is used
}

impl Display for LLMQType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
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
        })
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
    fn consensus_decode<D: io::Read + ?Sized>(
        mut d: &mut D,
    ) -> Result<LLMQType, encode::Error> {
        u8::consensus_decode(&mut d)
            .map(LLMQType::from)
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
}