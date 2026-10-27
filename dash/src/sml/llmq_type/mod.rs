pub mod network;
pub mod rotation;

use std::fmt::{Display, Formatter};
use std::io;
use std::sync::OnceLock;

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};

use dash_params::LlmqType as CoreLlmqType;
use dash_types::Numeric;

use crate::consensus::{Decodable, Encodable, encode};

pub use dash_params::LlmqParams;

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
}

/// Blocks below the tip whose active LLMQ set a signing session picks its quorum
/// from, per DIP-0007. Type-independent: it applies to every signing session,
/// ChainLocks among them.
pub const LLMQ_SIGN_HEIGHT_OFFSET: u32 = 8;

/// Blocks below a quorum's own height whose masternode list its members are
/// selected from, per DIP-0024. The lag keeps the selection off a block that is
/// still being mined, which Dash Core needs for evoDB consistency.
pub const QUORUM_MEMBER_LIST_OFFSET: u32 = 8;

/// Runtime override values for `LLMQ_DEVNET`, matching Dash Core's
/// `-llmqdevnetparams=<size>:<threshold>`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct LlmqDevnetParams {
    /// Quorum size (total members).
    pub size: u16,
    /// Signing threshold (also used as min_size and bad_votes_threshold).
    pub threshold: u16,
}

/// Runtime override for `LLMQ_DEVNET` params, matching Dash Core's `-llmqdevnetparams`.
static LLMQ_DEVNET_OVERRIDE: OnceLock<LlmqDevnetParams> = OnceLock::new();

/// Override the `LLMQ_DEVNET` quorum size and threshold (matches Dash Core's
/// `-llmqdevnetparams=<size>:<threshold>`). Idempotent for identical values,
/// returns an error if a conflicting override was already set.
pub fn set_llmq_devnet_params(params: LlmqDevnetParams) -> Result<(), &'static str> {
    match LLMQ_DEVNET_OVERRIDE.get() {
        Some(&existing) if existing == params => Ok(()),
        Some(_) => Err("LLMQ_DEVNET params already set to a different value"),
        None => LLMQ_DEVNET_OVERRIDE
            .set(params)
            .map_err(|_| "LLMQ_DEVNET params already set to a different value"),
    }
}

/// Get the effective `LLMQ_DEVNET` params, applying any runtime override.
pub fn llmq_devnet_params() -> LlmqParams {
    let mut params = LlmqParams::LLMQ_DEVNET;
    if let Some(&LlmqDevnetParams {
        size,
        threshold,
    }) = LLMQ_DEVNET_OVERRIDE.get()
    {
        params.size = size;
        params.min_size = threshold;
        params.threshold = threshold;
        params.dkg_bad_votes_threshold = threshold;
    }
    params
}

/// Runtime override for the LLMQ type used for ChainLocks on devnet,
/// matching Dash Core's `-llmqchainlocks=<quorum name>`.
static DEVNET_CHAIN_LOCKS_OVERRIDE: OnceLock<LLMQType> = OnceLock::new();
/// Runtime override for the LLMQ type used for InstantSend DIP24 on devnet,
/// matching Dash Core's `-llmqinstantsenddip0024=<quorum name>`.
static DEVNET_ISD_OVERRIDE: OnceLock<LLMQType> = OnceLock::new();
/// Runtime override for the LLMQ type used for Platform on devnet,
/// matching Dash Core's `-llmqplatform=<quorum name>`.
static DEVNET_PLATFORM_OVERRIDE: OnceLock<LLMQType> = OnceLock::new();

/// LLMQ types registered on devnet by Dash Core (`chainparams.cpp` `CDevNetParams`
/// `AddLLMQ` calls). Routing overrides accept any of these as a target.
pub(crate) const DEVNET_REGISTERED_LLMQ_TYPES: [LLMQType; 8] = [
    LLMQType::Llmqtype50_60,
    LLMQType::Llmqtype60_75,
    LLMQType::Llmqtype400_60,
    LLMQType::Llmqtype400_85,
    LLMQType::Llmqtype100_67,
    LLMQType::LlmqtypeDevnet,
    LLMQType::LlmqtypeDevnetDIP0024,
    LLMQType::LlmqtypeDevnetPlatform,
];

/// Parse a Dash-Core LLMQ name into an `LLMQType`. Mirrors the name set Dash Core
/// registers on devnet so `-llmqchainlocks` / `-llmqinstantsenddip0024` /
/// `-llmqplatform` accept the same strings as `dashd`.
///
/// `llmq_dev_platform` is accepted as an alias for `llmq_devnet_platform`.
pub fn devnet_llmq_type_from_name(name: &str) -> Result<LLMQType, String> {
    match name {
        "llmq_50_60" => Ok(LLMQType::Llmqtype50_60),
        "llmq_60_75" => Ok(LLMQType::Llmqtype60_75),
        "llmq_400_60" => Ok(LLMQType::Llmqtype400_60),
        "llmq_400_85" => Ok(LLMQType::Llmqtype400_85),
        "llmq_100_67" => Ok(LLMQType::Llmqtype100_67),
        "llmq_devnet" => Ok(LLMQType::LlmqtypeDevnet),
        "llmq_devnet_dip0024" => Ok(LLMQType::LlmqtypeDevnetDIP0024),
        "llmq_devnet_platform" | "llmq_dev_platform" => Ok(LLMQType::LlmqtypeDevnetPlatform),
        _ => Err(format!("Invalid LLMQ type: {}", name)),
    }
}

/// Constraint a devnet routing override must satisfy beyond being a devnet-registered type.
enum RotationConstraint {
    MustNotRotate,
    MustRotate,
    Any,
}

fn set_devnet_routing_override(
    slot: &'static OnceLock<LLMQType>,
    flag_name: &str,
    constraint: RotationConstraint,
    llmq_type: LLMQType,
) -> Result<(), String> {
    if !DEVNET_REGISTERED_LLMQ_TYPES.contains(&llmq_type) {
        return Err(format!("Invalid LLMQ type specified for -{}.", flag_name));
    }
    let rotates = llmq_type.is_rotating_quorum_type();
    match constraint {
        RotationConstraint::MustNotRotate if rotates => {
            return Err(format!("LLMQ type specified for -{} must NOT use rotation", flag_name));
        }
        RotationConstraint::MustRotate if !rotates => {
            return Err(format!("LLMQ type specified for -{} must use rotation", flag_name));
        }
        _ => {}
    }
    match slot.get() {
        Some(&existing) if existing == llmq_type => Ok(()),
        Some(_) => Err(format!("-{} already set to a different value", flag_name)),
        None => slot
            .set(llmq_type)
            .map_err(|_| format!("-{} already set to a different value", flag_name)),
    }
}

/// Override the LLMQ type used for ChainLocks (matches Dash Core's
/// `-llmqchainlocks=<quorum name>`). Type must be devnet-registered and
/// non-rotating, per Dash Core. Idempotent for identical values, errors on
/// conflicting re-set.
pub fn set_devnet_chain_locks_type(llmq_type: LLMQType) -> Result<(), String> {
    set_devnet_routing_override(
        &DEVNET_CHAIN_LOCKS_OVERRIDE,
        "llmqchainlocks",
        RotationConstraint::MustNotRotate,
        llmq_type,
    )
}

/// Override the LLMQ type used for InstantSend DIP24 (matches Dash Core's
/// `-llmqinstantsenddip0024=<quorum name>`). Type must be devnet-registered
/// and rotating, per Dash Core. Idempotent for identical values, errors on
/// conflicting re-set.
pub fn set_devnet_isd_type(llmq_type: LLMQType) -> Result<(), String> {
    set_devnet_routing_override(
        &DEVNET_ISD_OVERRIDE,
        "llmqinstantsenddip0024",
        RotationConstraint::MustRotate,
        llmq_type,
    )
}

/// Override the LLMQ type used for Platform (matches Dash Core's
/// `-llmqplatform=<quorum name>`). Type must be devnet-registered. Dash Core
/// imposes no rotation constraint for Platform. Idempotent for identical
/// values, errors on conflicting re-set.
pub fn set_devnet_platform_type(llmq_type: LLMQType) -> Result<(), String> {
    set_devnet_routing_override(
        &DEVNET_PLATFORM_OVERRIDE,
        "llmqplatform",
        RotationConstraint::Any,
        llmq_type,
    )
}

/// Returns the ChainLocks LLMQ override if one was set via
/// [`set_devnet_chain_locks_type`]. Only meaningful on devnet.
pub fn devnet_chain_locks_type_override() -> Option<LLMQType> {
    DEVNET_CHAIN_LOCKS_OVERRIDE.get().copied()
}

/// Returns the InstantSend DIP24 LLMQ override if one was set via
/// [`set_devnet_isd_type`]. Only meaningful on devnet.
pub fn devnet_isd_type_override() -> Option<LLMQType> {
    DEVNET_ISD_OVERRIDE.get().copied()
}

/// Returns the Platform LLMQ override if one was set via
/// [`set_devnet_platform_type`]. Only meaningful on devnet.
pub fn devnet_platform_type_override() -> Option<LLMQType> {
    DEVNET_PLATFORM_OVERRIDE.get().copied()
}

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
        f.write_str(match self {
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
    pub fn params(&self) -> LlmqParams {
        match self {
            LLMQType::LlmqtypeDevnet | LLMQType::LlmqtypeUnknown => llmq_devnet_params(),
            _ => CoreLlmqType::new(self.index())
                .params()
                .expect("every named LLMQ type but devnet has fixed parameters"),
        }
    }
    pub fn size(&self) -> u32 {
        self.params().size.into()
    }

    pub fn threshold(&self) -> u32 {
        self.params().threshold.into()
    }

    pub fn active_quorum_count(&self) -> u32 {
        self.params().signing_active_quorum_count.into()
    }

    /// Blocks between the starts of two DKG cycles.
    pub fn dkg_interval(&self) -> u32 {
        self.params().dkg_interval.into()
    }

    /// Blocks a quorum stays active for: one DKG interval per active quorum.
    pub fn active_window(&self) -> u32 {
        self.active_quorum_count() * self.dkg_interval()
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

impl From<CoreLlmqType> for LLMQType {
    fn from(llmq_type: CoreLlmqType) -> Self {
        LLMQType::from(llmq_type.to_base())
    }
}

impl From<LLMQType> for u8 {
    fn from(value: LLMQType) -> Self {
        value as u8
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

impl LLMQType {
    pub fn index(&self) -> u8 {
        u8::from(*self)
    }
    pub fn from_u16(index: u16) -> LLMQType {
        LLMQType::from(index as u8)
    }
    pub fn from_u8(index: u8) -> LLMQType {
        LLMQType::from(index)
    }

    pub fn is_rotating_quorum_type(&self) -> bool {
        self.params().use_rotation
    }

    /// Calculate the cycle base height for a given block height
    pub fn get_cycle_base_height(&self, height: u32) -> u32 {
        let interval = self.dkg_interval();
        (height / interval) * interval
    }

    /// Get the DKG window that would contain a commitment mined at the given height
    pub fn get_dkg_window_for_height(&self, height: u32) -> DKGWindow {
        self.dkg_window_at_cycle(self.get_cycle_base_height(height))
    }

    /// The DKG window of the cycle that starts at `cycle_start`.
    pub fn dkg_window_at_cycle(&self, cycle_start: u32) -> DKGWindow {
        let params = self.params();

        // For rotating quorums, the mining window calculation is different
        let mining_start = if self.is_rotating_quorum_type() {
            // For rotating quorums: signingActiveQuorumCount + dkgPhaseBlocks * 5
            cycle_start
                + u32::from(params.signing_active_quorum_count)
                + u32::from(params.dkg_phase_blocks) * 5
        } else {
            // For non-rotating quorums: use the standard mining window start
            cycle_start + u32::from(params.dkg_mining_window_start)
        };

        let mining_end = cycle_start + u32::from(params.dkg_mining_window_end);

        DKGWindow {
            cycle_start,
            mining_start,
            mining_end,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Network;
    use crate::sml::llmq_type::network::NetworkLLMQExt;

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
    }

    // Each devnet `OnceLock` accepts only one value per process; the full contract
    // must be exercised in a single test per lock.

    #[test]
    fn test_llmq_devnet_override_lifecycle() {
        set_llmq_devnet_params(LlmqDevnetParams {
            size: 8,
            threshold: 5,
        })
        .expect("initial override should succeed");

        let params = llmq_devnet_params();
        assert_eq!(params.size, 8);
        assert_eq!(params.min_size, 5);
        assert_eq!(params.threshold, 5);
        assert_eq!(params.dkg_bad_votes_threshold, 5);

        set_llmq_devnet_params(LlmqDevnetParams {
            size: 8,
            threshold: 5,
        })
        .expect("re-setting identical values should be idempotent");
        assert!(
            set_llmq_devnet_params(LlmqDevnetParams {
                size: 12,
                threshold: 6,
            })
            .is_err(),
            "conflicting override must error"
        );

        let params_after = llmq_devnet_params();
        assert_eq!(params_after.size, 8);
        assert_eq!(params_after.threshold, 5);
    }

    #[test]
    fn test_devnet_llmq_type_from_name() {
        assert_eq!(devnet_llmq_type_from_name("llmq_50_60").unwrap(), LLMQType::Llmqtype50_60);
        assert_eq!(devnet_llmq_type_from_name("llmq_60_75").unwrap(), LLMQType::Llmqtype60_75);
        assert_eq!(devnet_llmq_type_from_name("llmq_400_60").unwrap(), LLMQType::Llmqtype400_60);
        assert_eq!(devnet_llmq_type_from_name("llmq_400_85").unwrap(), LLMQType::Llmqtype400_85);
        assert_eq!(devnet_llmq_type_from_name("llmq_100_67").unwrap(), LLMQType::Llmqtype100_67);
        assert_eq!(devnet_llmq_type_from_name("llmq_devnet").unwrap(), LLMQType::LlmqtypeDevnet);
        assert_eq!(
            devnet_llmq_type_from_name("llmq_devnet_dip0024").unwrap(),
            LLMQType::LlmqtypeDevnetDIP0024
        );
        assert_eq!(
            devnet_llmq_type_from_name("llmq_devnet_platform").unwrap(),
            LLMQType::LlmqtypeDevnetPlatform
        );
        assert_eq!(
            devnet_llmq_type_from_name("llmq_dev_platform").unwrap(),
            LLMQType::LlmqtypeDevnetPlatform,
            "shorter alias must resolve to the same type as `llmq_devnet_platform`"
        );

        assert!(devnet_llmq_type_from_name("").is_err());
        assert!(devnet_llmq_type_from_name("llmq_test").is_err());
        assert!(devnet_llmq_type_from_name("not_a_quorum").is_err());
    }

    #[test]
    fn test_devnet_routing_setters_reject_invalid_types() {
        // Regtest-only types are not registered on devnet in Dash Core, so the
        // setters must refuse them before touching any `OnceLock` state.
        for &llmq_type in &[
            LLMQType::LlmqtypeTest,
            LLMQType::LlmqtypeTestDIP0024,
            LLMQType::LlmqtypeTestInstantSend,
            LLMQType::LlmqtypeTestnetPlatform,
        ] {
            assert!(set_devnet_chain_locks_type(llmq_type).is_err());
            assert!(set_devnet_isd_type(llmq_type).is_err());
            assert!(set_devnet_platform_type(llmq_type).is_err());
        }

        // ChainLocks must NOT use a rotating quorum (Dash Core
        // `chainparams.cpp` `UpdateDevnetLLMQChainLocksFromArgs`).
        let err =
            set_devnet_chain_locks_type(LLMQType::LlmqtypeDevnetDIP0024).expect_err("must reject");
        assert!(err.contains("must NOT use rotation"), "got: {}", err);

        // InstantSend DIP24 MUST use a rotating quorum (Dash Core
        // `UpdateDevnetLLMQInstantSendDIP0024FromArgs`).
        let err = set_devnet_isd_type(LLMQType::LlmqtypeDevnet).expect_err("must reject");
        assert!(err.contains("must use rotation"), "got: {}", err);
    }

    #[test]
    fn test_devnet_chain_locks_override_lifecycle() {
        assert!(devnet_chain_locks_type_override().is_none());
        assert_eq!(
            Network::Devnet.chain_locks_type(),
            LLMQType::LlmqtypeDevnet,
            "default ChainLocks routing before override"
        );

        set_devnet_chain_locks_type(LLMQType::Llmqtype50_60)
            .expect("non-rotating registered type should be accepted");

        assert_eq!(devnet_chain_locks_type_override(), Some(LLMQType::Llmqtype50_60));
        assert_eq!(Network::Devnet.chain_locks_type(), LLMQType::Llmqtype50_60);
        assert_eq!(
            Network::Mainnet.chain_locks_type(),
            LLMQType::Llmqtype400_60,
            "other networks must be unaffected"
        );

        set_devnet_chain_locks_type(LLMQType::Llmqtype50_60)
            .expect("idempotent re-set with same value");
        assert!(
            set_devnet_chain_locks_type(LLMQType::Llmqtype400_60).is_err(),
            "conflicting re-set must error"
        );
        assert_eq!(Network::Devnet.chain_locks_type(), LLMQType::Llmqtype50_60);
    }

    #[test]
    fn test_devnet_isd_override_lifecycle() {
        assert!(devnet_isd_type_override().is_none());
        assert_eq!(Network::Devnet.isd_llmq_type(), LLMQType::LlmqtypeDevnetDIP0024);

        set_devnet_isd_type(LLMQType::Llmqtype60_75).expect("rotating registered type accepted");

        assert_eq!(devnet_isd_type_override(), Some(LLMQType::Llmqtype60_75));
        assert_eq!(Network::Devnet.isd_llmq_type(), LLMQType::Llmqtype60_75);
        assert_eq!(
            Network::Mainnet.isd_llmq_type(),
            LLMQType::Llmqtype60_75,
            "mainnet's default for ISD24 is independent of the devnet override"
        );

        set_devnet_isd_type(LLMQType::Llmqtype60_75).expect("idempotent");
        assert!(set_devnet_isd_type(LLMQType::LlmqtypeDevnetDIP0024).is_err());
    }

    #[test]
    fn test_devnet_platform_override_lifecycle() {
        assert!(devnet_platform_type_override().is_none());
        assert_eq!(Network::Devnet.platform_type(), LLMQType::LlmqtypeDevnetPlatform);

        set_devnet_platform_type(LLMQType::Llmqtype100_67)
            .expect("non-rotating registered type accepted (no rotation constraint for Platform)");

        assert_eq!(devnet_platform_type_override(), Some(LLMQType::Llmqtype100_67));
        assert_eq!(Network::Devnet.platform_type(), LLMQType::Llmqtype100_67);
        assert_eq!(
            Network::Regtest.platform_type(),
            LLMQType::LlmqtypeTestnetPlatform,
            "regtest platform routing must be unaffected"
        );

        set_devnet_platform_type(LLMQType::Llmqtype100_67).expect("idempotent");
        assert!(set_devnet_platform_type(LLMQType::LlmqtypeDevnet).is_err());
    }
}
