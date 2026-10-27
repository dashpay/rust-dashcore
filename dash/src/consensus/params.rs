// Rust Dash Library
// Originally written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//     For Bitcoin
// Updated for Dash in 2022 by
//     The Dash Core Developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Dash consensus parameters.
//!
//! This module provides a predefined set of parameters for different Dash
//! chains (such as mainnet, testnet), as Dash Core's `chainparams.cpp` sets them.
//!

use crate::{Target, network::constants::Network};

/// Parameters that influence chain consensus.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Params {
    /// Network for which parameters are valid.
    pub network: Network,
    /// Time when BIP16 becomes active.
    pub bip16_time: u32,
    /// Block height at which BIP34 becomes active.
    pub bip34_height: u32,
    /// Block height at which BIP65 becomes active.
    pub bip65_height: u32,
    /// Block height at which BIP66 becomes active.
    pub bip66_height: u32,
    /// Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
    /// (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
    /// Examples: 1916 for 95%, 1512 for testchains.
    pub rule_change_activation_threshold: u32,
    /// Number of blocks with the same set of rules.
    pub miner_confirmation_window: u32,
    /// The highest target, i.e. the lowest difficulty, as Dash Core's `powLimit`.
    pub pow_limit: Target,
    /// Expected amount of time to mine one block.
    pub pow_target_spacing: u64,
    /// Difficulty recalculation interval.
    pub pow_target_timespan: u64,
    /// Determines whether minimal difficulty may be used for blocks or not.
    pub allow_min_difficulty_blocks: bool,
    /// Determines whether retargeting is disabled for this network or not.
    pub no_pow_retargeting: bool,
    /// Block height from which the difficulty follows Dark Gravity Wave.
    pub pow_dgw_height: u32,
    /// Last block height whose bits only have to be within 50% of Dark Gravity Wave's, as early
    /// mainnet ran its first versions.
    pub pow_dgw_tolerant_height: Option<u32>,
}

impl Params {
    /// Mainnet parameters.
    pub const MAINNET: Params = Params {
        network: Network::Mainnet,
        bip16_time: 1333238400, // Apr 1 2012
        bip34_height: 951,
        bip65_height: 619382, // 00000000000076d8fcea02ec0963de4abfd01e771fec0863f960c2c64fe6f357
        bip66_height: 245817, // 00000000000b1fa2dfa312863570e13fae9ca7b5566cb27e55422620b469aefa
        rule_change_activation_threshold: 1815, // 90%
        miner_confirmation_window: 2016,
        pow_limit: Target::max_shr(20),
        pow_target_spacing: 150,           // 2.5 minutes.
        pow_target_timespan: 24 * 60 * 60, // 1 day.
        allow_min_difficulty_blocks: false,
        no_pow_retargeting: false,
        pow_dgw_height: 34140,
        pow_dgw_tolerant_height: Some(68589),
    };

    /// Testnet parameters.
    pub const TESTNET: Params = Params {
        network: Network::Testnet,
        bip16_time: 1333238400, // Apr 1 2012
        bip34_height: 76,
        bip65_height: 2431, // 0000039cf01242c7f921dcb4806a5994bc003b48c1973ae0c89b67809c2bb2ab
        bip66_height: 2075, // 0000002acdd29a14583540cb72e1c5cc83783560e38fa7081495d474fe1671f7
        rule_change_activation_threshold: 1512, // 75%
        miner_confirmation_window: 2016,
        pow_limit: Target::max_shr(20),
        pow_target_spacing: 150,           // 2.5 minutes.
        pow_target_timespan: 24 * 60 * 60, // 1 day.
        allow_min_difficulty_blocks: true,
        no_pow_retargeting: false,
        pow_dgw_height: 4002,
        pow_dgw_tolerant_height: None,
    };

    /// Devnet parameters, with Dash Core's defaults: each devnet can override its difficulty rules.
    pub const DEVNET: Params = Params {
        network: Network::Devnet,
        bip16_time: 1333238400, // Apr 1 2012
        bip34_height: 1,
        bip65_height: 1,
        bip66_height: 1,
        rule_change_activation_threshold: 1512, // 75%
        miner_confirmation_window: 2016,
        pow_limit: Target::max_shr(1),
        pow_target_spacing: 150,           // 2.5 minutes.
        pow_target_timespan: 24 * 60 * 60, // 1 day.
        allow_min_difficulty_blocks: true,
        no_pow_retargeting: false,
        pow_dgw_height: 4001,
        pow_dgw_tolerant_height: None,
    };

    /// Regtest parameters.
    pub const REGTEST: Params = Params {
        network: Network::Regtest,
        bip16_time: 1333238400, // Apr 1 2012
        bip34_height: 1,
        bip65_height: 1,
        bip66_height: 1,
        rule_change_activation_threshold: 108, // 75%
        miner_confirmation_window: 144,
        pow_limit: Target::max_shr(1),
        pow_target_spacing: 150,           // 2.5 minutes.
        pow_target_timespan: 24 * 60 * 60, // 1 day.
        allow_min_difficulty_blocks: true,
        no_pow_retargeting: true,
        pow_dgw_height: 34140,
        pow_dgw_tolerant_height: None,
    };

    /// The parameters of `network`.
    pub const fn new(network: Network) -> &'static Params {
        match network {
            Network::Mainnet => &Params::MAINNET,
            Network::Testnet => &Params::TESTNET,
            Network::Devnet => &Params::DEVNET,
            Network::Regtest => &Params::REGTEST,
        }
    }

    /// Calculates the number of blocks between difficulty adjustments.
    pub fn difficulty_adjustment_interval(&self) -> u64 {
        self.pow_target_timespan / self.pow_target_spacing
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    // Dash Core's `powLimit` in compact form, as `GetNextWorkRequired` returns it.
    #[test_case(Network::Mainnet, 0x1e0fffff)]
    #[test_case(Network::Testnet, 0x1e0fffff)]
    #[test_case(Network::Devnet, 0x207fffff)]
    #[test_case(Network::Regtest, 0x207fffff)]
    fn pow_limit_matches_core(network: Network, compact: u32) {
        assert_eq!(Params::new(network).pow_limit.to_compact_lossy().to_consensus(), compact);
    }
}
