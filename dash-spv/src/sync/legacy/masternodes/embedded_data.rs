//! Embedded masternode list diffs for faster initial sync.
//!
//! This module contains pre-computed MNListDiff data embedded at compile time
//! to speed up initial synchronization by starting from a known good state.

use dashcore::{consensus::deserialize, network::message_sml::MnListDiff, Network};

// Embed the mainnet MNListDiff from height 0 to 2227096
const MAINNET_MNLIST_DIFF_0_2227096: &[u8] =
    include_bytes!("../../../../../dash/artifacts/mn_list_diff_0_2227096.bin");

// Embed the testnet MNListDiff from height 0 to 1296600
const TESTNET_MNLIST_DIFF_0_1296600: &[u8] =
    include_bytes!("../../../../../dash/artifacts/mn_list_diff_testnet_0_1296600.bin");

/// Information about an embedded MNListDiff
pub struct EmbeddedDiff {
    pub diff: MnListDiff,
    pub base_height: u32,
    pub target_height: u32,
}

/// Get the embedded MNListDiff for a specific network, if available.
pub fn get_embedded_diff(network: Network) -> Option<EmbeddedDiff> {
    match network {
        Network::Dash => {
            let bytes = MAINNET_MNLIST_DIFF_0_2227096;
            match deserialize::<MnListDiff>(bytes) {
                Ok(diff) => Some(EmbeddedDiff {
                    diff,
                    base_height: 0,
                    target_height: 2227096,
                }),
                Err(e) => {
                    tracing::warn!("Failed to deserialize embedded mainnet MNListDiff: {}", e);
                    None
                }
            }
        }
        Network::Testnet => {
            let bytes = TESTNET_MNLIST_DIFF_0_1296600;
            match deserialize::<MnListDiff>(bytes) {
                Ok(diff) => Some(EmbeddedDiff {
                    diff,
                    base_height: 0,
                    target_height: 1296600,
                }),
                Err(e) => {
                    tracing::warn!("Failed to deserialize embedded testnet MNListDiff: {}", e);
                    None
                }
            }
        }
        _ => {
            // No embedded data for other networks (regtest, devnet, etc.)
            None
        }
    }
}
