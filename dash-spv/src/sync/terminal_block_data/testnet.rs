//! Pre-calculated testnet terminal block data.
//!
//! This file includes the generated terminal block data for testnet.

use super::*;

/// Load pre-calculated testnet terminal block data.
pub fn load_testnet_terminal_blocks(manager: &mut TerminalBlockDataManager) {
    // Terminal block 900000 (latest)
    {
        let data = include_str!("../../../data/testnet/terminal_block_900000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }
}