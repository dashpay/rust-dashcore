//! Pre-calculated mainnet terminal block data.
//!
//! This file includes the generated terminal block data for mainnet.

use super::*;

/// Load pre-calculated mainnet terminal block data.
pub fn load_mainnet_terminal_blocks(manager: &mut TerminalBlockDataManager) {
    // Terminal block 1950000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1950000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 2000000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_2000000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }
}