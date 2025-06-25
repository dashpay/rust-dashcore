//! Pre-calculated mainnet terminal block data.
//!
//! This file includes the generated terminal block data for mainnet.

use super::*;

/// Load pre-calculated mainnet terminal block data.
pub fn load_mainnet_terminal_blocks(manager: &mut TerminalBlockDataManager) {
    // Terminal block 1088640 (DIP3 activation)
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1088640.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1100000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1100000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1150000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1150000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1200000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1200000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1250000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1250000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1300000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1300000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1350000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1350000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1400000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1400000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1450000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1450000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1500000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1500000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1550000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1550000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1600000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1600000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1650000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1650000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1700000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1700000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1720000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1720000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1750000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1750000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1800000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1800000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1850000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1850000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

    // Terminal block 1900000
    {
        let data = include_str!("../../../data/mainnet/terminal_block_1900000.json");
        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {
            manager.add_state(state);
        }
    }

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