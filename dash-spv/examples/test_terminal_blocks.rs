//! Test terminal blocks with pre-calculated masternode data

use dash_spv::sync::terminal_blocks::TerminalBlockManager;
use dashcore::Network;

fn main() {
    // Create terminal block manager for testnet
    let manager = TerminalBlockManager::new(Network::Testnet);

    println!("Testing terminal block manager with pre-calculated data...\n");

    // Check if we have pre-calculated data for terminal blocks
    let test_heights = vec![
        387480, 400000, 450000, 500000, 550000, 600000, 650000, 700000, 750000, 760000, 800000,
        850000, 900000,
    ];

    for height in test_heights {
        if manager.has_masternode_data(height) {
            if let Some(data) = manager.get_masternode_data(height) {
                println!("✓ Terminal block {} has pre-calculated data:", height);
                println!("  - Block hash: {}", data.block_hash);
                println!("  - Masternode count: {}", data.masternode_count);
                println!("  - Merkle root: {}", data.merkle_root_mn_list);
                println!("");
            }
        } else {
            println!("✗ Terminal block {} - no pre-calculated data", height);
        }
    }

    // Test finding best terminal block with data
    let test_target_heights = vec![500000, 750000, 900000, 1000000];
    println!("\nTesting best terminal block lookup:");

    for target in test_target_heights {
        if let Some(best) = manager.find_best_terminal_block_with_data(target) {
            println!(
                "For target height {}: best terminal block is {} with {} masternodes",
                target, best.height, best.masternode_count
            );
        } else {
            println!("For target height {}: no terminal block with data found", target);
        }
    }
}
