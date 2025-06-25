use dashcore::{blockdata::constants::genesis_block, Network};

fn main() {
    println!("Testing genesis block generation...\n");
    
    // Test mainnet genesis
    println!("=== Mainnet Genesis ===");
    let mainnet_genesis = genesis_block(Network::Dash);
    println!("Hash: {}", mainnet_genesis.block_hash());
    println!("Time: {}", mainnet_genesis.header.time);
    println!("Nonce: {}", mainnet_genesis.header.nonce);
    println!("Bits: {:x}", mainnet_genesis.header.bits.to_consensus());
    println!("Merkle root: {}", mainnet_genesis.header.merkle_root);
    println!();
    
    // Test testnet genesis
    println!("=== Testnet Genesis ===");
    let testnet_genesis = genesis_block(Network::Testnet);
    println!("Hash: {}", testnet_genesis.block_hash());
    println!("Time: {}", testnet_genesis.header.time);
    println!("Nonce: {}", testnet_genesis.header.nonce);
    println!("Bits: {:x}", testnet_genesis.header.bits.to_consensus());
    println!("Merkle root: {}", testnet_genesis.header.merkle_root);
    println!();
    
    // Expected values
    println!("=== Expected Testnet Values ===");
    println!("Hash: 00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c");
    println!("Time: 1390666206");
    println!("Nonce: 3861367235");
    println!("Bits: 1e0ffff0");
    println!("Merkle root: e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7");
}