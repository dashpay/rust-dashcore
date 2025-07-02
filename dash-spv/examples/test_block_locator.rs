//! Test the block locator generation

use dash_spv::chain::block_locator::build_block_locator;
use dash_spv::storage::{MemoryStorageManager, StorageManager};
use dashcore::{block::Header as BlockHeader, block::Version, CompactTarget, BlockHash, Network};
use dashcore::network::constants::NetworkExt;
use dashcore_hashes::Hash;

fn create_test_header(height: u32, prev_hash: BlockHash) -> BlockHeader {
    BlockHeader {
        version: Version::from_consensus(1),
        prev_blockhash: prev_hash,
        merkle_root: dashcore::TxMerkleNode::from_byte_array([height as u8; 32]),
        time: 1234567890 + height,
        bits: CompactTarget::from_consensus(0x1d00ffff),
        nonce: height,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a test storage with 2000 headers
    let mut storage = MemoryStorageManager::new().await?;
    let genesis_hash = Network::Dash.known_genesis_block_hash().unwrap();
    
    println!("Building test chain with 2000 headers...");
    
    // Build a chain
    let mut headers = vec![];
    let mut prev_hash = genesis_hash;
    
    for i in 0..2000 {
        let header = create_test_header(i, prev_hash);
        prev_hash = header.block_hash();
        headers.push(header);
    }
    
    // Store headers
    storage.store_headers(&headers).await?;
    
    println!("Chain built. Tip height: 1999");
    
    // Build block locator
    let locator = build_block_locator(&storage, genesis_hash).await?;
    
    println!("\nBlock locator generated with {} hashes:", locator.len());
    println!("First 10 locator entries:");
    
    // Print the first 10 entries with their heights
    for (i, hash) in locator.iter().take(10).enumerate() {
        // Find the height of this hash
        let height = headers.iter().position(|h| h.block_hash() == *hash);
        match height {
            Some(h) => println!("  [{}] Height {} - {}", i, h, hash),
            None => println!("  [{}] Genesis - {}", i, hash),
        }
    }
    
    println!("\nRemaining locator entries (showing intervals):");
    
    // Show the intervals for the rest
    let mut last_height = 1999;
    for (i, hash) in locator.iter().skip(10).enumerate() {
        // Find the height of this hash
        if let Some(height) = headers.iter().position(|h| h.block_hash() == *hash) {
            let interval = last_height - height;
            println!("  [{}] Height {} (interval: {})", i + 10, height, interval);
            last_height = height;
        }
    }
    
    // Verify the locator properties
    println!("\nLocator properties:");
    println!("- Total hashes: {}", locator.len());
    println!("- Includes tip: {}", locator.first() == Some(&headers[1999].block_hash()));
    println!("- Includes genesis: {}", locator.last() == Some(&headers[0].block_hash()));
    
    // Test with empty chain
    println!("\nTesting with empty chain...");
    let empty_storage = MemoryStorageManager::new().await?;
    let empty_locator = build_block_locator(&empty_storage, genesis_hash).await?;
    println!("Empty chain locator: {} hashes", empty_locator.len());
    println!("Contains genesis: {}", empty_locator.first() == Some(&genesis_hash));
    
    Ok(())
}