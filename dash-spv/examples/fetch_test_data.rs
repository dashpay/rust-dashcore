//! Utility to fetch test data from a live Dash node for unit tests.

use dashcore::network::message::NetworkMessage;
use dashcore::network::message_sml::{GetMnListDiff, MnListDiff};
use dashcore::BlockHash;
use dash_spv::{ClientConfig, DashSpvClient, Network};
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    dash_spv::init_logging("info")?;
    
    // Connect to local regtest node
    let config = ClientConfig::new(Network::Regtest)
        .with_peer("127.0.0.1:9999".parse()?)
        .without_filters()
        .without_masternodes();
    
    let mut client = DashSpvClient::new(config).await?;
    client.start().await?;
    
    println!("Connected to Dash node, fetching test data...");
    
    // Create GetMnListDiff request for blocks 1 to 2132092
    let base_block_hash = BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000001")?; // Genesis + 1
    let target_block_hash = get_block_hash_at_height(&mut client, 2132092).await?;
    
    println!("Requesting MnListDiff from {} to {}", base_block_hash, target_block_hash);
    
    // Send GetMnListDiff message
    let get_mn_list_diff = GetMnListDiff {
        base_block_hash,
        block_hash: target_block_hash,
    };
    
    // Access the network manager directly to send the message
    // Note: This is a simplified approach - in a real implementation you'd want proper message handling
    let network_msg = NetworkMessage::GetMnListD(get_mn_list_diff);
    
    // For this example, we'll print the structure we want to request
    // In a full implementation, you'd send this and wait for the response
    println!("GetMnListDiff request structure:");
    println!("  base_block_hash: {}", base_block_hash);
    println!("  block_hash: {}", target_block_hash);
    
    // Also demonstrate quorum info request structure
    println!("\nQuorum info would be requested via:");
    println!("  For block height: 2132092");
    println!("  Target block hash: {}", target_block_hash);
    
    client.stop().await?;
    
    Ok(())
}

async fn get_block_hash_at_height(
    _client: &mut DashSpvClient, 
    height: u32
) -> Result<BlockHash, Box<dyn std::error::Error>> {
    // For this example, we'll use a placeholder block hash
    // In a real implementation, you'd sync to get the actual block hash at height
    println!("Would fetch block hash at height {}", height);
    
    // Return a placeholder hash for now
    Ok(BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000000")?)
}