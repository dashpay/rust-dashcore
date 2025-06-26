use dashcore::Network;
use dash_spv::network::{MultiPeerNetworkManager, NetworkManager};
use dash_spv::client::ClientConfig;
use std::time::Duration;
use tokio;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .init();

    println!("🚀 Testing headers2 implementation directly...");

    // Configure network
    let mut config = ClientConfig::new(Network::Dash);
    config.peers = vec!["seed.dash.org:9999".parse()?];
    config.max_peers = 1;

    // Create network manager
    let mut network = MultiPeerNetworkManager::new(&config).await?;
    
    println!("📡 Connecting to peer...");
    network.connect().await?;
    
    // Wait a moment for connection
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    println!("🔍 Checking peer count...");
    let peer_count = network.peer_count();
    println!("Connected peers: {}", peer_count);
    
    if peer_count == 0 {
        println!("❌ No peers connected!");
        return Ok(());
    }
    
    // Check for headers2 support
    println!("🔍 Checking headers2 support...");
    let has_headers2 = network.has_headers2_peer().await;
    println!("Has headers2 peer: {}", has_headers2);
    
    // Monitor for a bit
    println!("⏳ Monitoring connection for 20 seconds...");
    for i in 0..20 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let peers = network.peer_count();
        println!("[{}s] Peers: {}", i + 1, peers);
        
        if peers == 0 && i > 5 {
            println!("❌ Connection dropped!");
            break;
        }
    }
    
    println!("🏁 Test complete");
    network.shutdown().await;
    
    Ok(())
}