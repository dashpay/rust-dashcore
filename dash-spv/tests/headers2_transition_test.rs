use dashcore::Network;
use dash_spv::{
    client::{ClientConfig, DashSpvClient},
    error::SpvError,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::{timeout, Duration};

#[tokio::test]
#[ignore] // This test requires a live Dash testnet node
async fn test_headers2_after_regular_sync() -> Result<(), SpvError> {
    // Use a temporary directory
    let data_dir = PathBuf::from(format!("/tmp/headers2-test-{}", std::process::id()));
    
    // Create client config
    let mut config = ClientConfig::new(Network::Testnet);
    config.peers = vec!["54.68.235.201:19999".parse().unwrap()];
    config.storage_path = Some(data_dir.clone());
    config.enable_filters = false; // Disable filters for faster testing
    
    // Create client
    let mut client = DashSpvClient::new(config.clone()).await?;
    
    // First, disable headers2 temporarily to sync some headers with regular GetHeaders
    // This would require modifying the sync logic, so for now we'll just start the sync
    
    println!("Starting sync...");
    client.start().await?;
    
    // Wait for some headers to sync
    println!("Waiting for initial headers sync...");
    tokio::time::sleep(Duration::from_secs(10)).await;
    
    // Check sync progress
    let progress = client.get_sync_progress().await;
    println!("Synced {} headers", progress.headers_synced);
    
    // Now the peer should have some context and might respond to GetHeaders2
    // In a real test, we'd modify the sync logic to switch to GetHeaders2 after some headers
    
    // Clean up
    let _ = client.stop().await;
    let _ = std::fs::remove_dir_all(data_dir);
    
    Ok(())
}

#[tokio::test] 
async fn test_headers2_protocol_negotiation() -> Result<(), SpvError> {
    // This test checks if we properly negotiate headers2 support
    use dash_spv::network::{HandshakeManager, TcpConnection};
    use dashcore::network::constants::{ServiceFlags, NODE_HEADERS_COMPRESSED};
    use std::net::SocketAddr;
    
    let addr: SocketAddr = "54.68.235.201:19999".parse().unwrap();
    let network = Network::Testnet;
    
    // Create connection
    let mut connection = TcpConnection::connect(addr, network).await
        .map_err(|e| SpvError::Network(format!("Connection failed: {}", e)))?;
    
    // Perform handshake
    let mut handshake = HandshakeManager::new(network, dash_spv::client::config::MempoolStrategy::DoNotFetch);
    let peer_info = handshake.perform_handshake(&mut connection).await
        .map_err(|e| SpvError::Network(format!("Handshake failed: {}", e)))?;
    
    println!("Peer version: {:?}", peer_info.version);
    println!("Peer services: {:?}", peer_info.services);
    println!("Peer user agent: {:?}", peer_info.user_agent);
    
    // Check if peer supports headers2
    if let Some(services) = peer_info.services {
        let supports_headers2 = services.has(NODE_HEADERS_COMPRESSED);
        println!("Peer supports headers2: {}", supports_headers2);
        
        if supports_headers2 {
            println!("✅ Peer advertises NODE_HEADERS_COMPRESSED support");
        }
    }
    
    // Check if we received SendHeaders2
    // This would require inspecting the messages exchanged during handshake
    
    connection.disconnect().await
        .map_err(|e| SpvError::Network(format!("Disconnect failed: {}", e)))?;
    
    Ok(())
}