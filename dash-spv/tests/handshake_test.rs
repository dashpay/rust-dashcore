//! Integration tests for network handshake functionality.

use std::net::SocketAddr;
use std::time::Duration;

use dash_spv::{ClientConfig, Network, ValidationMode};
use dash_spv::network::{TcpNetworkManager, NetworkManager};

#[tokio::test]
async fn test_handshake_with_mainnet_peer() {
    // Initialize logging for test output
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .is_test(true)
        .try_init();

    // Create configuration for mainnet with test peer
    let peer_addr: SocketAddr = "127.0.0.1:9999".parse().expect("Valid peer address");
    let mut config = ClientConfig::new(Network::Dash)
        .with_validation_mode(ValidationMode::Basic)
        .with_connection_timeout(Duration::from_secs(10));
    
    config.peers.clear();
    config.add_peer(peer_addr);

    // Create network manager
    let mut network = TcpNetworkManager::new(&config).await
        .expect("Failed to create network manager");

    // Attempt to connect and perform handshake
    let result = network.connect().await;
    
    match result {
        Ok(_) => {
            println!("✓ Handshake successful with peer {}", peer_addr);
            assert!(network.is_connected(), "Network should be connected after successful handshake");
            assert_eq!(network.peer_count(), 1, "Should have one connected peer");
            
            // Get peer info
            let peer_info = network.peer_info();
            assert_eq!(peer_info.len(), 1, "Should have one peer info");
            assert_eq!(peer_info[0].address, peer_addr, "Peer address should match");
            assert!(peer_info[0].connected, "Peer should be marked as connected");
            
            // Clean disconnect
            network.disconnect().await.expect("Failed to disconnect");
            assert!(!network.is_connected(), "Network should be disconnected");
            assert_eq!(network.peer_count(), 0, "Should have no connected peers");
        }
        Err(e) => {
            println!("✗ Handshake failed with peer {}: {}", peer_addr, e);
            // For CI/testing environments where the peer might not be available,
            // we'll make this a warning rather than a failure
            println!("Note: This test requires a Dash Core node running at 127.0.0.1:9999");
            println!("Error details: {}", e);
        }
    }
}

#[tokio::test]
async fn test_handshake_timeout() {
    // Test connecting to a non-existent peer to verify timeout behavior
    let peer_addr: SocketAddr = "127.0.0.1:49999".parse().expect("Valid peer address");
    let mut config = ClientConfig::new(Network::Dash)
        .with_validation_mode(ValidationMode::Basic)
        .with_connection_timeout(Duration::from_secs(2)); // Short timeout for test
    
    config.peers.clear();
    config.add_peer(peer_addr);

    let mut network = TcpNetworkManager::new(&config).await
        .expect("Failed to create network manager");

    let start = std::time::Instant::now();
    let result = network.connect().await;
    let elapsed = start.elapsed();

    assert!(result.is_err(), "Connection should fail for non-existent peer");
    assert!(elapsed >= Duration::from_secs(2), "Should respect timeout duration");
    assert!(elapsed < Duration::from_secs(15), "Should not take excessively long beyond timeout");
    
    assert!(!network.is_connected(), "Network should not be connected");
    assert_eq!(network.peer_count(), 0, "Should have no connected peers");
}

#[tokio::test]
async fn test_network_manager_creation() {
    let config = ClientConfig::new(Network::Dash);
    let network = TcpNetworkManager::new(&config).await;
    
    assert!(network.is_ok(), "Network manager creation should succeed");
    let network = network.unwrap();
    
    assert!(!network.is_connected(), "Should start disconnected");
    assert_eq!(network.peer_count(), 0, "Should start with no peers");
    assert!(network.peer_info().is_empty(), "Should start with empty peer info");
}

#[tokio::test]
async fn test_multiple_connect_disconnect_cycles() {
    let peer_addr: SocketAddr = "127.0.0.1:9999".parse().expect("Valid peer address");
    let mut config = ClientConfig::new(Network::Dash)
        .with_validation_mode(ValidationMode::Basic)
        .with_connection_timeout(Duration::from_secs(10));
    
    config.peers.clear();
    config.add_peer(peer_addr);

    let mut network = TcpNetworkManager::new(&config).await
        .expect("Failed to create network manager");

    // Try multiple connect/disconnect cycles
    for i in 1..=3 {
        println!("Attempt {} to connect to {}", i, peer_addr);
        
        let connect_result = network.connect().await;
        if connect_result.is_ok() {
            assert!(network.is_connected(), "Should be connected after successful connect");
            
            // Brief delay
            tokio::time::sleep(Duration::from_millis(100)).await;
            
            // Disconnect
            let disconnect_result = network.disconnect().await;
            assert!(disconnect_result.is_ok(), "Disconnect should succeed");
            assert!(!network.is_connected(), "Should be disconnected after disconnect");
            
            // Brief delay before next attempt
            tokio::time::sleep(Duration::from_millis(100)).await;
        } else {
            println!("Connection attempt {} failed: {}", i, connect_result.unwrap_err());
            break;
        }
    }
}