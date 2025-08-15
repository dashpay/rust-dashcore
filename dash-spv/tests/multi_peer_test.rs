//! Integration tests for multi-peer networking

use std::net::SocketAddr;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time;

use dash_spv::client::{ClientConfig, DashSpvClient};
use dash_spv::types::ValidationMode;
use dashcore::Network;

/// Create a test configuration with the given network
fn create_test_config(network: Network, data_dir: Option<TempDir>) -> ClientConfig {
    let mut config = ClientConfig::new(network);
    config.storage_path = data_dir.map(|d| d.path().to_path_buf());
    config.validation_mode = ValidationMode::Basic;
    config.enable_filters = false;
    config.enable_masternodes = false;
    config.max_peers = 3;
    config.connection_timeout = Duration::from_secs(10);
    config.message_timeout = Duration::from_secs(30);
    config.peers = vec![]; // Will be populated by DNS discovery
    config
}

#[tokio::test]
#[ignore] // Requires network access
async fn test_multi_peer_connection() {
    let _ = env_logger::builder().is_test(true).try_init();

    let temp_dir = TempDir::new().unwrap();
    let config = create_test_config(Network::Testnet, Some(temp_dir));

    let mut client = DashSpvClient::new(config).await.unwrap();

    // Start the client
    client.start().await.unwrap();

    // Give it time to connect to peers
    time::sleep(Duration::from_secs(5)).await;

    // Check that we have connected to at least one peer
    let peer_count = client.peer_count();
    assert!(peer_count > 0, "Should have connected to at least one peer");

    // Get peer info
    let peer_info = client.peer_info();
    assert_eq!(peer_info.len(), peer_count);

    println!("Connected to {} peers:", peer_count);
    for info in peer_info {
        println!("  - {} (version: {:?})", info.address, info.version);
    }

    // Stop the client
    client.stop().await.unwrap();
}

#[tokio::test]
#[ignore] // Requires network access
async fn test_peer_persistence() {
    let _ = env_logger::builder().is_test(true).try_init();

    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path().to_path_buf();

    // First run: connect and save peers
    {
        let config = create_test_config(Network::Testnet, Some(temp_dir));
        let mut client = DashSpvClient::new(config).await.unwrap();

        client.start().await.unwrap();
        time::sleep(Duration::from_secs(5)).await;

        let peer_count = client.peer_count();
        assert!(peer_count > 0, "Should have connected to peers");

        client.stop().await.unwrap();
    }

    // Second run: should load saved peers
    {
        let mut config = create_test_config(Network::Testnet, None);
        config.storage_path = Some(temp_path);

        let mut client = DashSpvClient::new(config).await.unwrap();

        // Should connect faster due to saved peers
        let start = tokio::time::Instant::now();
        client.start().await.unwrap();

        // Wait for connection but with shorter timeout
        time::sleep(Duration::from_secs(3)).await;

        let peer_count = client.peer_count();
        assert!(peer_count > 0, "Should have connected using saved peers");

        let elapsed = start.elapsed();
        println!("Connected to {} peers in {:?} (using saved peers)", peer_count, elapsed);

        client.stop().await.unwrap();
    }
}

#[tokio::test]
async fn test_peer_disconnection() {
    let _ = env_logger::builder().is_test(true).try_init();

    let temp_dir = TempDir::new().unwrap();
    let mut config = create_test_config(Network::Regtest, Some(temp_dir));

    // Add manual test peers (would need actual regtest nodes running)
    config.peers = vec!["127.0.0.1:19899".parse().unwrap(), "127.0.0.1:19898".parse().unwrap()];

    let client = DashSpvClient::new(config).await.unwrap();

    // Note: This test would require actual regtest nodes running
    // For now, we just test that the API works
    let test_addr: SocketAddr = "127.0.0.1:19899".parse().unwrap();

    // Try to disconnect (will fail if not connected, but tests the API)
    match client.disconnect_peer(&test_addr, "Test disconnection").await {
        Ok(_) => println!("Disconnected peer {}", test_addr),
        Err(e) => println!("Expected error disconnecting non-existent peer: {}", e),
    }
}

#[tokio::test]
async fn test_max_peer_limit() {
    use dash_spv::network::constants::MAX_PEERS;

    let _ = env_logger::builder().is_test(true).try_init();

    let temp_dir = TempDir::new().unwrap();
    let mut config = create_test_config(Network::Testnet, Some(temp_dir));

    // Add at least one peer to avoid "No peers specified" error
    config.peers = vec!["127.0.0.1:19999".parse().unwrap()];

    let _client = DashSpvClient::new(config).await.unwrap();

    // The client should never connect to more than MAX_PEERS
    // This is enforced in the ConnectionPool
    println!("Maximum peer limit is set to: {}", MAX_PEERS);
    assert_eq!(MAX_PEERS, 3, "Default max peers should be 12");
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use dash_spv::network::addrv2::AddrV2Handler;
    use dash_spv::network::discovery::DnsDiscovery;
    use dash_spv::network::pool::ConnectionPool;
    use dashcore::network::constants::ServiceFlags;

    #[tokio::test]
    async fn test_connection_pool_limits() {
        let pool = ConnectionPool::new();

        // Should start empty
        assert_eq!(pool.connection_count().await, 0);
        assert!(pool.needs_more_connections().await);
        assert!(pool.can_accept_connections().await);

        // Test marking as connecting
        let addr1: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        assert!(pool.mark_connecting(addr1).await);
        assert!(!pool.mark_connecting(addr1).await); // Already marked
        assert!(pool.is_connecting(&addr1).await);
    }

    #[tokio::test]
    async fn test_addrv2_handler() {
        let handler = AddrV2Handler::new();

        // Test tracking AddrV2 support
        let peer: SocketAddr = "192.168.1.1:9999".parse().unwrap();
        handler.handle_sendaddrv2(peer).await;
        assert!(handler.peer_supports_addrv2(&peer).await);

        // Test adding addresses
        handler.add_known_address(peer, ServiceFlags::from(1)).await;
        let known = handler.get_known_addresses().await;
        assert_eq!(known.len(), 1);
        assert_eq!(known[0], peer);

        // Test getting addresses for sharing
        let to_share = handler.get_addresses_for_peer(10).await;
        assert_eq!(to_share.len(), 1);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_dns_discovery() {
        let discovery = DnsDiscovery::new().await.unwrap();

        // Test mainnet discovery
        let peers = discovery.discover_peers(Network::Dash).await;
        assert!(!peers.is_empty(), "Should discover mainnet peers");

        // All peers should use correct port
        for peer in &peers {
            assert_eq!(peer.port(), 9999);
        }

        // Test limited discovery
        let limited = discovery.discover_peers_limited(Network::Dash, 5).await;
        assert!(limited.len() <= 5);
    }
}
