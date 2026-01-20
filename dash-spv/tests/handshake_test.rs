//! Integration tests for network handshake functionality.

use std::net::SocketAddr;
use std::time::Duration;

use dash_spv::network::{HandshakeManager, NetworkManager, Peer, PeerNetworkManager};
use dash_spv::Network;
use dash_spv::{ClientConfigBuilder, MempoolStrategy};

#[tokio::test]
async fn test_handshake_with_mainnet_peer() {
    // Initialize logging for test output
    let _ = env_logger::builder().filter_level(log::LevelFilter::Debug).is_test(true).try_init();

    let peer_addr: SocketAddr = "127.0.0.1:9999".parse().expect("Valid peer address");
    let result = Peer::connect(peer_addr, 10, Network::Dash).await;

    match result {
        Ok(mut connection) => {
            let mut handshake_manager = HandshakeManager::new(
                Network::Dash,
                MempoolStrategy::BloomFilter,
                Some("handshake_test".parse().unwrap()),
            );
            handshake_manager.perform_handshake(&mut connection).await.expect("Handshake failed");
            println!("✓ Handshake successful with peer {}", peer_addr);
            assert!(
                connection.is_connected(),
                "Peer should be connected after successful handshake"
            );

            // Get peer info
            let peer_info = connection.peer_info();
            assert_eq!(peer_info.address, peer_addr, "Peer address should match");
            assert!(peer_info.connected, "Peer should be marked as connected");

            // Clean disconnect
            connection.disconnect().await.expect("Failed to disconnect");
            assert!(!connection.is_connected(), "Network should be disconnected");
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
    // Test connection timeout behavior using TEST-NET-1 from RFC 5737.
    // https://datatracker.ietf.org/doc/html/rfc5737
    // This IP range is reserved for documentation and will never respond.
    let peer_addr: SocketAddr = "192.0.2.1:9999".parse().expect("Valid peer address");
    let start = std::time::Instant::now();
    let result = Peer::connect(peer_addr, 2, Network::Dash).await;
    let elapsed = start.elapsed();

    assert!(result.is_err(), "Connection should fail for unreachable peer");
    assert!(
        elapsed >= Duration::from_secs(1),
        "Should respect timeout duration (elapsed: {:?})",
        elapsed
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "Should not take excessively long beyond timeout (elapsed: {:?})",
        elapsed
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_network_manager_creation() {
    let config = ClientConfigBuilder::mainnet().build().expect("Valid config");
    let network = PeerNetworkManager::new(&config).await;

    assert!(network.is_ok(), "Network manager creation should succeed");
    let network = network.unwrap();

    assert!(!network.is_connected(), "Should start disconnected");
    assert_eq!(network.peer_count(), 0, "Should start with no peers");
    assert!(network.peer_info().is_empty(), "Should start with empty peer info");
}

#[tokio::test]
async fn test_multiple_connect_disconnect_cycles() {
    let peer_addr: SocketAddr = "127.0.0.1:9999".parse().expect("Valid peer address");
    let mut connection = Peer::new(peer_addr, Duration::from_secs(10), Network::Dash);

    // Try multiple connect/disconnect cycles
    for i in 1..=3 {
        println!("Attempt {} to connect to {}", i, peer_addr);

        match connection.connect_instance().await {
            Ok(_) => {
                assert!(connection.is_connected(), "Should be connected after successful connect");

                // Brief delay
                tokio::time::sleep(Duration::from_millis(100)).await;

                // Disconnect
                let disconnect_result = connection.disconnect().await;
                assert!(disconnect_result.is_ok(), "Disconnect should succeed");
                assert!(!connection.is_connected(), "Should be disconnected after disconnect");

                // Brief delay before next attempt
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => {
                println!("Connection attempt {} failed: {}", i, e);
                break;
            }
        }
    }
}
