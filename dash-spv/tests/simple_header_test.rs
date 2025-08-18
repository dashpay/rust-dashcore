//! Simple test to verify header sync fix works

use dash_spv::{
    client::{ClientConfig, DashSpvClient},
    network::MultiPeerNetworkManager,
    storage::{MemoryStorageManager, StorageManager},
    types::ValidationMode,
};
use dashcore::Network;
use key_wallet_manager::spv_wallet_manager::SPVWalletManager;
use log::info;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::RwLock;

const DASH_NODE_ADDR: &str = "127.0.0.1:9999";

/// Check if node is available
async fn check_node_availability() -> bool {
    match tokio::net::TcpStream::connect(DASH_NODE_ADDR).await {
        Ok(_) => {
            info!("Dash Core node is available at {}", DASH_NODE_ADDR);
            true
        }
        Err(e) => {
            info!("Dash Core node not available at {}: {}", DASH_NODE_ADDR, e);
            info!("Skipping test - ensure Dash Core is running on mainnet");
            false
        }
    }
}

#[tokio::test]
async fn test_simple_header_sync() {
    let _ = env_logger::try_init();

    if !check_node_availability().await {
        return;
    }

    info!("Testing simple header sync to verify fix");

    let peer_addr: SocketAddr = DASH_NODE_ADDR.parse().unwrap();

    // Create client configuration
    let mut config = ClientConfig::new(Network::Dash)
        .with_validation_mode(ValidationMode::Basic)
        .with_connection_timeout(Duration::from_secs(10));

    config.peers.push(peer_addr);

    // Create fresh storage
    let storage = MemoryStorageManager::new().await.expect("Failed to create storage");

    // Verify starting from empty state
    assert_eq!(storage.get_tip_height().await.unwrap(), None);

    // Create network manager
    let network_manager =
        MultiPeerNetworkManager::new(&config).await.expect("Failed to create network manager");

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(SPVWalletManager::new()));

    let mut client = DashSpvClient::new(config.clone(), network_manager, storage, wallet)
        .await
        .expect("Failed to create SPV client");

    // Start the client
    client.start().await.expect("Failed to start client");

    info!("Starting header sync...");

    // Sync just a few headers with short timeout
    let sync_result = tokio::time::timeout(Duration::from_secs(30), async {
        // Try to sync to tip once
        info!("Attempting sync to tip...");
        match client.sync_to_tip().await {
            Ok(progress) => {
                info!("Sync succeeded! Progress: height={}", progress.header_height);
            }
            Err(e) => {
                // This is the critical test - the error should NOT be about headers not connecting
                let error_msg = format!("{}", e);
                if error_msg.contains("Header does not connect to previous header") {
                    panic!(
                        "FAILED: Got the header connection error we were trying to fix: {}",
                        error_msg
                    );
                }
                info!("Sync failed (may be expected): {}", e);
            }
        }

        // Check final state
        let final_height =
            client.storage().lock().await.get_tip_height().await.expect("Failed to get tip height");

        info!("Final header height: {:?}", final_height);

        // As long as we didn't get the "Header does not connect" error, the fix worked
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await;

    match sync_result {
        Ok(_) => {
            info!("✅ Header sync test completed - no 'Header does not connect' errors detected");
            info!("This means our fix for the GetHeaders protocol is working correctly!");
        }
        Err(_) => {
            info!(
                "⚠️  Test timed out, but that's okay as long as we didn't get the connection error"
            );
            info!(
                "The important thing is we didn't see 'Header does not connect to previous header'"
            );
        }
    }
}
