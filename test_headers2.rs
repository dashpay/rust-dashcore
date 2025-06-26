#!/usr/bin/env cargo +nightly -Zscript

//! Test headers2 implementation with a real Dash node
//! 
//! Run with: ./test_headers2.rs

use dashcore::Network;
use dash_spv::client::{ClientConfig, DashSpvClient};
use dash_spv::error::SpvError;
use std::time::Duration;
use tokio;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), SpvError> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    println!("🚀 Testing headers2 implementation with mainnet Dash node...");

    // Configure client
    let mut config = ClientConfig::new(Network::Dash);
    config.initial_peers = vec!["seed.dash.org:9999".parse().unwrap()];
    config.max_peers = 1; // Single peer for testing
    config.sync_batch_size = 100; // Small batch for testing

    // Create and start client
    let client = DashSpvClient::new(config).await?;
    
    println!("📡 Starting SPV client...");
    client.start().await?;

    // Wait a bit to see if connection drops
    println!("⏳ Monitoring connection for 30 seconds...");
    for i in 0..30 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        
        let progress = client.get_sync_progress().await?;
        let peers = client.get_peer_count().await;
        
        println!("[{}s] Peers: {}, Headers: {}, Sync phase: {:?}", 
                 i + 1, 
                 peers, 
                 progress.header_height,
                 if progress.syncing_headers { "Headers" } 
                 else if progress.syncing_masternode_list { "Masternodes" }
                 else if progress.syncing_filter_headers { "Filter Headers" }
                 else if progress.syncing_filters { "Filters" }
                 else { "Idle" });
        
        if peers == 0 && i > 5 {
            println!("❌ Connection dropped!");
            break;
        }
    }

    println!("🏁 Test complete");
    client.shutdown().await?;
    
    Ok(())
}