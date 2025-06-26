//! Test headers2 implementation with a real Dash node

use dashcore::Network;
use dash_spv::client::{ClientConfig, DashSpvClient};
use dash_spv::error::SpvError;
use std::time::Duration;
use tokio;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), SpvError> {
    // Initialize logging with more verbose output for debugging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .init();

    println!("🚀 Testing headers2 implementation with mainnet Dash node...");

    // Configure client
    let mut config = ClientConfig::new(Network::Dash);
    
    // Use a known good mainnet peer or seed
    config.peers = vec![
        "seed.dash.org:9999".parse().unwrap(),
        "dnsseed.dash.org:9999".parse().unwrap(),
    ];
    
    config.max_peers = 1; // Single peer for testing
    config.header_batch_size = 100; // Small batch for testing
    config.connection_timeout = Duration::from_secs(30); // Shorter timeout for testing

    // Create and start client
    let client = DashSpvClient::new(config).await?;
    
    println!("📡 Starting SPV client...");
    client.start().await?;

    // Monitor the connection
    println!("⏳ Monitoring connection and sync progress...");
    
    let mut last_height = 0;
    let mut no_progress_count = 0;
    
    for i in 0..60 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        
        let progress = client.sync_progress().await?;
        let peers = client.get_peer_count().await;
        
        // Determine current phase
        let phase = if !progress.headers_synced { 
            "Headers" 
        } else if !progress.masternodes_synced { 
            "Masternodes" 
        } else if !progress.filter_headers_synced { 
            "Filter Headers" 
        } else if progress.filters_downloaded == 0 { 
            "Filters" 
        } else { 
            "Idle" 
        };
        
        println!("[{}s] Peers: {}, Headers: {}, Phase: {}", 
                 i + 1, 
                 peers, 
                 progress.header_height,
                 phase);
        
        // Check for connection drops
        if peers == 0 && i > 5 {
            println!("❌ Connection dropped after {} seconds!", i + 1);
            println!("   This likely indicates a headers2 protocol issue");
            break;
        }
        
        // Check for progress
        if progress.header_height > last_height {
            println!("✅ Progress! Downloaded {} new headers", progress.header_height - last_height);
            last_height = progress.header_height;
            no_progress_count = 0;
        } else if !progress.headers_synced {
            no_progress_count += 1;
            if no_progress_count > 10 {
                println!("⚠️  No header progress for 10 seconds");
            }
        }
        
        // Stop after some headers are downloaded
        if progress.header_height > 1000 {
            println!("✅ Successfully downloaded {} headers using headers2!", progress.header_height);
            break;
        }
    }

    // Final status
    let final_progress = client.sync_progress().await?;
    let final_peers = client.get_peer_count().await;
    
    println!("\n📊 Final Status:");
    println!("   Connected peers: {}", final_peers);
    println!("   Headers synced: {}", final_progress.header_height);
    println!("   Sync phase: {:?}", final_progress);
    
    if final_peers > 0 && final_progress.header_height > 0 {
        println!("\n✅ Headers2 implementation appears to be working!");
    } else {
        println!("\n❌ Headers2 implementation may have issues");
    }

    println!("\n🏁 Shutting down...");
    client.shutdown().await?;
    
    Ok(())
}