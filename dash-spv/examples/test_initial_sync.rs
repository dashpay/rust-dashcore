use dash_spv::{
    client::{ClientConfig, DashSpvClient},
    error::SpvError,
};
use dashcore::Network;
use std::path::PathBuf;
use std::time::Duration;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), SpvError> {
    // Setup logging
    tracing_subscriber::fmt()
        .with_env_filter("dash_spv=debug")
        .init();

    // Create a temporary directory for this test
    let data_dir = PathBuf::from(format!("/tmp/dash-spv-initial-sync-{}", std::process::id()));
    
    // Create client config
    let mut config = ClientConfig::new(Network::Testnet);
    config.peers = vec![
        "54.68.235.201:19999".parse().unwrap(),
        "52.40.219.41:19999".parse().unwrap(),
    ];
    config.storage_path = Some(data_dir.clone());
    config.enable_filters = false; // Disable filters for faster testing
    
    // Create and start client
    println!("🚀 Starting Dash SPV client for initial sync test...");
    let mut client = DashSpvClient::new(config).await?;
    
    client.start().await?;
    
    // Wait for some headers to sync
    println!("⏳ Waiting for initial headers sync...");
    tokio::time::sleep(Duration::from_secs(10)).await;
    
    // Check sync progress
    let progress = client.sync_progress().await;
    if let Some(p) = progress {
        println!("📊 Sync progress after 10 seconds:");
        println!("  - Headers synced: {}", p.header_height);
        println!("  - Headers synced (bool): {}", p.headers_synced);
        println!("  - Peer count: {}", p.peer_count);
    } else {
        println!("❌ No sync progress available");
    }
    
    // Wait a bit more to see if headers2 kicks in after initial sync
    println!("\n⏳ Waiting to see if headers2 is used after initial sync...");
    tokio::time::sleep(Duration::from_secs(10)).await;
    
    let final_progress = client.sync_progress().await;
    
    // Clean up
    client.stop().await?;
    let _ = std::fs::remove_dir_all(data_dir);
    
    if let Some(p) = final_progress {
        println!("\n📊 Final sync progress:");
        println!("  - Headers synced: {}", p.header_height);
        
        if p.header_height > 0 {
            println!("\n✅ Initial sync successful! Synced {} headers", p.header_height);
            Ok(())
        } else {
            println!("\n❌ Initial sync failed - no headers synced");
            Err(SpvError::Sync(dash_spv::error::SyncError::SyncFailed("No headers synced".to_string())))
        }
    } else {
        println!("\n❌ No sync progress available");
        Err(SpvError::Sync(dash_spv::error::SyncError::SyncFailed("No sync progress".to_string())))
    }
}