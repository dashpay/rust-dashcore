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
    tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).init();

    // Create a temporary directory for this test
    let data_dir = PathBuf::from(format!("/tmp/dash-spv-initial-sync-{}", std::process::id()));

    // Create client config
    let mut config = ClientConfig::new(Network::Testnet);
    config.peers =
        vec!["54.68.235.201:19999".parse().unwrap(), "52.40.219.41:19999".parse().unwrap()];
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
    let progress = client.sync_progress().await?;
    println!("📊 Sync progress after 10 seconds:");
    println!("  - Headers synced: {}", progress.header_height);
    println!("  - Headers synced (bool): {}", progress.headers_synced);
    println!("  - Peer count: {}", progress.peer_count);

    // Wait a bit more to see if headers2 kicks in after initial sync
    println!("\n⏳ Waiting to see if headers2 is used after initial sync...");
    tokio::time::sleep(Duration::from_secs(10)).await;

    let final_progress = client.sync_progress().await?;

    // Clean up
    client.stop().await?;
    let _ = std::fs::remove_dir_all(data_dir);

    println!("\n📊 Final sync progress:");
    println!("  - Headers synced: {}", final_progress.header_height);

    if final_progress.header_height > 0 {
        println!("\n✅ Initial sync successful! Synced {} headers", final_progress.header_height);
        Ok(())
    } else {
        println!("\n❌ Initial sync failed - no headers synced");
        Err(SpvError::Sync(dash_spv::error::SyncError::Network("No headers synced".to_string())))
    }
}
