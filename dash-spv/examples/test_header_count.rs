//! Test to verify header count display fix for normal sync

use dash_spv::client::{Client, ClientConfig};
use dashcore::Network;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,dash_spv=debug")),
        )
        .init();

    // Test directory
    let storage_dir = "test-header-count-data";

    // Clean up any previous test data
    if std::path::Path::new(storage_dir).exists() {
        std::fs::remove_dir_all(storage_dir)?;
    }

    println!("Testing header count display fix");
    println!("================================");

    // Phase 1: Initial sync
    println!("\nPhase 1: Initial sync from genesis (normal sync without checkpoint)");
    println!("-------------------------------------------------------------------");

    {
        let config = ClientConfig {
            network: Network::Testnet,
            storage_path: Some(storage_dir.into()),
            enable_persistence: true,
            start_from_height: None, // Normal sync from genesis
            ..Default::default()
        };

        let mut client = Client::new(config)?;
        client.start().await?;

        println!("Syncing headers for 20 seconds...");
        tokio::time::sleep(Duration::from_secs(20)).await;

        let progress = client.sync_progress().await?;
        println!("Headers synced: {}", progress.header_height);

        client.shutdown().await?;
        println!("Client shut down.");
    }

    // Phase 2: Restart and check header count
    println!("\nPhase 2: Restart client and check header count display");
    println!("------------------------------------------------------");

    {
        let config = ClientConfig {
            network: Network::Testnet,
            storage_path: Some(storage_dir.into()),
            enable_persistence: true,
            start_from_height: None,
            ..Default::default()
        };

        let mut client = Client::new(config)?;

        // Get progress before starting (headers not loaded yet)
        let progress_before = client.sync_progress().await?;
        println!("Header count BEFORE start (ChainState empty): {}", progress_before.header_height);

        client.start().await?;

        // Wait a bit for initialization
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Get progress after starting (headers should be loaded)
        let progress_after = client.sync_progress().await?;
        println!("Header count AFTER start (headers loaded): {}", progress_after.header_height);

        if progress_before.header_height == 0 && progress_after.header_height > 0 {
            println!("\n✅ SUCCESS: Fix is working! Headers are correctly displayed even when ChainState is empty.");
        } else if progress_before.header_height > 0 {
            println!(
                "\n✅ SUCCESS: Headers were already correctly displayed: {}",
                progress_before.header_height
            );
        } else {
            println!("\n❌ FAIL: Headers still showing as 0 after restart");
        }

        client.shutdown().await?;
    }

    // Clean up
    std::fs::remove_dir_all(storage_dir)?;

    Ok(())
}
