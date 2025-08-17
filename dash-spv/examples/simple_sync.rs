//! Simple header synchronization example.

use dash_spv::network::MultiPeerNetworkManager;
use dash_spv::storage::MemoryStorageManager;
use dash_spv::{init_logging, ClientConfig, DashSpvClient};
use key_wallet_manager::spv_wallet_manager::SPVWalletManager;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    init_logging("info")?;

    // Create a simple configuration
    let config = ClientConfig::mainnet()
        .without_filters() // Skip filter sync for this example
        .without_masternodes(); // Skip masternode sync for this example

    // Create network manager
    let network_manager = MultiPeerNetworkManager::new(&config).await?;

    // Create storage manager
    let storage_manager = MemoryStorageManager::new().await?;

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(SPVWalletManager::new(config.network)));

    // Create the client
    let mut client = DashSpvClient::new(config, network_manager, storage_manager, wallet).await?;

    // Start the client
    client.start().await?;

    println!("Starting header synchronization...");

    // Sync headers only
    let progress = client.sync_to_tip().await?;

    println!("Synchronization completed!");
    println!("Synced {} headers", progress.header_height);

    // Get some statistics
    let stats = client.stats().await?;
    println!("Headers downloaded: {}", stats.headers_downloaded);
    println!("Bytes received: {}", stats.bytes_received);

    // Stop the client
    client.stop().await?;

    println!("Done!");
    Ok(())
}
