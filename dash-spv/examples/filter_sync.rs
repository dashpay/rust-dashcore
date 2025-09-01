//! BIP157 filter synchronization example.

use dash_spv::network::MultiPeerNetworkManager;
use dash_spv::storage::MemoryStorageManager;
use dash_spv::{init_logging, ClientConfig, DashSpvClient};
use dashcore::Address;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::wallet_manager::WalletManager;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    init_logging("info")?;

    // Parse a Dash address to watch
    let watch_address = Address::<dashcore::address::NetworkUnchecked>::from_str(
        "Xan9iCVe1q5jYRDZ4VSMCtBjq2VyQA3Dge",
    )?;

    // Create configuration with filter support
    let config = ClientConfig::mainnet().without_masternodes(); // Skip masternode sync for this example

    // Create network manager
    let network_manager = MultiPeerNetworkManager::new(&config).await?;

    // Create storage manager
    let storage_manager = MemoryStorageManager::new().await?;

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new()));

    // Create the client
    let mut client = DashSpvClient::new(config, network_manager, storage_manager, wallet).await?;

    // Start the client
    client.start().await?;

    println!("Starting synchronization with filter support...");
    println!("Watching address: {:?}", watch_address);

    // Full sync including filters
    let progress = client.sync_to_tip().await?;

    println!("Synchronization completed!");
    println!("Headers synced: {}", progress.header_height);
    println!("Filter headers synced: {}", progress.filter_header_height);

    // Get statistics
    let stats = client.stats().await?;
    println!("Filter headers downloaded: {}", stats.filter_headers_downloaded);
    println!("Filters downloaded: {}", stats.filters_downloaded);
    println!("Filter matches found: {}", stats.filters_matched);
    println!("Blocks requested: {}", stats.blocks_requested);

    // Stop the client
    client.stop().await?;

    println!("Done!");
    Ok(())
}
