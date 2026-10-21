//! Simple header synchronization example.

use dash_spv::network::PeerNetworkManager;
use dash_spv::storage::DiskStorageManager;
use dash_spv::{init_console_logging, ClientConfig, DashSpvClient, LevelFilter};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;

use key_wallet_manager::WalletManager;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    let _logging_guard = init_console_logging(LevelFilter::INFO)?;

    // Create a simple configuration
    let config = ClientConfig::mainnet()
        .with_storage_path("./.tmp/simple-sync-example-storage")
        .without_filters() // Skip filter sync for this example
        .without_masternodes(); // Skip masternode sync for this example

    // Create network manager
    let network_manager = PeerNetworkManager::new(&config).await?;

    // Create storage manager
    let storage_manager = DiskStorageManager::new(&config).await?;

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(config.network)));

    // Create the client
    let client =
        DashSpvClient::new(config, network_manager, storage_manager, wallet, vec![]).await?;

    println!("Starting header synchronization...");

    client.run().await?;

    println!("Done!");
    Ok(())
}
