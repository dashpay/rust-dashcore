//! Simple header synchronization example.

use dash_spv::network::PeerNetworkManager;
use dash_spv::storage::DiskStorageManager;
use dash_spv::ClientConfigBuilder;
use dash_spv::{init_console_logging, DashSpvClient, LevelFilter};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;

use key_wallet_manager::wallet_manager::WalletManager;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    let _logging_guard = init_console_logging(LevelFilter::INFO)?;

    // Create a simple configuration
    let config = ClientConfigBuilder::mainnet()
        .storage_path("./.tmp/simple-sync-example-storage")
        .enable_filters(false) // Skip filter sync for this example
        .enable_masternodes(false) // Skip masternode sync for this example
        .build()?;
    // Create network manager
    let network_manager = PeerNetworkManager::new(&config).await?;

    // Create storage manager
    let storage_manager = DiskStorageManager::new(&config).await?;

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(config.network())));

    // Create the client
    let mut client = DashSpvClient::new(config, network_manager, storage_manager, wallet).await?;

    // Start the client
    client.start().await?;

    println!("Starting header synchronization...");

    // Get some statistics
    let stats = client.stats().await?;
    println!("Headers downloaded: {}", stats.headers_downloaded);
    println!("Bytes received: {}", stats.bytes_received);

    let (_command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();
    let shutdown_token = CancellationToken::new();

    client.run(command_receiver, shutdown_token).await?;

    println!("Done!");
    Ok(())
}
