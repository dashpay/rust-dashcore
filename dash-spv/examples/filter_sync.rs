//! BIP157 filter synchronization example.

use dash_spv::network::PeerNetworkManager;
use dash_spv::storage::DiskStorageManager;
use dash_spv::{init_console_logging, ClientConfig, DashSpvClient, LevelFilter};
use dashcore::Address;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::wallet_manager::WalletManager;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    let _logging_guard = init_console_logging(LevelFilter::INFO)?;

    // Parse a Dash address to watch
    let watch_address = Address::<dashcore::address::NetworkUnchecked>::from_str(
        "Xan9iCVe1q5jYRDZ4VSMCtBjq2VyQA3Dge",
    )?;

    // Create configuration with filter support
    let config = ClientConfig::mainnet()
        .with_storage_path("./.tmp/filter-sync-example-storage")
        .without_masternodes(); // Skip masternode sync for this example

    // Create network manager
    let network_manager = PeerNetworkManager::new(&config).await?;

    // Create storage manager
    let storage_manager = DiskStorageManager::new(&config).await?;

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(config.network)));

    // Create the client
    let mut client = DashSpvClient::new(config, network_manager, storage_manager, wallet).await?;

    // Start the client
    client.start().await?;

    println!("Starting synchronization with filter support...");
    println!("Watching address: {:?}", watch_address);

    let (_command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();
    let shutdown_token = CancellationToken::new();

    client.run(command_receiver, shutdown_token).await?;

    println!("Done!");
    Ok(())
}
