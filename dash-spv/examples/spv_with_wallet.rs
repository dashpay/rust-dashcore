//! Example of using DashSpvClient with a wallet implementation
//!
//! This example shows how to integrate the SPV client with a wallet manager.

use dash_spv::network::PeerNetworkManager;
use dash_spv::storage::DiskStorageManager;
use dash_spv::{Config, DashSpvClient, LevelFilter};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::wallet_manager::WalletManager;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    let _logging_guard = dash_spv::init_console_logging(LevelFilter::INFO)?;

    // Create SPV client configuration
    let config = Config::testnet()
        .with_storage_path("./.tmp/spv-with-wallet-example-storage")
        .with_validation_mode(dash_spv::ValidationMode::Full);

    // Create network manager
    let network_manager = PeerNetworkManager::new(&config).await?;

    // Create storage manager - use disk storage for persistence
    let storage_manager = DiskStorageManager::new(&config).await?;

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(config.network)));

    // Create the SPV client with all components
    let mut client = DashSpvClient::new(config, network_manager, storage_manager, wallet).await?;

    // Start the client
    println!("Starting SPV client...");
    client.start().await?;

    // The wallet will automatically be notified of:
    // - New blocks via process_block()
    // - Mempool transactions via process_mempool_transaction()
    // - Reorgs via handle_reorg()
    // - Compact filter checks via check_compact_filter()

    let (_command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();
    let shutdown_token = CancellationToken::new();

    client.run(command_receiver, shutdown_token).await?;

    println!("Done!");
    Ok(())
}
