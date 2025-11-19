//! Example of using DashSpvClient with a wallet implementation
//!
//! This example shows how to integrate the SPV client with a wallet manager.

use dash_spv::network::PeerNetworkManager;
use dash_spv::storage::DiskStorageManager;
use dash_spv::{ClientConfig, DashSpvClient};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::wallet_manager::WalletManager;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    dash_spv::init_logging("info")?;

    // Create SPV client configuration
    let mut config = ClientConfig::testnet();
    config.storage_path = Some("/tmp/dash-spv-example".into());
    config.validation_mode = dash_spv::types::ValidationMode::Full;
    config.enable_filters = true;

    // Create network manager
    let network_manager = PeerNetworkManager::new(&config).await?;

    // Create storage manager - use disk storage for persistence
    let storage_manager = DiskStorageManager::new("/tmp/dash-spv-example".into()).await?;

    // Create wallet manager
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new()));

    // Create the SPV client with all components
    let mut client = DashSpvClient::new(config, network_manager, storage_manager, wallet).await?;

    // Start the client
    println!("Starting SPV client...");
    client.start().await?;

    // Sync to the tip of the blockchain
    println!("Syncing to blockchain tip...");
    let progress = client.sync_to_tip().await?;
    println!("Synced to height: {}", progress.header_height);

    // The wallet will automatically be notified of:
    // - New blocks via process_block()
    // - Mempool transactions via process_mempool_transaction()
    // - Reorgs via handle_reorg()
    // - Compact filter checks via check_compact_filter()
    tokio::select! {
        result = client.monitor_network() => {
            println!("monitor_network result {:?}", result);
        },
        _ = signal::ctrl_c() => {
            println!("monitor_network canceled");
        }
    }

    // Stop the client
    println!("Stopping SPV client...");
    client.stop().await?;

    println!("Done!");
    Ok(())
}
