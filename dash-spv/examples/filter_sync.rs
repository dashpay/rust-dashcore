//! BIP157 filter synchronization example.

use dash_spv::{init_logging, ClientConfig, DashSpvClient, WatchItem};
use dashcore::{Address, Network};
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    init_logging("info")?;

    // Parse a Dash address to watch
    let watch_address = Address::<dashcore::address::NetworkUnchecked>::from_str(
        "Xan9iCVe1q5jYRDZ4VSMCtBjq2VyQA3Dge",
    )?;

    // Create configuration with filter support
    let config = ClientConfig::mainnet()
        .watch_address(watch_address.clone().require_network(Network::Dash).unwrap())
        .without_masternodes(); // Skip masternode sync for this example

    // Create the client
    let mut client = DashSpvClient::new(config).await?;

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
