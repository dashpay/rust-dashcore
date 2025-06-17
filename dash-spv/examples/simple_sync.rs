//! Simple header synchronization example.

use dash_spv::{init_logging, ClientConfig, DashSpvClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    init_logging("info")?;

    // Create a simple configuration
    let config = ClientConfig::mainnet()
        .without_filters() // Skip filter sync for this example
        .without_masternodes(); // Skip masternode sync for this example

    // Create the client
    let mut client = DashSpvClient::new(config).await?;

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
