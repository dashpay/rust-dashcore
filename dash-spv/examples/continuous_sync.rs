//! Example of using continuous header sync to keep monitoring for new blocks
//!
//! This example shows how to configure dash-spv to continuously monitor
//! for new headers after reaching the chain tip, instead of going idle.

use std::time::Duration;
use tokio::time::sleep;

use dash_spv::{ClientConfig, DashSpvClient};
use dashcore::Network;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("dash_spv=debug")
        .init();

    println!("Starting Dash SPV client with continuous header sync...");

    // Create config with continuous sync enabled
    let mut config = ClientConfig::new(Network::Testnet);
    
    // Enable continuous sync with 30 second interval
    config.continuous_sync_interval = Some(Duration::from_secs(30));
    
    // Add testnet peers
    config.peers = vec![
        "174.138.35.118:19999".parse()?,
        "149.28.22.65:19999".parse()?,
    ];
    
    // Create client
    let mut client = DashSpvClient::new(config).await?;

    // Take the progress receiver to monitor sync progress
    let mut progress_rx = client.take_progress_receiver()
        .expect("Failed to take progress receiver");

    // Start the client
    println!("Starting SPV client...");
    client.start().await?;

    // Monitor progress
    println!("Monitoring sync progress...");
    
    let mut monitoring_logged = false;
    
    loop {
        tokio::select! {
            Some(progress) = progress_rx.recv() => {
                match &progress.sync_stage {
                    dash_spv::types::SyncStage::DownloadingHeaders { start, end } => {
                        println!(
                            "Downloading headers: {} to {} ({:.1}%)",
                            start, end,
                            progress.calculate_percentage()
                        );
                    }
                    dash_spv::types::SyncStage::MonitoringHeaders { interval_secs } => {
                        if !monitoring_logged {
                            println!(
                                "Reached chain tip at height {}. Now monitoring for new headers every {} seconds...",
                                progress.current_height,
                                interval_secs
                            );
                            monitoring_logged = true;
                        }
                    }
                    dash_spv::types::SyncStage::Complete => {
                        println!("Initial sync complete at height {}", progress.current_height);
                    }
                    _ => {}
                }
            }
            _ = sleep(Duration::from_secs(300)) => {
                println!("Client has been monitoring for 5 minutes...");
                break;
            }
        }
    }

    // The client will continue monitoring in the background
    println!("SPV client is continuously monitoring for new blocks.");
    println!("It will check for new headers every 30 seconds.");
    
    // Keep the client running
    sleep(Duration::from_secs(600)).await;
    
    // Stop the client
    println!("Stopping client...");
    client.stop().await?;

    Ok(())
}