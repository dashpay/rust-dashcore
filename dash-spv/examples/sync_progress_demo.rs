//! Example demonstrating how to track detailed sync phase information from dash-spv.

use std::time::Duration;

use dash_spv::client::{ClientConfig, DashSpvClient};
use dash_spv::types::SyncPhaseInfo;
use dashcore::Network;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt().with_env_filter("dash_spv=info").init();

    // Configure the SPV client
    let config = ClientConfig {
        network: Network::Testnet,
        data_dir: "/tmp/dash-spv-demo".into(),
        peer_addresses: vec![], // Will use DNS seeds
        max_peers: 3,
        enable_filters: true,
        enable_masternodes: true,
        enable_headers2: true,
        enable_mempool_tracking: false,
        validation_mode: dash_spv::types::ValidationMode::Full,
        storage_type: "disk".to_string(),
        filter_checkpoint_height: None,
        watch_items: vec![],
        header_batch_size: 2000,
        filter_batch_size: 1000,
        socket_timeout_secs: 30,
        header_download_timeout_secs: 30,
        headers2_min_protocol_version: None,
        cfheader_request_timeout_secs: 60,
        cfheader_gap_check_interval_secs: 300,
        socket_read_timeout_secs: 30,
    };

    // Create and start the SPV client
    let mut client = DashSpvClient::new(config).await?;

    println!("Starting Dash SPV client...");
    client.start().await?;

    // Give the client time to connect to peers
    sleep(Duration::from_secs(2)).await;

    // Monitor sync progress
    let mut last_phase = String::new();

    loop {
        // Get current sync progress
        let progress = client.sync_progress().await?;

        // Check if we have phase information
        if let Some(phase_info) = &progress.current_phase {
            // Print phase change
            if phase_info.phase_name != last_phase {
                println!("\n🔄 Phase Change: {}", phase_info.phase_name);
                last_phase = phase_info.phase_name.clone();
            }

            // Print detailed progress
            print_phase_progress(phase_info);

            // Check if sync is complete
            if phase_info.phase_name == "Fully Synced" {
                println!("\n✅ Synchronization complete!");
                break;
            }
        } else {
            println!("⏳ Waiting for sync to start...");
        }

        // Also print basic stats
        println!(
            "📊 Stats: {} headers, {} filter headers, {} filters downloaded, {} peers",
            progress.header_height,
            progress.filter_header_height,
            progress.filters_downloaded,
            progress.peer_count
        );

        // Wait before next check
        sleep(Duration::from_secs(1)).await;
    }

    // Clean shutdown
    client.stop().await?;
    println!("Client stopped successfully.");

    Ok(())
}

fn print_phase_progress(phase: &SyncPhaseInfo) {
    print!("\r{}: ", phase.phase_name);

    // Show progress bar if percentage is available
    if phase.progress_percentage > 0.0 {
        let filled = (phase.progress_percentage / 5.0) as usize;
        let empty = 20 - filled;
        print!("[{}{}] {:.1}%", "█".repeat(filled), "░".repeat(empty), phase.progress_percentage);
    }

    // Show items progress
    if let Some(total) = phase.items_total {
        print!(" ({}/{})", phase.items_completed, total);
    } else {
        print!(" ({})", phase.items_completed);
    }

    // Show rate
    if phase.rate > 0.0 {
        print!(" @ {:.1} items/sec", phase.rate);
    }

    // Show ETA
    if let Some(eta_secs) = phase.eta_seconds {
        let mins = eta_secs / 60;
        let secs = eta_secs % 60;
        if mins > 0 {
            print!(" - ETA: {}m {}s", mins, secs);
        } else {
            print!(" - ETA: {}s", secs);
        }
    }

    // Show details
    if let Some(details) = &phase.details {
        print!(" - {}", details);
    }

    // Flush to ensure immediate display
    use std::io::{stdout, Write};
    let _ = stdout().flush();
}
