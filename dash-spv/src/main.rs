//! Command-line interface for the Dash SPV client.

// Removed unused import
use std::path::PathBuf;
use std::process;

use clap::{Arg, Command};
use tokio::signal;

use dash_spv::{ClientConfig, DashSpvClient, Network, init_logging};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("dash-spv")
        .version(dash_spv::VERSION)
        .about("Dash SPV (Simplified Payment Verification) client")
        .arg(
            Arg::new("network")
                .short('n')
                .long("network")
                .value_name("NETWORK")
                .help("Network to connect to")
                .value_parser(["mainnet", "testnet", "regtest"])
                .default_value("mainnet")
        )
        .arg(
            Arg::new("data-dir")
                .short('d')
                .long("data-dir")
                .value_name("DIR")
                .help("Data directory for storage")
                .default_value("./dash-spv-data")
        )
        .arg(
            Arg::new("peer")
                .short('p')
                .long("peer")
                .value_name("ADDRESS")
                .help("Peer address to connect to (can be used multiple times)")
                .action(clap::ArgAction::Append)
        )
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .value_name("LEVEL")
                .help("Log level")
                .value_parser(["error", "warn", "info", "debug", "trace"])
                .default_value("info")
        )
        .arg(
            Arg::new("no-filters")
                .long("no-filters")
                .help("Disable BIP157 filter synchronization")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("no-masternodes")
                .long("no-masternodes")
                .help("Disable masternode list synchronization")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("validation-mode")
                .long("validation-mode")
                .value_name("MODE")
                .help("Validation mode")
                .value_parser(["none", "basic", "full"])
                .default_value("full")
        )
        .get_matches();

    // Initialize logging
    let log_level = matches.get_one::<String>("log-level").unwrap();
    init_logging(log_level)?;

    // Parse network
    let network = match matches.get_one::<String>("network").unwrap().as_str() {
        "mainnet" => Network::Dash,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        _ => unreachable!(),
    };

    // Parse validation mode
    let validation_mode = match matches.get_one::<String>("validation-mode").unwrap().as_str() {
        "none" => dash_spv::ValidationMode::None,
        "basic" => dash_spv::ValidationMode::Basic,
        "full" => dash_spv::ValidationMode::Full,
        _ => unreachable!(),
    };

    // Create configuration
    let data_dir = PathBuf::from(matches.get_one::<String>("data-dir").unwrap());
    let mut config = ClientConfig::new(network)
        .with_storage_path(data_dir)
        .with_validation_mode(validation_mode)
        .with_log_level(log_level);

    // Add custom peers if specified
    if let Some(peers) = matches.get_many::<String>("peer") {
        config.peers.clear();
        for peer in peers {
            match peer.parse() {
                Ok(addr) => config.add_peer(addr),
                Err(e) => {
                    eprintln!("Invalid peer address '{}': {}", peer, e);
                    process::exit(1);
                }
            };
        }
    }

    // Configure features
    if matches.get_flag("no-filters") {
        config = config.without_filters();
    }
    if matches.get_flag("no-masternodes") {
        config = config.without_masternodes();
    }

    // Validate configuration
    if let Err(e) = config.validate() {
        eprintln!("Configuration error: {}", e);
        process::exit(1);
    }

    tracing::info!("Starting Dash SPV client");
    tracing::info!("Network: {:?}", network);
    tracing::info!("Data directory: {}", config.storage_path.as_ref().unwrap().display());
    tracing::info!("Validation mode: {:?}", validation_mode);

    // Create and start the client
    let mut client = match DashSpvClient::new(config).await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to create SPV client: {}", e);
            process::exit(1);
        }
    };

    if let Err(e) = client.start().await {
        eprintln!("Failed to start SPV client: {}", e);
        process::exit(1);
    }

    tracing::info!("SPV client started successfully");

    // Start synchronization
    tracing::info!("Starting synchronization to tip...");
    match client.sync_to_tip().await {
        Ok(progress) => {
            tracing::info!("Synchronization completed!");
            tracing::info!("Header height: {}", progress.header_height);
            tracing::info!("Filter header height: {}", progress.filter_header_height);
            tracing::info!("Masternode height: {}", progress.masternode_height);
        }
        Err(e) => {
            tracing::error!("Synchronization failed: {}", e);
        }
    }

    // Wait for shutdown signal
    tracing::info!("SPV client running. Press Ctrl+C to shutdown.");
    
    tokio::select! {
        _ = signal::ctrl_c() => {
            tracing::info!("Received shutdown signal");
        }
    }

    // Stop the client
    tracing::info!("Stopping SPV client...");
    if let Err(e) = client.stop().await {
        tracing::error!("Error stopping client: {}", e);
    }

    tracing::info!("SPV client stopped");
    Ok(())
}