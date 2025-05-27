//! Command-line interface for the Dash SPV client.

// Removed unused import
use std::path::PathBuf;
use std::process;

use clap::{Arg, Command};
use tokio::signal;

use dash_spv::{ClientConfig, DashSpvClient, Network};
use dash_spv::terminal::TerminalGuard;

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
        .arg(
            Arg::new("watch-address")
                .short('w')
                .long("watch-address")
                .value_name("ADDRESS")
                .help("Dash address to watch for transactions (can be used multiple times)")
                .action(clap::ArgAction::Append)
        )
        .arg(
            Arg::new("add-example-addresses")
                .long("add-example-addresses")
                .help("Add some example Dash addresses to watch for testing")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("no-terminal-ui")
                .long("no-terminal-ui")
                .help("Disable terminal UI status bar")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();

    // Get log level (will be used after we know if terminal UI is enabled)
    let log_level = matches.get_one::<String>("log-level").unwrap();

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

    // Check if terminal UI should be enabled
    let enable_terminal_ui = !matches.get_flag("no-terminal-ui");

    // Initialize logging first (without terminal UI)
    dash_spv::init_logging(log_level)?;

    // Create and start the client
    let mut client = match DashSpvClient::new(config).await {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to create SPV client: {}", e);
            process::exit(1);
        }
    };

    // Enable terminal UI in the client if requested
    let _terminal_guard = if enable_terminal_ui {
        client.enable_terminal_ui();
        
        // Get the terminal UI from the client and initialize it
        if let Some(ui) = client.get_terminal_ui() {
            match TerminalGuard::new(ui.clone()) {
                Ok(guard) => {
                    // Initial update with network info
                    let network_name = format!("{:?}", client.network());
                    let _ = ui.update_status(|status| {
                        status.network = network_name;
                        status.peer_count = 0; // Will be updated when connected
                    }).await;
                    
                    Some(guard)
                }
                Err(e) => {
                    tracing::warn!("Failed to initialize terminal UI: {}", e);
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    if let Err(e) = client.start().await {
        eprintln!("Failed to start SPV client: {}", e);
        process::exit(1);
    }

    tracing::info!("SPV client started successfully");

    // Add watch addresses if specified
    if let Some(addresses) = matches.get_many::<String>("watch-address") {
        for addr_str in addresses {
            match addr_str.parse::<dashcore::Address<dashcore::address::NetworkUnchecked>>() {
                Ok(addr) => {
                    let checked_addr = addr.require_network(network).map_err(|_| {
                        format!("Address '{}' is not valid for network {:?}", addr_str, network)
                    });
                    match checked_addr {
                        Ok(valid_addr) => {
                            if let Err(e) = client.add_watch_item(dash_spv::WatchItem::Address(valid_addr)).await {
                                tracing::error!("Failed to add watch address '{}': {}", addr_str, e);
                            } else {
                                tracing::info!("Added watch address: {}", addr_str);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Invalid address for network: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Invalid address format '{}': {}", addr_str, e);
                }
            }
        }
    }

    // Add example addresses for testing if requested
    if matches.get_flag("add-example-addresses") {
        let example_addresses = match network {
            dashcore::Network::Dash => vec![
                // Some example mainnet addresses (these are from block explorers/faucets)
                "XjbaGWaGnvEtuQAUoBgDxJWe8ZNv45upG2", // Crowdnode
            ],
            dashcore::Network::Testnet => vec![
                // Testnet addresses
                "yNEr8u4Kx8PTH9A9G3P7NwkJRmqFD7tKSj", // Example testnet address
                "yMGqjKTqr2HKKV6zqSg5vTPQUzJNt72h8h", // Another testnet example
            ],
            dashcore::Network::Regtest => vec![
                // Regtest addresses (these would be from local testing)
                "yQ9J8qK3nNW8JL8h5T6tB3VZwwH9h5T6tB", // Example regtest address
                "yeRZBWYfeNE4yVUHV4ZLs83Ppn9aMRH57A", // Another regtest example
            ],
            _ => vec![],
        };

        for addr_str in example_addresses {
            match addr_str.parse::<dashcore::Address<dashcore::address::NetworkUnchecked>>() {
                Ok(addr) => {
                    if let Ok(valid_addr) = addr.require_network(network) {
                        if let Err(e) = client.add_watch_item(dash_spv::WatchItem::Address(valid_addr)).await {
                            tracing::error!("Failed to add example address '{}': {}", addr_str, e);
                        } else {
                            tracing::info!("Added example watch address: {}", addr_str);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Example address '{}' failed to parse: {}", addr_str, e);
                }
            }
        }
    }

    // Display current watch list
    let watch_items = client.get_watch_items().await;
    if !watch_items.is_empty() {
        tracing::info!("Watching {} items:", watch_items.len());
        for (i, item) in watch_items.iter().enumerate() {
            match item {
                dash_spv::WatchItem::Address(addr) => tracing::info!("  {}: Address {}", i + 1, addr),
                dash_spv::WatchItem::Script(script) => tracing::info!("  {}: Script {}", i + 1, script.to_hex_string()),
                dash_spv::WatchItem::Outpoint(outpoint) => tracing::info!("  {}: Outpoint {}:{}", i + 1, outpoint.txid, outpoint.vout),
            }
        }
    } else {
        tracing::info!("No watch items configured. Use --watch-address or --add-example-addresses to watch for transactions.");
    }

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
            panic!("SPV client synchronization failed: {}", e);
        }
    }

    // Check filters for matches if we have watch items
    let watch_items = client.get_watch_items().await;
    if !watch_items.is_empty() && matches.get_flag("no-filters") == false {
        tracing::info!("Checking recent filters for matches...");
        match client.sync_and_check_filters(Some(1000)).await {
            Ok(matches) => {
                if matches.is_empty() {
                    tracing::info!("No filter matches found in recent blocks");
                } else {
                    tracing::info!("🎯 Found {} filter matches:", matches.len());
                    for (i, filter_match) in matches.iter().enumerate() {
                        tracing::info!("  {}: Block {} at height {}", 
                                      i + 1, filter_match.block_hash, filter_match.height);
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to check filters: {}", e);
            }
        }
    }

    // The client will handle updating the terminal UI internally
    
    // Start continuous monitoring
    tracing::info!("SPV client running. Starting network monitoring...");
    
    tokio::select! {
        result = client.monitor_network() => {
            if let Err(e) = result {
                tracing::error!("Network monitoring failed: {}", e);
            }
        }
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