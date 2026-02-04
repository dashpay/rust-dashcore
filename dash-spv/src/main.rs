//! Command-line interface for the Dash SPV client.

// Removed unused import
use std::path::PathBuf;
use std::process;
use std::sync::Arc;

use clap::{Arg, Command};
use dash_spv::{ClientConfig, DashSpvClient, LevelFilter, Network};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::wallet_manager::WalletManager;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);

        // Provide specific exit codes for different error types
        let exit_code = if let Some(spv_error) = e.downcast_ref::<dash_spv::SpvError>() {
            match spv_error {
                dash_spv::SpvError::Network(_) => 1,
                dash_spv::SpvError::Storage(_) => 2,
                dash_spv::SpvError::Validation(_) => 3,
                dash_spv::SpvError::Config(_) => 4,
                dash_spv::SpvError::Parse(_) => 5,
                _ => 255,
            }
        } else {
            255
        };

        process::exit(exit_code);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
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
                .default_value("mainnet"),
        )
        .arg(
            Arg::new("data-dir")
                .short('d')
                .long("data-dir")
                .value_name("DIR")
                .help("Data directory for storage (default: unique directory in /tmp)"),
        )
        .arg(
            Arg::new("peer")
                .short('p')
                .long("peer")
                .value_name("ADDRESS")
                .help("Peer address to connect to (can be used multiple times)")
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .env("RUST_LOG")
                .default_value("info")
                .value_name("LEVEL")
                .help("Log level (CLI overrides RUST_LOG env var)")
                .value_parser(["error", "warn", "info", "debug", "trace"]),
        )
        .arg(
            Arg::new("no-filters")
                .long("no-filters")
                .help("Disable BIP157 filter synchronization")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-masternodes")
                .long("no-masternodes")
                .help("Disable masternode list synchronization")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-mempool")
                .long("no-mempool")
                .help("Disable mempool transaction tracking")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("validation-mode")
                .long("validation-mode")
                .value_name("MODE")
                .help("Validation mode")
                .value_parser(["none", "basic", "full"])
                .default_value("full"),
        )
        .arg(
            Arg::new("start-height")
                .long("start-height")
                .short('s')
                .help("Start syncing from a specific block height using the nearest checkpoint. Use 'now' for the latest checkpoint")
                .value_name("HEIGHT"),
        )
        .arg(
            Arg::new("no-log-file")
                .long("no-log-file")
                .help("Disable log file output (enables console logging as fallback)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("print-to-console")
                .long("print-to-console")
                .help("Print logs to the console")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("log-dir")
                .long("log-dir")
                .value_name("DIR")
                .help("Directory for log files (default: <data-dir>/logs)"),
        )
        .arg(
            Arg::new("max-log-files")
                .long("max-log-files")
                .help("Maximum number of archived log files to keep")
                .value_name("COUNT")
                .default_value("20")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("mnemonic-file")
                .long("mnemonic-file")
                .value_name("PATH")
                .help("Path to file containing BIP39 mnemonic phrase")
                .required(true),
        )
        .get_matches();

    let log_level: LevelFilter = matches
        .get_one::<String>("log-level")
        .expect("log-level has default value")
        .parse()
        .expect("log-level value_parser ensures valid level");

    // Parse network
    let network_str = matches.get_one::<String>("network").ok_or("Missing network argument")?;
    let network = match network_str.as_str() {
        "mainnet" => Network::Dash,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        n => return Err(format!("Invalid network: {}", n).into()),
    };

    let mnemonic_path =
        matches.get_one::<String>("mnemonic-file").ok_or("Missing mnemonic-file argument")?;
    let mnemonic_phrase = std::fs::read_to_string(mnemonic_path)
        .map_err(|e| format!("Failed to read mnemonic file '{}': {}", mnemonic_path, e))?
        .trim()
        .to_string();

    // Parse validation mode
    let validation_str =
        matches.get_one::<String>("validation-mode").ok_or("Missing validation-mode argument")?;
    let validation_mode = match validation_str.as_str() {
        "none" => dash_spv::ValidationMode::None,
        "basic" => dash_spv::ValidationMode::Basic,
        "full" => dash_spv::ValidationMode::Full,
        v => return Err(format!("Invalid validation mode: {}", v).into()),
    };

    // Create configuration
    let data_dir = if let Some(data_dir_str) = matches.get_one::<String>("data-dir") {
        PathBuf::from(data_dir_str)
    } else {
        // Create a unique temp directory with timestamp and process ID
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let pid = std::process::id();
        let dir_name = format!("dash-spv-{}-{}", timestamp, pid);
        std::env::temp_dir().join(dir_name)
    };

    // Parse logging flags and initialize logging early
    let no_log_file = matches.get_flag("no-log-file");
    let print_to_console = matches.get_flag("print-to-console");
    let max_log_files = *matches.get_one::<usize>("max-log-files").unwrap();
    let log_dir = matches
        .get_one::<String>("log-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir.join("logs"));

    let file_config = if !no_log_file {
        Some(dash_spv::LogFileConfig {
            log_dir,
            max_files: max_log_files,
        })
    } else {
        None
    };

    let console_enabled = no_log_file || print_to_console;

    let logging_config = dash_spv::LoggingConfig {
        level: Some(log_level),
        console: console_enabled,
        file: file_config,
    };

    // Initialize logging, keep guard alive for the duration of run()
    let _logging_guard = dash_spv::init_logging(logging_config)?;

    tracing::info!("Starting Dash SPV client");
    tracing::info!("Network: {:?}", network);
    tracing::info!("Data directory: {}", data_dir.display());
    tracing::info!("Validation mode: {:?}", validation_mode);

    // Create configuration
    let mut config = ClientConfig::new(network)
        .with_storage_path(data_dir.clone())
        .with_validation_mode(validation_mode);

    // Add custom peers if specified
    if let Some(peers) = matches.get_many::<String>("peer") {
        config.peers.clear();
        for peer in peers {
            match peer.parse() {
                Ok(addr) => config.add_peer(addr),
                Err(e) => {
                    tracing::error!("Invalid peer address '{}': {}", peer, e);
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
    if matches.get_flag("no-mempool") {
        config.enable_mempool_tracking = false;
    }

    // Set start height if specified
    if let Some(start_height_str) = matches.get_one::<String>("start-height") {
        if start_height_str == "now" {
            // Use a very high number to get the latest checkpoint
            config.start_from_height = Some(u32::MAX);
            tracing::info!("Will start syncing from the latest available checkpoint");
        } else {
            let start_height = start_height_str
                .parse::<u32>()
                .map_err(|e| format!("Invalid start height '{}': {}", start_height_str, e))?;
            config.start_from_height = Some(start_height);
            tracing::info!("Will start syncing from height: {}", start_height);
        }
    }

    // Validate configuration
    if let Err(e) = config.validate() {
        tracing::error!("Configuration error: {}", e);
        process::exit(1);
    }

    // Create the wallet manager
    let mut wallet_manager = WalletManager::<ManagedWalletInfo>::new(config.network);
    wallet_manager.create_wallet_from_mnemonic(
        mnemonic_phrase.as_str(),
        "",
        0,
        key_wallet::wallet::initialization::WalletAccountCreationOptions::default(),
    )?;
    let wallet = Arc::new(tokio::sync::RwLock::new(wallet_manager));

    // Create network manager
    let network_manager = match dash_spv::network::manager::PeerNetworkManager::new(&config).await {
        Ok(nm) => nm,
        Err(e) => {
            eprintln!("Failed to create network manager: {}", e);
            process::exit(1);
        }
    };

    let storage_manager = match dash_spv::storage::DiskStorageManager::new(&config).await {
        Ok(sm) => sm,
        Err(e) => {
            eprintln!("Failed to create disk storage manager: {}", e);
            process::exit(1);
        }
    };
    run_client(config, network_manager, storage_manager, wallet).await?;

    Ok(())
}

async fn run_client<S: dash_spv::storage::StorageManager>(
    config: ClientConfig,
    network_manager: dash_spv::network::manager::PeerNetworkManager,
    storage_manager: S,
    wallet: Arc<tokio::sync::RwLock<WalletManager<ManagedWalletInfo>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create and start the client
    let mut client =
        match DashSpvClient::<
            WalletManager<ManagedWalletInfo>,
            dash_spv::network::manager::PeerNetworkManager,
            S,
        >::new(config.clone(), network_manager, storage_manager, wallet.clone())
        .await
        {
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

    let (_command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();
    let shutdown_token = CancellationToken::new();

    client.run(command_receiver, shutdown_token).await?;

    Ok(())
}
