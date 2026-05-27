//! Command-line interface for the Dash SPV client.

use std::path::PathBuf;
use std::process;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use dash_spv::{ClientConfig, DashSpvClient, LevelFilter, MempoolStrategy, Network};
use dashcore::sml::llmq_type::LlmqDevnetParams;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::WalletManager;

/// Network selection for CLI
#[derive(Clone, Copy, Debug, ValueEnum)]
enum NetworkArg {
    Mainnet,
    Testnet,
    Devnet,
    Regtest,
}

impl From<NetworkArg> for Network {
    fn from(arg: NetworkArg) -> Self {
        match arg {
            NetworkArg::Mainnet => Network::Mainnet,
            NetworkArg::Testnet => Network::Testnet,
            NetworkArg::Devnet => Network::Devnet,
            NetworkArg::Regtest => Network::Regtest,
        }
    }
}

/// Validation mode selection for CLI
#[derive(Clone, Copy, Debug, ValueEnum)]
enum ValidationModeArg {
    None,
    Basic,
    Full,
}

impl From<ValidationModeArg> for dash_spv::ValidationMode {
    fn from(arg: ValidationModeArg) -> Self {
        match arg {
            ValidationModeArg::None => dash_spv::ValidationMode::None,
            ValidationModeArg::Basic => dash_spv::ValidationMode::Basic,
            ValidationModeArg::Full => dash_spv::ValidationMode::Full,
        }
    }
}

/// Log level selection for CLI
#[derive(Clone, Copy, Debug, ValueEnum)]
#[value(rename_all = "lowercase")]
enum LogLevelArg {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevelArg> for LevelFilter {
    fn from(arg: LogLevelArg) -> Self {
        match arg {
            LogLevelArg::Error => LevelFilter::ERROR,
            LogLevelArg::Warn => LevelFilter::WARN,
            LogLevelArg::Info => LevelFilter::INFO,
            LogLevelArg::Debug => LevelFilter::DEBUG,
            LogLevelArg::Trace => LevelFilter::TRACE,
        }
    }
}

/// Dash SPV (Simplified Payment Verification) client
#[derive(Parser, Debug)]
#[command(name = "dash-spv", version = dash_spv::VERSION, about)]
struct Args {
    /// Network to connect to
    #[arg(short, long, value_enum, default_value = "mainnet")]
    network: NetworkArg,

    /// Data directory for storage (default: unique directory in /tmp)
    #[arg(short, long)]
    data_dir: Option<PathBuf>,

    /// Peer address to connect to (can be used multiple times)
    #[arg(short, long, value_name = "ADDRESS")]
    peer: Vec<String>,

    /// Log level (CLI overrides RUST_LOG env var)
    #[arg(short, long, value_enum, env = "RUST_LOG", default_value = "info")]
    log_level: LogLevelArg,

    /// Disable BIP157 filter synchronization
    #[arg(long)]
    no_filters: bool,

    /// Disable masternode list synchronization
    #[arg(long)]
    no_masternodes: bool,

    /// Disable mempool transaction tracking
    #[arg(long)]
    no_mempool: bool,

    /// Mempool strategy: fetch-all (higher bandwidth / more privacy) or bloom-filter (efficient / less privacy)
    #[arg(long, value_enum, default_value = "bloom-filter")]
    mempool_strategy: MempoolStrategy,

    /// Validation mode
    #[arg(long, value_enum, default_value = "full")]
    validation_mode: ValidationModeArg,

    /// Start syncing from a specific block height using the nearest checkpoint.
    /// Use 'now' for the latest checkpoint.
    #[arg(short, long, value_name = "HEIGHT")]
    start_height: Option<String>,

    /// Disable log file output (enables console logging as fallback)
    #[arg(long)]
    no_log_file: bool,

    /// Print logs to the console
    #[arg(long)]
    print_to_console: bool,

    /// Directory for log files (default: <data-dir>/logs)
    #[arg(long)]
    log_dir: Option<PathBuf>,

    /// Maximum number of archived log files to keep
    #[arg(long, default_value = "20")]
    max_log_files: usize,

    /// Path to file containing BIP39 mnemonic phrase
    #[arg(long, value_name = "PATH")]
    mnemonic_file: String,

    /// Devnet name (required when --network=devnet). Embedded in user agent so devnet peers accept the connection.
    #[arg(long, value_name = "NAME")]
    devnet_name: Option<String>,

    /// Override `LLMQ_DEVNET` size and threshold (matches Dash Core's `-llmqdevnetparams=<size>:<threshold>`).
    #[arg(long, value_name = "SIZE:THRESHOLD")]
    llmq_devnet_params: Option<String>,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {}", e);

        // Provide specific exit codes for different error types
        let exit_code = if let Some(spv_error) = e.downcast_ref::<dash_spv::SpvError>() {
            match spv_error {
                dash_spv::SpvError::Network(_) => 1,
                dash_spv::SpvError::Storage(_) => 2,
                dash_spv::SpvError::Config(_) => 3,
                _ => 255,
            }
        } else {
            255
        };

        process::exit(exit_code);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let network: Network = args.network.into();
    let validation_mode: dash_spv::ValidationMode = args.validation_mode.into();
    let log_level: LevelFilter = args.log_level.into();

    let mnemonic_phrase = std::fs::read_to_string(&args.mnemonic_file)
        .map_err(|e| format!("Failed to read mnemonic file '{}': {}", args.mnemonic_file, e))?
        .trim()
        .to_string();

    // Create data directory
    let data_dir = args.data_dir.clone().unwrap_or_else(|| {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let pid = std::process::id();
        let dir_name = format!("dash-spv-{}-{}", timestamp, pid);
        std::env::temp_dir().join(dir_name)
    });

    // Configure logging
    let log_dir = args.log_dir.clone().unwrap_or_else(|| data_dir.join("logs"));

    let file_config = if !args.no_log_file {
        Some(dash_spv::LogFileConfig {
            log_dir,
            max_files: args.max_log_files,
        })
    } else {
        None
    };

    let console_enabled = args.no_log_file || args.print_to_console;

    let logging_config = dash_spv::LoggingConfig {
        level: Some(log_level),
        console: console_enabled,
        file: file_config,
        thread_local: false,
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

    if network == Network::Devnet {
        let devnet_name =
            args.devnet_name.as_deref().ok_or("--devnet-name is required when --network=devnet")?;
        let user_agent =
            format!("/rust-dash-spv:{}(devnet.devnet-{})/", dash_spv::VERSION, devnet_name);
        tracing::info!("Devnet user agent: {}", user_agent);
        config = config.with_user_agent(user_agent);

        if let Some(raw) = args.llmq_devnet_params.as_deref() {
            let (size_str, threshold_str) = raw.split_once(':').ok_or_else(|| {
                format!("--llmq-devnet-params expects SIZE:THRESHOLD, got '{}'", raw)
            })?;
            let size: u32 = size_str
                .parse()
                .map_err(|e| format!("invalid LLMQ_DEVNET size '{}': {}", size_str, e))?;
            let threshold: u32 = threshold_str
                .parse()
                .map_err(|e| format!("invalid LLMQ_DEVNET threshold '{}': {}", threshold_str, e))?;
            let params = LlmqDevnetParams {
                size,
                threshold,
            };
            config = config.with_llmq_devnet_params(params);
            tracing::info!(
                "LLMQ_DEVNET params overridden: size={} threshold={}",
                params.size,
                params.threshold
            );
        }
    } else {
        if args.devnet_name.is_some() {
            return Err("--devnet-name is only valid with --network=devnet".into());
        }
        if args.llmq_devnet_params.is_some() {
            return Err("--llmq-devnet-params is only valid with --network=devnet".into());
        }
    }

    // Add custom peers if specified
    if !args.peer.is_empty() {
        config.peers.clear();
        for peer in &args.peer {
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
    if args.no_filters {
        config = config.without_filters();
    }
    if args.no_masternodes {
        config = config.without_masternodes();
    }
    if args.no_mempool {
        config.enable_mempool_tracking = false;
    } else {
        config = config.with_mempool_tracking(args.mempool_strategy);
    }

    // Set start height if specified
    if let Some(ref start_height_str) = args.start_height {
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
    let client =
        match DashSpvClient::<
            WalletManager<ManagedWalletInfo>,
            dash_spv::network::manager::PeerNetworkManager,
            S,
        >::new(
            config.clone(), network_manager, storage_manager, wallet.clone(), Vec::new()
        )
        .await
        {
            Ok(client) => client,
            Err(e) => {
                eprintln!("Failed to create SPV client: {}", e);
                process::exit(1);
            }
        };

    let stop_client = client.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::debug!("Shutdown signal received");
            if let Err(e) = stop_client.stop().await {
                tracing::warn!("Error during ctrl-c stop: {}", e);
            }
        }
    });

    client.run().await?;

    Ok(())
}
