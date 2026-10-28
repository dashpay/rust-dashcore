//! Generate the checkpoints embedded in `dash-spv` from the network.
//!
//! Syncs the block headers of a network from genesis without a wallet, then writes a
//! checkpoint every `--interval` blocks, each validated, to `checkpoints/<network>.json`.
//!
//! ```bash
//! cargo run --release -p dash-spv --bin generate-checkpoints -- -n mainnet -d <dir>
//! cargo run --release -p dash-spv --bin generate-checkpoints -- -n testnet -d <dir>
//! ```
//!
//! Running again with the same `<dir>` resumes the sync from where it stopped.

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use dash_spv::chain::checkpoints::CHECKPOINT_HEADERS;
use dash_spv::chain::Checkpoint;
use dash_spv::network::PeerNetworkManager;
use dash_spv::validation::{BlockHeaderValidator, Validator};
use dash_spv::SyncEvent;
use dash_spv::{
    init_console_logging, ClientConfig, DashSpvClient, EventHandler, LevelFilter, Network,
};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::WalletManager;
use tokio::sync::{Notify, RwLock};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum NetworkArg {
    Mainnet,
    Testnet,
}

impl From<NetworkArg> for Network {
    fn from(arg: NetworkArg) -> Self {
        match arg {
            NetworkArg::Mainnet => Network::Mainnet,
            NetworkArg::Testnet => Network::Testnet,
        }
    }
}

#[derive(Parser, Debug)]
#[command(about = "Generate the checkpoints embedded in dash-spv from the network")]
struct Args {
    /// Network to generate the checkpoints of
    #[arg(short, long, value_enum)]
    network: NetworkArg,

    /// Storage directory for the header sync, kept so a later run resumes from it
    #[arg(short, long, value_name = "PATH")]
    data_dir: PathBuf,

    /// File to write the checkpoints to, `checkpoints/<network>.json` by default
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,

    /// Blocks between two checkpoints
    #[arg(long, default_value = "50000")]
    interval: u32,

    /// Blocks a checkpoint must be below the tip
    #[arg(long, default_value = "1000")]
    min_depth: u32,
}

/// Wakes the generator once the block headers are synced.
struct HeadersSynced(Arc<Notify>);

impl EventHandler for HeadersSynced {
    fn on_sync_event(&self, event: &SyncEvent) {
        if let SyncEvent::BlockHeaderSyncComplete {
            ..
        } = event
        {
            self.0.notify_one();
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let network: Network = args.network.into();
    let _logging_guard = init_console_logging(LevelFilter::INFO)?;

    let mut config = ClientConfig::new(network)
        .with_storage_path(args.data_dir)
        .without_filters()
        .without_masternodes();
    config.enable_mempool_tracking = false;
    // From genesis: checkpoints must not come from the checkpoints they replace.
    config.start_from_height = Some(0);

    let network_manager = PeerNetworkManager::new(&config).await;
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(network)));
    let synced = Arc::new(Notify::new());
    let client = DashSpvClient::new(
        config,
        network_manager,
        wallet,
        vec![Arc::new(HeadersSynced(synced.clone()))],
    )
    .await?;

    client.run().await?;
    synced.notified().await;
    client.stop().await;

    let tip = client.tip_header().await.ok_or("no headers synced")?.height();
    tracing::info!("Headers synced up to {}", tip);

    let mut checkpoints = Vec::new();
    let last = tip.saturating_sub(args.min_depth);

    for height in (args.interval..=last).step_by(args.interval as usize) {
        let mut headers = Vec::with_capacity(CHECKPOINT_HEADERS);
        for h in height + 1 - CHECKPOINT_HEADERS as u32..=height {
            headers.push(client.header_at(h).await?.ok_or(format!("header {h} not stored"))?);
        }

        BlockHeaderValidator::new(network, vec![], height - CHECKPOINT_HEADERS as u32)
            .validate(&headers)
            .map_err(|e| format!("checkpoint {height} is invalid: {e}"))?;

        let checkpoint = Checkpoint::new(height, headers)
            .ok_or(format!("checkpoint {height} does not fit its headers"))?;

        checkpoints.push(serde_json::json!({
            "height": checkpoint.height(),
            "headers": checkpoint.headers().iter().map(|h| h.header()).collect::<Vec<_>>(),
        }));
    }

    let output = args.output.unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("checkpoints")
            .join(format!("{}.json", network))
    });
    std::fs::write(&output, serde_json::to_string_pretty(&checkpoints)? + "\n")?;

    tracing::info!(
        "Wrote {} checkpoints up to {} to {}",
        checkpoints.len(),
        last,
        output.display()
    );

    Ok(())
}
