use dash_spv::network::NetworkEvent;
use dash_spv::test_utils::{MasternodeTestContext, TestEventHandler};
use dash_spv::{
    client::{ClientConfig, DashSpvClient},
    network::PeerNetworkManager,
    storage::DiskStorageManager,
    sync::{SyncEvent, SyncProgress},
    LevelFilter, LoggingGuard, Network,
};
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use key_wallet::managed_account::managed_account_type::ManagedAccountType;
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::{WalletEvent, WalletId, WalletManager};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::{broadcast, watch, RwLock};
use tokio_util::sync::CancellationToken;

/// Timeout for masternode sync tests (masternode sync takes longer than wallet sync).
pub(super) const SYNC_TIMEOUT: u64 = 60;

pub(super) type TestClient = DashSpvClient<
    WalletManager<ManagedWalletInfo>,
    PeerNetworkManager,
    DiskStorageManager,
    TestEventHandler,
>;

pub(super) struct ClientHandle {
    pub(super) client: TestClient,
    pub(super) run_handle: Option<tokio::task::JoinHandle<dash_spv::error::Result<()>>>,
    pub(super) progress_receiver: watch::Receiver<SyncProgress>,
    pub(super) sync_event_receiver: broadcast::Receiver<SyncEvent>,
    pub(super) wallet_event_receiver: broadcast::Receiver<WalletEvent>,
    pub(super) _network_event_receiver: broadcast::Receiver<NetworkEvent>,
    pub(super) cancel_token: CancellationToken,
    pub(super) engine: Arc<RwLock<MasternodeListEngine>>,
}

impl ClientHandle {
    pub(super) async fn stop(&mut self) {
        tracing::info!("Cancelling client run loop...");
        self.cancel_token.cancel();
        if let Some(handle) = self.run_handle.take() {
            handle.await.expect("Run task panicked").expect("Run task returned error");
        }
    }
}

/// SPV-specific test context wrapping the masternode network infrastructure.
///
/// Storage and blockchain directories are cleaned up on drop.
/// Set `DASHD_TEST_RETAIN_DIR` to a directory path to retain logs and storage for failed tests.
pub(super) struct TestContext {
    pub(super) mn_ctx: MasternodeTestContext,
    pub(super) storage_path: PathBuf,
    _storage_dir: TempDir,
    _log_guard: LoggingGuard,
}

impl TestContext {
    pub(super) async fn new(controller_only: bool) -> Option<Self> {
        let storage_dir = TempDir::new().expect("Failed to create temp directory");
        let log_dir = storage_dir.path().join("logs");
        let _log_guard = dash_spv::init_logging(dash_spv::LoggingConfig {
            level: Some(LevelFilter::DEBUG),
            console: std::env::var("DASHD_TEST_LOG").is_ok(),
            file: Some(dash_spv::LogFileConfig {
                log_dir,
                max_files: 1,
            }),
            thread_local: true,
        })
        .expect("Failed to initialize test logging");

        let mn_ctx = MasternodeTestContext::new(controller_only).await?;
        let storage_path = storage_dir.path().to_path_buf();

        eprintln!(
            "TestContext: addr={}, blocks={}, data={}",
            mn_ctx.controller_addr,
            mn_ctx.expected_height,
            storage_path.display(),
        );

        Some(TestContext {
            mn_ctx,
            storage_path,
            _storage_dir: storage_dir,
            _log_guard,
        })
    }

    pub(super) fn storage_path(&self) -> &Path {
        &self.storage_path
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        dash_spv::test_utils::retain_test_dir(&self.storage_path, "spv");
    }
}

/// Wait for the controller to confirm an IS lock for `txid`. Matches Dash
/// Core's `wait_for_instantlock` pattern from `test_framework.py`: one initial
/// mocktime bump to kick the MN scheduler, then poll `getrawtransaction` on
/// real time only.
///
/// We must NOT advance mocktime inside the poll loop. `CSigSharesManager` runs
/// `SendMessages` and `Cleanup` on a dedicated 100ms real-time thread
/// (`HousekeepingThreadMain` in `llmq/signing_shares.cpp`), but the session
/// timeout inside `Cleanup` reads `GetTime<std::chrono::seconds>()`, which
/// returns mocktime when set. Bumping mocktime in the poll loop expires the
/// `SESSION_NEW_SHARES_TIMEOUT` (60s mocktime) in a few real seconds, long
/// before real-time p2p can propagate enough sigshares between the 4 MNs to
/// reach threshold.
pub(super) fn wait_for_controller_islock(
    mn_ctx: &mut MasternodeTestContext,
    txid: &dashcore::Txid,
    timeout_secs: u64,
) {
    mn_ctx.bump_mocktime(30);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        if let Some(raw) = mn_ctx
            .controller
            .try_rpc_call("getrawtransaction", &[txid.to_string().into(), 1.into()])
        {
            if raw.get("instantlock").and_then(|v| v.as_bool()).unwrap_or(false) {
                return;
            }
        }
        assert!(std::time::Instant::now() < deadline, "Controller never IS-locked txid {}", txid);
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// Create a test client config with masternodes enabled.
pub(super) fn create_mn_test_config(
    storage_path: PathBuf,
    peer_addr: std::net::SocketAddr,
) -> ClientConfig {
    let mut config = ClientConfig::regtest().with_storage_path(storage_path);
    config.peers.clear();
    config.add_peer(peer_addr);
    config
}

fn account_options() -> WalletAccountCreationOptions {
    WalletAccountCreationOptions::SpecificAccounts(
        BTreeSet::from([0]),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        None,
    )
}

/// Create a dummy wallet (masternode sync doesn't need real wallet data).
pub(super) fn create_dummy_wallet() -> Arc<RwLock<WalletManager<ManagedWalletInfo>>> {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet_manager = WalletManager::<ManagedWalletInfo>::new(Network::Regtest);
    wallet_manager
        .create_wallet_from_mnemonic(mnemonic, "", 0, account_options())
        .expect("Failed to create wallet");
    Arc::new(RwLock::new(wallet_manager))
}

/// Create a wallet from the pre-generated controller wallet's mnemonic.
///
/// Using the same mnemonic as the dashd controller wallet means the SPV wallet
/// derives the same addresses, so any `send_to_address` call routed through the
/// controller lands in the SPV wallet as well.
pub(super) fn create_wallet_from_controller(
    mn_ctx: &MasternodeTestContext,
) -> (Arc<RwLock<WalletManager<ManagedWalletInfo>>>, WalletId) {
    let mut wallet_manager = WalletManager::<ManagedWalletInfo>::new(Network::Regtest);
    let wallet_id = wallet_manager
        .create_wallet_from_mnemonic(&mn_ctx.wallet.mnemonic, "", 0, account_options())
        .expect("Failed to create wallet from controller mnemonic");
    (Arc::new(RwLock::new(wallet_manager)), wallet_id)
}

/// Fetch an unused external receive address from the wallet's BIP44 account 0.
pub(super) async fn receive_address(
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &WalletId,
) -> dashcore::Address {
    let wallet_read = wallet.read().await;
    let wallet_info = wallet_read.get_wallet_info(wallet_id).expect("Wallet info not found");
    let account =
        wallet_info.accounts().standard_bip44_accounts.get(&0).expect("BIP44 account 0 not found");
    let ManagedAccountType::Standard {
        external_addresses,
        ..
    } = &account.account_type
    else {
        panic!("Account 0 is not a Standard account type");
    };
    external_addresses
        .unused_addresses()
        .into_iter()
        .next()
        .expect("No unused receive address available")
}

/// Start the SPV client and return handles for monitoring.
pub(super) async fn create_and_start_client(
    config: &ClientConfig,
    wallet: Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
) -> ClientHandle {
    let network_manager =
        PeerNetworkManager::new(config).await.expect("Failed to create network manager");
    let storage_manager =
        DiskStorageManager::new(config).await.expect("Failed to create storage manager");

    let handler = Arc::new(TestEventHandler::new());
    let progress_receiver = handler.subscribe_progress();
    let sync_event_receiver = handler.subscribe_sync_events();
    let wallet_event_receiver = handler.subscribe_wallet_events();
    let _network_event_receiver = handler.subscribe_network_events();

    let client =
        DashSpvClient::new(config.clone(), network_manager, storage_manager, wallet, handler)
            .await
            .expect("Failed to create client");

    let engine =
        client.masternode_list_engine().expect("Engine should be initialized after creation");
    let cancel_token = CancellationToken::new();
    let run_token = cancel_token.clone();
    let run_client = client.clone();

    let run_handle = tokio::task::spawn(async move { run_client.run(run_token).await });

    ClientHandle {
        client,
        run_handle: Some(run_handle),
        progress_receiver,
        sync_event_receiver,
        wallet_event_receiver,
        _network_event_receiver,
        cancel_token,
        engine,
    }
}
