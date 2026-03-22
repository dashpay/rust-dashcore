use dash_spv::network::NetworkEvent;
use dash_spv::storage::{PeerStorage, PersistentPeerStorage, PersistentStorage};
use dash_spv::test_utils::{retain_test_dir, DashdTestContext, TestChain, TestEventHandler};
use dash_spv::{
    client::{ClientConfig, DashSpvClient},
    network::PeerNetworkManager,
    storage::DiskStorageManager,
    sync::{ProgressPercentage, SyncEvent, SyncProgress},
    LevelFilter, LoggingGuard, Network,
};
use dashcore::network::address::AddrV2Message;
use dashcore::network::constants::ServiceFlags;
use key_wallet::managed_account::managed_account_type::ManagedAccountType;
use key_wallet::manager::{WalletId, WalletManager};
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::{broadcast, watch, RwLock};
use tokio_util::sync::CancellationToken;

/// SPV-specific test context wrapping the shared dashd infrastructure.
///
/// Storage and blockchain directories are cleaned up on drop.
/// Set `DASHD_TEST_RETAIN_DIR` to a directory path to retain logs and storage for failed tests.
pub(super) struct TestContext {
    /// Shared dashd test context.
    pub(super) dashd: DashdTestContext,
    /// Temporary directory containing the blockchain data.
    pub(super) storage_dir: TempDir,
    /// Test client configuration.
    pub(super) client_config: ClientConfig,
    /// Shared wallet manager.
    pub(super) wallet: Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    /// ID of the test wallet.
    pub(super) wallet_id: WalletId,
    /// Logging guard to ensure test logging is cleaned up on drop.
    _log_guard: LoggingGuard,
}

impl TestContext {
    /// Creates a new `TestContext` instance if the setup is successful.
    ///
    /// # Returns
    /// This function returns an `Option<TestContext>`:
    /// - `Some(TestContext)` if all initialization steps succeed.
    /// - `None` if any part of the initialization fails, such as creating the `DashdTestContext`.
    ///
    /// # Example
    /// ```rust
    /// if let Some(context) = TestContext::new(TestChain::Full).await {
    ///     // Proceed with using the `context` for testing.
    /// } else {
    ///     eprintln!("Failed to create the test context");
    /// }
    /// ```
    pub(super) async fn new(chain: TestChain) -> Option<Self> {
        let dashd = DashdTestContext::new(chain).await?;
        Some(Self::create(dashd))
    }

    fn create(dashd: DashdTestContext) -> Self {
        let storage_dir = TempDir::new().expect("Failed to create temporary directory");
        let log_dir = storage_dir.path().join("logs");
        let _log_guard = dash_spv::init_logging(dash_spv::LoggingConfig {
            level: Some(LevelFilter::DEBUG),
            console: std::env::var("DASHD_TEST_LOG").is_ok(),
            file: Some(dash_spv::LogFileConfig {
                log_dir: log_dir.clone(),
                max_files: 1,
            }),
            thread_local: true,
        })
        .expect("Failed to initialize test logging");

        let client_config = create_test_config(storage_dir.path().to_path_buf(), dashd.addr);

        let (wallet, wallet_id) = create_test_wallet(&dashd.wallet.mnemonic, Network::Regtest);

        eprintln!(
            "TestContext: addr={}, blocks={}, data={}",
            dashd.addr,
            dashd.initial_height,
            storage_dir.path().display(),
        );

        TestContext {
            dashd,
            storage_dir,
            client_config,
            wallet,
            wallet_id,
            _log_guard,
        }
    }
    /// Spawns and initializes a new client instance asynchronously.
    pub(super) async fn spawn_new_client(&self) -> ClientHandle {
        create_and_start_client(&self.client_config, Arc::clone(&self.wallet)).await
    }
    /// Retrieves the total count of transactions across all accounts in the wallet.
    pub(super) async fn transaction_count(&self) -> usize {
        let wallet_read = self.wallet.read().await;
        let wallet_info =
            wallet_read.get_wallet_info(&self.wallet_id).expect("Wallet info not found");
        wallet_info.accounts().all_accounts().iter().map(|a| a.transactions.len()).sum()
    }
    /// Retrieves the spendable balance of the wallet.
    pub(super) async fn spendable_balance(&self) -> u64 {
        let wallet_read = self.wallet.read().await;
        wallet_read
            .get_wallet_balance(&self.wallet_id)
            .expect("Failed to get wallet balance")
            .spendable()
    }
    /// Retrieves an unused receiving address from the wallet.
    pub(super) async fn receive_address(&self) -> dashcore::Address {
        let wallet_read = self.wallet.read().await;
        let wallet_info =
            wallet_read.get_wallet_info(&self.wallet_id).expect("Wallet info not found");

        let account = wallet_info
            .accounts()
            .standard_bip44_accounts
            .get(&0)
            .expect("BIP44 account 0 not found");

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
    /// Checks if a transaction with the specified transaction ID (`txid`) exists in the wallet.
    pub(super) async fn has_transaction(&self, txid: &dashcore::Txid) -> bool {
        let wallet_read = self.wallet.read().await;
        let wallet_info =
            wallet_read.get_wallet_info(&self.wallet_id).expect("Wallet info not found");

        wallet_info
            .accounts()
            .all_accounts()
            .iter()
            .any(|account| account.transactions.contains_key(txid))
            || wallet_info.immature_transactions().iter().any(|tx| &tx.txid() == txid)
    }

    /// Validate that the context wallet matches the expected baseline from dashd.
    pub(super) async fn assert_synced(&self, progress: &SyncProgress) {
        self.assert_wallet_synced(progress, &self.wallet, &self.wallet_id).await;
    }

    /// Validate that an arbitrary wallet matches the expected baseline from dashd.
    pub(super) async fn assert_wallet_synced(
        &self,
        progress: &SyncProgress,
        wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
        wallet_id: &WalletId,
    ) {
        let header_height = progress.headers().unwrap().current_height();
        let filter_header_height = progress.filter_headers().unwrap().current_height();
        assert_eq!(header_height, self.dashd.initial_height, "Header height mismatch");
        assert_eq!(
            filter_header_height, self.dashd.initial_height,
            "Filter header height mismatch"
        );

        let wallet_read = wallet.read().await;
        let wallet_info = wallet_read.get_wallet_info(wallet_id).expect("Wallet info not found");

        let mut spv_txids = HashSet::new();
        for managed_account in wallet_info.accounts().all_accounts() {
            for txid in managed_account.transactions.keys() {
                spv_txids.insert(txid.to_string());
            }
        }
        for tx in wallet_info.immature_transactions() {
            spv_txids.insert(tx.txid().to_string());
        }

        let expected_txids: HashSet<String> = self
            .dashd
            .wallet
            .transactions
            .iter()
            .filter_map(|tx| tx.get("txid").and_then(|v| v.as_str()).map(String::from))
            .collect();

        let missing: Vec<_> = expected_txids.difference(&spv_txids).collect();
        let extra: Vec<_> = spv_txids.difference(&expected_txids).collect();

        assert!(
            missing.is_empty(),
            "SPV wallet is missing {} transactions: {:?}",
            missing.len(),
            missing
        );
        assert!(
            extra.is_empty(),
            "SPV wallet has {} unexpected transactions: {:?}",
            extra.len(),
            extra
        );

        drop(wallet_read);
        let balance = {
            let wr = wallet.read().await;
            wr.get_wallet_balance(wallet_id).expect("Failed to get wallet balance").spendable()
        };
        let expected_balance: u64 = self
            .dashd
            .wallet
            .utxos
            .iter()
            .filter_map(|u| u.get("amount").and_then(|v| v.as_f64()))
            .map(|dash| (dash * 100_000_000.0).round() as u64)
            .sum();

        assert_eq!(balance, expected_balance, "Wallet balance mismatch");
        tracing::info!(
            "Wallet validation passed: {} transactions, balance={}",
            spv_txids.len(),
            balance
        );
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        retain_test_dir(self.storage_dir.path(), "spv");
    }
}

/// Type alias for the SPV client used in tests.
pub(super) type TestClient = DashSpvClient<
    WalletManager<ManagedWalletInfo>,
    PeerNetworkManager,
    DiskStorageManager,
    TestEventHandler,
>;

/// A `ClientHandle` is a utility structure that manages the state and handles for a `TestClient`
/// required to interact with the synchronization process, various event channels, and cancellation capabilities.
pub(super) struct ClientHandle {
    /// The underlying SPV client instance.
    pub(super) client: TestClient,
    /// The handle to the client's run loop task.
    pub(super) run_handle: Option<tokio::task::JoinHandle<dash_spv::error::Result<()>>>,
    /// A channel for receiving progress updates.
    pub(super) progress_receiver: watch::Receiver<SyncProgress>,
    /// A channel for receiving sync events.
    pub(super) sync_event_receiver: broadcast::Receiver<SyncEvent>,
    /// A channel for receiving network events.
    pub(super) network_event_receiver: broadcast::Receiver<NetworkEvent>,
    /// A cancellation token for the client's run loop.
    pub(super) cancel_token: CancellationToken,
}

impl ClientHandle {
    /// Stops the execution of the client run loop by canceling its associated token and awaiting the
    /// termination of the background task.
    pub(super) async fn stop(&mut self) {
        tracing::info!("Cancelling client run loop...");
        self.cancel_token.cancel();
        if let Some(handle) = self.run_handle.take() {
            handle.await.expect("Run task panicked").expect("Run task returned error");
        }
    }
}

/// Creates a new SPV client and starts it with a `TestEventHandler`.
///
/// The handler bridges events back to channels so tests can use `tokio::select!`
/// patterns while going through the `EventHandler` trait.
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
    let network_event_receiver = handler.subscribe_network_events();

    let client =
        DashSpvClient::new(config.clone(), network_manager, storage_manager, wallet, handler)
            .await
            .expect("Failed to create client");

    let cancel_token = CancellationToken::new();
    let run_token = cancel_token.clone();
    let run_client = client.clone();

    let run_handle = tokio::task::spawn(async move { run_client.run(run_token).await });

    ClientHandle {
        client,
        run_handle: Some(run_handle),
        progress_receiver,
        sync_event_receiver,
        network_event_receiver,
        cancel_token,
    }
}

/// Account creation options for tests: just a standard BIP44 account 0.
pub(super) fn test_account_options() -> WalletAccountCreationOptions {
    WalletAccountCreationOptions::SpecificAccounts(
        BTreeSet::from([0]),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        None,
    )
}

/// Create a test wallet from mnemonic.
pub(super) fn create_test_wallet(
    mnemonic: &str,
    network: Network,
) -> (Arc<RwLock<WalletManager<ManagedWalletInfo>>>, WalletId) {
    let mut wallet_manager = WalletManager::<ManagedWalletInfo>::new(network);
    let wallet_id = wallet_manager
        .create_wallet_from_mnemonic(mnemonic, "", 0, test_account_options())
        .expect("Failed to create wallet from mnemonic");
    (Arc::new(RwLock::new(wallet_manager)), wallet_id)
}

/// Create test client config pointing to a specific peer (exclusive mode).
fn create_test_config(storage_path: PathBuf, peer_addr: std::net::SocketAddr) -> ClientConfig {
    let mut config = ClientConfig::regtest().with_storage_path(storage_path).without_masternodes();
    config.peers.clear();
    config.add_peer(peer_addr);
    config
}

/// Create test client config with no explicit peers (non-exclusive mode).
///
/// The peer address is seeded into the peer store on disk so the client
/// discovers it through the normal peer discovery path.
pub(super) async fn create_non_exclusive_test_config(
    storage_path: PathBuf,
    peer_addr: std::net::SocketAddr,
) -> ClientConfig {
    let mut config = ClientConfig::regtest().with_storage_path(storage_path).without_masternodes();
    // Clear default regtest peers so the manager enters non-exclusive mode
    config.peers.clear();
    // Seed the peer store so the client can discover our dashd node
    let peer_store = PersistentPeerStorage::open(config.storage_path.clone())
        .await
        .expect("Failed to open peer storage");
    let msg = AddrV2Message::new(peer_addr, ServiceFlags::NETWORK);
    peer_store.save_peers(&[msg]).await.expect("Failed to seed peer store");
    config
}
