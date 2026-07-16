//! Dash Core node test infrastructure for integration testing.
//!
//! This provides utilities for managing a dashd instance and loading test wallet data.

use dashcore::{Address, Amount, BlockHash, Transaction, Txid};
use dashcore_rpc::json as rpc_json;
use dashcore_rpc::{Auth, Client, RpcApi};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tokio::process::Child;
use tokio::time::{sleep, timeout};

use super::fs_helpers::{clear_stale_runtime_locks, retain_test_dir_now};

/// Default readiness wait for dashd startup.
///
/// Windows CI hosts frequently need longer than Unix runners when several
/// independent dashd processes start in parallel. Override with
/// `DASHD_STARTUP_TIMEOUT_SECS` when diagnosing slow environments.
fn readiness_timeout() -> Duration {
    const DEFAULT_SECS: u64 = if cfg!(windows) {
        90
    } else {
        30
    };
    let secs = match std::env::var("DASHD_STARTUP_TIMEOUT_SECS") {
        Ok(raw) => match raw.parse::<u64>() {
            Ok(secs) if secs > 0 => secs,
            _ => {
                tracing::warn!(
                    "invalid DASHD_STARTUP_TIMEOUT_SECS={raw:?}; using default {DEFAULT_SECS}s"
                );
                DEFAULT_SECS
            }
        },
        Err(_) => DEFAULT_SECS,
    };
    Duration::from_secs(secs)
}

/// Base of the port range used by tests. Sits above the standard Dash regtest
/// ports (19898/19899) and below the Linux ephemeral range (32768+).
const PORT_RANGE_BASE: u16 = 20000;
/// Ports handed out per test process before wrapping into a neighbour's lane.
///
/// Sized for the heaviest target: `dashd_masternode` runs 3 controller-only
/// tests (2 ports each) plus 7 full-network ones (controller + 4 masternodes at
/// 2 ports apiece), so ~76 ports in one process.
const PORT_LANE_WIDTH: u16 = 100;
/// Number of lanes carved out of the range
const PORT_LANE_COUNT: u16 = 120;

const _: () = assert!(
    PORT_RANGE_BASE as u32 + PORT_LANE_WIDTH as u32 * PORT_LANE_COUNT as u32 <= 32768,
    "range must stay below the Linux ephemeral range"
);

const MAX_PORT_ATTEMPTS: usize = 100;

/// Atomic counter for unique port allocation across parallel tests.
/// Seeded lazily from the PID
static NEXT_PORT: AtomicU16 = AtomicU16::new(0);

/// Allocate a unique, available TCP port for test use.
pub(super) fn find_available_port() -> u16 {
    let _ = NEXT_PORT.compare_exchange(
        0,
        PORT_RANGE_BASE + (std::process::id() % PORT_LANE_COUNT as u32) as u16 * PORT_LANE_WIDTH,
        Ordering::Relaxed,
        Ordering::Relaxed,
    );

    for _ in 0..MAX_PORT_ATTEMPTS {
        let raw = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        // Keep the counter inside the range no matter how many are allocated.
        let port = PORT_RANGE_BASE
            + raw.wrapping_sub(PORT_RANGE_BASE) % (PORT_LANE_WIDTH * PORT_LANE_COUNT);
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("failed to find an available port after {} attempts", MAX_PORT_ATTEMPTS);
}

/// Selects which pre-built regtest blockchain to use for integration tests.
#[derive(Debug, Clone, Copy)]
pub enum TestChain {
    /// Full 40,000-block regtest chain (wallet integration tests).
    Full,
    /// Minimal 200-block regtest chain (faster tests).
    Minimal,
}

impl TestChain {
    pub(crate) fn variant_dir(self) -> &'static str {
        match self {
            TestChain::Full => "regtest-40000",
            TestChain::Minimal => "regtest-200",
        }
    }
}

/// Configuration for Dash Core node.
pub struct DashCoreConfig {
    /// Path to dashd binary
    pub dashd_path: PathBuf,
    /// Path to existing datadir with blockchain data
    pub datadir: PathBuf,
    /// Wallet name to load on startup
    pub wallet: String,
    /// P2P port for the node
    pub p2p_port: u16,
    /// RPC port for the node
    pub rpc_port: u16,
    pub extra_args: Vec<String>,
}

impl DashCoreConfig {
    /// Create a config for the given test chain variant under `DASHD_TEST_DATA`.
    ///
    /// `DASHD_TEST_DATA` points to the root directory containing all variants
    /// (e.g. `regtest-40000`, `regtest-200`). Returns `None` if the variant
    /// directory doesn't exist. Panics if env vars are missing.
    pub fn from_env(chain: TestChain) -> Option<Self> {
        let error = "DASHD_PATH and DASHD_TEST_DATA environment variables are required. \
             Either run `eval $(python3 contrib/setup-dashd.py)` to set them up, \
             or set SKIP_DASHD_TESTS=1 to skip these tests. \
             In CI, the setup-dashd step in build-and-test.yml handles this automatically.";
        let dashd_path = std::env::var("DASHD_PATH").ok().map(PathBuf::from).expect(error);

        assert!(
            dashd_path.exists(),
            "DASHD_PATH points to a file that does not exist: {}",
            dashd_path.display()
        );

        let base_datadir = std::env::var("DASHD_TEST_DATA").ok().map(PathBuf::from).expect(error);
        let datadir = base_datadir.join(chain.variant_dir());

        if !datadir.exists() {
            return None;
        }

        Some(Self {
            dashd_path,
            datadir,
            wallet: "default".to_string(),
            p2p_port: find_available_port(),
            rpc_port: find_available_port(),
            extra_args: Vec::new(),
        })
    }

    pub fn with_extra_args(mut self, args: Vec<String>) -> Self {
        self.extra_args.extend(args);
        self
    }
}

/// Test infrastructure for managing a Dash Core node.
pub struct DashCoreNode {
    config: DashCoreConfig,
    process: Option<Child>,
}

impl DashCoreNode {
    /// Create a new Dash Core node with custom configuration
    pub fn with_config(config: DashCoreConfig) -> Self {
        Self {
            config,
            process: None,
        }
    }

    /// Start the Dash Core node
    pub async fn start(&mut self) -> SocketAddr {
        tracing::info!("Starting dashd...");
        tracing::info!("  Binary: {:?}", self.config.dashd_path);
        tracing::info!("  Datadir: {:?}", self.config.datadir);
        tracing::info!("  P2P port: {}", self.config.p2p_port);
        tracing::info!("  RPC port: {}", self.config.rpc_port);

        fs::create_dir_all(&self.config.datadir).expect("failed to create datadir");
        // Fixture snapshots may include lock files from the process that built them.
        clear_stale_runtime_locks(&self.config.datadir);

        let mut args_vec = vec![
            "-regtest".to_string(),
            format!("-datadir={}", self.config.datadir.display()),
            format!("-port={}", self.config.p2p_port),
            format!("-rpcport={}", self.config.rpc_port),
            "-server=1".to_string(),
            "-daemon=0".to_string(),
            "-fallbackfee=0.00001".to_string(),
            "-rpcbind=127.0.0.1".to_string(),
            "-rpcallowip=127.0.0.1".to_string(),
            "-bind=127.0.0.1".to_string(),
            "-listen=1".to_string(),
            "-txindex=0".to_string(),
            "-addressindex=0".to_string(),
            "-spentindex=0".to_string(),
            "-timestampindex=0".to_string(),
            "-blockfilterindex=1".to_string(),
            "-peerblockfilters=1".to_string(),
            "-peerbloomfilters=1".to_string(),
            "-whitelist=127.0.0.1".to_string(),
            "-debug=all".to_string(),
        ];
        if !self.config.wallet.is_empty() {
            args_vec.push(format!("-wallet={}", self.config.wallet));
        }
        args_vec.extend(self.config.extra_args.iter().cloned());

        let mut cmd = tokio::process::Command::new(&self.config.dashd_path);
        cmd.args(&args_vec)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit());

        let child = cmd.spawn().expect("failed to spawn dashd process");

        self.process = Some(child);

        let ready_timeout = readiness_timeout();
        tracing::info!("Waiting for dashd to be ready (timeout {}s)...", ready_timeout.as_secs());
        // Brief yield so a process that dies on spawn is observed immediately.
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Some(status) = self.process_exit_status() {
            self.fail_startup(&format!("dashd exited immediately with status: {status}"));
        }

        if let Err(reason) = self.wait_for_ready(ready_timeout).await {
            self.fail_startup(&reason);
        }

        let addr = SocketAddr::from(([127, 0, 0, 1], self.config.p2p_port));
        tracing::info!("dashd started and ready at {}", addr);

        addr
    }

    fn process_exit_status(&mut self) -> Option<std::process::ExitStatus> {
        let proc = self.process.as_mut()?;
        match proc.try_wait() {
            Ok(status) => status,
            Err(e) => {
                tracing::warn!("failed to poll dashd process status: {e}");
                None
            }
        }
    }

    fn fail_startup(&self, reason: &str) -> ! {
        let debug_log = self.config.datadir.join("regtest/debug.log");
        let tail = read_log_tail(&debug_log, 40);
        // Callers that need post-start retain (e.g. DashdTestContext) install
        // RetainOnPanic only after start() returns, so this is the sole retain
        // path for startup failures.
        retain_test_dir_now(&self.config.datadir, &format!("dashd-{}", self.config.p2p_port));
        panic!(
            "{reason}\n  binary: {}\n  datadir: {}\n  p2p: {}\n  rpc: {}\n  debug.log tail:\n{tail}",
            self.config.dashd_path.display(),
            self.config.datadir.display(),
            self.config.p2p_port,
            self.config.rpc_port,
        );
    }

    async fn wait_for_ready(&mut self, max_wait: Duration) -> Result<(), String> {
        let check_interval = Duration::from_millis(500);
        let mut last_rpc_error = String::from("no RPC attempt yet");
        let mut p2p_ready = false;
        let mut cookie_seen = false;

        let result = timeout(max_wait, async {
            loop {
                if let Some(status) = self.process_exit_status() {
                    return Err(format!("dashd exited during startup with status: {status}"));
                }

                if !p2p_ready {
                    let addr = SocketAddr::from(([127, 0, 0, 1], self.config.p2p_port));
                    if tokio::net::TcpStream::connect(addr).await.is_ok() {
                        p2p_ready = true;
                        tracing::debug!("dashd P2P port accepting connections");
                    } else {
                        sleep(check_interval).await;
                        continue;
                    }
                }

                match self.try_rpc_client_base() {
                    Ok(client) => {
                        cookie_seen = true;
                        match client.get_blockchain_info() {
                            Ok(_) => return Ok(()),
                            Err(e) => {
                                last_rpc_error = format!("getblockchaininfo: {e}");
                                tracing::debug!("RPC not ready yet: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        if self.rpc_cookie_path().exists() {
                            cookie_seen = true;
                        }
                        last_rpc_error = e;
                        tracing::debug!("RPC client not ready yet: {last_rpc_error}");
                    }
                }
                sleep(check_interval).await;
            }
        })
        .await;

        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(format!(
                "dashd failed to become ready within {}s \
                 (p2p_ready={p2p_ready}, cookie_seen={cookie_seen}, last_rpc_error={last_rpc_error})",
                max_wait.as_secs()
            )),
        }
    }

    /// Get block count via RPC.
    pub fn get_block_count(&self) -> u32 {
        let client = self.rpc_client();
        client.get_block_count().expect("failed to get block count")
    }

    /// Get an RPC client targeting the primary wallet.
    fn rpc_client(&self) -> Client {
        self.rpc_client_for_wallet(&self.config.wallet)
    }

    /// Get an RPC client targeting a specific wallet.
    fn rpc_client_for_wallet(&self, wallet_name: &str) -> Client {
        self.rpc_client_at_path(&format!("/wallet/{wallet_name}"))
    }

    /// Base (non-wallet) RPC client for node-global methods.
    fn rpc_client_base(&self) -> Client {
        self.rpc_client_at_path("")
    }

    fn rpc_cookie_path(&self) -> PathBuf {
        self.config.datadir.join("regtest/.cookie")
    }

    fn rpc_client_at_path(&self, path: &str) -> Client {
        let cookie_path = self.rpc_cookie_path();
        assert!(
            cookie_path.exists(),
            "RPC cookie file not found at {}. Is dashd running with this datadir?",
            cookie_path.display()
        );
        let url = format!("http://127.0.0.1:{}{path}", self.config.rpc_port);
        Client::new(&url, Auth::CookieFile(cookie_path)).expect("failed to create rpc client")
    }

    /// Soft base RPC client for readiness probes and best-effort RPCs.
    ///
    /// Returns a diagnostic string on failure so readiness timeouts can report
    /// whether the cookie was missing or cookie auth itself failed.
    fn try_rpc_client_base(&self) -> Result<Client, String> {
        let cookie_path = self.rpc_cookie_path();
        if !cookie_path.exists() {
            return Err("RPC cookie file not created yet".to_string());
        }
        let url = format!("http://127.0.0.1:{}", self.config.rpc_port);
        Client::new(&url, Auth::CookieFile(cookie_path)).map_err(|e| format!("cookie auth: {e}"))
    }

    /// Ensure a wallet is loaded, creating it only when Core reports it is missing
    /// and no on-disk database already exists.
    ///
    /// The regtest fixtures ship both a `wallet` and a `default` wallet on
    /// disk. Treating every `loadwallet` failure as permission to call
    /// `createwallet` races with those existing databases and panics with
    /// "Database already exists" (especially under parallel Windows CI).
    ///
    /// Prefer [`Self::load_wallet`] when the wallet is known to ship in the
    /// fixture (e.g. the mining `default` wallet).
    pub fn ensure_wallet(&self, wallet_name: &str) {
        // Wallet management RPCs are node-global; use the base endpoint so we
        // are not coupled to whichever wallet was started with `-wallet=`.
        let client = self.rpc_client_base();
        match client.load_wallet(wallet_name) {
            Ok(_) => {
                tracing::info!("Loaded wallet: {wallet_name}");
                return;
            }
            Err(e) if wallet_already_loaded(&e) => {
                tracing::info!("Wallet already loaded: {wallet_name}");
                return;
            }
            Err(e) if wallet_does_not_exist(&e) => {
                if wallet_database_exists(self.config.datadir.as_path(), wallet_name) {
                    panic!(
                        "loadwallet reported wallet '{wallet_name}' missing, but a \
                         database path already exists under the datadir: {e}"
                    );
                }
                tracing::info!("Wallet {wallet_name} not found; creating");
            }
            Err(e) => {
                // Prefer loading an on-disk wallet over creating a new one when
                // the error is ambiguous but the database path already exists.
                if wallet_database_exists(self.config.datadir.as_path(), wallet_name) {
                    panic!(
                        "failed to load existing wallet '{wallet_name}' \
                         (database present under datadir): {e}"
                    );
                }
                panic!("failed to load wallet '{wallet_name}': {e}");
            }
        }

        match client.create_wallet(wallet_name, None, None, None, None) {
            Ok(_) => tracing::info!("Created wallet: {wallet_name}"),
            Err(e) if wallet_already_loaded(&e) => {
                tracing::info!("Wallet already loaded during create: {wallet_name}");
            }
            Err(e) if wallet_already_exists(&e) => {
                // Database appeared between load and create. Load it rather
                // than treating the create error as success by name alone.
                match client.load_wallet(wallet_name) {
                    Ok(_) => tracing::info!("Loaded wallet after create race: {wallet_name}"),
                    Err(load_err) if wallet_already_loaded(&load_err) => {
                        tracing::info!("Wallet already loaded after create race: {wallet_name}");
                    }
                    Err(load_err) => panic!(
                        "failed to create wallet '{wallet_name}': {e}; \
                         subsequent load also failed: {load_err}"
                    ),
                }
            }
            Err(e) => panic!("failed to create wallet '{wallet_name}': {e}"),
        }
    }

    /// Load a wallet that is expected to already exist (fixture or prior create).
    ///
    /// Unlike [`Self::ensure_wallet`], this never calls `createwallet`, so a
    /// shipped fixture wallet cannot race into "Database already exists".
    pub fn load_wallet(&self, wallet_name: &str) {
        let client = self.rpc_client_base();
        match client.load_wallet(wallet_name) {
            Ok(_) => tracing::info!("Loaded wallet: {wallet_name}"),
            Err(e) if wallet_already_loaded(&e) => {
                tracing::info!("Wallet already loaded: {wallet_name}");
            }
            Err(e) => panic!("failed to load expected wallet '{wallet_name}': {e}"),
        }
    }

    pub fn get_new_address(&self) -> Address {
        self.get_new_address_from_wallet(&self.config.wallet)
    }

    /// Get a new address from a specific dashd wallet.
    pub fn get_new_address_from_wallet(&self, wallet_name: &str) -> Address {
        let client = self.rpc_client_for_wallet(wallet_name);
        let address = client.get_new_address(None).expect("failed to get new address");
        address.assume_checked()
    }

    /// Check if the connected dashd supports `generatetoaddress` (RPC miner).
    ///
    /// Some builds (e.g. Windows release binaries) ship without the RPC miner compiled in.
    pub fn supports_mining(&self) -> bool {
        let client = self.rpc_client();
        let addr = Address::dummy(dashcore::Network::Regtest, 0);
        match client.generate_to_address(0, &addr) {
            Ok(_) => true,
            Err(dashcore_rpc::Error::JsonRpc(dashcore_rpc::jsonrpc::Error::Rpc(ref e)))
                if e.message.contains("not available") =>
            {
                false
            }
            // Any other error (auth, network) still counts as "available" —
            // a real generate call will surface the actual error.
            Err(_) => true,
        }
    }

    /// Generate blocks to the given address.
    pub fn generate_blocks(&self, count: u64, address: &Address) -> Vec<BlockHash> {
        let client = self.rpc_client();
        let hashes = client.generate_to_address(count, address).expect("failed to generate blocks");
        tracing::info!("Generated {} blocks to {}", count, address);
        hashes
    }

    /// Send DASH to an address from the primary wallet.
    pub fn send_to_address(&self, address: &Address, amount: Amount) -> Txid {
        self.send_to_address_from_wallet(&self.config.wallet, address, amount)
    }

    /// Send DASH to many addresses in a single transaction from the primary
    /// wallet, so one transaction carries one output per `(address, amount)`
    /// pair.
    pub fn send_many(&self, payments: &[(Address, Amount)]) -> Txid {
        let client = self.rpc_client();
        let amounts: Map<String, Value> = payments
            .iter()
            .map(|(address, amount)| (address.to_string(), serde_json::json!(amount.to_dash())))
            .collect();
        let txid: Txid = client
            .call("sendmany", &[serde_json::json!(""), Value::Object(amounts)])
            .expect("failed to sendmany");
        tracing::info!("Sent {} outputs in one transaction, txid: {}", payments.len(), txid);
        txid
    }

    /// Send DASH to an address from a specific wallet.
    pub fn send_to_address_from_wallet(
        &self,
        wallet_name: &str,
        address: &Address,
        amount: Amount,
    ) -> Txid {
        let client = self.rpc_client_for_wallet(wallet_name);
        let txid = client
            .send_to_address(address, amount, None, None, None, None, None, None, None, None)
            .expect("failed to send to address");
        tracing::info!("Sent {} to {} (wallet: {}), txid: {}", amount, address, wallet_name, txid);
        txid
    }

    /// List unspent outputs for a specific wallet.
    pub fn list_unspent_from_wallet(
        &self,
        wallet_name: &str,
    ) -> Vec<rpc_json::ListUnspentResultEntry> {
        let client = self.rpc_client_for_wallet(wallet_name);
        client.list_unspent(None, None, None, None, None).expect("failed to list unspent")
    }

    /// Create, sign, and broadcast a raw transaction spending a single UTXO.
    /// Sends the input amount minus fee to the destination address.
    pub fn send_raw_from_wallet(
        &self,
        wallet_name: &str,
        input_txid: Txid,
        input_vout: u32,
        input_amount: Amount,
        destination: &Address,
        fee: Amount,
    ) -> Txid {
        let tx = self.create_signed_transaction(
            wallet_name,
            input_txid,
            input_vout,
            input_amount,
            destination,
            fee,
        );
        let txid = self
            .rpc_client_for_wallet(wallet_name)
            .send_raw_transaction(&tx)
            .expect("failed to send raw tx");
        tracing::info!(
            "Sent raw tx from wallet '{wallet_name}': {input_amount} -> {destination}, txid: {txid}"
        );
        txid
    }

    /// Create and sign a raw transaction without broadcasting it.
    ///
    /// Returns the signed transaction for use with `broadcast_transaction()`.
    pub fn create_signed_transaction(
        &self,
        wallet_name: &str,
        input_txid: Txid,
        input_vout: u32,
        input_amount: Amount,
        destination: &Address,
        fee: Amount,
    ) -> Transaction {
        let client = self.rpc_client_for_wallet(wallet_name);

        let inputs = vec![rpc_json::CreateRawTransactionInput {
            txid: input_txid,
            vout: input_vout,
            sequence: None,
        }];
        let send_amount = input_amount.checked_sub(fee).expect("fee exceeds input amount");
        let mut outputs = HashMap::new();
        outputs.insert(destination.to_string(), send_amount);

        let raw_tx: Transaction = client
            .create_raw_transaction(&inputs, &outputs, None)
            .expect("failed to create raw tx");

        let signed = client
            .sign_raw_transaction_with_wallet(&raw_tx, None, None)
            .expect("failed to sign raw tx");
        assert!(signed.complete, "raw transaction signing incomplete");

        signed.transaction().expect("invalid signed tx")
    }

    /// Connect this dashd node to another dashd node via P2P and wait for the
    /// connection to be established.
    pub async fn connect_to_node(&self, addr: SocketAddr) {
        let client = self.rpc_client();
        client.onetry_node(&addr.to_string()).expect("failed to connect to node");

        for _ in 0..30 {
            let peers = client.get_peer_info().expect("failed to get peer info");
            if peers.iter().any(|p| p.addr.to_string().starts_with(&addr.ip().to_string())) {
                tracing::info!("Connected to node {}", addr);
                return;
            }
            sleep(Duration::from_millis(500)).await;
        }
        panic!("Timed out waiting for connection to {}", addr);
    }

    /// Disconnect a specific peer by address.
    pub fn disconnect_peer(&self, addr: SocketAddr) {
        let client = self.rpc_client();
        client.disconnect_node(&addr.to_string()).expect("failed to disconnect peer");
        tracing::info!("Disconnected peer {}", addr);
    }

    /// Enable or disable all P2P network activity on this node.
    pub fn set_network_active(&self, active: bool) {
        let client = self.rpc_client();
        client.set_network_active(active).expect("failed to set network active");
        tracing::info!("Set network active={} on dashd", active);
    }

    /// Set mock time on this node.
    pub fn set_mocktime(&self, time: u64) {
        let client = self.rpc_client();
        let _: Value = client.call("setmocktime", &[time.into()]).expect("setmocktime failed");
    }

    pub fn get_best_block_hash(&self) -> BlockHash {
        let client = self.rpc_client();
        client.get_best_block_hash().expect("getbestblockhash failed")
    }

    /// Call getblocktemplate to trigger CreateNewBlock (includes quorum commitments).
    pub fn get_block_template(&self) {
        let client = self.rpc_client();
        let _: Result<Value, _> = client.call("getblocktemplate", &[]);
    }

    /// Disconnect all currently connected peers.
    pub fn disconnect_all_peers(&self) {
        let client = self.rpc_client();
        let peers = client.get_peer_info().expect("failed to get peer info");
        for peer in &peers {
            let addr = peer.addr.to_string();
            let _ = client.disconnect_node(&addr);
            tracing::info!("Disconnected peer {}", addr);
        }
        tracing::info!("Disconnected {} peers", peers.len());
    }

    /// Execute an RPC call, returning None on failure instead of panicking.
    ///
    /// Uses the base URL (no wallet path) which works for all non-wallet RPCs.
    /// Useful during DKG orchestration where transient failures are expected.
    pub fn try_rpc_call(&self, method: &str, params: &[serde_json::Value]) -> Option<Value> {
        self.try_rpc_client_base().ok()?.call(method, params).ok()
    }

    pub fn datadir(&self) -> &Path {
        &self.config.datadir
    }

    pub fn p2p_port(&self) -> u16 {
        self.config.p2p_port
    }

    pub fn rpc_port(&self) -> u16 {
        self.config.rpc_port
    }
}

impl Drop for DashCoreNode {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            tracing::info!("Stopping dashd process in Drop...");
            if let Err(e) = process.start_kill() {
                tracing::warn!("Failed to kill dashd process: {}", e);
            }
        }
    }
}

/// Wallet file structure for test wallets.
#[derive(Debug, Deserialize)]
pub struct WalletFile {
    /// Wallet name, e.g. "default"
    pub wallet_name: String,
    /// Wallet mnemonic, in BIP39 format
    pub mnemonic: String,
    /// Wallet balance, in duffs
    pub balance: f64,
    /// Number of transactions in the wallet
    pub transaction_count: usize,
    /// Number of UTXOs in the wallet
    pub utxo_count: usize,
    /// List of transaction hashes in the wallet
    pub transactions: Vec<serde_json::Value>,
    /// List of UTXOs in the wallet, including their addresses and amounts
    pub utxos: Vec<serde_json::Value>,
}

impl WalletFile {
    /// Load a wallet file from the wallets directory in a datadir
    pub fn from_json(datadir: &Path, wallet_name: &str) -> Self {
        let wallet_path = datadir.join("wallets").join(format!("{}.json", wallet_name));
        if !wallet_path.exists() {
            panic!("Wallet file not found: {:?}", wallet_path);
        }

        let contents = fs::read_to_string(&wallet_path).expect("Failed to read wallet file");
        serde_json::from_str(&contents).expect("Failed to deserialize wallet file")
    }
}

/// RPC error code used by Bitcoin/Dash Core when a wallet file is missing.
const RPC_WALLET_NOT_FOUND: i32 = -18;
/// RPC error code used when a wallet is already loaded.
const RPC_WALLET_ALREADY_LOADED: i32 = -35;
/// RPC error code used for generic wallet errors (e.g. database already exists).
const RPC_WALLET_ERROR: i32 = -4;

fn rpc_error_parts(err: &dashcore_rpc::Error) -> Option<(i32, &str)> {
    match err {
        dashcore_rpc::Error::JsonRpc(dashcore_rpc::jsonrpc::Error::Rpc(rpc)) => {
            Some((rpc.code, rpc.message.as_str()))
        }
        _ => None,
    }
}

/// True when `loadwallet`/`createwallet` reports the wallet is already loaded.
pub(crate) fn wallet_already_loaded(err: &dashcore_rpc::Error) -> bool {
    match rpc_error_parts(err) {
        Some((RPC_WALLET_ALREADY_LOADED, _)) => true,
        Some((_, msg)) => {
            let lower = msg.to_ascii_lowercase();
            lower.contains("already loaded")
        }
        None => false,
    }
}

/// True when `loadwallet` reports the wallet file does not exist.
pub(crate) fn wallet_does_not_exist(err: &dashcore_rpc::Error) -> bool {
    match rpc_error_parts(err) {
        Some((code, msg)) => {
            let lower = msg.to_ascii_lowercase();
            // Require a wallet-related phrase so unrelated "not found" / code
            // -18 responses never authorize createwallet.
            let walletish = lower.contains("wallet");
            let missing = lower.contains("not found") || lower.contains("does not exist");
            walletish && missing && (code == RPC_WALLET_NOT_FOUND || code != 0)
        }
        None => false,
    }
}

/// True when `createwallet` reports the wallet database already exists.
pub(crate) fn wallet_already_exists(err: &dashcore_rpc::Error) -> bool {
    match rpc_error_parts(err) {
        Some((code, msg)) => {
            let lower = msg.to_ascii_lowercase();
            // Bitcoin/Dash Core uses -4 (RPC_WALLET_ERROR) for this; match the
            // message so minor code drift does not reintroduce create-on-exists.
            let message_match = lower.contains("database already exists")
                || (lower.contains("already exists")
                    && (lower.contains("wallet") || lower.contains("database")));
            message_match || (code == RPC_WALLET_ERROR && lower.contains("already exists"))
        }
        None => false,
    }
}

/// Whether a wallet database directory already exists under the datadir.
pub(crate) fn wallet_database_exists(datadir: &Path, wallet_name: &str) -> bool {
    let regtest = datadir.join("regtest");
    let candidates = [
        regtest.join(wallet_name).join("wallet.dat"),
        regtest.join("wallets").join(wallet_name).join("wallet.dat"),
        regtest.join(wallet_name),
        regtest.join("wallets").join(wallet_name),
    ];
    candidates.iter().any(|p| p.exists())
}

fn read_log_tail(path: &Path, max_lines: usize) -> String {
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return format!("  <unavailable: {} ({})>", path.display(), e),
    };
    let mut contents = String::new();
    if let Err(e) = file.read_to_string(&mut contents) {
        return format!("  <failed to read {}: {}>", path.display(), e);
    }
    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    if lines.is_empty() {
        return "  <empty>".to_string();
    }
    lines[start..].iter().map(|l| format!("  {l}")).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore_rpc::jsonrpc::error::RpcError;
    use dashcore_rpc::Error as RpcErrorEnum;
    use std::io::Write;
    use tempfile::TempDir;

    fn rpc_err(code: i32, message: &str) -> RpcErrorEnum {
        RpcErrorEnum::JsonRpc(dashcore_rpc::jsonrpc::Error::Rpc(RpcError {
            code,
            message: message.to_string(),
            data: None,
        }))
    }

    #[test]
    fn classifies_wallet_not_found() {
        let err = rpc_err(RPC_WALLET_NOT_FOUND, "Wallet file not found.");
        assert!(wallet_does_not_exist(&err));
        assert!(!wallet_already_loaded(&err));
        assert!(!wallet_already_exists(&err));

        // Unrelated "not found" must not authorize createwallet.
        let method = rpc_err(-32601, "Method not found");
        assert!(!wallet_does_not_exist(&method));
    }

    #[test]
    fn classifies_wallet_already_loaded() {
        let err = rpc_err(RPC_WALLET_ALREADY_LOADED, "Wallet already loaded.");
        assert!(wallet_already_loaded(&err));
        assert!(!wallet_does_not_exist(&err));
    }

    #[test]
    fn classifies_database_already_exists() {
        // Exact message observed on Windows CI for issue #903.
        let err = rpc_err(
            RPC_WALLET_ERROR,
            "Wallet file verification failed. Failed to create database path \
             'C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\.tmpwqBeK5\\regtest\\default'. \
             Database already exists.",
        );
        assert!(wallet_already_exists(&err));
        // The old ensure_wallet treated this as create-permission; it must not
        // be classified as a missing wallet.
        assert!(!wallet_does_not_exist(&err));
    }

    #[test]
    fn wallet_database_exists_detects_fixture_layout() {
        let tmp = TempDir::new().unwrap();
        let wallet_dir = tmp.path().join("regtest").join("default");
        fs::create_dir_all(&wallet_dir).unwrap();
        fs::write(wallet_dir.join("wallet.dat"), b"dummy").unwrap();
        assert!(wallet_database_exists(tmp.path(), "default"));
        assert!(!wallet_database_exists(tmp.path(), "missing"));
    }

    #[test]
    fn clear_stale_runtime_locks_removes_fixture_locks() {
        let tmp = TempDir::new().unwrap();
        let regtest = tmp.path().join("regtest");
        let wallet = regtest.join("default");
        fs::create_dir_all(&wallet).unwrap();
        fs::write(regtest.join(".lock"), b"").unwrap();
        fs::write(regtest.join(".walletlock"), b"").unwrap();
        fs::write(wallet.join(".walletlock"), b"").unwrap();

        clear_stale_runtime_locks(tmp.path());

        assert!(!regtest.join(".lock").exists());
        assert!(!regtest.join(".walletlock").exists());
        assert!(!wallet.join(".walletlock").exists());
    }

    #[test]
    fn read_log_tail_returns_last_lines() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("debug.log");
        let mut f = fs::File::create(&path).unwrap();
        for i in 0..10 {
            writeln!(f, "line{i}").unwrap();
        }
        let tail = read_log_tail(&path, 3);
        assert!(tail.contains("line7"));
        assert!(tail.contains("line9"));
        assert!(!tail.contains("line0"));
    }
}
