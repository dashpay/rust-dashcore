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
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tokio::process::Child;
use tokio::time::{sleep, timeout};

/// Atomic counter for unique port allocation across parallel tests.
/// Starts below the standard Dash regtest ports (19898/19899) to avoid conflicts.
static NEXT_PORT: AtomicU16 = AtomicU16::new(19400);

const MAX_PORT_ATTEMPTS: usize = 100;

/// Allocate a unique, available TCP port for test use.
pub(super) fn find_available_port() -> u16 {
    for _ in 0..MAX_PORT_ATTEMPTS {
        let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        assert!(port >= 1024, "port counter overflowed");
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

        tracing::info!("Waiting for dashd to be ready...");
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Some(ref mut proc) = self.process {
            if let Ok(Some(status)) = proc.try_wait() {
                panic!("dashd exited immediately with status: {}", status);
            }
        }

        let ready = self.wait_for_ready().await;
        if !ready {
            if let Some(ref mut proc) = self.process {
                if let Ok(Some(status)) = proc.try_wait() {
                    panic!("dashd exited with status: {}", status);
                }
            }
            panic!("dashd failed to start within timeout");
        }

        let addr = SocketAddr::from(([127, 0, 0, 1], self.config.p2p_port));
        tracing::info!("dashd started and ready at {}", addr);

        addr
    }

    async fn wait_for_ready(&self) -> bool {
        let max_wait = Duration::from_secs(30);
        let check_interval = Duration::from_millis(500);

        let result = timeout(max_wait, async {
            // Wait for the P2P port to accept connections
            loop {
                let addr = SocketAddr::from(([127, 0, 0, 1], self.config.p2p_port));
                if tokio::net::TcpStream::connect(addr).await.is_ok() {
                    break;
                }
                sleep(check_interval).await;
            }

            // Wait for RPC to be fully responsive (not just "warming up")
            loop {
                let url = format!("http://127.0.0.1:{}", self.config.rpc_port);
                let cookie_path = self.config.datadir.join("regtest/.cookie");
                if cookie_path.exists() {
                    if let Ok(client) = Client::new(&url, Auth::CookieFile(cookie_path)) {
                        match client.get_blockchain_info() {
                            Ok(_) => return true,
                            Err(e) => {
                                tracing::debug!("RPC not ready yet: {}", e);
                            }
                        }
                    }
                }
                sleep(check_interval).await;
            }
        })
        .await;

        result.unwrap_or(false)
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
        let url = format!("http://127.0.0.1:{}/wallet/{}", self.config.rpc_port, wallet_name);
        let cookie_path = self.config.datadir.join("regtest/.cookie");
        assert!(
            cookie_path.exists(),
            "RPC cookie file not found at {}. Is dashd running with this datadir?",
            cookie_path.display()
        );
        let auth = Auth::CookieFile(cookie_path);
        Client::new(&url, auth).expect("failed to create rpc client")
    }

    /// Load a wallet by name, creating it if it doesn't exist.
    pub fn ensure_wallet(&self, wallet_name: &str) {
        let client = self.rpc_client();
        match client.load_wallet(wallet_name) {
            Ok(_) => tracing::info!("Loaded wallet: {}", wallet_name),
            Err(_) => {
                client
                    .create_wallet(wallet_name, None, None, None, None)
                    .unwrap_or_else(|e| panic!("failed to create wallet '{}': {}", wallet_name, e));
                tracing::info!("Created wallet: {}", wallet_name);
            }
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
        let client = self.rpc_client();
        let txid = client
            .send_to_address(address, amount, None, None, None, None, None, None, None, None)
            .expect("failed to send to address");
        tracing::info!("Sent {} to {}, txid: {}", amount, address, txid);
        txid
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

        let txid = client
            .send_raw_transaction(&signed.transaction().expect("invalid signed tx"))
            .expect("failed to send raw tx");
        tracing::info!(
            "Sent raw tx from wallet '{}': {} -> {}, txid: {}",
            wallet_name,
            input_amount,
            destination,
            txid
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
        let url = format!("http://127.0.0.1:{}", self.config.rpc_port);
        let cookie_path = self.config.datadir.join("regtest/.cookie");
        if !cookie_path.exists() {
            return None;
        }
        let auth = Auth::CookieFile(cookie_path);
        let client = Client::new(&url, auth).ok()?;
        client.call(method, params).ok()
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
