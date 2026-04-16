//! Masternode network test infrastructure.
//!
//! Manages a pre-generated masternode network (1 controller + N masternodes)
//! for integration testing of masternode list sync against real dashd peers.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use dashcore::BlockHash;
use serde::Deserialize;
use tempfile::TempDir;
use tracing::{debug, info, warn};

use super::fs_helpers::copy_dir;
use super::node::find_available_port;
use super::{retain_test_dir, DashCoreConfig, DashCoreNode, WalletFile};

/// Metadata for a pre-generated masternode network, deserialized from network.json.
#[derive(Debug, Deserialize)]
pub struct NetworkMetadata {
    pub version: String,
    pub chain_height: u32,
    pub dkg_cycles_completed: u32,
    pub dkg_interval: u32,
    pub controller: ControllerInfo,
    pub masternodes: Vec<MasternodeInfo>,
    pub spork_private_key: String,
    pub dashd_extra_args: Vec<String>,
}

/// Controller node info from network.json.
#[derive(Debug, Deserialize)]
pub struct ControllerInfo {
    pub datadir: String,
    pub wallet: String,
}

/// Individual masternode info from network.json.
#[derive(Debug, Deserialize)]
pub struct MasternodeInfo {
    pub index: u32,
    pub datadir: String,
    pub pro_tx_hash: String,
    pub bls_private_key: String,
    pub bls_public_key: String,
    pub owner_address: String,
    pub voting_address: String,
    pub payout_address: String,
}

impl NetworkMetadata {
    /// Load from a network.json file.
    fn from_json(path: &Path) -> Self {
        let contents = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
        serde_json::from_str(&contents)
            .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e))
    }
}

/// Test context managing a full masternode network (controller + masternodes).
///
/// Starts dashd instances from pre-generated blockchain data, connects them,
/// and provides the controller's P2P address for SPV client testing.
pub struct MasternodeTestContext {
    pub controller: DashCoreNode,
    pub masternodes: Vec<DashCoreNode>,
    pub metadata: NetworkMetadata,
    pub controller_addr: SocketAddr,
    pub wallet: WalletFile,
    pub expected_height: u32,
    /// Current mock time used for DKG phase orchestration.
    mocktime: u64,
}

impl MasternodeTestContext {
    /// Create a new masternode test context.
    ///
    /// When `controller_only` is true, only the controller node is started
    /// (sufficient for static masternode list sync tests).
    ///
    /// Returns `None` if `SKIP_DASHD_TESTS` is set or required env vars are missing.
    pub async fn new(controller_only: bool) -> Option<Self> {
        if std::env::var("SKIP_DASHD_TESTS").is_ok() {
            eprintln!("Skipping dashd integration test (SKIP_DASHD_TESTS is set)");
            return None;
        }

        let dashd_path = std::env::var("DASHD_PATH")
            .ok()
            .map(PathBuf::from)
            .expect("DASHD_PATH must be set for masternode tests");
        assert!(dashd_path.exists(), "DASHD_PATH does not exist: {}", dashd_path.display());

        let mn_datadir = std::env::var("DASHD_MN_DATADIR")
            .ok()
            .map(PathBuf::from)
            .expect("DASHD_MN_DATADIR must be set for masternode tests");
        assert!(mn_datadir.exists(), "DASHD_MN_DATADIR does not exist: {}", mn_datadir.display());

        let metadata = NetworkMetadata::from_json(&mn_datadir.join("network.json"));
        info!(
            "Loaded masternode network: height={}, dkg_cycles={}, masternodes={}",
            metadata.chain_height,
            metadata.dkg_cycles_completed,
            metadata.masternodes.len()
        );

        let wallet = WalletFile::from_json(&mn_datadir, &metadata.controller.wallet);
        info!(
            "Loaded wallet: {} transactions, balance: {:.8}",
            wallet.transaction_count, wallet.balance
        );

        // Build extra args shared by all nodes
        let mut shared_args: Vec<String> = metadata.dashd_extra_args.clone();
        shared_args.push(format!("-sporkkey={}", metadata.spork_private_key));
        // Enable full debug logging so debug.log captures all internal state
        shared_args.push("-debug=all".to_string());
        shared_args.push("-debuglogfile=debug.log".to_string());

        // Start controller — keep the temp dir so debug.log is accessible after the test
        let controller_temp = TempDir::new().expect("failed to create controller temp dir");
        copy_dir(&mn_datadir.join(&metadata.controller.datadir), controller_temp.path())
            .expect("failed to copy controller datadir");
        let controller_config = DashCoreConfig {
            dashd_path: dashd_path.clone(),
            datadir: controller_temp.path().to_path_buf(),
            wallet: metadata.controller.wallet.clone(),
            p2p_port: find_available_port(),
            rpc_port: find_available_port(),
            extra_args: shared_args.clone(),
        };
        let controller_path = controller_temp.keep();
        let mut controller = DashCoreNode::with_config(controller_config);
        let controller_addr = controller.start().await;
        info!(
            "Controller started at {} | debug.log: {}/regtest/debug.log",
            controller_addr,
            controller_path.display()
        );

        // Start masternode nodes (if not controller-only)
        let mut masternodes = Vec::new();
        if !controller_only {
            for mn_info in &metadata.masternodes {
                let mn_temp = TempDir::new().expect("failed to create mn temp dir");
                copy_dir(&mn_datadir.join(&mn_info.datadir), mn_temp.path())
                    .expect("failed to copy masternode datadir");

                let mut mn_args = shared_args.clone();
                mn_args.push("-txindex=1".to_string());
                mn_args.push(format!("-masternodeblsprivkey={}", mn_info.bls_private_key));

                let mn_config = DashCoreConfig {
                    dashd_path: dashd_path.clone(),
                    datadir: mn_temp.keep(),
                    wallet: "".to_string(),
                    p2p_port: find_available_port(),
                    rpc_port: find_available_port(),
                    extra_args: mn_args,
                };
                let mut node = DashCoreNode::with_config(mn_config);
                let addr = node.start().await;
                info!(
                    "Masternode {} started at {} | debug.log: {}/regtest/debug.log",
                    mn_info.datadir,
                    addr,
                    node.datadir().display()
                );

                masternodes.push(node);
            }

            // Connect all masternodes to controller and to each other.
            // DKG requires masternodes to exchange messages - direct connections
            // between them ensure reliable message propagation.
            connect_all_nodes(&controller, &masternodes).await;

            // Update each masternode's service address to match its actual P2P port.
            // The proTx entries from generation reference the original ports, but the
            // nodes now run on different ports. Without this update, quorum connections
            // between masternodes would fail (dashd connects to registered addresses).
            update_mn_service_addresses(&controller, &masternodes, &metadata);
        }

        let expected_height = controller
            .try_rpc_call("getblockcount", &[])
            .and_then(|v| v.as_u64())
            .expect("getblockcount on controller") as u32;

        // Get the current block time for mocktime initialization.
        // DKG orchestration requires advancing time via setmocktime.
        let mocktime = {
            let hash = controller.get_best_block_hash().to_string();
            let block_info = controller
                .try_rpc_call("getblock", &[hash.into()])
                .expect("getblock on controller");
            block_info["time"].as_u64().expect("block time") + 1
        };

        // Set mocktime on all nodes so DKG timing is consistent with the
        // pre-generated data. Without this, nodes use real system time which
        // is far ahead of the block timestamps from generation.
        controller.set_mocktime(mocktime);
        for mn in &masternodes {
            mn.set_mocktime(mocktime);
        }

        info!("Network ready: controller at height {}, mocktime={}", expected_height, mocktime);

        Some(MasternodeTestContext {
            controller,
            masternodes,
            metadata,
            controller_addr,
            wallet,
            expected_height,
            mocktime,
        })
    }
    /// Advance mocktime on all nodes and trigger the scheduler.
    ///
    /// Calls both `setmocktime` and `mockscheduler` on every node. The scheduler
    /// trigger is needed for DKG phase transitions - without it, nodes don't
    /// process scheduled DKG tasks. Errors are tolerated since nodes may be
    /// temporarily busy during DKG processing.
    fn bump_mocktime(&mut self, seconds: u64) {
        self.mocktime += seconds;
        let time = self.mocktime;
        for node in std::iter::once(&self.controller).chain(self.masternodes.iter()) {
            node.try_rpc_call("setmocktime", &[time.into()]);
            node.try_rpc_call("mockscheduler", &[seconds.into()]);
        }
    }

    /// Generate blocks on the controller and wait for all nodes to sync.
    pub fn move_blocks(&mut self, count: u64) {
        if count == 0 {
            return;
        }
        self.bump_mocktime(1);
        let addr = self.controller.get_new_address();
        self.controller.generate_blocks(count, &addr);
        self.wait_for_sync();
    }

    /// Wait for all masternode nodes to reach the same height as the controller.
    fn wait_for_sync(&self) {
        let target_height = self
            .controller
            .try_rpc_call("getblockcount", &[])
            .and_then(|v| v.as_u64())
            .expect("getblockcount on controller");

        for mn in &self.masternodes {
            let start = Instant::now();
            loop {
                let h = mn.try_rpc_call("getblockcount", &[]).and_then(|v| v.as_u64()).unwrap_or(0);
                if h >= target_height {
                    break;
                }
                if start.elapsed() > Duration::from_secs(30) {
                    panic!("Masternode sync timeout: at {}, expected {}", h, target_height);
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }

    /// Wait for masternodes to reach a specific DKG phase for the given quorum type and hash.
    ///
    /// Returns true if enough members reached the phase within the timeout.
    /// Uses error-tolerant RPC calls since nodes may be busy during DKG.
    fn wait_for_quorum_phase(
        &mut self,
        llmq_type: &str,
        quorum_hash: &str,
        phase: u64,
        expected_members: usize,
        check_received_messages: Option<&str>,
        check_received_messages_count: u64,
        timeout_secs: u64,
    ) -> bool {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            let mut member_count = 0;
            for mn in &self.masternodes {
                if let Some(status) = mn.try_rpc_call("quorum", &["dkgstatus".into()]) {
                    if let Some(sessions) = status.get("session").and_then(|s| s.as_array()) {
                        for session in sessions {
                            let session_type = session.get("llmqType").and_then(|t| t.as_str());
                            if session_type != Some(llmq_type) {
                                continue;
                            }
                            let qs = session.get("status").unwrap_or(session);
                            let hash_matches =
                                qs.get("quorumHash").and_then(|h| h.as_str()) == Some(quorum_hash);
                            let phase_matches =
                                qs.get("phase").and_then(|p| p.as_u64()) == Some(phase);
                            let messages_match = check_received_messages.is_none_or(|field| {
                                qs.get(field).and_then(|v| v.as_u64()).unwrap_or(0)
                                    >= check_received_messages_count
                            });
                            if hash_matches && phase_matches && messages_match {
                                member_count += 1;
                                break;
                            }
                        }
                    }
                }
            }
            if member_count >= expected_members {
                return true;
            }
            self.bump_mocktime(1);
            std::thread::sleep(Duration::from_millis(300));
        }
        false
    }

    /// Wait for quorum connections between masternodes to be actually established.
    ///
    /// Checks the `quorumConnections` field in dkgstatus for masternodes that have
    /// outbound connections marked as `connected: true`. The TCP connections use
    /// real wall-clock time, so mockscheduler alone is not enough.
    fn wait_for_quorum_connections(
        &mut self,
        llmq_type: &str,
        quorum_hash: &str,
        expected_connections: usize,
        timeout_secs: u64,
    ) -> bool {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            let mut all_connected = true;

            for mn in &self.masternodes {
                let Some(status) = mn.try_rpc_call("quorum", &["dkgstatus".into()]) else {
                    all_connected = false;
                    break;
                };
                let Some(sessions) = status.get("session").and_then(|s| s.as_array()) else {
                    all_connected = false;
                    break;
                };
                let has_session = sessions.iter().any(|session| {
                    session.get("llmqType").and_then(|t| t.as_str()) == Some(llmq_type)
                        && session
                            .get("status")
                            .unwrap_or(session)
                            .get("quorumHash")
                            .and_then(|h| h.as_str())
                            == Some(quorum_hash)
                });
                if !has_session {
                    continue;
                }

                let Some(conn_groups) = status.get("quorumConnections").and_then(|c| c.as_array())
                else {
                    all_connected = false;
                    break;
                };

                let Some(conn_group) = conn_groups.iter().find(|conn_group| {
                    conn_group.get("llmqType").and_then(|t| t.as_str()) == Some(llmq_type)
                        && conn_group.get("quorumHash").and_then(|h| h.as_str())
                            == Some(quorum_hash)
                }) else {
                    all_connected = false;
                    break;
                };

                let connected = conn_group
                    .get("quorumConnections")
                    .and_then(|p| p.as_array())
                    .map(|peers| {
                        peers
                            .iter()
                            .filter(|p| p.get("connected").and_then(|c| c.as_bool()) == Some(true))
                            .count()
                    })
                    .unwrap_or(0);
                if connected < expected_connections {
                    all_connected = false;
                    break;
                }
            }

            if all_connected {
                debug!(
                    "Quorum connections established for {} with {} peers per masternode",
                    llmq_type, expected_connections
                );
                return true;
            }
            self.bump_mocktime(1);
            std::thread::sleep(Duration::from_millis(500));
        }
        false
    }

    fn wait_for_masternode_probes(
        &mut self,
        llmq_type: &str,
        quorum_hash: &str,
        timeout_secs: u64,
    ) -> bool {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            let mut all_probed = true;

            'nodes: for mn in &self.masternodes {
                let Some(status) = mn.try_rpc_call("quorum", &["dkgstatus".into()]) else {
                    all_probed = false;
                    break;
                };
                let Some(conn_groups) = status.get("quorumConnections").and_then(|c| c.as_array())
                else {
                    all_probed = false;
                    break;
                };

                for conn_group in conn_groups {
                    let type_matches =
                        conn_group.get("llmqType").and_then(|t| t.as_str()) == Some(llmq_type);
                    let hash_matches =
                        conn_group.get("quorumHash").and_then(|h| h.as_str()) == Some(quorum_hash);
                    if !type_matches || !hash_matches {
                        continue;
                    }

                    let Some(peers) =
                        conn_group.get("quorumConnections").and_then(|p| p.as_array())
                    else {
                        all_probed = false;
                        break 'nodes;
                    };

                    for peer in peers {
                        if peer.get("outbound").and_then(|v| v.as_bool()) != Some(false) {
                            continue;
                        }
                        let Some(pro_tx_hash) = peer.get("proTxHash").and_then(|v| v.as_str())
                        else {
                            all_probed = false;
                            break 'nodes;
                        };
                        let Some(info) =
                            mn.try_rpc_call("protx", &["info".into(), pro_tx_hash.into()])
                        else {
                            all_probed = false;
                            break 'nodes;
                        };
                        let meta = info.get("metaInfo").unwrap_or(&info);
                        let last_success = meta
                            .get("lastOutboundSuccessElapsed")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(u64::MAX);
                        let last_attempt = meta
                            .get("lastOutboundAttemptElapsed")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(u64::MAX);
                        let is_expected_mn = self
                            .metadata
                            .masternodes
                            .iter()
                            .any(|mn_info| mn_info.pro_tx_hash == pro_tx_hash);
                        if is_expected_mn {
                            if last_success > 55 * 60 {
                                all_probed = false;
                                break 'nodes;
                            }
                        } else if last_attempt > 55 * 60 && last_success > 55 * 60 {
                            all_probed = false;
                            break 'nodes;
                        }
                    }
                }
            }

            if all_probed {
                return true;
            }
            self.bump_mocktime(1);
            std::thread::sleep(Duration::from_millis(500));
        }
        false
    }

    fn wait_for_sporks_same(&mut self, timeout_secs: u64) -> bool {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            let Some(controller_sporks) = self.controller.try_rpc_call("spork", &["show".into()])
            else {
                self.bump_mocktime(1);
                std::thread::sleep(Duration::from_secs(1));
                continue;
            };
            let all_same = self.masternodes.iter().all(|mn| {
                mn.try_rpc_call("spork", &["show".into()]).as_ref() == Some(&controller_sporks)
            });
            if all_same {
                return true;
            }
            self.bump_mocktime(1);
            std::thread::sleep(Duration::from_secs(1));
        }
        false
    }

    /// Wait for a quorum with the given hash to appear in `quorum list` for the given type.
    fn wait_for_quorum_in_list(
        &self,
        llmq_type: &str,
        quorum_hash: &str,
        timeout_secs: u64,
    ) -> bool {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            if let Some(qlist) = self.controller.try_rpc_call("quorum", &["list".into(), 1.into()])
            {
                if let Some(arr) = qlist.get(llmq_type).and_then(|v| v.as_array()) {
                    if arr.iter().any(|e| e.as_str() == Some(quorum_hash)) {
                        return true;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        false
    }

    /// Wait for enough masternodes to report a minable commitment for the quorum.
    fn wait_for_quorum_commitment(
        &mut self,
        llmq_type: u64,
        quorum_hash: &str,
        expected_members: usize,
        timeout_secs: u64,
    ) -> bool {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);
        let zero_key =
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        while start.elapsed() < timeout {
            let mut ready_count = 0;
            for mn in &self.masternodes {
                if let Some(status) = mn.try_rpc_call("quorum", &["dkgstatus".into()]) {
                    if let Some(commits) =
                        status.get("minableCommitments").and_then(|c| c.as_array())
                    {
                        let ready = commits.iter().any(|commit| {
                            commit.get("llmqType").and_then(|t| t.as_u64()) == Some(llmq_type)
                                && commit.get("quorumHash").and_then(|h| h.as_str())
                                    == Some(quorum_hash)
                                && commit.get("quorumPublicKey").and_then(|k| k.as_str())
                                    != Some(zero_key)
                        });
                        if ready {
                            ready_count += 1;
                        }
                    }
                }
            }
            if ready_count >= expected_members {
                return true;
            }
            self.bump_mocktime(1);
            std::thread::sleep(Duration::from_millis(300));
        }
        false
    }

    /// Mine a single block and then call `on_block_mined` with the controller
    /// reference and the resulting block height. Helper for
    /// `mine_dkg_cycle_with_hook` so each hook site stays a one-liner.
    fn mine_block_then_notify<F: FnMut(&DashCoreNode, u32)>(&mut self, on_block_mined: &mut F) {
        self.move_blocks(1);
        let height = self
            .controller
            .try_rpc_call("getblockcount", &[])
            .and_then(|v| v.as_u64())
            .expect("getblockcount") as u32;
        on_block_mined(&self.controller, height);
    }

    /// Mine a complete DKG cycle and return the quorum hash if successful.
    ///
    /// Orchestrates all 6 DKG phases, mines the commitment block, and verifies
    /// the quorum appears in `quorum list`.
    ///
    /// In regtest, `llmq_test` (type 100, 3 members) and `llmq_test_platform`
    /// (type 106) reliably produce commitments. `llmq_test_dip0024` (type 103,
    /// 4 members, minSize=4) requires all masternodes to succeed and is fragile
    /// in live orchestration (pre-generated data has DIP0024 quorums from
    /// controlled generation).
    ///
    /// ChainLocks use `llmq_test` in regtest, so new DKG cycles enable ChainLock
    /// signing. QRInfo for rotated quorums references the pre-generated DIP0024
    /// quorum history.
    ///
    /// Returns `None` if any phase times out.
    /// Requires the full network to be running (controller + masternodes).
    pub fn mine_dkg_cycle(&mut self) -> Option<BlockHash> {
        self.mine_dkg_cycle_with_hook(|_, _| {})
    }

    /// Mine a complete DKG cycle, invoking `on_block_mined` after every block
    /// mined past the cycle alignment point.
    ///
    /// Blocks mined to align the chain to the next DKG cycle boundary do *not*
    /// trigger the hook — alignment is an implementation detail. The hook is
    /// called for every subsequent block that advances a DKG phase, the
    /// commitment block, and every maturity block.
    ///
    /// The hook receives a shared reference to the controller node so it can
    /// issue RPC calls (for example `send_to_address`) from inside the cycle.
    pub fn mine_dkg_cycle_with_hook<F>(&mut self, mut on_block_mined: F) -> Option<BlockHash>
    where
        F: FnMut(&DashCoreNode, u32),
    {
        assert!(!self.masternodes.is_empty(), "mine_dkg_cycle requires masternodes to be running");

        // Both llmq_test (100) and llmq_test_dip0024 (103) share the same DKG
        // interval so their cycles run simultaneously. We track phases using
        // llmq_test (3 members, easier to satisfy) and then verify that the
        // rotated type also produced a quorum.
        let dkg_interval = self.metadata.dkg_interval as u64;
        let current_height = self
            .controller
            .try_rpc_call("getblockcount", &[])
            .and_then(|v| v.as_u64())
            .expect("getblockcount");

        // Align to next DKG cycle boundary
        let remainder = current_height % dkg_interval;
        if remainder != 0 {
            let skip = dkg_interval - remainder;
            debug!("Aligning to DKG boundary: mining {} blocks", skip);
            self.move_blocks(skip);
        }

        // The quorum hash is the best block hash at the cycle start
        let quorum_hash = self.controller.get_best_block_hash();
        let quorum_hash_str = quorum_hash.to_string();
        info!("Starting DKG cycle, quorum_hash={}", quorum_hash_str);

        if self
            .controller
            .try_rpc_call("sporkupdate", &["SPORK_21_QUORUM_ALL_CONNECTED".into(), 0.into()])
            .is_none()
        {
            warn!("Failed to activate SPORK_21_QUORUM_ALL_CONNECTED");
            return None;
        }
        if !self.wait_for_sporks_same(30) {
            warn!("Spork synchronization timeout");
            return None;
        }

        let sporks = self.controller.try_rpc_call("spork", &["show".into()])?;
        let spork21_active = sporks
            .get("SPORK_21_QUORUM_ALL_CONNECTED")
            .and_then(|v| v.as_i64())
            .is_some_and(|value| value <= 1);
        let spork23_active = sporks
            .get("SPORK_23_QUORUM_POSE")
            .and_then(|v| v.as_i64())
            .is_some_and(|value| value <= 1);

        // LLMQ_TEST: 3 members out of 4, threshold 2
        let expected_members = 3;
        let expected_connections_test = if spork21_active {
            expected_members - 1
        } else {
            2
        };
        let dip0024_size = self.metadata.masternodes.len();
        let expected_connections_dip0024 = if spork21_active {
            dip0024_size - 1
        } else {
            2
        };

        // Wait for quorum connections for both types to be established.
        // DKG requires direct TCP connections between quorum members. These
        // connections take real wall-clock time to establish (independent of
        // mocktime), so we wait before pushing DKG phases forward.
        debug!("Waiting for quorum connections...");
        if !self.wait_for_quorum_connections(
            "llmq_test",
            &quorum_hash_str,
            expected_connections_test,
            60,
        ) {
            warn!("llmq_test quorum connections timeout");
            return None;
        }
        if !self.wait_for_quorum_connections(
            "llmq_test_dip0024",
            &quorum_hash_str,
            expected_connections_dip0024,
            60,
        ) {
            warn!("llmq_test_dip0024 quorum connections timeout");
            return None;
        }
        if spork23_active {
            if !self.wait_for_masternode_probes("llmq_test", &quorum_hash_str, 30) {
                warn!("llmq_test masternode probe timeout");
                return None;
            }
            if !self.wait_for_masternode_probes("llmq_test_dip0024", &quorum_hash_str, 30) {
                warn!("llmq_test_dip0024 masternode probe timeout");
                return None;
            }
        }

        // Phase 1: Initialization
        debug!("DKG phase 1 (init)...");
        if !self.wait_for_quorum_phase(
            "llmq_test",
            &quorum_hash_str,
            1,
            expected_members,
            None,
            0,
            60,
        ) {
            warn!("DKG phase 1 timeout");
            return None;
        }
        self.mine_block_then_notify(&mut on_block_mined);
        self.mine_block_then_notify(&mut on_block_mined);

        // Phases 2-5: Contribute, Complain, Justify, Commit
        let phase_checks = [
            (2, Some("receivedContributions"), expected_members as u64, 30),
            (3, Some("receivedComplaints"), 0, 30),
            (4, Some("receivedJustifications"), 0, 30),
            (5, Some("receivedPrematureCommitments"), expected_members as u64, 30),
        ];
        for (phase, field, count, timeout_secs) in phase_checks {
            debug!("DKG phase {}...", phase);
            if !self.wait_for_quorum_phase(
                "llmq_test",
                &quorum_hash_str,
                phase,
                expected_members,
                field,
                count,
                timeout_secs,
            ) {
                warn!("DKG phase {} timeout", phase);
                return None;
            }
            self.mine_block_then_notify(&mut on_block_mined);
            self.mine_block_then_notify(&mut on_block_mined);
        }

        // Phase 6: Mining
        debug!("DKG phase 6 (mining)...");
        if !self.wait_for_quorum_phase(
            "llmq_test",
            &quorum_hash_str,
            6,
            expected_members,
            None,
            0,
            60,
        ) {
            warn!("DKG phase 6 timeout");
            return None;
        }
        if !self.wait_for_quorum_commitment(100, &quorum_hash_str, expected_members, 30) {
            warn!("Quorum commitment timeout");
            return None;
        }

        self.bump_mocktime(1);
        self.controller.get_block_template();
        self.mine_block_then_notify(&mut on_block_mined);

        if !self.wait_for_quorum_in_list("llmq_test", &quorum_hash_str, 15) {
            warn!("Quorum not found in list after mining commitment");
            return None;
        }

        // Mine maturity blocks
        for _ in 0..8 {
            self.mine_block_then_notify(&mut on_block_mined);
        }

        info!("DKG cycle complete: quorum_hash={}", quorum_hash_str);
        Some(quorum_hash)
    }

    /// Wait for a specific block to become ChainLocked on the controller.
    pub fn wait_for_chainlocked_block(
        &mut self,
        block_hash: &BlockHash,
        timeout_secs: u64,
    ) -> bool {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);
        let block_hash_str = block_hash.to_string();

        while start.elapsed() < timeout {
            if let Some(block) =
                self.controller.try_rpc_call("getblock", &[block_hash_str.clone().into()])
            {
                let confirmed = block.get("confirmations").and_then(|v| v.as_i64()).unwrap_or(0);
                let chainlocked = block.get("chainlock").and_then(|v| v.as_bool()).unwrap_or(false);
                if confirmed > 0 && chainlocked {
                    return true;
                }
            }
            self.bump_mocktime(1);
            std::thread::sleep(Duration::from_millis(500));
        }
        false
    }

    /// Mine blocks and wait for each newly mined block to become ChainLocked.
    ///
    /// Mining one block at a time matches Dash Core's own functional tests more
    /// closely than mining a batch and polling `getbestchainlock`, and avoids
    /// depending on an RPC that returns an error before the first ChainLock exists.
    pub fn mine_blocks_and_wait_for_chainlock(
        &mut self,
        block_count: u64,
        timeout_secs: u64,
    ) -> Option<u32> {
        let mut last_chainlocked_height = None;

        for _ in 0..block_count {
            self.bump_mocktime(1);
            let addr = self.controller.get_new_address();
            let block_hash = self
                .controller
                .generate_blocks(1, &addr)
                .into_iter()
                .next()
                .expect("generated block hash");
            self.wait_for_sync();

            if self.wait_for_chainlocked_block(&block_hash, timeout_secs) {
                let height = self
                    .controller
                    .try_rpc_call("getblock", &[block_hash.to_string().into()])
                    .and_then(|b| b.get("height").and_then(|h| h.as_u64()))
                    .map(|h| h as u32)
                    .expect("getblock height");
                info!("ChainLock found at height {}", height);
                last_chainlocked_height = Some(height);
            }
        }

        last_chainlocked_height
    }
}

impl Drop for MasternodeTestContext {
    fn drop(&mut self) {
        retain_test_dir(self.controller.datadir(), "controller");
        for (idx, masternode) in self.masternodes.iter().enumerate() {
            let label = format!("masternode-{}-{}", idx, masternode.rpc_port());
            retain_test_dir(masternode.datadir(), &label);
        }
    }
}

/// Connect all nodes to each other: each masternode to the controller and to other masternodes.
///
/// Direct connections between masternodes are important for DKG message exchange.
async fn connect_all_nodes(controller: &DashCoreNode, masternodes: &[DashCoreNode]) {
    let controller_p2p: serde_json::Value = format!("127.0.0.1:{}", controller.p2p_port()).into();

    // Connect each masternode to the controller
    for mn in masternodes {
        mn.try_rpc_call("addnode", &[controller_p2p.clone(), "add".into()]);
    }

    // Connect each masternode to every other masternode
    for i in 0..masternodes.len() {
        for j in (i + 1)..masternodes.len() {
            let target: serde_json::Value =
                format!("127.0.0.1:{}", masternodes[j].p2p_port()).into();
            masternodes[i].try_rpc_call("addnode", &[target, "add".into()]);
        }
    }

    // Wait for the controller to have all expected peer connections
    let expected_peers = masternodes.len();
    for _ in 0..15 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let count = controller
            .try_rpc_call("getpeerinfo", &[])
            .and_then(|v| v.as_array().map(|a| a.len()))
            .unwrap_or(0);
        if count >= expected_peers {
            info!("Controller has {} peers connected", count);
            return;
        }
    }
    let count = controller
        .try_rpc_call("getpeerinfo", &[])
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0);
    info!("Controller has {} peers (expected {})", count, expected_peers);
}

/// Update each masternode's registered service address to match its actual P2P port.
///
/// The proTx entries from generation reference the original ports. After restarting
/// with different ports, we need to call `protx update_service` so that dashd can
/// establish quorum connections between masternodes at the correct addresses.
fn update_mn_service_addresses(
    controller: &DashCoreNode,
    masternodes: &[DashCoreNode],
    metadata: &NetworkMetadata,
) {
    use dashcore_rpc::{Auth, Client, RpcApi};

    // Wallet-aware client needed because protx update_service sends a transaction
    let url =
        format!("http://127.0.0.1:{}/wallet/{}", controller.rpc_port(), metadata.controller.wallet);
    let cookie_path = controller.datadir().join("regtest/.cookie");
    let client = Client::new(&url, Auth::CookieFile(cookie_path)).expect("rpc client");

    for (mn, mn_info) in masternodes.iter().zip(metadata.masternodes.iter()) {
        let new_addr = format!("127.0.0.1:{}", mn.p2p_port());
        info!("Updating {} service address to {}", mn_info.datadir, new_addr);

        let result: Result<serde_json::Value, _> = client.call(
            "protx",
            &[
                "update_service".into(),
                mn_info.pro_tx_hash.clone().into(),
                new_addr.into(),
                mn_info.bls_private_key.clone().into(),
            ],
        );
        if let Err(e) = result {
            warn!("protx update_service failed for {}: {}", mn_info.datadir, e);
        }
    }

    // Mine a block to confirm the update transactions
    let addr = controller.get_new_address();
    controller.generate_blocks(1, &addr);
    info!("Service addresses updated and confirmed");
}
