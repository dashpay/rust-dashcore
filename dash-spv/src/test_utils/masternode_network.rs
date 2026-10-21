//! Masternode network test infrastructure.
//!
//! Manages a pre-generated masternode network (1 controller + N masternodes)
//! for integration testing of masternode list sync against real dashd peers.

use std::env;
use std::fs;
use std::iter;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use dashcore::sml::llmq_type::LLMQ_TEST_DIP00024;
use dashcore::BlockHash;
use dashcore_rpc::{Auth, Client, RpcApi};
use serde::Deserialize;
use serde_json::Value;
use tempfile::TempDir;
use tokio::time;
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
    fn from_json(path: &Path) -> Self {
        let contents = fs::read_to_string(path)
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
    /// Returns `None` when `SKIP_DASHD_TESTS=1` or when the dashd binary lacks
    /// the RPC miner (`generatetoaddress`) — every masternode test mines
    /// blocks, so without the miner none can run. Missing or invalid
    /// `DASHD_PATH` / `DASHD_MN_DATADIR` env vars panic, matching the
    /// `DashdTestContext::new` policy in `tests/dashd_sync`: a CI
    /// misconfiguration must fail loudly rather than silently skipping
    /// every dashd-backed test.
    pub async fn new(controller_only: bool) -> Option<Self> {
        if env::var("SKIP_DASHD_TESTS").is_ok() {
            eprintln!("Skipping dashd integration test (SKIP_DASHD_TESTS is set)");
            return None;
        }

        let dashd_path = env::var("DASHD_PATH")
            .ok()
            .map(PathBuf::from)
            .expect("DASHD_PATH must be set for masternode tests");
        assert!(dashd_path.exists(), "DASHD_PATH does not exist: {}", dashd_path.display());

        let mn_datadir = env::var("DASHD_MN_DATADIR")
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

        let mut shared_args: Vec<String> = metadata.dashd_extra_args.clone();
        shared_args.push(format!("-sporkkey={}", metadata.spork_private_key));
        shared_args.push("-debug=all".to_string());
        shared_args.push("-debuglogfile=debug.log".to_string());

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
        let mut controller = DashCoreNode::with_config(controller_config);
        let controller_addr = controller.start().await;

        // Every masternode test path mines blocks (DKG cycles, ISLOCK, mocktime
        // bumps), so a dashd binary without the RPC miner cannot run any of
        // them. Some Windows release builds ship without `generatetoaddress`
        // compiled in. Detect this and skip rather than panicking deep inside
        // a test, mirroring the policy in `DashdTestContext`.
        if !controller.supports_mining() {
            eprintln!("Skipping masternode test (dashd RPC miner not available)");
            return None;
        }

        // Keep the temp dir so debug.log is accessible after the test.
        let controller_path = controller_temp.keep();
        info!(
            "Controller started at {} | debug.log: {}/regtest/debug.log",
            controller_addr,
            controller_path.display()
        );

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

            connect_all_nodes(&controller, &masternodes).await;

            // Update each masternode's service address to match its actual P2P port.
            // The proTx entries from generation reference the original ports, but the
            // nodes now run on different ports. Without this update, quorum connections
            // between masternodes would fail (dashd connects to registered addresses).
            update_mn_service_addresses(&controller, &masternodes, &metadata);

            // Disable `SPORK_21_QUORUM_ALL_CONNECTED` to match upstream Dash
            // Core functional tests (`p2p_instantsend.py`,
            // `feature_llmq_is_*.py`, `feature_llmq_rotation.py`) which all
            // run with SPORK_21 OFF. The pre-generated chain bakes this spork
            // at value=0 (ON), which switches `GetQuorumConnections` into the
            // asymmetric `DeterministicOutboundConnection` hub-and-spoke mode.
            // With only 4 MNs and our fixed pre-generated proTxHashes, that
            // produces a degenerate topology where one MN ends up as the
            // outbound initiator against all three others, so none of them
            // ever put it in their `masternodeQuorumRelayMembers` set, no
            // `QSENDRECSIGS` reaches it, and its recovered input-lock sig
            // never propagates back — leaving ISLOCK sessions stuck at a
            // single share. Setting the spork to `4070908800` (far-future
            // timestamp) disables it per Dash Core convention.
            if controller
                .try_rpc_call(
                    "sporkupdate",
                    &["SPORK_21_QUORUM_ALL_CONNECTED".into(), 4070908800i64.into()],
                )
                .is_none()
            {
                warn!("Failed to disable SPORK_21_QUORUM_ALL_CONNECTED");
            }
            // Mine one block so the updated spork value is gossiped to MNs
            // before any signing session starts.
            {
                let addr = controller.get_new_address();
                controller.generate_blocks(1, &addr);
            }
        }

        let expected_height = controller
            .try_rpc_call("getblockcount", &[])
            .and_then(|v| v.as_u64())
            .expect("getblockcount on controller") as u32;

        // DKG orchestration requires initializing mocktime to the latest block timestamp.
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

    pub fn bump_mocktime(&mut self, seconds: u64) {
        self.mocktime += seconds;
        let time = self.mocktime;
        for node in iter::once(&self.controller).chain(self.masternodes.iter()) {
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
                thread::sleep(Duration::from_millis(200));
            }
        }
    }

    /// Wait for masternodes to reach a specific DKG phase for the given quorum type and hash.
    ///
    /// Returns true if enough members reached the phase within the timeout.
    #[allow(clippy::too_many_arguments)]
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
        let mut poll_iter: u32 = 0;

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
            if poll_iter.is_multiple_of(5) {
                self.bump_mocktime(1);
            }
            poll_iter += 1;
            thread::sleep(Duration::from_millis(100));
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
        expected_members: usize,
        timeout_secs: u64,
    ) -> bool {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);
        let mut poll_iter: u32 = 0;

        while start.elapsed() < timeout {
            let mut connected_members = 0;

            for mn in &self.masternodes {
                let Some(status) = mn.try_rpc_call("quorum", &["dkgstatus".into()]) else {
                    continue;
                };
                let Some(sessions) = status.get("session").and_then(|s| s.as_array()) else {
                    continue;
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
                    continue;
                };

                let Some(conn_group) = conn_groups.iter().find(|conn_group| {
                    conn_group.get("llmqType").and_then(|t| t.as_str()) == Some(llmq_type)
                        && conn_group.get("quorumHash").and_then(|h| h.as_str())
                            == Some(quorum_hash)
                }) else {
                    continue;
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
                if connected >= expected_connections {
                    connected_members += 1;
                }
            }

            if connected_members >= expected_members {
                debug!(
                    "Quorum connections established for {} ({} members with {} peers each)",
                    llmq_type, connected_members, expected_connections
                );
                return true;
            }
            if poll_iter.is_multiple_of(5) {
                self.bump_mocktime(1);
            }
            poll_iter += 1;
            thread::sleep(Duration::from_millis(100));
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
        let mut poll_iter: u32 = 0;

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
            if poll_iter.is_multiple_of(5) {
                self.bump_mocktime(1);
            }
            poll_iter += 1;
            thread::sleep(Duration::from_millis(100));
        }
        false
    }

    /// Wait for at least `expected_count` entries of `llmq_type` to appear in
    /// the controller's `quorum list` output.
    fn wait_for_quorum_list_count(
        &self,
        llmq_type: &str,
        expected_count: usize,
        timeout_secs: u64,
    ) -> bool {
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            if let Some(qlist) = self.controller.try_rpc_call("quorum", &["list".into(), 10.into()])
            {
                let count =
                    qlist.get(llmq_type).and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
                if count >= expected_count {
                    return true;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        false
    }

    /// Mine a single block and then call `on_block_mined` with the controller
    /// reference and the resulting block height.
    fn mine_block_then_notify<F: FnMut(&DashCoreNode, u32)>(&mut self, on_block_mined: &mut F) {
        self.move_blocks(1);
        let height = self
            .controller
            .try_rpc_call("getblockcount", &[])
            .and_then(|v| v.as_u64())
            .expect("getblockcount") as u32;
        on_block_mined(&self.controller, height);
    }

    /// Mine a single block, wait for it to be ChainLocked, then call the hook.
    ///
    /// The ChainLock wait guarantees the block's CbTx `bestCLSignature` is
    /// populated, which is required whenever the block is later referenced as
    /// a QRInfo rotating-quorum lookup target (`cycleBlock - quorumIndex - 8`).
    ///
    /// A missed ChainLock within `cl_timeout_secs` is logged as a warning and
    /// the method returns normally.
    fn mine_block_with_cl_then_notify<F: FnMut(&DashCoreNode, u32)>(
        &mut self,
        on_block_mined: &mut F,
        cl_timeout_secs: u64,
    ) {
        self.move_blocks(1);
        let best_hash = self.controller.get_best_block_hash();
        if !self.wait_for_chainlocked_block(&best_hash, cl_timeout_secs) {
            warn!("ChainLock for {} not received within {}s", best_hash, cl_timeout_secs);
        }
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

        // Align to the next DKG cycle boundary. Each alignment block waits for
        // ChainLock so its CbTx carries a valid `bestCLSignature` for later
        // QRInfo rotating-quorum lookups.
        let remainder = current_height % dkg_interval;
        if remainder != 0 {
            let skip = dkg_interval - remainder;
            debug!("Aligning to DKG boundary: mining {} blocks with CL wait", skip);
            for _ in 0..skip {
                self.mine_block_with_cl_then_notify(&mut |_, _| {}, 15);
            }
        }

        // The quorum hash is the best block hash at the cycle start
        let quorum_hash = self.controller.get_best_block_hash();
        let quorum_hash_str = quorum_hash.to_string();
        info!("Starting DKG cycle, quorum_hash={}", quorum_hash_str);

        // Do NOT activate SPORK_21_QUORUM_ALL_CONNECTED. Upstream Dash Core
        // functional tests (`p2p_instantsend.py`, `feature_llmq_is_*.py`,
        // `feature_llmq_rotation.py`) all run with SPORK_21 OFF, which keeps
        // `GetQuorumConnections` on the default power-of-2-gap mesh in
        // `GetQuorumRelayMembers`.
        //
        // With SPORK_21 ON, `GetQuorumConnections` instead uses
        // `DeterministicOutboundConnection` to pick an asymmetric set. With
        // only 4 MNs and our fixed pre-generated proTxHashes it happens that
        // one MN (the `SelectMemberForRecovery` winner) is the outbound
        // initiator for all three pairs, so the other three never put it into
        // their `masternodeQuorumRelayMembers` set. They never send
        // `QSENDRECSIGS` to it (`CMNAuth::ProcessMessage`,
        // `SetMasternodeQuorumRelayMembers`), so its `peer->m_wants_recsigs`
        // stays false for every peer. When that MN recovers the input-lock
        // signature, `PeerManagerImpl::RelayRecoveredSig` iterates its peers
        // and finds none with `m_wants_recsigs==true`, so the recovered
        // signature never reaches the other three MNs, they never run
        // `TrySignInstantSendLock`, and the ISLOCK session stays stuck at a
        // single sigshare.
        let sporks = self.controller.try_rpc_call("spork", &["show".into()])?;
        let spork23_active = sporks
            .get("SPORK_23_QUORUM_POSE")
            .and_then(|v| v.as_i64())
            .is_some_and(|value| value <= 1);

        // Per-MN expected counts:
        //   - `LLMQ_TEST` is non-rotating, size 3 on regtest, so 3 members.
        //   - `LLMQ_TEST_DIP0024` is rotating, size 4 on regtest, so 4 members
        //     for each of the 2 rotating quorum indices (q_0 and q_1).
        // With SPORK_21 OFF, each member establishes the power-of-2-gap count
        // of outbound quorum connections (2 per member).
        let expected_connections = 2;
        let expected_members_test = 3;
        let expected_members_dip24 = 4;

        if !self.wait_for_quorum_connections(
            "llmq_test",
            &quorum_hash_str,
            expected_connections,
            expected_members_test,
            60,
        ) {
            warn!("llmq_test quorum connections timeout");
            return None;
        }
        if !self.wait_for_quorum_connections(
            "llmq_test_dip0024",
            &quorum_hash_str,
            expected_connections,
            expected_members_dip24,
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

        let q0_hash_str = quorum_hash_str.clone();
        if !self.wait_for_quorum_phase(
            "llmq_test",
            &q0_hash_str,
            1,
            expected_members_test,
            None,
            0,
            30,
        ) {
            warn!("DKG phase 1 (llmq_test) timeout");
            return None;
        }
        if !self.wait_for_quorum_phase(
            "llmq_test_dip0024",
            &q0_hash_str,
            1,
            expected_members_dip24,
            None,
            0,
            30,
        ) {
            warn!("DKG phase 1 (llmq_test_dip0024 q_0) timeout");
            return None;
        }

        self.mine_block_then_notify(&mut on_block_mined);
        let q1_hash = self.controller.get_best_block_hash();
        let q1_hash_str = q1_hash.to_string();

        if !self.wait_for_quorum_phase(
            "llmq_test_dip0024",
            &q1_hash_str,
            1,
            expected_members_dip24,
            None,
            0,
            30,
        ) {
            warn!("DKG phase 1 (llmq_test_dip0024 q_1) timeout");
            return None;
        }
        if !self.wait_for_quorum_connections(
            "llmq_test_dip0024",
            &q1_hash_str,
            expected_connections,
            expected_members_dip24,
            30,
        ) {
            warn!("llmq_test_dip0024 q_1 connections timeout");
            return None;
        }
        if spork23_active && !self.wait_for_masternode_probes("llmq_test_dip0024", &q1_hash_str, 30)
        {
            warn!("llmq_test_dip0024 q_1 masternode probe timeout");
            return None;
        }

        self.mine_block_then_notify(&mut on_block_mined);

        // Phases 2-6: interleave q_0 and q_1 with one block between each wait.
        // LLMQ_TEST is tracked alongside q_0 only (non-rotating, single session).
        let phase_checks: [(u64, Option<&str>, u64, u64); 5] = [
            (2, Some("receivedContributions"), 0, 30),
            (3, Some("receivedComplaints"), 0, 30),
            (4, Some("receivedJustifications"), 0, 30),
            (5, Some("receivedPrematureCommitments"), 0, 30),
            (6, None, 0, 45),
        ];
        for (phase, field, _count, timeout_secs) in phase_checks {
            let dip24_count = match phase {
                2 | 5 => expected_members_dip24 as u64,
                _ => 0,
            };
            let test_count = match phase {
                2 | 5 => expected_members_test as u64,
                _ => 0,
            };

            if phase < 6
                && !self.wait_for_quorum_phase(
                    "llmq_test",
                    &q0_hash_str,
                    phase,
                    expected_members_test,
                    field,
                    test_count,
                    timeout_secs,
                )
            {
                warn!("DKG phase {} (llmq_test) timeout", phase);
                return None;
            }
            if phase == 6
                && !self.wait_for_quorum_phase(
                    "llmq_test",
                    &q0_hash_str,
                    phase,
                    expected_members_test,
                    None,
                    0,
                    timeout_secs,
                )
            {
                warn!("DKG phase 6 (llmq_test) timeout");
                return None;
            }
            if !self.wait_for_quorum_phase(
                "llmq_test_dip0024",
                &q0_hash_str,
                phase,
                expected_members_dip24,
                field,
                dip24_count,
                timeout_secs,
            ) {
                warn!("DKG phase {} (llmq_test_dip0024 q_0) timeout", phase);
                return None;
            }
            self.mine_block_then_notify(&mut on_block_mined);

            if !self.wait_for_quorum_phase(
                "llmq_test_dip0024",
                &q1_hash_str,
                phase,
                expected_members_dip24,
                field,
                dip24_count,
                timeout_secs,
            ) {
                warn!("DKG phase {} (llmq_test_dip0024 q_1) timeout", phase);
                return None;
            }
            self.mine_block_then_notify(&mut on_block_mined);
        }

        // Commitments are mined into phase blocks once the mining window opens. Polling
        // the minable-commitment queue would miss them, so mining one more block here
        // forces any pending commitment on-chain.
        self.bump_mocktime(1);
        self.controller.get_block_template();
        self.mine_block_then_notify(&mut on_block_mined);

        if !self.wait_for_quorum_list_count("llmq_test", 1, 15) {
            warn!("LLMQ_TEST quorum not in list after mining commitment");
            return None;
        }

        if !self.wait_for_quorum_list_count("llmq_test_dip0024", 2, 15) {
            warn!("LLMQ_TEST_DIP0024 rotating quorums not all mined (DKG null commitment)");
            return None;
        }

        // Mine maturity blocks past this cycle's DKG mining window. Each block
        // waits for its ChainLock so the CbTx carries a valid
        // `bestCLSignature` for next-cycle rotating-quorum lookups.
        let dkg_interval = self.metadata.dkg_interval;
        let cycle_start = (self
            .controller
            .try_rpc_call("getblockcount", &[])
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32
            / dkg_interval)
            * dkg_interval;
        // LLMQ_TEST_DIP0024 mining window end, sourced from the params struct
        // so an `-llmqtestparams` regtest override would be honoured.
        let mining_window_end = cycle_start + LLMQ_TEST_DIP00024.dkg_params.mining_window_end;
        for _ in 0..8 {
            self.mine_block_with_cl_then_notify(&mut on_block_mined, 15);
        }
        while let Some(h) = self
            .controller
            .try_rpc_call("getblockcount", &[])
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
        {
            if h > mining_window_end {
                break;
            }
            self.mine_block_with_cl_then_notify(&mut on_block_mined, 15);
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

        let mut poll_iter: u32 = 0;
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
            // Bump mocktime every 10 polls (~1s) to nudge the CL scheduler without
            // over-advancing the signing-session clock.
            if poll_iter.is_multiple_of(5) {
                self.bump_mocktime(1);
            }
            poll_iter += 1;
            thread::sleep(Duration::from_millis(100));
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

/// Connect each masternode to the controller only. Intra-quorum (MN↔MN)
/// connections are established by dashd's own `EnsureQuorumConnections` logic
/// after quorum formation, matching Dash Core's functional test framework
/// (`test/functional/test_framework/test_framework.py`, comment: "masternodes
/// should take care of intra-quorum connections themselves").
///
/// Pre-wiring MN↔MN via `addnode` here is harmful: those manual connections
/// bypass the `EnsureQuorumConnections` → `SetMasternodeQuorumRelayMembers` →
/// `QSENDRECSIGS` handshake, so `peer->m_wants_recsigs` stays false on the
/// inbound side. `PeerManagerImpl::RelayRecoveredSig(proactive=true)` then
/// skips those peers, and recovered input-lock signatures never propagate to
/// every quorum member, which starves ISLOCK signing of shares.
async fn connect_all_nodes(controller: &DashCoreNode, masternodes: &[DashCoreNode]) {
    let controller_p2p: Value = format!("127.0.0.1:{}", controller.p2p_port()).into();

    for mn in masternodes {
        mn.try_rpc_call("addnode", &[controller_p2p.clone(), "add".into()]);
    }

    let expected_peers = masternodes.len();
    for _ in 0..15 {
        time::sleep(Duration::from_secs(2)).await;
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
    panic!(
        "connect_all_nodes: controller has {} peer(s) after waiting, expected {}. \
         Tests downstream assume the controller is connected to every masternode \
         and would silently flake if we proceeded with a partial mesh.",
        count, expected_peers
    );
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
    // Wallet-aware client needed because protx update_service sends a transaction
    let url =
        format!("http://127.0.0.1:{}/wallet/{}", controller.rpc_port(), metadata.controller.wallet);
    let cookie_path = controller.datadir().join("regtest/.cookie");
    let client = Client::new(&url, Auth::CookieFile(cookie_path)).expect("rpc client");

    let mut failures = Vec::new();
    for (mn, mn_info) in masternodes.iter().zip(metadata.masternodes.iter()) {
        let new_addr = format!("127.0.0.1:{}", mn.p2p_port());
        info!("Updating {} service address to {}", mn_info.datadir, new_addr);

        let result: Result<Value, _> = client.call(
            "protx",
            &[
                "update_service".into(),
                mn_info.pro_tx_hash.clone().into(),
                new_addr.into(),
                mn_info.bls_private_key.clone().into(),
            ],
        );
        if let Err(e) = result {
            failures.push(format!("{}: {}", mn_info.datadir, e));
        }
    }
    assert!(
        failures.is_empty(),
        "protx update_service failed for {} masternode(s): {:?}",
        failures.len(),
        failures
    );

    // Mine a block to confirm the update transactions
    let addr = controller.get_new_address();
    controller.generate_blocks(1, &addr);
    info!("Service addresses updated and confirmed");
}
