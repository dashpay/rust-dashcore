use std::net::SocketAddr;
use std::time::Duration;

use dash_spv::client::ClientConfig;
use dash_spv::network::NetworkEvent;
use dash_spv::sync::ProgressPercentage;
use dash_spv::test_utils::{ChaoticDashd, TestChain};
use dash_spv::Network;
use tempfile::TempDir;
use tokio::process::Command;
use tokio::time::{sleep, timeout};

use super::setup::{create_and_start_client, create_test_wallet, ClientHandle};

const SMOKE_HEADER_TARGET: u32 = 100;
const SMOKE_SYNC_TIMEOUT: Duration = Duration::from_secs(60);

fn build_chaos_config(storage: &TempDir, addrs: &[SocketAddr]) -> ClientConfig {
    let mut config = ClientConfig::regtest()
        .with_storage_path(storage.path().to_path_buf())
        .without_masternodes();
    for addr in addrs {
        config.add_peer(*addr);
    }
    config
}

async fn spawn_client_against(chaos: &ChaoticDashd, storage: &TempDir) -> ClientHandle {
    let config = build_chaos_config(storage, &chaos.p2p_addrs());
    let (wallet, _) = create_test_wallet(&chaos.dashd().wallet.mnemonic, Network::Regtest);
    create_and_start_client(&config, wallet).await
}

async fn wait_for_header_height(handle: &mut ClientHandle, target: u32, deadline: Duration) {
    let inner = async {
        loop {
            handle.progress_receiver.changed().await.expect("progress channel closed");
            if let Ok(progress) = handle.progress_receiver.borrow().headers() {
                if progress.current_height() >= target {
                    return progress.current_height();
                }
            }
        }
    };
    timeout(deadline, inner).await.expect("header height not reached in time");
}

fn current_header_height(handle: &ClientHandle) -> u32 {
    handle.progress_receiver.borrow().headers().map(|p| p.current_height()).unwrap_or(0)
}

fn current_filter_height(handle: &ClientHandle) -> u32 {
    handle.progress_receiver.borrow().filters().map(|p| p.current_height()).unwrap_or(0)
}

fn current_filter_header_height(handle: &ClientHandle) -> u32 {
    handle.progress_receiver.borrow().filter_headers().map(|p| p.current_height()).unwrap_or(0)
}

#[tokio::test]
async fn test_chaos_harness_smoke() {
    let Some(chaos) = ChaoticDashd::start(2, TestChain::Minimal).await else {
        return;
    };
    assert_eq!(chaos.slot_count(), 2);
    let toxiproxy_pid = chaos.toxiproxy_pid().expect("toxiproxy pid");

    let storage = tempfile::tempdir().expect("create storage tempdir");
    let mut handle = spawn_client_against(&chaos, &storage).await;

    let progress_wait = async {
        loop {
            handle.progress_receiver.changed().await.expect("progress channel closed");
            if let Ok(headers) = handle.progress_receiver.borrow().headers() {
                if headers.current_height() >= SMOKE_HEADER_TARGET {
                    return;
                }
            }
        }
    };
    timeout(SMOKE_SYNC_TIMEOUT, progress_wait)
        .await
        .expect("header sync did not reach smoke target through proxies");

    chaos.add_latency(0, 50, 0).await;
    chaos.restore(0).await;

    handle.stop().await;
    drop(chaos);

    sleep(Duration::from_millis(500)).await;
    let alive = Command::new("kill")
        .args(["-0", &toxiproxy_pid.to_string()])
        .output()
        .await
        .expect("invoke kill -0")
        .status
        .success();
    assert!(!alive, "toxiproxy server (pid {}) leaked after Drop", toxiproxy_pid);
}

#[tokio::test]
#[ignore] // TODO: enable once fix #1 lands (header regression on disconnect)
async fn test_disconnect_does_not_regress_headers() {
    let Some(chaos) = ChaoticDashd::start(3, TestChain::Full).await else {
        return;
    };
    let storage = tempfile::tempdir().expect("create storage tempdir");
    let mut handle = spawn_client_against(&chaos, &storage).await;

    wait_for_header_height(&mut handle, 50_000, Duration::from_secs(120)).await;
    let before_drop = current_header_height(&handle);

    chaos.drop_all().await;
    sleep(Duration::from_secs(5)).await;
    chaos.restore_all().await;

    sleep(Duration::from_secs(30)).await;
    let after_recovery = current_header_height(&handle);

    handle.stop().await;
    assert!(
        after_recovery >= before_drop,
        "header height regressed after reconnect: before={}, after={}",
        before_drop,
        after_recovery,
    );
}

#[tokio::test]
#[ignore] // TODO: enable once fix #2 lands (lockstep ping cycle); long-running, run via --ignored
async fn test_lockstep_ping_under_high_latency() {
    let Some(chaos) = ChaoticDashd::start(3, TestChain::Minimal).await else {
        return;
    };
    chaos.add_latency_all(300, 50).await;

    let storage = tempfile::tempdir().expect("create storage tempdir");
    let mut handle = spawn_client_against(&chaos, &storage).await;

    let mut ping_timeout_disconnects: u32 = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10 * 60);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Ok(NetworkEvent::PeerDisconnected {
            ..
        })) = timeout(Duration::from_secs(5), handle.network_event_receiver.recv()).await
        {
            ping_timeout_disconnects += 1;
        }
    }

    handle.stop().await;
    assert_eq!(
        ping_timeout_disconnects, 0,
        "saw {} disconnects under sustained 300ms latency",
        ping_timeout_disconnects
    );
}

#[tokio::test]
#[ignore] // TODO: enable once fix #4 lands (startup stampede / per-peer in-flight cap)
async fn test_low_bandwidth_peer_drains_eventually() {
    let Some(chaos) = ChaoticDashd::start(1, TestChain::Full).await else {
        return;
    };
    chaos.add_bandwidth_limit(0, 50).await;

    let storage = tempfile::tempdir().expect("create storage tempdir");
    let mut handle = spawn_client_against(&chaos, &storage).await;

    let mut last_height = 0;
    let warmup_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < warmup_deadline {
        sleep(Duration::from_secs(5)).await;
        last_height = current_header_height(&handle);
    }

    let mut progress_windows = 0;
    for _ in 0..4 {
        sleep(Duration::from_secs(60)).await;
        let now_height = current_header_height(&handle);
        assert!(
            now_height >= last_height + 8_000,
            "no forward progress under 50 KB/s: {} -> {}",
            last_height,
            now_height,
        );
        last_height = now_height;
        progress_windows += 1;
    }

    handle.stop().await;
    assert!(progress_windows >= 4, "expected 4 progress windows");
    assert!(last_height >= 100_000, "header sync stalled below 100k: {}", last_height);
}

#[tokio::test]
#[ignore] // TODO: enable once fix #4/5e lands (capability gate accepts headers-only peers)
async fn test_capability_gate_does_not_starve_header_sync() {
    let Some(_chaos) = ChaoticDashd::start(2, TestChain::Minimal).await else {
        return;
    };

    todo!(
        "harness extension required: spawn a second dashd variant with COMPACT_FILTERS \
         disabled (e.g. -peerblockfilters=0) and expose it as a separate proxy slot. \
         Once available, assert that the headers-only peer is utilised for header sync."
    );
}

#[tokio::test]
#[ignore] // TODO: enable once fix #6 lands (filter sync resume after disconnect)
async fn test_filter_sync_resumes_after_disconnect() {
    let Some(chaos) = ChaoticDashd::start(3, TestChain::Full).await else {
        return;
    };
    let storage = tempfile::tempdir().expect("create storage tempdir");
    let mut handle = spawn_client_against(&chaos, &storage).await;

    wait_for_header_height(&mut handle, 30_000, Duration::from_secs(180)).await;
    let filter_tip_before = loop {
        sleep(Duration::from_secs(5)).await;
        let filters = current_filter_height(&handle);
        let filter_headers = current_filter_header_height(&handle);
        if filters >= 10_000 && filter_headers >= 30_000 {
            break filters;
        }
    };

    chaos.drop_all().await;
    sleep(Duration::from_secs(2)).await;
    chaos.restore_all().await;
    sleep(Duration::from_secs(60)).await;

    let filter_tip_after = current_filter_height(&handle);
    handle.stop().await;
    assert!(
        filter_tip_after > filter_tip_before,
        "filter sync wedged after reconnect: {} -> {}",
        filter_tip_before,
        filter_tip_after,
    );
}

#[tokio::test]
#[ignore] // TODO: enable once fix #7 lands (filter-headers livelock / silent peer rotation)
async fn test_filter_headers_rotates_off_silent_peer() {
    let Some(chaos) = ChaoticDashd::start(3, TestChain::Full).await else {
        return;
    };
    let storage = tempfile::tempdir().expect("create storage tempdir");
    let mut handle = spawn_client_against(&chaos, &storage).await;

    wait_for_header_height(&mut handle, 1_000, Duration::from_secs(60)).await;
    sleep(Duration::from_secs(2)).await;
    chaos.drop_connection(0).await;

    let before = current_filter_header_height(&handle);
    sleep(Duration::from_secs(90)).await;
    let after = current_filter_header_height(&handle);

    handle.stop().await;
    assert!(
        after > before,
        "filter-headers stayed pinned to silenced slot 0: {} -> {}",
        before,
        after,
    );
}

#[tokio::test]
#[ignore] // TODO: enable once fix #9 lands (`max_peers` config wiring)
async fn test_max_peers_config_takes_effect() {
    todo!(
        "harness extension required: a fleet of >8 candidate peer addresses including \
         idle TCP listeners. Once available, configure `ClientConfig::max_peers = 8`, \
         `target_peers = 8` and assert the resulting pool stabilises between 6 and 8."
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore] // TODO: enable once fix #9 lands (subnet diversity rule)
async fn test_subnet_diversity_enforced() {
    todo!(
        "harness extension required: bind multiple loopback aliases (127.0.0.X). \
         Multi-IP loopback is platform-dependent, hence the cfg(linux) gate. \
         Once available, configure 5 candidate peers in `127.0.0.0/24` plus 2 in a \
         different /16 with `target_peers = 5` and assert at most 1 peer per /24."
    );
}

#[tokio::test]
#[ignore] // TODO: enable once fix #10 lands (handshake accounting includes connecting set)
async fn test_simultaneous_disconnects_dont_overcommit_handshakes() {
    let Some(chaos) = ChaoticDashd::start(3, TestChain::Minimal).await else {
        return;
    };
    let storage = tempfile::tempdir().expect("create storage tempdir");
    let mut handle = spawn_client_against(&chaos, &storage).await;

    wait_for_header_height(&mut handle, 50, Duration::from_secs(60)).await;

    let mut connections_observed = 0;
    while handle.network_event_receiver.try_recv().is_ok() {
        connections_observed += 1;
    }
    assert!(connections_observed >= 3, "expected at least 3 initial connections");

    chaos.drop_all().await;

    let mut new_handshake_attempts = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Ok(NetworkEvent::PeerConnected {
            ..
        })) = timeout(Duration::from_millis(200), handle.network_event_receiver.recv()).await
        {
            new_handshake_attempts += 1;
        }
    }

    handle.stop().await;
    assert!(
        new_handshake_attempts <= 3,
        "fanned out {} handshake attempts after lockstep drop, exceeds max_peers=3",
        new_handshake_attempts,
    );
}

#[tokio::test]
#[ignore] // TODO: enable once fix #13 lands (reader iteration / 10ms sleep arm); timing-sensitive
async fn test_inbound_message_processed_promptly() {
    let Some(chaos) = ChaoticDashd::start(1, TestChain::Minimal).await else {
        return;
    };
    let storage = tempfile::tempdir().expect("create storage tempdir");
    let mut handle = spawn_client_against(&chaos, &storage).await;

    wait_for_header_height(&mut handle, 50, Duration::from_secs(60)).await;

    let mut samples = Vec::with_capacity(100);
    let dashd = chaos.dashd();
    if !dashd.supports_mining {
        handle.stop().await;
        return;
    }
    let address = dashd.node.get_new_address_from_wallet("default");

    for _ in 0..100 {
        let start = tokio::time::Instant::now();
        let _ = dashd.node.generate_blocks(1, &address);
        let _ = timeout(Duration::from_millis(200), handle.network_event_receiver.recv()).await;
        samples.push(start.elapsed());
    }

    samples.sort();
    let median = samples[samples.len() / 2];

    handle.stop().await;
    assert!(
        median < Duration::from_millis(5),
        "median inv -> handler latency {:?} exceeds 5ms budget; see comment for backup metric",
        median,
    );
}
