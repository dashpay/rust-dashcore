use std::time::Duration;

use dash_spv::client::ClientConfig;
use dash_spv::sync::ProgressPercentage;
use dash_spv::test_utils::{ChaoticDashd, TestChain};
use dash_spv::Network;
use tokio::process::Command;
use tokio::time::{sleep, timeout};

use super::setup::{create_and_start_client, create_test_wallet};

const SMOKE_HEADER_TARGET: u32 = 100;
const SMOKE_SYNC_TIMEOUT: Duration = Duration::from_secs(60);

#[tokio::test]
async fn test_chaos_harness_smoke() {
    let Some(chaos) = ChaoticDashd::start(2, TestChain::Minimal).await else {
        return;
    };
    assert_eq!(chaos.slot_count(), 2);
    let toxiproxy_pid = chaos.toxiproxy_pid().expect("toxiproxy pid");

    let storage = tempfile::tempdir().expect("create storage tempdir");
    let mut config = ClientConfig::regtest()
        .with_storage_path(storage.path().to_path_buf())
        .without_masternodes();
    for addr in chaos.p2p_addrs() {
        config.add_peer(addr);
    }

    let (wallet, _wallet_id) = create_test_wallet(&chaos.dashd().wallet.mnemonic, Network::Regtest);

    let mut handle = create_and_start_client(&config, wallet).await;

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
