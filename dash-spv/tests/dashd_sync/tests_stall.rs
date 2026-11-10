use std::time::Duration;

use dash_spv::network::NetworkEvent;
use dash_spv::test_utils::{TestChain, SYNC_TIMEOUT};
use dash_spv::SyncEvent;
use tokio::sync::broadcast::error::TryRecvError;

use super::helpers::{is_progress_event, wait_for_sync};
use super::setup::TestContext;

/// Verify a peer that goes silent mid-sync, as when our own link stalls, stays connected.
///
/// `SIGSTOP` freezes dashd with its socket open for well over a request timeout, but
/// under the bound for holding a silent peer. The client must keep its only peer through
/// the freeze, and sync must complete once dashd resumes.
#[tokio::test]
async fn test_sync_keeps_a_peer_frozen_mid_sync() {
    let Some(ctx) = TestContext::new(TestChain::Full).await else {
        return;
    };
    let mut client_handle = ctx.spawn_new_client().await;

    let mut progress_events = 0;
    tokio::time::timeout(SYNC_TIMEOUT, async {
        while progress_events < 5 {
            match client_handle.sync_event_receiver.recv().await {
                Ok(ref event) if is_progress_event(event) => progress_events += 1,
                Ok(SyncEvent::SyncComplete {
                    ..
                }) => panic!("sync completed before dashd could be frozen"),
                Ok(_) => {}
                Err(e) => panic!("sync events lost: {e}"),
            }
        }
    })
    .await
    .expect("Timeout waiting for sync progress");

    ctx.dashd.node.set_paused(true).await;
    tokio::time::sleep(Duration::from_secs(30)).await;
    ctx.dashd.node.set_paused(false).await;

    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;
    loop {
        match client_handle.network_event_receiver.try_recv() {
            Ok(NetworkEvent::PeerDisconnected(addr)) => panic!("peer {addr} was dropped"),
            Ok(_) => {}
            Err(TryRecvError::Empty) => break,
            Err(e) => panic!("network events lost: {e}"),
        }
    }

    client_handle.stop().await;
    ctx.assert_synced(&client_handle.client.progress().await).await;
}
