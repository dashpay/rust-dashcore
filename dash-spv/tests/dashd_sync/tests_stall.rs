use std::sync::Arc;
use std::time::Duration;

use dash_spv::network::NetworkEvent;
use dash_spv::test_utils::{DashdTestContext, TestChain, SYNC_TIMEOUT};
use dash_spv::{SyncEvent, SyncProgress};
use tokio::sync::broadcast::error::TryRecvError;
use tokio::time::{sleep, timeout};

use super::helpers::{is_progress_event, wait_for_network_event, wait_for_sync};
use super::setup::{create_and_start_client, TestContext};

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
    timeout(SYNC_TIMEOUT, async {
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
    // Sync may have finished while the loop above stopped reading, so the freeze must
    // be checked to fall mid-sync.
    while let Ok(event) = client_handle.sync_event_receiver.try_recv() {
        assert!(
            !matches!(event, SyncEvent::SyncComplete { .. }),
            "sync completed before dashd was frozen"
        );
    }
    assert!(
        !client_handle.client.progress().await.is_synced(),
        "sync completed before dashd was frozen"
    );
    sleep(Duration::from_secs(30)).await;
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

/// Verify one of two peers going silent during filter sync does not hold the filters back
/// until its requests time out.
///
/// The filter batches the frozen peer owes block the store. The other peer must deliver them
/// while the frozen one is still connected, so before a timeout drops it.
#[tokio::test]
async fn test_filter_sync_passes_a_frozen_peer() {
    let Some(ctx) = TestContext::new(TestChain::Full).await else {
        return;
    };
    let Some(frozen) = DashdTestContext::new(TestChain::Full).await else {
        return;
    };
    let tip = ctx.dashd.initial_height;
    let mut config = ctx.client_config.clone();
    config.add_peer(frozen.addr);
    let mut client_handle = create_and_start_client(&config, Arc::clone(&ctx.wallet)).await;

    let both_connected = wait_for_network_event(
        &mut client_handle.network_event_receiver,
        |event| {
            matches!(event, NetworkEvent::PeersUpdated { addresses, .. } if addresses.len() == 2)
        },
        SYNC_TIMEOUT,
    )
    .await;
    assert!(both_connected, "expected the client to connect to both nodes");
    // Past the headers and filter headers, the frozen peer can only owe filters and blocks.
    timeout(SYNC_TIMEOUT, async {
        loop {
            match client_handle.sync_event_receiver.recv().await {
                Ok(SyncEvent::FilterHeadersStored {
                    tip_height,
                    ..
                }) if tip_height == tip => break,
                Ok(_) => {}
                Err(e) => panic!("sync events lost: {e}"),
            }
        }
    })
    .await
    .expect("Timeout waiting for filter headers");
    frozen.node.set_paused(true).await;

    let mut progress = client_handle.progress_receiver.clone();
    let stored = |progress: &SyncProgress| progress.filters().unwrap().stored_height();
    assert!(stored(&progress.borrow()) < tip, "filters were stored before the freeze");
    timeout(SYNC_TIMEOUT, async {
        while stored(&progress.borrow_and_update()) < tip {
            tokio::select! {
                changed = progress.changed() => changed.expect("progress channel closed"),
                event = client_handle.network_event_receiver.recv() => {
                    if let NetworkEvent::PeerDisconnected(addr) = event.expect("network events lost") {
                        panic!("peer {addr} was dropped before the filters were stored");
                    }
                }
            }
        }
    })
    .await
    .expect("Timeout waiting for the filters");

    frozen.node.set_paused(false).await;
    wait_for_sync(&mut client_handle.progress_receiver, tip).await;
    client_handle.stop().await;
    ctx.assert_synced(&client_handle.client.progress().await).await;
}
