use std::sync::Arc;

use super::helpers::run_disconnect_loop;
use super::setup::{create_and_start_client, create_non_exclusive_test_config, TestContext};
use dash_spv::test_utils::TestChain;

/// Verify sync completes successfully despite peer disconnections mid-sync.
///
/// Waits for sync progress, then disconnects all peers via dashd RPC 3 times.
/// After each disconnection, validates that the SPV client observes a
/// `NetworkEvent::PeerDisconnected` followed by a `NetworkEvent::PeerConnected`
/// (automatic reconnection). After all disconnections, waits for full sync.
#[tokio::test]
async fn test_sync_with_peer_disconnection() {
    let Some(ctx) = TestContext::new(TestChain::Full).await else {
        return;
    };

    let num_disconnects = 3;
    let client_handle = ctx.spawn_new_client().await;

    run_disconnect_loop(client_handle, &ctx.dashd.node, num_disconnects, &ctx).await;
}

/// Verify sync completes in non-exclusive mode despite peer disconnections.
///
/// Unlike `test_sync_with_peer_disconnection` which uses exclusive mode (explicit
/// peers), this test uses non-exclusive mode where the peer is discovered via the
/// seeded peer store. The reconnection path goes through the normal peer discovery
/// mechanism (known addresses + DNS fallback) instead of the exclusive peer list.
#[tokio::test]
async fn test_sync_with_peer_disconnection_non_exclusive() {
    let Some(ctx) = TestContext::new(TestChain::Full).await else {
        return;
    };

    // Create non-exclusive config: no explicit peers, dashd seeded in peer store
    let non_exclusive_config =
        create_non_exclusive_test_config(ctx.storage_dir.path().to_path_buf(), ctx.dashd.addr)
            .await;

    let num_disconnects = 3;
    let client_handle =
        create_and_start_client(&non_exclusive_config, Arc::clone(&ctx.wallet)).await;

    run_disconnect_loop(client_handle, &ctx.dashd.node, num_disconnects, &ctx).await;
}
