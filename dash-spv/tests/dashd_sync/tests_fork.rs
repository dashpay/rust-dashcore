use std::time::Duration;

use super::helpers::wait_for_sync;
use super::setup::TestContext;
use dash_spv::test_utils::TestChain;

/// Verify a synced client follows the network onto a longer branch that
/// replaces its last blocks.
#[tokio::test]
async fn test_sync_follows_reorg() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }
    let mut client_handle = ctx.spawn_new_client().await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    // Replace the last 3 blocks with a branch of 5.
    let fork_height = ctx.dashd.initial_height - 3;
    let node = &ctx.dashd.node;
    node.invalidate_block(&node.get_block_hash(fork_height + 1));
    node.generate_blocks(5, &node.get_new_address());
    let new_tip = fork_height + 5;

    tokio::time::timeout(
        Duration::from_secs(60),
        wait_for_sync(&mut client_handle.progress_receiver, new_tip),
    )
    .await
    .expect("client did not follow the reorg");

    assert_eq!(client_handle.client.tip_height().await, new_tip);
    assert_eq!(client_handle.client.tip_hash().await, Some(node.get_best_block_hash()));

    client_handle.stop().await;
}
