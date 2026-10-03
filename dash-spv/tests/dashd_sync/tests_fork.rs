use std::time::Duration;

use dash_spv::test_utils::{create_test_wallet, next_unused_receive_address, TestChain};
use dash_spv::Network;

use super::helpers::{count_wallet_transactions, wait_for_sync, EMPTY_MNEMONIC};
use super::setup::{create_and_start_client, TestContext};

/// Verify a synced client follows the network onto a longer branch that
/// replaces its last block, and drops the funds its wallet received there.
#[tokio::test]
async fn test_sync_follows_reorg() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }
    let (wallet, wallet_id) = create_test_wallet(EMPTY_MNEMONIC, Network::Regtest);
    let mut client_handle = create_and_start_client(&ctx.client_config, wallet.clone()).await;
    let fork_height = ctx.dashd.initial_height;
    wait_for_sync(&mut client_handle.progress_receiver, fork_height).await;

    // Fund the wallet with the coinbase of a block the reorg replaces. A coinbase
    // cannot go back to the mempool, so the new branch does not include it.
    let node = &ctx.dashd.node;
    let address = next_unused_receive_address(&wallet, &wallet_id).await;
    let funding_block = node.generate_blocks(1, &address)[0];
    wait_for_sync(&mut client_handle.progress_receiver, fork_height + 1).await;
    let balance = wallet.read().await.get_wallet_balance(&wallet_id).unwrap().total();
    assert!(balance > 0, "the coinbase funds the wallet");

    // Replace the funding block with a branch of 3.
    node.invalidate_block(&funding_block);
    node.generate_blocks(3, &node.get_new_address());
    let new_tip = fork_height + 3;

    tokio::time::timeout(
        Duration::from_secs(60),
        wait_for_sync(&mut client_handle.progress_receiver, new_tip),
    )
    .await
    .expect("client did not follow the reorg");
    assert_eq!(client_handle.client.tip_height().await, new_tip);
    assert_eq!(client_handle.client.tip_hash().await, Some(node.get_best_block_hash()));

    let balance = wallet.read().await.get_wallet_balance(&wallet_id).unwrap().total();
    assert_eq!(balance, 0, "the reorg dropped the funding coinbase");
    assert_eq!(count_wallet_transactions(&wallet, &wallet_id).await, 0);

    client_handle.stop().await;
}
