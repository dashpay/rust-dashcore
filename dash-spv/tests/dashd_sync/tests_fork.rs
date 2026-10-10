use std::time::Duration;

use dash_spv::test_utils::{create_test_wallet, next_unused_receive_address, TestChain};
use dash_spv::Network;
use dashcore::{Address, Amount};
use key_wallet_manager::WalletEvent;
use serde_json::json;

use super::helpers::{
    build_and_sign, count_wallet_transactions, wait_for_sync, wait_for_wallet_synced,
    EMPTY_MNEMONIC,
};
use super::setup::{create_and_start_client, TestContext};

/// Verify a synced client follows the network onto a longer branch that
/// replaces its last block, and that its wallet drops the coinbase it received
/// there and holds again the coin it spent there.
#[tokio::test]
async fn test_sync_follows_reorg() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }
    // Without mempool tracking the spend, back in dashd's mempool after the
    // reorg, is not seen again: only the chain decides what the wallet holds.
    let mut config = ctx.client_config.clone();
    config.enable_mempool_tracking = false;
    let (wallet, wallet_id) = create_test_wallet(EMPTY_MNEMONIC, Network::Regtest);
    let mut client_handle = create_and_start_client(&config, wallet.clone()).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    let node = &ctx.dashd.node;
    let miner_address = node.get_new_address();
    let funding_amount = 500_000_000;
    let address = next_unused_receive_address(&wallet, &wallet_id).await;
    let funding_txid = node.send_to_address(&address, Amount::from_sat(funding_amount));
    node.generate_blocks(1, &miner_address);
    let fork_height = ctx.dashd.initial_height + 1;
    wait_for_sync(&mut client_handle.progress_receiver, fork_height).await;
    wait_for_wallet_synced(&wallet, &wallet_id, fork_height).await;

    let destination = Address::dummy(Network::Regtest, 1);
    let (spend, _) =
        build_and_sign(&wallet, &wallet_id, &destination, 100_000_000).await.expect("build spend");
    client_handle.client.broadcast_transaction(&spend).await.expect("broadcast spend");
    tokio::time::timeout(Duration::from_secs(30), async {
        while !node
            .try_rpc_call("getrawmempool", &[])
            .is_some_and(|mempool| mempool.to_string().contains(&spend.txid().to_string()))
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("spend did not reach dashd's mempool");

    // The block the reorg replaces carries the spend and pays its coinbase to
    // the wallet. A coinbase cannot go back to the mempool, so no branch has it.
    let address = next_unused_receive_address(&wallet, &wallet_id).await;
    let replaced_block = node.generate_blocks(1, &address)[0];
    wait_for_sync(&mut client_handle.progress_receiver, fork_height + 1).await;
    wait_for_wallet_synced(&wallet, &wallet_id, fork_height + 1).await;
    assert_eq!(count_wallet_transactions(&wallet, &wallet_id).await, 3);

    // Replace it with a branch of 3 blocks that leave the spend out.
    let mut events = wallet.read().await.subscribe_events();
    node.invalidate_block(&replaced_block);
    for _ in 0..3 {
        node.try_rpc_call("generateblock", &[json!(miner_address.to_string()), json!([])])
            .expect("generateblock failed");
    }
    let new_tip = fork_height + 3;

    tokio::time::timeout(
        Duration::from_secs(60),
        wait_for_sync(&mut client_handle.progress_receiver, new_tip),
    )
    .await
    .expect("client did not follow the reorg");
    wait_for_wallet_synced(&wallet, &wallet_id, new_tip).await;
    assert_eq!(client_handle.client.tip_height().await, new_tip);
    assert_eq!(client_handle.client.tip_hash().await, Some(node.get_best_block_hash()));

    let balance = wallet.read().await.get_wallet_balance(&wallet_id).unwrap();
    assert_eq!(balance.total(), funding_amount, "only the funding coin is left, unspent");
    assert_eq!(balance.confirmed(), funding_amount);
    assert_eq!(count_wallet_transactions(&wallet, &wallet_id).await, 1);

    let funding_outpoint = spend
        .input
        .iter()
        .map(|input| input.previous_output)
        .find(|outpoint| outpoint.txid == funding_txid)
        .expect("the spend takes the funding output");
    let mut truncations = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let WalletEvent::ChainTruncated {
            height,
            txids,
            restored_outpoints,
            ..
        } = event
        {
            truncations.push((
                height,
                txids.len(),
                txids.contains(&spend.txid()),
                restored_outpoints,
            ));
        }
    }
    assert_eq!(
        truncations,
        vec![(fork_height, 2, true, vec![funding_outpoint])],
        "the persister is told what to drop and what to restore"
    );

    client_handle.stop().await;
}
