use std::collections::HashSet;
use std::time::Duration;

use dash_spv::client::config::MempoolStrategy;
use dash_spv::network::NetworkEvent;
use dash_spv::test_utils::{DashdTestContext, TestChain};
use dashcore::Amount;

use super::helpers::{
    assert_no_mempool_tx_both, wait_for_mempool_synced_both, wait_for_mempool_tx_both,
    wait_for_mempool_txs_both, wait_for_network_event, wait_for_network_event_both,
    wait_for_sync_both,
};
use super::setup::{
    client_has_transaction, create_and_start_client, create_test_wallet, TestContext,
};

const MEMPOOL_TIMEOUT: Duration = Duration::from_secs(30);

/// Verify mempool detects an incoming wallet transaction using both strategies.
#[tokio::test]
async fn test_mempool_detects_incoming_tx() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let (mut fa, _fa_dir) = ctx.spawn_client(MempoolStrategy::FetchAll).await;
    let (mut bf, _bf_dir) = ctx.spawn_client(MempoolStrategy::BloomFilter).await;
    wait_for_sync_both(&mut fa, &mut bf, ctx.dashd.initial_height).await;

    let receive_address = ctx.receive_address().await;
    let txid = ctx.dashd.node.send_to_address(&receive_address, Amount::from_sat(100_000_000));
    tracing::info!("Sent tx to SPV wallet, txid: {}", txid);

    let mempool_txid = wait_for_mempool_tx_both(&mut fa, &mut bf, MEMPOOL_TIMEOUT)
        .await
        .expect("Expected TransactionReceived event");
    assert_eq!(mempool_txid, txid, "Mempool event txid should match sent txid");

    fa.stop().await;
    bf.stop().await;
    tracing::info!("test_mempool_detects_incoming_tx passed");
}

/// Verify mempool ignores transactions not relevant to the SPV wallet.
#[tokio::test]
async fn test_mempool_ignores_irrelevant_tx() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    // Fund the "default" wallet with a regular (non-coinbase) output so it's
    // immediately spendable. Send from the primary wallet and mine the tx.
    let default_addr = ctx.dashd.node.get_new_address_from_wallet("default");
    ctx.dashd.node.send_to_address(&default_addr, Amount::from_sat(100_000_000));
    let miner_addr = ctx.dashd.node.get_new_address_from_wallet("default");
    ctx.dashd.node.generate_blocks(1, &miner_addr);
    let funded_height = ctx.dashd.initial_height + 1;

    let (mut fa, _fa_dir) = ctx.spawn_client(MempoolStrategy::FetchAll).await;
    let (mut bf, _bf_dir) = ctx.spawn_client(MempoolStrategy::BloomFilter).await;
    wait_for_sync_both(&mut fa, &mut bf, funded_height).await;

    // Send from the "default" wallet to itself (no relation to SPV wallet)
    let non_wallet_address = ctx.dashd.node.get_new_address_from_wallet("default");
    let txid = ctx.dashd.node.send_to_address_from_wallet(
        "default",
        &non_wallet_address,
        Amount::from_sat(50_000_000),
    );
    tracing::info!("Sent irrelevant tx (not to SPV wallet), txid: {}", txid);

    assert_no_mempool_tx_both(&mut fa, &mut bf, Duration::from_secs(3)).await;

    fa.stop().await;
    bf.stop().await;
    tracing::info!("test_mempool_ignores_irrelevant_tx passed");
}

/// Verify a mempool transaction transitions to confirmed after mining.
#[tokio::test]
async fn test_mempool_to_confirmed_lifecycle() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let (mut fa, _fa_dir) = ctx.spawn_client(MempoolStrategy::FetchAll).await;
    let (mut bf, _bf_dir) = ctx.spawn_client(MempoolStrategy::BloomFilter).await;
    wait_for_sync_both(&mut fa, &mut bf, ctx.dashd.initial_height).await;

    let receive_address = ctx.receive_address().await;
    let txid = ctx.dashd.node.send_to_address(&receive_address, Amount::from_sat(100_000_000));
    tracing::info!("Sent tx to SPV wallet (lifecycle test), txid: {}", txid);

    let mempool_txid = wait_for_mempool_tx_both(&mut fa, &mut bf, MEMPOOL_TIMEOUT)
        .await
        .expect("Expected TransactionReceived event");
    assert_eq!(mempool_txid, txid);

    // Mine the transaction
    let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
    ctx.dashd.node.generate_blocks(1, &miner_address);
    let new_height = ctx.dashd.initial_height + 1;
    wait_for_sync_both(&mut fa, &mut bf, new_height).await;

    assert!(
        client_has_transaction(&fa.client, &ctx.wallet_id, &txid).await,
        "FetchAll: confirmed tx should be in wallet"
    );
    assert!(
        client_has_transaction(&bf.client, &ctx.wallet_id, &txid).await,
        "BloomFilter: confirmed tx should be in wallet"
    );

    fa.stop().await;
    bf.stop().await;
    tracing::info!("test_mempool_to_confirmed_lifecycle passed");
}

/// Verify multiple mempool transactions are all detected.
#[tokio::test]
async fn test_mempool_multiple_txs() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let (mut fa, _fa_dir) = ctx.spawn_client(MempoolStrategy::FetchAll).await;
    let (mut bf, _bf_dir) = ctx.spawn_client(MempoolStrategy::BloomFilter).await;
    wait_for_sync_both(&mut fa, &mut bf, ctx.dashd.initial_height).await;

    let receive_address = ctx.receive_address().await;
    let amounts =
        [Amount::from_sat(50_000_000), Amount::from_sat(75_000_000), Amount::from_sat(120_000_000)];
    let mut expected_txids = HashSet::new();
    for amount in &amounts {
        let txid = ctx.dashd.node.send_to_address(&receive_address, *amount);
        tracing::info!("Sent {} to SPV wallet (multi-tx test), txid: {}", amount, txid);
        expected_txids.insert(txid);
    }

    let received_txids = wait_for_mempool_txs_both(&mut fa, &mut bf, 3, MEMPOOL_TIMEOUT).await;
    assert_eq!(received_txids, expected_txids, "Received mempool txids should match sent txids");

    fa.stop().await;
    bf.stop().await;
    tracing::info!("test_mempool_multiple_txs passed");
}

/// Verify mempool detects both incoming (address match) and outgoing (outpoint match) transactions.
///
/// 1. Sync to tip
/// 2. Send from "default" wallet TO the SPV wallet receive address (incoming)
/// 3. Wait for mempool event (address match)
/// 4. Mine the tx so it becomes a confirmed UTXO in the SPV wallet
/// 5. Craft a raw tx that spends the wallet UTXO with all outputs going to an external
///    "default" address (no change back to the wallet) and broadcast it
/// 6. Wait for mempool event (outpoint match only, no address match)
/// 7. Assert both txids were detected
#[tokio::test]
async fn test_mempool_incoming_and_outgoing_tx() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let (mut fa, _fa_dir) = ctx.spawn_client(MempoolStrategy::FetchAll).await;
    let (mut bf, _bf_dir) = ctx.spawn_client(MempoolStrategy::BloomFilter).await;
    wait_for_sync_both(&mut fa, &mut bf, ctx.dashd.initial_height).await;

    // Step 1: Send an incoming transaction to the SPV wallet
    let receive_address = ctx.receive_address().await;
    let incoming_amount = Amount::from_sat(200_000_000);
    let incoming_txid = ctx.dashd.node.send_to_address(&receive_address, incoming_amount);
    tracing::info!("Sent incoming tx to SPV wallet, txid: {}", incoming_txid);

    let mempool_txid = wait_for_mempool_tx_both(&mut fa, &mut bf, MEMPOOL_TIMEOUT)
        .await
        .expect("Expected mempool event for incoming tx");
    assert_eq!(mempool_txid, incoming_txid);

    // Step 2: Mine the incoming tx so it becomes a confirmed UTXO
    let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
    ctx.dashd.node.generate_blocks(1, &miner_address);
    let mined_height = ctx.dashd.initial_height + 1;
    wait_for_sync_both(&mut fa, &mut bf, mined_height).await;

    // Step 3: Craft a raw transaction that spends the wallet UTXO with all outputs
    // going to an external address. This ensures the mempool detects it purely via
    // the watched outpoint, not via any output address match.
    let wallet_name = &ctx.dashd.wallet.wallet_name;
    let utxos = ctx.dashd.node.list_unspent_from_wallet(wallet_name);
    let utxo = utxos
        .iter()
        .find(|u| u.txid == incoming_txid)
        .expect("Incoming tx UTXO not found in wallet");

    let external_address = ctx.dashd.node.get_new_address_from_wallet("default");
    let fee = Amount::from_sat(10_000);
    let outgoing_txid = ctx.dashd.node.send_raw_from_wallet(
        wallet_name,
        utxo.txid,
        utxo.vout,
        utxo.amount,
        &external_address,
        fee,
    );
    tracing::info!("Sent raw outgoing tx (outpoint-only match), txid: {}", outgoing_txid);

    let mempool_txid = wait_for_mempool_tx_both(&mut fa, &mut bf, MEMPOOL_TIMEOUT)
        .await
        .expect("Expected mempool event for outgoing tx (outpoint match)");
    assert_eq!(mempool_txid, outgoing_txid);

    fa.stop().await;
    bf.stop().await;
    tracing::info!("test_mempool_incoming_and_outgoing_tx passed");
}

/// Verify full mempool lifecycle: detection, disconnect recovery, and confirmation.
///
/// 1. Sync to tip with empty mempool
/// 2. Send 2 transactions, verify both arrive via mempool events
/// 3. Disconnect the SPV client from the peer (via dashd disconnectnode)
/// 4. Send 1 transaction while disconnected (it sits in dashd's mempool)
/// 5. Reconnect and wait for mempool reactivation
/// 6. Verify the tx sent while disconnected is detected (mempool dump on reconnect)
/// 7. Verify all 3 transactions are tracked
/// 8. Mine a block, verify all txs transition to confirmed, mempool count drops to 0
#[tokio::test]
async fn test_mempool_lifecycle() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let (mut fa, _fa_dir) = ctx.spawn_client(MempoolStrategy::FetchAll).await;
    let (mut bf, _bf_dir) = ctx.spawn_client(MempoolStrategy::BloomFilter).await;
    wait_for_sync_both(&mut fa, &mut bf, ctx.dashd.initial_height).await;

    // Wait for mempool activation before sending transactions
    wait_for_mempool_synced_both(&mut fa, &mut bf).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    tracing::info!("Mempool synced on both clients");

    // Step 1: Send 2 transactions, verify both arrive
    let receive_address = ctx.receive_address().await;
    let txid1 = ctx.dashd.node.send_to_address(&receive_address, Amount::from_sat(50_000_000));
    let txid2 = ctx.dashd.node.send_to_address(&receive_address, Amount::from_sat(60_000_000));
    tracing::info!("Sent tx1={}, tx2={}", txid1, txid2);

    let received = wait_for_mempool_txs_both(&mut fa, &mut bf, 2, MEMPOOL_TIMEOUT).await;
    assert!(received.contains(&txid1), "Should have received tx1");
    assert!(received.contains(&txid2), "Should have received tx2");

    // Step 2: Disconnect the peer
    ctx.dashd.node.disconnect_all_peers();
    let saw_disconnect = wait_for_network_event_both(
        &mut fa,
        &mut bf,
        |e| matches!(e, NetworkEvent::PeerDisconnected { .. }),
        Duration::from_secs(10),
    )
    .await;
    assert!(saw_disconnect, "Both clients should observe PeerDisconnected");

    // Step 3: Send a transaction while disconnected
    let txid3 = ctx.dashd.node.send_to_address(&receive_address, Amount::from_sat(70_000_000));
    tracing::info!("Sent tx3={} while disconnected", txid3);

    // Step 4: Reconnect and wait for mempool reactivation
    let saw_reconnect = wait_for_network_event_both(
        &mut fa,
        &mut bf,
        |e| matches!(e, NetworkEvent::PeerConnected { .. }),
        Duration::from_secs(30),
    )
    .await;
    assert!(saw_reconnect, "Both clients should reconnect to peer");

    wait_for_mempool_synced_both(&mut fa, &mut bf).await;
    tracing::info!("Mempool reactivated after reconnect on both clients");

    // Step 5: Verify tx sent while disconnected is detected via mempool dump
    let detected = wait_for_mempool_tx_both(&mut fa, &mut bf, MEMPOOL_TIMEOUT)
        .await
        .expect("Expected mempool event for tx sent while disconnected");
    assert_eq!(detected, txid3, "Should detect tx3 via mempool dump on reconnect");

    // Step 6: Mine a block, verify all txs confirmed
    let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
    ctx.dashd.node.generate_blocks(1, &miner_address);
    let new_height = ctx.dashd.initial_height + 1;
    wait_for_sync_both(&mut fa, &mut bf, new_height).await;

    for (label, client) in [("FetchAll", &fa.client), ("BloomFilter", &bf.client)] {
        assert!(
            client_has_transaction(client, &ctx.wallet_id, &txid1).await,
            "{}: tx1 should be confirmed",
            label
        );
        assert!(
            client_has_transaction(client, &ctx.wallet_id, &txid2).await,
            "{}: tx2 should be confirmed",
            label
        );
        assert!(
            client_has_transaction(client, &ctx.wallet_id, &txid3).await,
            "{}: tx3 should be confirmed",
            label
        );
    }

    fa.stop().await;
    bf.stop().await;
    tracing::info!("test_mempool_lifecycle passed");
}

/// Verify mempool handles peer disconnection with multi-peer activation.
///
/// Uses two dashd nodes connected to each other. Both SPV clients connect to both peers and
/// exercise these scenarios in sequence:
/// 1. Both peers active after sync — send tx, verify detection
/// 2. Disconnect one peer — no event expected, send tx from remaining, verify detection
/// 3. Disconnect both, reconnect — wait for mempool Synced state, verify detection
#[tokio::test]
async fn test_mempool_peer_disconnect_reactivation() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let Some(dashd2) = DashdTestContext::new(TestChain::Minimal).await else {
        eprintln!("Skipping test (could not create second dashd node)");
        return;
    };

    // Connect the two dashd nodes so mempool transactions propagate between them
    ctx.dashd.node.connect_to_node(dashd2.addr).await;

    // Spawn both SPV clients with both peers configured
    let mut fa_config = ctx.client_config.clone();
    fa_config.add_peer(dashd2.addr);

    let fa_storage = tempfile::TempDir::new().expect("Failed to create FetchAll temp dir");
    let bf_storage = tempfile::TempDir::new().expect("Failed to create BloomFilter temp dir");

    let mut fa_cfg = fa_config.clone();
    fa_cfg.storage_path = fa_storage.path().to_path_buf();
    fa_cfg.mempool_strategy = MempoolStrategy::FetchAll;

    let mut bf_cfg = fa_config.clone();
    bf_cfg.storage_path = bf_storage.path().to_path_buf();
    bf_cfg.mempool_strategy = MempoolStrategy::BloomFilter;

    let (fa_wallet, _) = create_test_wallet(&ctx.dashd.wallet.mnemonic, dash_spv::Network::Regtest);
    let (bf_wallet, _) = create_test_wallet(&ctx.dashd.wallet.mnemonic, dash_spv::Network::Regtest);

    let mut fa = create_and_start_client(&fa_cfg, fa_wallet).await;
    let mut bf = create_and_start_client(&bf_cfg, bf_wallet).await;

    // Sync both clients
    wait_for_sync_both(&mut fa, &mut bf, ctx.dashd.initial_height).await;

    // Both peers should be activated after sync
    wait_for_mempool_synced_both(&mut fa, &mut bf).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    tracing::info!("Mempool synced on all peers for both clients");

    // --- Scenario 1: baseline mempool detection with both peers ---
    let receive_address = ctx.receive_address().await;
    let txid1 = ctx.dashd.node.send_to_address(&receive_address, Amount::from_sat(50_000_000));
    tracing::info!("[scenario 1] sent tx {}", txid1);

    let detected = wait_for_mempool_tx_both(&mut fa, &mut bf, MEMPOOL_TIMEOUT)
        .await
        .expect("Scenario 1: expected mempool tx detection");
    assert_eq!(detected, txid1);

    // --- Scenario 2: disconnect one peer, verify detection still works ---
    // Resubscribe to get fresh receivers, avoiding stale events or lagged errors
    // from earlier phases that could cause the wait to miss the disconnect event.
    let mut fa_net_rx = fa.network_event_receiver.resubscribe();
    let mut bf_net_rx = bf.network_event_receiver.resubscribe();

    ctx.dashd.node.disconnect_all_peers();

    let (fa_disc, bf_disc) = tokio::join!(
        wait_for_network_event(
            &mut fa_net_rx,
            |e| matches!(e, NetworkEvent::PeerDisconnected { address } if *address == ctx.dashd.addr),
            Duration::from_secs(10),
        ),
        wait_for_network_event(
            &mut bf_net_rx,
            |e| matches!(e, NetworkEvent::PeerDisconnected { address } if *address == ctx.dashd.addr),
            Duration::from_secs(10),
        ),
    );
    assert!(fa_disc, "FetchAll: should observe PeerDisconnected");
    assert!(bf_disc, "BloomFilter: should observe PeerDisconnected");
    tokio::time::sleep(Duration::from_secs(1)).await;

    let txid2 = dashd2.node.send_to_address(&receive_address, Amount::from_sat(60_000_000));
    tracing::info!("[scenario 2] sent tx {} from remaining peer", txid2);

    let detected = wait_for_mempool_tx_both(&mut fa, &mut bf, MEMPOOL_TIMEOUT)
        .await
        .expect("Scenario 2: expected mempool tx detection from remaining peer");
    assert_eq!(detected, txid2);

    // --- Scenario 3: disconnect both peers, verify recovery ---
    ctx.dashd.node.set_network_active(false);
    dashd2.node.set_network_active(false);

    // Wait for both disconnect events on both clients
    for (label, receiver) in [
        ("FetchAll", &mut fa.network_event_receiver),
        ("BloomFilter", &mut bf.network_event_receiver),
    ] {
        let mut seen_dashd1 = false;
        let mut seen_dashd2 = false;
        let deadline = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(deadline);
        while !seen_dashd1 || !seen_dashd2 {
            tokio::select! {
                _ = &mut deadline => panic!("{}: timed out waiting for both peer disconnects", label),
                result = receiver.recv() => {
                    match result {
                        Ok(NetworkEvent::PeerDisconnected { address }) if address == ctx.dashd.addr => {
                            seen_dashd1 = true;
                        }
                        Ok(NetworkEvent::PeerDisconnected { address }) if address == dashd2.addr => {
                            seen_dashd2 = true;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    tracing::info!("[scenario 3] both peers disconnected from both clients");

    // Re-enable networking so SPV can reconnect
    ctx.dashd.node.set_network_active(true);
    dashd2.node.set_network_active(true);
    ctx.dashd.node.connect_to_node(dashd2.addr).await;

    // Wait for reconnection and mempool reactivation on both clients
    let saw_reconnect = wait_for_network_event_both(
        &mut fa,
        &mut bf,
        |e| matches!(e, NetworkEvent::PeerConnected { .. }),
        Duration::from_secs(30),
    )
    .await;
    assert!(saw_reconnect, "Both clients should reconnect to a peer");

    wait_for_mempool_synced_both(&mut fa, &mut bf).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    tracing::info!("[scenario 3] mempool recovered on both clients");

    let txid3 = ctx.dashd.node.send_to_address(&receive_address, Amount::from_sat(70_000_000));
    tracing::info!("[scenario 3] sent tx {}", txid3);

    let detected = wait_for_mempool_tx_both(&mut fa, &mut bf, MEMPOOL_TIMEOUT)
        .await
        .expect("Scenario 3: expected mempool tx detection after recovery");
    assert_eq!(detected, txid3);

    fa.stop().await;
    bf.stop().await;
    tracing::info!("test_mempool_peer_disconnect_reactivation passed");
}

/// Verify that a locally broadcast transaction is immediately visible in mempool state.
#[tokio::test]
async fn test_broadcast_transaction_local_detection() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let (mut fa, _fa_dir) = ctx.spawn_client(MempoolStrategy::FetchAll).await;
    let (mut bf, _bf_dir) = ctx.spawn_client(MempoolStrategy::BloomFilter).await;
    wait_for_sync_both(&mut fa, &mut bf, ctx.dashd.initial_height).await;

    // Step 1: Fund the SPV wallet with a confirmed UTXO
    let receive_address = ctx.receive_address().await;
    let funding_amount = Amount::from_sat(200_000_000);
    let funding_txid = ctx.dashd.node.send_to_address(&receive_address, funding_amount);

    wait_for_mempool_tx_both(&mut fa, &mut bf, MEMPOOL_TIMEOUT)
        .await
        .expect("Expected mempool event for funding tx");

    let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
    ctx.dashd.node.generate_blocks(1, &miner_address);
    let mined_height = ctx.dashd.initial_height + 1;
    wait_for_sync_both(&mut fa, &mut bf, mined_height).await;

    // Step 2: Create a signed transaction without broadcasting via dashd
    let wallet_name = &ctx.dashd.wallet.wallet_name;
    let utxos = ctx.dashd.node.list_unspent_from_wallet(wallet_name);
    let utxo =
        utxos.iter().find(|u| u.txid == funding_txid).expect("Funding tx UTXO not found in wallet");

    let external_address = ctx.dashd.node.get_new_address_from_wallet("default");
    let fee = Amount::from_sat(10_000);
    let signed_tx = ctx.dashd.node.create_signed_transaction(
        wallet_name,
        utxo.txid,
        utxo.vout,
        utxo.amount,
        &external_address,
        fee,
    );
    let txid = signed_tx.txid();
    tracing::info!("Created signed tx for SPV broadcast, txid: {}", txid);

    // Step 3: Broadcast via the SPV client (not via dashd)
    fa.client.broadcast_transaction(&signed_tx).await.expect("broadcast_transaction failed");
    tracing::info!("Broadcast tx via FetchAll client");

    // The locally dispatched transaction should be picked up by the mempool manager
    let detected = wait_for_mempool_tx_both(&mut fa, &mut bf, MEMPOOL_TIMEOUT)
        .await
        .expect("Expected TransactionReceived event after broadcast");
    assert_eq!(detected, txid, "Detected txid should match broadcast txid");

    // Step 4: Mine the broadcast tx and verify it transitions to confirmed
    ctx.dashd.node.generate_blocks(1, &miner_address);
    let confirmed_height = mined_height + 1;
    wait_for_sync_both(&mut fa, &mut bf, confirmed_height).await;
    assert!(
        client_has_transaction(&fa.client, &ctx.wallet_id, &txid).await,
        "FetchAll: broadcast tx should be confirmed in wallet"
    );
    assert!(
        client_has_transaction(&bf.client, &ctx.wallet_id, &txid).await,
        "BloomFilter: broadcast tx should be confirmed in wallet"
    );

    fa.stop().await;
    bf.stop().await;
    tracing::info!("test_broadcast_transaction_local_detection passed");
}
