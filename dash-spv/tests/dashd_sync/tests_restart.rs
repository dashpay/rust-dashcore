use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashSet;
use std::fs;
use std::sync::Arc;
use std::time::Duration;

use dash_spv::Network;
use dash_spv::{SyncEvent, SyncProgress};

use super::helpers::{
    get_spendable_balance, is_progress_event, wait_for_sync, wait_for_sync_complete,
    wait_for_wallet_synced, PeerTracker, EMPTY_MNEMONIC,
};
use dash_spv::test_utils::SYNC_TIMEOUT;

use super::setup::{create_and_start_client, TestContext};
use dash_spv::test_utils::{create_test_wallet, default_test_account_options, TestChain};

/// Verify sync state is identical after stopping and restarting with same storage,
/// and that a corrupted segment of it is wiped and synced again.
#[tokio::test]
async fn test_sync_restart_consistency() {
    let Some(ctx) = TestContext::new(TestChain::Full).await else {
        return;
    };

    // First sync
    tracing::info!("Starting first sync");
    let mut client_handle = ctx.spawn_new_client().await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;
    let mut tracker = PeerTracker::default();
    tracker.update(&mut client_handle.network_event_receiver);
    assert!(tracker.peers.contains(&ctx.dashd.addr), "synced through the dashd peer");

    // The handler must hear the peers go, or it keeps reporting peers the client dropped.
    client_handle.stop().await;
    tracker.update(&mut client_handle.network_event_receiver);
    assert!(tracker.peers.is_empty(), "peers still tracked after stop: {:?}", tracker.peers);
    assert_eq!(tracker.listed, Some(HashSet::new()));
    ctx.assert_synced(&client_handle.client.progress().await).await;
    let first_balance = ctx.spendable_balance().await;
    let first_tx_count = ctx.transaction_count().await;

    drop(client_handle);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Restart with same storage and wallet
    tracing::info!("Restarting with same storage");
    let mut client_handle = ctx.spawn_new_client().await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    client_handle.stop().await;
    ctx.assert_synced(&client_handle.client.progress().await).await;
    let second_balance = ctx.spendable_balance().await;
    let second_tx_count = ctx.transaction_count().await;

    // Validate state is identical across restarts
    assert_eq!(first_balance, second_balance, "Balance mismatch after restart");
    assert_eq!(first_tx_count, second_tx_count, "Transaction count mismatch after restart");
    tracing::info!("State consistent after restart");

    drop(client_handle);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let segment = ctx.client_config.storage_path.join("block_headers").join("segment_000000.dat");
    let original_segment = fs::read(&segment).unwrap();
    let mut corrupted_segment = original_segment.clone();
    corrupted_segment[0] ^= 1;
    fs::write(&segment, corrupted_segment).unwrap();

    tracing::info!("Restarting with a corrupted segment");
    let mut client_handle = ctx.spawn_new_client().await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    client_handle.stop().await;
    ctx.assert_synced(&client_handle.client.progress().await).await;
    assert_eq!(first_balance, ctx.spendable_balance().await, "Balance mismatch after resync");
    assert_eq!(
        first_tx_count,
        ctx.transaction_count().await,
        "Transaction count mismatch after resync"
    );
    assert_eq!(fs::read(&segment).unwrap(), original_segment, "Corrupted segment not synced again");

    // A block mined right after a fully-synced restart must commit through the
    // Filters phase instead of freezing `committed_height` one below the new
    // tip. `wait_for_sync` checks the filters committed height, so the wedge
    // surfaces as a timeout here.
    if ctx.dashd.supports_mining {
        drop(client_handle);
        tokio::time::sleep(Duration::from_millis(100)).await;

        tracing::info!("Restarting fully synced, then mining a boundary block");
        let mut client_handle = ctx.spawn_new_client().await;
        wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

        let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
        ctx.dashd.node.generate_blocks(1, &miner_address);
        wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height + 1).await;
        client_handle.stop().await;
    } else {
        eprintln!("Skipping boundary-block restart check (dashd RPC miner not available)");
    }
}

/// Verify correct rescan behavior when restarting with a fresh wallet but existing storage.
#[tokio::test]
async fn test_sync_restart_with_fresh_wallet() {
    let Some(ctx) = TestContext::new(TestChain::Full).await else {
        return;
    };

    // First sync
    tracing::info!("Starting first sync");
    let mut client_handle = ctx.spawn_new_client().await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    client_handle.stop().await;
    ctx.assert_synced(&client_handle.client.progress().await).await;

    drop(client_handle);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Restart with fresh wallet (triggers rescan)
    tracing::info!("Restarting with fresh wallet (triggers rescan)");
    let (fresh_wallet, fresh_wallet_id) =
        create_test_wallet(&ctx.dashd.wallet.mnemonic, Network::Regtest);

    {
        let balance = get_spendable_balance(&fresh_wallet, &fresh_wallet_id).await;
        assert_eq!(balance, 0, "Fresh wallet should start with zero balance");
    }

    let mut client_handle =
        create_and_start_client(&ctx.client_config, Arc::clone(&fresh_wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    client_handle.stop().await;
    ctx.assert_wallet_synced(
        &client_handle.client.progress().await,
        &fresh_wallet,
        &fresh_wallet_id,
    )
    .await;
}

/// Verify sync completes successfully despite repeated interruptions.
///
/// Listens for key sync events (BlockHeadersStored, FilterHeadersStored, FiltersStored,
/// BlocksNeeded, BlockProcessed) and restarts the client on every 2nd occurrence until
/// sync completes. This exercises restart/resume from unpredictable points across the
/// full sync lifecycle.
#[tokio::test]
async fn test_sync_with_multiple_restarts() {
    let Some(ctx) = TestContext::new(TestChain::Full).await else {
        return;
    };

    // Restarting on every 2nd progress event until completion takes hundreds of cycles.
    const MAX_RESTARTS: usize = 8;

    let mut restart_count = 0;
    let final_progress = loop {
        tracing::info!("Starting sync (restart count: {})", restart_count);
        let mut client_handle = ctx.spawn_new_client().await;
        let final_run = restart_count >= MAX_RESTARTS;

        // Wait for either sync completion or the 2nd matching event
        let mut events_seen = 0;
        let mut should_restart = false;
        let timeout = tokio::time::sleep(SYNC_TIMEOUT);
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                _ = &mut timeout => {
                    let progress = client_handle.progress_receiver.borrow();
                    panic!(
                        "Timeout after {} restarts. Current progress: {:?}",
                        restart_count, progress
                    );
                }
                result = client_handle.sync_event_receiver.recv() => {
                    match result {
                        Ok(ref event) if is_progress_event(event) => {
                            events_seen += 1;
                            if !final_run && events_seen % 2 == 0 {
                                tracing::info!("Restarting on: {}", event);
                                should_restart = true;
                                break;
                            }
                            tracing::info!("Skipped: {}", event);
                        }
                        Ok(SyncEvent::SyncComplete { .. }) => break,
                        Ok(_) => continue,
                        Err(_) => {
                            panic!("Sync event channel error after {} restarts", restart_count);
                        }
                    }
                }
            }
        }

        client_handle.stop().await;
        let progress = client_handle.client.progress().await;

        if !should_restart {
            tracing::info!("Sync completed after {} restarts", restart_count);
            break progress;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        restart_count += 1;
    };

    ctx.assert_synced(&final_progress).await;
}

/// Verify sync completes successfully despite restarts at random points.
///
/// Uses a seeded RNG to sleep a random duration (50-500ms) after starting, then restarts.
#[tokio::test]
async fn test_sync_with_random_restarts() {
    let Some(ctx) = TestContext::new(TestChain::Full).await else {
        return;
    };

    let num_restarts = 10;
    let seed = 42;
    let mut rng = StdRng::seed_from_u64(seed);

    for i in 0..num_restarts {
        let delay_ms = rng.random_range(50..500);
        tracing::info!("Restart {}: sleeping {}ms before stopping", i + 1, delay_ms);
        let mut client_handle = ctx.spawn_new_client().await;

        tokio::time::sleep(Duration::from_millis(delay_ms)).await;

        client_handle.stop().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Final sync to completion
    tracing::info!("Final sync to completion");
    let mut client_handle = ctx.spawn_new_client().await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    client_handle.stop().await;
    ctx.assert_synced(&client_handle.client.progress().await).await;
    tracing::info!("Sync completed after {} random restarts (seed={})", num_restarts, seed);
}

/// Verify the same client syncs again after being stopped, including after
/// runs that were stopped right away.
#[tokio::test]
async fn test_sync_restarts_same_client() {
    let Some(ctx) = TestContext::new(TestChain::Full).await else {
        return;
    };
    let mut client_handle = ctx.spawn_new_client().await;

    for _ in 0..3 {
        client_handle.run().await;
        client_handle.stop().await;
    }

    client_handle.run().await;
    wait_for_sync_complete(&mut client_handle.sync_event_receiver, ctx.dashd.initial_height).await;
    client_handle.stop().await;

    ctx.assert_synced(&client_handle.client.progress().await).await;
}

/// Verify clearing the storage of a running client stops it, and the client
/// syncs from scratch after its storage was cleared again between runs.
#[tokio::test]
async fn test_clear_storage_stops_running_client() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    let mut client_handle = ctx.spawn_new_client().await;
    wait_for_sync_complete(&mut client_handle.sync_event_receiver, ctx.dashd.initial_height).await;

    client_handle.client.clear_storage().await.unwrap();
    assert!(!client_handle.client.is_running());
    assert!(client_handle.client.tip_header().await.is_none());
    assert_eq!(client_handle.client.progress().await, SyncProgress::default());

    client_handle.stop().await;
    client_handle.run().await;
    client_handle.client.clear_storage().await.unwrap();

    client_handle.sync_event_receiver = client_handle.sync_event_receiver.resubscribe();
    client_handle.run().await;
    wait_for_sync_complete(&mut client_handle.sync_event_receiver, ctx.dashd.initial_height).await;
    client_handle.stop().await;
    ctx.assert_synced(&client_handle.client.progress().await).await;
}

/// Verify a segment corrupted while the client runs is wiped and synced again.
#[tokio::test]
async fn test_runtime_corruption_resyncs() {
    let Some(ctx) = TestContext::new(TestChain::Full).await else {
        return;
    };
    let height = ctx.dashd.initial_height;
    let mut client_handle = ctx.spawn_new_client().await;
    wait_for_sync(&mut client_handle.progress_receiver, height).await;

    let segment = ctx.client_config.storage_path.join("filters").join("segment_000000.dat");
    let original_segment = fs::read(&segment).unwrap();
    let mut corrupted_segment = original_segment.clone();
    corrupted_segment[0] ^= 1;
    fs::write(&segment, corrupted_segment).unwrap();

    // A wallet born at 0 rescans the filters, so the client reads the corrupted segment.
    let wallet_id = client_handle
        .client
        .wallet()
        .write()
        .await
        .create_wallet_from_mnemonic(EMPTY_MNEMONIC, 0, default_test_account_options())
        .unwrap();

    tokio::time::timeout(SYNC_TIMEOUT, async {
        while !matches!(
            client_handle.sync_event_receiver.recv().await.unwrap(),
            SyncEvent::StorageCorrupted { .. }
        ) {}
    })
    .await
    .expect("Corruption not detected");

    wait_for_wallet_synced(client_handle.client.wallet(), &wallet_id, height).await;
    wait_for_sync(&mut client_handle.progress_receiver, height).await;
    client_handle.stop().await;
    ctx.assert_synced(&client_handle.client.progress().await).await;
    assert_eq!(fs::read(&segment).unwrap(), original_segment, "Corrupted segment not synced again");
}
