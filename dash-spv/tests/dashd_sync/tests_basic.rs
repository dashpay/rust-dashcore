use std::sync::Arc;
use std::time::Duration;

use dash_spv::sync::{ProgressPercentage, SyncEvent};
use dash_spv::Network;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::WalletManager;
use tokio::sync::broadcast::error::TryRecvError;
use tokio::sync::RwLock;

use super::helpers::{
    count_wallet_transactions, get_spendable_balance, wait_for_sync, EMPTY_MNEMONIC,
};
use super::setup::{create_and_start_client, create_test_wallet, TestContext};
use dash_spv::test_utils::TestChain;

#[tokio::test]
async fn test_wallet_sync() {
    let Some(ctx) = TestContext::new(TestChain::Full).await else {
        return;
    };

    let mut client_handle = ctx.spawn_new_client().await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    client_handle.stop().await;
    ctx.assert_synced(&client_handle.client.progress().await).await;
}

/// Verify that syncing with a wallet that has no on-chain activity results in zero
/// transactions and zero balance, while headers and filters sync fully.
#[tokio::test]
async fn test_sync_empty_wallet() {
    let Some(ctx) = TestContext::new(TestChain::Full).await else {
        return;
    };

    let (empty_wallet, empty_wallet_id) = create_test_wallet(EMPTY_MNEMONIC, Network::Regtest);

    tracing::info!("Starting sync with empty wallet");
    let mut client_handle =
        create_and_start_client(&ctx.client_config, Arc::clone(&empty_wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    client_handle.stop().await;

    // Verify headers and filter headers synced fully
    let final_progress = client_handle.client.progress().await;
    let header_height = final_progress.headers().unwrap().current_height();
    let filter_header_height = final_progress.filter_headers().unwrap().current_height();

    assert_eq!(header_height, ctx.dashd.initial_height, "Header height mismatch");
    assert_eq!(filter_header_height, ctx.dashd.initial_height, "Filter header height mismatch");

    // Verify zero transactions and zero balance
    let tx_count = count_wallet_transactions(&empty_wallet, &empty_wallet_id).await;
    let balance = get_spendable_balance(&empty_wallet, &empty_wallet_id).await;

    assert_eq!(tx_count, 0, "Empty wallet should have 0 transactions, got {}", tx_count);
    assert_eq!(balance, 0, "Empty wallet should have 0 balance, got {}", balance);

    tracing::info!(
        "Empty wallet sync complete: headers={}, filters={}, txs={}, balance={}",
        header_height,
        filter_header_height,
        tx_count,
        balance
    );
}

/// A `WalletManager` with no wallets reaches `Synced` and stays there:
/// the post-sync window must be free of `FiltersSyncComplete` events, since
/// the rescan trigger has nothing to act on.
#[tokio::test]
async fn test_empty_wallet_manager_no_spurious_rescan() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };

    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(Network::Regtest)));
    let mut client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    loop {
        match client_handle.sync_event_receiver.try_recv() {
            Ok(_) => {}
            Err(TryRecvError::Empty) => break,
            Err(err) => panic!("sync event channel failure while draining: {err}"),
        }
    }

    let watch_window = Duration::from_secs(2);
    let deadline = tokio::time::Instant::now() + watch_window;
    let mut spurious = 0;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, client_handle.sync_event_receiver.recv()).await {
            Ok(Ok(SyncEvent::FiltersSyncComplete {
                ..
            })) => spurious += 1,
            Ok(Ok(_)) => {}
            Ok(Err(err)) => panic!("sync event channel failure during empty-manager watch: {err}"),
            Err(_) => break,
        }
    }
    assert_eq!(
        spurious, 0,
        "empty wallet manager emitted {} FiltersSyncComplete events in {:?}",
        spurious, watch_window
    );
    assert!(
        client_handle.client.progress().await.is_synced(),
        "client should remain Synced after the empty-manager watch window"
    );

    client_handle.stop().await;
}
