use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::wallet_manager::WalletManager;
use std::sync::Arc;
use tokio::sync::RwLock;

use dash_spv::sync::ProgressPercentage;
use dash_spv::Network;

use super::helpers::{count_wallet_transactions, get_spendable_balance, wait_for_sync};
use super::setup::{
    create_and_start_client, create_test_wallet, test_account_options, TestContext,
};

#[tokio::test]
async fn test_wallet_sync() {
    let Some(ctx) = TestContext::new().await else {
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
    let Some(ctx) = TestContext::new().await else {
        return;
    };

    // Use a mnemonic with no regtest activity
    let empty_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let (empty_wallet, empty_wallet_id) = create_test_wallet(empty_mnemonic, Network::Regtest);

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

/// Verify two wallets in one WalletManager sync independently without cross-contamination.
///
/// Creates a manager with the test mnemonic wallet (has transactions) and the "abandon"
/// wallet (no regtest activity). After sync, the test wallet should have all expected
/// transactions while the abandon wallet remains empty.
#[tokio::test]
async fn test_sync_two_wallets_same_client() {
    let Some(ctx) = TestContext::new().await else {
        return;
    };

    let empty_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Create a WalletManager with two wallets
    let mut wallet_manager = WalletManager::<ManagedWalletInfo>::new(Network::Regtest);
    let test_wallet_id = wallet_manager
        .create_wallet_from_mnemonic(&ctx.dashd.wallet.mnemonic, "", 0, test_account_options())
        .expect("Failed to create test wallet");

    let empty_wallet_id = wallet_manager
        .create_wallet_from_mnemonic(empty_mnemonic, "", 0, test_account_options())
        .expect("Failed to create empty wallet");

    assert_eq!(wallet_manager.wallet_count(), 2, "Should have two wallets");
    let multi_wallet = Arc::new(RwLock::new(wallet_manager));

    // Sync
    tracing::info!("Starting sync with two wallets");
    let mut client_handle =
        create_and_start_client(&ctx.client_config, Arc::clone(&multi_wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    client_handle.stop().await;

    // Verify the test wallet has expected transactions and balance
    ctx.assert_wallet_synced(
        &client_handle.client.progress().await,
        &multi_wallet,
        &test_wallet_id,
    )
    .await;

    // Verify the empty wallet has zero transactions and zero balance
    let empty_tx_count = count_wallet_transactions(&multi_wallet, &empty_wallet_id).await;
    let empty_balance = get_spendable_balance(&multi_wallet, &empty_wallet_id).await;

    assert_eq!(
        empty_tx_count, 0,
        "Empty wallet should have 0 transactions, got {}",
        empty_tx_count
    );
    assert_eq!(empty_balance, 0, "Empty wallet should have 0 balance, got {}", empty_balance);

    tracing::info!(
        "Multi-wallet sync passed: empty_wallet(txs={}, balance={})",
        empty_tx_count,
        empty_balance
    );
}
