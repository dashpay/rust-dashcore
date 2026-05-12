use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::sync::Arc;
use std::time::Duration;

use dash_spv::sync::SyncEvent;
use dash_spv::Network;

use super::helpers::{get_spendable_balance, is_progress_event, wait_for_sync};
use dash_spv::test_utils::SYNC_TIMEOUT;

use super::setup::{create_and_start_client, TestContext};
use dash_spv::test_utils::{create_test_wallet, TestChain};

use dashcore::Amount;
use key_wallet::managed_account::address_pool::KeySource;
use key_wallet::managed_account::managed_account_trait::ManagedAccountTrait;
use key_wallet::managed_account::managed_account_type::ManagedAccountType;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::wallet::Wallet;

/// Verify sync state is identical after stopping and restarting with same storage.
#[tokio::test]
async fn test_sync_restart_consistency() {
    let Some(ctx) = TestContext::new(TestChain::Full).await else {
        return;
    };

    // First sync
    tracing::info!("Starting first sync");
    let mut client_handle = ctx.spawn_new_client().await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    client_handle.stop().await;
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

    let mut restart_count = 0;
    let final_progress = loop {
        tracing::info!("Starting sync (restart count: {})", restart_count);
        let mut client_handle = ctx.spawn_new_client().await;

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
                            if events_seen % 2 == 0 {
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
        let delay_ms = rng.gen_range(50..500);
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

/// When a wallet is rebuilt from xpubs alone (the platform persister
/// flow) and snapshotted UTXOs are re-inserted via [`insert_utxo`],
/// the address pool must reconcile any UTXO whose address lives past
/// the initial gap limit — otherwise signing fails with "no
/// derivation path for input address …".
#[tokio::test]
async fn test_persisted_utxo_outside_initial_gap_limit_resolves_after_reload() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let mut client_handle = ctx.spawn_new_client().await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    // Pick an address well past the initial gap limit so the
    // rebuild's default pool can't coincidentally cover it.
    const TARGET_INDEX: u32 = 50;

    let high_index_address: dashcore::Address = {
        let mut wallet_write = ctx.wallet.write().await;
        let (wallet, info) =
            wallet_write.get_wallet_and_info_mut(&ctx.wallet_id).expect("wallet under test exists");

        let xpub = wallet
            .accounts
            .standard_bip44_accounts
            .get(&0)
            .expect("BIP-44 account 0 on Wallet")
            .account_xpub;

        let funds_acc = info
            .accounts
            .standard_bip44_accounts
            .get_mut(&0)
            .expect("BIP-44 account 0 on ManagedWalletInfo");

        let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = funds_acc.managed_account_type_mut()
        else {
            panic!("BIP-44 account 0 is not Standard");
        };

        let key_source = KeySource::Public(xpub);
        let highest = external_addresses.highest_generated.unwrap_or(0);
        if TARGET_INDEX > highest {
            external_addresses
                .generate_addresses(TARGET_INDEX - highest, &key_source, true)
                .expect("extend external pool");
        }
        external_addresses
            .info_at_index(TARGET_INDEX)
            .expect("address at TARGET_INDEX after extension")
            .address
            .clone()
    };

    tracing::info!(
        "Faucet target: index={} address={} (initial gap-limit = 30)",
        TARGET_INDEX,
        high_index_address
    );

    let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
    let send_amount = Amount::from_sat(100_000_000);
    let _txid = ctx.dashd.node.send_to_address(&high_index_address, send_amount);
    ctx.dashd.node.generate_blocks(1, &miner_address);
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height + 1).await;
    client_handle.stop().await;

    {
        let wallet_read = ctx.wallet.read().await;
        let info = wallet_read.get_wallet_info(&ctx.wallet_id).expect("wallet info");
        let funds_acc = info.accounts.standard_bip44_accounts.get(&0).expect("BIP-44 account 0");
        assert!(
            funds_acc.utxos().values().any(|u| u.address == high_index_address),
            "live wallet should have tracked the faucet UTXO"
        );
        assert!(
            funds_acc.address_derivation_path(&high_index_address).is_some(),
            "live pool should resolve the address before any reload"
        );
    }

    // Mirror the platform persister: snapshot xpubs + UTXOs, then
    // rebuild a wallet from xpubs alone and replay the UTXOs.
    let (accounts_snapshot, utxos_snapshot) = {
        let wallet_read = ctx.wallet.read().await;
        let wallet = wallet_read.get_wallet(&ctx.wallet_id).expect("wallet snapshot");
        let info = wallet_read.get_wallet_info(&ctx.wallet_id).expect("wallet info snapshot");
        let accounts = wallet.accounts.clone();
        let utxos: Vec<_> = info
            .accounts
            .standard_bip44_accounts
            .get(&0)
            .expect("BIP-44 account 0")
            .utxos()
            .values()
            .cloned()
            .collect();
        (accounts, utxos)
    };

    let rebuilt_wallet =
        Wallet::new_external_signable(Network::Regtest, ctx.wallet_id, accounts_snapshot);
    let mut rebuilt_info = ManagedWalletInfo::from_wallet(&rebuilt_wallet, 0);
    let rebuilt_xpub = rebuilt_wallet
        .accounts
        .standard_bip44_accounts
        .get(&0)
        .expect("rebuilt BIP-44 account 0 xpub")
        .account_xpub;
    let rebuilt_funds = rebuilt_info
        .accounts
        .standard_bip44_accounts
        .get_mut(&0)
        .expect("rebuilt BIP-44 account 0");
    for utxo in utxos_snapshot {
        rebuilt_funds
            .insert_utxo(utxo, &KeySource::Public(rebuilt_xpub))
            .expect("insert_utxo reconciles the pool past the initial gap limit");
    }

    assert!(
        rebuilt_funds.utxos().values().any(|u| u.address == high_index_address),
        "rebuilt funds account should still track the snapshotted UTXO"
    );
    assert!(
        rebuilt_funds.address_derivation_path(&high_index_address).is_some(),
        "rebuilt pool should resolve the derivation path for index {TARGET_INDEX}"
    );
}
