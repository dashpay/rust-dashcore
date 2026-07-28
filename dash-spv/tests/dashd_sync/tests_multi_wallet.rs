use key_wallet::managed_account::managed_account_type::ManagedAccountType;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::WalletManager;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use dash_spv::client::ClientConfig;
use dash_spv::Network;
use dashcore::{Address, Amount};

use super::helpers::{
    count_wallet_transactions, get_spendable_balance, wait_for_sync, wait_for_wallet_synced,
    EMPTY_MNEMONIC, SECONDARY_MNEMONIC,
};
use super::setup::{create_and_start_client, create_and_start_client_at_checkpoint, TestContext};
use dash_spv::test_utils::{create_test_wallet, default_test_account_options, TestChain};
use key_wallet::account::ManagedAccountTrait;

/// Derive a fresh BIP44 external receive address for `mnemonic` without
/// touching the live wallet manager. Builds a temporary manager, pulls the
/// first unused address from account 0, and drops the temporary manager.
async fn reserve_first_address(mnemonic: &str) -> Address {
    let (temp_mgr, temp_id) = create_test_wallet(mnemonic, Network::Regtest);
    let reader = temp_mgr.read().await;
    let info = reader.get_wallet_info(&temp_id).expect("temp wallet info");
    let account =
        info.accounts().standard_bip44_accounts.get(&0).expect("temp wallet BIP44 account 0");
    let ManagedAccountType::Standard {
        external_addresses,
        ..
    } = &account.managed_account_type()
    else {
        panic!("temp wallet account 0 is not a Standard account type");
    };
    external_addresses
        .unused_addresses()
        .into_iter()
        .next()
        .expect("temp wallet receive address available")
}

/// Read a wallet's `(synced_height, last_processed_height)` snapshot.
async fn wallet_heights(
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &key_wallet_manager::WalletId,
) -> (u32, u32) {
    let reader = wallet.read().await;
    let info = reader.get_wallet_info(wallet_id).expect("wallet info");
    (info.synced_height(), info.last_processed_height())
}

/// End-to-end coverage for the runtime wallet-add path.
///
/// 1. Start with an empty `WalletManager`, add the pre-funded test wallet
///    (W1) at runtime with `birth_height = 0`, and verify the rescan finds
///    every expected transaction.
/// 2. Mine a block funding W2's address, add W2 with `birth_height` before
///    the funding block, and verify it picks up its transaction during
///    catch-up without regressing W1's per-wallet heights.
/// 3. Add W3 with `birth_height` beyond tip, mine past it, fund W3 in the
///    next block, and verify W3 picks up the funding tx via the per-wallet
///    live-monitoring path.
#[tokio::test]
async fn test_wallet_added_at_runtime_catches_up() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(Network::Regtest)));
    let mut client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    let initial_height = ctx.dashd.initial_height;

    // Step 1: add the pre-funded test wallet (W1) at runtime.
    let w1_id = {
        let mut wallet_guard = client_handle.client.wallet().write().await;
        wallet_guard
            .create_wallet_from_mnemonic(
                &ctx.dashd.wallet.mnemonic,
                0,
                default_test_account_options(),
            )
            .expect("add pre-funded W1 at runtime")
    };
    wait_for_wallet_synced(client_handle.client.wallet(), &w1_id, initial_height).await;
    ctx.assert_wallet_synced(
        &client_handle.client.progress().await,
        client_handle.client.wallet(),
        &w1_id,
    )
    .await;

    // Step 2: mine a block funding W2, then add W2 with birth before that block.
    let w2_address = reserve_first_address(EMPTY_MNEMONIC).await;
    let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
    let w2_txid = ctx.dashd.node.send_to_address(&w2_address, Amount::from_sat(100_000_000));
    ctx.dashd.node.generate_blocks(1, &miner_address);
    let height_with_w2_tx = initial_height + 1;
    wait_for_sync(&mut client_handle.progress_receiver, height_with_w2_tx).await;

    // dashd mines coinbase to a separate "default" wallet that does not share
    // W1's mnemonic, but the W2 funding spend itself is sent from dashd's
    // primary wallet (which does share W1's mnemonic), so W1 picks up the
    // spend as a sending-side tx.
    let w1_tx_count_before_w2 =
        count_wallet_transactions(client_handle.client.wallet(), &w1_id).await;
    let (w1_synced_before_w2, w1_processed_before_w2) =
        wallet_heights(client_handle.client.wallet(), &w1_id).await;

    let w2_id = {
        let mut wallet_guard = client_handle.client.wallet().write().await;
        wallet_guard
            .create_wallet_from_mnemonic(
                EMPTY_MNEMONIC,
                initial_height,
                default_test_account_options(),
            )
            .expect("add W2 at runtime")
    };

    wait_for_wallet_synced(client_handle.client.wallet(), &w2_id, height_with_w2_tx).await;
    let (w1_synced_after_w2, w1_processed_after_w2) =
        wallet_heights(client_handle.client.wallet(), &w1_id).await;
    assert!(
        w1_synced_after_w2 >= w1_synced_before_w2,
        "W1 synced_height regressed during W2 rescan: {} -> {}",
        w1_synced_before_w2,
        w1_synced_after_w2,
    );
    assert!(
        w1_processed_after_w2 >= w1_processed_before_w2,
        "W1 last_processed_height regressed during W2 rescan: {} -> {}",
        w1_processed_before_w2,
        w1_processed_after_w2,
    );

    assert_eq!(
        count_wallet_transactions(client_handle.client.wallet(), &w2_id).await,
        1,
        "W2 should have picked up its one funding tx"
    );
    assert_eq!(
        get_spendable_balance(client_handle.client.wallet(), &w2_id).await,
        100_000_000,
        "W2 balance should match the funded amount"
    );
    let w2_has_tx = {
        let reader = client_handle.client.wallet().read().await;
        let info = reader.get_wallet_info(&w2_id).expect("W2 info");
        info.accounts()
            .all_accounts()
            .iter()
            .any(|account| account.transactions().contains_key(&w2_txid))
    };
    assert!(w2_has_tx, "W2 should have funding tx {} after rescan", w2_txid);
    assert_eq!(
        count_wallet_transactions(client_handle.client.wallet(), &w1_id).await,
        w1_tx_count_before_w2,
        "W1 transaction count must not change across W2's rescan"
    );

    // Step 3: add W3 with birth beyond tip, advance the tip past birth, fund
    // W3 in the next block, and verify W3 picks up the tx via per-wallet live
    // monitoring (no runtime-add rescan needed since birth was in the future).
    let future_height = height_with_w2_tx + 10;
    let w3_id = {
        let mut wallet_guard = client_handle.client.wallet().write().await;
        wallet_guard
            .create_wallet_from_mnemonic(
                SECONDARY_MNEMONIC,
                future_height,
                default_test_account_options(),
            )
            .expect("add W3 at runtime")
    };

    let w1_tx_count_before_w3 =
        count_wallet_transactions(client_handle.client.wallet(), &w1_id).await;
    let w2_tx_count_before_w3 =
        count_wallet_transactions(client_handle.client.wallet(), &w2_id).await;

    let w3_address = {
        let reader = client_handle.client.wallet().read().await;
        let info = reader.get_wallet_info(&w3_id).expect("W3 info");
        let account = info.accounts().standard_bip44_accounts.get(&0).expect("W3 BIP44 account 0");
        let ManagedAccountType::Standard {
            external_addresses,
            ..
        } = &account.managed_account_type()
        else {
            panic!("W3 account 0 is not a Standard account type");
        };
        external_addresses
            .unused_addresses()
            .into_iter()
            .next()
            .expect("W3 should have an unused receive address")
    };

    ctx.dashd.node.generate_blocks(10, &miner_address);
    let w3_funding_txid = ctx.dashd.node.send_to_address(&w3_address, Amount::from_sat(40_000_000));
    ctx.dashd.node.generate_blocks(1, &miner_address);
    let w3_funding_height = future_height + 1;
    wait_for_sync(&mut client_handle.progress_receiver, w3_funding_height).await;
    wait_for_wallet_synced(client_handle.client.wallet(), &w3_id, w3_funding_height).await;

    assert_eq!(
        count_wallet_transactions(client_handle.client.wallet(), &w3_id).await,
        1,
        "W3 should have exactly its one funding tx",
    );
    assert_eq!(
        get_spendable_balance(client_handle.client.wallet(), &w3_id).await,
        40_000_000,
        "W3 balance should match the funded amount",
    );
    let w3_has_funding_tx = {
        let reader = client_handle.client.wallet().read().await;
        let info = reader.get_wallet_info(&w3_id).expect("W3 info");
        info.accounts()
            .all_accounts()
            .iter()
            .any(|account| account.transactions().contains_key(&w3_funding_txid))
    };
    assert!(w3_has_funding_tx, "W3 should hold funding tx {}", w3_funding_txid);
    assert_eq!(
        count_wallet_transactions(client_handle.client.wallet(), &w2_id).await,
        w2_tx_count_before_w3,
        "W2 transaction count must not change after W3's birth-and-fund cycle",
    );

    // The 11 new blocks contribute no coinbase txs to W1 (dashd mines coinbase
    // to the separate "default" wallet), so the only new W1 entry is the
    // outgoing W3-funding spend from dashd's primary wallet.
    let w1_tx_count_after_w3 =
        count_wallet_transactions(client_handle.client.wallet(), &w1_id).await;
    assert_eq!(
        w1_tx_count_after_w3,
        w1_tx_count_before_w3 + 1,
        "W1 should have picked up exactly the W3-funding spend",
    );

    client_handle.stop().await;
}

/// A single block carries funding transactions for two distinct wallets that
/// are both added at runtime after the initial sync. The runtime-add rescan
/// must scan the shared block once, attribute it to both wallets, and deliver
/// the block to each wallet's processor with only its own transaction visible.
#[tokio::test]
async fn test_runtime_add_shared_block_two_wallets() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(Network::Regtest)));
    let mut client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    let initial_height = ctx.dashd.initial_height;

    let w1_address = reserve_first_address(EMPTY_MNEMONIC).await;
    let w2_address = reserve_first_address(SECONDARY_MNEMONIC).await;

    let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
    let w1_txid = ctx.dashd.node.send_to_address(&w1_address, Amount::from_sat(50_000_000));
    let w2_txid = ctx.dashd.node.send_to_address(&w2_address, Amount::from_sat(70_000_000));
    ctx.dashd.node.generate_blocks(1, &miner_address);
    let shared_block_height = initial_height + 1;
    wait_for_sync(&mut client_handle.progress_receiver, shared_block_height).await;

    let w1_id = {
        let mut wallet_guard = client_handle.client.wallet().write().await;
        wallet_guard
            .create_wallet_from_mnemonic(
                EMPTY_MNEMONIC,
                initial_height,
                default_test_account_options(),
            )
            .expect("add W1 at runtime")
    };
    let w2_id = {
        let mut wallet_guard = client_handle.client.wallet().write().await;
        wallet_guard
            .create_wallet_from_mnemonic(
                SECONDARY_MNEMONIC,
                initial_height,
                default_test_account_options(),
            )
            .expect("add W2 at runtime")
    };

    wait_for_wallet_synced(client_handle.client.wallet(), &w1_id, shared_block_height).await;
    wait_for_wallet_synced(client_handle.client.wallet(), &w2_id, shared_block_height).await;

    assert_eq!(
        count_wallet_transactions(client_handle.client.wallet(), &w1_id).await,
        1,
        "W1 should have its single funding tx after the shared-block rescan"
    );
    assert_eq!(
        count_wallet_transactions(client_handle.client.wallet(), &w2_id).await,
        1,
        "W2 should have its single funding tx after the shared-block rescan"
    );
    assert_eq!(
        get_spendable_balance(client_handle.client.wallet(), &w1_id).await,
        50_000_000,
        "W1 balance should match its funded amount"
    );
    assert_eq!(
        get_spendable_balance(client_handle.client.wallet(), &w2_id).await,
        70_000_000,
        "W2 balance should match its funded amount"
    );

    let (w1_has_own, w1_has_other, w2_has_own, w2_has_other) = {
        let reader = client_handle.client.wallet().read().await;
        let w1_info = reader.get_wallet_info(&w1_id).expect("W1 info");
        let w2_info = reader.get_wallet_info(&w2_id).expect("W2 info");
        let w1_txids: HashSet<_> = w1_info
            .accounts()
            .all_accounts()
            .iter()
            .flat_map(|a| a.transactions().keys().copied())
            .collect();
        let w2_txids: HashSet<_> = w2_info
            .accounts()
            .all_accounts()
            .iter()
            .flat_map(|a| a.transactions().keys().copied())
            .collect();
        (
            w1_txids.contains(&w1_txid),
            w1_txids.contains(&w2_txid),
            w2_txids.contains(&w2_txid),
            w2_txids.contains(&w1_txid),
        )
    };
    assert!(w1_has_own, "W1 must have its own funding tx {}", w1_txid);
    assert!(!w1_has_other, "W1 must not have W2's tx {}", w2_txid);
    assert!(w2_has_own, "W2 must have its own funding tx {}", w2_txid);
    assert!(!w2_has_other, "W2 must not have W1's tx {}", w1_txid);

    client_handle.stop().await;
}

/// Add a second wallet while the FiltersManager is still mid-flight on the
/// initial filter download. W1 (the pre-funded test wallet) starts the client
/// from genesis with `birth_height = 0`; once `committed_height` crosses the
/// midpoint of the chain but before reaching tip, W2 (the empty mnemonic) is
/// added with `birth_height = 0`. The rescan trigger fires against a
/// `Syncing`-state FiltersManager, dragging `committed_height` back to 0,
/// clearing in-flight batches, and re-issuing them. Throughout the re-issue,
/// W1's per-wallet `synced_height` and `last_processed_height` must never
/// regress, and the final state must match the dashd reference.
/// `TestChain::Full` is required so the filter download is long enough to
/// observe a stable mid-flight state.
#[tokio::test]
async fn test_runtime_add_during_initial_sync() {
    let Some(ctx) = TestContext::new(TestChain::Full).await else {
        return;
    };

    let initial_height = ctx.dashd.initial_height;

    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(Network::Regtest)));
    let w1_id = {
        let mut wallet_guard = wallet.write().await;
        wallet_guard
            .create_wallet_from_mnemonic(
                &ctx.dashd.wallet.mnemonic,
                0,
                default_test_account_options(),
            )
            .expect("add W1 before start")
    };

    let mut client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;

    let midpoint = initial_height / 2;
    let inflight_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let filter_height = {
            let progress = client_handle.progress_receiver.borrow_and_update();
            progress.filters().ok().map(|f| f.committed_height()).unwrap_or(0)
        };
        if filter_height >= midpoint && filter_height < initial_height {
            tracing::info!(
                "Mid-flight: filter committed_height={} (midpoint={}, tip={})",
                filter_height,
                midpoint,
                initial_height,
            );
            break;
        }
        if filter_height >= initial_height {
            panic!(
                "filter sync reached tip ({}) before W2 could be added; \
                 lower the midpoint threshold or use a larger TestChain",
                initial_height,
            );
        }
        if tokio::time::Instant::now() > inflight_deadline {
            panic!(
                "filter committed_height did not reach midpoint {} within 60s, stuck at {}",
                midpoint, filter_height,
            );
        }
        tokio::select! {
            _ = client_handle.progress_receiver.changed() => {}
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }

    let (w1_synced_at_add, w1_processed_at_add) = wallet_heights(&wallet, &w1_id).await;
    assert!(
        w1_synced_at_add < initial_height,
        "W1 must be in mid-flight at the moment W2 is added (synced_height={}, tip={})",
        w1_synced_at_add,
        initial_height,
    );

    let w2_id = {
        let mut wallet_guard = client_handle.client.wallet().write().await;
        wallet_guard
            .create_wallet_from_mnemonic(EMPTY_MNEMONIC, 0, default_test_account_options())
            .expect("add W2 mid-flight")
    };

    let final_deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    loop {
        let (w1_synced_now, w1_processed_now) = wallet_heights(&wallet, &w1_id).await;
        let (w2_synced_now, _) = wallet_heights(&wallet, &w2_id).await;
        assert!(
            w1_synced_now >= w1_synced_at_add,
            "W1 synced_height regressed during mid-flight rescan: {} -> {}",
            w1_synced_at_add,
            w1_synced_now,
        );
        assert!(
            w1_processed_now >= w1_processed_at_add,
            "W1 last_processed_height regressed during mid-flight rescan: {} -> {}",
            w1_processed_at_add,
            w1_processed_now,
        );
        if w1_synced_now >= initial_height && w2_synced_now >= initial_height {
            break;
        }
        if tokio::time::Instant::now() > final_deadline {
            panic!(
                "wallets did not reach tip within 180s: W1.synced={}, W2.synced={}, tip={}",
                w1_synced_now, w2_synced_now, initial_height,
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    ctx.assert_wallet_synced(&client_handle.client.progress().await, &wallet, &w1_id).await;
    assert_eq!(
        count_wallet_transactions(&wallet, &w2_id).await,
        0,
        "W2 should have 0 transactions after rescan",
    );
    assert_eq!(
        get_spendable_balance(&wallet, &w2_id).await,
        0,
        "W2 should have 0 balance after rescan",
    );

    client_handle.stop().await;
}

/// Compose a runtime-add rescan with a live tip advance. W1 (the pre-funded
/// test wallet) syncs to tip via the initial sync path. W2 (the empty
/// mnemonic) is then added at runtime with `birth_height = 0`, dragging
/// `committed_height` back to genesis. While the rescan is climbing back
/// through the chain, the test funds W2's address and mines additional
/// blocks via dashd RPC so `extend_target` raises `target_height` while the
/// lowered `committed_height` is still in flight. Both wallets must reach
/// the new tip with W1's per-wallet heights never regressing, and W2 must
/// hold its single funding transaction. `TestChain::Full` is required so
/// the rescan spans many filter batches and the mid-flight window is large
/// enough to interleave RPC mining.
#[tokio::test]
async fn test_runtime_add_with_tip_advance_during_rescan() {
    let Some(ctx) = TestContext::new(TestChain::Full).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let initial_height = ctx.dashd.initial_height;

    let mut client_handle = ctx.spawn_new_client().await;
    wait_for_sync(&mut client_handle.progress_receiver, initial_height).await;
    let w1_id = ctx.wallet_id;
    ctx.assert_wallet_synced(&client_handle.client.progress().await, &ctx.wallet, &w1_id).await;

    let w1_tx_count_before = count_wallet_transactions(&ctx.wallet, &w1_id).await;
    let (w1_synced_before, w1_processed_before) = wallet_heights(&ctx.wallet, &w1_id).await;

    let w2_address = reserve_first_address(EMPTY_MNEMONIC).await;

    let w2_id = {
        let mut wallet_guard = client_handle.client.wallet().write().await;
        wallet_guard
            .create_wallet_from_mnemonic(EMPTY_MNEMONIC, 0, default_test_account_options())
            .expect("add W2 at runtime")
    };

    // Wait for the rescan trigger to lower committed_height, then for it to
    // climb back to the midpoint without yet reaching tip. Polling raw
    // committed_height isn't enough because immediately after W2 is added the
    // FiltersManager's tick has not yet fired, so committed_height is still
    // at the post-W1-sync value (the chain tip).
    let midpoint = initial_height / 2;
    let trigger_deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let filter_height = {
            let progress = client_handle.progress_receiver.borrow_and_update();
            progress.filters().ok().map(|f| f.committed_height()).unwrap_or(0)
        };
        if filter_height < initial_height {
            tracing::info!(
                "Rescan trigger fired: committed_height dropped to {} (was {})",
                filter_height,
                initial_height,
            );
            break;
        }
        if tokio::time::Instant::now() > trigger_deadline {
            panic!(
                "rescan trigger did not fire within 30s, committed_height still at {}",
                filter_height,
            );
        }
        tokio::select! {
            _ = client_handle.progress_receiver.changed() => {}
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }

    let inflight_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let filter_height = {
            let progress = client_handle.progress_receiver.borrow_and_update();
            progress.filters().ok().map(|f| f.committed_height()).unwrap_or(0)
        };
        if filter_height >= midpoint && filter_height < initial_height {
            tracing::info!(
                "Mid-rescan: filter committed_height={} (midpoint={}, tip={})",
                filter_height,
                midpoint,
                initial_height,
            );
            break;
        }
        if filter_height >= initial_height {
            panic!(
                "rescan completed before tip-advance window opened; \
                 lower the midpoint threshold or use a larger TestChain (got {})",
                filter_height,
            );
        }
        if tokio::time::Instant::now() > inflight_deadline {
            panic!(
                "rescan committed_height did not reach midpoint {} within 60s, stuck at {}",
                midpoint, filter_height,
            );
        }
        tokio::select! {
            _ = client_handle.progress_receiver.changed() => {}
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }

    let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
    let w2_funding_txid = ctx.dashd.node.send_to_address(&w2_address, Amount::from_sat(60_000_000));
    ctx.dashd.node.generate_blocks(5, &miner_address);
    let new_tip = initial_height + 5;

    let final_deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    loop {
        let (w1_synced_now, w1_processed_now) = wallet_heights(&ctx.wallet, &w1_id).await;
        let (w2_synced_now, _) = wallet_heights(&ctx.wallet, &w2_id).await;
        assert!(
            w1_synced_now >= w1_synced_before,
            "W1 synced_height regressed: {} -> {}",
            w1_synced_before,
            w1_synced_now,
        );
        assert!(
            w1_processed_now >= w1_processed_before,
            "W1 last_processed_height regressed: {} -> {}",
            w1_processed_before,
            w1_processed_now,
        );
        if w1_synced_now >= new_tip && w2_synced_now >= new_tip {
            break;
        }
        if tokio::time::Instant::now() > final_deadline {
            panic!(
                "wallets did not reach new tip {} within 180s: W1.synced={}, W2.synced={}",
                new_tip, w1_synced_now, w2_synced_now,
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // The 5 new blocks contribute no coinbase txs to W1 (dashd mines coinbase
    // to the separate "default" wallet), so the only new W1 entry is the
    // outgoing W2-funding spend from dashd's primary wallet.
    let w1_tx_count_after = count_wallet_transactions(&ctx.wallet, &w1_id).await;
    assert_eq!(
        w1_tx_count_after,
        w1_tx_count_before + 1,
        "W1 should have picked up exactly the W2-funding spend",
    );

    assert_eq!(
        count_wallet_transactions(&ctx.wallet, &w2_id).await,
        1,
        "W2 should have exactly its one funding tx",
    );
    assert_eq!(
        get_spendable_balance(&ctx.wallet, &w2_id).await,
        60_000_000,
        "W2 balance should match the funded amount",
    );
    let w2_has_funding = {
        let reader = ctx.wallet.read().await;
        let info = reader.get_wallet_info(&w2_id).expect("W2 info");
        info.accounts()
            .all_accounts()
            .iter()
            .any(|account| account.transactions().contains_key(&w2_funding_txid))
    };
    assert!(w2_has_funding, "W2 should hold funding tx {}", w2_funding_txid);

    client_handle.stop().await;
}

/// Every txid a wallet holds, confirmed or immature.
async fn wallet_txids(
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &key_wallet_manager::WalletId,
) -> HashSet<String> {
    let reader = wallet.read().await;
    let info = reader.get_wallet_info(wallet_id).expect("wallet info");
    let mut txids: HashSet<String> = info
        .accounts()
        .all_accounts()
        .iter()
        .flat_map(|a| a.transactions().keys())
        .map(|txid| txid.to_string())
        .collect();
    txids.extend(info.immature_transactions().iter().map(|tx| tx.txid().to_string()));
    txids
}

/// Fixture txids in blocks within `range`, from the wallet JSON's
/// `confirmations` (`height = tip - confirmations + 1`).
fn fixture_txids_in_range(ctx: &TestContext, range: std::ops::Range<u32>) -> HashSet<String> {
    ctx.dashd
        .wallet
        .transactions
        .iter()
        .filter_map(|tx| {
            let confirmations = tx.get("confirmations")?.as_u64()? as u32;
            let tx_height = ctx.dashd.initial_height.checked_sub(confirmations)? + 1;
            let txid = tx.get("txid")?.as_str()?;
            range.contains(&tx_height).then(|| txid.to_string())
        })
        .collect()
}

/// A wallet added below the checkpoint the client is anchored on cannot see its
/// own history: the client holds no headers or filter headers below that
/// checkpoint, so no rescan can reach those blocks.
///
/// Two checkpoints, so the backfill has to anchor on the lower one rather than
/// on genesis — the shape a real client sees, since mainnet and testnet bundle a
/// checkpoint every 50k blocks. Three wallets, one per height that matters:
///
/// 1. Born at the upper checkpoint. It has no regtest history: its job is to
///    anchor the client there, leaving nothing stored below it.
/// 2. The funded wallet, born at the lower checkpoint and added while the client
///    runs. Reaching its history means backfilling from that checkpoint up to
///    the upper one — and never below it. A third checkpoint sits in between, so
///    that backfill has to span more than one segment.
/// 3. The funded wallet again, re-imported from seed at height 0, which has to
///    backfill a second time, now down to genesis.
///
/// Only one fixture mnemonic is cheap to scan, so (1) is unfunded: the other
/// funded wallet in the fixture is the miner's, which owns a coinbase in every
/// block and would drag the whole chain's blocks down with it.
///
/// Regtest ships no checkpoints, hence the injected ones.
#[tokio::test]
async fn test_wallet_added_below_checkpoint_cannot_see_its_history() {
    let Some(ctx) = TestContext::new(TestChain::Full).await else {
        return;
    };
    let tip = ctx.dashd.initial_height;
    let lower_checkpoint = tip / 4;
    let middle_checkpoint = tip * 3 / 8;
    let upper_checkpoint = tip / 2;
    let anchor_birth = upper_checkpoint;
    let funded_birth = lower_checkpoint;

    // What the funded wallet owns in the span only a backfill can reach: at or
    // above its birth height, but below the checkpoint the client anchored on.
    let unreachable_without_backfill = fixture_txids_in_range(&ctx, funded_birth..upper_checkpoint);
    assert!(
        !unreachable_without_backfill.is_empty(),
        "fixture has no transactions in [{funded_birth}, {upper_checkpoint}) to find"
    );

    // Wallet 1: no regtest history, only its birth height matters here.
    let wallet = Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(Network::Regtest)));
    {
        let mut guard = wallet.write().await;
        guard
            .create_wallet_from_mnemonic(
                EMPTY_MNEMONIC,
                anchor_birth,
                default_test_account_options(),
            )
            .expect("add the anchoring wallet born at the upper checkpoint");
    }

    let mut client_handle = create_and_start_client_at_checkpoint(
        &ctx.client_config,
        Arc::clone(&wallet),
        &ctx.dashd.node,
        &[lower_checkpoint, middle_checkpoint, upper_checkpoint],
    )
    .await;
    wait_for_sync(&mut client_handle.progress_receiver, tip).await;

    // Wallet 2: the funded one, born at the lower checkpoint, added mid-flight.
    let funded_id = {
        let mut guard = client_handle.client.wallet().write().await;
        guard
            .create_wallet_from_mnemonic(
                &ctx.dashd.wallet.mnemonic,
                funded_birth,
                default_test_account_options(),
            )
            .expect("add the funded wallet below the checkpoint")
    };

    // Own budget rather than `wait_for_wallet_synced`: dropping the scan floor
    // reissues every filter batch, and a batch lost to a transient send failure
    // is only retried after the download coordinator's 30s timeout — the same
    // value as `SYNC_TIMEOUT`.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    loop {
        let (synced, _) = wallet_heights(&wallet, &funded_id).await;
        if synced >= tip {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the funded wallet never caught up: stuck at synced_height {synced}, target {tip}",
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let found = wallet_txids(&wallet, &funded_id).await;
    client_handle.stop().await;
    // Release the storage lock: the re-import below reuses this directory.
    drop(client_handle);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Control: the same wallet at the same birth height on a client that never
    // anchored above it, so it needs no backfill. Comparing against it keeps this
    // test about the backfill — whatever a mid-chain birth height costs a wallet
    // on its own shows up in both runs alike.
    let control_dir = tempfile::TempDir::new().expect("control storage dir");
    let mut control_config = ClientConfig::regtest()
        .with_storage_path(control_dir.path().to_path_buf())
        .without_masternodes();
    control_config.add_peer(ctx.dashd.addr);

    let control_wallet =
        Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(Network::Regtest)));
    let control_id = {
        let mut guard = control_wallet.write().await;
        guard
            .create_wallet_from_mnemonic(
                &ctx.dashd.wallet.mnemonic,
                funded_birth,
                default_test_account_options(),
            )
            .expect("add the funded wallet to the control client")
    };
    let mut control_handle =
        create_and_start_client(&control_config, Arc::clone(&control_wallet)).await;
    wait_for_sync(&mut control_handle.progress_receiver, tip).await;
    wait_for_wallet_synced(&control_wallet, &control_id, tip).await;
    let control_found = wallet_txids(&control_wallet, &control_id).await;
    control_handle.stop().await;
    drop(control_handle);

    let reachable_by_control: HashSet<String> =
        unreachable_without_backfill.intersection(&control_found).cloned().collect();
    assert!(
        !reachable_by_control.is_empty(),
        "the control client found none of the {} transactions in [{funded_birth}, \
         {upper_checkpoint}), so this run proves nothing",
        unreachable_without_backfill.len(),
    );

    let mut missing: Vec<_> = reachable_by_control.difference(&found).cloned().collect();
    missing.sort_unstable();
    assert!(
        missing.is_empty(),
        "the wallet was added below the checkpoint the client anchored on and is missing {} of \
         the {} transactions in [{funded_birth}, {upper_checkpoint}) that the control client \
         found without a backfill: {missing:?}",
        missing.len(),
        reachable_by_control.len(),
    );

    // Wallet 3: the same wallet re-imported from seed at height 0, on the storage
    // the first backfill left reaching down to the lower checkpoint. That has to backfill
    // again, this time all the way to genesis — and a wallet scanning from 0
    // carries no gap-limit handicap, so it must end up with the whole balance
    // dashd reports.
    let reimported =
        Arc::new(RwLock::new(WalletManager::<ManagedWalletInfo>::new(Network::Regtest)));
    let reimported_id = {
        let mut guard = reimported.write().await;
        guard
            .create_wallet_from_mnemonic(
                &ctx.dashd.wallet.mnemonic,
                0,
                default_test_account_options(),
            )
            .expect("re-import the funded wallet at height 0")
    };
    let mut reimported_handle = create_and_start_client_at_checkpoint(
        &ctx.client_config,
        Arc::clone(&reimported),
        &ctx.dashd.node,
        &[lower_checkpoint, middle_checkpoint, upper_checkpoint],
    )
    .await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    loop {
        let (synced, _) = wallet_heights(&reimported, &reimported_id).await;
        if synced >= tip {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the re-imported wallet never caught up: stuck at synced_height {synced}, \
             target {tip}",
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    assert_eq!(
        get_spendable_balance(&reimported, &reimported_id).await,
        (ctx.dashd.wallet.balance * 1e8).round() as u64,
        "a wallet re-imported at height 0 must end up with the whole balance, so the second \
         backfill has to reach genesis",
    );

    // A block mined after the backfills must extend the filter headers from the
    // real tip. The fill left the pipeline aimed at the range below the old
    // floor, so anything that resumes from there would re-request the span that
    // is already stored.
    if ctx.dashd.supports_mining {
        let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
        ctx.dashd.node.generate_blocks(1, &miner_address);
        wait_for_sync(&mut reimported_handle.progress_receiver, tip + 1).await;
    }

    reimported_handle.stop().await;
}
