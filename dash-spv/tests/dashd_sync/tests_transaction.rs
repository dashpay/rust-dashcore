use dash_spv::sync::ProgressPercentage;
use dashcore::{Address, Amount, Network};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use super::helpers::{
    count_wallet_transactions, get_spendable_balance, wait_for_mempool_tx, wait_for_sync,
    wait_for_wallet_synced, EMPTY_MNEMONIC, SECONDARY_MNEMONIC,
};
use super::setup::{create_and_start_client, TestContext};
use dash_spv::test_utils::{create_test_wallet, TestChain};
use dashcore::address::NetworkUnchecked;
use dashcore::secp256k1::Secp256k1;
use dashcore::PublicKey;
use key_wallet::account::ManagedAccountTrait;
use key_wallet::bip32::{ChildNumber, ExtendedPrivKey};
use key_wallet::gap_limit::DEFAULT_EXTERNAL_GAP_LIMIT;
use key_wallet::mnemonic::{Language, Mnemonic};
use key_wallet::wallet::managed_wallet_info::transaction_builder::{
    BuilderError, TransactionBuilder,
};
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::ManagedWalletInfo;
use key_wallet::ManagedAccountType;
use key_wallet_manager::{WalletId, WalletManager};

/// Verify incremental sync works by generating blocks after initial sync.
///
/// Generates a single block (with a wallet transaction) and then a batch of blocks,
/// verifying wallet balance updates and height progression at each step.
#[tokio::test]
async fn test_sync_then_generate_blocks() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    tracing::info!("Starting initial sync");
    let mut client_handle = ctx.spawn_new_client().await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    let initial_balance = ctx.spendable_balance().await;
    let initial_tx_count = ctx.transaction_count().await;
    tracing::info!(
        "Initial state: height={}, balance={}, tx_count={}",
        ctx.dashd.initial_height,
        initial_balance,
        initial_tx_count
    );

    let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");

    // Generate a single block containing a wallet transaction
    let receive_address = ctx.receive_address().await;
    let send_amount = Amount::from_sat(100_000_000);
    let txid = ctx.dashd.node.send_to_address(&receive_address, send_amount);
    tracing::info!("Sent {} to SPV wallet, txid: {}", send_amount, txid);

    ctx.dashd.node.generate_blocks(1, &miner_address);
    let height_after_one = ctx.dashd.initial_height + 1;
    wait_for_sync(&mut client_handle.progress_receiver, height_after_one).await;

    // Verify the transaction was detected and balance reflects fees
    assert!(ctx.has_transaction(&txid).await, "SPV wallet should contain transaction {}", txid);
    let balance_after_tx = ctx.spendable_balance().await;
    assert!(
        balance_after_tx < initial_balance,
        "Balance should decrease by fees: initial={}, after_tx={}",
        initial_balance,
        balance_after_tx
    );
    let fees = initial_balance - balance_after_tx;
    assert!(fees < 1_000_000, "Fees ({}) should be reasonable", fees);

    // Generate a batch of blocks and verify sync reaches the expected height
    ctx.dashd.node.generate_blocks(5, &miner_address);
    let expected_final_height = ctx.dashd.initial_height + 6;
    wait_for_sync(&mut client_handle.progress_receiver, expected_final_height).await;

    client_handle.stop().await;
    let final_height = client_handle.client.progress().await.headers().unwrap().current_height();
    let final_tx_count = ctx.transaction_count().await;

    assert_eq!(final_height, expected_final_height, "Header height mismatch");
    assert!(
        final_tx_count > initial_tx_count,
        "Transaction count should have increased: {} -> {}",
        initial_tx_count,
        final_tx_count
    );
    tracing::info!(
        "Incremental sync complete: height {} -> {}, tx_count {} -> {}",
        ctx.dashd.initial_height,
        final_height,
        initial_tx_count,
        final_tx_count
    );
}

/// Verify that multiple transactions sent in quick succession and mined in a single block
/// are all detected by the SPV client.
#[tokio::test]
async fn test_multiple_transactions_in_single_block() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    // Initial sync to chain tip
    tracing::info!("Starting initial sync");
    let mut client_handle = ctx.spawn_new_client().await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    let baseline_tx_count = ctx.transaction_count().await;
    let baseline_balance = ctx.spendable_balance().await;
    tracing::info!("Baseline: tx_count={}, balance={}", baseline_tx_count, baseline_balance);

    // Send 3 transactions of different amounts to the SPV wallet
    let receive_address = ctx.receive_address().await;
    let amounts =
        [Amount::from_sat(50_000_000), Amount::from_sat(75_000_000), Amount::from_sat(120_000_000)];
    let mut txids = Vec::new();
    for amount in &amounts {
        let txid = ctx.dashd.node.send_to_address(&receive_address, *amount);
        tracing::info!("Sent {} to SPV wallet, txid: {}", amount, txid);
        txids.push(txid);
    }

    // Mine a single block to confirm all 3
    let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
    ctx.dashd.node.generate_blocks(1, &miner_address);
    let expected_height = ctx.dashd.initial_height + 1;

    // Wait for SPV to sync the new block
    wait_for_sync(&mut client_handle.progress_receiver, expected_height).await;

    // Verify all 3 transactions are in the wallet
    let final_tx_count = ctx.transaction_count().await;
    let final_balance = ctx.spendable_balance().await;

    assert_eq!(
        final_tx_count,
        baseline_tx_count + 3,
        "Expected 3 new transactions, got {}",
        final_tx_count - baseline_tx_count
    );

    // Since dashd and SPV share the same wallet, sends are internal transfers.
    // The only balance change is the transaction fees deducted by dashd.
    assert!(
        final_balance < baseline_balance,
        "Balance should decrease by fees for internal transfers"
    );
    let fees_paid = baseline_balance - final_balance;
    assert!(fees_paid < 1_000_000, "Total fees ({}) should be reasonable", fees_paid);

    for txid in &txids {
        assert!(ctx.has_transaction(txid).await, "Wallet should contain transaction {}", txid);
    }

    tracing::info!(
        "All 3 transactions found: tx_count {} -> {}, balance {} -> {} (fees={})",
        baseline_tx_count,
        final_tx_count,
        baseline_balance,
        final_balance,
        fees_paid
    );
}

/// Verify that transactions sent one per block over several blocks are each detected
/// incrementally by the SPV client.
#[tokio::test]
async fn test_multiple_transactions_across_blocks() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    // Initial sync to chain tip
    tracing::info!("Starting initial sync");
    let mut client_handle = ctx.spawn_new_client().await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    let baseline_tx_count = ctx.transaction_count().await;
    let baseline_balance = ctx.spendable_balance().await;
    tracing::info!("Baseline: tx_count={}, balance={}", baseline_tx_count, baseline_balance);

    // Send 1 tx per block, 3 iterations
    let amounts =
        [Amount::from_sat(30_000_000), Amount::from_sat(60_000_000), Amount::from_sat(90_000_000)];
    let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
    let mut current_height = ctx.dashd.initial_height;
    let mut txids = Vec::new();

    for (i, amount) in amounts.iter().enumerate() {
        let receive_address = ctx.receive_address().await;
        let txid = ctx.dashd.node.send_to_address(&receive_address, *amount);
        tracing::info!("Iteration {}: sent {} to SPV wallet, txid: {}", i, amount, txid);
        txids.push(txid);

        ctx.dashd.node.generate_blocks(1, &miner_address);
        current_height += 1;

        wait_for_sync(&mut client_handle.progress_receiver, current_height).await;

        let tx_count = ctx.transaction_count().await;
        assert_eq!(
            tx_count,
            baseline_tx_count + i + 1,
            "After iteration {}, expected {} transactions, got {}",
            i,
            baseline_tx_count + i + 1,
            tx_count
        );
        tracing::info!("Iteration {}: tx_count={}", i, tx_count);
    }

    // Final verification
    let final_balance = ctx.spendable_balance().await;

    // Internal transfers: only fees are deducted
    assert!(
        final_balance < baseline_balance,
        "Balance should decrease by fees for internal transfers"
    );
    let fees_paid = baseline_balance - final_balance;
    assert!(fees_paid < 1_000_000, "Total fees ({}) should be reasonable", fees_paid);

    for txid in &txids {
        assert!(ctx.has_transaction(txid).await, "Wallet should contain transaction {}", txid);
    }

    tracing::info!(
        "All iterations complete: tx_count {} -> {}, balance {} -> {} (fees={})",
        baseline_tx_count,
        baseline_tx_count + amounts.len(),
        baseline_balance,
        final_balance,
        fees_paid
    );
}

const MEMPOOL_TIMEOUT: Duration = Duration::from_secs(30);

/// Derive the first `count` BIP44 external addresses of `mnemonic` directly,
/// independently of any wallet state, so a test can pay addresses far beyond
/// the pre-generated pool window.
fn derive_external_addresses(mnemonic: &str, count: u32) -> Vec<Address> {
    let mnemonic = Mnemonic::from_phrase(mnemonic, Language::English).expect("mnemonic");
    let seed = mnemonic.to_seed("");
    let secp = Secp256k1::new();
    let master = ExtendedPrivKey::new_master(Network::Regtest, &seed).expect("master key");
    let chain = [
        ChildNumber::from_hardened_idx(44).expect("purpose"),
        ChildNumber::from_hardened_idx(1).expect("coin type"),
        ChildNumber::from_hardened_idx(0).expect("account"),
        ChildNumber::from_normal_idx(0).expect("external branch"),
    ];
    (0..count)
        .map(|index| {
            let mut path = chain.to_vec();
            path.push(ChildNumber::from_normal_idx(index).expect("index"));
            let xprv = master.derive_priv(&secp, &path).expect("derive");
            let pk = PublicKey::new(xprv.private_key.public_key(&secp));
            Address::p2pkh(&pk, Network::Regtest)
        })
        .collect()
}

/// A single transaction paying a run of consecutive fresh addresses reaching
/// far beyond the gap window (the shape of a CreateDenominations burst),
/// mined before the client ever starts. A sync from scratch must recognize
/// every output: the block is scanned to fixpoint against the extending
/// pool, so outputs past the initial look-ahead are still credited.
#[tokio::test]
async fn test_burst_payment_beyond_gap_window_synced_from_scratch() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let burst = DEFAULT_EXTERNAL_GAP_LIMIT + 21;
    let addresses = derive_external_addresses(EMPTY_MNEMONIC, burst);
    let per_output = Amount::from_sat(100_000);
    let payments: Vec<(Address, Amount)> =
        addresses.into_iter().map(|address| (address, per_output)).collect();
    let burst_txid = ctx.dashd.node.send_many(&payments);

    let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
    ctx.dashd.node.generate_blocks(1, &miner_address);
    let funded_height = ctx.dashd.initial_height + 1;

    // Only now create the wallet and start the client, so discovery has to
    // climb the whole burst during the historical scan.
    let (wallet, wallet_id) = create_test_wallet(EMPTY_MNEMONIC, Network::Regtest);
    let mut client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, funded_height).await;
    wait_for_wallet_synced(&wallet, &wallet_id, funded_height).await;

    assert_eq!(
        count_wallet_transactions(&wallet, &wallet_id).await,
        1,
        "burst tx {} must be discovered",
        burst_txid
    );
    assert_eq!(
        get_spendable_balance(&wallet, &wallet_id).await,
        burst as u64 * per_output.to_sat(),
        "every burst output must be credited, not only those inside the initial gap window"
    );

    client_handle.stop().await;
}

async fn reserve_first_address(mnemonic: &str) -> Address {
    let (temp_mgr, temp_id) = create_test_wallet(mnemonic, Network::Regtest);

    let reader = temp_mgr.read().await;
    let info = reader.get_wallet_info(&temp_id).expect("wallet info");
    let account = info.accounts().standard_bip44_accounts.get(&0).expect("BIP44 account 0");

    let ManagedAccountType::Standard {
        external_addresses,
        ..
    } = &account.managed_account_type()
    else {
        panic!("not a Standard account");
    };

    external_addresses.unused_addresses().into_iter().next().expect("unused address")
}

async fn build_and_sign(
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &WalletId,
    destination: &Address,
    amount: u64,
) -> Result<(dashcore::Transaction, u64), BuilderError> {
    let dest_unchecked: Address<NetworkUnchecked> =
        destination.to_string().parse().expect("destination address");

    let mut wallet_lock = wallet.write().await;
    let (w, info) = wallet_lock.get_wallet_and_info_mut(wallet_id).expect("wallet present");

    let height = info.last_processed_height();
    let network = w.network;
    let account = w.get_bip44_account(0).expect("account 0").clone();
    let funds_account = info.accounts.standard_bip44_accounts.get_mut(&0).expect("account 0");
    let dest = dest_unchecked.require_network(network).expect("destination network");

    TransactionBuilder::new()
        .set_current_height(height)
        .set_funding(funds_account, &account)
        .add_output(&dest, amount)
        .build_signed(w, |a| funds_account.address_derivation_path(&a))
        .await
}

/// Build, sign and broadcast a tx via `TransactionBuilder`, then re-spend
/// the resulting mempool change UTXO before its parent confirms.
#[tokio::test]
async fn test_spend_change_balance() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let (wallet, wallet_id) = create_test_wallet(EMPTY_MNEMONIC, Network::Regtest);
    let mut client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    let receive_address = reserve_first_address(EMPTY_MNEMONIC).await;
    let funding_amount = Amount::from_sat(500_000_000);
    ctx.dashd.node.send_to_address(&receive_address, funding_amount);

    let miner_address = ctx.dashd.node.get_new_address_from_wallet("default");
    ctx.dashd.node.generate_blocks(1, &miner_address);
    let funded_height = ctx.dashd.initial_height + 1;
    wait_for_sync(&mut client_handle.progress_receiver, funded_height).await;
    wait_for_wallet_synced(&wallet, &wallet_id, funded_height).await;

    let dest_a = Address::dummy(Network::Regtest, 1);
    let (tx_a, _) =
        build_and_sign(&wallet, &wallet_id, &dest_a, 100_000_000).await.expect("build tx_a");

    client_handle.client.broadcast_transaction(&tx_a).await.expect("broadcast tx_a");
    wait_for_mempool_tx(&mut client_handle.wallet_event_receiver, MEMPOOL_TIMEOUT)
        .await
        .expect("detect tx_a");

    // The wallet's only UTXO now is the mempool change from tx_a, so a
    // successful build proves coin selection used it.
    let dest_b = Address::dummy(Network::Regtest, 2);
    let (tx_b, _) = build_and_sign(&wallet, &wallet_id, &dest_b, 50_000_000)
        .await
        .expect("spend mempool change");
    assert!(
        tx_b.input.iter().any(|i| i.previous_output.txid == tx_a.txid()),
        "tx_b must spend tx_a's mempool change UTXO",
    );

    client_handle.client.broadcast_transaction(&tx_b).await.expect("broadcast tx_b");
    wait_for_mempool_tx(&mut client_handle.wallet_event_receiver, MEMPOOL_TIMEOUT)
        .await
        .expect("detect tx_b");

    client_handle.stop().await;
}

/// Spend an incoming mempool UTXO (we own the output, none of the inputs)
/// before it confirms.
#[tokio::test]
async fn test_spend_incoming_balance() {
    let Some(ctx) = TestContext::new(TestChain::Minimal).await else {
        return;
    };
    if !ctx.dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    let (wallet, wallet_id) = create_test_wallet(SECONDARY_MNEMONIC, Network::Regtest);
    let mut client_handle = create_and_start_client(&ctx.client_config, Arc::clone(&wallet)).await;
    wait_for_sync(&mut client_handle.progress_receiver, ctx.dashd.initial_height).await;

    let receive_address = reserve_first_address(SECONDARY_MNEMONIC).await;
    let incoming_amount = Amount::from_sat(300_000_000);
    let incoming_txid = ctx.dashd.node.send_to_address(&receive_address, incoming_amount);

    wait_for_mempool_tx(&mut client_handle.wallet_event_receiver, MEMPOOL_TIMEOUT)
        .await
        .expect("detect incoming");

    let dest = Address::dummy(Network::Regtest, 3);
    let (tx, _) = build_and_sign(&wallet, &wallet_id, &dest, 150_000_000)
        .await
        .expect("spend unconfirmed incoming");
    assert!(
        tx.input.iter().any(|i| i.previous_output.txid == incoming_txid),
        "spend must reference the unconfirmed incoming txid",
    );

    client_handle.client.broadcast_transaction(&tx).await.expect("broadcast spend");
    wait_for_mempool_tx(&mut client_handle.wallet_event_receiver, MEMPOOL_TIMEOUT)
        .await
        .expect("detect spend");

    client_handle.stop().await;
}
