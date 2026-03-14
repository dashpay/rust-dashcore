use dash_spv::sync::ProgressPercentage;
use dashcore::Amount;

use super::helpers::wait_for_sync;
use super::setup::TestContext;
use dash_spv::test_utils::TestChain;

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
