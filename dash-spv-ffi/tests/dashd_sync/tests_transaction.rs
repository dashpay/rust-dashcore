use std::sync::atomic::Ordering;

use dash_spv::test_utils::{DashdTestContext, TestChain};
use dashcore::hashes::Hash;
use dashcore::Amount;

use super::context::FFITestContext;

/// Verify incremental sync works via FFI by generating blocks after initial sync.
///
/// Generates a single block (with a wallet transaction) and a batch of blocks,
/// verifying deterministic cycle counting and wallet balance updates.
#[test]
fn test_ffi_sync_then_generate_blocks() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let Some(dashd) = rt.block_on(DashdTestContext::new(TestChain::Minimal)) else {
        eprintln!("Skipping test (dashd context unavailable)");
        return;
    };
    if !dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    unsafe {
        let ctx = FFITestContext::new(dashd.addr);
        let wallet_id = ctx.add_wallet(&dashd.wallet.mnemonic);

        ctx.run();
        ctx.wait_for_sync(dashd.initial_height);

        assert_eq!(
            ctx.tracker().last_sync_cycle.load(Ordering::SeqCst),
            0,
            "Initial sync should be cycle 0"
        );

        let (initial_balance, _) = ctx.get_wallet_balance(&wallet_id);
        let initial_tx_count = ctx.transaction_count(&wallet_id);
        tracing::info!(
            "Initial state: balance={} satoshis, tx_count={}",
            initial_balance,
            initial_tx_count
        );

        let miner_address = dashd.node.get_new_address_from_wallet("default");

        // Generate a block containing a wallet transaction and wait for sync.
        let cycle_before = ctx.tracker().last_sync_cycle.load(Ordering::SeqCst);
        let tx_received_before = ctx.tracker().transaction_received_count.load(Ordering::SeqCst);
        let receive_address = ctx.get_receive_address(&wallet_id);
        let send_amount = Amount::from_sat(100_000_000);
        let txid = dashd.node.send_to_address(&receive_address, send_amount);
        tracing::info!("Sent {} to FFI wallet, txid: {}", send_amount, txid);

        dashd.node.generate_blocks(1, &miner_address);
        let height_after_one = dashd.initial_height + 1;
        ctx.wait_for_sync(height_after_one);

        let cycle_after_first = ctx.tracker().last_sync_cycle.load(Ordering::SeqCst);
        assert_eq!(
            cycle_after_first,
            cycle_before + 1,
            "Single block should produce exactly one sync cycle: before={}, after={}",
            cycle_before,
            cycle_after_first
        );

        // Wait for wallet callback (travels on a separate channel from sync events)
        ctx.tracker().wait_for_callback(
            &ctx.tracker().transaction_received_count,
            tx_received_before,
            "transaction_received",
        );

        // Verify the transaction was received via wallet callback
        let received_txs = ctx.tracker().received_transactions.lock().unwrap();
        let txid_bytes = *txid.as_byte_array();
        assert!(
            received_txs.iter().any(|&(txid, _)| txid == txid_bytes),
            "Wallet callback should have received txid {}",
            txid
        );
        drop(received_txs);

        // Verify via wallet query as well
        assert!(
            ctx.has_transaction(&wallet_id, &txid),
            "Wallet should contain transaction {}",
            txid
        );

        // Verify balance changed from the transaction
        let (balance_after_tx, _) = ctx.get_wallet_balance(&wallet_id);
        assert!(
            balance_after_tx < initial_balance,
            "Balance should decrease by fees: initial={}, after_tx={}",
            initial_balance,
            balance_after_tx
        );
        let fees = initial_balance - balance_after_tx;
        assert!(fees < 1_000_000, "Fees ({}) should be reasonable", fees);

        // Generate multiple blocks at once and verify the cycle advances
        let cycle_before_batch = ctx.tracker().last_sync_cycle.load(Ordering::SeqCst);
        dashd.node.generate_blocks(5, &miner_address);
        let expected_final_height = dashd.initial_height + 6;
        ctx.wait_for_sync(expected_final_height);

        let cycle_after_batch = ctx.tracker().last_sync_cycle.load(Ordering::SeqCst);
        assert!(
            cycle_after_batch > cycle_before_batch,
            "Sync cycle should advance after batch: before={}, after={}",
            cycle_before_batch,
            cycle_after_batch
        );

        let final_tx_count = ctx.transaction_count(&wallet_id);
        assert!(
            final_tx_count > initial_tx_count,
            "Transaction count should have increased: {} -> {}",
            initial_tx_count,
            final_tx_count
        );

        ctx.tracker().assert_no_errors();
    }
}

/// Verify that multiple transactions sent in quick succession and mined in a single block
/// are all detected by the SPV client via FFI.
#[test]
fn test_ffi_multiple_transactions_in_single_block() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let Some(dashd) = rt.block_on(DashdTestContext::new(TestChain::Minimal)) else {
        eprintln!("Skipping test (dashd context unavailable)");
        return;
    };
    if !dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    unsafe {
        let ctx = FFITestContext::new(dashd.addr);
        let wallet_id = ctx.add_wallet(&dashd.wallet.mnemonic);

        ctx.run();
        ctx.wait_for_sync(dashd.initial_height);

        let baseline_tx_count = ctx.transaction_count(&wallet_id);
        let (baseline_balance, _) = ctx.get_wallet_balance(&wallet_id);
        tracing::info!("Baseline: tx_count={}, balance={}", baseline_tx_count, baseline_balance);

        // Send 3 transactions of different amounts to the SPV wallet
        let receive_address = ctx.get_receive_address(&wallet_id);
        let amounts = [
            Amount::from_sat(50_000_000),
            Amount::from_sat(75_000_000),
            Amount::from_sat(120_000_000),
        ];
        let mut txids = Vec::new();
        for amount in &amounts {
            let txid = dashd.node.send_to_address(&receive_address, *amount);
            tracing::info!("Sent {} to FFI wallet, txid: {}", amount, txid);
            txids.push(txid);
        }

        // Mine a single block to confirm all 3
        let miner_address = dashd.node.get_new_address_from_wallet("default");
        dashd.node.generate_blocks(1, &miner_address);
        let expected_height = dashd.initial_height + 1;
        ctx.wait_for_sync(expected_height);

        let final_tx_count = ctx.transaction_count(&wallet_id);
        let (final_balance, _) = ctx.get_wallet_balance(&wallet_id);

        assert_eq!(
            final_tx_count,
            baseline_tx_count + 3,
            "Expected 3 new transactions, got {}",
            final_tx_count - baseline_tx_count
        );

        // Since dashd and SPV share the same wallet, sends are internal transfers.
        // The only balance change is the transaction fees deducted by dashd.
        let fees_paid = baseline_balance - final_balance;
        assert!(
            final_balance < baseline_balance,
            "Balance should decrease by fees for internal transfers"
        );
        assert!(fees_paid < 1_000_000, "Total fees ({}) should be reasonable", fees_paid);

        for txid in &txids {
            assert!(
                ctx.has_transaction(&wallet_id, txid),
                "Wallet should contain transaction {}",
                txid
            );
        }

        ctx.tracker().assert_no_errors();
        tracing::info!(
            "All 3 transactions found: tx_count {} -> {}, balance {} -> {} (fees={})",
            baseline_tx_count,
            final_tx_count,
            baseline_balance,
            final_balance,
            fees_paid
        );
    }
}

/// Verify that transactions sent one per block over several blocks are each detected
/// incrementally by the SPV client via FFI.
#[test]
fn test_ffi_multiple_transactions_across_blocks() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let Some(dashd) = rt.block_on(DashdTestContext::new(TestChain::Minimal)) else {
        eprintln!("Skipping test (dashd context unavailable)");
        return;
    };
    if !dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    unsafe {
        let ctx = FFITestContext::new(dashd.addr);
        let wallet_id = ctx.add_wallet(&dashd.wallet.mnemonic);

        ctx.run();
        ctx.wait_for_sync(dashd.initial_height);

        let baseline_tx_count = ctx.transaction_count(&wallet_id);
        let (baseline_balance, _) = ctx.get_wallet_balance(&wallet_id);
        tracing::info!("Baseline: tx_count={}, balance={}", baseline_tx_count, baseline_balance);

        // Send 1 tx per block, 3 iterations
        let amounts = [
            Amount::from_sat(30_000_000),
            Amount::from_sat(60_000_000),
            Amount::from_sat(90_000_000),
        ];
        let miner_address = dashd.node.get_new_address_from_wallet("default");
        let mut current_height = dashd.initial_height;
        let mut txids = Vec::new();

        for (i, amount) in amounts.iter().enumerate() {
            let receive_address = ctx.get_receive_address(&wallet_id);
            let txid = dashd.node.send_to_address(&receive_address, *amount);
            tracing::info!("Iteration {}: sent {} to FFI wallet, txid: {}", i, amount, txid);
            txids.push(txid);

            dashd.node.generate_blocks(1, &miner_address);
            current_height += 1;
            ctx.wait_for_sync(current_height);

            let tx_count = ctx.transaction_count(&wallet_id);
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
        let (final_balance, _) = ctx.get_wallet_balance(&wallet_id);

        // Internal transfers: only fees are deducted
        let fees_paid = baseline_balance - final_balance;
        assert!(
            final_balance < baseline_balance,
            "Balance should decrease by fees for internal transfers"
        );
        assert!(fees_paid < 1_000_000, "Total fees ({}) should be reasonable", fees_paid);

        for txid in &txids {
            assert!(
                ctx.has_transaction(&wallet_id, txid),
                "Wallet should contain transaction {}",
                txid
            );
        }

        ctx.tracker().assert_no_errors();
        tracing::info!(
            "All iterations complete: tx_count {} -> {}, balance {} -> {} (fees={})",
            baseline_tx_count,
            baseline_tx_count + amounts.len(),
            baseline_balance,
            final_balance,
            fees_paid
        );
    }
}
