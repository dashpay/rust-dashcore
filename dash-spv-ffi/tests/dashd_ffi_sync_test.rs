//! FFI Sync tests using dashd.
//!
//! These tests mirror Rust SPV sync tests but use FFI bindings
//! with the event-based API (dash_spv_ffi_client_run + event callbacks).

use dash_spv::test_utils::DashdTestContext;
use dash_spv_ffi::test_utils::{init_test_logging, FFITestContext};
use dashcore::Amount;
use std::sync::atomic::Ordering;

#[test]
fn test_wallet_sync_via_ffi() {
    init_test_logging();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let Some(mut dashd) = rt.block_on(DashdTestContext::new()) else {
        return;
    };

    unsafe {
        let ctx = FFITestContext::new(dashd.addr);

        let wallet_id = ctx.add_wallet(&dashd.wallet.mnemonic);
        tracing::info!("Added wallet, ID: {}", hex::encode(&wallet_id));

        ctx.run_with_sync_callbacks();
        tracing::info!("FFI client running");

        ctx.wait_for_sync(dashd.expected_height, 180);

        {
            let errors = ctx.tracker.errors.lock().unwrap();
            assert!(errors.is_empty(), "Unexpected sync errors: {:?}", *errors);
        }

        // Validate sync heights
        let final_header = ctx.tracker.last_header_tip.load(Ordering::SeqCst);
        let final_filter = ctx.tracker.last_filter_tip.load(Ordering::SeqCst);

        assert_eq!(final_header, dashd.expected_height, "Header height mismatch");
        assert_eq!(final_filter, dashd.expected_height, "Filter header height mismatch");
        tracing::info!("Heights match: headers={}, filters={}", final_header, final_filter);

        // Validate wallet balance
        let (confirmed, _unconfirmed) = ctx.get_wallet_balance(&wallet_id);
        let expected_balance = (dashd.wallet.balance * 100_000_000.0).round() as u64;
        tracing::info!(
            "Balance: confirmed={} satoshis, expected={} satoshis",
            confirmed,
            expected_balance
        );

        assert_eq!(confirmed, expected_balance, "Balance mismatch");

        ctx.cleanup();
    }

    rt.block_on(async { dashd.node.stop().await });

    tracing::info!("FFI sync test completed successfully");
}

/// Verify incremental sync works via FFI after generating new blocks with wallet transactions.
#[test]
fn test_ffi_sync_then_generate_blocks() {
    init_test_logging();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let Some(mut dashd) = rt.block_on(DashdTestContext::new()) else {
        return;
    };
    if !dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    unsafe {
        let ctx = FFITestContext::new(dashd.addr);
        let wallet_id = ctx.add_wallet(&dashd.wallet.mnemonic);

        ctx.run_with_sync_callbacks();
        ctx.wait_for_sync(dashd.expected_height, 180);

        let (initial_balance, _) = ctx.get_wallet_balance(&wallet_id);
        tracing::info!("Initial balance: {} satoshis", initial_balance);

        // Send DASH to the SPV wallet and mine blocks to confirm
        let receive_address = ctx.get_receive_address(&wallet_id);
        let addr: dashcore::Address =
            receive_address.parse::<dashcore::Address<_>>().unwrap().assume_checked();
        let send_amount = Amount::from_sat(100_000_000);
        let txid = dashd.node.send_to_address(&addr, send_amount);
        tracing::info!("Sent {} to FFI wallet, txid: {}", send_amount, txid);

        let miner_address = dashd.node.get_new_address_from_wallet("default");
        dashd.node.generate_blocks(6, &miner_address);

        // Wait for incremental sync to complete
        ctx.wait_for_next_sync(60);

        let (final_balance, _) = ctx.get_wallet_balance(&wallet_id);
        tracing::info!("Final balance: {} satoshis", final_balance);

        // Since dashd and SPV share the same wallet, sends are internal transfers.
        // The only balance change is the transaction fees. Verify balance changed.
        assert_ne!(initial_balance, final_balance, "Balance should change after new transactions");

        let final_header = ctx.tracker.last_header_tip.load(Ordering::SeqCst);
        assert_eq!(final_header, dashd.expected_height + 6, "Header tip should reflect new blocks");

        {
            let errors = ctx.tracker.errors.lock().unwrap();
            assert!(errors.is_empty(), "Unexpected sync errors: {:?}", *errors);
        }

        ctx.cleanup();
    }

    rt.block_on(async { dashd.node.stop().await });

    tracing::info!("FFI incremental sync test completed successfully");
}

/// Verify FFI client restart preserves consistent state across stop/recreate cycles.
#[test]
fn test_ffi_restart_consistency() {
    init_test_logging();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let Some(mut dashd) = rt.block_on(DashdTestContext::new()) else {
        return;
    };

    unsafe {
        // First sync
        tracing::info!("=== First FFI sync ===");
        let ctx = FFITestContext::new(dashd.addr);
        let wallet_id = ctx.add_wallet(&dashd.wallet.mnemonic);

        ctx.run_with_sync_callbacks();
        ctx.wait_for_sync(dashd.expected_height, 180);

        let (first_balance, _) = ctx.get_wallet_balance(&wallet_id);
        let first_header = ctx.tracker.last_header_tip.load(Ordering::SeqCst);

        {
            let errors = ctx.tracker.errors.lock().unwrap();
            assert!(errors.is_empty(), "Unexpected errors in first sync: {:?}", *errors);
        }

        tracing::info!("First sync: balance={}, header_tip={}", first_balance, first_header);

        // Restart with same storage
        tracing::info!("=== Restarting FFI client ===");
        let ctx = ctx.restart();
        let wallet_id = ctx.add_wallet(&dashd.wallet.mnemonic);

        ctx.run_with_sync_callbacks();
        // Give the client time to start and discover it's already synced
        std::thread::sleep(std::time::Duration::from_secs(3));
        ctx.wait_for_sync(dashd.expected_height, 180);

        let (second_balance, _) = ctx.get_wallet_balance(&wallet_id);
        let second_header = ctx.tracker.last_header_tip.load(Ordering::SeqCst);

        {
            let errors = ctx.tracker.errors.lock().unwrap();
            assert!(errors.is_empty(), "Unexpected errors in second sync: {:?}", *errors);
        }

        tracing::info!("Second sync: balance={}, header_tip={}", second_balance, second_header);

        // Verify state is identical
        assert_eq!(first_balance, second_balance, "Balance mismatch after restart");
        assert_eq!(first_header, second_header, "Header tip mismatch after restart");

        ctx.cleanup();
    }

    rt.block_on(async { dashd.node.stop().await });

    tracing::info!("FFI restart consistency test completed successfully");
}
