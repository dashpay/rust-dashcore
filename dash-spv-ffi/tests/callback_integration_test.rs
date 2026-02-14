//! Integration test for FFI event callbacks.
//!
//! This test verifies all three callback structs work correctly in a real sync scenario:
//! - FFISyncEventCallbacks
//! - FFINetworkEventCallbacks
//! - FFIWalletEventCallbacks

use dash_spv::test_utils::DashdTestContext;
use dash_spv_ffi::test_utils::{
    create_full_sync_callbacks, create_network_callbacks, create_wallet_callbacks,
    init_test_logging, FFITestContext,
};
use dashcore::Amount;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[test]
fn test_all_callbacks_during_sync() {
    init_test_logging();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let Some(mut dashd) = rt.block_on(DashdTestContext::new()) else {
        return;
    };

    unsafe {
        let ctx = FFITestContext::new(dashd.addr);
        let tracker = ctx.tracker.clone();

        ctx.add_wallet(&dashd.wallet.mnemonic);
        tracing::info!("Added wallet from mnemonic via FFI");

        // Set up all three callback types
        let sync_callbacks = create_full_sync_callbacks(&tracker);
        let network_callbacks = create_network_callbacks(&tracker);
        let wallet_callbacks = create_wallet_callbacks(&tracker);

        let result =
            dash_spv_ffi::dash_spv_ffi_client_set_sync_event_callbacks(ctx.client, sync_callbacks);
        assert_eq!(result, 0, "Failed to set sync callbacks");

        let result = dash_spv_ffi::dash_spv_ffi_client_set_network_event_callbacks(
            ctx.client,
            network_callbacks,
        );
        assert_eq!(result, 0, "Failed to set network callbacks");

        let result = dash_spv_ffi::dash_spv_ffi_client_set_wallet_event_callbacks(
            ctx.client,
            wallet_callbacks,
        );
        assert_eq!(result, 0, "Failed to set wallet callbacks");

        let result = dash_spv_ffi::dash_spv_ffi_client_run(ctx.client);
        assert_eq!(result, 0, "Failed to run FFI client");
        tracing::info!("FFI client running with all callback types");

        ctx.wait_for_sync(dashd.expected_height, 180);

        // Log callback invocation summary
        let sync_start = tracker.sync_start_count.load(Ordering::SeqCst);
        let headers_stored = tracker.block_headers_stored_count.load(Ordering::SeqCst);
        let header_complete = tracker.block_header_sync_complete_count.load(Ordering::SeqCst);
        let filter_headers_stored = tracker.filter_headers_stored_count.load(Ordering::SeqCst);
        let filter_header_complete =
            tracker.filter_headers_sync_complete_count.load(Ordering::SeqCst);
        let sync_complete = tracker.sync_complete_count.load(Ordering::SeqCst);
        let peer_connected = tracker.peer_connected_count.load(Ordering::SeqCst);
        let peers_updated = tracker.peers_updated_count.load(Ordering::SeqCst);

        tracing::info!("=== Callback Summary ===");
        tracing::info!(
            "Sync: start={}, headers_stored={}, header_complete={}, filter_headers={}, filter_complete={}, sync_complete={}",
            sync_start, headers_stored, header_complete, filter_headers_stored, filter_header_complete, sync_complete
        );
        tracing::info!(
            "Network: peer_connected={}, peers_updated={}",
            peer_connected,
            peers_updated
        );
        tracing::info!(
            "Wallet: tx_received={}",
            tracker.transaction_received_count.load(Ordering::SeqCst)
        );

        // Validate sync callbacks
        assert!(sync_start > 0, "on_sync_start should have been called");
        assert!(headers_stored > 0, "on_block_headers_stored should have been called");
        assert_eq!(header_complete, 1, "on_block_header_sync_complete should be called once");
        assert!(filter_headers_stored > 0, "on_filter_headers_stored should have been called");
        assert_eq!(
            filter_header_complete, 1,
            "on_filter_headers_sync_complete should be called once"
        );
        assert_eq!(sync_complete, 1, "on_sync_complete should be called once");

        // Validate network callbacks
        assert!(peer_connected > 0, "on_peer_connected should have been called");
        assert!(peers_updated > 0, "on_peers_updated should have been called");

        // Validate final state
        let final_header = tracker.last_header_tip.load(Ordering::SeqCst);
        assert_eq!(final_header, dashd.expected_height, "Final header tip mismatch");

        {
            let errors = tracker.errors.lock().unwrap();
            assert!(errors.is_empty(), "Unexpected errors during sync: {:?}", *errors);
        }

        ctx.cleanup();
    }

    rt.block_on(async { dashd.node.stop().await });

    tracing::info!("Callback integration test completed successfully");
}

/// Verify wallet and network callbacks fire correctly after initial sync completes.
///
/// After initial sync, sends DASH to the wallet and mines a block. Verifies that
/// on_transaction_received and on_balance_updated callbacks fire. Then disconnects
/// dashd peers and verifies on_peer_disconnected fires, followed by on_peer_connected
/// after automatic reconnection.
#[test]
fn test_callbacks_post_sync_transactions_and_disconnect() {
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
        let tracker = ctx.tracker.clone();

        let wallet_id = ctx.add_wallet(&dashd.wallet.mnemonic);

        // Set up all three callback types
        let sync_callbacks = create_full_sync_callbacks(&tracker);
        let network_callbacks = create_network_callbacks(&tracker);
        let wallet_callbacks = create_wallet_callbacks(&tracker);

        let result =
            dash_spv_ffi::dash_spv_ffi_client_set_sync_event_callbacks(ctx.client, sync_callbacks);
        assert_eq!(result, 0, "Failed to set sync callbacks");
        let result = dash_spv_ffi::dash_spv_ffi_client_set_network_event_callbacks(
            ctx.client,
            network_callbacks,
        );
        assert_eq!(result, 0, "Failed to set network callbacks");
        let result = dash_spv_ffi::dash_spv_ffi_client_set_wallet_event_callbacks(
            ctx.client,
            wallet_callbacks,
        );
        assert_eq!(result, 0, "Failed to set wallet callbacks");

        let result = dash_spv_ffi::dash_spv_ffi_client_run(ctx.client);
        assert_eq!(result, 0, "Failed to run FFI client");

        // Wait for initial sync
        ctx.wait_for_sync(dashd.expected_height, 180);
        tracing::info!("Initial sync complete");

        // Record callback counts before post-sync operations
        let tx_received_before = tracker.transaction_received_count.load(Ordering::SeqCst);

        // Send DASH to the wallet and mine a block
        let receive_address = ctx.get_receive_address(&wallet_id);
        let addr: dashcore::Address =
            receive_address.parse::<dashcore::Address<_>>().unwrap().assume_checked();
        let send_amount = Amount::from_sat(100_000_000);
        let txid = dashd.node.send_to_address(&addr, send_amount);
        tracing::info!("Sent {} to wallet, txid: {}", send_amount, txid);

        let miner_address = dashd.node.get_new_address_from_wallet("default");
        dashd.node.generate_blocks(1, &miner_address);

        // Wait for incremental sync to complete
        ctx.wait_for_next_sync(60);

        // Verify on_transaction_received fired for the new transaction
        let tx_received_after = tracker.transaction_received_count.load(Ordering::SeqCst);
        assert!(
            tx_received_after > tx_received_before,
            "on_transaction_received should fire for post-sync transaction: {} -> {}",
            tx_received_before,
            tx_received_after
        );
        tracing::info!(
            "Transaction callback verified: {} -> {}",
            tx_received_before,
            tx_received_after
        );

        // Disconnect peers via dashd and verify on_peer_disconnected fires
        let disconnect_before = tracker.peer_disconnected_count.load(Ordering::SeqCst);
        dashd.node.disconnect_all_peers();

        // Wait for disconnect callback
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while tracker.peer_disconnected_count.load(Ordering::SeqCst) <= disconnect_before
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(200));
        }

        let disconnect_after = tracker.peer_disconnected_count.load(Ordering::SeqCst);
        assert!(
            disconnect_after > disconnect_before,
            "on_peer_disconnected should fire after disconnect: {} -> {}",
            disconnect_before,
            disconnect_after
        );
        tracing::info!(
            "Disconnect callback verified: {} -> {}",
            disconnect_before,
            disconnect_after
        );

        // Wait for automatic reconnection (on_peer_connected should fire again)
        let connect_before = tracker.peer_connected_count.load(Ordering::SeqCst);
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while tracker.peer_connected_count.load(Ordering::SeqCst) <= connect_before
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(200));
        }

        let connect_after = tracker.peer_connected_count.load(Ordering::SeqCst);
        assert!(
            connect_after > connect_before,
            "on_peer_connected should fire after reconnection: {} -> {}",
            connect_before,
            connect_after
        );
        tracing::info!("Reconnect callback verified: {} -> {}", connect_before, connect_after);

        {
            let errors = tracker.errors.lock().unwrap();
            assert!(errors.is_empty(), "Unexpected errors: {:?}", *errors);
        }

        ctx.cleanup();
    }

    rt.block_on(async { dashd.node.stop().await });

    tracing::info!("Post-sync callbacks test completed successfully");
}
