use std::sync::atomic::Ordering;
use std::time::Duration;

use dash_spv::test_utils::{DashdTestContext, TestChain};
use dash_spv_ffi::FFIAccountKind;
use dashcore::hashes::Hash;
use dashcore::Amount;

use super::context::FFITestContext;

#[test]
fn test_all_callbacks_during_sync() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    // TODO: This should doesn't need a full chain but its currently flaky with the minimal chain
    //       will be fixed once the flakiness is resolved.
    let Some(dashd) = rt.block_on(DashdTestContext::new(TestChain::Full)) else {
        return;
    };

    unsafe {
        let ctx = FFITestContext::new(dashd.addr);
        let tracker = ctx.tracker().clone();

        ctx.add_wallet(&dashd.wallet.mnemonic);
        ctx.run();
        tracing::info!("FFI client running with all callback types");

        ctx.wait_for_sync(dashd.initial_height);

        // Validate sync event callbacks
        let sync_start = tracker.sync_start_count.load(Ordering::SeqCst);
        let headers_stored = tracker.block_headers_stored_count.load(Ordering::SeqCst);
        let header_complete = tracker.block_header_sync_complete_count.load(Ordering::SeqCst);
        let filter_headers_stored = tracker.filter_headers_stored_count.load(Ordering::SeqCst);
        let filter_header_complete =
            tracker.filter_headers_sync_complete_count.load(Ordering::SeqCst);
        let filters_stored = tracker.filters_stored_count.load(Ordering::SeqCst);
        let filters_sync_complete = tracker.filters_sync_complete_count.load(Ordering::SeqCst);
        let blocks_needed = tracker.blocks_needed_count.load(Ordering::SeqCst);
        let block_processed = tracker.block_processed_count.load(Ordering::SeqCst);
        let sync_complete = tracker.sync_complete_count.load(Ordering::SeqCst);

        tracing::info!("Callback Summary");
        tracing::info!(
            "Sync: start={}, headers_stored={}, header_complete={}, filter_headers={}, \
             filter_complete={}, filters_stored={}, filters_sync={}, blocks_needed={}, \
             block_processed={}, sync_complete={}",
            sync_start,
            headers_stored,
            header_complete,
            filter_headers_stored,
            filter_header_complete,
            filters_stored,
            filters_sync_complete,
            blocks_needed,
            block_processed,
            sync_complete
        );

        assert!(sync_start > 0, "on_sync_start should have been called");
        assert!(headers_stored > 0, "on_block_headers_stored should have been called");
        assert_eq!(header_complete, 1, "on_block_header_sync_complete should be called once");
        assert!(filter_headers_stored > 0, "on_filter_headers_stored should have been called");
        assert_eq!(
            filter_header_complete, 1,
            "on_filter_headers_sync_complete should be called once"
        );
        assert!(filters_stored > 0, "on_filters_stored should have been called");
        assert!(filters_sync_complete > 0, "on_filters_sync_complete should have been called");
        assert!(blocks_needed > 0, "on_blocks_needed should have been called");
        assert!(block_processed > 0, "on_block_processed should have been called");
        assert_eq!(sync_complete, 1, "on_sync_complete should be called once");

        // Validate network event callbacks
        let peer_connected = tracker.peer_connected_count.load(Ordering::SeqCst);
        let peers_updated = tracker.peers_updated_count.load(Ordering::SeqCst);
        let last_peer_count = tracker.last_connected_peer_count.load(Ordering::SeqCst);
        let last_best_height = tracker.last_best_height.load(Ordering::SeqCst);

        tracing::info!(
            "Network: peer_connected={}, peers_updated={}, last_peer_count={}, best_height={}",
            peer_connected,
            peers_updated,
            last_peer_count,
            last_best_height
        );

        assert!(peer_connected > 0, "on_peer_connected should have been called");
        assert!(peers_updated > 0, "on_peers_updated should have been called");
        assert!(last_peer_count > 0, "at least one peer should be tracked");
        assert!(last_best_height > 0, "best height from peers should be positive");

        let connected_peers = tracker.connected_peers.lock().unwrap();
        assert!(!connected_peers.is_empty(), "connected_peers should contain at least one entry");
        let dashd_addr = dashd.addr.to_string();
        assert!(
            connected_peers.iter().any(|p| p.contains(&dashd_addr)),
            "connected_peers should contain the dashd address {}: {:?}",
            dashd_addr,
            *connected_peers
        );
        drop(connected_peers);

        // Wait for wallet callbacks (they travel on a separate channel from sync events).
        // Wait on `block_processed_wallet_count` because it is bumped last in the
        // callback, after all per-record state has been written. Reading the
        // record counter afterwards is therefore guaranteed to see the matching
        // increment.
        tracker.wait_for_callback(&tracker.block_processed_wallet_count, 0, "block_processed");

        // Validate wallet event callbacks (test wallet has transactions)
        let block_records = tracker.block_processed_wallet_record_count.load(Ordering::SeqCst);
        let block_changes = tracker.block_processed_wallet_count.load(Ordering::SeqCst);
        let received = tracker.transaction_received_count.load(Ordering::SeqCst);
        let instant_send_locked =
            tracker.transaction_instant_send_locked_count.load(Ordering::SeqCst);

        tracing::info!(
            "Wallet: received={}, instant_send_locked={}, block_changes={}, block_records={}",
            received,
            instant_send_locked,
            block_changes,
            block_records
        );

        assert!(
            block_records > 0,
            "on_block_processed should deliver records for a wallet with transactions"
        );
        assert!(
            block_changes > 0,
            "on_block_processed should fire for blocks containing wallet records"
        );
        assert_eq!(
            received, 0,
            "on_transaction_detected must not fire during historical block sync"
        );
        assert_eq!(
            instant_send_locked, 0,
            "on_transaction_instant_send_locked should not fire during initial sync"
        );

        // Validate SyncedHeightUpdated callback (atomicity boundary for persistence flush).
        // Wait explicitly for the callback because it travels on the same wallet
        // broadcast channel as `BlockProcessed` but is dispatched separately,
        // so observing block-processed records does not guarantee it has fired yet.
        tracker.wait_for_callback(&tracker.synced_height_updated_count, 0, "synced_height_updated");
        let synced_height_fired = tracker.synced_height_updated_count.load(Ordering::SeqCst);
        let last_synced_height = tracker.last_synced_height.load(Ordering::SeqCst);
        assert!(
            synced_height_fired > 0,
            "on_synced_height_updated should fire at least once during sync"
        );
        assert!(
            last_synced_height >= dashd.initial_height,
            "last_synced_height ({}) should be at least initial_height ({}) after sync",
            last_synced_height,
            dashd.initial_height
        );

        // Validate sync cycle (initial sync is cycle 0)
        let last_sync_cycle = tracker.last_sync_cycle.load(Ordering::SeqCst);
        assert_eq!(last_sync_cycle, 0, "Initial sync should be cycle 0");

        // Validate callback lifecycle ordering
        let sync_start_seq = tracker.sync_start_seq.load(Ordering::SeqCst);
        let header_complete_seq = tracker.header_complete_seq.load(Ordering::SeqCst);
        let filter_header_complete_seq = tracker.filter_header_complete_seq.load(Ordering::SeqCst);
        let filters_sync_complete_seq = tracker.filters_sync_complete_seq.load(Ordering::SeqCst);
        let sync_complete_seq = tracker.sync_complete_seq.load(Ordering::SeqCst);

        tracing::info!(
            "Sequence ordering: sync_start={}, header_complete={}, filter_header_complete={}, \
             filters_sync_complete={}, sync_complete={}",
            sync_start_seq,
            header_complete_seq,
            filter_header_complete_seq,
            filters_sync_complete_seq,
            sync_complete_seq
        );

        assert!(
            sync_start_seq < header_complete_seq,
            "sync_start ({}) should precede header_complete ({})",
            sync_start_seq,
            header_complete_seq
        );
        assert!(
            header_complete_seq < filter_header_complete_seq,
            "header_complete ({}) should precede filter_header_complete ({})",
            header_complete_seq,
            filter_header_complete_seq
        );
        assert!(
            filter_header_complete_seq < filters_sync_complete_seq,
            "filter_header_complete ({}) should precede filters_sync_complete ({})",
            filter_header_complete_seq,
            filters_sync_complete_seq
        );
        assert!(
            filters_sync_complete_seq < sync_complete_seq,
            "filters_sync_complete ({}) should precede sync_complete ({})",
            filters_sync_complete_seq,
            sync_complete_seq
        );

        // Validate filter header ranges
        let filter_ranges = tracker.filter_header_ranges.lock().unwrap();
        assert!(!filter_ranges.is_empty(), "filter header ranges should be recorded");
        for &(start, end, tip) in filter_ranges.iter() {
            assert!(
                start <= end,
                "filter header range start ({}) should be <= end ({})",
                start,
                end
            );
            assert!(end <= tip, "filter header range end ({}) should be <= tip ({})", end, tip);
        }
        drop(filter_ranges);

        // Validate block processed heights
        let block_heights = tracker.processed_block_heights.lock().unwrap();
        assert!(!block_heights.is_empty(), "block processed heights should be recorded");
        for &h in block_heights.iter() {
            assert!(
                h >= 1 && h <= dashd.initial_height,
                "block processed height {} should be within [1, {}]",
                h,
                dashd.initial_height
            );
        }
        drop(block_heights);

        // Validate final state
        let final_header = tracker.last_header_tip.load(Ordering::SeqCst);
        let final_filter = tracker.last_filter_tip.load(Ordering::SeqCst);
        assert_eq!(final_header, dashd.initial_height, "Final header tip mismatch");
        assert_eq!(final_filter, dashd.initial_height, "Final filter tip mismatch");

        // Validate best height matches initial height
        assert_eq!(
            last_best_height, dashd.initial_height,
            "best height from peers should match initial height"
        );

        // Validate transaction data from initial sync. Historical sync only
        // touches the block-processed callback (off-chain callback must
        // remain silent during initial sync), so assert against that bucket
        // explicitly.
        let block_received = tracker.block_received_transactions.lock().unwrap();
        assert!(!block_received.is_empty(), "should have received block records during sync");
        assert!(
            block_received.iter().any(|&(_, amount)| amount != 0),
            "at least one block-record net_amount should be non-zero"
        );
        drop(block_received);

        // Every record observed during initial sync is a fresh insertion
        // (no prior mempool sighting), so each must arrive in the `inserted`
        // bucket of `BlockProcessed`.
        let bucket = tracker.block_record_inserted.lock().unwrap();
        assert!(!bucket.is_empty(), "block records should be captured");
        assert!(
            bucket.iter().all(|inserted| *inserted),
            "every block record during historical sync should arrive via `inserted`, got: {:?}",
            *bucket
        );
        drop(bucket);

        // Validate the BIP-44 account discriminant + index reach the FFI
        // boundary intact: every change observed during historical sync
        // belongs to the default BIP-44 account (index 0) of the test wallet.
        let account_types = tracker.block_account_types.lock().unwrap();
        let account_indices = tracker.block_account_indices.lock().unwrap();
        assert!(!account_types.is_empty(), "block account types should be captured");
        assert_eq!(
            account_types.len(),
            account_indices.len(),
            "block account types and indices must be paired 1:1"
        );
        assert!(
            account_types.iter().all(|t| *t == FFIAccountKind::StandardBIP44),
            "every block change should carry FFIAccountKind::StandardBIP44, got: {:?}",
            *account_types
        );
        assert!(
            account_indices.iter().all(|i| *i == 0),
            "every BIP-44 change should carry account_index = 0, got: {:?}",
            *account_indices
        );
        drop(account_indices);
        drop(account_types);

        // Masternodes are disabled in test config, so these should not fire
        let masternode_updated = tracker.masternode_state_updated_count.load(Ordering::SeqCst);
        assert_eq!(
            masternode_updated, 0,
            "masternode callbacks should not fire with masternodes disabled"
        );

        tracker.assert_no_errors();
    }
}

/// Verify wallet and network callbacks fire correctly after initial sync completes.
///
/// After initial sync, sends DASH to the wallet and mines a block. Verifies that
/// on_transaction_detected and on_balance_updated callbacks fire. Then disconnects
/// dashd peers and verifies on_peer_disconnected fires, followed by on_peer_connected
/// after automatic reconnection.
#[test]
fn test_callbacks_post_sync_transactions_and_disconnect() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let Some(dashd) = rt.block_on(DashdTestContext::new(TestChain::Minimal)) else {
        return;
    };
    if !dashd.supports_mining {
        eprintln!("Skipping test (dashd RPC miner not available)");
        return;
    }

    unsafe {
        let ctx = FFITestContext::new(dashd.addr);
        let tracker = ctx.tracker().clone();

        let wallet_id = ctx.add_wallet(&dashd.wallet.mnemonic);
        ctx.run();

        // Wait for initial sync
        ctx.wait_for_sync(dashd.initial_height);
        tracing::info!("Initial sync complete");

        // Record callback counts before post-sync operations
        let received_before = tracker.transaction_received_count.load(Ordering::SeqCst);
        let block_changes_before = tracker.block_processed_wallet_count.load(Ordering::SeqCst);
        let block_records_before =
            tracker.block_processed_wallet_record_count.load(Ordering::SeqCst);

        // Send DASH to the wallet. Wait for the off-chain callback before
        // mining so the SPV node observes the transaction in the mempool.
        // If we mine immediately, the block path can deliver the transaction
        // first and the off-chain callback would never fire.
        let receive_address = ctx.get_receive_address(&wallet_id);
        let send_amount = Amount::from_sat(100_000_000);
        let txid = dashd.node.send_to_address(&receive_address, send_amount);
        tracing::info!("Sent {} to wallet, txid: {}", send_amount, txid);

        tracker.wait_for_callback(
            &tracker.transaction_received_count,
            received_before,
            "transaction_received",
        );

        // The off-chain callback updates `last_unconfirmed` with the
        // post-event balance. Snapshot it now, before mining. After
        // confirmation the block-processed callback overwrites the same
        // field back toward zero, so this is the only window in which the
        // unconfirmed-balance update is observable.
        let unconfirmed_after_mempool = tracker.last_unconfirmed.load(Ordering::SeqCst);
        assert!(
            unconfirmed_after_mempool > 0,
            "balance.unconfirmed should be positive after mempool receipt, got {}",
            unconfirmed_after_mempool
        );

        let miner_address = dashd.node.get_new_address_from_wallet("default");
        dashd.node.generate_blocks(1, &miner_address);

        // Wait for incremental sync to complete
        ctx.wait_for_sync(dashd.initial_height + 1);

        // Wait for the block-processed callback. The per-callback counter is
        // bumped last in the callback, so observing it incremented guarantees
        // the per-record vectors and counters have already been updated.
        tracker.wait_for_callback(
            &tracker.block_processed_wallet_count,
            block_changes_before,
            "block_processed",
        );

        // Verify on_transaction_detected fired for the new transaction
        let received_after = tracker.transaction_received_count.load(Ordering::SeqCst);
        assert!(
            received_after > received_before,
            "on_transaction_detected should fire for post-sync transaction: {} -> {}",
            received_before,
            received_after
        );
        tracing::info!(
            "Off-chain transaction callback verified: {} -> {}",
            received_before,
            received_after
        );

        // Verify the sent txid appears in the off-chain callback data with a
        // non-zero net_amount. Asserting against the off-chain bucket (rather
        // than the union of off-chain + block records) ensures the off-chain
        // callback specifically delivered the txid — a broken off-chain
        // callback that pushed the wrong txid wouldn't be masked by the
        // block path. The SPV wallet and dashd share the same mnemonic so
        // the transaction is an internal transfer (wallet owns both inputs
        // and outputs); net_amount therefore equals approximately -fee, not
        // the nominal send amount.
        let sent_txid_bytes = *txid.as_byte_array();
        let received_txs = tracker.received_transactions.lock().unwrap();
        let sent_entry = received_txs.iter().find(|&&(id, _)| id == sent_txid_bytes);
        assert!(sent_entry.is_some(), "sent txid should appear in transaction callback data");
        let &(_, net_amount) = sent_entry.unwrap();
        // Internal transfer: net_amount = received - sent = (send_amount + change) - input = -fee.
        // The fee must be negative, non-zero, and small (< 0.001 DASH).
        assert!(
            net_amount < 0 && net_amount > -100_000,
            "internal transfer net_amount should equal -fee (small negative), got: {}",
            net_amount
        );
        drop(received_txs);

        // Verify the off-chain callback delivered the BIP-44 account
        // discriminant + index 0 (default test account).
        let received_types = tracker.received_account_types.lock().unwrap();
        let received_indices = tracker.received_account_indices.lock().unwrap();
        assert!(
            received_types.iter().all(|t| *t == FFIAccountKind::StandardBIP44),
            "off-chain callback should deliver FFIAccountKind::StandardBIP44, got: {:?}",
            *received_types
        );
        assert!(
            received_indices.iter().all(|i| *i == 0),
            "off-chain BIP-44 callback should deliver account_index = 0, got: {:?}",
            *received_indices
        );
        drop(received_indices);
        drop(received_types);

        // The post-sync block confirms a transaction that was already known
        // from the mempool, so the corresponding `BlockProcessed` change must
        // arrive in the `updated` bucket rather than `inserted`. Slice by
        // the pre-captured index so only post-sync entries are checked,
        // avoiding masking by any `updated` entry that might appear during
        // initial sync.
        let block_bucket = tracker.block_record_inserted.lock().unwrap();
        assert!(
            block_bucket.len() >= block_records_before as usize,
            "block_record_inserted length ({}) < block_records_before ({}): counter/vector mismatch",
            block_bucket.len(),
            block_records_before
        );
        let new_bucket = &block_bucket[block_records_before as usize..];
        assert!(
            new_bucket.iter().any(|inserted| !inserted),
            "post-sync block confirming a known mempool tx should arrive in the \
             `updated` bucket, got: {:?}",
            new_bucket
        );
        drop(block_bucket);

        let block_records_after =
            tracker.block_processed_wallet_record_count.load(Ordering::SeqCst);
        tracing::info!(
            "Block-processed record callback verified: {} -> {}",
            block_records_before,
            block_records_after
        );

        // Verify balance data from the most recent wallet event reflects a positive
        // confirmed balance.
        let last_confirmed = tracker.last_confirmed.load(Ordering::SeqCst);
        assert!(last_confirmed > 0, "last_confirmed should be positive after receiving funds");
        tracing::info!("Balance data verified: last_confirmed={}", last_confirmed);

        // Record connect count before disconnect
        let connect_before = tracker.peer_connected_count.load(Ordering::SeqCst);

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

        tracker.assert_no_errors();
    }
}
