//! InstantSend integration tests using the masternode network harness.
//!
//! These tests exercise the SPV client's InstantSend plumbing end-to-end against
//! a real dashd masternode network: `InstantSendManager` validation, the mempool
//! manager's InstantSend status propagation to the wallet, and the transition from
//! an InstantSend-locked transaction to a ChainLocked block.

use dash_spv::sync::SyncState;
use dashcore::Amount;
use key_wallet::transaction_checking::TransactionContext;

use super::helpers::{
    wait_for_chainlock_height_at_least, wait_for_instant_lock_received,
    wait_for_instantsend_valid_at_least, wait_for_masternode_sync, wait_for_mn_state_event_above,
    wait_for_wallet_tx_status,
};
use super::setup::{
    create_and_start_client, create_mn_test_config, create_wallet_from_controller, receive_address,
    TestContext, SYNC_TIMEOUT,
};

/// Full InstantSend lifecycle: send → validated islock → wallet IS status →
/// chainlocked block → wallet InChainLockedBlock status.
///
/// Starts the full masternode network, drives a DKG cycle to form a live
/// `llmq_test` signing quorum, then sends three concurrent transactions from
/// the controller wallet to the SPV wallet (same mnemonic, so addresses line
/// up). For each transaction the test asserts:
///   1. `SyncEvent::InstantLockReceived { validated: true }` fires.
///   2. A wallet event reports `TransactionContext::InstantSend(_)` for the txid.
/// Then it mines blocks until a ChainLock is produced and asserts each tx
/// transitions to `TransactionContext::InChainLockedBlock(_)`.
///
/// Uses multi-thread runtime because DKG orchestration makes blocking RPC calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_instantsend_full_lifecycle() {
    let Some(mut ctx) = TestContext::new(false).await else {
        return;
    };

    let (wallet, wallet_id) = create_wallet_from_controller(&ctx.mn_ctx);
    let config = create_mn_test_config(ctx.storage_dir.clone(), ctx.mn_ctx.controller_addr);

    let mut client_handle = create_and_start_client(&config, std::sync::Arc::clone(&wallet)).await;

    // Initial masternode sync so the engine knows about the pre-generated quorums.
    let mn_progress =
        wait_for_masternode_sync(&mut client_handle.progress_receiver, SYNC_TIMEOUT).await;
    assert_eq!(mn_progress.state(), SyncState::Synced);
    let initial_height = mn_progress.current_height();
    tracing::info!("Initial masternode sync complete at height {}", initial_height);

    // Drive a DKG cycle so the newly formed llmq_test quorum can sign islocks and
    // chainlocks for subsequent transactions. Pre-generated data alone isn't enough
    // because its quorums are fixed in the past and won't produce fresh signatures.
    tracing::info!("Mining DKG cycle to form a live signing quorum...");
    ctx.mn_ctx.mine_dkg_cycle().expect("DKG cycle should succeed");

    // Make sure the SPV client has caught up to the post-DKG masternode state
    // before we start generating user transactions.
    let post_dkg_height = wait_for_mn_state_event_above(
        &mut client_handle.sync_event_receiver,
        initial_height,
        SYNC_TIMEOUT,
    )
    .await;
    tracing::info!("SPV caught up to post-DKG masternode state at height {}", post_dkg_height);

    // Send three independent transactions from the controller wallet to three
    // fresh SPV receive addresses. Because the SPV wallet is derived from the
    // same mnemonic as the controller wallet, these are internal self-transfers
    // that still get broadcast and islocked exactly like regular sends.
    const NUM_TXS: usize = 3;
    const SEND_AMOUNT: Amount = Amount::from_sat(50_000_000);
    let mut txids = Vec::with_capacity(NUM_TXS);
    for i in 0..NUM_TXS {
        let addr = receive_address(&wallet, &wallet_id).await;
        let txid = ctx.mn_ctx.controller.send_to_address(&addr, SEND_AMOUNT);
        tracing::info!("Sent tx {}/{}: txid={} to {}", i + 1, NUM_TXS, txid, addr);
        txids.push(txid);
    }

    // Assert each transaction receives a validated InstantLock.
    for (i, txid) in txids.iter().enumerate() {
        let lock = wait_for_instant_lock_received(
            &mut client_handle.sync_event_receiver,
            *txid,
            true,
            SYNC_TIMEOUT,
        )
        .await;
        assert_eq!(lock.txid, *txid);
        tracing::info!("Tx {}/{} islocked (txid={})", i + 1, NUM_TXS, txid);
    }

    // Progress counter must reflect all validated locks.
    wait_for_instantsend_valid_at_least(
        &mut client_handle.progress_receiver,
        NUM_TXS as u32,
        SYNC_TIMEOUT,
    )
    .await;

    // Each tx must surface in the wallet with an InstantSend context. The wallet
    // may report it via `TransactionReceived` (first-seen) or a subsequent
    // `TransactionStatusChanged` — the helper accepts either.
    for (i, txid) in txids.iter().enumerate() {
        let status = wait_for_wallet_tx_status(
            &mut client_handle.wallet_event_receiver,
            *txid,
            |ctx| matches!(ctx, TransactionContext::InstantSend(_)),
            SYNC_TIMEOUT,
        )
        .await;
        assert!(matches!(status, TransactionContext::InstantSend(_)));
        tracing::info!("Tx {}/{} wallet-observed with InstantSend context", i + 1, NUM_TXS);
    }

    // Mine blocks until a ChainLock is produced and propagated. After the DKG
    // cycle above, the llmq_test quorum is eligible to sign chainlocks.
    tracing::info!("Mining blocks and waiting for ChainLock...");
    let cl_height = ctx
        .mn_ctx
        .mine_blocks_and_wait_for_chainlock(3, 60)
        .expect("ChainLock should be produced after DKG cycle completion");

    // SPV client must catch up to that ChainLock.
    let cl_sync_height = wait_for_chainlock_height_at_least(
        &mut client_handle.progress_receiver,
        cl_height,
        SYNC_TIMEOUT,
    )
    .await;
    assert!(cl_sync_height >= cl_height);
    tracing::info!("SPV synced to ChainLocked height {}", cl_sync_height);

    // Each previously islocked tx must now appear in a chainlocked block.
    for (i, txid) in txids.iter().enumerate() {
        let status = wait_for_wallet_tx_status(
            &mut client_handle.wallet_event_receiver,
            *txid,
            |ctx| matches!(ctx, TransactionContext::InChainLockedBlock(_)),
            SYNC_TIMEOUT,
        )
        .await;
        assert!(matches!(status, TransactionContext::InChainLockedBlock(_)));
        tracing::info!("Tx {}/{} transitioned to InChainLockedBlock", i + 1, NUM_TXS);
    }

    client_handle.stop().await;
}

/// InstantSend continues to work across a full DIP-0024 quorum rotation cycle.
///
/// Drives the chain to exactly one block before the next DKG cycle boundary,
/// sends an InstantSend transaction for the boundary block, then runs a full
/// DKG cycle with a per-block hook that sends one additional InstantSend
/// transaction after every block mined during phases 1-6, the commitment
/// block, and the 8 maturity blocks. After the cycle completes and the new
/// masternode state is observed by the SPV client, a final InstantSend
/// transaction is sent on one more block. Every transaction — pre-cycle,
/// in-cycle, and post-cycle — must produce a validated `InstantLockReceived`
/// event.
///
/// This proves that signing quorum availability remains continuous across a
/// quorum rotation: at no block within the transition window does an
/// InstantSend transaction fail to acquire a validated lock.
///
/// Uses multi-thread runtime because DKG orchestration makes blocking RPC calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_instantsend_across_quorum_rotation() {
    let Some(mut ctx) = TestContext::new(false).await else {
        return;
    };

    let (wallet, wallet_id) = create_wallet_from_controller(&ctx.mn_ctx);
    let config = create_mn_test_config(ctx.storage_dir.clone(), ctx.mn_ctx.controller_addr);

    let mut client_handle = create_and_start_client(&config, std::sync::Arc::clone(&wallet)).await;

    // Initial masternode sync.
    let mn_progress =
        wait_for_masternode_sync(&mut client_handle.progress_receiver, SYNC_TIMEOUT).await;
    assert_eq!(mn_progress.state(), SyncState::Synced);
    let initial_height = mn_progress.current_height();
    tracing::info!("Initial masternode sync complete at height {}", initial_height);

    // A first DKG cycle forms a live signing quorum that will be able to sign
    // InstantSend locks throughout the rotation test below.
    tracing::info!("Priming a signing quorum with an initial DKG cycle...");
    ctx.mn_ctx.mine_dkg_cycle().expect("Initial DKG cycle should succeed");
    let post_initial_height = wait_for_mn_state_event_above(
        &mut client_handle.sync_event_receiver,
        initial_height,
        SYNC_TIMEOUT,
    )
    .await;
    tracing::info!("SPV caught up to post-initial-DKG height {}", post_initial_height);

    // Align the chain to exactly one block before the next DKG cycle boundary.
    // We do this silently (no InstantSend per block) because the alignment
    // window is outside the rotation transition we care about.
    let dkg_interval = ctx.mn_ctx.metadata.dkg_interval as u64;
    let current_height = ctx
        .mn_ctx
        .controller
        .try_rpc_call("getblockcount", &[])
        .and_then(|v| v.as_u64())
        .expect("getblockcount") as u32;
    let remainder = current_height as u64 % dkg_interval;
    let blocks_to_boundary = (dkg_interval - remainder) as u32;
    // We want to stop exactly one block before the boundary, which means
    // mining (blocks_to_boundary - 1) more blocks. If we are already on that
    // position (remainder == dkg_interval - 1), skip is 0.
    let silent_skip = blocks_to_boundary.saturating_sub(1);
    tracing::info!(
        "Aligning to boundary-1: current={}, dkg_interval={}, silent_skip={}",
        current_height,
        dkg_interval,
        silent_skip
    );
    if silent_skip > 0 {
        ctx.mn_ctx.move_blocks(silent_skip as u64);
    }
    wait_for_mn_state_event_above(
        &mut client_handle.sync_event_receiver,
        post_initial_height,
        SYNC_TIMEOUT,
    )
    .await;

    // Pre-rotation IS transaction: sent now, will be mined in the block that
    // crosses the DKG cycle boundary. The receive address is fetched once and
    // reused for all in-cycle sends below as well — the SPV wallet's
    // `receive_address` accessor keeps returning the same "first unused"
    // address until the wallet processes a received tx, but multiple pays to
    // the same address still yield distinct txids, which is what the test
    // needs.
    let send_addr = receive_address(&wallet, &wallet_id).await;
    let send_amount = Amount::from_sat(50_000_000);

    let pre_rotation_txid = ctx.mn_ctx.controller.send_to_address(&send_addr, send_amount);
    tracing::info!("Pre-rotation (boundary) IS tx: {}", pre_rotation_txid);

    // Mine the boundary block containing the pre-rotation tx. Note: this call
    // runs before `mine_dkg_cycle_with_hook`, which will align internally (no
    // alignment needed since we are already on a boundary after this block).
    ctx.mn_ctx.move_blocks(1);

    // In-cycle IS sends: one per block mined during the DKG rotation. The
    // closure captures `sent_txids` and the pre-fetched address, and sends
    // directly via the controller RPC passed into the hook.
    let mut in_cycle_txids: Vec<(u32, dashcore::Txid)> = Vec::new();
    tracing::info!("Running DKG rotation with per-block IS sends...");
    ctx.mn_ctx
        .mine_dkg_cycle_with_hook(|node, height| {
            let txid = node.send_to_address(&send_addr, send_amount);
            tracing::info!("In-cycle IS tx at height {}: {}", height, txid);
            in_cycle_txids.push((height, txid));
        })
        .expect("Rotation DKG cycle should succeed");

    tracing::info!("Rotation cycle complete with {} in-cycle IS txs", in_cycle_txids.len());
    assert!(
        !in_cycle_txids.is_empty(),
        "mine_dkg_cycle_with_hook should have mined at least one hooked block"
    );

    // Wait for the SPV client to catch up to the post-rotation masternode
    // state before collecting islocks — we want every event the network
    // produced during the cycle to have landed.
    let post_cycle_height = wait_for_mn_state_event_above(
        &mut client_handle.sync_event_receiver,
        post_initial_height,
        SYNC_TIMEOUT,
    )
    .await;
    tracing::info!("SPV caught up to post-rotation height {}", post_cycle_height);

    // Assert the pre-rotation tx got a validated islock.
    let _ = wait_for_instant_lock_received(
        &mut client_handle.sync_event_receiver,
        pre_rotation_txid,
        true,
        SYNC_TIMEOUT,
    )
    .await;

    // Drain a validated islock for every in-cycle tx. Order is irrelevant
    // because `wait_for_instant_lock_received` filters by txid and ignores
    // non-matching events.
    for (height, txid) in &in_cycle_txids {
        let _ = wait_for_instant_lock_received(
            &mut client_handle.sync_event_receiver,
            *txid,
            true,
            SYNC_TIMEOUT,
        )
        .await;
        tracing::info!("In-cycle islock verified for tx {} at height {}", txid, height);
    }

    // Progress counter: 1 pre-rotation + N in-cycle locks must be reflected.
    let expected_valid = 1 + in_cycle_txids.len() as u32;
    wait_for_instantsend_valid_at_least(
        &mut client_handle.progress_receiver,
        expected_valid,
        SYNC_TIMEOUT,
    )
    .await;

    // Post-rotation IS: one more block with an IS lock — the final assertion
    // that signing keeps working after the rotation has fully completed.
    let final_txid = ctx.mn_ctx.controller.send_to_address(&send_addr, send_amount);
    tracing::info!("Post-rotation IS tx: {}", final_txid);
    ctx.mn_ctx.move_blocks(1);
    let _ = wait_for_instant_lock_received(
        &mut client_handle.sync_event_receiver,
        final_txid,
        true,
        SYNC_TIMEOUT,
    )
    .await;

    // And the progress counter must now include the post-rotation lock too.
    wait_for_instantsend_valid_at_least(
        &mut client_handle.progress_receiver,
        expected_valid + 1,
        SYNC_TIMEOUT,
    )
    .await;

    // Also assert every tx appears in the wallet with an InstantSend context.
    // Walk the full set in order: pre-rotation, in-cycle, final.
    let mut all_txids = Vec::with_capacity(in_cycle_txids.len() + 2);
    all_txids.push(pre_rotation_txid);
    all_txids.extend(in_cycle_txids.iter().map(|(_, t)| *t));
    all_txids.push(final_txid);
    for txid in &all_txids {
        let status = wait_for_wallet_tx_status(
            &mut client_handle.wallet_event_receiver,
            *txid,
            |ctx| matches!(ctx, TransactionContext::InstantSend(_)),
            SYNC_TIMEOUT,
        )
        .await;
        assert!(matches!(status, TransactionContext::InstantSend(_)));
    }

    client_handle.stop().await;
}

/// InstantSend lock arrives before the SPV sees the transaction.
///
/// Drives a DKG cycle, stops the SPV client, sends a transaction from the
/// controller, and waits for the controller to record an islock for that tx.
/// A fresh SPV client is then started against the same storage: when it
/// reconnects, the controller relays both the tx inv and the islock inv and
/// there is no ordering guarantee about which message the SPV processes first.
/// In particular, the islock may reach `InstantSendManager` before the
/// transaction reaches `MempoolManager`, exercising the `pending_is_locks`
/// path where an islock is held until the matching mempool entry arrives.
///
/// Regardless of exact ordering, the test asserts the end-to-end outcome: a
/// validated `InstantLockReceived` event plus a wallet event reporting the
/// transaction in an `InstantSend` context.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_instantsend_islock_arrives_before_tx() {
    let Some(mut ctx) = TestContext::new(false).await else {
        return;
    };

    let (wallet, wallet_id) = create_wallet_from_controller(&ctx.mn_ctx);
    let config = create_mn_test_config(ctx.storage_dir.clone(), ctx.mn_ctx.controller_addr);

    // Initial run: sync MN list and form a live signing quorum, then shut down.
    let mut client_handle = create_and_start_client(&config, std::sync::Arc::clone(&wallet)).await;
    let initial_mn =
        wait_for_masternode_sync(&mut client_handle.progress_receiver, SYNC_TIMEOUT).await;
    let initial_height = initial_mn.current_height();
    tracing::info!("Initial masternode sync at height {}", initial_height);

    tracing::info!("Mining DKG cycle to form a live signing quorum...");
    ctx.mn_ctx.mine_dkg_cycle().expect("DKG cycle should succeed");
    wait_for_mn_state_event_above(
        &mut client_handle.sync_event_receiver,
        initial_height,
        SYNC_TIMEOUT,
    )
    .await;

    tracing::info!("Stopping SPV client before sending the transaction");
    client_handle.stop().await;
    drop(client_handle);

    // Send the tx and wait for the controller to record an islock for it. This
    // ensures the islock exists on the network before the fresh SPV client
    // reconnects, so both the tx and the islock are relayed in quick succession
    // on reconnect with no guaranteed ordering.
    let addr = receive_address(&wallet, &wallet_id).await;
    let txid = ctx.mn_ctx.controller.send_to_address(&addr, Amount::from_sat(50_000_000));
    tracing::info!("Sent tx {} while SPV is down, waiting for controller islock...", txid);

    let island_deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut saw_islock = false;
    while std::time::Instant::now() < island_deadline {
        if let Some(raw) = ctx
            .mn_ctx
            .controller
            .try_rpc_call("getrawtransaction", &[txid.to_string().into(), 1.into()])
        {
            if raw.get("instantlock").and_then(|v| v.as_bool()).unwrap_or(false) {
                saw_islock = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    assert!(saw_islock, "Controller should produce an islock for txid {} within timeout", txid);
    tracing::info!("Controller reports islock for tx {}", txid);

    // Reconnect the SPV client against the same storage. Reusing the storage
    // keeps the previously synced masternode list so signature verification
    // for the islock succeeds on first processing.
    tracing::info!("Starting fresh SPV client to receive tx and islock together");
    let mut client_handle = create_and_start_client(&config, std::sync::Arc::clone(&wallet)).await;

    // The islock must land as validated — either on first arrival (if the tx
    // landed first) or via the pending_is_locks path (if the islock landed
    // first and had to wait for the tx).
    let lock = wait_for_instant_lock_received(
        &mut client_handle.sync_event_receiver,
        txid,
        true,
        SYNC_TIMEOUT,
    )
    .await;
    assert_eq!(lock.txid, txid);

    // And the wallet must observe it with an InstantSend context regardless of
    // the internal ordering.
    let status = wait_for_wallet_tx_status(
        &mut client_handle.wallet_event_receiver,
        txid,
        |ctx| matches!(ctx, TransactionContext::InstantSend(_)),
        SYNC_TIMEOUT,
    )
    .await;
    assert!(matches!(status, TransactionContext::InstantSend(_)));

    client_handle.stop().await;
}
