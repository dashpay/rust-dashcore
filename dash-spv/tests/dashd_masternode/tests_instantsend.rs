//! InstantSend integration tests using the masternode network harness.
//!
//! These tests exercise the SPV client's InstantSend plumbing end-to-end against
//! a real dashd masternode network: `InstantSendManager` validation, the mempool
//! manager's InstantSend status propagation to the wallet, and the transition from
//! an InstantSend-locked transaction to a ChainLocked block.

use std::sync::Arc;

use dash_spv::sync::SyncState;
use dashcore::Amount;
use key_wallet::transaction_checking::TransactionContext;

use super::helpers::{
    mine_dkg_cycle_and_wait, wait_for_chainlock_height_at_least, wait_for_instant_lock_received,
    wait_for_instantsend_valid_at_least, wait_for_masternode_sync,
    wait_for_mn_state_with_stored_cycle_above, wait_for_wallet_tx_status,
    wait_for_wallet_txs_chainlocked,
};
use super::setup::{
    create_and_start_client, create_mn_test_config, create_wallet_from_controller, receive_address,
    wait_for_controller_islock, TestContext, SYNC_TIMEOUT,
};

/// Full InstantSend lifecycle: send -> validated islock -> wallet IS status ->
/// chainlocked block -> wallet InChainLockedBlock status.
///
/// Starts the full masternode network, drives a DKG cycle to form a live
/// `llmq_test` signing quorum, then sends three sequential transactions from
/// the controller wallet to the SPV wallet (same mnemonic, so addresses line
/// up). The sends are sequential rather than concurrent because regtest's
/// 4-MN quorum has trouble keeping multiple concurrent IS signing sessions
/// alive past the session timeout. For each transaction the test asserts:
///   1. `SyncEvent::InstantLockReceived { validated: true }` fires.
///   2. A wallet event reports `TransactionContext::InstantSend(_)` for the txid.
/// Then it mines blocks until a ChainLock is produced and asserts each tx
/// transitions to `TransactionContext::InChainLockedBlock(_)`.
#[tokio::test]
async fn test_instantsend_full_lifecycle() {
    let Some(mut ctx) = TestContext::new(false).await else {
        return;
    };

    let (wallet, wallet_id) = create_wallet_from_controller(&ctx.mn_ctx);
    let config =
        create_mn_test_config(ctx.storage_path().to_path_buf(), ctx.mn_ctx.controller_addr);

    let mut client_handle = create_and_start_client(&config, Arc::clone(&wallet)).await;

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
    let post_dkg_height =
        mine_dkg_cycle_and_wait(&mut ctx, &mut client_handle.sync_event_receiver, initial_height)
            .await;
    tracing::info!("SPV caught up to post-DKG masternode state at height {}", post_dkg_height);

    // Send transactions sequentially from the controller wallet, waiting for
    // each IS lock before sending the next. Sequential sends avoid concurrent
    // signing sessions on regtest's small quorum (4 MNs) where UTXO
    // dependencies between txs can delay sigShare collection past the session
    // timeout.
    const NUM_TXS: usize = 3;
    const SEND_AMOUNT: Amount = Amount::from_sat(50_000_000);
    let mut txids = Vec::with_capacity(NUM_TXS);
    for i in 0..NUM_TXS {
        let addr = receive_address(&wallet, &wallet_id).await;
        let txid = ctx.mn_ctx.controller.send_to_address(&addr, SEND_AMOUNT);
        tracing::info!("Sent tx {}/{}: txid={} to {}", i + 1, NUM_TXS, txid, addr);

        wait_for_controller_islock(&mut ctx.mn_ctx, &txid, 60).await;
        let lock = wait_for_instant_lock_received(
            &mut client_handle.sync_event_receiver,
            txid,
            true,
            SYNC_TIMEOUT,
        )
        .await;
        assert_eq!(lock.txid, txid);
        tracing::info!("Tx {}/{} islocked (txid={})", i + 1, NUM_TXS, txid);
        txids.push(txid);
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
    // `TransactionStatusChanged`, the helper accepts either.
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

    // Wallet-side assertion: every previously-IS-locked tx must now be
    // surfaced as chainlock-finalized. A single `BlockProcessed
    // { chain_lock: Some(..) }` event can cover all of them at once
    // when they confirm in the same chainlocked block, so use the
    // plural helper rather than a per-txid wait that would only
    // consume the first event.
    wait_for_wallet_txs_chainlocked(&mut client_handle.wallet_event_receiver, &txids, SYNC_TIMEOUT)
        .await;
    tracing::info!("All {} txs wallet-finalized via chainlock", NUM_TXS);

    client_handle.stop().await;
}

/// InstantSend works before and after a DIP-0024 quorum rotation cycle.
///
/// Drives two DKG cycles: the first forms a signing quorum and verifies an
/// IS lock, the second performs the rotation and verifies a post-rotation
/// IS lock. This proves signing quorum availability survives the rotation.
#[tokio::test]
async fn test_instantsend_across_quorum_rotation() {
    let Some(mut ctx) = TestContext::new(false).await else {
        return;
    };

    let (wallet, wallet_id) = create_wallet_from_controller(&ctx.mn_ctx);
    let config =
        create_mn_test_config(ctx.storage_path().to_path_buf(), ctx.mn_ctx.controller_addr);

    let mut client_handle = create_and_start_client(&config, Arc::clone(&wallet)).await;

    let mn_progress =
        wait_for_masternode_sync(&mut client_handle.progress_receiver, SYNC_TIMEOUT).await;
    assert_eq!(mn_progress.state(), SyncState::Synced);
    let initial_height = mn_progress.current_height();

    // First DKG cycle: forms a signing quorum.
    tracing::info!("Mining first DKG cycle...");
    let post_first_height =
        mine_dkg_cycle_and_wait(&mut ctx, &mut client_handle.sync_event_receiver, initial_height)
            .await;
    tracing::info!("Post-first-DKG height {}", post_first_height);

    // Pre-rotation IS lock.
    let send_addr = receive_address(&wallet, &wallet_id).await;
    let send_amount = Amount::from_sat(50_000_000);
    let pre_txid = ctx.mn_ctx.controller.send_to_address(&send_addr, send_amount);
    tracing::info!("Pre-rotation IS tx: {}", pre_txid);
    wait_for_controller_islock(&mut ctx.mn_ctx, &pre_txid, 60).await;
    let _ = wait_for_instant_lock_received(
        &mut client_handle.sync_event_receiver,
        pre_txid,
        true,
        SYNC_TIMEOUT,
    )
    .await;
    tracing::info!("Pre-rotation IS lock verified");

    // Second DKG cycle: rotation. The post-rotation IS lock below needs the new
    // rotation cycle stored in `rotated_quorums_per_cycle`, which only happens
    // when a QRInfo completes with every rotated quorum freshly validated.
    // Depending on the timing race between the tip MnListDiff and the mining
    // window QRInfos, the first `MasternodeStateUpdated` after rotation may come
    // from either pipeline: the Incremental path (MnListDiff-only, cycle not
    // yet stored) or the QuorumValidation path (cycle already stored). Bump
    // mocktime to nudge the tick handler if a catch-up QRInfo is still needed,
    // and wait specifically for an update carrying a freshly-validated
    // post-rotation cycle.
    tracing::info!("Mining second DKG cycle (rotation)...");
    ctx.mn_ctx.mine_dkg_cycle().expect("Second DKG cycle should succeed");
    ctx.mn_ctx.bump_mocktime(30);
    let post_rotation_height = wait_for_mn_state_with_stored_cycle_above(
        &mut client_handle.sync_event_receiver,
        post_first_height,
        SYNC_TIMEOUT,
    )
    .await;
    tracing::info!("Post-rotation height {}", post_rotation_height);

    // Post-rotation IS lock.
    let post_txid = ctx.mn_ctx.controller.send_to_address(&send_addr, send_amount);
    tracing::info!("Post-rotation IS tx: {}", post_txid);
    wait_for_controller_islock(&mut ctx.mn_ctx, &post_txid, 60).await;
    let _ = wait_for_instant_lock_received(
        &mut client_handle.sync_event_receiver,
        post_txid,
        true,
        SYNC_TIMEOUT,
    )
    .await;
    tracing::info!("Post-rotation IS lock verified");

    wait_for_instantsend_valid_at_least(&mut client_handle.progress_receiver, 2, SYNC_TIMEOUT)
        .await;

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
#[tokio::test]
async fn test_instantsend_islock_arrives_before_tx() {
    let Some(mut ctx) = TestContext::new(false).await else {
        return;
    };

    let (wallet, wallet_id) = create_wallet_from_controller(&ctx.mn_ctx);
    let config =
        create_mn_test_config(ctx.storage_path().to_path_buf(), ctx.mn_ctx.controller_addr);

    // Initial run: sync MN list and form a live signing quorum, then shut down.
    let mut client_handle = create_and_start_client(&config, Arc::clone(&wallet)).await;
    let initial_mn =
        wait_for_masternode_sync(&mut client_handle.progress_receiver, SYNC_TIMEOUT).await;
    let initial_height = initial_mn.current_height();
    tracing::info!("Initial masternode sync at height {}", initial_height);

    tracing::info!("Mining DKG cycle to form a live signing quorum...");
    mine_dkg_cycle_and_wait(&mut ctx, &mut client_handle.sync_event_receiver, initial_height).await;

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
    wait_for_controller_islock(&mut ctx.mn_ctx, &txid, 60).await;
    tracing::info!("Controller reports islock for tx {}", txid);

    // Reconnect the SPV client against the same storage. Reusing the storage
    // keeps the previously synced masternode list so signature verification
    // for the islock succeeds on first processing.
    tracing::info!("Starting fresh SPV client to receive tx and islock together");
    // Bump mocktime before starting the fresh client so the MN scheduler
    // relays the islock to the new peer once it connects.
    ctx.mn_ctx.bump_mocktime(30);
    let mut client_handle = create_and_start_client(&config, Arc::clone(&wallet)).await;

    // Wait for initial MN sync to complete on the fresh client. This populates
    // rotated_quorums_per_cycle so the pending islock can be validated.
    wait_for_masternode_sync(&mut client_handle.progress_receiver, SYNC_TIMEOUT).await;

    // The isdlock may have arrived before MN sync (validated=false, queued as
    // pending). MasternodeStateUpdated triggers validate_pending which re-emits
    // with validated=true. Bump mocktime again to ensure the scheduler fires.
    ctx.mn_ctx.bump_mocktime(30);

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
