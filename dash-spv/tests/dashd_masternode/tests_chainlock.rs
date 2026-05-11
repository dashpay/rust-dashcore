//! ChainLock-driven wallet finalization tests using the masternode network harness.
//!
//! These tests exercise the chainlock fan-out from the SPV layer's
//! [`ChainLockManager`] into the wallet manager's chainlock-driven
//! record promotion. Each scenario lands on the deferred-sync /
//! live-arrival contract: during initial sync the wallet ignores
//! chainlocks and applies one at `SyncComplete { cycle: 0 }`, after
//! which every validated chainlock immediately promotes the relevant
//! transactions and fires
//! [`key_wallet_manager::WalletEvent::TransactionsChainlocked`].

use std::sync::Arc;

use dash_spv::sync::SyncState;
use dashcore::Amount;

use super::helpers::{
    mine_dkg_cycle_and_wait, wait_for_chainlock_height_at_least, wait_for_masternode_sync,
    wait_for_wallet_tx_chainlocked,
};
use super::setup::{
    create_and_start_client, create_mn_test_config, create_wallet_from_controller, receive_address,
    TestContext, SYNC_TIMEOUT,
};

/// Live arrival: send a tx into a block, mine through to a chainlock,
/// and assert the wallet emits [`WalletEvent::TransactionsChainlocked`]
/// carrying the tx's txid.
///
/// Drives the full live path: the tx lands as `InBlock` during normal
/// block processing, and a later chainlock promotes its context to
/// `InChainLockedBlock`.
/// Under the default `keep-finalized-transactions=false` feature the
/// full record is dropped at that moment, but the txid lives on in the
/// emitted event so the consumer can persist the finalization.
#[tokio::test]
async fn test_chainlock_promotes_in_block_tx() {
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

    ctx.mn_ctx
        .controller
        .try_rpc_call(
            "sporkupdate",
            &["SPORK_2_INSTANTSEND_ENABLED".into(), 4_070_908_800i64.into()],
        )
        .expect("disable SPORK_2_INSTANTSEND_ENABLED");

    // Form a live signing quorum so the network can sign chainlocks for
    // the blocks we're about to mine.
    let post_dkg_height =
        mine_dkg_cycle_and_wait(&mut ctx, &mut client_handle.sync_event_receiver, initial_height)
            .await;
    tracing::info!("Live signing quorum ready at height {}", post_dkg_height);

    // Send a tx from the controller to the SPV wallet. With IS disabled,
    // dashd includes it in the next block as a normal mempool tx.
    let addr = receive_address(&wallet, &wallet_id).await;
    let txid = ctx.mn_ctx.controller.send_to_address(&addr, Amount::from_sat(50_000_000));
    tracing::info!("Sent tx txid={} to {}", txid, addr);

    // Mine until a chainlock is produced. The chainlock will cover the
    // block carrying our tx and trigger the wallet-side promotion.
    let cl_height = ctx
        .mn_ctx
        .mine_blocks_and_wait_for_chainlock(3, 60)
        .expect("ChainLock should be produced after DKG cycle completion");

    // SPV catches up to the chainlock height.
    let cl_sync_height = wait_for_chainlock_height_at_least(
        &mut client_handle.progress_receiver,
        cl_height,
        SYNC_TIMEOUT,
    )
    .await;
    assert!(cl_sync_height >= cl_height);

    // Wallet event must surface chainlock-driven finality for our txid.
    let promoted_at = wait_for_wallet_tx_chainlocked(
        &mut client_handle.wallet_event_receiver,
        txid,
        SYNC_TIMEOUT,
    )
    .await;
    assert!(
        promoted_at >= cl_height,
        "wallet promotion height ({}) must reach the network chainlock height ({})",
        promoted_at,
        cl_height
    );

    client_handle.stop().await;
}
