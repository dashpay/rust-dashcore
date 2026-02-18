use dash_spv::network::NetworkEvent;
use dash_spv::sync::{ProgressPercentage, SyncEvent, SyncProgress};
use dash_spv::test_utils::DashCoreNode;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::wallet_manager::{WalletId, WalletManager};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, watch, RwLock};

use dash_spv::test_utils::SYNC_TIMEOUT;

use super::setup::{ClientHandle, TestContext};

/// Wait for sync to reach target height.
pub(super) async fn wait_for_sync(
    progress_receiver: &mut watch::Receiver<SyncProgress>,
    target_height: u32,
) {
    let timeout = tokio::time::sleep(SYNC_TIMEOUT);
    tokio::pin!(timeout);

    loop {
        // Check current state before waiting for changes — the receiver may
        // already hold a value that satisfies the condition.
        {
            let update = progress_receiver.borrow_and_update();
            let header_height = update.headers().ok().map(|h| h.current_height()).unwrap_or(0);
            let filters_height = update.filters().ok().map(|f| f.committed_height()).unwrap_or(0);
            if update.is_synced()
                && header_height >= target_height
                && filters_height >= target_height
            {
                return;
            }
        }

        tokio::select! {
            _ = &mut timeout => {
                let update = progress_receiver.borrow();
                panic!("Timeout waiting for sync to height {}. Current progress: {:?}",
                    target_height, update
                );
            }
            result = progress_receiver.changed() => {
                if result.is_err() {
                    panic!("Progress channel closed");
                }
            }
        }
    }
}

/// Count all unique transactions across wallet accounts.
pub(super) async fn count_wallet_transactions(
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &WalletId,
) -> usize {
    let wallet_read = wallet.read().await;
    let wallet_info = wallet_read.get_wallet_info(wallet_id).expect("Wallet info not found");
    let txids: HashSet<_> =
        wallet_info.accounts().all_accounts().iter().flat_map(|a| a.transactions.keys()).collect();
    txids.len()
}

/// Get the spendable balance for a wallet.
pub(super) async fn get_spendable_balance(
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &WalletId,
) -> u64 {
    let wallet_read = wallet.read().await;
    wallet_read.get_wallet_balance(wallet_id).expect("Failed to get wallet balance").spendable()
}

/// Returns true for sync events that represent meaningful forward progress.
///
/// Used by restart and disconnection tests to decide when to interrupt.
/// Only counts BlockProcessed events that generated new addresses, since
/// re-processed blocks from storage with no new info are not real progress.
pub(super) fn is_progress_event(event: &SyncEvent) -> bool {
    match event {
        SyncEvent::BlockHeadersStored {
            ..
        }
        | SyncEvent::FilterHeadersStored {
            ..
        }
        | SyncEvent::FiltersStored {
            ..
        }
        | SyncEvent::BlocksNeeded {
            ..
        } => true,
        SyncEvent::BlockProcessed {
            new_addresses,
            ..
        } => !new_addresses.is_empty(),
        _ => false,
    }
}

/// Wait for a specific network event, returning true if seen within the timeout.
pub(super) async fn wait_for_network_event(
    receiver: &mut broadcast::Receiver<NetworkEvent>,
    predicate: impl Fn(&NetworkEvent) -> bool,
    max_wait: Duration,
) -> bool {
    let deadline = tokio::time::sleep(max_wait);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = &mut deadline => return false,
            result = receiver.recv() => {
                match result {
                    Ok(ref event) if predicate(event) => return true,
                    Ok(_) => continue,
                    Err(_) => return false,
                }
            }
        }
    }
}

/// Run a disconnect-and-reconnect loop during sync, then verify final state.
///
/// Waits for progress events, disconnects all peers after every 5th event,
/// validates disconnect/reconnect network events, and asserts wallet state
/// after sync completes.
pub(super) async fn run_disconnect_loop(
    mut client_handle: ClientHandle,
    node: &DashCoreNode,
    num_disconnects: usize,
    ctx: &TestContext,
) {
    let mut disconnect_count = 0;
    let mut events_since_disconnect = 0;

    let timeout = tokio::time::sleep(SYNC_TIMEOUT * 2);
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                let progress = client_handle.progress_receiver.borrow();
                panic!(
                    "Timeout after {} disconnections. Current progress: {:?}",
                    disconnect_count, progress
                );
            }
            result = client_handle.sync_event_receiver.recv() => {
                match result {
                    Ok(ref event) if is_progress_event(event) => {
                        events_since_disconnect += 1;
                        if disconnect_count < num_disconnects && events_since_disconnect >= 5 {
                            tracing::info!(
                                "Disconnection {}: disconnecting peers after: {}",
                                disconnect_count + 1,
                                event.description()
                            );
                            node.disconnect_all_peers();
                            disconnect_count += 1;
                            events_since_disconnect = 0;

                            let saw_disconnect = wait_for_network_event(
                                &mut client_handle.network_event_receiver,
                                |e| matches!(e, NetworkEvent::PeerDisconnected { .. }),
                                Duration::from_secs(10),
                            ).await;
                            assert!(saw_disconnect, "SPV should observe PeerDisconnected");
                            tracing::info!("SPV observed PeerDisconnected");

                            let saw_reconnect = wait_for_network_event(
                                &mut client_handle.network_event_receiver,
                                |e| matches!(e, NetworkEvent::PeerConnected { .. }),
                                Duration::from_secs(30),
                            ).await;
                            assert!(saw_reconnect, "SPV should reconnect after disconnection");
                            tracing::info!("SPV reconnected (PeerConnected)");
                        }
                    }
                    Ok(SyncEvent::SyncComplete { .. }) => {
                        tracing::info!(
                            "Sync completed after {} peer disconnections",
                            disconnect_count
                        );
                        break;
                    }
                    Ok(_) => continue,
                    Err(_) => {
                        panic!("Sync event channel error after {} disconnections", disconnect_count);
                    }
                }
            }
        }
    }

    assert_eq!(
        disconnect_count, num_disconnects,
        "Expected {} disconnections but only did {}",
        num_disconnects, disconnect_count
    );

    client_handle.stop().await;
    ctx.assert_synced(&client_handle.client.progress().await).await;
}
