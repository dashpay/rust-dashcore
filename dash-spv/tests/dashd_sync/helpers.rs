use dash_spv::network::NetworkEvent;
use dash_spv::sync::{ProgressPercentage, SyncEvent, SyncProgress, SyncState};
use dash_spv::test_utils::DashCoreNode;
use dashcore::Txid;
use key_wallet::transaction_checking::TransactionContext;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::WalletEvent;
use key_wallet_manager::{WalletId, WalletManager};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, watch, RwLock};

use dash_spv::test_utils::SYNC_TIMEOUT;

use super::setup::{ClientHandle, TestContext};

/// BIP39 "abandon abandon ... about" mnemonic. No regtest activity, used as
/// the default empty wallet across multi-wallet tests.
pub(super) const EMPTY_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Second well-known BIP39 vector mnemonic, used when an additional empty
/// wallet is needed alongside `EMPTY_MNEMONIC`.
pub(super) const SECONDARY_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

/// Read the headers manager's effective height (storage tip plus buffered).
fn current_header_height(handle: &ClientHandle) -> u32 {
    handle.progress_receiver.borrow().headers().ok().map(|h| h.current_height()).unwrap_or(0)
}

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
    let txids: HashSet<_> = wallet_info
        .accounts()
        .all_accounts()
        .iter()
        .flat_map(|a| a.transactions().keys())
        .collect();
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

/// Wait for a specific wallet's `synced_height` to reach `target`. Used to
/// wait for the per-wallet catch-up rescan rather than the manager-wide
/// progress channel, which only reflects the aggregate.
///
/// Subscribes before the upfront height check so an advance racing the
/// subscription is still observed via the event stream.
pub(super) async fn wait_for_wallet_synced(
    wallet: &Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    wallet_id: &WalletId,
    target: u32,
) {
    let (mut events, mut synced) = {
        let reader = wallet.read().await;
        let events = reader.subscribe_events();
        let synced = reader.get_wallet_info(wallet_id).expect("wallet info").synced_height();
        (events, synced)
    };
    if synced >= target {
        return;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let recv = tokio::time::timeout_at(deadline, events.recv()).await;
        match recv {
            Err(_) => {
                panic!("wallet did not reach synced_height {} within 30s, got {}", target, synced)
            }
            Ok(Err(_)) => {
                panic!("wallet event channel error before reaching synced_height {}", target);
            }
            Ok(Ok(WalletEvent::SyncHeightAdvanced {
                wallet_id: id,
                height,
            })) if id == *wallet_id => {
                synced = height;
                if synced >= target {
                    return;
                }
            }
            Ok(Ok(_)) => {}
        }
    }
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
            new_scripts,
            ..
        } => new_scripts.values().any(|v| !v.is_empty()),
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

/// Wait for a wallet `TransactionDetected` event within the given timeout.
/// Accepts both plain mempool and InstantSend-locked mempool arrivals.
/// Returns `Some(txid)` if received, `None` on timeout.
pub(super) async fn wait_for_mempool_tx(
    receiver: &mut broadcast::Receiver<WalletEvent>,
    max_wait: Duration,
) -> Option<Txid> {
    let timeout = tokio::time::sleep(max_wait);
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => return None,
            result = receiver.recv() => {
                match result {
                    Ok(WalletEvent::TransactionDetected { ref record, .. })
                        if matches!(
                            record.context,
                            TransactionContext::Mempool | TransactionContext::InstantSend(_)
                        ) =>
                    {
                        return Some(record.txid);
                    }
                    Ok(_) => continue,
                    Err(_) => return None,
                }
            }
        }
    }
}

/// Wait for the mempool manager to reach `Synced` state via the progress watch channel.
/// Returns `true` if the state is reached within the timeout, `false` otherwise.
pub(super) async fn wait_for_mempool_synced(
    progress_receiver: &mut watch::Receiver<SyncProgress>,
) -> bool {
    let timeout = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(timeout);

    loop {
        {
            let progress = progress_receiver.borrow_and_update();
            if progress.mempool().ok().is_some_and(|m| m.state() == SyncState::Synced) {
                return true;
            }
        }

        tokio::select! {
            _ = &mut timeout => return false,
            result = progress_receiver.changed() => {
                if result.is_err() {
                    return false;
                }
            }
        }
    }
}

/// Assert that no mempool `TransactionDetected` event arrives within the given duration.
pub(super) async fn assert_no_mempool_tx(
    receiver: &mut broadcast::Receiver<WalletEvent>,
    wait: Duration,
) {
    if let Some(txid) = wait_for_mempool_tx(receiver, wait).await {
        panic!("Unexpected TransactionDetected event with txid: {}", txid);
    }
}

/// Run a disconnect-and-reconnect loop during sync, then verify final state.
///
/// Waits for progress events, disconnects all peers after every 5th event,
/// validates disconnect/reconnect network events, and asserts wallet state
/// after sync completes. Also asserts header progress (storage tip plus
/// buffered) is monotonic across each disconnect cycle, so a regression that
/// drops validated chain state on disconnect is caught.
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
                                event
                            );
                            let pre_disconnect_height = current_header_height(&client_handle);
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

                            let post_reconnect_height = current_header_height(&client_handle);
                            assert!(
                                post_reconnect_height >= pre_disconnect_height,
                                "Header progress regressed across disconnect {}: {} -> {}",
                                disconnect_count, pre_disconnect_height, post_reconnect_height
                            );
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

/// Wait for two clients to sync to the target height concurrently.
pub(super) async fn wait_for_sync_both(
    a: &mut ClientHandle,
    b: &mut ClientHandle,
    target_height: u32,
) {
    tokio::join!(
        wait_for_sync(&mut a.progress_receiver, target_height),
        wait_for_sync(&mut b.progress_receiver, target_height),
    );
}

/// Wait for a mempool transaction event from two clients concurrently.
/// Asserts both detect the same txid.
pub(super) async fn wait_for_mempool_tx_both(
    a: &mut ClientHandle,
    b: &mut ClientHandle,
    timeout: Duration,
) -> Option<Txid> {
    let (r_a, r_b) = tokio::join!(
        wait_for_mempool_tx(&mut a.wallet_event_receiver, timeout),
        wait_for_mempool_tx(&mut b.wallet_event_receiver, timeout),
    );
    match (r_a, r_b) {
        (Some(txid_a), Some(txid_b)) => {
            assert_eq!(txid_a, txid_b, "Clients detected different txids");
            Some(txid_a)
        }
        (None, None) => None,
        (a, b) => panic!("Strategy mismatch: client_a={:?}, client_b={:?}", a, b),
    }
}

/// Collect N mempool transaction events from two clients concurrently.
/// Asserts both detect the same set of txids.
pub(super) async fn wait_for_mempool_txs_both(
    a: &mut ClientHandle,
    b: &mut ClientHandle,
    count: usize,
    timeout: Duration,
) -> HashSet<Txid> {
    async fn collect_n(
        receiver: &mut broadcast::Receiver<WalletEvent>,
        count: usize,
        timeout: Duration,
    ) -> HashSet<Txid> {
        let mut txids = HashSet::new();
        for _ in 0..count {
            let txid = wait_for_mempool_tx(receiver, timeout)
                .await
                .expect("Expected TransactionDetected event");
            txids.insert(txid);
        }
        txids
    }

    let (txids_a, txids_b) = tokio::join!(
        collect_n(&mut a.wallet_event_receiver, count, timeout),
        collect_n(&mut b.wallet_event_receiver, count, timeout),
    );
    assert_eq!(txids_a, txids_b, "Clients detected different txid sets");
    txids_a
}

/// Wait for both clients to reach mempool Synced state.
pub(super) async fn wait_for_mempool_synced_both(a: &mut ClientHandle, b: &mut ClientHandle) {
    let (r_a, r_b) = tokio::join!(
        wait_for_mempool_synced(&mut a.progress_receiver),
        wait_for_mempool_synced(&mut b.progress_receiver),
    );
    assert!(r_a, "Client A: expected mempool to reach Synced state");
    assert!(r_b, "Client B: expected mempool to reach Synced state");
}

/// Assert that neither client receives a mempool transaction event within the given duration.
pub(super) async fn assert_no_mempool_tx_both(
    a: &mut ClientHandle,
    b: &mut ClientHandle,
    wait: Duration,
) {
    tokio::join!(
        assert_no_mempool_tx(&mut a.wallet_event_receiver, wait),
        assert_no_mempool_tx(&mut b.wallet_event_receiver, wait),
    );
}

/// Wait for a network event on both clients concurrently.
pub(super) async fn wait_for_network_event_both(
    a: &mut ClientHandle,
    b: &mut ClientHandle,
    predicate: impl Fn(&NetworkEvent) -> bool + Clone,
    max_wait: Duration,
) -> bool {
    let pred_clone = predicate.clone();
    let (r_a, r_b) = tokio::join!(
        wait_for_network_event(&mut a.network_event_receiver, predicate, max_wait),
        wait_for_network_event(&mut b.network_event_receiver, pred_clone, max_wait),
    );
    r_a && r_b
}
