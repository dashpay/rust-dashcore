use dash_spv::sync::{MasternodesProgress, SyncEvent, SyncProgress, SyncState};
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::Txid;
use key_wallet::transaction_checking::TransactionContext;
use key_wallet_manager::WalletEvent;
use std::time::Duration;
use tokio::sync::{broadcast, watch};

/// Wait for masternode sync to reach Synced state.
pub(super) async fn wait_for_masternode_sync(
    progress_receiver: &mut watch::Receiver<SyncProgress>,
    timeout_secs: u64,
) -> MasternodesProgress {
    let timeout = tokio::time::sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                let progress = progress_receiver.borrow();
                panic!(
                    "Timeout waiting for masternode sync. Current progress: {:?}",
                    progress
                );
            }
            result = progress_receiver.changed() => {
                if result.is_err() {
                    panic!("Progress channel closed");
                }
                let progress = progress_receiver.borrow_and_update().clone();

                // Check if masternodes are synced
                if let Ok(mn_progress) = progress.masternodes() {
                    if mn_progress.state() == SyncState::Synced {
                        tracing::info!(
                            "Masternode sync complete at height {}",
                            mn_progress.current_height()
                        );
                        return mn_progress.clone();
                    }
                }
            }
        }
    }
}

/// Wait for the MasternodeStateUpdated sync event.
pub(super) async fn wait_for_mn_state_event(
    event_receiver: &mut broadcast::Receiver<SyncEvent>,
    timeout_secs: u64,
) -> u32 {
    wait_for_mn_state_event_above(event_receiver, 0, timeout_secs).await
}

/// Wait for a MasternodeStateUpdated event at a height strictly above `min_height`.
pub(super) async fn wait_for_mn_state_event_above(
    event_receiver: &mut broadcast::Receiver<SyncEvent>,
    min_height: u32,
    timeout_secs: u64,
) -> u32 {
    let timeout = tokio::time::sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                panic!(
                    "Timeout waiting for MasternodeStateUpdated above height {}",
                    min_height
                );
            }
            result = event_receiver.recv() => {
                match result {
                    Ok(SyncEvent::MasternodeStateUpdated { height }) if height > min_height => {
                        tracing::info!("MasternodeStateUpdated at height {} (above {})", height, min_height);
                        return height;
                    }
                    Ok(SyncEvent::MasternodeStateUpdated { height }) => {
                        tracing::debug!("MasternodeStateUpdated at height {} (waiting for > {})", height, min_height);
                        continue;
                    }
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Event receiver lagged by {} messages", n);
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        panic!("Sync event channel closed");
                    }
                }
            }
        }
    }
}

/// Wait for an `InstantLockReceived` sync event for `txid` with the desired validation state.
///
/// Returns the received `InstantLock`. Ignores events for unrelated txids and events
/// whose `validated` flag does not match `want_validated`.
pub(super) async fn wait_for_instant_lock_received(
    event_receiver: &mut broadcast::Receiver<SyncEvent>,
    txid: Txid,
    want_validated: bool,
    timeout_secs: u64,
) -> InstantLock {
    let timeout = tokio::time::sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                panic!(
                    "Timeout waiting for InstantLockReceived(txid={}, validated={})",
                    txid, want_validated
                );
            }
            result = event_receiver.recv() => {
                match result {
                    Ok(SyncEvent::InstantLockReceived { instant_lock, validated })
                        if instant_lock.txid == txid && validated == want_validated =>
                    {
                        tracing::info!(
                            "InstantLockReceived(txid={}, validated={})",
                            txid, validated
                        );
                        return instant_lock;
                    }
                    Ok(SyncEvent::InstantLockReceived { instant_lock, validated }) => {
                        tracing::debug!(
                            "Ignoring InstantLockReceived(txid={}, validated={}) — waiting for txid={} validated={}",
                            instant_lock.txid, validated, txid, want_validated
                        );
                        continue;
                    }
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Sync event receiver lagged by {} messages", n);
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        panic!("Sync event channel closed");
                    }
                }
            }
        }
    }
}

/// Wait for a wallet event about `txid` whose `TransactionContext` matches `pred`.
///
/// Returns the matching context. Matches both `TransactionReceived` (first-time seen)
/// and `TransactionStatusChanged` (subsequent status update).
pub(super) async fn wait_for_wallet_tx_status<F>(
    event_receiver: &mut broadcast::Receiver<WalletEvent>,
    txid: Txid,
    pred: F,
    timeout_secs: u64,
) -> TransactionContext
where
    F: Fn(&TransactionContext) -> bool,
{
    let timeout = tokio::time::sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                panic!("Timeout waiting for wallet event for txid {}", txid);
            }
            result = event_receiver.recv() => {
                match result {
                    Ok(WalletEvent::TransactionReceived { record, .. })
                        if record.txid == txid && pred(&record.context) =>
                    {
                        tracing::info!(
                            "Wallet TransactionReceived(txid={}, context={})",
                            txid, record.context
                        );
                        return record.context.clone();
                    }
                    Ok(WalletEvent::TransactionStatusChanged { txid: event_txid, status, .. })
                        if event_txid == txid && pred(&status) =>
                    {
                        tracing::info!(
                            "Wallet TransactionStatusChanged(txid={}, status={})",
                            txid, status
                        );
                        return status;
                    }
                    Ok(other) => {
                        tracing::debug!("Ignoring wallet event: {}", other.description());
                        continue;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("Wallet event receiver lagged by {} messages", n);
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        panic!("Wallet event channel closed");
                    }
                }
            }
        }
    }
}

/// Wait for `InstantSendProgress::valid()` to reach at least `min_valid`.
pub(super) async fn wait_for_instantsend_valid_at_least(
    progress_receiver: &mut watch::Receiver<SyncProgress>,
    min_valid: u32,
    timeout_secs: u64,
) {
    {
        let progress = progress_receiver.borrow();
        if let Ok(is_progress) = progress.instantsend() {
            if is_progress.valid() >= min_valid {
                return;
            }
        }
    }

    let timeout = tokio::time::sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                let progress = progress_receiver.borrow();
                panic!(
                    "Timeout waiting for InstantSendProgress.valid >= {}. Current: {:?}",
                    min_valid, progress.instantsend().ok()
                );
            }
            result = progress_receiver.changed() => {
                if result.is_err() {
                    panic!("Progress channel closed");
                }
                let progress = progress_receiver.borrow_and_update().clone();
                if let Ok(is_progress) = progress.instantsend() {
                    if is_progress.valid() >= min_valid {
                        return;
                    }
                }
            }
        }
    }
}

/// Wait for validated ChainLock progress to reach at least `min_height`.
pub(super) async fn wait_for_chainlock_height_at_least(
    progress_receiver: &mut watch::Receiver<SyncProgress>,
    min_height: u32,
    timeout_secs: u64,
) -> u32 {
    {
        let progress = progress_receiver.borrow();
        if let Ok(chainlock_progress) = progress.chainlocks() {
            let height = chainlock_progress.best_validated_height();
            if height >= min_height {
                return height;
            }
        }
    }

    let timeout = tokio::time::sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                panic!("Timeout waiting for ChainLock height >= {}", min_height);
            }
            result = progress_receiver.changed() => {
                if result.is_err() {
                    panic!("Progress channel closed");
                }
                let progress = progress_receiver.borrow_and_update().clone();
                if let Ok(chainlock_progress) = progress.chainlocks() {
                    let height = chainlock_progress.best_validated_height();
                    if height >= min_height {
                        return height;
                    }
                }
            }
        }
    }
}
