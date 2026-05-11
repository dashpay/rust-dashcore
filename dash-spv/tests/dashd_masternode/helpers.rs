use dash_spv::sync::{MasternodesProgress, SyncEvent, SyncProgress, SyncState};
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::sml::llmq_entry_verification::LLMQEntryVerificationStatus;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::Txid;
use key_wallet::transaction_checking::TransactionContext;
use key_wallet_manager::WalletEvent;
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::{broadcast, watch};
use tokio::time;

use super::setup::{TestContext, SYNC_TIMEOUT};

/// Mine a DKG cycle and wait for the SPV to surface a `MasternodeStateUpdated`
/// event above `baseline_height`.
pub(super) async fn mine_dkg_cycle_and_wait(
    ctx: &mut TestContext,
    sync_event_receiver: &mut broadcast::Receiver<SyncEvent>,
    baseline_height: u32,
) -> u32 {
    ctx.mn_ctx.mine_dkg_cycle().expect("DKG cycle should succeed");
    wait_for_mn_state_event_above(sync_event_receiver, baseline_height, SYNC_TIMEOUT).await
}

/// Assert every rotated quorum across all stored cycles is `Verified`.
pub(super) fn assert_all_rotated_quorums_verified(engine: &MasternodeListEngine) {
    for (cycle_key, cycle_quorums) in &engine.rotated_quorums_per_cycle {
        for (idx, entry) in cycle_quorums {
            assert!(
                matches!(entry.verified, LLMQEntryVerificationStatus::Verified),
                "Rotated quorum (cycle_key={}, idx={}, hash={}) should be Verified, got {}",
                cycle_key,
                idx,
                entry.quorum_entry.quorum_hash,
                entry.verified
            );
        }
    }
}

/// Wait for masternode sync to reach Synced state.
pub(super) async fn wait_for_masternode_sync(
    progress_receiver: &mut watch::Receiver<SyncProgress>,
    timeout_secs: u64,
) -> MasternodesProgress {
    {
        let progress = progress_receiver.borrow_and_update();
        if let Ok(mn_progress) = progress.masternodes() {
            if mn_progress.state() == SyncState::Synced {
                tracing::info!(
                    "Masternode sync already complete at height {}",
                    mn_progress.current_height()
                );
                return mn_progress.clone();
            }
        }
    }

    let timeout = time::sleep(Duration::from_secs(timeout_secs));
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
    let timeout = time::sleep(Duration::from_secs(timeout_secs));
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
                    Ok(SyncEvent::MasternodeStateUpdated { height, .. }) if height > min_height => {
                        tracing::info!("MasternodeStateUpdated at height {} (above {})", height, min_height);
                        return height;
                    }
                    Ok(SyncEvent::MasternodeStateUpdated { height, .. }) => {
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

/// Wait for a `MasternodeStateUpdated` event that carries a `QRInfoFeedResult`
/// whose `stored_cycle_height` is above `min_cycle_height` and which reports
/// `all_fully_verified()` (i.e. every rotated quorum settled as `Verified` and
/// the rotation cycle was actually stored in `rotated_quorums_per_cycle`). Use
/// this when a test needs the SPV to have a fully-verified rotation cycle
/// before proceeding, for example when preparing to verify a post-rotation
/// InstantSend lock.
pub(super) async fn wait_for_mn_state_with_stored_cycle_above(
    event_receiver: &mut broadcast::Receiver<SyncEvent>,
    min_cycle_height: u32,
    timeout_secs: u64,
) -> u32 {
    let timeout = time::sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                panic!(
                    "Timeout waiting for MasternodeStateUpdated carrying a fully-verified rotation cycle above height {}",
                    min_cycle_height
                );
            }
            result = event_receiver.recv() => {
                match result {
                    Ok(SyncEvent::MasternodeStateUpdated {
                        height,
                        qr_info_result: Some(ref s),
                    }) if s.all_fully_verified()
                        && matches!(s.stored_cycle_height, Some(h) if h > min_cycle_height) =>
                    {
                        tracing::info!(
                            "MasternodeStateUpdated at height {} with fully-verified stored_cycle_height={:?}",
                            height,
                            s.stored_cycle_height,
                        );
                        return height;
                    }
                    Ok(SyncEvent::MasternodeStateUpdated { height, qr_info_result }) => {
                        tracing::debug!(
                            "MasternodeStateUpdated at height {} (waiting for stored cycle > {}, got {:?})",
                            height,
                            min_cycle_height,
                            qr_info_result.as_ref().map(|r| (r.stored_cycle_height, r.fully_verified_count, r.rotated_quorum_count)),
                        );
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
    let timeout = time::sleep(Duration::from_secs(timeout_secs));
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

/// Wait for every txid in `txids` to be surfaced by the wallet as
/// chainlock-finalized, via either a
/// [`WalletEvent::TransactionsChainlocked`] event whose `per_account`
/// includes the txid (across any account) or a
/// [`WalletEvent::BlockProcessed`] event with `chain_lock = Some(..)`
/// whose `inserted` / `updated` list includes the txid.
///
/// A single event can cover multiple txids at once (e.g. one chainlock
/// promotes several `InBlock` records into `InChainLockedBlock` in one
/// pass, or one chainlocked block contains several IS-locked txs that
/// confirm together), which is why this consumes the receiver in a
/// loop until every txid has been observed.
pub(super) async fn wait_for_wallet_txs_chainlocked(
    event_receiver: &mut broadcast::Receiver<WalletEvent>,
    txids: &[Txid],
    timeout_secs: u64,
) {
    let mut pending: HashSet<Txid> = txids.iter().copied().collect();
    let timeout = time::sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(timeout);

    while !pending.is_empty() {
        tokio::select! {
            _ = &mut timeout => {
                panic!(
                    "Timeout waiting for chainlock finalization, {} txids still pending: {:?}",
                    pending.len(), pending,
                );
            }
            result = event_receiver.recv() => {
                match result {
                    Ok(WalletEvent::TransactionsChainlocked {
                        chain_lock,
                        per_account,
                        ..
                    }) => {
                        for finalized in per_account.values().flatten() {
                            if pending.remove(finalized) {
                                tracing::info!(
                                    "Wallet TransactionsChainlocked(chainlock_height={}, txid={})",
                                    chain_lock.block_height, finalized,
                                );
                            }
                        }
                    }
                    Ok(WalletEvent::BlockProcessed {
                        chain_lock: Some(cl),
                        inserted,
                        updated,
                        ..
                    }) => {
                        for record in inserted.iter().chain(updated.iter()) {
                            if pending.remove(&record.txid) {
                                tracing::info!(
                                    "Wallet BlockProcessed(chainlock_height={}, txid={})",
                                    cl.block_height, record.txid,
                                );
                            }
                        }
                    }
                    Ok(other) => {
                        tracing::debug!("Ignoring wallet event: {}", other.description());
                    }
                    Err(err) => {
                        panic!("Wallet event receiver failed: {}", err);
                    }
                }
            }
        }
    }
}

/// Single-txid variant of [`wait_for_wallet_txs_chainlocked`] that
/// also returns the chainlock height that drove the promotion. Use
/// this when the test asserts on the promotion height. Otherwise
/// prefer the plural form which consumes events more robustly.
pub(super) async fn wait_for_wallet_tx_chainlocked(
    event_receiver: &mut broadcast::Receiver<WalletEvent>,
    txid: Txid,
    timeout_secs: u64,
) -> u32 {
    let timeout = time::sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                panic!("Timeout waiting for TransactionsChainlocked carrying txid {}", txid);
            }
            result = event_receiver.recv() => {
                match result {
                    Ok(WalletEvent::TransactionsChainlocked {
                        chain_lock,
                        per_account,
                        ..
                    }) if per_account
                        .values()
                        .any(|txids| txids.contains(&txid)) =>
                    {
                        tracing::info!(
                            "Wallet TransactionsChainlocked(chainlock_height={}, txid={})",
                            chain_lock.block_height, txid
                        );
                        return chain_lock.block_height;
                    }
                    Ok(WalletEvent::BlockProcessed {
                        chain_lock: Some(_),
                        inserted,
                        updated,
                        ..
                    }) if inserted.iter().chain(updated.iter()).any(|r| r.txid == txid) =>
                    {
                        tracing::info!(
                            "Wallet BlockProcessed(chainlocked, txid={})",
                            txid
                        );
                        return inserted
                            .iter()
                            .chain(updated.iter())
                            .find(|r| r.txid == txid)
                            .and_then(|r| r.context.block_info().map(|i| i.height()))
                            .unwrap_or_default();
                    }
                    Ok(other) => {
                        tracing::debug!("Ignoring wallet event: {}", other.description());
                        continue;
                    }
                    Err(err) => {
                        panic!("Wallet event receiver failed: {}", err);
                    }
                }
            }
        }
    }
}

/// Wait for a wallet event about `txid` whose `TransactionContext` matches `pred`.
///
/// Returns the matching context. Matches both `TransactionDetected` (first-time
/// seen, predicate runs against `record.context`) and `TransactionInstantLocked`
/// (subsequent IS-lock application, synthesized as `InstantSend(lock)` so the
/// same predicate works).
pub(super) async fn wait_for_wallet_tx_status<F>(
    event_receiver: &mut broadcast::Receiver<WalletEvent>,
    txid: Txid,
    pred: F,
    timeout_secs: u64,
) -> TransactionContext
where
    F: Fn(&TransactionContext) -> bool,
{
    let timeout = time::sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                panic!("Timeout waiting for wallet event for txid {}", txid);
            }
            result = event_receiver.recv() => {
                match result {
                    Ok(WalletEvent::TransactionDetected { record, .. })
                        if record.txid == txid && pred(&record.context) =>
                    {
                        tracing::info!(
                            "Wallet TransactionDetected(txid={}, context={})",
                            txid, record.context
                        );
                        return record.context.clone();
                    }
                    Ok(WalletEvent::TransactionInstantLocked { txid: event_txid, instant_lock, .. })
                        if event_txid == txid =>
                    {
                        let status = TransactionContext::InstantSend(instant_lock);
                        if pred(&status) {
                            tracing::info!(
                                "Wallet TransactionInstantLocked(txid={}, status={})",
                                txid, status
                            );
                            return status;
                        }
                        continue;
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

    let timeout = time::sleep(Duration::from_secs(timeout_secs));
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

    let timeout = time::sleep(Duration::from_secs(timeout_secs));
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
