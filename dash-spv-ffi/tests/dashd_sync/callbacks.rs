//! FFI callback implementations and tracker for integration tests.

use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::slice;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dash_spv_ffi::*;
use key_wallet_ffi::types::FFIBalance;

/// Tracks callback invocations for verification.
///
/// Fields are updated atomically from FFI callbacks and read in test assertions.
#[derive(Default)]
pub(super) struct CallbackTracker {
    // Sync event tracking
    pub(super) sync_start_count: AtomicU32,
    pub(super) block_headers_stored_count: AtomicU32,
    pub(super) block_header_sync_complete_count: AtomicU32,
    pub(super) filter_headers_stored_count: AtomicU32,
    pub(super) filter_headers_sync_complete_count: AtomicU32,
    pub(super) filters_stored_count: AtomicU32,
    pub(super) filters_sync_complete_count: AtomicU32,
    pub(super) blocks_needed_count: AtomicU32,
    pub(super) block_processed_count: AtomicU32,
    pub(super) masternode_state_updated_count: AtomicU32,
    pub(super) chainlock_received_count: AtomicU32,
    pub(super) instantlock_received_count: AtomicU32,
    pub(super) manager_error_count: AtomicU32,
    pub(super) sync_complete_count: AtomicU32,

    // Network event tracking
    pub(super) peer_connected_count: AtomicU32,
    pub(super) peer_disconnected_count: AtomicU32,
    pub(super) peers_updated_count: AtomicU32,

    // Wallet event tracking
    pub(super) transaction_received_count: AtomicU32,
    pub(super) transaction_instant_send_locked_count: AtomicU32,
    pub(super) block_processed_wallet_count: AtomicU32,
    pub(super) block_processed_wallet_record_count: AtomicU32,
    pub(super) synced_height_updated_count: AtomicU32,
    /// Highest synced-height value observed from any `SyncedHeightUpdated`.
    pub(super) last_synced_height: AtomicU32,

    // Data from callbacks
    pub(super) last_header_tip: AtomicU32,
    pub(super) last_filter_tip: AtomicU32,
    pub(super) last_connected_peer_count: AtomicU32,
    pub(super) last_best_height: AtomicU32,
    pub(super) connected_peers: Mutex<Vec<String>>,
    pub(super) errors: Mutex<Vec<String>>,

    // Per-record (txid, net_amount) seen via the off-chain wallet callback.
    pub(super) received_transactions: Mutex<Vec<([u8; 32], i64)>>,
    // Per-record (txid, net_amount) seen via the block-processed callback.
    pub(super) block_received_transactions: Mutex<Vec<([u8; 32], i64)>>,

    // `FFIAccountKind` discriminants captured from wallet callbacks. Lets
    // tests assert that account-type delivery is well-formed and matches the
    // expected account.
    pub(super) received_account_types: Mutex<Vec<FFIAccountKind>>,
    pub(super) block_account_types: Mutex<Vec<FFIAccountKind>>,

    // `account_index` values captured alongside `FFIAccountKind`, paired
    // positionally with the corresponding `*_account_types` entries.
    pub(super) received_account_indices: Mutex<Vec<u32>>,
    pub(super) block_account_indices: Mutex<Vec<u32>>,

    // Per-record bucketing observed on `BlockProcessed` changes, in delivery
    // order. Each entry is `true` when the record was delivered via the
    // `inserted` array, `false` when delivered via `updated`. Lets tests
    // assert that confirmation of a previously-known mempool transaction
    // lands in `updated` rather than `inserted`.
    pub(super) block_record_inserted: Mutex<Vec<bool>>,

    // Number of changed-account entries observed on the most recent wallet
    // event. Lets tests assert that per-account balance diffs are wired
    // through and arrive non-empty for state-changing events.
    pub(super) last_changed_account_count: AtomicU32,
    /// Highest changed-account count observed across all wallet events so a
    /// single state-changing event can be detected without racing the
    /// "last" snapshot.
    pub(super) max_changed_account_count: AtomicU32,

    // Balance data from the most recent wallet event.
    pub(super) last_confirmed: AtomicU64,
    pub(super) last_unconfirmed: AtomicU64,

    // Raw IS lock bytes captured from the most recent
    // `on_transaction_instant_send_locked` callback. Lets tests verify the
    // payload is non-empty and round-trips through `InstantLock` deserialisation.
    pub(super) last_islock_bytes: Mutex<Option<Vec<u8>>>,

    // Lifecycle ordering via global sequence counter
    pub(super) sequence_counter: AtomicU32,
    pub(super) sync_start_seq: AtomicU32,
    pub(super) header_complete_seq: AtomicU32,
    pub(super) filter_header_complete_seq: AtomicU32,
    pub(super) filters_sync_complete_seq: AtomicU32,
    pub(super) sync_complete_seq: AtomicU32,

    // Filter header range validation: (start, end, tip)
    pub(super) filter_header_ranges: Mutex<Vec<(u32, u32, u32)>>,

    // Block processed heights
    pub(super) processed_block_heights: Mutex<Vec<u32>>,

    // Completion tracking
    pub(super) last_sync_cycle: AtomicU32,

    // Baseline for `wait_for_sync`: captured before the client starts so that
    // a SyncComplete firing between client start and `wait_for_sync` entry is
    // not missed.
    pub(super) sync_count_baseline: AtomicU32,
}

impl CallbackTracker {
    /// Assert that no errors were recorded during sync.
    pub(super) fn assert_no_errors(&self) {
        let errors = self.errors.lock().unwrap();
        assert!(errors.is_empty(), "Unexpected sync errors: {:?}", *errors);
    }

    /// Polls until the given counter exceeds `baseline`, with a 10s timeout.
    ///
    /// Wallet event callbacks travel on a separate broadcast channel from sync
    /// events, so `wait_for_sync` completing does not guarantee they have fired.
    pub(super) fn wait_for_callback(&self, counter: &AtomicU32, baseline: u32, name: &str) {
        let timeout = std::time::Instant::now() + Duration::from_secs(10);
        while counter.load(Ordering::SeqCst) <= baseline {
            assert!(
                std::time::Instant::now() < timeout,
                "Timed out waiting for {} callback (stuck at baseline {})",
                name,
                baseline
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Extract the `CallbackTracker` reference from a `user_data` pointer.
/// Returns `None` if the pointer is null.
///
/// # Safety
///
/// The pointer must point to a valid, live `CallbackTracker`
/// (e.g. obtained via `Arc::as_ptr`).
unsafe fn tracker_from(user_data: *mut c_void) -> Option<&'static CallbackTracker> {
    if user_data.is_null() {
        None
    } else {
        Some(&*(user_data as *const CallbackTracker))
    }
}

/// Convert a nullable C string pointer to an owned `String`.
/// Returns `"Unknown"` if the pointer is null.
///
/// # Safety
///
/// The pointer must point to a valid, null-terminated C string if non-null.
unsafe fn cstr_or_unknown(ptr: *const c_char) -> String {
    if ptr.is_null() {
        "Unknown".to_string()
    } else {
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

extern "C" fn on_sync_start(manager_id: FFIManagerId, user_data: *mut c_void) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    let seq = tracker.sequence_counter.fetch_add(1, Ordering::SeqCst);
    tracker.sync_start_seq.store(seq, Ordering::SeqCst);
    tracker.sync_start_count.fetch_add(1, Ordering::SeqCst);
    tracing::debug!("on_sync_start: manager={:?}, seq={}", manager_id, seq);
}

extern "C" fn on_block_headers_stored(tip_height: u32, user_data: *mut c_void) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    tracker.last_header_tip.store(tip_height, Ordering::SeqCst);
    tracker.block_headers_stored_count.fetch_add(1, Ordering::SeqCst);
    tracing::debug!("on_block_headers_stored: tip={}", tip_height);
}

extern "C" fn on_block_header_sync_complete(tip_height: u32, user_data: *mut c_void) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    tracker.last_header_tip.store(tip_height, Ordering::SeqCst);
    let seq = tracker.sequence_counter.fetch_add(1, Ordering::SeqCst);
    tracker.header_complete_seq.store(seq, Ordering::SeqCst);
    tracker.block_header_sync_complete_count.fetch_add(1, Ordering::SeqCst);
    tracing::info!("on_block_header_sync_complete: tip={}, seq={}", tip_height, seq);
}

extern "C" fn on_filter_headers_stored(
    start_height: u32,
    end_height: u32,
    tip_height: u32,
    user_data: *mut c_void,
) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    tracker.last_filter_tip.store(tip_height, Ordering::SeqCst);
    tracker.filter_header_ranges.lock().unwrap_or_else(|e| e.into_inner()).push((
        start_height,
        end_height,
        tip_height,
    ));
    tracker.filter_headers_stored_count.fetch_add(1, Ordering::SeqCst);
    tracing::debug!(
        "on_filter_headers_stored: start={}, end={}, tip={}",
        start_height,
        end_height,
        tip_height
    );
}

extern "C" fn on_filter_headers_sync_complete(tip_height: u32, user_data: *mut c_void) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    tracker.last_filter_tip.store(tip_height, Ordering::SeqCst);
    let seq = tracker.sequence_counter.fetch_add(1, Ordering::SeqCst);
    tracker.filter_header_complete_seq.store(seq, Ordering::SeqCst);
    tracker.filter_headers_sync_complete_count.fetch_add(1, Ordering::SeqCst);
    tracing::info!("on_filter_headers_sync_complete: tip={}, seq={}", tip_height, seq);
}

extern "C" fn on_filters_stored(start_height: u32, end_height: u32, user_data: *mut c_void) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    tracker.filters_stored_count.fetch_add(1, Ordering::SeqCst);
    tracing::debug!("on_filters_stored: {}-{}", start_height, end_height);
}

extern "C" fn on_filters_sync_complete(tip_height: u32, user_data: *mut c_void) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    tracker.last_filter_tip.store(tip_height, Ordering::SeqCst);
    let seq = tracker.sequence_counter.fetch_add(1, Ordering::SeqCst);
    tracker.filters_sync_complete_seq.store(seq, Ordering::SeqCst);
    tracker.filters_sync_complete_count.fetch_add(1, Ordering::SeqCst);
    tracing::info!("on_filters_sync_complete: tip={}, seq={}", tip_height, seq);
}

extern "C" fn on_blocks_needed(
    _blocks: *const dash_spv_ffi::FFIBlockNeeded,
    count: u32,
    user_data: *mut c_void,
) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    tracker.blocks_needed_count.fetch_add(1, Ordering::SeqCst);
    tracing::debug!("on_blocks_needed: count={}", count);
}

extern "C" fn on_block_processed(
    height: u32,
    _hash: *const [u8; 32],
    new_address_count: u32,
    _confirmed_txids: *const [u8; 32],
    confirmed_txid_count: u32,
    user_data: *mut c_void,
) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    tracker.processed_block_heights.lock().unwrap_or_else(|e| e.into_inner()).push(height);
    tracker.block_processed_count.fetch_add(1, Ordering::SeqCst);
    tracing::debug!(
        "on_block_processed: height={}, new_addresses={}, confirmed_txs={}",
        height,
        new_address_count,
        confirmed_txid_count
    );
}

extern "C" fn on_masternode_state_updated(height: u32, user_data: *mut c_void) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    tracker.masternode_state_updated_count.fetch_add(1, Ordering::SeqCst);
    tracing::debug!("on_masternode_state_updated: height={}", height);
}

extern "C" fn on_chainlock_received(
    height: u32,
    _hash: *const [u8; 32],
    _signature: *const [u8; 96],
    validated: bool,
    user_data: *mut c_void,
) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    tracker.chainlock_received_count.fetch_add(1, Ordering::SeqCst);
    tracing::info!("on_chainlock_received: height={}, validated={}", height, validated);
}

extern "C" fn on_instantlock_received(
    _txid: *const [u8; 32],
    _instantlock_data: *const u8,
    _instantlock_len: usize,
    validated: bool,
    user_data: *mut c_void,
) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    tracker.instantlock_received_count.fetch_add(1, Ordering::SeqCst);
    tracing::debug!("on_instantlock_received: validated={}", validated);
}

extern "C" fn on_manager_error(
    manager_id: FFIManagerId,
    error: *const c_char,
    user_data: *mut c_void,
) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    let error_str = unsafe { cstr_or_unknown(error) };
    tracing::error!("on_manager_error: manager={:?}, error={}", manager_id, error_str);
    tracker.errors.lock().unwrap_or_else(|e| e.into_inner()).push(error_str);
    tracker.manager_error_count.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn on_sync_complete(header_tip: u32, cycle: u32, user_data: *mut c_void) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    tracker.last_header_tip.store(header_tip, Ordering::SeqCst);
    tracker.last_sync_cycle.store(cycle, Ordering::SeqCst);
    let seq = tracker.sequence_counter.fetch_add(1, Ordering::SeqCst);
    tracker.sync_complete_seq.store(seq, Ordering::SeqCst);
    tracker.sync_complete_count.fetch_add(1, Ordering::SeqCst);
    tracing::info!("on_sync_complete: header_tip={}, cycle={}, seq={}", header_tip, cycle, seq);
}

extern "C" fn on_peer_connected(address: *const c_char, user_data: *mut c_void) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    let addr_str = unsafe { cstr_or_unknown(address) };
    tracing::info!("on_peer_connected: {}", addr_str);
    tracker.connected_peers.lock().unwrap_or_else(|e| e.into_inner()).push(addr_str);
    tracker.peer_connected_count.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn on_peer_disconnected(address: *const c_char, user_data: *mut c_void) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    tracker.peer_disconnected_count.fetch_add(1, Ordering::SeqCst);
    let addr_str = unsafe { cstr_or_unknown(address) };
    tracing::info!("on_peer_disconnected: {}", addr_str);
}

extern "C" fn on_peers_updated(connected_count: u32, best_height: u32, user_data: *mut c_void) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    tracker.last_connected_peer_count.store(connected_count, Ordering::SeqCst);
    tracker.last_best_height.store(best_height, Ordering::SeqCst);
    tracker.peers_updated_count.fetch_add(1, Ordering::SeqCst);
    tracing::debug!("on_peers_updated: connected={}, best_height={}", connected_count, best_height);
}

fn record_balance(tracker: &CallbackTracker, balance: *const FFIBalance) {
    if balance.is_null() {
        return;
    }
    let b = unsafe { *balance };
    tracker.last_confirmed.store(b.confirmed, Ordering::SeqCst);
    tracker.last_unconfirmed.store(b.unconfirmed, Ordering::SeqCst);
}

/// Capture the size of the per-account balance diff delivered with a wallet
/// event. Stores both the most recent and the running max so tests can wait
/// on a non-zero observation without racing the "last" snapshot.
fn record_account_balances(
    tracker: &CallbackTracker,
    account_balances: *const FFIAccountBalance,
    count: u32,
) {
    tracker.last_changed_account_count.store(count, Ordering::SeqCst);
    tracker.max_changed_account_count.fetch_max(count, Ordering::SeqCst);
    if account_balances.is_null() || count == 0 {
        return;
    }
    // Borrow check: the array and its `FFIAccountType` entries are owned by
    // the caller's dispatch and freed when control returns. We only read.
    let slice = unsafe { slice::from_raw_parts(account_balances, count as usize) };
    for entry in slice {
        tracing::debug!(
            "  account_balance: kind={:?}, idx={}, total={}",
            entry.account_type.kind,
            entry.account_type.index,
            entry.balance.total
        );
    }
}

#[allow(clippy::too_many_arguments)]
extern "C" fn on_transaction_detected(
    wallet_id: *const c_char,
    record: *const FFITransactionRecord,
    balance: *const FFIBalance,
    account_balances: *const FFIAccountBalance,
    account_balances_count: u32,
    user_data: *mut c_void,
) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    record_account_balances(tracker, account_balances, account_balances_count);
    let mut account_log = None;
    if !record.is_null() {
        let r = unsafe { &*record };
        tracker
            .received_transactions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((r.txid, r.net_amount));
        tracker
            .received_account_types
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(r.account_type.kind);
        tracker
            .received_account_indices
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(r.account_type.index);
        account_log = Some((r.account_type.kind, r.account_type.index));
    }
    // Store the balance before bumping the counter so a test that waits on the
    // counter and then reads `last_unconfirmed` is guaranteed to observe the
    // balance for the same callback invocation.
    record_balance(tracker, balance);
    tracker.transaction_received_count.fetch_add(1, Ordering::SeqCst);
    let wallet_str = unsafe { cstr_or_unknown(wallet_id) };
    tracing::info!("on_transaction_detected: wallet={}, account={:?}", wallet_str, account_log);
}

#[allow(clippy::too_many_arguments)]
extern "C" fn on_transaction_instant_locked(
    _wallet_id: *const c_char,
    _txid: *const [u8; 32],
    islock_data: *const u8,
    islock_len: usize,
    balance: *const FFIBalance,
    account_balances: *const FFIAccountBalance,
    account_balances_count: u32,
    user_data: *mut c_void,
) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    record_account_balances(tracker, account_balances, account_balances_count);
    if !islock_data.is_null() && islock_len > 0 {
        let bytes = unsafe { slice::from_raw_parts(islock_data, islock_len) }.to_vec();
        *tracker.last_islock_bytes.lock().unwrap_or_else(|e| e.into_inner()) = Some(bytes);
    }
    record_balance(tracker, balance);
    tracker.transaction_instant_send_locked_count.fetch_add(1, Ordering::SeqCst);
    tracing::debug!("on_transaction_instant_locked");
}

#[allow(clippy::too_many_arguments)]
extern "C" fn on_wallet_block_processed(
    wallet_id: *const c_char,
    height: u32,
    inserted: *const FFITransactionRecord,
    inserted_count: u32,
    updated: *const FFITransactionRecord,
    updated_count: u32,
    _matured: *const FFITransactionRecord,
    matured_count: u32,
    balance: *const FFIBalance,
    account_balances: *const FFIAccountBalance,
    account_balances_count: u32,
    user_data: *mut c_void,
) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    record_account_balances(tracker, account_balances, account_balances_count);
    // Append all per-record state before bumping either counter so that a
    // test waiting on `block_processed_wallet_count` (the per-callback counter)
    // is guaranteed to also observe the matching `block_processed_wallet_record_count`
    // and the underlying vectors. Tests should always wait on
    // `block_processed_wallet_count` and read the record counter afterwards.
    let mut sink = tracker.block_received_transactions.lock().unwrap_or_else(|e| e.into_inner());
    let mut types = tracker.block_account_types.lock().unwrap_or_else(|e| e.into_inner());
    let mut indices = tracker.block_account_indices.lock().unwrap_or_else(|e| e.into_inner());
    let mut bucket = tracker.block_record_inserted.lock().unwrap_or_else(|e| e.into_inner());
    let mut records_added = 0u32;
    if !inserted.is_null() && inserted_count > 0 {
        let slice = unsafe { slice::from_raw_parts(inserted, inserted_count as usize) };
        for r in slice {
            sink.push((r.txid, r.net_amount));
            types.push(r.account_type.kind);
            indices.push(r.account_type.index);
            bucket.push(true);
            records_added += 1;
        }
    }
    if !updated.is_null() && updated_count > 0 {
        let slice = unsafe { slice::from_raw_parts(updated, updated_count as usize) };
        for r in slice {
            sink.push((r.txid, r.net_amount));
            types.push(r.account_type.kind);
            indices.push(r.account_type.index);
            bucket.push(false);
            records_added += 1;
        }
    }
    drop(sink);
    drop(types);
    drop(indices);
    drop(bucket);
    if records_added > 0 {
        tracker.block_processed_wallet_record_count.fetch_add(records_added, Ordering::SeqCst);
    }
    record_balance(tracker, balance);
    tracker.block_processed_wallet_count.fetch_add(1, Ordering::SeqCst);
    let wallet_str = unsafe { cstr_or_unknown(wallet_id) };
    tracing::info!(
        "on_wallet_block_processed: wallet={}, height={}, inserted={}, updated={}, matured={}",
        wallet_str,
        height,
        inserted_count,
        updated_count,
        matured_count
    );
}

extern "C" fn on_sync_height_advanced(
    wallet_id: *const c_char,
    height: u32,
    user_data: *mut c_void,
) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    // Store the height before bumping the counter so a test that waits on the
    // counter and then reads `last_synced_height` is guaranteed to observe the
    // height for the same callback invocation.
    tracker.last_synced_height.store(height, Ordering::SeqCst);
    tracker.synced_height_updated_count.fetch_add(1, Ordering::SeqCst);
    let wallet_str = unsafe { cstr_or_unknown(wallet_id) };
    tracing::info!("on_sync_height_advanced: wallet={}, height={}", wallet_str, height);
}

/// Create sync callbacks with all event handlers wired to the tracker.
///
/// The `user_data` pointer borrows the tracker Arc. The caller must ensure the
/// Arc outlives all callback invocations (i.e. stop the client before dropping it).
pub(super) fn create_sync_callbacks(tracker: &Arc<CallbackTracker>) -> FFISyncEventCallbacks {
    FFISyncEventCallbacks {
        on_sync_start: Some(on_sync_start),
        on_block_headers_stored: Some(on_block_headers_stored),
        on_block_header_sync_complete: Some(on_block_header_sync_complete),
        on_filter_headers_stored: Some(on_filter_headers_stored),
        on_filter_headers_sync_complete: Some(on_filter_headers_sync_complete),
        on_filters_stored: Some(on_filters_stored),
        on_filters_sync_complete: Some(on_filters_sync_complete),
        on_blocks_needed: Some(on_blocks_needed),
        on_block_processed: Some(on_block_processed),
        on_masternode_state_updated: Some(on_masternode_state_updated),
        on_chainlock_received: Some(on_chainlock_received),
        on_instantlock_received: Some(on_instantlock_received),
        on_manager_error: Some(on_manager_error),
        on_sync_complete: Some(on_sync_complete),
        user_data: Arc::as_ptr(tracker) as *mut c_void,
    }
}

/// Create network event callbacks wired to the tracker.
///
/// The `user_data` pointer borrows the tracker Arc. The caller must ensure the
/// Arc outlives all callback invocations.
pub(super) fn create_network_callbacks(tracker: &Arc<CallbackTracker>) -> FFINetworkEventCallbacks {
    FFINetworkEventCallbacks {
        on_peer_connected: Some(on_peer_connected),
        on_peer_disconnected: Some(on_peer_disconnected),
        on_peers_updated: Some(on_peers_updated),
        user_data: Arc::as_ptr(tracker) as *mut c_void,
    }
}

/// Create wallet event callbacks wired to the tracker.
///
/// The `user_data` pointer borrows the tracker Arc. The caller must ensure the
/// Arc outlives all callback invocations.
pub(super) fn create_wallet_callbacks(tracker: &Arc<CallbackTracker>) -> FFIWalletEventCallbacks {
    FFIWalletEventCallbacks {
        on_transaction_detected: Some(on_transaction_detected),
        on_transaction_instant_locked: Some(on_transaction_instant_locked),
        on_block_processed: Some(on_wallet_block_processed),
        on_sync_height_advanced: Some(on_sync_height_advanced),
        user_data: Arc::as_ptr(tracker) as *mut c_void,
    }
}
