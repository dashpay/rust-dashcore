//! FFI callback implementations and tracker for integration tests.

use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dash_spv_ffi::*;

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
    pub(super) balance_updated_count: AtomicU32,

    // Data from callbacks
    pub(super) last_header_tip: AtomicU32,
    pub(super) last_filter_tip: AtomicU32,
    pub(super) last_connected_peer_count: AtomicU32,
    pub(super) last_best_height: AtomicU32,
    pub(super) connected_peers: Mutex<Vec<String>>,
    pub(super) errors: Mutex<Vec<String>>,

    // Transaction data from on_transaction_received
    pub(super) received_txids: Mutex<Vec<[u8; 32]>>,
    pub(super) received_amounts: Mutex<Vec<i64>>,

    // Balance data from on_balance_updated
    pub(super) last_spendable: AtomicU64,
    pub(super) last_unconfirmed: AtomicU64,

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
    user_data: *mut c_void,
) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    tracker.processed_block_heights.lock().unwrap_or_else(|e| e.into_inner()).push(height);
    tracker.block_processed_count.fetch_add(1, Ordering::SeqCst);
    tracing::debug!("on_block_processed: height={}, new_addresses={}", height, new_address_count);
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

extern "C" fn on_transaction_received(
    wallet_id: *const c_char,
    account_index: u32,
    txid: *const [u8; 32],
    amount: i64,
    _addresses: *const c_char,
    user_data: *mut c_void,
) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    if !txid.is_null() {
        let txid_bytes = unsafe { *txid };
        tracker.received_txids.lock().unwrap_or_else(|e| e.into_inner()).push(txid_bytes);
    }
    tracker.received_amounts.lock().unwrap_or_else(|e| e.into_inner()).push(amount);
    tracker.transaction_received_count.fetch_add(1, Ordering::SeqCst);
    let wallet_str = unsafe { cstr_or_unknown(wallet_id) };
    tracing::info!(
        "on_transaction_received: wallet={}, account={}, amount={}",
        wallet_str,
        account_index,
        amount
    );
}

extern "C" fn on_balance_updated(
    wallet_id: *const c_char,
    spendable: u64,
    unconfirmed: u64,
    immature: u64,
    locked: u64,
    user_data: *mut c_void,
) {
    let Some(tracker) = (unsafe { tracker_from(user_data) }) else {
        return;
    };
    tracker.last_spendable.store(spendable, Ordering::SeqCst);
    tracker.last_unconfirmed.store(unconfirmed, Ordering::SeqCst);
    tracker.balance_updated_count.fetch_add(1, Ordering::SeqCst);
    let wallet_str = unsafe { cstr_or_unknown(wallet_id) };
    tracing::info!(
        "on_balance_updated: wallet={}, spendable={}, unconfirmed={}, immature={}, locked={}",
        wallet_str,
        spendable,
        unconfirmed,
        immature,
        locked,
    );
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
        on_transaction_received: Some(on_transaction_received),
        on_balance_updated: Some(on_balance_updated),
        user_data: Arc::as_ptr(tracker) as *mut c_void,
    }
}
