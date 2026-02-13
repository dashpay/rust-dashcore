//! FFI callback types for event notifications.
//!
//! This module provides several callback structs, each with one callback per event variant:
//! - `FFIProgressCallback` - Sync progress updates
//! - `FFISyncEventCallbacks` - Sync coordinator events
//! - `FFINetworkEventCallbacks` - Network manager events
//! - `FFIWalletEventCallbacks` - Wallet manager events

use crate::{dash_spv_ffi_manager_sync_progress_destroy, FFISyncProgress};
use dashcore::hashes::Hash;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};

// ============================================================================
// Sync Event Types (for FFISyncEventCallbacks)
// ============================================================================

/// Identifies which sync manager generated an event.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FFIManagerId {
    Headers = 0,
    FilterHeaders = 1,
    Filters = 2,
    Blocks = 3,
    Masternodes = 4,
    ChainLocks = 5,
    InstantSend = 6,
}

impl From<dash_spv::sync::ManagerIdentifier> for FFIManagerId {
    fn from(id: dash_spv::sync::ManagerIdentifier) -> Self {
        match id {
            dash_spv::sync::ManagerIdentifier::BlockHeader => FFIManagerId::Headers,
            dash_spv::sync::ManagerIdentifier::FilterHeader => FFIManagerId::FilterHeaders,
            dash_spv::sync::ManagerIdentifier::Filter => FFIManagerId::Filters,
            dash_spv::sync::ManagerIdentifier::Block => FFIManagerId::Blocks,
            dash_spv::sync::ManagerIdentifier::Masternode => FFIManagerId::Masternodes,
            dash_spv::sync::ManagerIdentifier::ChainLock => FFIManagerId::ChainLocks,
            dash_spv::sync::ManagerIdentifier::InstantSend => FFIManagerId::InstantSend,
        }
    }
}

// ============================================================================
// Progress Callback
// ============================================================================

/// Callback for sync progress updates.
///
/// Called whenever the sync progress changes. The progress pointer is only
/// valid for the duration of the callback. The caller must NOT free the
/// progress pointer - it will be freed automatically after the callback returns.
pub type OnProgressUpdateCallback =
    Option<extern "C" fn(progress: *const FFISyncProgress, user_data: *mut c_void)>;

/// Progress callback configuration.
#[repr(C)]
#[derive(Clone)]
pub struct FFIProgressCallback {
    /// Callback function for progress updates.
    pub on_progress: OnProgressUpdateCallback,
    /// User data passed to the callback.
    pub user_data: *mut c_void,
}

unsafe impl Send for FFIProgressCallback {}
unsafe impl Sync for FFIProgressCallback {}

impl Default for FFIProgressCallback {
    fn default() -> Self {
        Self {
            on_progress: None,
            user_data: std::ptr::null_mut(),
        }
    }
}

impl FFIProgressCallback {
    /// Dispatch a progress update to the callback.
    ///
    /// Creates an FFISyncProgress from the Rust progress, calls the callback,
    /// then cleans up all allocated memory.
    pub fn dispatch(&self, progress: &dash_spv::sync::SyncProgress) {
        if let Some(cb) = self.on_progress {
            // Clone the progress to get an owned SyncProgress for conversion
            let owned_progress = progress.clone();
            let ffi_progress = Box::new(FFISyncProgress::from(owned_progress));
            let ptr = Box::into_raw(ffi_progress);

            // Call the callback
            cb(ptr as *const FFISyncProgress, self.user_data);

            // Clean up the progress and all its nested pointers
            unsafe {
                dash_spv_ffi_manager_sync_progress_destroy(ptr);
            }
        }
    }
}

// ============================================================================
// FFISyncEventCallbacks - One callback per SyncEvent variant
// ============================================================================

/// Callback for SyncEvent::SyncStart
pub type OnSyncStartCallback =
    Option<extern "C" fn(manager_id: FFIManagerId, user_data: *mut c_void)>;

/// Callback for SyncEvent::BlockHeadersStored
pub type OnBlockHeadersStoredCallback =
    Option<extern "C" fn(tip_height: u32, user_data: *mut c_void)>;

/// Callback for SyncEvent::BlockHeaderSyncComplete
pub type OnBlockHeaderSyncCompleteCallback =
    Option<extern "C" fn(tip_height: u32, user_data: *mut c_void)>;

/// Callback for SyncEvent::FilterHeadersStored
pub type OnFilterHeadersStoredCallback = Option<
    extern "C" fn(start_height: u32, end_height: u32, tip_height: u32, user_data: *mut c_void),
>;

/// Callback for SyncEvent::FilterHeadersSyncComplete
pub type OnFilterHeadersSyncCompleteCallback =
    Option<extern "C" fn(tip_height: u32, user_data: *mut c_void)>;

/// Callback for SyncEvent::FiltersStored
pub type OnFiltersStoredCallback =
    Option<extern "C" fn(start_height: u32, end_height: u32, user_data: *mut c_void)>;

/// Callback for SyncEvent::FiltersSyncComplete
pub type OnFiltersSyncCompleteCallback =
    Option<extern "C" fn(tip_height: u32, user_data: *mut c_void)>;

/// A block that needs to be downloaded (height + hash).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FFIBlockNeeded {
    /// Block height
    pub height: u32,
    /// Block hash (32 bytes)
    pub hash: [u8; 32],
}

/// Callback for SyncEvent::BlocksNeeded
///
/// The `blocks` pointer points to an array of `FFIBlockNeeded` structs.
/// The pointer is borrowed and only valid for the duration of the callback.
/// Callers must memcpy/duplicate any data they need to retain after the
/// callback returns.
pub type OnBlocksNeededCallback =
    Option<extern "C" fn(blocks: *const FFIBlockNeeded, count: u32, user_data: *mut c_void)>;

/// Callback for SyncEvent::BlockProcessed
///
/// The `hash` pointer is borrowed and only valid for the duration of the
/// callback. Callers must memcpy/duplicate it to retain the value after
/// the callback returns.
pub type OnBlockProcessedCallback = Option<
    extern "C" fn(
        height: u32,
        hash: *const [u8; 32],
        new_address_count: u32,
        user_data: *mut c_void,
    ),
>;

/// Callback for SyncEvent::MasternodeStateUpdated
pub type OnMasternodeStateUpdatedCallback =
    Option<extern "C" fn(height: u32, user_data: *mut c_void)>;

/// Callback for SyncEvent::ChainLockReceived
///
/// The `hash` and `signature` pointers are borrowed and only valid for the
/// duration of the callback. Callers must memcpy/duplicate them to retain
/// the values after the callback returns.
pub type OnChainLockReceivedCallback = Option<
    extern "C" fn(
        height: u32,
        hash: *const [u8; 32],
        signature: *const [u8; 96],
        validated: bool,
        user_data: *mut c_void,
    ),
>;

/// Callback for SyncEvent::InstantLockReceived
///
/// The `txid` pointer is borrowed and only valid for the duration of the callback.
/// The `instantlock_data` pointer points to the consensus-serialized InstantLock
/// bytes and is only valid for the duration of the callback.
/// Callers must memcpy/duplicate any data they need to retain.
pub type OnInstantLockReceivedCallback = Option<
    extern "C" fn(
        txid: *const [u8; 32],
        instantlock_data: *const u8,
        instantlock_len: usize,
        validated: bool,
        user_data: *mut c_void,
    ),
>;

/// Callback for SyncEvent::ManagerError
///
/// The `error` string pointer is borrowed and only valid for the duration
/// of the callback. Callers must copy the string if they need to retain it
/// after the callback returns.
pub type OnManagerErrorCallback =
    Option<extern "C" fn(manager_id: FFIManagerId, error: *const c_char, user_data: *mut c_void)>;

/// Callback for SyncEvent::SyncComplete
pub type OnSyncCompleteCallback =
    Option<extern "C" fn(header_tip: u32, cycle: u32, user_data: *mut c_void)>;

/// Sync event callbacks - one callback per SyncEvent variant.
///
/// Set only the callbacks you're interested in; unset callbacks will be ignored.
///
/// All pointer parameters passed to callbacks (strings, hashes, arrays) are
/// borrowed and only valid for the duration of the callback invocation.
/// Callers must memcpy/duplicate any data they need to retain.
#[repr(C)]
#[derive(Clone)]
pub struct FFISyncEventCallbacks {
    pub on_sync_start: OnSyncStartCallback,
    pub on_block_headers_stored: OnBlockHeadersStoredCallback,
    pub on_block_header_sync_complete: OnBlockHeaderSyncCompleteCallback,
    pub on_filter_headers_stored: OnFilterHeadersStoredCallback,
    pub on_filter_headers_sync_complete: OnFilterHeadersSyncCompleteCallback,
    pub on_filters_stored: OnFiltersStoredCallback,
    pub on_filters_sync_complete: OnFiltersSyncCompleteCallback,
    pub on_blocks_needed: OnBlocksNeededCallback,
    pub on_block_processed: OnBlockProcessedCallback,
    pub on_masternode_state_updated: OnMasternodeStateUpdatedCallback,
    pub on_chainlock_received: OnChainLockReceivedCallback,
    pub on_instantlock_received: OnInstantLockReceivedCallback,
    pub on_manager_error: OnManagerErrorCallback,
    pub on_sync_complete: OnSyncCompleteCallback,
    pub user_data: *mut c_void,
}

// SAFETY: FFISyncEventCallbacks is safe to send between threads because:
// 1. All callback function pointers are extern "C" functions with no captured state
// 2. The user_data pointer is treated as opaque and managed by the caller
// 3. The caller is responsible for ensuring user_data points to thread-safe memory
unsafe impl Send for FFISyncEventCallbacks {}

// SAFETY: FFISyncEventCallbacks is safe to share between threads because:
// 1. The struct is immutable after construction
// 2. Function pointers are inherently thread-safe
// 3. Thread safety of user_data is the caller's responsibility
unsafe impl Sync for FFISyncEventCallbacks {}

impl Default for FFISyncEventCallbacks {
    fn default() -> Self {
        Self {
            on_sync_start: None,
            on_block_headers_stored: None,
            on_block_header_sync_complete: None,
            on_filter_headers_stored: None,
            on_filter_headers_sync_complete: None,
            on_filters_stored: None,
            on_filters_sync_complete: None,
            on_blocks_needed: None,
            on_block_processed: None,
            on_masternode_state_updated: None,
            on_chainlock_received: None,
            on_instantlock_received: None,
            on_manager_error: None,
            on_sync_complete: None,
            user_data: std::ptr::null_mut(),
        }
    }
}

impl FFISyncEventCallbacks {
    /// Dispatch a SyncEvent to the appropriate callback.
    pub fn dispatch(&self, event: &dash_spv::sync::SyncEvent) {
        use dash_spv::sync::SyncEvent;

        match event {
            SyncEvent::SyncStart {
                identifier,
            } => {
                if let Some(cb) = self.on_sync_start {
                    cb((*identifier).into(), self.user_data);
                }
            }
            SyncEvent::BlockHeadersStored {
                tip_height,
            } => {
                if let Some(cb) = self.on_block_headers_stored {
                    cb(*tip_height, self.user_data);
                }
            }
            SyncEvent::BlockHeaderSyncComplete {
                tip_height,
            } => {
                if let Some(cb) = self.on_block_header_sync_complete {
                    cb(*tip_height, self.user_data);
                }
            }
            SyncEvent::FilterHeadersStored {
                start_height,
                end_height,
                tip_height,
            } => {
                if let Some(cb) = self.on_filter_headers_stored {
                    cb(*start_height, *end_height, *tip_height, self.user_data);
                }
            }
            SyncEvent::FilterHeadersSyncComplete {
                tip_height,
            } => {
                if let Some(cb) = self.on_filter_headers_sync_complete {
                    cb(*tip_height, self.user_data);
                }
            }
            SyncEvent::FiltersStored {
                start_height,
                end_height,
            } => {
                if let Some(cb) = self.on_filters_stored {
                    cb(*start_height, *end_height, self.user_data);
                }
            }
            SyncEvent::FiltersSyncComplete {
                tip_height,
            } => {
                if let Some(cb) = self.on_filters_sync_complete {
                    cb(*tip_height, self.user_data);
                }
            }
            SyncEvent::BlocksNeeded {
                blocks,
            } => {
                if let Some(cb) = self.on_blocks_needed {
                    let ffi_blocks: Vec<FFIBlockNeeded> = blocks
                        .iter()
                        .map(|key| FFIBlockNeeded {
                            height: key.height(),
                            hash: *key.hash().as_byte_array(),
                        })
                        .collect();
                    cb(ffi_blocks.as_ptr(), ffi_blocks.len() as u32, self.user_data);
                }
            }
            SyncEvent::BlockProcessed {
                block_hash,
                height,
                new_addresses,
            } => {
                if let Some(cb) = self.on_block_processed {
                    let hash_bytes = block_hash.as_byte_array();
                    cb(
                        *height,
                        hash_bytes as *const [u8; 32],
                        new_addresses.len() as u32,
                        self.user_data,
                    );
                }
            }
            SyncEvent::MasternodeStateUpdated {
                height,
            } => {
                if let Some(cb) = self.on_masternode_state_updated {
                    cb(*height, self.user_data);
                }
            }
            SyncEvent::ChainLockReceived {
                chain_lock,
                validated,
            } => {
                if let Some(cb) = self.on_chainlock_received {
                    let hash_bytes = chain_lock.block_hash.as_byte_array();
                    let sig_bytes = chain_lock.signature.as_bytes();
                    cb(
                        chain_lock.block_height,
                        hash_bytes as *const [u8; 32],
                        sig_bytes as *const [u8; 96],
                        *validated,
                        self.user_data,
                    );
                }
            }
            SyncEvent::InstantLockReceived {
                instant_lock,
                validated,
            } => {
                if let Some(cb) = self.on_instantlock_received {
                    let txid_bytes = instant_lock.txid.as_byte_array();
                    let serialized = dashcore::consensus::serialize(instant_lock);
                    cb(
                        txid_bytes as *const [u8; 32],
                        serialized.as_ptr(),
                        serialized.len(),
                        *validated,
                        self.user_data,
                    );
                }
            }
            SyncEvent::ManagerError {
                manager,
                error,
            } => {
                if let Some(cb) = self.on_manager_error {
                    let c_error = CString::new(error.as_str()).unwrap_or_default();
                    cb((*manager).into(), c_error.as_ptr(), self.user_data);
                }
            }
            SyncEvent::SyncComplete {
                header_tip,
                cycle,
            } => {
                if let Some(cb) = self.on_sync_complete {
                    cb(*header_tip, *cycle, self.user_data);
                }
            }
        }
    }
}

// ============================================================================
// FFINetworkEventCallbacks - One callback per NetworkEvent variant
// ============================================================================

/// Callback for NetworkEvent::PeerConnected
///
/// The `address` string pointer is borrowed and only valid for the duration
/// of the callback. Callers must copy the string if they need to retain it
/// after the callback returns.
pub type OnPeerConnectedCallback =
    Option<extern "C" fn(address: *const c_char, user_data: *mut c_void)>;

/// Callback for NetworkEvent::PeerDisconnected
///
/// The `address` string pointer is borrowed and only valid for the duration
/// of the callback. Callers must copy the string if they need to retain it
/// after the callback returns.
pub type OnPeerDisconnectedCallback =
    Option<extern "C" fn(address: *const c_char, user_data: *mut c_void)>;

/// Callback for NetworkEvent::PeersUpdated
pub type OnPeersUpdatedCallback =
    Option<extern "C" fn(connected_count: u32, best_height: u32, user_data: *mut c_void)>;

/// Network event callbacks - one callback per NetworkEvent variant.
///
/// Set only the callbacks you're interested in; unset callbacks will be ignored.
///
/// All pointer parameters passed to callbacks (strings, addresses) are
/// borrowed and only valid for the duration of the callback invocation.
/// Callers must copy any data they need to retain.
#[repr(C)]
#[derive(Clone)]
pub struct FFINetworkEventCallbacks {
    pub on_peer_connected: OnPeerConnectedCallback,
    pub on_peer_disconnected: OnPeerDisconnectedCallback,
    pub on_peers_updated: OnPeersUpdatedCallback,
    pub user_data: *mut c_void,
}

// SAFETY: Same rationale as FFISyncEventCallbacks
unsafe impl Send for FFINetworkEventCallbacks {}
unsafe impl Sync for FFINetworkEventCallbacks {}

impl Default for FFINetworkEventCallbacks {
    fn default() -> Self {
        Self {
            on_peer_connected: None,
            on_peer_disconnected: None,
            on_peers_updated: None,
            user_data: std::ptr::null_mut(),
        }
    }
}

impl FFINetworkEventCallbacks {
    /// Dispatch a NetworkEvent to the appropriate callback.
    pub fn dispatch(&self, event: &dash_spv::network::NetworkEvent) {
        use dash_spv::network::NetworkEvent;

        match event {
            NetworkEvent::PeerConnected {
                address,
            } => {
                if let Some(cb) = self.on_peer_connected {
                    let c_addr = CString::new(address.to_string()).unwrap_or_default();
                    cb(c_addr.as_ptr(), self.user_data);
                }
            }
            NetworkEvent::PeerDisconnected {
                address,
            } => {
                if let Some(cb) = self.on_peer_disconnected {
                    let c_addr = CString::new(address.to_string()).unwrap_or_default();
                    cb(c_addr.as_ptr(), self.user_data);
                }
            }
            NetworkEvent::PeersUpdated {
                connected_count,
                best_height,
                ..
            } => {
                if let Some(cb) = self.on_peers_updated {
                    cb(*connected_count as u32, best_height.unwrap_or(0), self.user_data);
                }
            }
        }
    }
}

// ============================================================================
// FFIWalletEventCallbacks - One callback per WalletEvent variant
// ============================================================================

/// Callback for WalletEvent::TransactionReceived
///
/// The `wallet_id`, `addresses` string pointers and the `txid` hash pointer
/// are borrowed and only valid for the duration of the callback. Callers must
/// copy any data they need to retain after the callback returns.
pub type OnTransactionReceivedCallback = Option<
    extern "C" fn(
        wallet_id: *const c_char,
        account_index: u32,
        txid: *const [u8; 32],
        amount: i64,
        addresses: *const c_char,
        user_data: *mut c_void,
    ),
>;

/// Callback for WalletEvent::BalanceUpdated
///
/// The `wallet_id` string pointer is borrowed and only valid for the duration
/// of the callback. Callers must copy the string if they need to retain it
/// after the callback returns.
pub type OnBalanceUpdatedCallback = Option<
    extern "C" fn(
        wallet_id: *const c_char,
        spendable: u64,
        unconfirmed: u64,
        immature: u64,
        locked: u64,
        user_data: *mut c_void,
    ),
>;

/// Wallet event callbacks - one callback per WalletEvent variant.
///
/// Set only the callbacks you're interested in; unset callbacks will be ignored.
///
/// All pointer parameters passed to callbacks (wallet IDs, txids, addresses)
/// are borrowed and only valid for the duration of the callback invocation.
/// Callers must copy any data they need to retain.
#[repr(C)]
#[derive(Clone)]
pub struct FFIWalletEventCallbacks {
    pub on_transaction_received: OnTransactionReceivedCallback,
    pub on_balance_updated: OnBalanceUpdatedCallback,
    pub user_data: *mut c_void,
}

// SAFETY: Same rationale as FFISyncEventCallbacks
unsafe impl Send for FFIWalletEventCallbacks {}
unsafe impl Sync for FFIWalletEventCallbacks {}

impl Default for FFIWalletEventCallbacks {
    fn default() -> Self {
        Self {
            on_transaction_received: None,
            on_balance_updated: None,
            user_data: std::ptr::null_mut(),
        }
    }
}

impl FFIWalletEventCallbacks {
    /// Dispatch a WalletEvent to the appropriate callback.
    pub fn dispatch(&self, event: &key_wallet_manager::WalletEvent) {
        use key_wallet_manager::WalletEvent;

        match event {
            WalletEvent::TransactionReceived {
                wallet_id,
                account_index,
                txid,
                amount,
                addresses,
            } => {
                if let Some(cb) = self.on_transaction_received {
                    let wallet_id_hex = hex::encode(wallet_id);
                    let c_wallet_id = CString::new(wallet_id_hex).unwrap_or_default();
                    let txid_bytes = txid.as_byte_array();
                    let addresses_str: Vec<String> =
                        addresses.iter().map(|a| a.to_string()).collect();
                    let c_addresses = CString::new(addresses_str.join(",")).unwrap_or_default();
                    cb(
                        c_wallet_id.as_ptr(),
                        *account_index,
                        txid_bytes as *const [u8; 32],
                        *amount,
                        c_addresses.as_ptr(),
                        self.user_data,
                    );
                }
            }
            WalletEvent::BalanceUpdated {
                wallet_id,
                spendable,
                unconfirmed,
                immature,
                locked,
            } => {
                if let Some(cb) = self.on_balance_updated {
                    let wallet_id_hex = hex::encode(wallet_id);
                    let c_wallet_id = CString::new(wallet_id_hex).unwrap_or_default();
                    cb(
                        c_wallet_id.as_ptr(),
                        *spendable,
                        *unconfirmed,
                        *immature,
                        *locked,
                        self.user_data,
                    );
                }
            }
        }
    }
}
