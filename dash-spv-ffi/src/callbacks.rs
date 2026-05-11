//! FFI callback types for event notifications.
//!
//! This module provides several callback structs, each with one callback per event variant:
//! - `FFIProgressCallback` - Sync progress updates
//! - `FFISyncEventCallbacks` - Sync coordinator events
//! - `FFINetworkEventCallbacks` - Network manager events
//! - `FFIWalletEventCallbacks` - Wallet manager events

use crate::{dash_spv_ffi_sync_progress_destroy, FFISyncProgress};
use dash_spv::network::NetworkEvent;
use dash_spv::sync::{SyncEvent, SyncProgress};
use dash_spv::EventHandler;
use dashcore::hashes::Hash;
use key_wallet::account::AccountType;
use key_wallet::WalletCoreBalance;
use key_wallet_ffi::managed_account::{FFIAccountType, FFITransactionRecord};
use key_wallet_ffi::types::FFIBalance;
use key_wallet_manager::WalletEvent;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::ptr;

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
    Mempool = 7,
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
            dash_spv::sync::ManagerIdentifier::Mempool => FFIManagerId::Mempool,
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
                dash_spv_ffi_sync_progress_destroy(ptr);
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
        confirmed_txids: *const [u8; 32],
        confirmed_txid_count: u32,
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
                        .keys()
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
                confirmed_txids,
                ..
            } => {
                if let Some(cb) = self.on_block_processed {
                    let hash_bytes = block_hash.as_byte_array();
                    let txid_bytes: Vec<[u8; 32]> =
                        confirmed_txids.iter().map(|txid| *txid.as_byte_array()).collect();
                    let total_new_addresses: usize = new_addresses.values().map(|v| v.len()).sum();
                    cb(
                        *height,
                        hash_bytes as *const [u8; 32],
                        total_new_addresses as u32,
                        txid_bytes.as_ptr(),
                        txid_bytes.len() as u32,
                        self.user_data,
                    );
                }
            }
            SyncEvent::MasternodeStateUpdated {
                height,
                ..
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
// FFIAccountBalance - Per-account balance entry
// ============================================================================

/// Per-account balance pair carried on wallet events.
///
/// Wallet events deliver an array of these — one entry per account whose
/// balance changed during the event. Accounts whose balance was unchanged
/// are omitted to keep the payload small (most transactions touch only
/// 1–2 accounts).
///
/// `account_type` follows the same memory rules as the equivalent field on
/// [`FFITransactionRecord`]: the embedded `identity_user` / `identity_friend`
/// pointers (non-null only for Dashpay variants) are owned by the
/// `FFIAccountType` and freed when the array is dropped after the callback
/// returns. Consumers that need to retain the data past the callback must
/// copy the contents.
#[repr(C)]
pub struct FFIAccountBalance {
    /// Owning-account descriptor (discriminant + indices + identity ids).
    pub account_type: FFIAccountType,
    /// Balance for the account after the event.
    pub balance: FFIBalance,
}

impl FFIAccountBalance {
    fn from_map(map: &BTreeMap<AccountType, WalletCoreBalance>) -> Vec<Self> {
        map.iter()
            .map(|(account_type, balance)| FFIAccountBalance {
                account_type: FFIAccountType::from(account_type),
                balance: FFIBalance::from(*balance),
            })
            .collect()
    }
}

// ============================================================================
// FFIDerivedAddress - One address derived during gap-limit maintenance
// ============================================================================

/// Pool the derived address belongs to.
///
/// Mirrors `key_wallet::managed_account::address_pool::AddressPoolType`
/// 1:1 — kept distinct from the existing `FFIAddressPoolType` (which
/// collapses Absent / AbsentHardened into a single `Single` variant) so
/// event consumers can distinguish hardened single-pool variants
/// (Provider operator keys, etc.) from non-hardened ones.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FFIDerivedAddressPoolType {
    External = 0,
    Internal = 1,
    Absent = 2,
    AbsentHardened = 3,
}

impl From<key_wallet::managed_account::address_pool::AddressPoolType>
    for FFIDerivedAddressPoolType
{
    fn from(t: key_wallet::managed_account::address_pool::AddressPoolType) -> Self {
        use key_wallet::managed_account::address_pool::AddressPoolType as P;
        match t {
            P::External => FFIDerivedAddressPoolType::External,
            P::Internal => FFIDerivedAddressPoolType::Internal,
            P::Absent => FFIDerivedAddressPoolType::Absent,
            P::AbsentHardened => FFIDerivedAddressPoolType::AbsentHardened,
        }
    }
}

/// One address derived as a side effect of gap-limit maintenance during
/// transaction or block processing.
///
/// Wallet events deliver an array of these so persisters can mirror the
/// on-disk address pool transactionally with the tx/block records that
/// triggered the derivation. Without this, UTXOs landing on freshly
/// derived addresses orphan their parent address row at the persister.
///
/// `account_type` follows the same memory rules as on
/// [`FFIAccountBalance`]: the embedded `identity_user` / `identity_friend`
/// pointers are owned by the `FFIAccountType` and freed when the array is
/// dropped after the callback returns. `address` is a heap-allocated
/// null-terminated UTF-8 string, owned by this struct and freed on drop.
/// Consumers that need to retain the data past the callback must copy
/// every owning field — not just retain pointers.
#[repr(C)]
pub struct FFIDerivedAddress {
    /// Owning-account descriptor (discriminant + indices + identity ids).
    pub account_type: FFIAccountType,
    /// Pool within the account that derived this address.
    pub pool_type: FFIDerivedAddressPoolType,
    /// Derivation index within the pool. Combined with `account_type`
    /// and `pool_type`, this fully determines the derivation path —
    /// consumers that need a rendered path can recompute it
    /// deterministically.
    pub derivation_index: u32,
    /// Heap-allocated null-terminated UTF-8 string. Owned by this
    /// struct; freed when the struct is dropped.
    pub address: *mut c_char,
    /// 33-byte compressed ECDSA public key (inline, no allocation).
    pub public_key: [u8; 33],
}

impl FFIDerivedAddress {
    fn from_slice(addresses: &[key_wallet_manager::DerivedAddress]) -> Vec<Self> {
        addresses
            .iter()
            .map(|d| {
                let address_str = d.address.to_string();
                let c_address = CString::new(address_str).unwrap_or_else(|_| CString::default());
                FFIDerivedAddress {
                    account_type: FFIAccountType::from(&d.account_type),
                    pool_type: FFIDerivedAddressPoolType::from(d.pool_type),
                    derivation_index: d.derivation_index,
                    address: c_address.into_raw(),
                    public_key: d.public_key,
                }
            })
            .collect()
    }
}

impl Drop for FFIDerivedAddress {
    fn drop(&mut self) {
        if !self.address.is_null() {
            // SAFETY: `address` was constructed via `CString::into_raw` in
            // `FFIDerivedAddress::from_slice`, so reclaiming via
            // `CString::from_raw` is the matching free.
            let _ = unsafe { CString::from_raw(self.address) };
            self.address = std::ptr::null_mut();
        }
        // `account_type` has its own Drop impl that frees the
        // identity_user / identity_friend allocations when applicable.
    }
}

// ============================================================================
// FFIWalletEventCallbacks - One callback per WalletEvent variant
// ============================================================================

/// Callback for `WalletEvent::TransactionDetected`.
///
/// Fires when a wallet-relevant transaction is first seen off-chain — either
/// in the mempool, or directly via an InstantSend lock (in that case the
/// record's `context` is `InstantSend(..)`).
///
/// All pointer parameters are borrowed and only valid for the duration of the
/// callback. `balance` is the wallet's balance *after* the transaction was
/// recorded. `account_balances` is an array of size `account_balances_count`
/// containing one entry per account whose balance changed (typically 1–2
/// entries for a normal transaction); accounts whose balance is unchanged
/// are omitted. The array is null with a zero count when no per-account
/// balance changed.
///
/// `addresses_derived` is an array of size `addresses_derived_count` of
/// addresses derived as a side effect of gap-limit maintenance while
/// processing this transaction, attributed to the same account as
/// `record`. Empty in the common case (null pointer with zero count).
/// Persisters should write these rows transactionally with `record` so
/// UTXOs landing on freshly-derived addresses retain a parent row.
pub type OnTransactionDetectedCallback = Option<
    extern "C" fn(
        wallet_id: *const c_char,
        record: *const FFITransactionRecord,
        balance: *const FFIBalance,
        account_balances: *const FFIAccountBalance,
        account_balances_count: u32,
        addresses_derived: *const FFIDerivedAddress,
        addresses_derived_count: u32,
        user_data: *mut c_void,
    ),
>;

/// Callback for `WalletEvent::TransactionInstantLocked`.
///
/// Fires when an InstantSend lock is applied to a previously-seen off-chain
/// wallet-relevant transaction. Consumers already hold the full record from
/// the prior `TransactionDetected`; only the txid, the consensus-serialized
/// `InstantLock` bytes, and the post-change balance are delivered.
///
/// All pointer parameters are borrowed and only valid for the duration of
/// the callback. `balance` is the wallet's balance *after* the change.
/// `account_balances` follows the same contract as on
/// [`OnTransactionDetectedCallback`].
pub type OnTransactionInstantLockedCallback = Option<
    extern "C" fn(
        wallet_id: *const c_char,
        txid: *const [u8; 32],
        islock_data: *const u8,
        islock_len: usize,
        balance: *const FFIBalance,
        account_balances: *const FFIAccountBalance,
        account_balances_count: u32,
        user_data: *mut c_void,
    ),
>;

/// Callback for `WalletEvent::BlockProcessed`.
///
/// Fires once per wallet affected by a processed block. The three record
/// arrays bucket what happened in this block: `inserted` is records first
/// stored, `updated` is previously-known records confirmed, `matured` is
/// older coinbase records whose maturity threshold was just crossed. Empty
/// arrays are passed as null with a zero count. `balance` is the wallet's
/// balance *after* the block was processed. `account_balances` follows the
/// same contract as on [`OnTransactionDetectedCallback`].
///
/// `addresses_derived` is an array of size `addresses_derived_count` of
/// addresses derived as a side effect of gap-limit maintenance across
/// every record in the block, deduplicated by
/// `(account_type, pool_type, derivation_index)`. Empty in the common
/// case (null pointer with zero count). Persisters should write these
/// rows transactionally with the inserted/updated records.
///
/// `cl_hash` and `cl_signature` are non-null iff the processed block is
/// covered by the wallet's chainlock at processing time. When non-null,
/// every record in this event has an `InChainLockedBlock` context and
/// the carried chainlock is the proof that established it (`cl_height
/// >= height` by construction). When null, the block is above the
/// wallet's finality boundary and records are `InBlock`.
///
/// All array pointers and their contents are borrowed and only valid for the
/// duration of the callback.
pub type OnWalletBlockProcessedCallback = Option<
    extern "C" fn(
        wallet_id: *const c_char,
        height: u32,
        inserted: *const FFITransactionRecord,
        inserted_count: u32,
        updated: *const FFITransactionRecord,
        updated_count: u32,
        matured: *const FFITransactionRecord,
        matured_count: u32,
        balance: *const FFIBalance,
        account_balances: *const FFIAccountBalance,
        account_balances_count: u32,
        addresses_derived: *const FFIDerivedAddress,
        addresses_derived_count: u32,
        cl_height: u32,
        cl_hash: *const [u8; 32],
        cl_signature: *const [u8; 96],
        user_data: *mut c_void,
    ),
>;

/// Callback for `WalletEvent::SyncHeightAdvanced`.
///
/// Fires once per wallet when the filter pipeline commits a batch — the
/// wallet has been scanned up to `height`. Consumers can persist this as a
/// checkpoint atomically with any records/balance already persisted from
/// prior `BlockProcessed` events inside the batch.
pub type OnSyncHeightAdvancedCallback =
    Option<extern "C" fn(wallet_id: *const c_char, height: u32, user_data: *mut c_void)>;

/// One net-new chainlock-finalized txid, scoped to the account it was
/// promoted on. `WalletEvent::TransactionsChainlocked` delivers an
/// array of these — one entry per (account, txid) pair promoted by
/// the chainlock.
///
/// `account_type` follows the same memory rules as on
/// [`FFIAccountBalance`]: the embedded `identity_user` /
/// `identity_friend` pointers (non-null only for Dashpay variants)
/// are owned by the `FFIAccountType` and freed when the array is
/// dropped after the callback returns.
#[repr(C)]
pub struct FFIChainlockedTxid {
    /// Owning-account descriptor.
    pub account_type: FFIAccountType,
    /// Promoted transaction id.
    pub txid: [u8; 32],
}

impl FFIChainlockedTxid {
    fn from_map(map: &BTreeMap<AccountType, Vec<dashcore::Txid>>) -> Vec<Self> {
        let mut out = Vec::new();
        for (account_type, txids) in map {
            for txid in txids {
                out.push(FFIChainlockedTxid {
                    account_type: FFIAccountType::from(account_type),
                    txid: *txid.as_byte_array(),
                });
            }
        }
        out
    }
}

/// Callback for `WalletEvent::TransactionsChainlocked`.
///
/// Fires once per wallet when a chainlock promotes one or more
/// previously-`InBlock` records to `InChainLockedBlock`. Carries the
/// signing proof and the net-new finalized txids grouped per account
/// in a flat array. No balance is delivered because a chainlock does
/// not change UTXO state, so the wallet balance is unchanged.
///
/// All pointers are borrowed and only valid for the duration of the
/// callback.
pub type OnWalletTransactionsChainlockedCallback = Option<
    extern "C" fn(
        wallet_id: *const c_char,
        cl_height: u32,
        cl_hash: *const [u8; 32],
        cl_signature: *const [u8; 96],
        finalized: *const FFIChainlockedTxid,
        finalized_count: u32,
        user_data: *mut c_void,
    ),
>;

/// Wallet event callbacks - one callback per WalletEvent variant.
///
/// Set only the callbacks you're interested in; unset callbacks will be ignored.
///
/// All pointer parameters passed to callbacks (wallet IDs, txids, records,
/// balances) are borrowed and only valid for the duration of the callback
/// invocation. Callers must copy any data they need to retain.
#[repr(C)]
#[derive(Clone)]
pub struct FFIWalletEventCallbacks {
    pub on_transaction_detected: OnTransactionDetectedCallback,
    pub on_transaction_instant_locked: OnTransactionInstantLockedCallback,
    pub on_block_processed: OnWalletBlockProcessedCallback,
    pub on_sync_height_advanced: OnSyncHeightAdvancedCallback,
    pub on_transactions_chainlocked: OnWalletTransactionsChainlockedCallback,
    pub user_data: *mut c_void,
}

// SAFETY: Same rationale as FFISyncEventCallbacks
unsafe impl Send for FFIWalletEventCallbacks {}
unsafe impl Sync for FFIWalletEventCallbacks {}

impl Default for FFIWalletEventCallbacks {
    fn default() -> Self {
        Self {
            on_transaction_detected: None,
            on_transaction_instant_locked: None,
            on_block_processed: None,
            on_sync_height_advanced: None,
            on_transactions_chainlocked: None,
            user_data: std::ptr::null_mut(),
        }
    }
}

// ============================================================================
// FFIClientErrorCallback - Fatal client-level errors
// ============================================================================

/// Callback for fatal client errors (e.g. start failure, monitor thread crash).
///
/// The `error` string pointer is borrowed and only valid for the duration
/// of the callback. Callers must copy the string if they need to retain it
/// after the callback returns.
pub type OnClientErrorCallback =
    Option<extern "C" fn(error: *const c_char, user_data: *mut c_void)>;

/// Client error callback configuration.
#[repr(C)]
#[derive(Clone)]
pub struct FFIClientErrorCallback {
    pub on_error: OnClientErrorCallback,
    pub user_data: *mut c_void,
}

unsafe impl Send for FFIClientErrorCallback {}
unsafe impl Sync for FFIClientErrorCallback {}

impl Default for FFIClientErrorCallback {
    fn default() -> Self {
        Self {
            on_error: None,
            user_data: std::ptr::null_mut(),
        }
    }
}

impl FFIClientErrorCallback {
    /// Dispatch a client error to the callback.
    pub fn dispatch(&self, error: &str) {
        if let Some(cb) = self.on_error {
            let c_error = CString::new(error).unwrap_or_default();
            cb(c_error.as_ptr(), self.user_data);
        }
    }
}

// ============================================================================
// FFIEventCallbacks - All callbacks in a single C-compatible struct
// ============================================================================

/// All event callbacks grouped into a single struct.
///
/// Pass this to `dash_spv_ffi_client_new`. Any callback group left at its
/// default (all function pointers null) will simply not receive events.
#[repr(C)]
#[derive(Clone, Default)]
pub struct FFIEventCallbacks {
    pub sync: FFISyncEventCallbacks,
    pub network: FFINetworkEventCallbacks,
    pub progress: FFIProgressCallback,
    pub wallet: FFIWalletEventCallbacks,
    pub error: FFIClientErrorCallback,
}

unsafe impl Send for FFIEventCallbacks {}
unsafe impl Sync for FFIEventCallbacks {}

impl EventHandler for FFIEventCallbacks {
    fn on_sync_event(&self, event: &SyncEvent) {
        self.sync.dispatch(event);
    }

    fn on_network_event(&self, event: &NetworkEvent) {
        self.network.dispatch(event);
    }

    fn on_progress(&self, progress: &SyncProgress) {
        self.progress.dispatch(progress);
    }

    fn on_wallet_event(&self, event: &WalletEvent) {
        self.wallet.dispatch(event);
    }

    fn on_error(&self, error: &str) {
        self.error.dispatch(error);
    }
}

impl FFIWalletEventCallbacks {
    /// Dispatch a WalletEvent to the appropriate callback.
    pub fn dispatch(&self, event: &WalletEvent) {
        match event {
            WalletEvent::TransactionDetected {
                wallet_id,
                record,
                balance,
                account_balances,
                addresses_derived,
            } => {
                if let Some(cb) = self.on_transaction_detected {
                    let wallet_id_hex = hex::encode(wallet_id);
                    let c_wallet_id = CString::new(wallet_id_hex).unwrap_or_default();
                    let ffi_record = FFITransactionRecord::from(record.as_ref());
                    let ffi_balance = FFIBalance::from(*balance);
                    let ffi_account_balances = FFIAccountBalance::from_map(account_balances);
                    let ffi_addresses_derived = FFIDerivedAddress::from_slice(addresses_derived);
                    let account_balances_ptr = if ffi_account_balances.is_empty() {
                        ptr::null()
                    } else {
                        ffi_account_balances.as_ptr()
                    };
                    let addresses_derived_ptr = if ffi_addresses_derived.is_empty() {
                        ptr::null()
                    } else {
                        ffi_addresses_derived.as_ptr()
                    };

                    cb(
                        c_wallet_id.as_ptr(),
                        &ffi_record as *const FFITransactionRecord,
                        &ffi_balance as *const FFIBalance,
                        account_balances_ptr,
                        ffi_account_balances.len() as u32,
                        addresses_derived_ptr,
                        ffi_addresses_derived.len() as u32,
                        self.user_data,
                    );

                    drop(ffi_account_balances);
                    drop(ffi_addresses_derived);
                }
            }
            WalletEvent::TransactionInstantLocked {
                wallet_id,
                txid,
                instant_lock,
                balance,
                account_balances,
            } => {
                if let Some(cb) = self.on_transaction_instant_locked {
                    let wallet_id_hex = hex::encode(wallet_id);
                    let c_wallet_id = CString::new(wallet_id_hex).unwrap_or_default();
                    let txid_bytes = *txid.as_byte_array();
                    let islock_bytes = dashcore::consensus::serialize(instant_lock);
                    let ffi_balance = FFIBalance::from(*balance);
                    let ffi_account_balances = FFIAccountBalance::from_map(account_balances);
                    let account_balances_ptr = if ffi_account_balances.is_empty() {
                        ptr::null()
                    } else {
                        ffi_account_balances.as_ptr()
                    };

                    cb(
                        c_wallet_id.as_ptr(),
                        &txid_bytes as *const [u8; 32],
                        islock_bytes.as_ptr(),
                        islock_bytes.len(),
                        &ffi_balance as *const FFIBalance,
                        account_balances_ptr,
                        ffi_account_balances.len() as u32,
                        self.user_data,
                    );

                    drop(ffi_account_balances);
                }
            }
            WalletEvent::BlockProcessed {
                wallet_id,
                height,
                inserted,
                updated,
                matured,
                balance,
                account_balances,
                addresses_derived,
                chain_lock,
            } => {
                if let Some(cb) = self.on_block_processed {
                    let wallet_id_hex = hex::encode(wallet_id);
                    let c_wallet_id = CString::new(wallet_id_hex).unwrap_or_default();
                    let ffi_inserted: Vec<FFITransactionRecord> =
                        inserted.iter().map(FFITransactionRecord::from).collect();
                    let ffi_updated: Vec<FFITransactionRecord> =
                        updated.iter().map(FFITransactionRecord::from).collect();
                    let ffi_matured: Vec<FFITransactionRecord> =
                        matured.iter().map(FFITransactionRecord::from).collect();
                    let ffi_balance = FFIBalance::from(*balance);
                    let ffi_account_balances = FFIAccountBalance::from_map(account_balances);
                    let ffi_addresses_derived = FFIDerivedAddress::from_slice(addresses_derived);

                    // Pass a null pointer when an array is empty so C/Swift
                    // consumers that null-check before reading don't see a
                    // non-null dangling pointer paired with a zero count.
                    let inserted_ptr = if ffi_inserted.is_empty() {
                        ptr::null()
                    } else {
                        ffi_inserted.as_ptr()
                    };
                    let updated_ptr = if ffi_updated.is_empty() {
                        ptr::null()
                    } else {
                        ffi_updated.as_ptr()
                    };
                    let matured_ptr = if ffi_matured.is_empty() {
                        ptr::null()
                    } else {
                        ffi_matured.as_ptr()
                    };
                    let account_balances_ptr = if ffi_account_balances.is_empty() {
                        ptr::null()
                    } else {
                        ffi_account_balances.as_ptr()
                    };
                    let addresses_derived_ptr = if ffi_addresses_derived.is_empty() {
                        ptr::null()
                    } else {
                        ffi_addresses_derived.as_ptr()
                    };
                    // Null pointers (and `cl_height=0`) when the block isn't
                    // chainlocked; non-null hash + signature pointers borrow
                    // from `chain_lock` for the duration of the callback.
                    let (cl_height_arg, cl_hash_arg, cl_signature_arg) = match chain_lock {
                        Some(cl) => (
                            cl.block_height,
                            cl.block_hash.as_byte_array() as *const [u8; 32],
                            cl.signature.as_bytes() as *const [u8; 96],
                        ),
                        None => (0, ptr::null(), ptr::null()),
                    };

                    cb(
                        c_wallet_id.as_ptr(),
                        *height,
                        inserted_ptr,
                        ffi_inserted.len() as u32,
                        updated_ptr,
                        ffi_updated.len() as u32,
                        matured_ptr,
                        ffi_matured.len() as u32,
                        &ffi_balance as *const FFIBalance,
                        account_balances_ptr,
                        ffi_account_balances.len() as u32,
                        addresses_derived_ptr,
                        ffi_addresses_derived.len() as u32,
                        cl_height_arg,
                        cl_hash_arg,
                        cl_signature_arg,
                        self.user_data,
                    );

                    drop(ffi_inserted);
                    drop(ffi_updated);
                    drop(ffi_matured);
                    drop(ffi_account_balances);
                    drop(ffi_addresses_derived);
                }
            }
            WalletEvent::SyncHeightAdvanced {
                wallet_id,
                height,
            } => {
                if let Some(cb) = self.on_sync_height_advanced {
                    let wallet_id_hex = hex::encode(wallet_id);
                    let c_wallet_id = CString::new(wallet_id_hex).unwrap_or_default();
                    cb(c_wallet_id.as_ptr(), *height, self.user_data);
                }
            }
            WalletEvent::TransactionsChainlocked {
                wallet_id,
                chain_lock,
                per_account,
            } => {
                if let Some(cb) = self.on_transactions_chainlocked {
                    let wallet_id_hex = hex::encode(wallet_id);
                    let c_wallet_id = CString::new(wallet_id_hex).unwrap_or_default();
                    let ffi_finalized = FFIChainlockedTxid::from_map(per_account);
                    let finalized_ptr = if ffi_finalized.is_empty() {
                        ptr::null()
                    } else {
                        ffi_finalized.as_ptr()
                    };

                    cb(
                        c_wallet_id.as_ptr(),
                        chain_lock.block_height,
                        chain_lock.block_hash.as_byte_array() as *const [u8; 32],
                        chain_lock.signature.as_bytes() as *const [u8; 96],
                        finalized_ptr,
                        ffi_finalized.len() as u32,
                        self.user_data,
                    );

                    drop(ffi_finalized);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::hashes::Hash;
    use dashcore::{Address, BlockHash, Network, Txid};
    use key_wallet_manager::{FilterMatchKey, WalletId};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// `BlocksNeeded` dispatch must pass exactly one entry per
    /// `FilterMatchKey` to the FFI callback (i.e. iterate keys, not
    /// inflated by the per-block wallet attribution).
    #[test]
    fn test_blocks_needed_dispatch_passes_unique_keys_count() {
        static COUNT: AtomicU32 = AtomicU32::new(u32::MAX);
        extern "C" fn cb(_blocks: *const FFIBlockNeeded, count: u32, _user: *mut c_void) {
            COUNT.store(count, Ordering::SeqCst);
        }

        let callbacks = FFISyncEventCallbacks {
            on_blocks_needed: Some(cb),
            ..FFISyncEventCallbacks::default()
        };

        let mut blocks: BTreeMap<FilterMatchKey, BTreeSet<WalletId>> = BTreeMap::new();
        // Two distinct blocks, each attributed to two wallets. The dispatch
        // must report 2 (unique keys), not 4.
        blocks.insert(
            FilterMatchKey::new(10, BlockHash::from_byte_array([1u8; 32])),
            BTreeSet::from([[1u8; 32], [2u8; 32]]),
        );
        blocks.insert(
            FilterMatchKey::new(20, BlockHash::from_byte_array([2u8; 32])),
            BTreeSet::from([[1u8; 32], [2u8; 32]]),
        );

        callbacks.dispatch(&SyncEvent::BlocksNeeded {
            blocks,
        });
        assert_eq!(COUNT.load(Ordering::SeqCst), 2);
    }

    /// `BlockProcessed` dispatch must report the total address count
    /// summed across all per-wallet entries in the `new_addresses` map.
    #[test]
    fn test_block_processed_dispatch_sums_per_wallet_addresses() {
        static NEW_ADDR_COUNT: AtomicU32 = AtomicU32::new(u32::MAX);
        extern "C" fn cb(
            _height: u32,
            _hash: *const [u8; 32],
            new_address_count: u32,
            _txids: *const [u8; 32],
            _txid_count: u32,
            _user: *mut c_void,
        ) {
            NEW_ADDR_COUNT.store(new_address_count, Ordering::SeqCst);
        }

        let callbacks = FFISyncEventCallbacks {
            on_block_processed: Some(cb),
            ..FFISyncEventCallbacks::default()
        };

        let addr_a = Address::dummy(Network::Regtest, 1);
        let addr_b = Address::dummy(Network::Regtest, 2);
        let addr_c = Address::dummy(Network::Regtest, 3);
        let mut new_addresses: BTreeMap<WalletId, Vec<Address>> = BTreeMap::new();
        // Wallet 1 contributes 2 new addresses, wallet 2 contributes 1. Total = 3.
        new_addresses.insert([1u8; 32], vec![addr_a, addr_b]);
        new_addresses.insert([2u8; 32], vec![addr_c]);

        callbacks.dispatch(&SyncEvent::BlockProcessed {
            block_hash: BlockHash::from_byte_array([7u8; 32]),
            height: 100,
            wallets: BTreeSet::new(),
            new_addresses,
            confirmed_txids: vec![Txid::from_byte_array([9u8; 32])],
        });
        assert_eq!(NEW_ADDR_COUNT.load(Ordering::SeqCst), 3);
    }
}
