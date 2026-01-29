use dashcore::hashes::Hash;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};

// ============================================================================
// Sync Event Types (for push-based event notifications)
// ============================================================================

/// Event types for the parallel sync system.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FFISyncEventType {
    SyncStart = 0,
    BlockHeadersStored = 1,
    BlockHeaderSyncComplete = 2,
    FilterHeadersStored = 3,
    FilterHeadersSyncComplete = 4,
    FiltersStored = 5,
    FiltersSyncComplete = 6,
    BlocksNeeded = 7,
    BlockProcessed = 8,
    MasternodeStateUpdated = 9,
    ChainLockReceived = 10,
    InstantLockReceived = 11,
    ManagerError = 12,
    SyncComplete = 13,
}

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

/// A sync event from the parallel sync system.
#[repr(C)]
pub struct FFISyncEvent {
    pub event_type: FFISyncEventType,
    pub height: u32,
    pub start_height: u32,
    pub end_height: u32,
    pub manager_id: FFIManagerId,
    pub validated: bool,
    pub hash: [u8; 32],
    pub txid: [u8; 32],
    pub error_message: *const c_char,
}

/// Callback type for receiving sync events.
pub type SyncEventCallback =
    Option<extern "C" fn(event: *const FFISyncEvent, user_data: *mut c_void)>;

pub type ProgressCallback =
    extern "C" fn(progress: f64, message: *const c_char, user_data: *mut c_void);
pub type CompletionCallback =
    extern "C" fn(success: bool, error: *const c_char, user_data: *mut c_void);
pub type DataCallback = extern "C" fn(data: *const c_void, len: usize, user_data: *mut c_void);

#[repr(C)]
pub struct FFICallbacks {
    pub on_progress: Option<ProgressCallback>,
    pub on_completion: Option<CompletionCallback>,
    pub on_data: Option<DataCallback>,
    pub user_data: *mut c_void,
}

/// # Safety
/// FFICallbacks is only Send if all callback functions and user_data are thread-safe.
/// The caller must ensure that:
/// - All callback functions can be safely called from any thread
/// - The user_data pointer points to thread-safe data or is properly synchronized
unsafe impl Send for FFICallbacks {}

/// # Safety
/// FFICallbacks is only Sync if all callback functions and user_data are thread-safe.
/// The caller must ensure that:
/// - All callback functions can be safely called concurrently from multiple threads
/// - The user_data pointer points to thread-safe data or is properly synchronized
unsafe impl Sync for FFICallbacks {}

impl Default for FFICallbacks {
    fn default() -> Self {
        FFICallbacks {
            on_progress: None,
            on_completion: None,
            on_data: None,
            user_data: std::ptr::null_mut(),
        }
    }
}

impl FFICallbacks {
    /// Call the progress callback with a progress value and message.
    ///
    /// # Safety
    /// The string pointer passed to the callback is only valid for the duration of the callback.
    /// The C code MUST NOT store or use this pointer after the callback returns.
    pub fn call_progress(&self, progress: f64, message: &str) {
        if let Some(callback) = self.on_progress {
            let c_message = CString::new(message).unwrap_or_else(|_| CString::new("").unwrap());
            callback(progress, c_message.as_ptr(), self.user_data);
        }
    }

    /// Call the completion callback with success status and optional error message.
    ///
    /// # Safety
    /// The string pointer passed to the callback is only valid for the duration of the callback.
    /// The C code MUST NOT store or use this pointer after the callback returns.
    pub fn call_completion(&self, success: bool, error: Option<&str>) {
        if let Some(callback) = self.on_completion {
            let c_error = error
                .map(|e| CString::new(e).unwrap_or_else(|_| CString::new("").unwrap()))
                .unwrap_or_else(|| CString::new("").unwrap());
            callback(success, c_error.as_ptr(), self.user_data);
        }
    }

    /// Call the data callback with raw byte data.
    ///
    /// # Safety
    /// The data pointer passed to the callback is only valid for the duration of the callback.
    /// The C code MUST NOT store or use this pointer after the callback returns.
    pub fn call_data(&self, data: &[u8]) {
        if let Some(callback) = self.on_data {
            callback(data.as_ptr() as *const c_void, data.len(), self.user_data);
        }
    }
}

pub type BlockCallback =
    Option<extern "C" fn(height: u32, hash: *const [u8; 32], user_data: *mut c_void)>;
pub type TransactionCallback = Option<
    extern "C" fn(
        txid: *const [u8; 32],
        confirmed: bool,
        amount: i64,
        addresses: *const c_char,
        block_height: u32,
        user_data: *mut c_void,
    ),
>;
pub type BalanceCallback =
    Option<extern "C" fn(confirmed: u64, unconfirmed: u64, user_data: *mut c_void)>;
pub type MempoolTransactionCallback = Option<
    extern "C" fn(
        txid: *const [u8; 32],
        amount: i64,
        addresses: *const c_char,
        is_instant_send: bool,
        user_data: *mut c_void,
    ),
>;
pub type MempoolConfirmedCallback = Option<
    extern "C" fn(
        txid: *const [u8; 32],
        block_height: u32,
        block_hash: *const [u8; 32],
        user_data: *mut c_void,
    ),
>;
pub type MempoolRemovedCallback =
    Option<extern "C" fn(txid: *const [u8; 32], reason: u8, user_data: *mut c_void)>;
pub type CompactFilterMatchedCallback = Option<
    extern "C" fn(
        block_hash: *const [u8; 32],
        matched_scripts: *const c_char,
        wallet_id: *const c_char,
        user_data: *mut c_void,
    ),
>;
pub type WalletTransactionCallback = Option<
    extern "C" fn(
        wallet_id: *const c_char,
        account_index: u32,
        txid: *const [u8; 32],
        confirmed: bool,
        amount: i64,
        addresses: *const c_char,
        block_height: u32,
        is_ours: bool,
        user_data: *mut c_void,
    ),
>;

#[repr(C)]
pub struct FFIEventCallbacks {
    pub on_block: BlockCallback,
    pub on_transaction: TransactionCallback,
    pub on_balance_update: BalanceCallback,
    pub on_mempool_transaction_added: MempoolTransactionCallback,
    pub on_mempool_transaction_confirmed: MempoolConfirmedCallback,
    pub on_mempool_transaction_removed: MempoolRemovedCallback,
    pub on_compact_filter_matched: CompactFilterMatchedCallback,
    pub on_wallet_transaction: WalletTransactionCallback,
    pub user_data: *mut c_void,
}

// SAFETY: FFIEventCallbacks is safe to send between threads because:
// 1. All callback function pointers are extern "C" functions which have no captured state
// 2. The user_data raw pointer is treated as opaque data that must be managed by the caller
// 3. The caller is responsible for ensuring that user_data points to thread-safe memory
// 4. All callback invocations happen through the FFI boundary where the caller manages synchronization
unsafe impl Send for FFIEventCallbacks {}

// SAFETY: FFIEventCallbacks is safe to share between threads because:
// 1. The struct is immutable after construction (all fields are read-only from Rust's perspective)
// 2. Function pointers themselves are inherently thread-safe as they don't contain mutable state
// 3. The user_data pointer is never dereferenced by Rust code, only passed through to callbacks
// 4. Thread safety of the data pointed to by user_data is the responsibility of the FFI caller
unsafe impl Sync for FFIEventCallbacks {}

impl Default for FFIEventCallbacks {
    fn default() -> Self {
        FFIEventCallbacks {
            on_block: None,
            on_transaction: None,
            on_balance_update: None,
            on_mempool_transaction_added: None,
            on_mempool_transaction_confirmed: None,
            on_mempool_transaction_removed: None,
            on_compact_filter_matched: None,
            on_wallet_transaction: None,
            user_data: std::ptr::null_mut(),
        }
    }
}

impl FFIEventCallbacks {
    pub fn call_block(&self, height: u32, hash: &dashcore::BlockHash) {
        if let Some(callback) = self.on_block {
            tracing::info!("🎯 Calling block callback: height={}, hash={}", height, hash);
            let hash_bytes = hash.as_byte_array();
            callback(height, hash_bytes.as_ptr() as *const [u8; 32], self.user_data);
            tracing::info!("✅ Block callback completed");
        } else {
            tracing::warn!("⚠️ Block callback not set");
        }
    }

    pub fn call_transaction(
        &self,
        txid: &dashcore::Txid,
        confirmed: bool,
        amount: i64,
        addresses: &[String],
        block_height: Option<u32>,
    ) {
        if let Some(callback) = self.on_transaction {
            tracing::info!(
                "🎯 Calling transaction callback: txid={}, confirmed={}, amount={}, addresses={:?}",
                txid,
                confirmed,
                amount,
                addresses
            );
            let txid_bytes = txid.as_byte_array();
            let addresses_str = addresses.join(",");
            let c_addresses =
                CString::new(addresses_str).unwrap_or_else(|_| CString::new("").unwrap());
            callback(
                txid_bytes.as_ptr() as *const [u8; 32],
                confirmed,
                amount,
                c_addresses.as_ptr(),
                block_height.unwrap_or(0),
                self.user_data,
            );
            tracing::info!("✅ Transaction callback completed");
        } else {
            tracing::warn!("⚠️ Transaction callback not set");
        }
    }

    pub fn call_balance_update(&self, confirmed: u64, unconfirmed: u64) {
        if let Some(callback) = self.on_balance_update {
            tracing::info!(
                "🎯 Calling balance update callback: confirmed={}, unconfirmed={}",
                confirmed,
                unconfirmed
            );
            callback(confirmed, unconfirmed, self.user_data);
            tracing::info!("✅ Balance update callback completed");
        } else {
            tracing::warn!("⚠️ Balance update callback not set");
        }
    }

    // Mempool callbacks use debug level for "not set" messages as they are optional and frequently unused
    pub fn call_mempool_transaction_added(
        &self,
        txid: &dashcore::Txid,
        amount: i64,
        addresses: &[String],
        is_instant_send: bool,
    ) {
        if let Some(callback) = self.on_mempool_transaction_added {
            tracing::info!("🎯 Calling mempool transaction added callback: txid={}, amount={}, is_instant_send={}",
                         txid, amount, is_instant_send);
            let txid_bytes = txid.as_byte_array();
            let addresses_str = addresses.join(",");
            let c_addresses =
                CString::new(addresses_str).unwrap_or_else(|_| CString::new("").unwrap());
            callback(
                txid_bytes.as_ptr() as *const [u8; 32],
                amount,
                c_addresses.as_ptr(),
                is_instant_send,
                self.user_data,
            );
            tracing::info!("✅ Mempool transaction added callback completed");
        } else {
            tracing::debug!("Mempool transaction added callback not set");
        }
    }

    pub fn call_mempool_transaction_confirmed(
        &self,
        txid: &dashcore::Txid,
        block_height: u32,
        block_hash: &dashcore::BlockHash,
    ) {
        if let Some(callback) = self.on_mempool_transaction_confirmed {
            tracing::info!(
                "🎯 Calling mempool transaction confirmed callback: txid={}, height={}, hash={}",
                txid,
                block_height,
                block_hash
            );
            let txid_bytes = txid.as_byte_array();
            let hash_bytes = block_hash.as_byte_array();
            callback(
                txid_bytes.as_ptr() as *const [u8; 32],
                block_height,
                hash_bytes.as_ptr() as *const [u8; 32],
                self.user_data,
            );
            tracing::info!("✅ Mempool transaction confirmed callback completed");
        } else {
            tracing::debug!("Mempool transaction confirmed callback not set");
        }
    }

    pub fn call_mempool_transaction_removed(&self, txid: &dashcore::Txid, reason: u8) {
        if let Some(callback) = self.on_mempool_transaction_removed {
            tracing::info!(
                "🎯 Calling mempool transaction removed callback: txid={}, reason={}",
                txid,
                reason
            );
            let txid_bytes = txid.as_byte_array();
            callback(txid_bytes.as_ptr() as *const [u8; 32], reason, self.user_data);
            tracing::info!("✅ Mempool transaction removed callback completed");
        } else {
            tracing::debug!("Mempool transaction removed callback not set");
        }
    }

    pub fn call_compact_filter_matched(
        &self,
        block_hash: &dashcore::BlockHash,
        matched_scripts: &[String],
        wallet_id: &str,
    ) {
        if let Some(callback) = self.on_compact_filter_matched {
            tracing::info!(
                "🎯 Calling compact filter matched callback: block={}, scripts={:?}, wallet={}",
                block_hash,
                matched_scripts,
                wallet_id
            );
            let hash_bytes = block_hash.as_byte_array();
            let scripts_str = matched_scripts.join(",");
            let c_scripts = CString::new(scripts_str).unwrap_or_else(|_| CString::new("").unwrap());
            let c_wallet_id = CString::new(wallet_id).unwrap_or_else(|_| CString::new("").unwrap());

            callback(
                hash_bytes.as_ptr() as *const [u8; 32],
                c_scripts.as_ptr(),
                c_wallet_id.as_ptr(),
                self.user_data,
            );
            tracing::info!("✅ Compact filter matched callback completed");
        } else {
            tracing::debug!("Compact filter matched callback not set");
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn call_wallet_transaction(
        &self,
        wallet_id: &str,
        account_index: u32,
        txid: &dashcore::Txid,
        confirmed: bool,
        amount: i64,
        addresses: &[String],
        block_height: u32,
        is_ours: bool,
    ) {
        if let Some(callback) = self.on_wallet_transaction {
            tracing::info!(
                "🎯 Calling wallet transaction callback: wallet={}, account={}, txid={}, confirmed={}, amount={}, is_ours={}",
                wallet_id,
                account_index,
                txid,
                confirmed,
                amount,
                is_ours
            );
            let txid_bytes = txid.as_byte_array();
            let addresses_str = addresses.join(",");
            let c_addresses =
                CString::new(addresses_str).unwrap_or_else(|_| CString::new("").unwrap());
            let c_wallet_id = CString::new(wallet_id).unwrap_or_else(|_| CString::new("").unwrap());

            callback(
                c_wallet_id.as_ptr(),
                account_index,
                txid_bytes.as_ptr() as *const [u8; 32],
                confirmed,
                amount,
                c_addresses.as_ptr(),
                block_height,
                is_ours,
                self.user_data,
            );
            tracing::info!("✅ Wallet transaction callback completed");
        } else {
            tracing::debug!("Wallet transaction callback not set");
        }
    }
}
