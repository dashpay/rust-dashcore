use std::ffi::CString;
use std::os::raw::{c_char, c_void};

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
    Option<extern "C" fn(height: u32, hash: *const c_char, user_data: *mut c_void)>;
pub type TransactionCallback = Option<
    extern "C" fn(
        txid: *const c_char,
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
        txid: *const c_char,
        amount: i64,
        addresses: *const c_char,
        is_instant_send: bool,
        user_data: *mut c_void,
    ),
>;
pub type MempoolConfirmedCallback = Option<
    extern "C" fn(
        txid: *const c_char,
        block_height: u32,
        block_hash: *const c_char,
        user_data: *mut c_void,
    ),
>;
pub type MempoolRemovedCallback =
    Option<extern "C" fn(txid: *const c_char, reason: u8, user_data: *mut c_void)>;

#[repr(C)]
pub struct FFIEventCallbacks {
    pub on_block: BlockCallback,
    pub on_transaction: TransactionCallback,
    pub on_balance_update: BalanceCallback,
    pub on_mempool_transaction_added: MempoolTransactionCallback,
    pub on_mempool_transaction_confirmed: MempoolConfirmedCallback,
    pub on_mempool_transaction_removed: MempoolRemovedCallback,
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
            user_data: std::ptr::null_mut(),
        }
    }
}

impl FFIEventCallbacks {
    pub fn call_block(&self, height: u32, hash: &str) {
        if let Some(callback) = self.on_block {
            tracing::info!("🎯 Calling block callback: height={}, hash={}", height, hash);
            let c_hash = CString::new(hash).unwrap_or_else(|_| CString::new("").unwrap());
            callback(height, c_hash.as_ptr(), self.user_data);
            tracing::info!("✅ Block callback completed");
        } else {
            tracing::warn!("⚠️ Block callback not set");
        }
    }

    pub fn call_transaction(
        &self,
        txid: &str,
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
            let c_txid = CString::new(txid).unwrap_or_else(|_| CString::new("").unwrap());
            let addresses_str = addresses.join(",");
            let c_addresses =
                CString::new(addresses_str).unwrap_or_else(|_| CString::new("").unwrap());
            callback(
                c_txid.as_ptr(),
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
        txid: &str,
        amount: i64,
        addresses: &[String],
        is_instant_send: bool,
    ) {
        if let Some(callback) = self.on_mempool_transaction_added {
            tracing::info!("🎯 Calling mempool transaction added callback: txid={}, amount={}, is_instant_send={}", 
                         txid, amount, is_instant_send);
            let c_txid = CString::new(txid).unwrap_or_else(|_| CString::new("").unwrap());
            let addresses_str = addresses.join(",");
            let c_addresses =
                CString::new(addresses_str).unwrap_or_else(|_| CString::new("").unwrap());
            callback(
                c_txid.as_ptr(),
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
        txid: &str,
        block_height: u32,
        block_hash: &str,
    ) {
        if let Some(callback) = self.on_mempool_transaction_confirmed {
            tracing::info!(
                "🎯 Calling mempool transaction confirmed callback: txid={}, height={}, hash={}",
                txid,
                block_height,
                block_hash
            );
            let c_txid = CString::new(txid).unwrap_or_else(|_| CString::new("").unwrap());
            let c_hash = CString::new(block_hash).unwrap_or_else(|_| CString::new("").unwrap());
            callback(c_txid.as_ptr(), block_height, c_hash.as_ptr(), self.user_data);
            tracing::info!("✅ Mempool transaction confirmed callback completed");
        } else {
            tracing::debug!("Mempool transaction confirmed callback not set");
        }
    }

    pub fn call_mempool_transaction_removed(&self, txid: &str, reason: u8) {
        if let Some(callback) = self.on_mempool_transaction_removed {
            tracing::info!(
                "🎯 Calling mempool transaction removed callback: txid={}, reason={}",
                txid,
                reason
            );
            let c_txid = CString::new(txid).unwrap_or_else(|_| CString::new("").unwrap());
            callback(c_txid.as_ptr(), reason, self.user_data);
            tracing::info!("✅ Mempool transaction removed callback completed");
        } else {
            tracing::debug!("Mempool transaction removed callback not set");
        }
    }
}
