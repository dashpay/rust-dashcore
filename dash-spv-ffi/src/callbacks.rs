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

pub type BlockCallback = extern "C" fn(height: u32, hash: *const c_char, user_data: *mut c_void);
pub type TransactionCallback =
    extern "C" fn(txid: *const c_char, confirmed: bool, user_data: *mut c_void);
pub type BalanceCallback = extern "C" fn(confirmed: u64, unconfirmed: u64, user_data: *mut c_void);

#[repr(C)]
pub struct FFIEventCallbacks {
    pub on_block: Option<BlockCallback>,
    pub on_transaction: Option<TransactionCallback>,
    pub on_balance_update: Option<BalanceCallback>,
    pub user_data: *mut c_void,
}

impl Default for FFIEventCallbacks {
    fn default() -> Self {
        FFIEventCallbacks {
            on_block: None,
            on_transaction: None,
            on_balance_update: None,
            user_data: std::ptr::null_mut(),
        }
    }
}

impl FFIEventCallbacks {
    pub fn call_block(&self, height: u32, hash: &str) {
        if let Some(callback) = self.on_block {
            let c_hash = CString::new(hash).unwrap_or_else(|_| CString::new("").unwrap());
            callback(height, c_hash.as_ptr(), self.user_data);
        }
    }

    pub fn call_transaction(&self, txid: &str, confirmed: bool) {
        if let Some(callback) = self.on_transaction {
            let c_txid = CString::new(txid).unwrap_or_else(|_| CString::new("").unwrap());
            callback(c_txid.as_ptr(), confirmed, self.user_data);
        }
    }

    pub fn call_balance_update(&self, confirmed: u64, unconfirmed: u64) {
        if let Some(callback) = self.on_balance_update {
            callback(confirmed, unconfirmed, self.user_data);
        }
    }
}
