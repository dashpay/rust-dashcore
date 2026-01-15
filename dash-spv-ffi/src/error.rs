use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::Mutex;

// Global error storage protected by mutex for thread safety
static LAST_ERROR: Mutex<Option<CString>> = Mutex::new(None);

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FFIErrorCode {
    Success = 0,
    NullPointer = 1,
    InvalidArgument = 2,
    NetworkError = 3,
    StorageError = 4,
    ValidationError = 5,
    SyncError = 6,
    WalletError = 7,
    ConfigError = 8,
    RuntimeError = 9,
    NotImplemented = 10,
    Unknown = 99,
}

pub fn set_last_error(err: &str) {
    let c_err = CString::new(err).unwrap_or_else(|_| CString::new("Unknown error").unwrap());
    if let Ok(mut guard) = LAST_ERROR.lock() {
        *guard = Some(c_err);
    }
}

pub fn clear_last_error() {
    if let Ok(mut guard) = LAST_ERROR.lock() {
        *guard = None;
    }
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_get_last_error() -> *const c_char {
    match LAST_ERROR.lock() {
        Ok(guard) => guard.as_ref().map(|err| err.as_ptr()).unwrap_or(std::ptr::null()),
        Err(_) => std::ptr::null(),
    }
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_clear_error() {
    clear_last_error();
}

impl From<dash_spv::Error> for FFIErrorCode {
    fn from(err: dash_spv::Error) -> Self {
        match err {
            dash_spv::Error::ChannelFailure(_, _) => FFIErrorCode::RuntimeError,
            dash_spv::Error::Network(_) => FFIErrorCode::NetworkError,
            dash_spv::Error::Storage(_) => FFIErrorCode::StorageError,
            dash_spv::Error::Validation(_) => FFIErrorCode::ValidationError,
            dash_spv::Error::Sync(_) => FFIErrorCode::SyncError,
            dash_spv::Error::Config(_) => FFIErrorCode::ConfigError,
            dash_spv::Error::Logging(_) => FFIErrorCode::RuntimeError,
            dash_spv::Error::QuorumLookupError(_) => FFIErrorCode::ValidationError,
            dash_spv::Error::General(_) => FFIErrorCode::Unknown,
            dash_spv::Error::UninitializedClient => FFIErrorCode::RuntimeError,
        }
    }
}

pub fn handle_error<T, E: std::fmt::Display>(result: Result<T, E>) -> Option<T> {
    match result {
        Ok(value) => {
            clear_last_error();
            Some(value)
        }
        Err(e) => {
            set_last_error(&e.to_string());
            None
        }
    }
}

pub fn handle_error_code<E: std::fmt::Display + Into<FFIErrorCode>>(
    result: Result<(), E>,
) -> FFIErrorCode {
    match result {
        Ok(()) => {
            clear_last_error();
            FFIErrorCode::Success
        }
        Err(e) => {
            set_last_error(&e.to_string());
            e.into()
        }
    }
}

#[macro_export]
macro_rules! ffi_result {
    ($expr:expr) => {
        match $expr {
            Ok(val) => {
                $crate::error::clear_last_error();
                val
            }
            Err(e) => {
                $crate::error::set_last_error(&e.to_string());
                return $crate::error::FFIErrorCode::from(e) as i32;
            }
        }
    };
}

#[macro_export]
macro_rules! null_check {
    ($ptr:expr) => {
        if $ptr.is_null() {
            $crate::error::set_last_error("Null pointer provided");
            return $crate::error::FFIErrorCode::NullPointer as i32;
        }
    };
    ($ptr:expr, $ret:expr) => {
        if $ptr.is_null() {
            $crate::error::set_last_error("Null pointer provided");
            return $ret;
        }
    };
}
