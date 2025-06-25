use dash_spv::error::SpvError;
use std::cell::RefCell;
use std::ffi::CString;
use std::os::raw::c_char;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = RefCell::new(None);
}

#[repr(C)]
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
    Unknown = 99,
}

pub fn set_last_error(err: &str) {
    let c_err = CString::new(err).unwrap_or_else(|_| CString::new("Unknown error").unwrap());
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(c_err);
    });
}

pub fn clear_last_error() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_get_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().as_ref().map(|err| err.as_ptr()).unwrap_or(std::ptr::null()))
}

#[no_mangle]
pub extern "C" fn dash_spv_ffi_clear_error() {
    clear_last_error();
}

impl From<SpvError> for FFIErrorCode {
    fn from(err: SpvError) -> Self {
        match err {
            SpvError::Network(_) => FFIErrorCode::NetworkError,
            SpvError::Storage(_) => FFIErrorCode::StorageError,
            SpvError::Validation(_) => FFIErrorCode::ValidationError,
            SpvError::Sync(_) => FFIErrorCode::SyncError,
            SpvError::Io(_) => FFIErrorCode::RuntimeError,
            SpvError::Config(_) => FFIErrorCode::ConfigError,
            SpvError::General(_) => FFIErrorCode::Unknown,
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
