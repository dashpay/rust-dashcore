//! Error handling for FFI interface

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

/// FFI Error code
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FFIErrorCode {
    Success = 0,
    InvalidInput = 1,
    AllocationFailed = 2,
    InvalidMnemonic = 3,
    InvalidDerivationPath = 4,
    InvalidNetwork = 5,
    InvalidAddress = 6,
    InvalidTransaction = 7,
    WalletError = 8,
    SerializationError = 9,
    NotFound = 10,
    InvalidState = 11,
}

/// FFI Error structure
#[repr(C)]
pub struct FFIError {
    pub code: FFIErrorCode,
    pub message: *mut c_char,
}

impl FFIError {
    /// Create a success result
    pub fn success() -> Self {
        FFIError {
            code: FFIErrorCode::Success,
            message: ptr::null_mut(),
        }
    }

    /// Create an error with code and message
    pub fn error(code: FFIErrorCode, msg: String) -> Self {
        FFIError {
            code,
            message: CString::new(msg).unwrap_or_default().into_raw(),
        }
    }

    /// Set error on a mutable pointer if it's not null
    pub fn set_error(error_ptr: *mut FFIError, code: FFIErrorCode, msg: String) {
        if !error_ptr.is_null() {
            unsafe {
                *error_ptr = Self::error(code, msg);
            }
        }
    }

    /// Set success on a mutable pointer if it's not null
    pub fn set_success(error_ptr: *mut FFIError) {
        if !error_ptr.is_null() {
            unsafe {
                *error_ptr = Self::success();
            }
        }
    }
}

/// Free an error message
#[no_mangle]
pub extern "C" fn error_message_free(message: *mut c_char) {
    if !message.is_null() {
        unsafe {
            let _ = CString::from_raw(message);
        }
    }
}

/// Convert key_wallet::Error to FFIError
impl From<key_wallet::Error> for FFIError {
    fn from(err: key_wallet::Error) -> Self {
        use key_wallet::Error;

        let (code, msg) = match err {
            Error::InvalidDerivationPath(_) => {
                (FFIErrorCode::InvalidDerivationPath, err.to_string())
            }
            Error::InvalidMnemonic(_) => (FFIErrorCode::InvalidMnemonic, err.to_string()),
            Error::InvalidNetwork => (FFIErrorCode::InvalidNetwork, "Invalid network".to_string()),
            Error::InvalidAddress(_) => (FFIErrorCode::InvalidAddress, err.to_string()),
            _ => (FFIErrorCode::WalletError, err.to_string()),
        };

        FFIError::error(code, msg)
    }
}
