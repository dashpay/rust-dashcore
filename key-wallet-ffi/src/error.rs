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
    InternalError = 12,
}

/// FFI Error structure
#[repr(C)]
#[derive(Debug)]
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

    /// Set error on a mutable pointer if it's not null.
    /// Frees any previous error message before setting the new one.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn set_error(error_ptr: *mut FFIError, code: FFIErrorCode, msg: String) {
        if !error_ptr.is_null() {
            unsafe {
                // Free previous message if present
                let prev = &mut *error_ptr;
                if !prev.message.is_null() {
                    let _ = CString::from_raw(prev.message);
                }
                *error_ptr = Self::error(code, msg);
            }
        }
    }

    /// Set success on a mutable pointer if it's not null.
    /// Frees any previous error message before setting success.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn set_success(error_ptr: *mut FFIError) {
        if !error_ptr.is_null() {
            unsafe {
                // Free previous message if present
                let prev = &mut *error_ptr;
                if !prev.message.is_null() {
                    let _ = CString::from_raw(prev.message);
                }
                *error_ptr = Self::success();
            }
        }
    }

    /// Free the error message if present.
    /// Use this in tests to prevent memory leaks.
    ///
    /// # Safety
    ///
    /// The message pointer must have been allocated by this library.
    pub unsafe fn free_message(&mut self) {
        if !self.message.is_null() {
            let _ = CString::from_raw(self.message);
            self.message = ptr::null_mut();
        }
    }
}

/// Free an error message
///
/// # Safety
///
/// - `message` must be a valid pointer to a C string that was allocated by this library
/// - The pointer must not be used after calling this function
/// - This function must only be called once per allocation
#[no_mangle]
pub unsafe extern "C" fn error_message_free(message: *mut c_char) {
    if !message.is_null() {
        let _ = CString::from_raw(message);
    }
}

/// Helper macro to convert any error that implements `Into<FFIError>` and set it on the error pointer.
/// Frees any previous error message before setting the new one.
#[macro_export]
macro_rules! ffi_error_set {
    ($error_ptr:expr, $err:expr) => {{
        let ffi_error: $crate::error::FFIError = $err.into();
        if !$error_ptr.is_null() {
            unsafe {
                // Free previous message if present
                let prev = &mut *$error_ptr;
                if !prev.message.is_null() {
                    let _ = std::ffi::CString::from_raw(prev.message);
                }
                *$error_ptr = ffi_error;
            }
        }
    }};
}

/// Helper macro to handle Result types in FFI functions
#[macro_export]
macro_rules! ffi_result {
    ($error_ptr:expr, $result:expr) => {
        match $result {
            Ok(val) => {
                $crate::error::FFIError::set_success($error_ptr);
                val
            }
            Err(err) => {
                ffi_error_set!($error_ptr, err);
                return std::ptr::null_mut();
            }
        }
    };
    ($error_ptr:expr, $result:expr, $default:expr) => {
        match $result {
            Ok(val) => {
                $crate::error::FFIError::set_success($error_ptr);
                val
            }
            Err(err) => {
                ffi_error_set!($error_ptr, err);
                return $default;
            }
        }
    };
}

/// Convert key_wallet::Error to FFIError
impl From<key_wallet::Error> for FFIError {
    fn from(err: key_wallet::Error) -> Self {
        use key_wallet::Error;

        let (code, msg) = match &err {
            Error::InvalidDerivationPath(_) => {
                (FFIErrorCode::InvalidDerivationPath, err.to_string())
            }
            Error::InvalidMnemonic(_) => (FFIErrorCode::InvalidMnemonic, err.to_string()),
            Error::InvalidNetwork => (FFIErrorCode::InvalidNetwork, "Invalid network".to_string()),
            Error::InvalidAddress(_) => (FFIErrorCode::InvalidAddress, err.to_string()),
            Error::InvalidParameter(_) => (FFIErrorCode::InvalidInput, err.to_string()),
            Error::Serialization(_) => (FFIErrorCode::SerializationError, err.to_string()),
            Error::WatchOnly => (
                FFIErrorCode::InvalidState,
                "Operation not supported on watch-only wallet".to_string(),
            ),
            Error::CoinJoinNotEnabled => {
                (FFIErrorCode::InvalidState, "CoinJoin not enabled".to_string())
            }
            Error::KeyError(_) | Error::Bip32(_) | Error::Secp256k1(_) | Error::Base58 => {
                (FFIErrorCode::WalletError, err.to_string())
            }
            Error::NoKeySource => {
                (FFIErrorCode::InvalidState, "No key source available".to_string())
            }
            #[allow(unreachable_patterns)]
            _ => (FFIErrorCode::WalletError, err.to_string()),
        };

        FFIError::error(code, msg)
    }
}

/// Convert key_wallet_manager::WalletError to FFIError
impl From<key_wallet_manager::wallet_manager::WalletError> for FFIError {
    fn from(err: key_wallet_manager::wallet_manager::WalletError) -> Self {
        use key_wallet_manager::wallet_manager::WalletError;

        let (code, msg) = match &err {
            WalletError::WalletCreation(msg) => {
                (FFIErrorCode::WalletError, format!("Wallet creation failed: {}", msg))
            }
            WalletError::WalletNotFound(_) => (FFIErrorCode::NotFound, err.to_string()),
            WalletError::WalletExists(_) => (FFIErrorCode::InvalidState, err.to_string()),
            WalletError::InvalidMnemonic(msg) => {
                (FFIErrorCode::InvalidMnemonic, format!("Invalid mnemonic: {}", msg))
            }
            WalletError::AccountCreation(msg) => {
                (FFIErrorCode::WalletError, format!("Account creation failed: {}", msg))
            }
            WalletError::AccountNotFound(_) => (FFIErrorCode::NotFound, err.to_string()),
            WalletError::AddressGeneration(msg) => {
                (FFIErrorCode::InvalidAddress, format!("Address generation failed: {}", msg))
            }
            WalletError::InvalidNetwork => {
                (FFIErrorCode::InvalidNetwork, "Invalid network".to_string())
            }
            WalletError::InvalidParameter(msg) => {
                (FFIErrorCode::InvalidInput, format!("Invalid parameter: {}", msg))
            }
            WalletError::TransactionBuild(msg) => {
                (FFIErrorCode::InvalidTransaction, format!("Transaction build failed: {}", msg))
            }
            WalletError::InsufficientFunds => {
                (FFIErrorCode::InvalidState, "Insufficient funds".to_string())
            }
        };

        FFIError::error(code, msg)
    }
}
