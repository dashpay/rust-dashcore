//! Error handling for FFI interface

use std::ffi::CString;
use std::os::raw::c_char;
use std::str::Utf8Error;
use std::{ffi, ptr};

/// Dereference a raw `*const` pointer as `&T`, or early-return after writing
/// `InvalidInput` into `*error`. The two-arg form returns `Default::default()`.
#[macro_export]
macro_rules! deref_ptr {
    ($ptr:expr, $error:expr, $return_value:expr) => {{
        (*$error).clean();

        if $ptr.is_null() {
            return {
                (*$error).set(
                    $crate::error::FFIErrorCode::InvalidInput,
                    &format!("{} ptr is null", stringify!($ptr)),
                );
                $return_value
            };
        }
        unsafe { &*$ptr }
    }};

    ($ptr:expr, $error:expr) => {{
        (*$error).clean();

        if $ptr.is_null() {
            return {
                (*$error).set(
                    $crate::error::FFIErrorCode::InvalidInput,
                    &format!("{} ptr is null", stringify!($ptr)),
                );
                Default::default()
            };
        }
        unsafe { &*$ptr }
    }};
}

/// Mutable variant of [`deref_ptr!`]: yields `&mut T` on success, otherwise
/// sets `*error` to `InvalidInput` and early-returns.
#[macro_export]
macro_rules! deref_ptr_mut {
    ($ptr:expr, $error:expr, $return_value:expr) => {{
        (*$error).clean();

        if $ptr.is_null() {
            return {
                (*$error).set(
                    $crate::error::FFIErrorCode::InvalidInput,
                    &format!("{} ptr is null", stringify!($ptr)),
                );
                $return_value
            };
        }
        unsafe { &mut *$ptr }
    }};

    ($ptr:expr, $error:expr) => {{
        (*$error).clean();

        if $ptr.is_null() {
            return {
                (*$error).set(
                    $crate::error::FFIErrorCode::InvalidInput,
                    &format!("{} ptr is null", stringify!($ptr)),
                );
                Default::default()
            };
        }
        unsafe { &mut *$ptr }
    }};
}

/// Null-check a raw pointer without dereferencing it. On null, sets
/// `*error` to `InvalidInput` and early-returns. Use this for out-parameters
/// where the pointer may point to uninitialized memory and forming a Rust
/// reference would be unsound.
#[macro_export]
macro_rules! check_ptr {
    ($ptr:expr, $error:expr, $return_value:expr) => {{
        (*$error).clean();

        if $ptr.is_null() {
            (*$error).set(
                $crate::error::FFIErrorCode::InvalidInput,
                &format!("{} ptr is null", stringify!($ptr)),
            );
            return $return_value;
        }
    }};

    ($ptr:expr, $error:expr) => {{
        (*$error).clean();

        if $ptr.is_null() {
            (*$error).set(
                $crate::error::FFIErrorCode::InvalidInput,
                &format!("{} ptr is null", stringify!($ptr)),
            );
            return Default::default();
        }
    }};
}

/// Unwrap a `Result`/`Option` via [`FfiErrMapper`], writing any error into
/// `*error` and early-returning. The two-arg form returns `Default::default()`.
#[macro_export]
macro_rules! unwrap_or_return {
    ($expr:expr, $error:expr, $return_value:expr) => {{
        match $crate::error::FfiErrMapper::map_to_ffi_err($expr, &mut *$error) {
            Some(v) => v,
            None => return $return_value,
        }
    }};

    ($expr:expr, $error:expr) => {{
        match $crate::error::FfiErrMapper::map_to_ffi_err($expr, &mut *$error) {
            Some(v) => v,
            None => return Default::default(),
        }
    }};
}

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
    NulByteError = 13,
}

/// FFI Error structure
#[repr(C)]
#[derive(Debug)]
pub struct FFIError {
    pub code: FFIErrorCode,
    pub message: *mut c_char,
}

impl FFIError {
    /// # Safety
    ///
    /// This will call FFIError::clean, to ensure message is deallocated
    /// before poinitng to a new string. FFIError::clean Safety consideation apply here.
    pub unsafe fn set(&mut self, code: FFIErrorCode, msg: &str) {
        self.clean();

        self.message = CString::new(msg).unwrap_or_default().into_raw();
        self.code = code;
    }

    /// Returns the error to the default state, deallocating the message if it exists
    ///
    /// # Safety
    ///
    /// The message pointer must have been allocated by this library.
    pub unsafe fn clean(&mut self) {
        self.code = FFIErrorCode::Success;

        if !self.message.is_null() {
            let _ = unsafe { CString::from_raw(self.message) };
            self.message = ptr::null_mut();
        }
    }

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

impl Default for FFIError {
    fn default() -> Self {
        FFIError {
            code: FFIErrorCode::Success,
            message: ptr::null_mut(),
        }
    }
}

pub trait FfiErrMapper<T>: Sized {
    /// Map `self` into an `FFIError` via `FfiErrMapperImpl`, clearing any prior
    /// error message stored in `error` first.
    ///
    /// # Safety
    ///
    /// If `error` currently holds a message pointer, it must have been allocated
    /// by this library; it will be freed before being overwritten.
    unsafe fn map_to_ffi_err(self, error: &mut FFIError) -> Option<T> {
        error.clean();

        self.map_to_ffi_err_impl(error)
    }

    fn map_to_ffi_err_impl(self, err: &mut FFIError) -> Option<T>;
}

impl<T, E> FfiErrMapper<T> for Result<T, E>
where
    E: Into<FFIError>,
{
    fn map_to_ffi_err_impl(self, err: &mut FFIError) -> Option<T> {
        match self {
            Ok(item) => Some(item),
            Err(e) => {
                *err = e.into();
                None
            }
        }
    }
}

impl<T> FfiErrMapper<T> for Option<T> {
    fn map_to_ffi_err_impl(self, err: &mut FFIError) -> Option<T> {
        if self.is_none() {
            err.code = FFIErrorCode::NotFound;
            err.message = CString::new("Item not found").unwrap().into_raw();
        }

        self
    }
}

impl From<key_wallet::Error> for FFIError {
    fn from(value: key_wallet::Error) -> Self {
        use key_wallet::Error;

        let code = match &value {
            Error::InvalidDerivationPath(_) => FFIErrorCode::InvalidDerivationPath,
            Error::InvalidMnemonic(_) => FFIErrorCode::InvalidMnemonic,
            Error::InvalidParameter(_) => FFIErrorCode::InvalidInput,
            Error::InvalidNetwork => FFIErrorCode::InvalidNetwork,
            Error::InvalidAddress(_) => FFIErrorCode::InvalidAddress,
            Error::Serialization(_) => FFIErrorCode::SerializationError,
            Error::WatchOnly | Error::CoinJoinNotEnabled | Error::NoKeySource => {
                FFIErrorCode::InvalidState
            }
            Error::Bip32(_)
            | Error::Slip10(_)
            | Error::BLS(_)
            | Error::Secp256k1(_)
            | Error::Base58
            | Error::KeyError(_) => FFIErrorCode::WalletError,
        };

        FFIError {
            code,
            message: CString::new(value.to_string())
                .unwrap_or(
                    CString::new("Rust key_wallet::Error message contains null byte").unwrap(),
                )
                .into_raw(),
        }
    }
}

impl From<key_wallet::bip32::Error> for FFIError {
    fn from(value: key_wallet::bip32::Error) -> Self {
        FFIError {
            code: FFIErrorCode::InvalidInput,
            message: CString::new(value.to_string())
                .unwrap_or(
                    CString::new("Rust key_wallet::bip32::Error message contains null byte")
                        .unwrap(),
                )
                .into_raw(),
        }
    }
}

impl From<key_wallet_manager::WalletError> for FFIError {
    fn from(value: key_wallet_manager::WalletError) -> Self {
        use key_wallet_manager::WalletError;

        let code = match &value {
            WalletError::WalletCreation(_) => FFIErrorCode::WalletError,
            WalletError::WalletNotFound(_) => FFIErrorCode::NotFound,
            WalletError::WalletExists(_) => FFIErrorCode::InvalidState,
            WalletError::InvalidMnemonic(_) => FFIErrorCode::InvalidMnemonic,
            WalletError::AccountCreation(_) => FFIErrorCode::WalletError,
            WalletError::AccountNotFound(_) => FFIErrorCode::NotFound,
            WalletError::AddressGeneration(_) => FFIErrorCode::InvalidAddress,
            WalletError::InvalidNetwork => FFIErrorCode::InvalidNetwork,
            WalletError::InvalidParameter(_) => FFIErrorCode::InvalidInput,
            WalletError::TransactionBuild(_) => FFIErrorCode::InvalidTransaction,
            WalletError::InsufficientFunds => FFIErrorCode::InvalidState,
            WalletError::ApplyChangeSet(_) => FFIErrorCode::WalletError,
            WalletError::Persistence(_) => FFIErrorCode::WalletError,
        };

        FFIError {
            code,
            message: CString::new(value.to_string())
                .unwrap_or(
                    CString::new("Rust key_wallet_manager::WalletError message contains null byte")
                        .unwrap(),
                )
                .into_raw(),
        }
    }
}

impl From<ffi::NulError> for FFIError {
    fn from(value: ffi::NulError) -> Self {
        FFIError {
            code: FFIErrorCode::NulByteError,
            message: CString::new(value.to_string())
                .unwrap_or(CString::new("Rust ffi::NulError message contains null byte").unwrap())
                .into_raw(),
        }
    }
}

impl From<Utf8Error> for FFIError {
    fn from(value: Utf8Error) -> Self {
        FFIError {
            code: FFIErrorCode::InvalidInput,
            message: CString::new(value.to_string())
                .unwrap_or(CString::new("Rust Utf8Error message contains null byte").unwrap())
                .into_raw(),
        }
    }
}

impl From<dashcore::address::Error> for FFIError {
    fn from(value: dashcore::address::Error) -> Self {
        FFIError {
            code: FFIErrorCode::InvalidAddress,
            message: CString::new(value.to_string())
                .unwrap_or(
                    CString::new("Rust dashcore::address::Error message contains null byte")
                        .unwrap(),
                )
                .into_raw(),
        }
    }
}

impl From<dashcore::consensus::encode::Error> for FFIError {
    fn from(value: dashcore::consensus::encode::Error) -> Self {
        FFIError {
            code: FFIErrorCode::InvalidInput,
            message: CString::new(value.to_string())
                .unwrap_or(
                    CString::new(
                        "Rust dashcore::consensus::encode::Error message contains null byte",
                    )
                    .unwrap(),
                )
                .into_raw(),
        }
    }
}

impl Drop for FFIError {
    fn drop(&mut self) {
        unsafe {
            self.clean();
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
