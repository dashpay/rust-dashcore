//! FFI bindings for key-wallet library
//!
//! This library provides C-compatible FFI bindings for the key-wallet Rust library.
//! It does not use uniffi and instead provides direct extern "C" functions.

// Module declarations
pub mod account;
pub mod address;
pub mod balance;
pub mod derivation;
pub mod error;
pub mod keys;
pub mod managed_wallet;
pub mod mnemonic;
pub mod transaction;
pub mod types;
pub mod utils;
pub mod utxo;
pub mod wallet;
pub mod wallet_manager;

#[cfg(feature = "bip38")]
pub mod bip38;

// Test modules are now included in each source file

// Re-export main types for convenience
pub use error::{FFIError, FFIErrorCode};
pub use types::{FFINetwork, FFIWallet};

// ============================================================================
// Initialization and Version
// ============================================================================

use std::ffi::CString;
use std::os::raw::c_char;

/// Initialize the library
#[no_mangle]
pub extern "C" fn key_wallet_ffi_initialize() -> bool {
    // Any global initialization
    true
}

/// Get library version
#[no_mangle]
pub extern "C" fn key_wallet_ffi_version() -> *const c_char {
    CString::new(env!("CARGO_PKG_VERSION"))
        .expect("Version string should never fail")
        .into_raw()
}
