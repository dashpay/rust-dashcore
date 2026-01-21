//! FFI bindings for key-wallet library
//!
//! This library provides C-compatible FFI bindings for the key-wallet Rust library.
//! It does not use uniffi and instead provides direct extern "C" functions.

// Module declarations
pub mod account;
pub mod account_collection;
pub mod account_derivation;
pub mod address;
pub mod address_pool;
pub mod derivation;
pub mod error;
pub mod keys;
pub mod managed_account;
pub mod managed_account_collection;
pub mod managed_platform_account;
pub mod managed_wallet;
pub mod mnemonic;
pub mod transaction;
pub mod transaction_checking;
pub mod types;
pub mod utils;
pub mod utxo;
pub mod wallet;
pub mod wallet_manager;

#[cfg(feature = "bip38")]
pub mod bip38;

// Test modules are now included in each source file

// Re-export all types and functions for unified access
pub use account::*;
pub use account_collection::*;
pub use account_derivation::*;
pub use address::*;
pub use address_pool::*;
pub use derivation::*;
pub use error::*;
pub use keys::*;
pub use managed_account::*;
pub use managed_account_collection::*;
pub use managed_platform_account::*;
pub use managed_wallet::*;
pub use mnemonic::*;
pub use transaction::*;
pub use transaction_checking::*;
pub use types::*;
pub use utils::*;
pub use utxo::*;
pub use wallet::*;
pub use wallet_manager::*;

// ============================================================================
// Initialization and Version
// ============================================================================

use std::os::raw::c_char;

/// Initialize the library
#[no_mangle]
pub extern "C" fn key_wallet_ffi_initialize() -> bool {
    // Any global initialization
    true
}

/// Get library version
///
/// Returns a static string that should NOT be freed by the caller
#[no_mangle]
pub extern "C" fn key_wallet_ffi_version() -> *const c_char {
    // Use a static CStr to avoid allocation and ensure the string is never freed
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}
