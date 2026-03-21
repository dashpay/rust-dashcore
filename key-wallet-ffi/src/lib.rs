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

// Re-export main types for convenience
pub use error::{FFIError, FFIErrorCode};
pub use types::{FFIBalance, FFINetwork, FFIWallet};
pub use utxo::FFIUTXO;
pub use wallet_manager::{
    wallet_manager_create, wallet_manager_describe, wallet_manager_free,
    wallet_manager_free_string, wallet_manager_free_wallet_ids, wallet_manager_get_wallet,
    wallet_manager_get_wallet_balance, wallet_manager_get_wallet_ids, wallet_manager_wallet_count,
    FFIWalletManager,
};

// ============================================================================
// Initialization and Version
// ============================================================================

use dashcore::hashes::Hash;
use key_wallet::transaction_checking::{BlockInfo, TransactionContext};
use std::os::raw::c_char;

use crate::types::FFITransactionContext;

/// Convert FFI block parameters to a `BlockInfo`.
///
/// `timestamp` is accepted as `u64` for FFI compatibility but truncated to `u32`
/// internally. This is safe because Dash block timestamps are Unix epoch seconds
/// which fit in `u32` until 2106. Callers must not pass millisecond or other
/// wider-than-seconds values.
///
/// # Safety
///
/// - If `block_hash` is non-null it must point to 32 readable bytes.
/// - `timestamp` must be a Unix epoch timestamp in seconds (truncated to `u32`).
pub(crate) unsafe fn block_info_from_ffi(
    height: u32,
    block_hash: *const u8,
    timestamp: u64,
) -> BlockInfo {
    let block_hash = if !block_hash.is_null() {
        let hash_bytes = std::slice::from_raw_parts(block_hash, 32);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(hash_bytes);
        dashcore::BlockHash::from_byte_array(arr)
    } else {
        dashcore::BlockHash::all_zeros()
    };
    BlockInfo::new(height, block_hash, timestamp as u32)
}

/// Convert FFI transaction context parameters to a native `TransactionContext`.
///
/// # Safety
///
/// Same requirements as `block_info_from_ffi`: if `block_hash` is non-null it
/// must point to 32 readable bytes.
pub(crate) unsafe fn transaction_context_from_ffi(
    context_type: FFITransactionContext,
    block_height: u32,
    block_hash: *const u8,
    timestamp: u64,
) -> TransactionContext {
    match context_type {
        FFITransactionContext::Mempool => TransactionContext::Mempool,
        FFITransactionContext::InstantSend => TransactionContext::InstantSend,
        FFITransactionContext::InBlock => {
            TransactionContext::InBlock(block_info_from_ffi(block_height, block_hash, timestamp))
        }
        FFITransactionContext::InChainLockedBlock => TransactionContext::InChainLockedBlock(
            block_info_from_ffi(block_height, block_hash, timestamp),
        ),
    }
}

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
