//! Transaction checking FFI bindings
//!
//! This module provides FFI bindings for the advanced transaction checking
//! functionality introduced in the key-wallet library, including transaction
//! routing, classification, and account matching.

use std::ffi::CString;
use std::os::raw::c_char;
use std::slice;

use crate::error::FFIError;
use crate::{check_ptr, unwrap_or_return};
use dashcore::consensus::Decodable;
use dashcore::Transaction;

/// Free a transaction check result
///
/// The result owns no heap memory, so this is a no-op kept for ABI compatibility.
///
/// # Safety
///
/// - `result` is not dereferenced
#[no_mangle]
pub unsafe extern "C" fn transaction_check_result_free(
    _result: *mut crate::transaction::FFITransactionCheckResult,
) {
}

/// Get the transaction classification for routing
///
/// Returns a string describing the transaction type (e.g., "Standard", "CoinJoin",
/// "AssetLock", "AssetUnlock", "ProviderRegistration", etc.)
///
/// # Safety
///
/// - `tx_bytes` must be a valid pointer to transaction bytes with at least `tx_len` bytes
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed by the caller
#[no_mangle]
pub unsafe extern "C" fn transaction_classify(
    tx_bytes: *const u8,
    tx_len: usize,
    error: *mut FFIError,
) -> *mut c_char {
    check_ptr!(tx_bytes, error);
    let tx_slice = slice::from_raw_parts(tx_bytes, tx_len);
    let tx = unwrap_or_return!(Transaction::consensus_decode(&mut &tx_slice[..]), error);

    use key_wallet::transaction_checking::transaction_router::TransactionRouter;
    let tx_type = TransactionRouter::classify_transaction(&tx);
    unwrap_or_return!(CString::new(format!("{:?}", tx_type)), error).into_raw()
}

#[cfg(test)]
mod tests {
    use crate::types::FFITransactionContextType;

    #[test]
    fn test_transaction_context_conversion() {
        // Test that FFI transaction context values match expectations
        assert_eq!(FFITransactionContextType::Mempool as u32, 0);
        assert_eq!(FFITransactionContextType::InstantSend as u32, 1);
        assert_eq!(FFITransactionContextType::InBlock as u32, 2);
        assert_eq!(FFITransactionContextType::InChainLockedBlock as u32, 3);
    }
}
