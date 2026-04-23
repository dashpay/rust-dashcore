//! Transaction checking FFI bindings
//!
//! This module provides FFI bindings for the advanced transaction checking
//! functionality introduced in the key-wallet library, including transaction
//! routing, classification, and account matching.

use std::ffi::CString;
use std::os::raw::c_char;
use std::slice;

use crate::error::FFIError;
use crate::managed_wallet::{managed_wallet_info_free, FFIManagedWalletInfo};
use crate::types::FFIWallet;
use crate::{check_ptr, deref_ptr, unwrap_or_return};
use dashcore::consensus::Decodable;
use dashcore::Transaction;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;

/// Create a managed wallet from a regular wallet
///
/// This creates a ManagedWalletInfo instance from a Wallet, which includes
/// address pools and transaction checking capabilities.
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `error` must be a valid pointer to an FFIError
/// - The returned pointer must be freed with `managed_wallet_info_free` (or `ffi_managed_wallet_free` for compatibility)
#[no_mangle]
pub unsafe extern "C" fn wallet_create_managed_wallet(
    wallet: *const FFIWallet,
    error: *mut FFIError,
) -> *mut FFIManagedWalletInfo {
    let wallet = deref_ptr!(wallet, error);
    let managed_info = ManagedWalletInfo::from_wallet(wallet.inner());
    Box::into_raw(Box::new(FFIManagedWalletInfo::new(managed_info)))
}

/// Free a managed wallet (FFIManagedWalletInfo type)
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo
/// - This function must only be called once per managed wallet
#[no_mangle]
pub unsafe extern "C" fn ffi_managed_wallet_free(managed_wallet: *mut FFIManagedWalletInfo) {
    // For compatibility, forward to canonical free
    managed_wallet_info_free(managed_wallet);
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
