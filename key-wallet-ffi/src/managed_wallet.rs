//! Managed wallet FFI bindings
//!
//! This module provides FFI bindings for ManagedWalletInfo which includes
//! address management, UTXO tracking, and transaction building capabilities.
//!

use std::ffi::CString;
use std::os::raw::c_char;

use crate::error::FFIError;
use crate::types::FFIWallet;
use crate::{deref_ptr, deref_ptr_mut, unwrap_or_return};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use std::ffi::c_void;

/// FFI wrapper for ManagedWalletInfo (single canonical type)
#[repr(C)]
pub struct FFIManagedWalletInfo {
    // Opaque pointer to avoid leaking ManagedWalletInfo into C headers
    inner: *mut c_void,
}

impl FFIManagedWalletInfo {
    /// Create a new FFIManagedWalletInfo from a ManagedWalletInfo
    pub fn new(inner: ManagedWalletInfo) -> Self {
        Self {
            inner: Box::into_raw(Box::new(inner)) as *mut c_void,
        }
    }

    pub fn inner(&self) -> &ManagedWalletInfo {
        unsafe { &*(self.inner as *const ManagedWalletInfo) }
    }

    pub fn inner_mut(&mut self) -> &mut ManagedWalletInfo {
        unsafe { &mut *(self.inner as *mut ManagedWalletInfo) }
    }
}

/// Get the next unused receive address
///
/// Generates the next unused receive address for the specified account.
/// This properly manages address gaps and updates the managed wallet state.
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed by the caller
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_get_next_bip44_receive_address(
    managed_wallet: *mut FFIManagedWalletInfo,
    wallet: *const FFIWallet,
    account_index: std::os::raw::c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    let managed_wallet = deref_ptr_mut!(managed_wallet, error);
    let wallet = deref_ptr!(wallet, error);

    // Get the specific managed account (default to BIP44)
    let managed_account = unwrap_or_return!(
        managed_wallet.inner_mut().accounts.standard_bip44_accounts.get_mut(&account_index),
        error
    );

    // Get the account from the wallet to get the extended public key
    let account = unwrap_or_return!(
        wallet.wallet.accounts.standard_bip44_accounts.get(&account_index),
        error
    );

    // Generate the next receive address
    let xpub = account.extended_public_key();
    let address = unwrap_or_return!(managed_account.next_receive_address(Some(&xpub), true), error)
        .to_string();
    unwrap_or_return!(CString::new(address), error).into_raw()
}

/// Get the next unused change address
///
/// Generates the next unused change address for the specified account.
/// This properly manages address gaps and updates the managed wallet state.
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed by the caller
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_get_next_bip44_change_address(
    managed_wallet: *mut FFIManagedWalletInfo,
    wallet: *const FFIWallet,
    account_index: std::os::raw::c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    let managed_wallet = deref_ptr_mut!(managed_wallet, error);
    let wallet = deref_ptr!(wallet, error);

    // Get the specific managed account (default to BIP44)
    let managed_account = unwrap_or_return!(
        managed_wallet.inner_mut().accounts.standard_bip44_accounts.get_mut(&account_index),
        error
    );

    // Get the account from the wallet to get the extended public key
    let account = unwrap_or_return!(
        wallet.wallet.accounts.standard_bip44_accounts.get(&account_index),
        error
    );

    // Generate the next change address
    let xpub = account.extended_public_key();
    let next_change_address =
        unwrap_or_return!(managed_account.next_change_address(Some(&xpub), true), error)
            .to_string();
    unwrap_or_return!(CString::new(next_change_address), error).into_raw()
}

/// Free managed wallet info returned by wallet_manager_get_managed_wallet_info
///
/// # Safety
///
/// - `wallet_info` must be a valid pointer returned by wallet_manager_get_managed_wallet_info or null
/// - After calling this function, the pointer becomes invalid and must not be used
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_info_free(wallet_info: *mut FFIManagedWalletInfo) {
    if !wallet_info.is_null() {
        let wrapper = Box::from_raw(wallet_info);
        if !wrapper.inner.is_null() {
            let _ = Box::from_raw(wrapper.inner as *mut ManagedWalletInfo);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::{FFIError, FFIErrorCode};
    use crate::managed_wallet::*;
    use std::ptr;

    // Note: managed_wallet_create has been removed as client libraries
    // should only get ManagedWalletInfo through WalletManager

    #[test]
    fn test_managed_wallet_get_next_receive_address_null_pointers() {
        let mut error = FFIError::default();

        // Test with null managed wallet
        let address = unsafe {
            managed_wallet_get_next_bip44_receive_address(
                ptr::null_mut(),
                ptr::null(),
                0,
                &mut error,
            )
        };

        assert!(address.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_managed_wallet_get_next_change_address_null_pointers() {
        let mut error = FFIError::default();

        // Test with null managed wallet
        let address = unsafe {
            managed_wallet_get_next_bip44_change_address(
                ptr::null_mut(),
                ptr::null(),
                0,
                &mut error,
            )
        };

        assert!(address.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }
}

#[cfg(test)]
#[path = "managed_wallet_tests.rs"]
mod managed_wallet_tests;
