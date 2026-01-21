//! Managed Platform Account FFI bindings
//!
//! This module provides FFI-compatible managed platform account functionality
//! specifically for Platform Payment accounts (DIP-17). These accounts have a
//! different balance model using Platform credits instead of UTXOs.
//!
//! Credit balance: Platform-side balance tracked in credits (1000 credits = 1 duff)
//! The credit balance must be set/updated from the Platform layer.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::address_pool::FFIAddressPool;
use crate::error::FFIErrorCode;
use crate::FFINetwork;
use key_wallet::managed_account::address_pool::AddressPool;
use key_wallet::managed_account::managed_account_type::ManagedAccountType;
use key_wallet::managed_account::ManagedAccount;

/// Opaque managed platform account handle
///
/// This wraps a ManagedAccount of PlatformPayment type and adds
/// Platform-specific credit balance tracking.
pub struct FFIManagedPlatformAccount {
    /// The underlying managed account (must be PlatformPayment type)
    account: Arc<ManagedAccount>,
    /// Credit balance (Platform-side, 1000 credits = 1 duff)
    /// This is set/updated from the Platform layer
    credit_balance: AtomicU64,
}

impl FFIManagedPlatformAccount {
    /// Create a new FFI managed platform account from a ManagedAccount
    ///
    /// Returns None if the account is not a PlatformPayment type
    pub fn new(account: &ManagedAccount) -> Option<Self> {
        // Verify this is a PlatformPayment account
        match &account.account_type {
            ManagedAccountType::PlatformPayment { .. } => Some(FFIManagedPlatformAccount {
                account: Arc::new(account.clone()),
                credit_balance: AtomicU64::new(0),
            }),
            _ => None,
        }
    }

    /// Get a reference to the inner managed account
    pub fn inner(&self) -> &ManagedAccount {
        self.account.as_ref()
    }

    /// Get the account index (from PlatformPayment variant)
    pub fn account_index(&self) -> u32 {
        match &self.inner().account_type {
            ManagedAccountType::PlatformPayment { account, .. } => *account,
            _ => 0, // Should never happen if constructed properly
        }
    }

    /// Get the key class (from PlatformPayment variant)
    pub fn key_class(&self) -> u32 {
        match &self.inner().account_type {
            ManagedAccountType::PlatformPayment { key_class, .. } => *key_class,
            _ => 0, // Should never happen if constructed properly
        }
    }

    /// Get the address pool
    pub fn address_pool(&self) -> Option<&AddressPool> {
        match &self.inner().account_type {
            ManagedAccountType::PlatformPayment { addresses, .. } => Some(addresses),
            _ => None,
        }
    }
}

/// FFI Result type for ManagedPlatformAccount operations
#[repr(C)]
pub struct FFIManagedPlatformAccountResult {
    /// The managed platform account handle if successful, NULL if error
    pub account: *mut FFIManagedPlatformAccount,
    /// Error code (0 = success)
    pub error_code: i32,
    /// Error message (NULL if success, must be freed by caller if not NULL)
    pub error_message: *mut std::os::raw::c_char,
}

impl FFIManagedPlatformAccountResult {
    /// Create a success result
    pub fn success(account: *mut FFIManagedPlatformAccount) -> Self {
        FFIManagedPlatformAccountResult {
            account,
            error_code: 0,
            error_message: std::ptr::null_mut(),
        }
    }

    /// Create an error result
    pub fn error(code: FFIErrorCode, message: String) -> Self {
        use std::ffi::CString;
        let c_message = CString::new(message).unwrap_or_else(|_| {
            CString::new("Unknown error").expect("Hardcoded string should never fail")
        });
        FFIManagedPlatformAccountResult {
            account: std::ptr::null_mut(),
            error_code: code as i32,
            error_message: c_message.into_raw(),
        }
    }
}

/// Get the network of a managed platform account
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedPlatformAccount instance
/// - Returns `FFINetwork::Dash` if the account is null
#[no_mangle]
pub unsafe extern "C" fn managed_platform_account_get_network(
    account: *const FFIManagedPlatformAccount,
) -> FFINetwork {
    if account.is_null() {
        return FFINetwork::Dash;
    }

    let account = &*account;
    account.inner().network.into()
}

/// Get the account index of a managed platform account
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedPlatformAccount instance
/// - Returns 0 if the account is null
#[no_mangle]
pub unsafe extern "C" fn managed_platform_account_get_account_index(
    account: *const FFIManagedPlatformAccount,
) -> u32 {
    if account.is_null() {
        return 0;
    }

    let account = &*account;
    account.account_index()
}

/// Get the key class of a managed platform account
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedPlatformAccount instance
/// - Returns 0 if the account is null
#[no_mangle]
pub unsafe extern "C" fn managed_platform_account_get_key_class(
    account: *const FFIManagedPlatformAccount,
) -> u32 {
    if account.is_null() {
        return 0;
    }

    let account = &*account;
    account.key_class()
}

/// Check if a managed platform account is watch-only
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedPlatformAccount instance
/// - Returns false if the account is null
#[no_mangle]
pub unsafe extern "C" fn managed_platform_account_get_is_watch_only(
    account: *const FFIManagedPlatformAccount,
) -> bool {
    if account.is_null() {
        return false;
    }

    let account = &*account;
    account.inner().is_watch_only
}

/// Get the credit balance of a managed platform account
///
/// The credit balance is Platform-specific (1000 credits = 1 duff).
/// This value must be set via `managed_platform_account_set_credit_balance`.
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedPlatformAccount instance
/// - Returns 0 if the account is null
#[no_mangle]
pub unsafe extern "C" fn managed_platform_account_get_credit_balance(
    account: *const FFIManagedPlatformAccount,
) -> u64 {
    if account.is_null() {
        return 0;
    }

    let account = &*account;
    account.credit_balance.load(Ordering::Relaxed)
}

/// Set the credit balance of a managed platform account
///
/// The credit balance is Platform-specific (1000 credits = 1 duff).
/// This should be called by the Platform layer to update the balance.
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedPlatformAccount instance
#[no_mangle]
pub unsafe extern "C" fn managed_platform_account_set_credit_balance(
    account: *mut FFIManagedPlatformAccount,
    credit_balance: u64,
) {
    if account.is_null() {
        return;
    }

    let account = &*account;
    account.credit_balance.store(credit_balance, Ordering::Relaxed);
}

/// Get the duff balance of a managed platform account
///
/// This is the credit balance divided by 1000 (1000 credits = 1 duff).
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedPlatformAccount instance
/// - Returns 0 if the account is null
#[no_mangle]
pub unsafe extern "C" fn managed_platform_account_get_duff_balance(
    account: *const FFIManagedPlatformAccount,
) -> u64 {
    if account.is_null() {
        return 0;
    }

    let account = &*account;
    account.credit_balance.load(Ordering::Relaxed) / 1000
}

/// Get the number of funded addresses in a managed platform account
///
/// A funded address is one that has been used (has received funds).
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedPlatformAccount instance
/// - Returns 0 if the account is null
#[no_mangle]
pub unsafe extern "C" fn managed_platform_account_get_funded_address_count(
    account: *const FFIManagedPlatformAccount,
) -> u32 {
    if account.is_null() {
        return 0;
    }

    let account = &*account;
    match account.address_pool() {
        Some(pool) => pool.used_addresses().len() as u32,
        None => 0,
    }
}

/// Get the total number of addresses in a managed platform account
///
/// This includes both used and unused addresses in the pool.
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedPlatformAccount instance
/// - Returns 0 if the account is null
#[no_mangle]
pub unsafe extern "C" fn managed_platform_account_get_total_address_count(
    account: *const FFIManagedPlatformAccount,
) -> u32 {
    if account.is_null() {
        return 0;
    }

    let account = &*account;
    match account.address_pool() {
        Some(pool) => pool.all_addresses().len() as u32,
        None => 0,
    }
}

/// Get the address pool from a managed platform account
///
/// Platform accounts only have a single address pool.
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedPlatformAccount instance
/// - The returned pool must be freed with `address_pool_free` when no longer needed
/// - Returns NULL if the account is null or has no address pool
#[no_mangle]
pub unsafe extern "C" fn managed_platform_account_get_address_pool(
    account: *const FFIManagedPlatformAccount,
) -> *mut FFIAddressPool {
    if account.is_null() {
        return std::ptr::null_mut();
    }

    let account = &*account;
    match account.address_pool() {
        Some(pool) => {
            let ffi_pool = FFIAddressPool {
                pool: pool as *const AddressPool as *mut AddressPool,
                pool_type: crate::address_pool::FFIAddressPoolType::Single,
            };
            Box::into_raw(Box::new(ffi_pool))
        }
        None => std::ptr::null_mut(),
    }
}

/// Free a managed platform account handle
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedPlatformAccount that was allocated by this library
/// - The pointer must not be used after calling this function
/// - This function must only be called once per allocation
#[no_mangle]
pub unsafe extern "C" fn managed_platform_account_free(account: *mut FFIManagedPlatformAccount) {
    if !account.is_null() {
        let _ = Box::from_raw(account);
    }
}

/// Free a managed platform account result's error message (if any)
///
/// Note: This does NOT free the account handle itself - use managed_platform_account_free for that
///
/// # Safety
///
/// - `result` must be a valid pointer to an FFIManagedPlatformAccountResult
/// - The error_message field must be either null or a valid CString allocated by this library
#[no_mangle]
pub unsafe extern "C" fn managed_platform_account_result_free_error(
    result: *mut FFIManagedPlatformAccountResult,
) {
    if !result.is_null() {
        let result = &mut *result;
        if !result.error_message.is_null() {
            let _ = std::ffi::CString::from_raw(result.error_message);
            result.error_message = std::ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_managed_platform_account_free_null() {
        unsafe {
            // Should not crash when freeing null
            managed_platform_account_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn test_managed_platform_account_getters_null() {
        unsafe {
            // Test null account for all getters
            let network = managed_platform_account_get_network(std::ptr::null());
            assert_eq!(network, FFINetwork::Dash);

            let account_index = managed_platform_account_get_account_index(std::ptr::null());
            assert_eq!(account_index, 0);

            let key_class = managed_platform_account_get_key_class(std::ptr::null());
            assert_eq!(key_class, 0);

            let is_watch_only = managed_platform_account_get_is_watch_only(std::ptr::null());
            assert!(!is_watch_only);

            let credit_balance = managed_platform_account_get_credit_balance(std::ptr::null());
            assert_eq!(credit_balance, 0);

            let duff_balance = managed_platform_account_get_duff_balance(std::ptr::null());
            assert_eq!(duff_balance, 0);

            let funded_count = managed_platform_account_get_funded_address_count(std::ptr::null());
            assert_eq!(funded_count, 0);

            let total_count = managed_platform_account_get_total_address_count(std::ptr::null());
            assert_eq!(total_count, 0);

            let pool = managed_platform_account_get_address_pool(std::ptr::null());
            assert!(pool.is_null());
        }
    }
}
