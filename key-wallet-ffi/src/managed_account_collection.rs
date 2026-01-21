//! FFI bindings for managed account collections
//!
//! This module provides FFI-compatible account collection functionality that works
//! with managed wallets through the wallet manager. It mirrors the functionality
//! of account_collection.rs but accesses accounts through the wallet manager's
//! wallet reference.

use std::ffi::CString;
use std::os::raw::{c_char, c_uint};
use std::ptr;

use crate::error::{FFIError, FFIErrorCode};
use crate::managed_account::FFIManagedAccount;
use crate::managed_platform_account::FFIManagedPlatformAccount;
use crate::wallet_manager::FFIWalletManager;
use key_wallet::account::account_collection::PlatformPaymentAccountKey;

/// Opaque handle to a managed account collection
pub struct FFIManagedAccountCollection {
    /// The underlying managed account collection
    collection: key_wallet::managed_account::managed_account_collection::ManagedAccountCollection,
}

impl FFIManagedAccountCollection {
    /// Create a new FFI managed account collection
    pub fn new(
        collection: &key_wallet::managed_account::managed_account_collection::ManagedAccountCollection,
    ) -> Self {
        FFIManagedAccountCollection {
            collection: collection.clone(),
        }
    }
}

/// C-compatible summary of all accounts in a managed collection
///
/// This struct provides Swift with structured data about all accounts
/// that exist in the managed collection, allowing programmatic access to account
/// indices and presence information.
#[repr(C)]
pub struct FFIManagedAccountCollectionSummary {
    /// Array of BIP44 account indices
    pub bip44_indices: *mut c_uint,
    /// Number of BIP44 accounts
    pub bip44_count: usize,

    /// Array of BIP32 account indices
    pub bip32_indices: *mut c_uint,
    /// Number of BIP32 accounts
    pub bip32_count: usize,

    /// Array of CoinJoin account indices
    pub coinjoin_indices: *mut c_uint,
    /// Number of CoinJoin accounts
    pub coinjoin_count: usize,

    /// Array of identity top-up registration indices
    pub identity_topup_indices: *mut c_uint,
    /// Number of identity top-up accounts
    pub identity_topup_count: usize,

    /// Whether identity registration account exists
    pub has_identity_registration: bool,
    /// Whether identity invitation account exists
    pub has_identity_invitation: bool,
    /// Whether identity top-up not bound account exists
    pub has_identity_topup_not_bound: bool,
    /// Whether provider voting keys account exists
    pub has_provider_voting_keys: bool,
    /// Whether provider owner keys account exists
    pub has_provider_owner_keys: bool,

    #[cfg(feature = "bls")]
    /// Whether provider operator keys account exists
    pub has_provider_operator_keys: bool,

    #[cfg(feature = "eddsa")]
    /// Whether provider platform keys account exists
    pub has_provider_platform_keys: bool,
}

/// Get managed account collection for a specific network from wallet manager
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `wallet_id` must be a valid pointer to a 32-byte wallet ID
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The returned pointer must be freed with `managed_account_collection_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_get_account_collection(
    manager: *const FFIWalletManager,
    wallet_id: *const u8,
    error: *mut FFIError,
) -> *mut FFIManagedAccountCollection {
    if manager.is_null() || wallet_id.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    // Get the managed wallet info from the manager
    let managed_wallet_ptr =
        crate::wallet_manager::wallet_manager_get_managed_wallet_info(manager, wallet_id, error);

    if managed_wallet_ptr.is_null() {
        // Error already set by wallet_manager_get_managed_wallet_info
        return ptr::null_mut();
    }

    // Get the managed account collection from the managed wallet info
    let managed_wallet = &*managed_wallet_ptr;

    let ffi_collection = FFIManagedAccountCollection::new(&managed_wallet.inner().accounts);

    // Clean up the managed wallet pointer since we've extracted what we need
    crate::managed_wallet::managed_wallet_info_free(managed_wallet_ptr);

    Box::into_raw(Box::new(ffi_collection))
}

/// Free a managed account collection handle
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection created by this library
/// - `collection` must not be used after calling this function
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_free(
    collection: *mut FFIManagedAccountCollection,
) {
    if !collection.is_null() {
        let _ = Box::from_raw(collection);
    }
}

// Standard BIP44 accounts functions

/// Get a BIP44 account by index from the managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - The returned pointer must be freed with `managed_account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_get_bip44_account(
    collection: *const FFIManagedAccountCollection,
    index: c_uint,
) -> *mut FFIManagedAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match collection.collection.standard_bip44_accounts.get(&index) {
        Some(account) => {
            // Get the network from the account
            let ffi_account = FFIManagedAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Get all BIP44 account indices from managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - `out_indices` must be a valid pointer to store the indices array
/// - `out_count` must be a valid pointer to store the count
/// - The returned array must be freed with `free_u32_array` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_get_bip44_indices(
    collection: *const FFIManagedAccountCollection,
    out_indices: *mut *mut c_uint,
    out_count: *mut usize,
) -> bool {
    if collection.is_null() || out_indices.is_null() || out_count.is_null() {
        return false;
    }

    let collection = &*collection;
    let mut indices: Vec<c_uint> =
        collection.collection.standard_bip44_accounts.keys().copied().collect();

    if indices.is_empty() {
        *out_indices = ptr::null_mut();
        *out_count = 0;
        return true;
    }

    indices.sort();

    let mut boxed_slice = indices.into_boxed_slice();
    let ptr = boxed_slice.as_mut_ptr();
    let len = boxed_slice.len();
    std::mem::forget(boxed_slice);

    *out_indices = ptr;
    *out_count = len;
    true
}

// Standard BIP32 accounts functions

/// Get a BIP32 account by index from the managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - The returned pointer must be freed with `managed_account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_get_bip32_account(
    collection: *const FFIManagedAccountCollection,
    index: c_uint,
) -> *mut FFIManagedAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match collection.collection.standard_bip32_accounts.get(&index) {
        Some(account) => {
            let ffi_account = FFIManagedAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Get all BIP32 account indices from managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - `out_indices` must be a valid pointer to store the indices array
/// - `out_count` must be a valid pointer to store the count
/// - The returned array must be freed with `free_u32_array` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_get_bip32_indices(
    collection: *const FFIManagedAccountCollection,
    out_indices: *mut *mut c_uint,
    out_count: *mut usize,
) -> bool {
    if collection.is_null() || out_indices.is_null() || out_count.is_null() {
        return false;
    }

    let collection = &*collection;
    let indices: Vec<c_uint> =
        collection.collection.standard_bip32_accounts.keys().copied().collect();

    if indices.is_empty() {
        *out_indices = ptr::null_mut();
        *out_count = 0;
        return true;
    }

    let mut boxed_slice = indices.into_boxed_slice();
    let ptr = boxed_slice.as_mut_ptr();
    let len = boxed_slice.len();
    std::mem::forget(boxed_slice);

    *out_indices = ptr;
    *out_count = len;
    true
}

// CoinJoin accounts functions

/// Get a CoinJoin account by index from the managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - The returned pointer must be freed with `managed_account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_get_coinjoin_account(
    collection: *const FFIManagedAccountCollection,
    index: c_uint,
) -> *mut FFIManagedAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match collection.collection.coinjoin_accounts.get(&index) {
        Some(account) => {
            let ffi_account = FFIManagedAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Get all CoinJoin account indices from managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - `out_indices` must be a valid pointer to store the indices array
/// - `out_count` must be a valid pointer to store the count
/// - The returned array must be freed with `free_u32_array` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_get_coinjoin_indices(
    collection: *const FFIManagedAccountCollection,
    out_indices: *mut *mut c_uint,
    out_count: *mut usize,
) -> bool {
    if collection.is_null() || out_indices.is_null() || out_count.is_null() {
        return false;
    }

    let collection = &*collection;
    let mut indices: Vec<c_uint> =
        collection.collection.coinjoin_accounts.keys().copied().collect();

    if indices.is_empty() {
        *out_indices = ptr::null_mut();
        *out_count = 0;
        return true;
    }

    indices.sort();

    let mut boxed_slice = indices.into_boxed_slice();
    let ptr = boxed_slice.as_mut_ptr();
    let len = boxed_slice.len();
    std::mem::forget(boxed_slice);

    *out_indices = ptr;
    *out_count = len;
    true
}

// Identity accounts functions

/// Get the identity registration account if it exists in managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - The returned pointer must be freed with `managed_account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_get_identity_registration(
    collection: *const FFIManagedAccountCollection,
) -> *mut FFIManagedAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match &collection.collection.identity_registration {
        Some(account) => {
            let ffi_account = FFIManagedAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Check if identity registration account exists in managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_has_identity_registration(
    collection: *const FFIManagedAccountCollection,
) -> bool {
    if collection.is_null() {
        return false;
    }

    let collection = &*collection;
    collection.collection.identity_registration.is_some()
}

/// Get an identity topup account by registration index from managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - The returned pointer must be freed with `managed_account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_get_identity_topup(
    collection: *const FFIManagedAccountCollection,
    registration_index: c_uint,
) -> *mut FFIManagedAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match collection.collection.identity_topup.get(&registration_index) {
        Some(account) => {
            let ffi_account = FFIManagedAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Get all identity topup registration indices from managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - `out_indices` must be a valid pointer to store the indices array
/// - `out_count` must be a valid pointer to store the count
/// - The returned array must be freed with `free_u32_array` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_get_identity_topup_indices(
    collection: *const FFIManagedAccountCollection,
    out_indices: *mut *mut c_uint,
    out_count: *mut usize,
) -> bool {
    if collection.is_null() || out_indices.is_null() || out_count.is_null() {
        return false;
    }

    let collection = &*collection;
    let mut indices: Vec<c_uint> = collection.collection.identity_topup.keys().copied().collect();

    if indices.is_empty() {
        *out_indices = ptr::null_mut();
        *out_count = 0;
        return true;
    }

    indices.sort();

    let mut boxed_slice = indices.into_boxed_slice();
    let ptr = boxed_slice.as_mut_ptr();
    let len = boxed_slice.len();
    std::mem::forget(boxed_slice);

    *out_indices = ptr;
    *out_count = len;
    true
}

/// Get the identity topup not bound account if it exists in managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - `manager` must be a valid pointer to an FFIWalletManager
/// - The returned pointer must be freed with `managed_account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_get_identity_topup_not_bound(
    collection: *const FFIManagedAccountCollection,
) -> *mut FFIManagedAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match &collection.collection.identity_topup_not_bound {
        Some(account) => {
            let ffi_account = FFIManagedAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Check if identity topup not bound account exists in managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_has_identity_topup_not_bound(
    collection: *const FFIManagedAccountCollection,
) -> bool {
    if collection.is_null() {
        return false;
    }

    let collection = &*collection;
    collection.collection.identity_topup_not_bound.is_some()
}

/// Get the identity invitation account if it exists in managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - The returned pointer must be freed with `managed_account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_get_identity_invitation(
    collection: *const FFIManagedAccountCollection,
) -> *mut FFIManagedAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match &collection.collection.identity_invitation {
        Some(account) => {
            let ffi_account = FFIManagedAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Check if identity invitation account exists in managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_has_identity_invitation(
    collection: *const FFIManagedAccountCollection,
) -> bool {
    if collection.is_null() {
        return false;
    }

    let collection = &*collection;
    collection.collection.identity_invitation.is_some()
}

// Provider accounts functions

/// Get the provider voting keys account if it exists in managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - The returned pointer must be freed with `managed_account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_get_provider_voting_keys(
    collection: *const FFIManagedAccountCollection,
) -> *mut FFIManagedAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match &collection.collection.provider_voting_keys {
        Some(account) => {
            let ffi_account = FFIManagedAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Check if provider voting keys account exists in managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_has_provider_voting_keys(
    collection: *const FFIManagedAccountCollection,
) -> bool {
    if collection.is_null() {
        return false;
    }

    let collection = &*collection;
    collection.collection.provider_voting_keys.is_some()
}

/// Get the provider owner keys account if it exists in managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - The returned pointer must be freed with `managed_account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_get_provider_owner_keys(
    collection: *const FFIManagedAccountCollection,
) -> *mut FFIManagedAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match &collection.collection.provider_owner_keys {
        Some(account) => {
            let ffi_account = FFIManagedAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Check if provider owner keys account exists in managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_has_provider_owner_keys(
    collection: *const FFIManagedAccountCollection,
) -> bool {
    if collection.is_null() {
        return false;
    }

    let collection = &*collection;
    collection.collection.provider_owner_keys.is_some()
}

/// Get the provider operator keys account if it exists in managed collection
/// Note: Returns null if the `bls` feature is not enabled
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - The returned pointer must be freed with `managed_account_free` when no longer needed (when BLS is enabled)
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_get_provider_operator_keys(
    collection: *const FFIManagedAccountCollection,
) -> *mut std::os::raw::c_void {
    #[cfg(feature = "bls")]
    {
        if collection.is_null() {
            return ptr::null_mut();
        }

        let collection = &*collection;
        match &collection.collection.provider_operator_keys {
            Some(account) => {
                let ffi_account = FFIManagedAccount::new(account);
                Box::into_raw(Box::new(ffi_account)) as *mut std::os::raw::c_void
            }
            None => ptr::null_mut(),
        }
    }

    #[cfg(not(feature = "bls"))]
    {
        // BLS feature not enabled, always return null
        let _ = collection; // Avoid unused parameter warning
        ptr::null_mut()
    }
}

/// Check if provider operator keys account exists in managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_has_provider_operator_keys(
    collection: *const FFIManagedAccountCollection,
) -> bool {
    if collection.is_null() {
        return false;
    }

    #[cfg(feature = "bls")]
    {
        let collection = &*collection;
        collection.collection.provider_operator_keys.is_some()
    }

    #[cfg(not(feature = "bls"))]
    {
        false
    }
}

/// Get the provider platform keys account if it exists in managed collection
/// Note: Returns null if the `eddsa` feature is not enabled
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - The returned pointer must be freed with `managed_account_free` when no longer needed (when EdDSA is enabled)
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_get_provider_platform_keys(
    collection: *const FFIManagedAccountCollection,
) -> *mut std::os::raw::c_void {
    #[cfg(feature = "eddsa")]
    {
        if collection.is_null() {
            return ptr::null_mut();
        }

        let collection = &*collection;
        match &collection.collection.provider_platform_keys {
            Some(account) => {
                let ffi_account = FFIManagedAccount::new(account);
                Box::into_raw(Box::new(ffi_account)) as *mut std::os::raw::c_void
            }
            None => ptr::null_mut(),
        }
    }

    #[cfg(not(feature = "eddsa"))]
    {
        // EdDSA feature not enabled, always return null
        let _ = collection; // Avoid unused parameter warning
        ptr::null_mut()
    }
}

/// Check if provider platform keys account exists in managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_has_provider_platform_keys(
    collection: *const FFIManagedAccountCollection,
) -> bool {
    if collection.is_null() {
        return false;
    }

    #[cfg(feature = "eddsa")]
    {
        let collection = &*collection;
        collection.collection.provider_platform_keys.is_some()
    }

    #[cfg(not(feature = "eddsa"))]
    {
        false
    }
}

// Utility functions

/// Get the total number of accounts in the managed collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_count(
    collection: *const FFIManagedAccountCollection,
) -> c_uint {
    if collection.is_null() {
        return 0;
    }

    let collection = &*collection;
    let mut count = 0u32;

    count += collection.collection.standard_bip44_accounts.len() as u32;
    count += collection.collection.standard_bip32_accounts.len() as u32;
    count += collection.collection.coinjoin_accounts.len() as u32;
    count += collection.collection.identity_topup.len() as u32;

    if collection.collection.identity_registration.is_some() {
        count += 1;
    }
    if collection.collection.identity_topup_not_bound.is_some() {
        count += 1;
    }
    if collection.collection.identity_invitation.is_some() {
        count += 1;
    }
    if collection.collection.provider_voting_keys.is_some() {
        count += 1;
    }
    if collection.collection.provider_owner_keys.is_some() {
        count += 1;
    }

    #[cfg(feature = "bls")]
    if collection.collection.provider_operator_keys.is_some() {
        count += 1;
    }

    #[cfg(feature = "eddsa")]
    if collection.collection.provider_platform_keys.is_some() {
        count += 1;
    }

    count
}

/// Get a human-readable summary of all accounts in the managed collection
///
/// Returns a formatted string showing all account types and their indices.
/// The format is designed to be clear and readable for end users.
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - The returned string must be freed with `string_free` when no longer needed
/// - Returns null if the collection pointer is null
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_summary(
    collection: *const FFIManagedAccountCollection,
) -> *mut c_char {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    let mut summary_parts = Vec::new();

    summary_parts.push("Managed Account Summary:".to_string());

    // BIP44 Accounts
    if !collection.collection.standard_bip44_accounts.is_empty() {
        let mut indices: Vec<u32> =
            collection.collection.standard_bip44_accounts.keys().copied().collect();
        indices.sort();
        let count = indices.len();
        let indices_str = format!("{:?}", indices);
        summary_parts.push(format!(
            "• BIP44 Accounts: {} {} at indices {}",
            count,
            if count == 1 {
                "account"
            } else {
                "accounts"
            },
            indices_str
        ));
    }

    // BIP32 Accounts
    if !collection.collection.standard_bip32_accounts.is_empty() {
        let mut indices: Vec<u32> =
            collection.collection.standard_bip32_accounts.keys().copied().collect();
        indices.sort();
        let count = indices.len();
        let indices_str = format!("{:?}", indices);
        summary_parts.push(format!(
            "• BIP32 Accounts: {} {} at indices {}",
            count,
            if count == 1 {
                "account"
            } else {
                "accounts"
            },
            indices_str
        ));
    }

    // CoinJoin Accounts
    if !collection.collection.coinjoin_accounts.is_empty() {
        let mut indices: Vec<u32> =
            collection.collection.coinjoin_accounts.keys().copied().collect();
        indices.sort();
        let count = indices.len();
        let indices_str = format!("{:?}", indices);
        summary_parts.push(format!(
            "• CoinJoin Accounts: {} {} at indices {}",
            count,
            if count == 1 {
                "account"
            } else {
                "accounts"
            },
            indices_str
        ));
    }

    // Identity TopUp Accounts
    if !collection.collection.identity_topup.is_empty() {
        let mut indices: Vec<u32> = collection.collection.identity_topup.keys().copied().collect();
        indices.sort();
        let count = indices.len();
        let indices_str = format!("{:?}", indices);
        summary_parts.push(format!(
            "• Identity TopUp: {} {} at indices {}",
            count,
            if count == 1 {
                "account"
            } else {
                "accounts"
            },
            indices_str
        ));
    }

    // Special accounts (single instances)
    if collection.collection.identity_registration.is_some() {
        summary_parts.push("• Identity Registration Account".to_string());
    }

    if collection.collection.identity_topup_not_bound.is_some() {
        summary_parts.push("• Identity TopUp Not Bound Account".to_string());
    }

    if collection.collection.identity_invitation.is_some() {
        summary_parts.push("• Identity Invitation Account".to_string());
    }

    if collection.collection.provider_voting_keys.is_some() {
        summary_parts.push("• Provider Voting Keys Account".to_string());
    }

    if collection.collection.provider_owner_keys.is_some() {
        summary_parts.push("• Provider Owner Keys Account".to_string());
    }

    #[cfg(feature = "bls")]
    if collection.collection.provider_operator_keys.is_some() {
        summary_parts.push("• Provider Operator Keys Account (BLS)".to_string());
    }

    #[cfg(feature = "eddsa")]
    if collection.collection.provider_platform_keys.is_some() {
        summary_parts.push("• Provider Platform Keys Account (EdDSA)".to_string());
    }

    // If there are no accounts at all
    if summary_parts.len() == 1 {
        summary_parts.push("No accounts configured".to_string());
    }

    let summary = summary_parts.join("\n");

    match CString::new(summary) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Get structured account collection summary data for managed collection
///
/// Returns a struct containing arrays of indices for each account type and boolean
/// flags for special accounts. This provides Swift with programmatic access to
/// account information.
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - The returned pointer must be freed with `managed_account_collection_summary_free` when no longer needed
/// - Returns null if the collection pointer is null
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_summary_data(
    collection: *const FFIManagedAccountCollection,
) -> *mut FFIManagedAccountCollectionSummary {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;

    // Collect BIP44 indices
    let mut bip44_indices: Vec<c_uint> =
        collection.collection.standard_bip44_accounts.keys().copied().collect();
    bip44_indices.sort();
    let (bip44_ptr, bip44_count) = if bip44_indices.is_empty() {
        (ptr::null_mut(), 0)
    } else {
        let count = bip44_indices.len();
        let mut boxed_slice = bip44_indices.into_boxed_slice();
        let ptr = boxed_slice.as_mut_ptr();
        std::mem::forget(boxed_slice);
        (ptr, count)
    };

    // Collect BIP32 indices
    let mut bip32_indices: Vec<c_uint> =
        collection.collection.standard_bip32_accounts.keys().copied().collect();
    bip32_indices.sort();
    let (bip32_ptr, bip32_count) = if bip32_indices.is_empty() {
        (ptr::null_mut(), 0)
    } else {
        let count = bip32_indices.len();
        let mut boxed_slice = bip32_indices.into_boxed_slice();
        let ptr = boxed_slice.as_mut_ptr();
        std::mem::forget(boxed_slice);
        (ptr, count)
    };

    // Collect CoinJoin indices
    let mut coinjoin_indices: Vec<c_uint> =
        collection.collection.coinjoin_accounts.keys().copied().collect();
    coinjoin_indices.sort();
    let (coinjoin_ptr, coinjoin_count) = if coinjoin_indices.is_empty() {
        (ptr::null_mut(), 0)
    } else {
        let count = coinjoin_indices.len();
        let mut boxed_slice = coinjoin_indices.into_boxed_slice();
        let ptr = boxed_slice.as_mut_ptr();
        std::mem::forget(boxed_slice);
        (ptr, count)
    };

    // Collect identity topup indices
    let mut topup_indices: Vec<c_uint> =
        collection.collection.identity_topup.keys().copied().collect();
    topup_indices.sort();
    let (topup_ptr, topup_count) = if topup_indices.is_empty() {
        (ptr::null_mut(), 0)
    } else {
        let count = topup_indices.len();
        let mut boxed_slice = topup_indices.into_boxed_slice();
        let ptr = boxed_slice.as_mut_ptr();
        std::mem::forget(boxed_slice);
        (ptr, count)
    };

    // Create the summary struct
    let summary = FFIManagedAccountCollectionSummary {
        bip44_indices: bip44_ptr,
        bip44_count,
        bip32_indices: bip32_ptr,
        bip32_count,
        coinjoin_indices: coinjoin_ptr,
        coinjoin_count,
        identity_topup_indices: topup_ptr,
        identity_topup_count: topup_count,
        has_identity_registration: collection.collection.identity_registration.is_some(),
        has_identity_invitation: collection.collection.identity_invitation.is_some(),
        has_identity_topup_not_bound: collection.collection.identity_topup_not_bound.is_some(),
        has_provider_voting_keys: collection.collection.provider_voting_keys.is_some(),
        has_provider_owner_keys: collection.collection.provider_owner_keys.is_some(),
        #[cfg(feature = "bls")]
        has_provider_operator_keys: collection.collection.provider_operator_keys.is_some(),
        #[cfg(feature = "eddsa")]
        has_provider_platform_keys: collection.collection.provider_platform_keys.is_some(),
    };

    Box::into_raw(Box::new(summary))
}

/// Free a managed account collection summary and all its allocated memory
///
/// # Safety
///
/// - `summary` must be a valid pointer to an FFIManagedAccountCollectionSummary created by `managed_account_collection_summary_data`
/// - `summary` must not be used after calling this function
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_summary_free(
    summary: *mut FFIManagedAccountCollectionSummary,
) {
    if !summary.is_null() {
        let summary = Box::from_raw(summary);

        // Free all the allocated arrays
        if !summary.bip44_indices.is_null() && summary.bip44_count > 0 {
            let _ = Vec::from_raw_parts(
                summary.bip44_indices,
                summary.bip44_count,
                summary.bip44_count,
            );
        }

        if !summary.bip32_indices.is_null() && summary.bip32_count > 0 {
            let _ = Vec::from_raw_parts(
                summary.bip32_indices,
                summary.bip32_count,
                summary.bip32_count,
            );
        }

        if !summary.coinjoin_indices.is_null() && summary.coinjoin_count > 0 {
            let _ = Vec::from_raw_parts(
                summary.coinjoin_indices,
                summary.coinjoin_count,
                summary.coinjoin_count,
            );
        }

        if !summary.identity_topup_indices.is_null() && summary.identity_topup_count > 0 {
            let _ = Vec::from_raw_parts(
                summary.identity_topup_indices,
                summary.identity_topup_count,
                summary.identity_topup_count,
            );
        }

        // The summary struct itself is dropped automatically when the Box is dropped
    }
}

// Platform Payment Account functions

/// FFI-compatible key for Platform Payment accounts
#[repr(C)]
pub struct FFIPlatformPaymentAccountKey {
    /// Account index (hardened)
    pub account: c_uint,
    /// Key class (hardened)
    pub key_class: c_uint,
}

/// Get a Platform Payment account by account index and key class
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - The returned pointer must be freed with `managed_platform_account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_get_platform_payment_account(
    collection: *const FFIManagedAccountCollection,
    account_index: c_uint,
    key_class: c_uint,
) -> *mut FFIManagedPlatformAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    let key = PlatformPaymentAccountKey {
        account: account_index,
        key_class,
    };

    match collection.collection.platform_payment_accounts.get(&key) {
        Some(account) => {
            match FFIManagedPlatformAccount::new(account) {
                Some(ffi_account) => Box::into_raw(Box::new(ffi_account)),
                None => ptr::null_mut(), // Not a PlatformPayment account type
            }
        }
        None => ptr::null_mut(),
    }
}

/// Get all Platform Payment account keys
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
/// - `out_keys` must be a valid pointer to store the keys array
/// - `out_count` must be a valid pointer to store the count
/// - The returned array must be freed with `managed_account_collection_free_platform_payment_keys` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_get_platform_payment_keys(
    collection: *const FFIManagedAccountCollection,
    out_keys: *mut *mut FFIPlatformPaymentAccountKey,
    out_count: *mut usize,
) -> bool {
    if collection.is_null() || out_keys.is_null() || out_count.is_null() {
        return false;
    }

    let collection = &*collection;
    let keys: Vec<FFIPlatformPaymentAccountKey> = collection
        .collection
        .platform_payment_accounts
        .keys()
        .map(|k| FFIPlatformPaymentAccountKey {
            account: k.account,
            key_class: k.key_class,
        })
        .collect();

    if keys.is_empty() {
        *out_keys = ptr::null_mut();
        *out_count = 0;
        return true;
    }

    let mut boxed_slice = keys.into_boxed_slice();
    let ptr = boxed_slice.as_mut_ptr();
    let len = boxed_slice.len();
    std::mem::forget(boxed_slice);

    *out_keys = ptr;
    *out_count = len;
    true
}

/// Free a Platform Payment account keys array
///
/// # Safety
///
/// - `keys` must be a valid pointer to an array created by `managed_account_collection_get_platform_payment_keys`
/// - `count` must match the count returned by `managed_account_collection_get_platform_payment_keys`
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_free_platform_payment_keys(
    keys: *mut FFIPlatformPaymentAccountKey,
    count: usize,
) {
    if !keys.is_null() && count > 0 {
        let _ = Vec::from_raw_parts(keys, count, count);
    }
}

/// Check if there are any Platform Payment accounts in the collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_has_platform_payment_accounts(
    collection: *const FFIManagedAccountCollection,
) -> bool {
    if collection.is_null() {
        return false;
    }

    let collection = &*collection;
    !collection.collection.platform_payment_accounts.is_empty()
}

/// Get the number of Platform Payment accounts in the collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIManagedAccountCollection
#[no_mangle]
pub unsafe extern "C" fn managed_account_collection_platform_payment_count(
    collection: *const FFIManagedAccountCollection,
) -> c_uint {
    if collection.is_null() {
        return 0;
    }

    let collection = &*collection;
    collection.collection.platform_payment_accounts.len() as c_uint
}
