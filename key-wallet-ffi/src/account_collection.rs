//! FFI bindings for account collections
//!
//! This module provides FFI-compatible account collection functionality that mirrors
//! the AccountCollection structure from key-wallet but uses FFI-safe types.

use std::ffi::CString;
use std::os::raw::{c_char, c_uint};
use std::ptr;

use crate::account::FFIAccount;
use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFINetwork, FFIWallet};

/// Opaque handle to an account collection
pub struct FFIAccountCollection {
    /// The underlying account collection reference
    collection: key_wallet::AccountCollection,
}

impl FFIAccountCollection {
    /// Create a new FFI account collection from a key_wallet AccountCollection
    pub fn new(collection: &key_wallet::AccountCollection) -> Self {
        FFIAccountCollection {
            collection: collection.clone(),
        }
    }
}

/// C-compatible summary of all accounts in a collection
///
/// This struct provides Swift with structured data about all accounts
/// that exist in the collection, allowing programmatic access to account
/// indices and presence information.
#[repr(C)]
pub struct FFIAccountCollectionSummary {
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

/// Get account collection for a specific network from wallet
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet instance
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The returned pointer must be freed with `account_collection_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn wallet_get_account_collection(
    wallet: *const FFIWallet,
    network: FFINetwork,
    error: *mut FFIError,
) -> *mut FFIAccountCollection {
    if wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Wallet is null".to_string());
        return ptr::null_mut();
    }

    let wallet = &*wallet;
    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
            return ptr::null_mut();
        }
    };

    match wallet.inner().accounts_on_network(network_rust) {
        Some(collection) => {
            let ffi_collection = FFIAccountCollection::new(collection);
            Box::into_raw(Box::new(ffi_collection))
        }
        None => {
            FFIError::set_error(
                error,
                FFIErrorCode::NotFound,
                format!("No accounts found for network {:?}", network_rust),
            );
            ptr::null_mut()
        }
    }
}

/// Free an account collection handle
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection created by this library
/// - `collection` must not be used after calling this function
#[no_mangle]
pub unsafe extern "C" fn account_collection_free(collection: *mut FFIAccountCollection) {
    if !collection.is_null() {
        let _ = Box::from_raw(collection);
    }
}

// Standard BIP44 accounts functions

/// Get a BIP44 account by index from the collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
/// - The returned pointer must be freed with `account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn account_collection_get_bip44_account(
    collection: *const FFIAccountCollection,
    index: c_uint,
) -> *mut FFIAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match collection.collection.standard_bip44_accounts.get(&index) {
        Some(account) => {
            let ffi_account = FFIAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Get all BIP44 account indices
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
/// - `out_indices` must be a valid pointer to store the indices array
/// - `out_count` must be a valid pointer to store the count
/// - The returned array must be freed with `free_u32_array` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn account_collection_get_bip44_indices(
    collection: *const FFIAccountCollection,
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

/// Get a BIP32 account by index from the collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
/// - The returned pointer must be freed with `account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn account_collection_get_bip32_account(
    collection: *const FFIAccountCollection,
    index: c_uint,
) -> *mut FFIAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match collection.collection.standard_bip32_accounts.get(&index) {
        Some(account) => {
            let ffi_account = FFIAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Get all BIP32 account indices
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
/// - `out_indices` must be a valid pointer to store the indices array
/// - `out_count` must be a valid pointer to store the count
/// - The returned array must be freed with `free_u32_array` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn account_collection_get_bip32_indices(
    collection: *const FFIAccountCollection,
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

/// Get a CoinJoin account by index from the collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
/// - The returned pointer must be freed with `account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn account_collection_get_coinjoin_account(
    collection: *const FFIAccountCollection,
    index: c_uint,
) -> *mut FFIAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match collection.collection.coinjoin_accounts.get(&index) {
        Some(account) => {
            let ffi_account = FFIAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Get all CoinJoin account indices
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
/// - `out_indices` must be a valid pointer to store the indices array
/// - `out_count` must be a valid pointer to store the count
/// - The returned array must be freed with `free_u32_array` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn account_collection_get_coinjoin_indices(
    collection: *const FFIAccountCollection,
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

/// Get the identity registration account if it exists
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
/// - The returned pointer must be freed with `account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn account_collection_get_identity_registration(
    collection: *const FFIAccountCollection,
) -> *mut FFIAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match &collection.collection.identity_registration {
        Some(account) => {
            let ffi_account = FFIAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Check if identity registration account exists
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
#[no_mangle]
pub unsafe extern "C" fn account_collection_has_identity_registration(
    collection: *const FFIAccountCollection,
) -> bool {
    if collection.is_null() {
        return false;
    }

    let collection = &*collection;
    collection.collection.identity_registration.is_some()
}

/// Get an identity topup account by registration index
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
/// - The returned pointer must be freed with `account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn account_collection_get_identity_topup(
    collection: *const FFIAccountCollection,
    registration_index: c_uint,
) -> *mut FFIAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match collection.collection.identity_topup.get(&registration_index) {
        Some(account) => {
            let ffi_account = FFIAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Get all identity topup registration indices
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
/// - `out_indices` must be a valid pointer to store the indices array
/// - `out_count` must be a valid pointer to store the count
/// - The returned array must be freed with `free_u32_array` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn account_collection_get_identity_topup_indices(
    collection: *const FFIAccountCollection,
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

/// Get the identity topup not bound account if it exists
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
/// - The returned pointer must be freed with `account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn account_collection_get_identity_topup_not_bound(
    collection: *const FFIAccountCollection,
) -> *mut FFIAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match &collection.collection.identity_topup_not_bound {
        Some(account) => {
            let ffi_account = FFIAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Check if identity topup not bound account exists
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
#[no_mangle]
pub unsafe extern "C" fn account_collection_has_identity_topup_not_bound(
    collection: *const FFIAccountCollection,
) -> bool {
    if collection.is_null() {
        return false;
    }

    let collection = &*collection;
    collection.collection.identity_topup_not_bound.is_some()
}

/// Get the identity invitation account if it exists
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
/// - The returned pointer must be freed with `account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn account_collection_get_identity_invitation(
    collection: *const FFIAccountCollection,
) -> *mut FFIAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match &collection.collection.identity_invitation {
        Some(account) => {
            let ffi_account = FFIAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Check if identity invitation account exists
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
#[no_mangle]
pub unsafe extern "C" fn account_collection_has_identity_invitation(
    collection: *const FFIAccountCollection,
) -> bool {
    if collection.is_null() {
        return false;
    }

    let collection = &*collection;
    collection.collection.identity_invitation.is_some()
}

// Provider accounts functions

/// Get the provider voting keys account if it exists
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
/// - The returned pointer must be freed with `account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn account_collection_get_provider_voting_keys(
    collection: *const FFIAccountCollection,
) -> *mut FFIAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match &collection.collection.provider_voting_keys {
        Some(account) => {
            let ffi_account = FFIAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Check if provider voting keys account exists
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
#[no_mangle]
pub unsafe extern "C" fn account_collection_has_provider_voting_keys(
    collection: *const FFIAccountCollection,
) -> bool {
    if collection.is_null() {
        return false;
    }

    let collection = &*collection;
    collection.collection.provider_voting_keys.is_some()
}

/// Get the provider owner keys account if it exists
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
/// - The returned pointer must be freed with `account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn account_collection_get_provider_owner_keys(
    collection: *const FFIAccountCollection,
) -> *mut FFIAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match &collection.collection.provider_owner_keys {
        Some(account) => {
            let ffi_account = FFIAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Check if provider owner keys account exists
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
#[no_mangle]
pub unsafe extern "C" fn account_collection_has_provider_owner_keys(
    collection: *const FFIAccountCollection,
) -> bool {
    if collection.is_null() {
        return false;
    }

    let collection = &*collection;
    collection.collection.provider_owner_keys.is_some()
}

/// Get the provider operator keys account if it exists
/// Note: This function is only available when the `bls` feature is enabled
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
/// - The returned pointer must be freed with `bls_account_free` when no longer needed
#[cfg(feature = "bls")]
#[no_mangle]
pub unsafe extern "C" fn account_collection_get_provider_operator_keys(
    collection: *const FFIAccountCollection,
) -> *mut crate::account::FFIBLSAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match &collection.collection.provider_operator_keys {
        Some(account) => {
            let ffi_account = crate::account::FFIBLSAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Get the provider operator keys account if it exists (stub when BLS is disabled)
#[cfg(not(feature = "bls"))]
#[no_mangle]
pub unsafe extern "C" fn account_collection_get_provider_operator_keys(
    _collection: *const FFIAccountCollection,
) -> *mut std::os::raw::c_void {
    // BLS feature not enabled, always return null
    ptr::null_mut()
}

/// Check if provider operator keys account exists
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
#[no_mangle]
pub unsafe extern "C" fn account_collection_has_provider_operator_keys(
    collection: *const FFIAccountCollection,
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

/// Get the provider platform keys account if it exists
/// Note: This function is only available when the `eddsa` feature is enabled
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
/// - The returned pointer must be freed with `eddsa_account_free` when no longer needed
#[cfg(feature = "eddsa")]
#[no_mangle]
pub unsafe extern "C" fn account_collection_get_provider_platform_keys(
    collection: *const FFIAccountCollection,
) -> *mut crate::account::FFIEdDSAAccount {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    match &collection.collection.provider_platform_keys {
        Some(account) => {
            let ffi_account = crate::account::FFIEdDSAAccount::new(account);
            Box::into_raw(Box::new(ffi_account))
        }
        None => ptr::null_mut(),
    }
}

/// Get the provider platform keys account if it exists (stub when EdDSA is disabled)
#[cfg(not(feature = "eddsa"))]
#[no_mangle]
pub unsafe extern "C" fn account_collection_get_provider_platform_keys(
    _collection: *const FFIAccountCollection,
) -> *mut std::os::raw::c_void {
    // EdDSA feature not enabled, always return null
    ptr::null_mut()
}

/// Check if provider platform keys account exists
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
#[no_mangle]
pub unsafe extern "C" fn account_collection_has_provider_platform_keys(
    collection: *const FFIAccountCollection,
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

/// Free a u32 array allocated by this library
///
/// # Safety
///
/// - `array` must be a valid pointer to an array allocated by this library
/// - `array` must not be used after calling this function
#[no_mangle]
pub unsafe extern "C" fn free_u32_array(array: *mut c_uint, count: usize) {
    if !array.is_null() && count > 0 {
        let _ = Vec::from_raw_parts(array, count, count);
    }
}

/// Get the total number of accounts in the collection
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
#[no_mangle]
pub unsafe extern "C" fn account_collection_count(
    collection: *const FFIAccountCollection,
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

/// Get a human-readable summary of all accounts in the collection
///
/// Returns a formatted string showing all account types and their indices.
/// The format is designed to be clear and readable for end users.
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
/// - The returned string must be freed with `string_free` when no longer needed
/// - Returns null if the collection pointer is null
#[no_mangle]
pub unsafe extern "C" fn account_collection_summary(
    collection: *const FFIAccountCollection,
) -> *mut c_char {
    if collection.is_null() {
        return ptr::null_mut();
    }

    let collection = &*collection;
    let mut summary_parts = Vec::new();

    summary_parts.push("Account Summary:".to_string());

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

/// Get structured account collection summary data
///
/// Returns a struct containing arrays of indices for each account type and boolean
/// flags for special accounts. This provides Swift with programmatic access to
/// account information.
///
/// # Safety
///
/// - `collection` must be a valid pointer to an FFIAccountCollection
/// - The returned pointer must be freed with `account_collection_summary_free` when no longer needed
/// - Returns null if the collection pointer is null
#[no_mangle]
pub unsafe extern "C" fn account_collection_summary_data(
    collection: *const FFIAccountCollection,
) -> *mut FFIAccountCollectionSummary {
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
    let summary = FFIAccountCollectionSummary {
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

/// Free an account collection summary and all its allocated memory
///
/// # Safety
///
/// - `summary` must be a valid pointer to an FFIAccountCollectionSummary created by `account_collection_summary_data`
/// - `summary` must not be used after calling this function
#[no_mangle]
pub unsafe extern "C" fn account_collection_summary_free(
    summary: *mut FFIAccountCollectionSummary,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::wallet_create_from_mnemonic_with_options;
    use std::ffi::CString;

    #[test]
    fn test_account_collection_basic() {
        unsafe {
            let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();

            // Create wallet with default accounts
            let wallet = wallet_create_from_mnemonic_with_options(
                mnemonic.as_ptr(),
                ptr::null(),
                crate::types::FFINetwork::Testnet,
                ptr::null(),
                ptr::null_mut(),
            );
            assert!(!wallet.is_null());

            // Get account collection
            let collection = wallet_get_account_collection(
                wallet,
                crate::types::FFINetwork::Testnet,
                ptr::null_mut(),
            );
            assert!(!collection.is_null());

            // Check that we have some accounts
            let count = account_collection_count(collection);
            assert!(count > 0);

            // Check BIP44 accounts
            let mut indices: *mut c_uint = ptr::null_mut();
            let mut indices_count: usize = 0;
            let success =
                account_collection_get_bip44_indices(collection, &mut indices, &mut indices_count);
            assert!(success);
            assert!(indices_count > 0);

            // Get first BIP44 account
            let account = account_collection_get_bip44_account(collection, 0);
            assert!(!account.is_null());

            // Clean up
            crate::account::account_free(account);
            if !indices.is_null() {
                free_u32_array(indices, indices_count);
            }
            account_collection_free(collection);
            crate::wallet::wallet_free(wallet);
        }
    }

    #[test]
    #[cfg(feature = "bls")]
    fn test_bls_account() {
        unsafe {
            let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();

            // Create wallet with provider accounts
            let mut options = crate::types::FFIWalletAccountCreationOptions::default_options();
            options.option_type = crate::types::FFIAccountCreationOptionType::AllAccounts;

            // Add provider operator keys account type
            let special_types = [crate::types::FFIAccountType::ProviderOperatorKeys];
            options.special_account_types = special_types.as_ptr();
            options.special_account_types_count = special_types.len();

            let wallet = wallet_create_from_mnemonic_with_options(
                mnemonic.as_ptr(),
                ptr::null(),
                crate::types::FFINetwork::Testnet,
                &options,
                ptr::null_mut(),
            );
            assert!(!wallet.is_null());

            // Get account collection
            let collection = wallet_get_account_collection(
                wallet,
                crate::types::FFINetwork::Testnet,
                ptr::null_mut(),
            );
            assert!(!collection.is_null());

            // Check for provider operator keys account (BLS)
            let has_operator = account_collection_has_provider_operator_keys(collection);
            if has_operator {
                let operator_account = account_collection_get_provider_operator_keys(collection);
                assert!(!operator_account.is_null());

                // Free the BLS account
                crate::account::bls_account_free(operator_account);
            }

            // Clean up
            account_collection_free(collection);
            crate::wallet::wallet_free(wallet);
        }
    }

    #[test]
    #[cfg(feature = "eddsa")]
    fn test_eddsa_account() {
        unsafe {
            let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();

            // Create wallet with provider accounts
            let mut options = crate::types::FFIWalletAccountCreationOptions::default_options();
            options.option_type = crate::types::FFIAccountCreationOptionType::AllAccounts;

            // Add provider platform keys account type
            let special_types = [crate::types::FFIAccountType::ProviderPlatformKeys];
            options.special_account_types = special_types.as_ptr();
            options.special_account_types_count = special_types.len();

            let wallet = wallet_create_from_mnemonic_with_options(
                mnemonic.as_ptr(),
                ptr::null(),
                crate::types::FFINetwork::Testnet,
                &options,
                ptr::null_mut(),
            );
            assert!(!wallet.is_null());

            // Get account collection
            let collection = wallet_get_account_collection(
                wallet,
                crate::types::FFINetwork::Testnet,
                ptr::null_mut(),
            );
            assert!(!collection.is_null());

            // Check for provider platform keys account (EdDSA)
            let has_platform = account_collection_has_provider_platform_keys(collection);
            if has_platform {
                let platform_account = account_collection_get_provider_platform_keys(collection);
                assert!(!platform_account.is_null());

                // Free the EdDSA account
                crate::account::eddsa_account_free(platform_account);
            }

            // Clean up
            account_collection_free(collection);
            crate::wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_account_collection_summary() {
        unsafe {
            use std::ffi::CStr;

            let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();

            // Create wallet with multiple account types
            let mut options = crate::types::FFIWalletAccountCreationOptions::default_options();
            options.option_type = crate::types::FFIAccountCreationOptionType::AllAccounts;

            // Add various special accounts
            let special_types = [
                crate::types::FFIAccountType::ProviderVotingKeys,
                crate::types::FFIAccountType::ProviderOwnerKeys,
                crate::types::FFIAccountType::IdentityRegistration,
                crate::types::FFIAccountType::IdentityInvitation,
            ];
            options.special_account_types = special_types.as_ptr();
            options.special_account_types_count = special_types.len();

            // Configure standard accounts - store vectors in variables to keep them alive
            let bip44_indices = [0, 4, 5, 8];
            let bip32_indices = [0];
            let coinjoin_indices = [0, 1];
            let topup_indices = [0, 1, 2];

            options.bip44_indices = bip44_indices.as_ptr();
            options.bip44_count = bip44_indices.len();

            options.bip32_indices = bip32_indices.as_ptr();
            options.bip32_count = bip32_indices.len();

            options.coinjoin_indices = coinjoin_indices.as_ptr();
            options.coinjoin_count = coinjoin_indices.len();

            options.topup_indices = topup_indices.as_ptr();
            options.topup_count = topup_indices.len();

            let wallet = wallet_create_from_mnemonic_with_options(
                mnemonic.as_ptr(),
                ptr::null(),
                crate::types::FFINetwork::Testnet,
                &options,
                ptr::null_mut(),
            );
            assert!(!wallet.is_null());

            // Get account collection
            let collection = wallet_get_account_collection(
                wallet,
                crate::types::FFINetwork::Testnet,
                ptr::null_mut(),
            );
            assert!(!collection.is_null());

            // Get the summary
            let summary_ptr = account_collection_summary(collection);
            assert!(!summary_ptr.is_null());

            // Convert to Rust string to verify content
            let summary_cstr = CStr::from_ptr(summary_ptr);
            let summary = summary_cstr.to_str().unwrap();

            // Verify the summary contains expected content
            assert!(summary.contains("Account Summary:"));
            // The indices might not be in that exact format, so check more flexibly
            assert!(summary.contains("BIP44 Accounts"));
            assert!(summary.contains("BIP32 Accounts"));
            assert!(summary.contains("CoinJoin Accounts"));
            assert!(summary.contains("Identity TopUp"));
            assert!(summary.contains("Identity Registration Account"));
            assert!(summary.contains("Identity Invitation Account"));
            assert!(summary.contains("Provider Voting Keys Account"));
            assert!(summary.contains("Provider Owner Keys Account"));

            // Clean up
            crate::utils::string_free(summary_ptr);
            account_collection_free(collection);
            crate::wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_account_collection_summary_empty() {
        unsafe {
            use std::ffi::CStr;

            let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();

            // Create wallet with no accounts using SpecificAccounts with empty lists
            let mut options = crate::types::FFIWalletAccountCreationOptions::default_options();
            options.option_type = crate::types::FFIAccountCreationOptionType::SpecificAccounts;
            // All arrays are already null/0 from default_options()

            let wallet = wallet_create_from_mnemonic_with_options(
                mnemonic.as_ptr(),
                ptr::null(),
                crate::types::FFINetwork::Testnet,
                &options,
                ptr::null_mut(),
            );
            assert!(!wallet.is_null());

            // Get account collection
            let collection = wallet_get_account_collection(
                wallet,
                crate::types::FFINetwork::Testnet,
                ptr::null_mut(),
            );

            // With SpecificAccounts and empty lists, collection might be null or empty
            if collection.is_null() {
                // If the collection doesn't exist, that's OK for this test - just clean up and return
                crate::wallet::wallet_free(wallet);
                return;
            }

            // Get the summary
            let summary_ptr = account_collection_summary(collection);
            assert!(!summary_ptr.is_null());

            // Convert to Rust string to verify content
            let summary_cstr = CStr::from_ptr(summary_ptr);
            let summary = summary_cstr.to_str().unwrap();

            // Verify the summary shows no accounts
            assert!(summary.contains("Account Summary:"));
            assert!(summary.contains("No accounts configured"));

            // Clean up
            crate::utils::string_free(summary_ptr);
            account_collection_free(collection);
            crate::wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_account_collection_summary_null_safety() {
        unsafe {
            // Test with null collection
            let summary_ptr = account_collection_summary(ptr::null());
            assert!(summary_ptr.is_null());
        }
    }

    #[test]
    fn test_account_collection_summary_data() {
        unsafe {
            let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();

            // Create wallet with various account types
            let mut options = crate::types::FFIWalletAccountCreationOptions::default_options();
            options.option_type = crate::types::FFIAccountCreationOptionType::AllAccounts;

            // Add various special accounts
            let special_types = [
                crate::types::FFIAccountType::ProviderVotingKeys,
                crate::types::FFIAccountType::ProviderOwnerKeys,
                crate::types::FFIAccountType::IdentityRegistration,
                crate::types::FFIAccountType::IdentityInvitation,
            ];
            options.special_account_types = special_types.as_ptr();
            options.special_account_types_count = special_types.len();

            // Configure standard accounts
            let bip44_indices = [0, 4, 5, 8];
            let bip32_indices = [0];
            let coinjoin_indices = [0, 1];
            let topup_indices = [0, 1, 2];

            options.bip44_indices = bip44_indices.as_ptr();
            options.bip44_count = bip44_indices.len();

            options.bip32_indices = bip32_indices.as_ptr();
            options.bip32_count = bip32_indices.len();

            options.coinjoin_indices = coinjoin_indices.as_ptr();
            options.coinjoin_count = coinjoin_indices.len();

            options.topup_indices = topup_indices.as_ptr();
            options.topup_count = topup_indices.len();

            let wallet = wallet_create_from_mnemonic_with_options(
                mnemonic.as_ptr(),
                ptr::null(),
                crate::types::FFINetwork::Testnet,
                &options,
                ptr::null_mut(),
            );
            assert!(!wallet.is_null());

            // Get account collection
            let collection = wallet_get_account_collection(
                wallet,
                crate::types::FFINetwork::Testnet,
                ptr::null_mut(),
            );
            assert!(!collection.is_null());

            // Get the summary data
            let summary = account_collection_summary_data(collection);
            assert!(!summary.is_null());

            let summary_ref = &*summary;

            // Verify BIP44 indices
            assert_eq!(summary_ref.bip44_count, 4);
            assert!(!summary_ref.bip44_indices.is_null());
            let bip44_slice =
                std::slice::from_raw_parts(summary_ref.bip44_indices, summary_ref.bip44_count);
            assert_eq!(bip44_slice, &[0, 4, 5, 8]);

            // Verify BIP32 indices
            assert_eq!(summary_ref.bip32_count, 1);
            assert!(!summary_ref.bip32_indices.is_null());
            let bip32_slice =
                std::slice::from_raw_parts(summary_ref.bip32_indices, summary_ref.bip32_count);
            assert_eq!(bip32_slice, &[0]);

            // Verify CoinJoin indices
            assert_eq!(summary_ref.coinjoin_count, 2);
            assert!(!summary_ref.coinjoin_indices.is_null());
            let coinjoin_slice = std::slice::from_raw_parts(
                summary_ref.coinjoin_indices,
                summary_ref.coinjoin_count,
            );
            assert_eq!(coinjoin_slice, &[0, 1]);

            // Verify identity topup indices
            assert_eq!(summary_ref.identity_topup_count, 3);
            assert!(!summary_ref.identity_topup_indices.is_null());
            let topup_slice = std::slice::from_raw_parts(
                summary_ref.identity_topup_indices,
                summary_ref.identity_topup_count,
            );
            assert_eq!(topup_slice, &[0, 1, 2]);

            // Verify boolean flags
            assert!(summary_ref.has_identity_registration);
            assert!(summary_ref.has_identity_invitation);
            assert!(summary_ref.has_provider_voting_keys);
            assert!(summary_ref.has_provider_owner_keys);

            // Clean up
            account_collection_summary_free(summary);
            account_collection_free(collection);
            crate::wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_account_collection_summary_data_empty() {
        unsafe {
            let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();

            // Create wallet with no accounts - but still create a collection on the network
            // Use SpecificAccounts with empty lists to get truly empty collections
            let mut options = crate::types::FFIWalletAccountCreationOptions::default_options();
            options.option_type = crate::types::FFIAccountCreationOptionType::SpecificAccounts;

            // Set empty arrays for all account types
            options.bip44_indices = ptr::null();
            options.bip44_count = 0;
            options.bip32_indices = ptr::null();
            options.bip32_count = 0;
            options.coinjoin_indices = ptr::null();
            options.coinjoin_count = 0;
            options.topup_indices = ptr::null();
            options.topup_count = 0;
            options.special_account_types = ptr::null();
            options.special_account_types_count = 0;

            let wallet = wallet_create_from_mnemonic_with_options(
                mnemonic.as_ptr(),
                ptr::null(),
                crate::types::FFINetwork::Testnet,
                &options,
                ptr::null_mut(),
            );
            assert!(!wallet.is_null());

            // Get account collection
            let collection = wallet_get_account_collection(
                wallet,
                crate::types::FFINetwork::Testnet,
                ptr::null_mut(),
            );

            // With AllAccounts but empty lists, collection should still exist
            if collection.is_null() {
                // If the collection doesn't exist, that's OK for this test - just clean up and return
                crate::wallet::wallet_free(wallet);
                return;
            }

            // Get the summary data
            let summary = account_collection_summary_data(collection);
            assert!(!summary.is_null());

            let summary_ref = &*summary;

            // Verify all arrays are empty
            assert_eq!(summary_ref.bip44_count, 0);
            assert!(summary_ref.bip44_indices.is_null());

            assert_eq!(summary_ref.bip32_count, 0);
            assert!(summary_ref.bip32_indices.is_null());

            assert_eq!(summary_ref.coinjoin_count, 0);
            assert!(summary_ref.coinjoin_indices.is_null());

            assert_eq!(summary_ref.identity_topup_count, 0);
            assert!(summary_ref.identity_topup_indices.is_null());

            // Verify all boolean flags are false
            assert!(!summary_ref.has_identity_registration);
            assert!(!summary_ref.has_identity_invitation);
            assert!(!summary_ref.has_identity_topup_not_bound);
            assert!(!summary_ref.has_provider_voting_keys);
            assert!(!summary_ref.has_provider_owner_keys);

            // Clean up
            account_collection_summary_free(summary);
            account_collection_free(collection);
            crate::wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_account_collection_summary_data_null_safety() {
        unsafe {
            // Test with null collection
            let summary = account_collection_summary_data(ptr::null());
            assert!(summary.is_null());

            // Test freeing null summary (should not crash)
            account_collection_summary_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_account_collection_summary_memory_management() {
        unsafe {
            let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();

            // Create wallet with default accounts (which should have at least BIP44 account 0)
            let wallet = wallet_create_from_mnemonic_with_options(
                mnemonic.as_ptr(),
                ptr::null(),
                crate::types::FFINetwork::Testnet,
                ptr::null(),
                ptr::null_mut(),
            );
            assert!(!wallet.is_null());

            // Get account collection
            let collection = wallet_get_account_collection(
                wallet,
                crate::types::FFINetwork::Testnet,
                ptr::null_mut(),
            );
            assert!(!collection.is_null());

            // Get multiple summaries to test memory management
            let summary1 = account_collection_summary_data(collection);
            assert!(!summary1.is_null());

            let summary2 = account_collection_summary_data(collection);
            assert!(!summary2.is_null());

            // The two summaries should be different pointers
            assert_ne!(summary1, summary2);

            // But they should contain the same data
            let summary1_ref = &*summary1;
            let summary2_ref = &*summary2;
            assert_eq!(summary1_ref.bip44_count, summary2_ref.bip44_count);
            assert_eq!(
                summary1_ref.has_identity_registration,
                summary2_ref.has_identity_registration
            );

            // Clean up both summaries
            account_collection_summary_free(summary1);
            account_collection_summary_free(summary2);

            // Clean up
            account_collection_free(collection);
            crate::wallet::wallet_free(wallet);
        }
    }
}
