//! Account management functions

use std::os::raw::c_uint;
use std::sync::Arc;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFIAccountResult, FFIAccountType, FFINetwork, FFIWallet};
#[cfg(feature = "bls")]
use key_wallet::account::BLSAccount;
#[cfg(feature = "eddsa")]
use key_wallet::account::EdDSAAccount;

/// Opaque account handle
pub struct FFIAccount {
    pub(crate) account: Arc<key_wallet::Account>,
}

impl FFIAccount {
    /// Create a new FFI account handle
    pub fn new(account: &key_wallet::Account) -> Self {
        FFIAccount {
            account: Arc::new(account.clone()),
        }
    }

    /// Get a reference to the inner account
    pub fn inner(&self) -> &key_wallet::Account {
        self.account.as_ref()
    }
}

/// Opaque BLS account handle
#[cfg(feature = "bls")]
pub struct FFIBLSAccount {
    pub(crate) account: Arc<BLSAccount>,
}

#[cfg(feature = "bls")]
impl FFIBLSAccount {
    /// Create a new FFI BLS account handle
    pub fn new(account: &BLSAccount) -> Self {
        FFIBLSAccount {
            account: Arc::new(account.clone()),
        }
    }

    /// Get a reference to the inner BLS account
    pub fn inner(&self) -> &BLSAccount {
        self.account.as_ref()
    }
}

/// Opaque EdDSA account handle
#[cfg(feature = "eddsa")]
pub struct FFIEdDSAAccount {
    pub(crate) account: Arc<EdDSAAccount>,
}

#[cfg(feature = "eddsa")]
impl FFIEdDSAAccount {
    /// Create a new FFI EdDSA account handle
    pub fn new(account: &EdDSAAccount) -> Self {
        FFIEdDSAAccount {
            account: Arc::new(account.clone()),
        }
    }

    /// Get a reference to the inner EdDSA account
    pub fn inner(&self) -> &EdDSAAccount {
        self.account.as_ref()
    }
}

/// Get an account handle for a specific account type
/// Returns a result containing either the account handle or an error
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet instance
/// - The caller must ensure the wallet pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_get_account(
    wallet: *const FFIWallet,
    account_index: c_uint,
    account_type: FFIAccountType,
) -> FFIAccountResult {
    if wallet.is_null() {
        return FFIAccountResult::error(FFIErrorCode::InvalidInput, "Wallet is null".to_string());
    }

    let wallet = &*wallet;
    let account_type_rust = account_type.to_account_type(account_index);

    match wallet.inner().accounts.account_of_type(account_type_rust) {
        Some(account) => {
            let ffi_account = FFIAccount::new(account);
            FFIAccountResult::success(Box::into_raw(Box::new(ffi_account)))
        }
        None => FFIAccountResult::error(FFIErrorCode::NotFound, "Account not found".to_string()),
    }
}

/// Get an IdentityTopUp account handle with a specific registration index
/// This is used for top-up accounts that are bound to a specific identity
/// Returns a result containing either the account handle or an error
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet instance
/// - The caller must ensure the wallet pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_get_top_up_account_with_registration_index(
    wallet: *const FFIWallet,
    registration_index: c_uint,
) -> FFIAccountResult {
    if wallet.is_null() {
        return FFIAccountResult::error(FFIErrorCode::InvalidInput, "Wallet is null".to_string());
    }

    let wallet = &*wallet;

    // This function is specifically for IdentityTopUp accounts
    let account_type = key_wallet::AccountType::IdentityTopUp {
        registration_index,
    };

    match wallet.inner().accounts.account_of_type(account_type) {
        Some(account) => {
            let ffi_account = FFIAccount::new(account);
            FFIAccountResult::success(Box::into_raw(Box::new(ffi_account)))
        }
        None => FFIAccountResult::error(
            FFIErrorCode::NotFound,
            format!(
                "IdentityTopUp account for registration index {} not found",
                registration_index
            ),
        ),
    }
}

/// Free an account handle
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIAccount that was allocated by this library
/// - The pointer must not be used after calling this function
/// - This function must only be called once per allocation
#[no_mangle]
pub unsafe extern "C" fn account_free(account: *mut FFIAccount) {
    if !account.is_null() {
        let _ = Box::from_raw(account);
    }
}

/// Free a BLS account handle
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIBLSAccount
/// - The pointer must not be used after calling this function
/// - This function must only be called once per allocation
#[cfg(feature = "bls")]
#[no_mangle]
pub unsafe extern "C" fn bls_account_free(account: *mut FFIBLSAccount) {
    if !account.is_null() {
        let _ = Box::from_raw(account);
    }
}

/// Free an EdDSA account handle
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIEdDSAAccount
/// - The pointer must not be used after calling this function
/// - This function must only be called once per allocation
#[cfg(feature = "eddsa")]
#[no_mangle]
pub unsafe extern "C" fn eddsa_account_free(account: *mut FFIEdDSAAccount) {
    if !account.is_null() {
        let _ = Box::from_raw(account);
    }
}

/// Free an account result's error message (if any)
/// Note: This does NOT free the account handle itself - use account_free for that
///
/// # Safety
///
/// - `result` must be a valid pointer to an FFIAccountResult
/// - The error_message field must be either null or a valid CString allocated by this library
/// - The caller must ensure the result pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn account_result_free_error(result: *mut FFIAccountResult) {
    if !result.is_null() {
        let result = &mut *result;
        if !result.error_message.is_null() {
            let _ = std::ffi::CString::from_raw(result.error_message);
            result.error_message = std::ptr::null_mut();
        }
    }
}

/// Get the extended public key of an account as a string
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIAccount instance
/// - The returned string must be freed by the caller using `string_free`
/// - Returns NULL if the account is null
#[no_mangle]
pub unsafe extern "C" fn account_get_extended_public_key_as_string(
    account: *const FFIAccount,
) -> *mut std::os::raw::c_char {
    if account.is_null() {
        return std::ptr::null_mut();
    }

    let account = &*account;
    let xpub = account.inner().extended_public_key();

    match std::ffi::CString::new(xpub.to_string()) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get the network of an account
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIAccount instance
/// - Returns `FFINetwork::Dash` if the account is null
#[no_mangle]
pub unsafe extern "C" fn account_get_network(account: *const FFIAccount) -> FFINetwork {
    if account.is_null() {
        return FFINetwork::Dash;
    }

    let account = &*account;
    account.inner().network.into()
}

/// Get the parent wallet ID of an account
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIAccount instance
/// - Returns a pointer to the 32-byte wallet ID, or NULL if not set or account is null
/// - The returned pointer is valid only as long as the account exists
/// - The caller should copy the data if needed for longer use
#[no_mangle]
pub unsafe extern "C" fn account_get_parent_wallet_id(account: *const FFIAccount) -> *const u8 {
    if account.is_null() {
        return std::ptr::null();
    }

    let account = &*account;
    match account.inner().parent_wallet_id {
        Some(ref id) => id.as_ptr(),
        None => std::ptr::null(),
    }
}

/// Get the account type of an account
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIAccount instance
/// - `out_index` must be a valid pointer to a c_uint where the index will be stored
/// - Returns FFIAccountType::StandardBIP44 with index 0 if the account is null
#[no_mangle]
pub unsafe extern "C" fn account_get_account_type(
    account: *const FFIAccount,
    out_index: *mut c_uint,
) -> FFIAccountType {
    if account.is_null() || out_index.is_null() {
        if !out_index.is_null() {
            *out_index = 0;
        }
        return FFIAccountType::StandardBIP44;
    }

    let account = &*account;
    let (account_type, index, registration_index) =
        FFIAccountType::from_account_type(&account.inner().account_type);

    // For IdentityTopUp, the registration_index is the relevant index
    *out_index = registration_index.unwrap_or(index);

    account_type
}

/// Check if an account is watch-only
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIAccount instance
/// - Returns false if the account is null
#[no_mangle]
pub unsafe extern "C" fn account_get_is_watch_only(account: *const FFIAccount) -> bool {
    if account.is_null() {
        return false;
    }

    let account = &*account;
    account.inner().is_watch_only
}

// BLS account getter functions
/// Get the extended public key of a BLS account as a string
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIBLSAccount instance
/// - The returned string must be freed by the caller using `string_free`
/// - Returns NULL if the account is null
#[cfg(feature = "bls")]
#[no_mangle]
pub unsafe extern "C" fn bls_account_get_extended_public_key_as_string(
    account: *const FFIBLSAccount,
) -> *mut std::os::raw::c_char {
    if account.is_null() {
        return std::ptr::null_mut();
    }

    let account = &*account;
    // For BLS accounts, we need to encode the extended public key bytes
    // There's no standard string representation for BLS extended keys
    let bytes = account.inner().bls_public_key.to_bytes();
    let hex_string = hex::encode(bytes);

    match std::ffi::CString::new(hex_string) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get the network of a BLS account
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIBLSAccount instance
/// - Returns `FFINetwork::Dash` if the account is null
#[cfg(feature = "bls")]
#[no_mangle]
pub unsafe extern "C" fn bls_account_get_network(account: *const FFIBLSAccount) -> FFINetwork {
    if account.is_null() {
        return FFINetwork::Dash;
    }

    let account = &*account;
    account.inner().network.into()
}

/// Get the parent wallet ID of a BLS account
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIBLSAccount instance
/// - Returns a pointer to the 32-byte wallet ID, or NULL if not set or account is null
/// - The returned pointer is valid only as long as the account exists
/// - The caller should copy the data if needed for longer use
#[cfg(feature = "bls")]
#[no_mangle]
pub unsafe extern "C" fn bls_account_get_parent_wallet_id(
    account: *const FFIBLSAccount,
) -> *const u8 {
    if account.is_null() {
        return std::ptr::null();
    }

    let account = &*account;
    match &account.inner().parent_wallet_id {
        Some(id) => id.as_ptr(),
        None => std::ptr::null(),
    }
}

/// Get the account type of a BLS account
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIBLSAccount instance
/// - `out_index` must be a valid pointer to a c_uint where the index will be stored
/// - Returns FFIAccountType::StandardBIP44 with index 0 if the account is null
#[cfg(feature = "bls")]
#[no_mangle]
pub unsafe extern "C" fn bls_account_get_account_type(
    account: *const FFIBLSAccount,
    out_index: *mut c_uint,
) -> FFIAccountType {
    if account.is_null() || out_index.is_null() {
        if !out_index.is_null() {
            *out_index = 0;
        }
        return FFIAccountType::StandardBIP44;
    }

    let account = &*account;
    let (account_type, index, registration_index) =
        FFIAccountType::from_account_type(&account.inner().account_type);

    // For IdentityTopUp, the registration_index is the relevant index
    *out_index = registration_index.unwrap_or(index);

    account_type
}

/// Check if a BLS account is watch-only
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIBLSAccount instance
/// - Returns false if the account is null
#[cfg(feature = "bls")]
#[no_mangle]
pub unsafe extern "C" fn bls_account_get_is_watch_only(account: *const FFIBLSAccount) -> bool {
    if account.is_null() {
        return false;
    }

    let account = &*account;
    account.inner().is_watch_only
}

// EdDSA account getter functions
/// Get the extended public key of an EdDSA account as a string
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIEdDSAAccount instance
/// - The returned string must be freed by the caller using `string_free`
/// - Returns NULL if the account is null
#[cfg(feature = "eddsa")]
#[no_mangle]
pub unsafe extern "C" fn eddsa_account_get_extended_public_key_as_string(
    account: *const FFIEdDSAAccount,
) -> *mut std::os::raw::c_char {
    if account.is_null() {
        return std::ptr::null_mut();
    }

    let account = &*account;
    // For EdDSA accounts, we need to encode the extended public key
    // There's no standard string representation for Ed25519 extended keys
    let bytes = account.inner().ed25519_public_key.encode();
    let hex_string = hex::encode(bytes);

    match std::ffi::CString::new(hex_string) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get the network of an EdDSA account
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIEdDSAAccount instance
/// - Returns `FFINetwork::Dash` if the account is null
#[cfg(feature = "eddsa")]
#[no_mangle]
pub unsafe extern "C" fn eddsa_account_get_network(account: *const FFIEdDSAAccount) -> FFINetwork {
    if account.is_null() {
        return FFINetwork::Dash;
    }

    let account = &*account;
    account.inner().network.into()
}

/// Get the parent wallet ID of an EdDSA account
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIEdDSAAccount instance
/// - Returns a pointer to the 32-byte wallet ID, or NULL if not set or account is null
/// - The returned pointer is valid only as long as the account exists
/// - The caller should copy the data if needed for longer use
#[cfg(feature = "eddsa")]
#[no_mangle]
pub unsafe extern "C" fn eddsa_account_get_parent_wallet_id(
    account: *const FFIEdDSAAccount,
) -> *const u8 {
    if account.is_null() {
        return std::ptr::null();
    }

    let account = &*account;
    match &account.inner().parent_wallet_id {
        Some(id) => id.as_ptr(),
        None => std::ptr::null(),
    }
}

/// Get the account type of an EdDSA account
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIEdDSAAccount instance
/// - `out_index` must be a valid pointer to a c_uint where the index will be stored
/// - Returns FFIAccountType::StandardBIP44 with index 0 if the account is null
#[cfg(feature = "eddsa")]
#[no_mangle]
pub unsafe extern "C" fn eddsa_account_get_account_type(
    account: *const FFIEdDSAAccount,
    out_index: *mut c_uint,
) -> FFIAccountType {
    if account.is_null() || out_index.is_null() {
        if !out_index.is_null() {
            *out_index = 0;
        }
        return FFIAccountType::StandardBIP44;
    }

    let account = &*account;
    let (account_type, index, registration_index) =
        FFIAccountType::from_account_type(&account.inner().account_type);

    // For IdentityTopUp, the registration_index is the relevant index
    *out_index = registration_index.unwrap_or(index);

    account_type
}

/// Check if an EdDSA account is watch-only
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIEdDSAAccount instance
/// - Returns false if the account is null
#[cfg(feature = "eddsa")]
#[no_mangle]
pub unsafe extern "C" fn eddsa_account_get_is_watch_only(account: *const FFIEdDSAAccount) -> bool {
    if account.is_null() {
        return false;
    }

    let account = &*account;
    account.inner().is_watch_only
}

/// Get number of accounts
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet instance
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure both pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_get_account_count(
    wallet: *const FFIWallet,
    error: *mut FFIError,
) -> c_uint {
    if wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Wallet is null".to_string());
        return 0;
    }

    let wallet = &*wallet;
    let accounts = &wallet.inner().accounts;
    FFIError::set_success(error);
    let count = accounts.standard_bip44_accounts.len()
        + accounts.standard_bip32_accounts.len()
        + accounts.coinjoin_accounts.len()
        + accounts.identity_registration.is_some() as usize
        + accounts.identity_topup.len();
    count as c_uint
}

#[cfg(test)]
#[path = "account_tests.rs"]
mod tests;
