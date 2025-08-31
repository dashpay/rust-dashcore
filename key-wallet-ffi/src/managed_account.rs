//! Managed account FFI bindings
//!
//! This module provides FFI-compatible managed account functionality that wraps
//! ManagedAccount instances from the key-wallet crate. FFIManagedAccount is a
//! simple wrapper around Arc<ManagedAccount> without additional fields.

use std::os::raw::c_uint;
use std::sync::Arc;

use crate::address_pool::{FFIAddressPool, FFIAddressPoolType};
use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFIAccountType, FFINetworks};
use crate::wallet_manager::FFIWalletManager;
use key_wallet::managed_account::address_pool::AddressPool;
use key_wallet::managed_account::ManagedAccount;
use key_wallet::AccountType;

/// Opaque managed account handle that wraps ManagedAccount
pub struct FFIManagedAccount {
    /// The underlying managed account
    pub(crate) account: Arc<ManagedAccount>,
}

impl FFIManagedAccount {
    /// Create a new FFI managed account handle
    pub fn new(account: &ManagedAccount) -> Self {
        FFIManagedAccount {
            account: Arc::new(account.clone()),
        }
    }

    /// Get a reference to the inner managed account
    pub fn inner(&self) -> &ManagedAccount {
        self.account.as_ref()
    }
}

/// FFI Result type for ManagedAccount operations
#[repr(C)]
pub struct FFIManagedAccountResult {
    /// The managed account handle if successful, NULL if error
    pub account: *mut FFIManagedAccount,
    /// Error code (0 = success)
    pub error_code: i32,
    /// Error message (NULL if success, must be freed by caller if not NULL)
    pub error_message: *mut std::os::raw::c_char,
}

impl FFIManagedAccountResult {
    /// Create a success result
    pub fn success(account: *mut FFIManagedAccount) -> Self {
        FFIManagedAccountResult {
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
        FFIManagedAccountResult {
            account: std::ptr::null_mut(),
            error_code: code as i32,
            error_message: c_message.into_raw(),
        }
    }
}

/// Get a managed account from a managed wallet
///
/// This function gets a ManagedAccount from the wallet manager's managed wallet info,
/// returning a managed account handle that wraps the ManagedAccount.
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `wallet_id` must be a valid pointer to a 32-byte wallet ID
/// - `network` must specify exactly one network
/// - The caller must ensure all pointers remain valid for the duration of this call
/// - The returned account must be freed with `managed_account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_get_account(
    manager: *const FFIWalletManager,
    wallet_id: *const u8,
    network: FFINetworks,
    account_index: c_uint,
    account_type: FFIAccountType,
) -> FFIManagedAccountResult {
    if manager.is_null() {
        return FFIManagedAccountResult::error(
            FFIErrorCode::InvalidInput,
            "Manager is null".to_string(),
        );
    }

    if wallet_id.is_null() {
        return FFIManagedAccountResult::error(
            FFIErrorCode::InvalidInput,
            "Wallet ID is null".to_string(),
        );
    }

    // Convert wallet_id to array
    let mut wallet_id_array = [0u8; 32];
    std::ptr::copy_nonoverlapping(wallet_id, wallet_id_array.as_mut_ptr(), 32);

    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            return FFIManagedAccountResult::error(
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
        }
    };

    // Get the managed wallet info from the manager
    let mut error = FFIError::success();
    let managed_wallet_ptr = crate::wallet_manager::wallet_manager_get_managed_wallet_info(
        manager, wallet_id, &mut error,
    );

    if managed_wallet_ptr.is_null() {
        return FFIManagedAccountResult::error(
            error.code,
            if error.message.is_null() {
                "Failed to get managed wallet info".to_string()
            } else {
                let c_str = std::ffi::CStr::from_ptr(error.message);
                c_str.to_string_lossy().to_string()
            },
        );
    }

    let managed_wallet = &*managed_wallet_ptr;
    let account_type_rust = account_type.to_account_type(account_index);

    // Get the managed account from the managed wallet info
    let result = match managed_wallet.inner().accounts.get(&network_rust) {
        Some(managed_collection) => {
            use key_wallet::account::StandardAccountType;

            let managed_account = match account_type_rust {
                AccountType::Standard {
                    index,
                    standard_account_type,
                } => match standard_account_type {
                    StandardAccountType::BIP44Account => {
                        managed_collection.standard_bip44_accounts.get(&index)
                    }
                    StandardAccountType::BIP32Account => {
                        managed_collection.standard_bip32_accounts.get(&index)
                    }
                },
                AccountType::CoinJoin {
                    index,
                } => managed_collection.coinjoin_accounts.get(&index),
                AccountType::IdentityRegistration => {
                    managed_collection.identity_registration.as_ref()
                }
                AccountType::IdentityTopUp {
                    registration_index,
                } => managed_collection.identity_topup.get(&registration_index),
                AccountType::IdentityTopUpNotBoundToIdentity => {
                    managed_collection.identity_topup_not_bound.as_ref()
                }
                AccountType::IdentityInvitation => managed_collection.identity_invitation.as_ref(),
                AccountType::ProviderVotingKeys => managed_collection.provider_voting_keys.as_ref(),
                AccountType::ProviderOwnerKeys => managed_collection.provider_owner_keys.as_ref(),
                AccountType::ProviderOperatorKeys => {
                    managed_collection.provider_operator_keys.as_ref()
                }
                AccountType::ProviderPlatformKeys => {
                    managed_collection.provider_platform_keys.as_ref()
                }
            };

            match managed_account {
                Some(account) => {
                    let ffi_account = FFIManagedAccount::new(account);
                    FFIManagedAccountResult::success(Box::into_raw(Box::new(ffi_account)))
                }
                None => FFIManagedAccountResult::error(
                    FFIErrorCode::NotFound,
                    "Account not found".to_string(),
                ),
            }
        }
        None => FFIManagedAccountResult::error(
            FFIErrorCode::NotFound,
            format!("No accounts found for network {:?}, wallet has networks {:?}", network_rust, managed_wallet.inner().networks_supported()),
        ),
    };

    // Clean up the managed wallet pointer
    crate::managed_wallet::managed_wallet_info_free(managed_wallet_ptr);

    result
}

/// Get a managed IdentityTopUp account with a specific registration index
///
/// This is used for top-up accounts that are bound to a specific identity.
/// Returns a managed account handle that wraps the ManagedAccount.
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `wallet_id` must be a valid pointer to a 32-byte wallet ID
/// - `network` must specify exactly one network
/// - The caller must ensure all pointers remain valid for the duration of this call
/// - The returned account must be freed with `managed_account_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_get_top_up_account_with_registration_index(
    manager: *const FFIWalletManager,
    wallet_id: *const u8,
    network: FFINetworks,
    registration_index: c_uint,
) -> FFIManagedAccountResult {
    if manager.is_null() {
        return FFIManagedAccountResult::error(
            FFIErrorCode::InvalidInput,
            "Manager is null".to_string(),
        );
    }

    if wallet_id.is_null() {
        return FFIManagedAccountResult::error(
            FFIErrorCode::InvalidInput,
            "Wallet ID is null".to_string(),
        );
    }

    // Convert wallet_id to array
    let mut wallet_id_array = [0u8; 32];
    std::ptr::copy_nonoverlapping(wallet_id, wallet_id_array.as_mut_ptr(), 32);

    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            return FFIManagedAccountResult::error(
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
        }
    };

    // Get the managed wallet info from the manager
    let mut error = FFIError::success();
    let managed_wallet_ptr = crate::wallet_manager::wallet_manager_get_managed_wallet_info(
        manager, wallet_id, &mut error,
    );

    if managed_wallet_ptr.is_null() {
        return FFIManagedAccountResult::error(
            error.code,
            if error.message.is_null() {
                "Failed to get managed wallet info".to_string()
            } else {
                let c_str = std::ffi::CStr::from_ptr(error.message);
                c_str.to_string_lossy().to_string()
            },
        );
    }

    let managed_wallet = &*managed_wallet_ptr;

    // Get the IdentityTopUp account from the managed collection
    let result = match managed_wallet.inner().accounts.get(&network_rust) {
        Some(managed_collection) => {
            match managed_collection.identity_topup.get(&registration_index) {
                Some(account) => {
                    let ffi_account = FFIManagedAccount::new(account);
                    FFIManagedAccountResult::success(Box::into_raw(Box::new(ffi_account)))
                }
                None => FFIManagedAccountResult::error(
                    FFIErrorCode::NotFound,
                    format!(
                        "IdentityTopUp account for registration index {} not found",
                        registration_index
                    ),
                ),
            }
        }
        None => FFIManagedAccountResult::error(
            FFIErrorCode::NotFound,
            format!("No accounts found for network {:?}, wallet has networks {:?}", network_rust, managed_wallet.inner().networks_supported()),
        ),
    };

    // Clean up the managed wallet pointer
    crate::managed_wallet::managed_wallet_info_free(managed_wallet_ptr);

    result
}

/// Get the network of a managed account
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedAccount instance
#[no_mangle]
pub unsafe extern "C" fn managed_account_get_network(
    account: *const FFIManagedAccount,
) -> FFINetworks {
    if account.is_null() {
        return FFINetworks::NoNetworks;
    }

    let account = &*account;
    account.inner().network.into()
}

/// Get the parent wallet ID of a managed account
///
/// Note: ManagedAccount doesn't store the parent wallet ID directly.
/// The wallet ID is typically known from the context (e.g., when getting the account from a managed wallet).
///
/// # Safety
///
/// - `wallet_id` must be a valid pointer to a 32-byte wallet ID buffer that was provided by the caller
/// - The returned pointer is the same as the input pointer for convenience
/// - The caller must not free the returned pointer as it's the same as the input
#[no_mangle]
pub unsafe extern "C" fn managed_account_get_parent_wallet_id(wallet_id: *const u8) -> *const u8 {
    // Simply return the wallet_id that was passed in
    // This function exists for API consistency but ManagedAccount doesn't store parent wallet ID
    wallet_id
}

/// Get the account type of a managed account
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedAccount instance
/// - `index_out` must be a valid pointer to receive the account index (or null)
#[no_mangle]
pub unsafe extern "C" fn managed_account_get_account_type(
    account: *const FFIManagedAccount,
    index_out: *mut c_uint,
) -> FFIAccountType {
    if account.is_null() {
        return FFIAccountType::StandardBIP44; // Default type
    }

    let account = &*account;
    let managed_account = account.inner();
    let account_type_rust = managed_account.account_type.to_account_type();

    // Set the index if output pointer is provided
    if !index_out.is_null() {
        *index_out = account_type_rust.index().unwrap_or(0);
    }

    // Convert to FFI account type
    match account_type_rust {
        AccountType::Standard {
            standard_account_type,
            ..
        } => {
            use key_wallet::account::StandardAccountType;
            match standard_account_type {
                StandardAccountType::BIP44Account => FFIAccountType::StandardBIP44,
                StandardAccountType::BIP32Account => FFIAccountType::StandardBIP32,
            }
        }
        AccountType::CoinJoin {
            ..
        } => FFIAccountType::CoinJoin,
        AccountType::IdentityRegistration => FFIAccountType::IdentityRegistration,
        AccountType::IdentityTopUp {
            ..
        } => FFIAccountType::IdentityTopUp,
        AccountType::IdentityTopUpNotBoundToIdentity => {
            FFIAccountType::IdentityTopUpNotBoundToIdentity
        }
        AccountType::IdentityInvitation => FFIAccountType::IdentityInvitation,
        AccountType::ProviderVotingKeys => FFIAccountType::ProviderVotingKeys,
        AccountType::ProviderOwnerKeys => FFIAccountType::ProviderOwnerKeys,
        AccountType::ProviderOperatorKeys => FFIAccountType::ProviderOperatorKeys,
        AccountType::ProviderPlatformKeys => FFIAccountType::ProviderPlatformKeys,
    }
}

/// Check if a managed account is watch-only
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedAccount instance
#[no_mangle]
pub unsafe extern "C" fn managed_account_get_is_watch_only(
    account: *const FFIManagedAccount,
) -> bool {
    if account.is_null() {
        return false;
    }

    let account = &*account;
    account.inner().is_watch_only
}

/// Get the balance of a managed account
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedAccount instance
/// - `balance_out` must be a valid pointer to an FFIBalance structure
#[no_mangle]
pub unsafe extern "C" fn managed_account_get_balance(
    account: *const FFIManagedAccount,
    balance_out: *mut crate::types::FFIBalance,
) -> bool {
    if account.is_null() || balance_out.is_null() {
        return false;
    }

    let account = &*account;
    let balance = &account.inner().balance;

    *balance_out = crate::types::FFIBalance {
        confirmed: balance.confirmed,
        unconfirmed: balance.unconfirmed,
        immature: 0, // WalletBalance doesn't have immature field
        total: balance.total,
    };

    true
}

/// Get the number of transactions in a managed account
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedAccount instance
#[no_mangle]
pub unsafe extern "C" fn managed_account_get_transaction_count(
    account: *const FFIManagedAccount,
) -> c_uint {
    if account.is_null() {
        return 0;
    }

    let account = &*account;
    account.inner().transactions.len() as c_uint
}

/// Get the number of UTXOs in a managed account
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedAccount instance
#[no_mangle]
pub unsafe extern "C" fn managed_account_get_utxo_count(
    account: *const FFIManagedAccount,
) -> c_uint {
    if account.is_null() {
        return 0;
    }

    let account = &*account;
    account.inner().utxos.len() as c_uint
}

/// Free a managed account handle
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedAccount that was allocated by this library
/// - The pointer must not be used after calling this function
/// - This function must only be called once per allocation
#[no_mangle]
pub unsafe extern "C" fn managed_account_free(account: *mut FFIManagedAccount) {
    if !account.is_null() {
        let _ = Box::from_raw(account);
    }
}

/// Free a managed account result's error message (if any)
/// Note: This does NOT free the account handle itself - use managed_account_free for that
///
/// # Safety
///
/// - `result` must be a valid pointer to an FFIManagedAccountResult
/// - The error_message field must be either null or a valid CString allocated by this library
/// - The caller must ensure the result pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn managed_account_result_free_error(result: *mut FFIManagedAccountResult) {
    if !result.is_null() {
        let result = &mut *result;
        if !result.error_message.is_null() {
            let _ = std::ffi::CString::from_raw(result.error_message);
            result.error_message = std::ptr::null_mut();
        }
    }
}

/// Get number of accounts in a managed wallet
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `wallet_id` must be a valid pointer to a 32-byte wallet ID
/// - `network` must specify exactly one network
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_get_account_count(
    manager: *const FFIWalletManager,
    wallet_id: *const u8,
    network: FFINetworks,
    error: *mut FFIError,
) -> c_uint {
    if manager.is_null() || wallet_id.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return 0;
    }

    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
            return 0;
        }
    };

    // Get the wallet from the manager
    let wallet_ptr = crate::wallet_manager::wallet_manager_get_wallet(manager, wallet_id, error);

    if wallet_ptr.is_null() {
        // Error already set by wallet_manager_get_wallet
        return 0;
    }

    let wallet = &*wallet_ptr;
    let count = match wallet.inner().accounts.get(&network_rust) {
        Some(accounts) => {
            FFIError::set_success(error);
            let count = accounts.standard_bip44_accounts.len()
                + accounts.standard_bip32_accounts.len()
                + accounts.coinjoin_accounts.len()
                + accounts.identity_registration.is_some() as usize
                + accounts.identity_topup.len();
            count as c_uint
        }
        None => {
            FFIError::set_success(error);
            0
        }
    };

    // Clean up the wallet pointer
    crate::wallet::wallet_free_const(wallet_ptr);

    count
}

// Note: BLS and EdDSA accounts are handled through regular FFIManagedAccount
// since ManagedAccountCollection stores all accounts as ManagedAccount type

/// Get the account index from a managed account
///
/// Returns the primary account index for Standard and CoinJoin accounts.
/// Returns 0 for account types that don't have an index (like Identity or Provider accounts).
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedAccount instance
#[no_mangle]
pub unsafe extern "C" fn managed_account_get_index(account: *const FFIManagedAccount) -> c_uint {
    if account.is_null() {
        return 0;
    }

    let account = &*account;
    account.inner().account_type.index_or_default()
}

/// Get the external address pool from a managed account
///
/// This function returns the external (receive) address pool for Standard accounts.
/// Returns NULL for account types that don't have separate external/internal pools.
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedAccount instance
/// - The returned pool must be freed with `address_pool_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_get_external_address_pool(
    account: *const FFIManagedAccount,
) -> *mut FFIAddressPool {
    if account.is_null() {
        return std::ptr::null_mut();
    }

    let account = &*account;
    let managed_account = account.inner();

    // Get external address pool if this is a standard account
    match &managed_account.account_type {
        key_wallet::managed_account::managed_account_type::ManagedAccountType::Standard {
            external_addresses,
            ..
        } => {
            let ffi_pool = FFIAddressPool {
                pool: external_addresses as *const AddressPool as *mut AddressPool,
                pool_type: FFIAddressPoolType::External,
            };
            Box::into_raw(Box::new(ffi_pool))
        }
        _ => std::ptr::null_mut(),
    }
}

/// Get the internal address pool from a managed account
///
/// This function returns the internal (change) address pool for Standard accounts.
/// Returns NULL for account types that don't have separate external/internal pools.
///
/// # Safety
///
/// - `account` must be a valid pointer to an FFIManagedAccount instance
/// - The returned pool must be freed with `address_pool_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_get_internal_address_pool(
    account: *const FFIManagedAccount,
) -> *mut FFIAddressPool {
    if account.is_null() {
        return std::ptr::null_mut();
    }

    let account = &*account;
    let managed_account = account.inner();

    // Get internal address pool if this is a standard account
    match &managed_account.account_type {
        key_wallet::managed_account::managed_account_type::ManagedAccountType::Standard {
            internal_addresses,
            ..
        } => {
            let ffi_pool = FFIAddressPool {
                pool: internal_addresses as *const AddressPool as *mut AddressPool,
                pool_type: FFIAddressPoolType::Internal,
            };
            Box::into_raw(Box::new(ffi_pool))
        }
        _ => std::ptr::null_mut(),
    }
}

/// Get an address pool from a managed account by type
///
/// This function returns the appropriate address pool based on the pool type parameter.
/// For Standard accounts with External/Internal pool types, returns the corresponding pool.
/// For non-standard accounts with Single pool type, returns their single address pool.
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `account` must be a valid pointer to an FFIManagedAccount instance
/// - `wallet_id` must be a valid pointer to a 32-byte wallet ID
/// - The returned pool must be freed with `address_pool_free` when no longer needed
#[no_mangle]
pub unsafe extern "C" fn managed_account_get_address_pool(
    account: *const FFIManagedAccount,
    pool_type: FFIAddressPoolType,
) -> *mut FFIAddressPool {
    if account.is_null() {
        return std::ptr::null_mut();
    }

    let account = &*account;
    let managed_account = account.inner();

    use key_wallet::managed_account::managed_account_type::ManagedAccountType;

    match pool_type {
        FFIAddressPoolType::External => {
            // Only standard accounts have external pools
            match &managed_account.account_type {
                ManagedAccountType::Standard {
                    external_addresses,
                    ..
                } => {
                    let ffi_pool = FFIAddressPool {
                        pool: external_addresses as *const AddressPool as *mut AddressPool,
                        pool_type: FFIAddressPoolType::External,
                    };
                    Box::into_raw(Box::new(ffi_pool))
                }
                _ => std::ptr::null_mut(),
            }
        }
        FFIAddressPoolType::Internal => {
            // Only standard accounts have internal pools
            match &managed_account.account_type {
                ManagedAccountType::Standard {
                    internal_addresses,
                    ..
                } => {
                    let ffi_pool = FFIAddressPool {
                        pool: internal_addresses as *const AddressPool as *mut AddressPool,
                        pool_type: FFIAddressPoolType::Internal,
                    };
                    Box::into_raw(Box::new(ffi_pool))
                }
                _ => std::ptr::null_mut(),
            }
        }
        FFIAddressPoolType::Single => {
            // Get the single address pool for non-standard accounts
            let pool_ref = match &managed_account.account_type {
                ManagedAccountType::Standard {
                    ..
                } => {
                    // Standard accounts don't have a "single" pool
                    return std::ptr::null_mut();
                }
                ManagedAccountType::CoinJoin {
                    addresses,
                    ..
                } => addresses,
                ManagedAccountType::IdentityRegistration {
                    addresses,
                } => addresses,
                ManagedAccountType::IdentityTopUp {
                    addresses,
                    ..
                } => addresses,
                ManagedAccountType::IdentityTopUpNotBoundToIdentity {
                    addresses,
                } => addresses,
                ManagedAccountType::IdentityInvitation {
                    addresses,
                } => addresses,
                ManagedAccountType::ProviderVotingKeys {
                    addresses,
                } => addresses,
                ManagedAccountType::ProviderOwnerKeys {
                    addresses,
                } => addresses,
                ManagedAccountType::ProviderOperatorKeys {
                    addresses,
                } => addresses,
                ManagedAccountType::ProviderPlatformKeys {
                    addresses,
                } => addresses,
            };

            let ffi_pool = FFIAddressPool {
                pool: pool_ref as *const AddressPool as *mut AddressPool,
                pool_type: FFIAddressPoolType::Single,
            };
            Box::into_raw(Box::new(ffi_pool))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address_pool::address_pool_free;
    use crate::types::{FFIAccountCreationOptionType, FFIWalletAccountCreationOptions};
    use crate::wallet_manager::{
        wallet_manager_add_wallet_from_mnemonic_with_options, wallet_manager_create,
        wallet_manager_free, wallet_manager_free_wallet_ids, wallet_manager_get_wallet_ids,
    };
    use std::ffi::CString;
    use std::ptr;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_managed_account_basic() {
        unsafe {
            let mut error = FFIError::success();

            // Create wallet manager
            let manager = wallet_manager_create(&mut error);
            assert!(!manager.is_null());
            assert_eq!(error.code, FFIErrorCode::Success);

            // Add a wallet with default accounts
            let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
            let passphrase = CString::new("").unwrap();

            let success = wallet_manager_add_wallet_from_mnemonic_with_options(
                manager,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetworks::Testnet,
                ptr::null(),
                &mut error,
            );
            assert!(success);
            assert_eq!(error.code, FFIErrorCode::Success);

            // Get wallet IDs
            let mut wallet_ids_out: *mut u8 = ptr::null_mut();
            let mut count_out: usize = 0;

            let success = wallet_manager_get_wallet_ids(
                manager,
                &mut wallet_ids_out,
                &mut count_out,
                &mut error,
            );
            assert!(success);
            assert_eq!(count_out, 1);
            assert!(!wallet_ids_out.is_null());

            // Get a managed account
            let result = managed_wallet_get_account(
                manager,
                wallet_ids_out,
                FFINetworks::Testnet,
                0,
                FFIAccountType::StandardBIP44,
            );

            assert!(!result.account.is_null());
            assert_eq!(result.error_code, 0);
            assert!(result.error_message.is_null());

            // Verify the account was created successfully
            let account = &*result.account;
            // Account should exist and be valid
            assert!(!account.inner().is_watch_only);

            // Clean up
            managed_account_free(result.account);
            wallet_manager_free_wallet_ids(wallet_ids_out, count_out);
            wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_managed_account_not_found() {
        unsafe {
            let mut error = FFIError::success();

            // Create wallet manager
            let manager = wallet_manager_create(&mut error);
            assert!(!manager.is_null());

            // Add a wallet with minimal accounts
            let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
            let passphrase = CString::new("").unwrap();

            let mut options = FFIWalletAccountCreationOptions::default_options();
            options.option_type = FFIAccountCreationOptionType::BIP44AccountsOnly;
            let bip44_indices = [0];
            options.bip44_indices = bip44_indices.as_ptr();
            options.bip44_count = bip44_indices.len();

            let success = wallet_manager_add_wallet_from_mnemonic_with_options(
                manager,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetworks::Testnet,
                &options,
                &mut error,
            );
            assert!(success);

            // Get wallet IDs
            let mut wallet_ids_out: *mut u8 = ptr::null_mut();
            let mut count_out: usize = 0;

            let success = wallet_manager_get_wallet_ids(
                manager,
                &mut wallet_ids_out,
                &mut count_out,
                &mut error,
            );
            assert!(success);
            assert_eq!(count_out, 1);

            // Try to get a non-existent CoinJoin account
            let mut result = managed_wallet_get_account(
                manager,
                wallet_ids_out,
                FFINetworks::Testnet,
                0,
                FFIAccountType::CoinJoin,
            );

            assert!(result.account.is_null());
            assert_ne!(result.error_code, 0);
            assert!(!result.error_message.is_null());

            // Clean up error message
            managed_account_result_free_error(&mut result as *mut _);

            // Clean up
            wallet_manager_free_wallet_ids(wallet_ids_out, count_out);
            wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_managed_account_free_null() {
        unsafe {
            // Should not crash when freeing null
            managed_account_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_managed_wallet_get_account_count() {
        unsafe {
            let mut error = FFIError::success();

            // Create wallet manager
            let manager = wallet_manager_create(&mut error);
            assert!(!manager.is_null());

            // Add a wallet with multiple accounts
            let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
            let passphrase = CString::new("").unwrap();

            let mut options = FFIWalletAccountCreationOptions::default_options();
            options.option_type = FFIAccountCreationOptionType::AllAccounts;

            let bip44_indices = [0, 1, 2];
            let bip32_indices = [0];
            let coinjoin_indices = [0];

            options.bip44_indices = bip44_indices.as_ptr();
            options.bip44_count = bip44_indices.len();
            options.bip32_indices = bip32_indices.as_ptr();
            options.bip32_count = bip32_indices.len();
            options.coinjoin_indices = coinjoin_indices.as_ptr();
            options.coinjoin_count = coinjoin_indices.len();

            let success = wallet_manager_add_wallet_from_mnemonic_with_options(
                manager,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetworks::Testnet,
                &options,
                &mut error,
            );
            assert!(success);

            // Get wallet IDs
            let mut wallet_ids_out: *mut u8 = ptr::null_mut();
            let mut count_out: usize = 0;

            let success = wallet_manager_get_wallet_ids(
                manager,
                &mut wallet_ids_out,
                &mut count_out,
                &mut error,
            );
            assert!(success);

            // Get account count
            let count = managed_wallet_get_account_count(
                manager,
                wallet_ids_out,
                FFINetworks::Testnet,
                &mut error,
            );

            // Should have at least the accounts we created
            assert!(count >= 5); // 3 BIP44 + 1 BIP32 + 1 CoinJoin
            assert_eq!(error.code, FFIErrorCode::Success);

            // Clean up
            wallet_manager_free_wallet_ids(wallet_ids_out, count_out);
            wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_managed_account_getters() {
        unsafe {
            let mut error = FFIError::success();

            // Create wallet manager
            let manager = wallet_manager_create(&mut error);
            assert!(!manager.is_null());
            assert_eq!(error.code, FFIErrorCode::Success);

            // Add a wallet with default accounts
            let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
            let passphrase = CString::new("").unwrap();

            let success = wallet_manager_add_wallet_from_mnemonic_with_options(
                manager,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetworks::Testnet,
                ptr::null(),
                &mut error,
            );
            assert!(success);
            assert_eq!(error.code, FFIErrorCode::Success);

            // Get wallet IDs
            let mut wallet_ids_out: *mut u8 = ptr::null_mut();
            let mut count_out: usize = 0;

            let success = wallet_manager_get_wallet_ids(
                manager,
                &mut wallet_ids_out,
                &mut count_out,
                &mut error,
            );
            assert!(success);
            assert_eq!(count_out, 1);
            assert!(!wallet_ids_out.is_null());

            // Get a managed account
            let result = managed_wallet_get_account(
                manager,
                wallet_ids_out,
                FFINetworks::Testnet,
                0,
                FFIAccountType::StandardBIP44,
            );

            assert!(!result.account.is_null());
            assert_eq!(result.error_code, 0);
            assert!(result.error_message.is_null());

            let account = result.account;

            // Test get_network
            let network = managed_account_get_network(account);
            assert_eq!(network, FFINetworks::Testnet);

            // Test get_account_type
            let mut index_out: c_uint = 999; // Initialize with unexpected value
            let account_type = managed_account_get_account_type(account, &mut index_out);
            assert_eq!(account_type, FFIAccountType::StandardBIP44);
            assert_eq!(index_out, 0);

            // Test get_is_watch_only
            let is_watch_only = managed_account_get_is_watch_only(account);
            assert!(!is_watch_only);

            // Test get_balance
            let mut balance_out = crate::types::FFIBalance {
                confirmed: 999,
                unconfirmed: 999,
                immature: 999,
                total: 999,
            };
            let success = managed_account_get_balance(account, &mut balance_out);
            assert!(success);
            // Initially, balance should be 0
            assert_eq!(balance_out.confirmed, 0);
            assert_eq!(balance_out.unconfirmed, 0);
            assert_eq!(balance_out.immature, 0);
            assert_eq!(balance_out.total, 0);

            // Test get_transaction_count
            let tx_count = managed_account_get_transaction_count(account);
            assert_eq!(tx_count, 0); // Initially no transactions

            // Test get_utxo_count
            let utxo_count = managed_account_get_utxo_count(account);
            assert_eq!(utxo_count, 0); // Initially no UTXOs

            // Test get_parent_wallet_id
            let parent_id = managed_account_get_parent_wallet_id(wallet_ids_out);
            assert_eq!(parent_id, wallet_ids_out); // Should return the same pointer

            // Clean up
            managed_account_free(account);
            wallet_manager_free_wallet_ids(wallet_ids_out, count_out);
            wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_managed_account_getter_edge_cases() {
        unsafe {
            // Test null account
            let network = managed_account_get_network(ptr::null());
            assert_eq!(network, FFINetworks::NoNetworks);

            let mut index_out: c_uint = 0;
            let account_type = managed_account_get_account_type(ptr::null(), &mut index_out);
            assert_eq!(account_type, FFIAccountType::StandardBIP44); // Default type

            let is_watch_only = managed_account_get_is_watch_only(ptr::null());
            assert!(!is_watch_only);

            let tx_count = managed_account_get_transaction_count(ptr::null());
            assert_eq!(tx_count, 0);

            let utxo_count = managed_account_get_utxo_count(ptr::null());
            assert_eq!(utxo_count, 0);

            // Test new getters with null account
            let index = managed_account_get_index(ptr::null());
            assert_eq!(index, 0);

            // Test null balance_out
            let mut error = FFIError::success();
            let manager = wallet_manager_create(&mut error);
            assert!(!manager.is_null());

            // Add a wallet
            let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
            let passphrase = CString::new("").unwrap();

            let success = wallet_manager_add_wallet_from_mnemonic_with_options(
                manager,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetworks::Testnet,
                ptr::null(),
                &mut error,
            );
            assert!(success);

            // Get wallet IDs
            let mut wallet_ids_out: *mut u8 = ptr::null_mut();
            let mut count_out: usize = 0;

            let success = wallet_manager_get_wallet_ids(
                manager,
                &mut wallet_ids_out,
                &mut count_out,
                &mut error,
            );
            assert!(success);

            // Get an account
            let result = managed_wallet_get_account(
                manager,
                wallet_ids_out,
                FFINetworks::Testnet,
                0,
                FFIAccountType::StandardBIP44,
            );
            assert!(!result.account.is_null());

            // Test balance with null output
            let success = managed_account_get_balance(result.account, ptr::null_mut());
            assert!(!success);

            // Clean up
            managed_account_free(result.account);
            wallet_manager_free_wallet_ids(wallet_ids_out, count_out);
            wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_managed_account_address_pools() {
        unsafe {
            let mut error = FFIError::success();

            // Create wallet manager
            let mut manager = wallet_manager_create(&mut error);
            assert!(!manager.is_null());
            assert_eq!(error.code, FFIErrorCode::Success);

            // Add a wallet with default accounts
            let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
            let passphrase = CString::new("").unwrap();

            let success = wallet_manager_add_wallet_from_mnemonic_with_options(
                manager,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetworks::Testnet,
                ptr::null(),
                &mut error,
            );
            assert!(success);
            assert_eq!(error.code, FFIErrorCode::Success);

            // Get wallet IDs
            let mut wallet_ids_out: *mut u8 = ptr::null_mut();
            let mut count_out: usize = 0;

            let success = wallet_manager_get_wallet_ids(
                manager,
                &mut wallet_ids_out,
                &mut count_out,
                &mut error,
            );
            assert!(success);
            assert_eq!(count_out, 1);
            assert!(!wallet_ids_out.is_null());

            // Get a standard BIP44 managed account
            let result = managed_wallet_get_account(
                manager,
                wallet_ids_out,
                FFINetworks::Testnet,
                0,
                FFIAccountType::StandardBIP44,
            );

            assert!(!result.account.is_null());
            assert_eq!(result.error_code, 0);

            let account = result.account;

            // Test get_index
            let index = managed_account_get_index(account);
            assert_eq!(index, 0);

            // Test get_external_address_pool
            let external_pool = managed_account_get_external_address_pool(account);
            assert!(!external_pool.is_null());

            // Test get_internal_address_pool
            let internal_pool = managed_account_get_internal_address_pool(account);
            assert!(!internal_pool.is_null());

            // Test get_address_pool with External type
            let external_pool2 =
                managed_account_get_address_pool(account, FFIAddressPoolType::External);
            assert!(!external_pool2.is_null());

            // Test get_address_pool with Internal type
            let internal_pool2 =
                managed_account_get_address_pool(account, FFIAddressPoolType::Internal);
            assert!(!internal_pool2.is_null());

            // Test get_address_pool with Single type (should return null for Standard account)
            let single_pool = managed_account_get_address_pool(account, FFIAddressPoolType::Single);
            assert!(single_pool.is_null());

            // Clean up address pools
            address_pool_free(external_pool);
            address_pool_free(internal_pool);
            address_pool_free(external_pool2);
            address_pool_free(internal_pool2);

            // Clean up account
            managed_account_free(account);

            // Now test with different account types from the same wallet
            // The default wallet should have been created with StandardBIP44 index 0
            // Let's try creating a wallet with CoinJoin accounts first

            // Clean up and start fresh for the second test
            wallet_manager_free_wallet_ids(wallet_ids_out, count_out);
            wallet_manager_free(manager);

            // Create a new manager
            manager = wallet_manager_create(&mut error);
            assert!(!manager.is_null());

            // Create wallet with CoinJoin account
            let mut options = FFIWalletAccountCreationOptions::default_options();
            options.option_type = FFIAccountCreationOptionType::SpecificAccounts;
            let coinjoin_indices = [0];
            options.coinjoin_indices = coinjoin_indices.as_ptr();
            options.coinjoin_count = coinjoin_indices.len();

            let mnemonic2 = CString::new(TEST_MNEMONIC).unwrap();
            let passphrase2 = CString::new("").unwrap();
            let success = wallet_manager_add_wallet_from_mnemonic_with_options(
                manager,
                mnemonic2.as_ptr(),
                passphrase2.as_ptr(),
                FFINetworks::Testnet,
                &options,
                &mut error,
            );
            assert!(success);

            // Get wallet IDs
            let success = wallet_manager_get_wallet_ids(
                manager,
                &mut wallet_ids_out,
                &mut count_out,
                &mut error,
            );
            assert!(success);
            assert_eq!(count_out, 1);

            // Get CoinJoin account
            let cj_result = managed_wallet_get_account(
                manager,
                wallet_ids_out,
                FFINetworks::Testnet,
                0,
                FFIAccountType::CoinJoin,
            );
            assert!(!cj_result.account.is_null());

            let cj_account = cj_result.account;

            // Test that external/internal return null for CoinJoin account
            let cj_external = managed_account_get_external_address_pool(cj_account);
            assert!(cj_external.is_null());

            let cj_internal = managed_account_get_internal_address_pool(cj_account);
            assert!(cj_internal.is_null());

            // Test that Single pool works for CoinJoin account
            let cj_single =
                managed_account_get_address_pool(cj_account, FFIAddressPoolType::Single);
            assert!(!cj_single.is_null());

            // Clean up
            address_pool_free(cj_single);
            managed_account_free(cj_account);
            wallet_manager_free_wallet_ids(wallet_ids_out, count_out);
            wallet_manager_free(manager);
        }
    }

    #[test]
    fn test_address_pool_free_null() {
        unsafe {
            // Should not crash when freeing null
            address_pool_free(ptr::null_mut());
        }
    }
}
