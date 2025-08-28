//! Address pool management FFI bindings
//!
//! This module provides FFI bindings for managing address pools within
//! managed accounts, including gap limit management and address generation.

use std::os::raw::{c_char, c_uint};

use crate::error::{FFIError, FFIErrorCode};
use crate::transaction_checking::FFIManagedWallet;
use crate::types::{FFIAccountType, FFINetwork, FFIWallet};
use key_wallet::account::ManagedAccountCollection;
use key_wallet::managed_account::address_pool::KeySource;
use key_wallet::managed_account::ManagedAccount;
use key_wallet::AccountType;

// Helper functions to get managed accounts by type
fn get_managed_account_by_type<'a>(
    collection: &'a ManagedAccountCollection,
    account_type: &AccountType,
) -> Option<&'a ManagedAccount> {
    match account_type {
        AccountType::Standard {
            index,
            standard_account_type,
        } => match standard_account_type {
            key_wallet::account::StandardAccountType::BIP44Account => {
                collection.standard_bip44_accounts.get(index)
            }
            key_wallet::account::StandardAccountType::BIP32Account => {
                collection.standard_bip32_accounts.get(index)
            }
        },
        AccountType::CoinJoin {
            index,
        } => collection.coinjoin_accounts.get(index),
        AccountType::IdentityRegistration => collection.identity_registration.as_ref(),
        AccountType::IdentityTopUp {
            registration_index,
        } => collection.identity_topup.get(registration_index),
        AccountType::IdentityTopUpNotBoundToIdentity => {
            collection.identity_topup_not_bound.as_ref()
        }
        AccountType::IdentityInvitation => collection.identity_invitation.as_ref(),
        AccountType::ProviderVotingKeys => collection.provider_voting_keys.as_ref(),
        AccountType::ProviderOwnerKeys => collection.provider_owner_keys.as_ref(),
        AccountType::ProviderOperatorKeys => collection.provider_operator_keys.as_ref(),
        AccountType::ProviderPlatformKeys => collection.provider_platform_keys.as_ref(),
    }
}

fn get_managed_account_by_type_mut<'a>(
    collection: &'a mut ManagedAccountCollection,
    account_type: &AccountType,
) -> Option<&'a mut ManagedAccount> {
    match account_type {
        AccountType::Standard {
            index,
            standard_account_type,
        } => match standard_account_type {
            key_wallet::account::StandardAccountType::BIP44Account => {
                collection.standard_bip44_accounts.get_mut(index)
            }
            key_wallet::account::StandardAccountType::BIP32Account => {
                collection.standard_bip32_accounts.get_mut(index)
            }
        },
        AccountType::CoinJoin {
            index,
        } => collection.coinjoin_accounts.get_mut(index),
        AccountType::IdentityRegistration => collection.identity_registration.as_mut(),
        AccountType::IdentityTopUp {
            registration_index,
        } => collection.identity_topup.get_mut(registration_index),
        AccountType::IdentityTopUpNotBoundToIdentity => {
            collection.identity_topup_not_bound.as_mut()
        }
        AccountType::IdentityInvitation => collection.identity_invitation.as_mut(),
        AccountType::ProviderVotingKeys => collection.provider_voting_keys.as_mut(),
        AccountType::ProviderOwnerKeys => collection.provider_owner_keys.as_mut(),
        AccountType::ProviderOperatorKeys => collection.provider_operator_keys.as_mut(),
        AccountType::ProviderPlatformKeys => collection.provider_platform_keys.as_mut(),
    }
}

/// Address pool type
#[repr(C)]
pub enum FFIAddressPoolType {
    /// External (receive) addresses
    External = 0,
    /// Internal (change) addresses
    Internal = 1,
    /// Single pool (for non-standard accounts)
    Single = 2,
}

/// Address pool info
#[repr(C)]
pub struct FFIAddressPoolInfo {
    /// Pool type
    pub pool_type: FFIAddressPoolType,
    /// Number of generated addresses
    pub generated_count: c_uint,
    /// Number of used addresses
    pub used_count: c_uint,
    /// Current gap (unused addresses at the end)
    pub current_gap: c_uint,
    /// Gap limit setting
    pub gap_limit: c_uint,
    /// Highest used index (-1 if none used)
    pub highest_used_index: i32,
}

/// Get address pool information for an account
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWallet
/// - `info_out` must be a valid pointer to store the pool info
/// - `error` must be a valid pointer to an FFIError or null
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_get_address_pool_info(
    managed_wallet: *const FFIManagedWallet,
    network: FFINetwork,
    account_type: FFIAccountType,
    account_index: c_uint,
    registration_index: c_uint,
    pool_type: FFIAddressPoolType,
    info_out: *mut FFIAddressPoolInfo,
    error: *mut FFIError,
) -> bool {
    if managed_wallet.is_null() || info_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let managed_wallet = &*(*managed_wallet).inner;
    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(error, FFIErrorCode::InvalidInput, "Must specify exactly one network".to_string());
            return ptr::null_mut();
        }
    };

    let registration_index_opt = if account_type == 4 {
        Some(registration_index)
    } else {
        None
    };

    let account_type_rust = account_type.to_account_type(account_index);

    // Get the account collection
    let collection = match managed_wallet.accounts.get(&network_rust) {
        Some(collection) => collection,
        None => {
            FFIError::set_error(
                error,
                FFIErrorCode::NotFound,
                "No accounts for network".to_string(),
            );
            return false;
        }
    };

    // Get the specific managed account
    let managed_account = match get_managed_account_by_type(collection, &account_type_rust) {
        Some(account) => account,
        None => {
            FFIError::set_error(error, FFIErrorCode::NotFound, "Account not found".to_string());
            return false;
        }
    };

    // Get the appropriate address pool
    let pool = match pool_type {
        FFIAddressPoolType::External => {
            // Only standard accounts have external/internal pools
            if let key_wallet::managed_account::managed_account_type::ManagedAccountType::Standard {
                external_addresses,
                ..
            } = &managed_account.account_type {
                external_addresses
            } else {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Account type does not have external address pool".to_string(),
                );
                return false;
            }
        }
        FFIAddressPoolType::Internal => {
            // Only standard accounts have external/internal pools
            if let key_wallet::managed_account::managed_account_type::ManagedAccountType::Standard {
                internal_addresses,
                ..
            } = &managed_account.account_type {
                internal_addresses
            } else {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Account type does not have internal address pool".to_string(),
                );
                return false;
            }
        }
        FFIAddressPoolType::Single => {
            // Get the first (and only) address pool for non-standard accounts
            let pools = managed_account.account_type.address_pools();
            if pools.is_empty() {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Account has no address pools".to_string(),
                );
                return false;
            }
            pools[0]
        }
    };

    // Fill the info structure
    let generated_count = pool.addresses.len();
    let used_count = pool.used_indices.len();
    let highest_used = pool.highest_used.unwrap_or(0);
    let highest_generated = pool.highest_generated.unwrap_or(0);
    let current_gap = highest_generated.saturating_sub(highest_used);

    *info_out = FFIAddressPoolInfo {
        pool_type,
        generated_count: generated_count as c_uint,
        used_count: used_count as c_uint,
        current_gap: current_gap as c_uint,
        gap_limit: pool.gap_limit as c_uint,
        highest_used_index: pool.highest_used.map(|i| i as i32).unwrap_or(-1),
    };

    FFIError::set_success(error);
    true
}

/// Set the gap limit for an address pool
///
/// The gap limit determines how many unused addresses to maintain at the end
/// of the pool. This is important for wallet recovery and address discovery.
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWallet
/// - `error` must be a valid pointer to an FFIError or null
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_set_gap_limit(
    managed_wallet: *mut FFIManagedWallet,
    network: FFINetwork,
    account_type: c_uint,
    account_index: c_uint,
    registration_index: c_uint,
    pool_type: FFIAddressPoolType,
    gap_limit: c_uint,
    error: *mut FFIError,
) -> bool {
    if managed_wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let managed_wallet = &mut *(*managed_wallet).inner;
    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(error, FFIErrorCode::InvalidInput, "Must specify exactly one network".to_string());
            return ptr::null_mut();
        }
    };

    // Convert FFI account type to AccountType
    let account_type_enum = match account_type {
        0 => FFIAccountType::StandardBIP44,
        1 => FFIAccountType::StandardBIP32,
        2 => FFIAccountType::CoinJoin,
        3 => FFIAccountType::IdentityRegistration,
        4 => FFIAccountType::IdentityTopUp,
        5 => FFIAccountType::IdentityTopUpNotBoundToIdentity,
        6 => FFIAccountType::IdentityInvitation,
        7 => FFIAccountType::ProviderVotingKeys,
        8 => FFIAccountType::ProviderOwnerKeys,
        9 => FFIAccountType::ProviderOperatorKeys,
        10 => FFIAccountType::ProviderPlatformKeys,
        _ => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                format!("Invalid account type: {}", account_type),
            );
            return false;
        }
    };

    let registration_index_opt = if account_type == 4 {
        Some(registration_index)
    } else {
        None
    };

    let account_type_rust =
        match account_type_enum.to_account_type(account_index, registration_index_opt) {
            Some(at) => at,
            None => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid account type parameters".to_string(),
                );
                return false;
            }
        };

    // Get the account collection
    let collection = match managed_wallet.accounts.get_mut(&network_rust) {
        Some(collection) => collection,
        None => {
            FFIError::set_error(
                error,
                FFIErrorCode::NotFound,
                "No accounts for network".to_string(),
            );
            return false;
        }
    };

    // Get the specific managed account
    let managed_account = match get_managed_account_by_type_mut(collection, &account_type_rust) {
        Some(account) => account,
        None => {
            FFIError::set_error(error, FFIErrorCode::NotFound, "Account not found".to_string());
            return false;
        }
    };

    // Get the appropriate address pool
    let pool = match pool_type {
        FFIAddressPoolType::External => {
            // Only standard accounts have external/internal pools
            if let key_wallet::managed_account::managed_account_type::ManagedAccountType::Standard {
                external_addresses,
                ..
            } = &mut managed_account.account_type {
                external_addresses
            } else {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Account type does not have external address pool".to_string(),
                );
                return false;
            }
        }
        FFIAddressPoolType::Internal => {
            // Only standard accounts have external/internal pools
            if let key_wallet::managed_account::managed_account_type::ManagedAccountType::Standard {
                internal_addresses,
                ..
            } = &mut managed_account.account_type {
                internal_addresses
            } else {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Account type does not have internal address pool".to_string(),
                );
                return false;
            }
        }
        FFIAddressPoolType::Single => {
            // Get the first (and only) address pool for non-standard accounts
            let pools = managed_account.account_type.address_pools_mut();
            if pools.is_empty() {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Account has no address pools".to_string(),
                );
                return false;
            }
            pools.into_iter().next().unwrap()
        }
    };

    // Set the gap limit
    pool.gap_limit = gap_limit;

    FFIError::set_success(error);
    true
}

/// Generate addresses up to a specific index in a pool
///
/// This ensures that addresses up to and including the specified index exist
/// in the pool. This is useful for wallet recovery or when specific indices
/// are needed.
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWallet
/// - `wallet` must be a valid pointer to an FFIWallet (for key derivation)
/// - `error` must be a valid pointer to an FFIError or null
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_generate_addresses_to_index(
    managed_wallet: *mut FFIManagedWallet,
    wallet: *const FFIWallet,
    network: FFINetwork,
    account_type: FFIAccountType,
    account_index: c_uint,
    pool_type: FFIAddressPoolType,
    target_index: c_uint,
    error: *mut FFIError,
) -> bool {
    if managed_wallet.is_null() || wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let managed_wallet = &mut *(*managed_wallet).inner;
    let wallet = &*wallet;
    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(error, FFIErrorCode::InvalidInput, "Must specify exactly one network".to_string());
            return ptr::null_mut();
        }
    };

    let account_type_rust = account_type.to_account_type(account_index);
    
    let account_type_to_check = account_type_rust.into();

    let xpub_opt = wallet.inner().extended_public_key_for_account_type(
        &account_type_to_check,
        Some(account_index),
        network_rust,
    );

    let xpub = match xpub_opt {
        Some(xpub) => xpub,
        None => {
            FFIError::set_error(
                error,
                FFIErrorCode::NotFound,
                "Account not found in wallet".to_string(),
            );
            return false;
        }
    };

    let key_source = KeySource::Public(xpub);

    // Get the account collection
    let collection = match managed_wallet.accounts.get_mut(&network_rust) {
        Some(collection) => collection,
        None => {
            FFIError::set_error(
                error,
                FFIErrorCode::NotFound,
                "No accounts for network".to_string(),
            );
            return false;
        }
    };

    // Get the specific managed account
    let managed_account = match get_managed_account_by_type_mut(collection, &account_type_rust) {
        Some(account) => account,
        None => {
            FFIError::set_error(error, FFIErrorCode::NotFound, "Account not found".to_string());
            return false;
        }
    };

    // Get the appropriate address pool and generate addresses
    let result = match pool_type {
        FFIAddressPoolType::External => {
            // Only standard accounts have external/internal pools
            if let key_wallet::managed_account::managed_account_type::ManagedAccountType::Standard {
                external_addresses,
                ..
            } = &mut managed_account.account_type {
                {
                    let current = external_addresses.highest_generated.unwrap_or(0);
                    if target_index > current {
                        let needed = target_index - current;
                        external_addresses.generate_addresses(needed, &key_source, true)
                    } else {
                        Ok(Vec::new())
                    }
                }
            } else {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Account type does not have external address pool".to_string(),
                );
                return false;
            }
        }
        FFIAddressPoolType::Internal => {
            // Only standard accounts have external/internal pools
            if let key_wallet::managed_account::managed_account_type::ManagedAccountType::Standard {
                internal_addresses,
                ..
            } = &mut managed_account.account_type {
                {
                    let current = internal_addresses.highest_generated.unwrap_or(0);
                    if target_index > current {
                        let needed = target_index - current;
                        internal_addresses.generate_addresses(needed, &key_source, true)
                    } else {
                        Ok(Vec::new())
                    }
                }
            } else {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Account type does not have internal address pool".to_string(),
                );
                return false;
            }
        }
        FFIAddressPoolType::Single => {
            // Get the first (and only) address pool for non-standard accounts
            let mut pools = managed_account.account_type.address_pools_mut();
            if pools.is_empty() {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Account has no address pools".to_string(),
                );
                return false;
            }
            {
                let pool = &mut pools[0];
                let current = pool.highest_generated.unwrap_or(0);
                if target_index > current {
                    let needed = target_index - current;
                    pool.generate_addresses(needed, &key_source, true)
                } else {
                    Ok(Vec::new())
                }
            }
        }
    };

    match result {
        Ok(_) => {
            FFIError::set_success(error);
            true
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to generate addresses: {}", e),
            );
            false
        }
    }
}

/// Mark an address as used in the pool
///
/// This updates the pool's tracking of which addresses have been used,
/// which is important for gap limit management and wallet recovery.
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWallet
/// - `address` must be a valid C string
/// - `error` must be a valid pointer to an FFIError or null
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_mark_address_used(
    managed_wallet: *mut FFIManagedWallet,
    network: FFINetwork,
    address: *const c_char,
    error: *mut FFIError,
) -> bool {
    if managed_wallet.is_null() || address.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let managed_wallet = &mut *(*managed_wallet).inner;
    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(error, FFIErrorCode::InvalidInput, "Must specify exactly one network".to_string());
            return ptr::null_mut();
        }
    };

    // Parse the address string
    let address_str = match std::ffi::CStr::from_ptr(address).to_str() {
        Ok(s) => s,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Invalid UTF-8 in address".to_string(),
            );
            return false;
        }
    };

    // Parse address as unchecked first, then convert to the correct network
    use core::str::FromStr;
    use dashcore::address::{Address, NetworkUnchecked};

    let unchecked_addr = match Address::<NetworkUnchecked>::from_str(address_str) {
        Ok(addr) => addr,
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                format!("Invalid address: {}", e),
            );
            return false;
        }
    };

    // Assume the address uses the same network we're working with
    let address = unchecked_addr.assume_checked();

    // Get the account collection
    let collection = match managed_wallet.accounts.get_mut(&network_rust) {
        Some(collection) => collection,
        None => {
            FFIError::set_error(
                error,
                FFIErrorCode::NotFound,
                "No accounts for network".to_string(),
            );
            return false;
        }
    };

    // Try to mark the address as used in any account that contains it
    let marked = {
        let mut found = false;
        // Check all accounts for the address
        for account in collection.standard_bip44_accounts.values_mut() {
            if account.mark_address_used(&address) {
                found = true;
                break;
            }
        }
        if !found {
            for account in collection.standard_bip32_accounts.values_mut() {
                if account.mark_address_used(&address) {
                    found = true;
                    break;
                }
            }
        }
        if !found {
            for account in collection.coinjoin_accounts.values_mut() {
                if account.mark_address_used(&address) {
                    found = true;
                    break;
                }
            }
        }
        if !found {
            if let Some(account) = &mut collection.identity_registration {
                if account.mark_address_used(&address) {
                    found = true;
                }
            }
        }
        if !found {
            for account in collection.identity_topup.values_mut() {
                if account.mark_address_used(&address) {
                    found = true;
                    break;
                }
            }
        }
        if !found {
            if let Some(account) = &mut collection.identity_topup_not_bound {
                if account.mark_address_used(&address) {
                    found = true;
                }
            }
        }
        if !found {
            if let Some(account) = &mut collection.identity_invitation {
                if account.mark_address_used(&address) {
                    found = true;
                }
            }
        }
        if !found {
            if let Some(account) = &mut collection.provider_voting_keys {
                if account.mark_address_used(&address) {
                    found = true;
                }
            }
        }
        if !found {
            if let Some(account) = &mut collection.provider_owner_keys {
                if account.mark_address_used(&address) {
                    found = true;
                }
            }
        }
        if !found {
            if let Some(account) = &mut collection.provider_operator_keys {
                if account.mark_address_used(&address) {
                    found = true;
                }
            }
        }
        if !found {
            if let Some(account) = &mut collection.provider_platform_keys {
                if account.mark_address_used(&address) {
                    found = true;
                }
            }
        }
        found
    };

    if marked {
        FFIError::set_success(error);
        true
    } else {
        FFIError::set_error(
            error,
            FFIErrorCode::NotFound,
            "Address not found in any account".to_string(),
        );
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_pool_type_values() {
        assert_eq!(FFIAddressPoolType::External as u32, 0);
        assert_eq!(FFIAddressPoolType::Internal as u32, 1);
        assert_eq!(FFIAddressPoolType::Single as u32, 2);
    }
}
