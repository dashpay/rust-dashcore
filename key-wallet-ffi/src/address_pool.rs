//! Address pool management FFI bindings
//!
//! This module provides FFI bindings for managing address pools within
//! managed accounts, including gap limit management and address generation.

use std::ffi::CString;
use std::os::raw::{c_char, c_uint};

use crate::error::{FFIError, FFIErrorCode};
use crate::managed_wallet::FFIManagedWalletInfo;
use crate::types::{FFIAccountType, FFIWallet};
use crate::utils::rust_string_to_c;
use key_wallet::account::ManagedAccountCollection;
use key_wallet::managed_account::address_pool::{
    AddressInfo, AddressPool, KeySource, PublicKeyType,
};
use key_wallet::managed_account::ManagedCoreAccount;
use key_wallet::AccountType;

// Helper functions to get managed accounts by type
fn get_managed_account_by_type<'a>(
    collection: &'a ManagedAccountCollection,
    account_type: &AccountType,
) -> Option<&'a ManagedCoreAccount> {
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
        AccountType::DashpayReceivingFunds {
            ..
        }
        | AccountType::DashpayExternalAccount {
            ..
        } => {
            // DashPay managed accounts are not currently persisted in ManagedAccountCollection
            None
        }
        AccountType::PlatformPayment {
            ..
        } => {
            // Platform Payment accounts are not currently persisted in ManagedAccountCollection
            None
        }
    }
}

fn get_managed_account_by_type_mut<'a>(
    collection: &'a mut ManagedAccountCollection,
    account_type: &AccountType,
) -> Option<&'a mut ManagedCoreAccount> {
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
        AccountType::DashpayReceivingFunds {
            ..
        }
        | AccountType::DashpayExternalAccount {
            ..
        } => {
            // DashPay managed accounts are not currently persisted in ManagedAccountCollection
            None
        }
        AccountType::PlatformPayment {
            ..
        } => {
            // Platform Payment accounts are not currently persisted in ManagedAccountCollection
            None
        }
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

/// FFI wrapper for an AddressPool from a ManagedAccount
///
/// This is a lightweight wrapper that holds a reference to an AddressPool
/// from within a ManagedAccount. It allows querying addresses and pool information.
pub struct FFIAddressPool {
    /// Reference to the address pool (mutable for internal consistency even if not modified)
    pub(crate) pool: *mut AddressPool,
    /// Pool type to track what kind of pool this is
    #[allow(dead_code)]
    pub(crate) pool_type: FFIAddressPoolType,
}

/// FFI-compatible version of AddressInfo
#[repr(C)]
pub struct FFIAddressInfo {
    /// Address as string
    pub address: *mut c_char,
    /// Script pubkey bytes
    pub script_pubkey: *mut u8,
    /// Length of script pubkey
    pub script_pubkey_len: usize,
    /// Public key bytes (nullable)
    pub public_key: *mut u8,
    /// Length of public key
    pub public_key_len: usize,
    /// Derivation index
    pub index: u32,
    /// Derivation path as string
    pub path: *mut c_char,
    /// Whether address has been used
    pub used: bool,
    /// When generated (timestamp)
    pub generated_at: u64,
    /// When first used (0 if never)
    pub used_at: u64,
    /// Transaction count
    pub tx_count: u32,
    /// Total received
    pub total_received: u64,
    /// Total sent
    pub total_sent: u64,
    /// Current balance
    pub balance: u64,
    /// Custom label (nullable)
    pub label: *mut c_char,
}

/// Convert from AddressInfo to FFIAddressInfo
fn address_info_to_ffi(info: &AddressInfo) -> FFIAddressInfo {
    // Convert address to string
    let address_str = rust_string_to_c(info.address.to_string());

    // Convert script pubkey to bytes
    let script_bytes = info.script_pubkey.as_bytes();
    let script_pubkey_len = script_bytes.len();
    let script_pubkey = if script_pubkey_len > 0 {
        let mut bytes = Vec::with_capacity(script_pubkey_len);
        bytes.extend_from_slice(script_bytes);
        Box::into_raw(bytes.into_boxed_slice()) as *mut u8
    } else {
        std::ptr::null_mut()
    };

    // Convert public key to bytes if present
    let (public_key, public_key_len) = match &info.public_key {
        Some(pk) => match pk {
            PublicKeyType::ECDSA(bytes)
            | PublicKeyType::EdDSA(bytes)
            | PublicKeyType::BLS(bytes) => {
                let len = bytes.len();
                if len > 0 {
                    let mut key_bytes = Vec::with_capacity(len);
                    key_bytes.extend_from_slice(bytes);
                    (Box::into_raw(key_bytes.into_boxed_slice()) as *mut u8, len)
                } else {
                    (std::ptr::null_mut(), 0)
                }
            }
        },
        None => (std::ptr::null_mut(), 0),
    };

    // Convert derivation path to string
    let path_str = rust_string_to_c(info.path.to_string());

    // Convert label if present
    let label =
        info.label.as_ref().map(|l| rust_string_to_c(l.clone())).unwrap_or(std::ptr::null_mut());

    FFIAddressInfo {
        address: address_str,
        script_pubkey,
        script_pubkey_len,
        public_key,
        public_key_len,
        index: info.index,
        path: path_str,
        used: info.used,
        generated_at: info.generated_at,
        used_at: info.used_at.unwrap_or(0),
        tx_count: info.tx_count,
        total_received: info.total_received,
        total_sent: info.total_sent,
        balance: info.balance,
        label,
    }
}

/// Free an address pool handle
///
/// # Safety
///
/// - `pool` must be a valid pointer to an FFIAddressPool that was allocated by this library
/// - The pointer must not be used after calling this function
/// - This function must only be called once per allocation
#[no_mangle]
pub unsafe extern "C" fn address_pool_free(pool: *mut FFIAddressPool) {
    if !pool.is_null() {
        let _ = Box::from_raw(pool);
    }
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
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo
/// - `info_out` must be a valid pointer to store the pool info
/// - `error` must be a valid pointer to an FFIError or null
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_get_address_pool_info(
    managed_wallet: *const FFIManagedWalletInfo,
    account_type: FFIAccountType,
    account_index: c_uint,
    pool_type: FFIAddressPoolType,
    info_out: *mut FFIAddressPoolInfo,
    error: *mut FFIError,
) -> bool {
    if managed_wallet.is_null() || info_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let wrapper = &*managed_wallet;
    let managed_wallet = wrapper.inner();

    let account_type_rust = account_type.to_account_type(account_index);

    // Get the specific managed account
    let managed_account =
        match get_managed_account_by_type(&managed_wallet.accounts, &account_type_rust) {
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
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo
/// - `error` must be a valid pointer to an FFIError or null
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_set_gap_limit(
    managed_wallet: *mut FFIManagedWalletInfo,
    account_type: FFIAccountType,
    account_index: c_uint,
    pool_type: FFIAddressPoolType,
    gap_limit: c_uint,
    error: *mut FFIError,
) -> bool {
    if managed_wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let managed_wallet = (&mut *managed_wallet).inner_mut();

    let account_type_rust = account_type.to_account_type(account_index);

    // Get the specific managed account
    let managed_account =
        match get_managed_account_by_type_mut(&mut managed_wallet.accounts, &account_type_rust) {
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
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo
/// - `wallet` must be a valid pointer to an FFIWallet (for key derivation)
/// - `error` must be a valid pointer to an FFIError or null
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_generate_addresses_to_index(
    managed_wallet: *mut FFIManagedWalletInfo,
    wallet: *const FFIWallet,
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

    let managed_wallet = (&mut *managed_wallet).inner_mut();
    let wallet = &*wallet;

    let account_type_rust = account_type.to_account_type(account_index);

    let account_type_to_check = match account_type_rust.try_into() {
        Ok(check_type) => check_type,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Platform Payment accounts cannot be used for address pool operations".to_string(),
            );
            return false;
        }
    };

    let xpub_opt = wallet
        .inner()
        .extended_public_key_for_account_type(&account_type_to_check, Some(account_index));

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

    // Get the specific managed account
    let managed_account =
        match get_managed_account_by_type_mut(&mut managed_wallet.accounts, &account_type_rust) {
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
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo
/// - `address` must be a valid C string
/// - `error` must be a valid pointer to an FFIError or null
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_mark_address_used(
    managed_wallet: *mut FFIManagedWalletInfo,
    address: *const c_char,
    error: *mut FFIError,
) -> bool {
    if managed_wallet.is_null() || address.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let managed_wallet = (&mut *managed_wallet).inner_mut();

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
    let collection = &mut managed_wallet.accounts;

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
        if !found {
            for account in collection.dashpay_receival_accounts.values_mut() {
                if account.mark_address_used(&address) {
                    found = true;
                    break;
                }
            }
        }
        if !found {
            for account in collection.dashpay_external_accounts.values_mut() {
                if account.mark_address_used(&address) {
                    found = true;
                    break;
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

/// Get a single address info at a specific index from the pool
///
/// Returns detailed information about the address at the given index, or NULL
/// if the index is out of bounds or not generated yet.
///
/// # Safety
///
/// - `pool` must be a valid pointer to an FFIAddressPool
/// - `error` must be a valid pointer to an FFIError or null
/// - The returned FFIAddressInfo must be freed using `address_info_free`
#[no_mangle]
pub unsafe extern "C" fn address_pool_get_address_at_index(
    pool: *const FFIAddressPool,
    index: u32,
    error: *mut FFIError,
) -> *mut FFIAddressInfo {
    if pool.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return std::ptr::null_mut();
    }

    let pool = &*pool;
    let address_pool = &*pool.pool;

    // Get the address info at the specified index
    match address_pool.info_at_index(index) {
        Some(info) => {
            let ffi_info = address_info_to_ffi(info);
            FFIError::set_success(error);
            Box::into_raw(Box::new(ffi_info))
        }
        None => {
            FFIError::set_error(
                error,
                FFIErrorCode::NotFound,
                format!("No address at index {}", index),
            );
            std::ptr::null_mut()
        }
    }
}

/// Get a range of addresses from the pool
///
/// Returns an array of FFIAddressInfo structures for addresses in the range [start_index, end_index).
/// The count_out parameter will be set to the actual number of addresses returned.
///
/// Note: This function only reads existing addresses from the pool. It does not generate new addresses.
/// Use managed_wallet_generate_addresses_to_index if you need to generate addresses first.
///
/// # Safety
///
/// - `pool` must be a valid pointer to an FFIAddressPool
/// - `count_out` must be a valid pointer to store the count
/// - `error` must be a valid pointer to an FFIError or null
/// - The returned array must be freed using `address_info_array_free`
#[no_mangle]
pub unsafe extern "C" fn address_pool_get_addresses_in_range(
    pool: *const FFIAddressPool,
    start_index: u32,
    end_index: u32,
    count_out: *mut usize,
    error: *mut FFIError,
) -> *mut *mut FFIAddressInfo {
    if pool.is_null() || count_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return std::ptr::null_mut();
    }

    *count_out = 0;

    let pool = &*pool;
    let address_pool = &*pool.pool;

    // Collect address infos in the range
    let mut infos = Vec::new();

    // Special case: if start_index == 0 and end_index == 0, return all addresses
    if start_index == 0 && end_index == 0 {
        for idx in 0..=address_pool.highest_generated.unwrap_or(0) {
            if let Some(info) = address_pool.info_at_index(idx) {
                infos.push(Box::into_raw(Box::new(address_info_to_ffi(info))));
            }
        }
    } else {
        // Normal range query
        if end_index <= start_index {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "End index must be greater than start index".to_string(),
            );
            return std::ptr::null_mut();
        }

        for idx in start_index..end_index {
            if let Some(info) = address_pool.info_at_index(idx) {
                infos.push(Box::into_raw(Box::new(address_info_to_ffi(info))));
            }
        }
    }

    if infos.is_empty() {
        FFIError::set_error(
            error,
            FFIErrorCode::NotFound,
            "No addresses found in the specified range".to_string(),
        );
        return std::ptr::null_mut();
    }

    *count_out = infos.len();
    let array_ptr = Box::into_raw(infos.into_boxed_slice()) as *mut *mut FFIAddressInfo;

    FFIError::set_success(error);
    array_ptr
}

/// Free a single FFIAddressInfo structure
///
/// # Safety
///
/// - `info` must be a valid pointer to an FFIAddressInfo allocated by this library or null
/// - The pointer must not be used after calling this function
#[no_mangle]
pub unsafe extern "C" fn address_info_free(info: *mut FFIAddressInfo) {
    if !info.is_null() {
        let info = Box::from_raw(info);

        // Free the C strings
        if !info.address.is_null() {
            let _ = CString::from_raw(info.address);
        }
        if !info.path.is_null() {
            let _ = CString::from_raw(info.path);
        }
        if !info.label.is_null() {
            let _ = CString::from_raw(info.label);
        }

        // Free the byte arrays
        if !info.script_pubkey.is_null() && info.script_pubkey_len > 0 {
            let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                info.script_pubkey,
                info.script_pubkey_len,
            ));
        }
        if !info.public_key.is_null() && info.public_key_len > 0 {
            let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                info.public_key,
                info.public_key_len,
            ));
        }
    }
}

/// Free an array of FFIAddressInfo structures
///
/// # Safety
///
/// - `infos` must be a valid pointer to an array of FFIAddressInfo pointers allocated by this library or null
/// - `count` must be the exact number of elements in the array
/// - The pointers must not be used after calling this function
#[no_mangle]
pub unsafe extern "C" fn address_info_array_free(infos: *mut *mut FFIAddressInfo, count: usize) {
    if !infos.is_null() && count > 0 {
        let array = Box::from_raw(std::ptr::slice_from_raw_parts_mut(infos, count));
        for info_ptr in array.iter() {
            address_info_free(*info_ptr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FFINetwork;

    #[test]
    fn test_address_pool_type_values() {
        assert_eq!(FFIAddressPoolType::External as u32, 0);
        assert_eq!(FFIAddressPoolType::Internal as u32, 1);
        assert_eq!(FFIAddressPoolType::Single as u32, 2);
    }

    #[test]
    fn test_address_info_conversion() {
        // Test the FFI conversion function with a mock AddressInfo
        use key_wallet::bip32::DerivationPath;
        use std::str::FromStr;

        // Create a test address programmatically
        use dashcore::PublicKey;

        // Use a valid compressed public key (this is a well-known test key)
        let pubkey_bytes = [
            0x02, // Compressed pubkey prefix
            0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1, 0xa8,
            0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04, 0x88,
            0x7e, 0x5b, 0x23, 0x52,
        ];
        let pubkey = PublicKey::from_slice(&pubkey_bytes).unwrap();
        let test_address = dashcore::Address::p2pkh(&pubkey, key_wallet::Network::Testnet);

        let test_path = DerivationPath::from_str("m/44'/5'/0'/0/0").unwrap();

        let info = AddressInfo {
            address: test_address.clone(),
            script_pubkey: test_address.script_pubkey(),
            public_key: Some(PublicKeyType::ECDSA(vec![0x02, 0x03, 0x04])),
            index: 0,
            path: test_path,
            used: false,
            generated_at: 1234567890,
            used_at: None,
            tx_count: 0,
            total_received: 0,
            total_sent: 0,
            balance: 0,
            label: Some("Test Label".to_string()),
            metadata: std::collections::BTreeMap::new(),
        };

        // Convert to FFI
        let ffi_info = address_info_to_ffi(&info);

        // Verify basic fields
        assert_eq!(ffi_info.index, 0);
        assert!(!ffi_info.used);
        assert_eq!(ffi_info.generated_at, 1234567890);
        assert_eq!(ffi_info.used_at, 0);
        assert_eq!(ffi_info.public_key_len, 3);
        assert!(ffi_info.script_pubkey_len > 0);

        // Clean up the FFI structure
        unsafe {
            let boxed = Box::new(ffi_info);
            address_info_free(Box::into_raw(boxed));
        }
    }

    #[test]
    fn test_address_info_free() {
        // Test that free functions handle NULL gracefully
        unsafe {
            address_info_free(std::ptr::null_mut());
            address_info_array_free(std::ptr::null_mut(), 0);
            address_info_array_free(std::ptr::null_mut(), 10);
        }
    }

    #[test]
    fn test_address_pool_get_address_at_index() {
        // Test the simplified address_pool_get_address_at_index function
        unsafe {
            use crate::managed_account::{
                managed_account_free, managed_account_get_external_address_pool,
            };
            use crate::wallet_manager::{
                wallet_manager_add_wallet_from_mnemonic_with_options, wallet_manager_create,
                wallet_manager_free, wallet_manager_free_wallet_ids, wallet_manager_get_wallet_ids,
            };
            use std::ffi::CString;
            use std::ptr;

            let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let mut error = FFIError::success();

            // Create wallet manager
            let manager = wallet_manager_create(FFINetwork::Testnet, &mut error);
            assert!(!manager.is_null());
            assert_eq!(error.code, FFIErrorCode::Success);

            // Add a wallet with default accounts
            let mnemonic = CString::new(test_mnemonic).unwrap();
            let passphrase = CString::new("").unwrap();

            let success = wallet_manager_add_wallet_from_mnemonic_with_options(
                manager,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
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
            let result = crate::managed_account::managed_wallet_get_account(
                manager,
                wallet_ids_out,
                0,
                FFIAccountType::StandardBIP44,
            );

            assert!(!result.account.is_null());
            assert_eq!(result.error_code, 0);

            let account = result.account;

            // Get external address pool
            let external_pool = managed_account_get_external_address_pool(account);
            assert!(!external_pool.is_null());

            // Test getting address at index 0 (should exist by default)
            let address_info = address_pool_get_address_at_index(external_pool, 0, &mut error);

            if !address_info.is_null() {
                // Verify the address info
                let info = &*address_info;
                assert_eq!(info.index, 0);
                assert!(!info.address.is_null());
                assert!(!info.path.is_null());

                // Clean up address info
                address_info_free(address_info);
            }

            // Test getting address at an out-of-bounds index
            let invalid_info = address_pool_get_address_at_index(external_pool, 10000, &mut error);
            assert!(invalid_info.is_null());
            assert_eq!(error.code, FFIErrorCode::NotFound);

            // Test null pool
            let null_info = address_pool_get_address_at_index(ptr::null(), 0, &mut error);
            assert!(null_info.is_null());
            assert_eq!(error.code, FFIErrorCode::InvalidInput);

            // Clean up
            address_pool_free(external_pool);
            managed_account_free(account);
            wallet_manager_free_wallet_ids(wallet_ids_out, count_out);
            wallet_manager_free(manager);
            error.free_message();
        }
    }

    #[test]
    fn test_address_pool_get_addresses_in_range() {
        // Test the simplified address_pool_get_addresses_in_range function
        unsafe {
            use crate::managed_account::{
                managed_account_free, managed_account_get_external_address_pool,
            };
            use crate::wallet_manager::{
                wallet_manager_add_wallet_from_mnemonic_with_options, wallet_manager_create,
                wallet_manager_free, wallet_manager_free_wallet_ids, wallet_manager_get_wallet_ids,
            };
            use std::ffi::CString;
            use std::ptr;

            let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let mut error = FFIError::success();

            // Create wallet manager
            let manager = wallet_manager_create(FFINetwork::Testnet, &mut error);
            assert!(!manager.is_null());
            assert_eq!(error.code, FFIErrorCode::Success);

            // Add a wallet with default accounts
            let mnemonic = CString::new(test_mnemonic).unwrap();
            let passphrase = CString::new("").unwrap();

            let success = wallet_manager_add_wallet_from_mnemonic_with_options(
                manager,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
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
            let result = crate::managed_account::managed_wallet_get_account(
                manager,
                wallet_ids_out,
                0,
                FFIAccountType::StandardBIP44,
            );

            assert!(!result.account.is_null());
            assert_eq!(result.error_code, 0);

            let account = result.account;

            // Get external address pool
            let external_pool = managed_account_get_external_address_pool(account);
            assert!(!external_pool.is_null());

            // Test getting a range of addresses
            let mut addresses_count: usize = 0;
            let addresses = address_pool_get_addresses_in_range(
                external_pool,
                0,
                5,
                &mut addresses_count,
                &mut error,
            );

            // The pool might not have 5 addresses generated yet, but should have at least 1
            if !addresses.is_null() && addresses_count > 0 {
                // Verify we got some addresses
                assert!(addresses_count <= 5);
                assert_eq!(error.code, FFIErrorCode::Success);

                // Clean up addresses
                address_info_array_free(addresses, addresses_count);
            }

            // Test invalid range (end <= start)
            let invalid_addresses = address_pool_get_addresses_in_range(
                external_pool,
                5,
                5,
                &mut addresses_count,
                &mut error,
            );
            assert!(invalid_addresses.is_null());
            assert_eq!(error.code, FFIErrorCode::InvalidInput);

            // Test null pool
            let null_addresses = address_pool_get_addresses_in_range(
                ptr::null(),
                0,
                5,
                &mut addresses_count,
                &mut error,
            );
            assert!(null_addresses.is_null());
            assert_eq!(error.code, FFIErrorCode::InvalidInput);

            // Test null count_out
            let null_count_addresses = address_pool_get_addresses_in_range(
                external_pool,
                0,
                5,
                ptr::null_mut(),
                &mut error,
            );
            assert!(null_count_addresses.is_null());
            assert_eq!(error.code, FFIErrorCode::InvalidInput);

            // Clean up
            address_pool_free(external_pool);
            managed_account_free(account);
            wallet_manager_free_wallet_ids(wallet_ids_out, count_out);
            wallet_manager_free(manager);
            error.free_message();
        }
    }
}
