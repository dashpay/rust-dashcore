//! Account management functions

use std::os::raw::c_uint;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFIAccount, FFIAccountResult, FFIAccountType, FFINetwork, FFIWallet};

/// Get an account handle for a specific account type
/// Returns a result containing either the account handle or an error
#[no_mangle]
pub extern "C" fn wallet_get_account(
    wallet: *const FFIWallet,
    network: FFINetwork,
    account_index: c_uint,
    account_type: c_uint,
) -> FFIAccountResult {
    if wallet.is_null() {
        return FFIAccountResult::error(FFIErrorCode::InvalidInput, "Wallet is null".to_string());
    }

    unsafe {
        let wallet = &*wallet;
        let network_rust: key_wallet::Network = network.into();

        let account_type_enum = match account_type {
            0 => FFIAccountType::StandardBIP44,
            1 => FFIAccountType::StandardBIP32,
            2 => FFIAccountType::CoinJoin,
            3 => FFIAccountType::IdentityRegistration,
            4 => {
                // IdentityTopUp requires a registration_index
                return FFIAccountResult::error(
                    FFIErrorCode::InvalidInput,
                    "IdentityTopUp accounts require a registration_index. Use wallet_get_top_up_account_with_registration_index instead".to_string(),
                );
            }
            5 => FFIAccountType::IdentityTopUpNotBoundToIdentity,
            6 => FFIAccountType::IdentityInvitation,
            7 => FFIAccountType::ProviderVotingKeys,
            8 => FFIAccountType::ProviderOwnerKeys,
            9 => FFIAccountType::ProviderOperatorKeys,
            10 => FFIAccountType::ProviderPlatformKeys,
            _ => {
                return FFIAccountResult::error(
                    FFIErrorCode::InvalidInput,
                    format!("Invalid account type: {}", account_type),
                );
            }
        };

        let account_type = match account_type_enum.to_account_type(account_index, None) {
            Some(at) => at,
            None => {
                return FFIAccountResult::error(
                    FFIErrorCode::InvalidInput,
                    format!("Missing required parameters for account type {}", account_type),
                );
            }
        };

        match wallet
            .inner()
            .accounts_on_network(network_rust)
            .and_then(|account_collection| account_collection.account_of_type(account_type))
        {
            Some(account) => {
                let ffi_account = FFIAccount::new(account);
                FFIAccountResult::success(Box::into_raw(Box::new(ffi_account)))
            }
            None => {
                FFIAccountResult::error(FFIErrorCode::NotFound, "Account not found".to_string())
            }
        }
    }
}

/// Get an IdentityTopUp account handle with a specific registration index
/// This is used for top-up accounts that are bound to a specific identity
/// Returns a result containing either the account handle or an error
#[no_mangle]
pub extern "C" fn wallet_get_top_up_account_with_registration_index(
    wallet: *const FFIWallet,
    network: FFINetwork,
    registration_index: c_uint,
) -> FFIAccountResult {
    if wallet.is_null() {
        return FFIAccountResult::error(FFIErrorCode::InvalidInput, "Wallet is null".to_string());
    }

    unsafe {
        let wallet = &*wallet;
        let network_rust: key_wallet::Network = network.into();

        // This function is specifically for IdentityTopUp accounts
        let account_type = key_wallet::AccountType::IdentityTopUp {
            registration_index,
        };

        match wallet
            .inner()
            .accounts_on_network(network_rust)
            .and_then(|account_collection| account_collection.account_of_type(account_type))
        {
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
}

/// Free an account handle
#[no_mangle]
pub extern "C" fn account_free(account: *mut FFIAccount) {
    if !account.is_null() {
        unsafe {
            let _ = Box::from_raw(account);
        }
    }
}

/// Free an account result's error message (if any)
/// Note: This does NOT free the account handle itself - use account_free for that
#[no_mangle]
pub extern "C" fn account_result_free_error(result: *mut FFIAccountResult) {
    if !result.is_null() {
        unsafe {
            let result = &mut *result;
            if !result.error_message.is_null() {
                let _ = std::ffi::CString::from_raw(result.error_message);
                result.error_message = std::ptr::null_mut();
            }
        }
    }
}

/// Get number of accounts
#[no_mangle]
pub extern "C" fn wallet_get_account_count(
    wallet: *const FFIWallet,
    network: FFINetwork,
    error: *mut FFIError,
) -> c_uint {
    if wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Wallet is null".to_string());
        return 0;
    }

    unsafe {
        let wallet = &*wallet;
        let network: key_wallet::Network = network.into();

        match wallet.inner().accounts.get(&network) {
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
        }
    }
}

#[cfg(test)]
#[path = "account_tests.rs"]
mod tests;
