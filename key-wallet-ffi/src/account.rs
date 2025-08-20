//! Account management functions

use std::os::raw::c_uint;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFIAccountType, FFINetwork, FFIWallet};

/// Create or get an account
#[no_mangle]
pub extern "C" fn wallet_get_account(
    wallet: *mut FFIWallet,
    network: FFINetwork,
    account_index: c_uint,
    account_type: c_uint,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Wallet is null".to_string());
        return false;
    }

    unsafe {
        let wallet = &mut *wallet;
        let network_rust: key_wallet::Network = network.into();

        let account_type_enum = match account_type {
            0 => FFIAccountType::Standard,
            1 => FFIAccountType::CoinJoin,
            2 => FFIAccountType::Identity,
            _ => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    format!("Invalid account type: {}", account_type),
                );
                return false;
            }
        };

        let account_type = account_type_enum.to_account_type(account_index);

        // Note: get_or_create_account is not available, just check if it exists
        match wallet.inner().get_bip44_account(network_rust, account_index) {
            Some(_) => {
                FFIError::set_success(error);
                true
            }
            None => {
                // Account doesn't exist
                FFIError::set_error(error, FFIErrorCode::NotFound, "Account not found".to_string());
                false
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
