//! Balance tracking

#[cfg(test)]
#[path = "balance_tests.rs"]
mod tests;

use std::os::raw::c_uint;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFINetwork, FFIWallet};

/// Balance structure for FFI
#[repr(C)]
#[derive(Default)]
pub struct FFIBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub immature: u64,
    pub total: u64,
}

impl From<key_wallet::WalletBalance> for FFIBalance {
    fn from(balance: key_wallet::WalletBalance) -> Self {
        FFIBalance {
            confirmed: balance.confirmed,
            unconfirmed: balance.unconfirmed,
            immature: 0, // key_wallet doesn't have immature field
            total: balance.confirmed + balance.unconfirmed,
        }
    }
}

/// Get wallet balance
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet instance
/// - `balance_out` must be a valid pointer to an FFIBalance structure
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_get_balance(
    wallet: *const FFIWallet,
    network: FFINetwork,
    balance_out: *mut FFIBalance,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() || balance_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let _wallet = &*wallet;
    let _network_rust: key_wallet::Network = network.into();

    // Note: get_balance is not directly available on Wallet
    // Would need to aggregate from accounts
    *balance_out = FFIBalance::default();

    FFIError::set_success(error);
    true
}

/// Get account balance
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet instance
/// - `balance_out` must be a valid pointer to an FFIBalance structure
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_get_account_balance(
    wallet: *const FFIWallet,
    network: FFINetwork,
    account_index: c_uint,
    balance_out: *mut FFIBalance,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() || balance_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let wallet = &*wallet;
    let network_rust: key_wallet::Network = network.into();

    use key_wallet::account::account_type::{AccountType, StandardAccountType};
    let _account_type = AccountType::Standard {
        index: account_index,
        standard_account_type: StandardAccountType::BIP44Account,
    };

    match wallet.inner().get_bip44_account(network_rust, account_index) {
        Some(_account) => {
            // Note: get_balance is not directly available on Account
            // Would need to implement balance tracking
            *balance_out = FFIBalance::default();
            FFIError::set_success(error);
            true
        }
        None => {
            FFIError::set_error(error, FFIErrorCode::NotFound, "Account not found".to_string());
            false
        }
    }
}
