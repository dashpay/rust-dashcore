//! Transaction checking FFI bindings
//!
//! This module provides FFI bindings for the advanced transaction checking
//! functionality introduced in the key-wallet library, including transaction
//! routing, classification, and account matching.

use std::ffi::CString;
use std::os::raw::{c_char, c_uint};
use std::slice;

use crate::error::{FFIError, FFIErrorCode};
use crate::managed_wallet::{managed_wallet_info_free, FFIManagedWalletInfo};
use crate::types::{FFITransactionContext, FFIWallet};
use dashcore::consensus::Decodable;
use dashcore::Transaction;
use key_wallet::transaction_checking::{
    account_checker::CoreAccountTypeMatch, TransactionContext, WalletTransactionChecker,
};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;

// Transaction context for checking
// FFITransactionContext is imported from types module at the top
/// Account type match result
#[repr(C)]
pub struct FFIAccountMatch {
    /// Account type ID (matches FFIAccountType enum values)
    pub account_type: c_uint,
    /// Account index (if applicable)
    pub account_index: c_uint,
    /// Registration index for identity top-up (if applicable)
    pub registration_index: c_uint,
    /// Amount received by this account
    pub received: u64,
    /// Amount sent from this account
    pub sent: u64,
    /// Number of external addresses involved
    pub external_addresses_count: c_uint,
    /// Number of internal addresses involved
    pub internal_addresses_count: c_uint,
    /// Whether external addresses were involved
    pub has_external_addresses: bool,
    /// Whether internal addresses were involved
    pub has_internal_addresses: bool,
}

/// Transaction check result
#[repr(C)]
pub struct FFITransactionCheckResult {
    /// Whether the transaction belongs to the wallet
    pub is_relevant: bool,
    /// Total amount received across all accounts
    pub total_received: u64,
    /// Total amount sent across all accounts
    pub total_sent: u64,
    /// Total amount received for credit conversion
    pub total_received_for_credit_conversion: u64,
    /// Array of affected accounts (must be freed)
    pub affected_accounts: *mut FFIAccountMatch,
    /// Number of affected accounts
    pub affected_accounts_count: c_uint,
}

/// Create a managed wallet from a regular wallet
///
/// This creates a ManagedWalletInfo instance from a Wallet, which includes
/// address pools and transaction checking capabilities.
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `error` must be a valid pointer to an FFIError or null
/// - The returned pointer must be freed with `managed_wallet_info_free` (or `ffi_managed_wallet_free` for compatibility)
#[no_mangle]
pub unsafe extern "C" fn wallet_create_managed_wallet(
    wallet: *const FFIWallet,
    error: *mut FFIError,
) -> *mut FFIManagedWalletInfo {
    if wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Wallet is null".to_string());
        return std::ptr::null_mut();
    }

    let wallet = &*wallet;

    // Create managed wallet info from the wallet
    let managed_info = ManagedWalletInfo::from_wallet(wallet.inner());

    // Box it and return raw pointer
    let managed_wallet = Box::new(FFIManagedWalletInfo::new(managed_info));

    FFIError::set_success(error);
    Box::into_raw(managed_wallet)
}

/// Check if a transaction belongs to the wallet
///
/// This function checks a transaction against all relevant account types in the wallet
/// and returns detailed information about which accounts are affected.
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo
/// - `wallet` must be a valid pointer to an FFIWallet (needed for address generation and DashPay queries)
/// - `tx_bytes` must be a valid pointer to transaction bytes with at least `tx_len` bytes
/// - `result_out` must be a valid pointer to store the result
/// - `error` must be a valid pointer to an FFIError
/// - The affected_accounts array in the result must be freed with `transaction_check_result_free`
#[no_mangle]
pub unsafe extern "C" fn managed_wallet_check_transaction(
    managed_wallet: *mut FFIManagedWalletInfo,
    wallet: *mut FFIWallet,
    tx_bytes: *const u8,
    tx_len: usize,
    context_type: FFITransactionContext,
    block_height: c_uint,
    block_hash: *const u8, // 32 bytes if not null
    timestamp: u64,
    update_state: bool,
    result_out: *mut FFITransactionCheckResult,
    error: *mut FFIError,
) -> bool {
    if managed_wallet.is_null() || tx_bytes.is_null() || result_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let managed_wallet: &mut ManagedWalletInfo = (*managed_wallet).inner_mut();
    let tx_slice = slice::from_raw_parts(tx_bytes, tx_len);

    // Parse the transaction
    let tx = match Transaction::consensus_decode(&mut &tx_slice[..]) {
        Ok(tx) => tx,
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                format!("Failed to decode transaction: {}", e),
            );
            return false;
        }
    };

    // Build the transaction context
    let context = match context_type {
        FFITransactionContext::Mempool => TransactionContext::Mempool,
        FFITransactionContext::InBlock => {
            let block_hash = if !block_hash.is_null() {
                use dashcore::hashes::Hash;
                let hash_bytes = slice::from_raw_parts(block_hash, 32);
                let mut hash_array = [0u8; 32];
                hash_array.copy_from_slice(hash_bytes);
                Some(dashcore::BlockHash::from_byte_array(hash_array))
            } else {
                None
            };
            TransactionContext::InBlock {
                height: block_height,
                block_hash,
                timestamp: if timestamp > 0 {
                    Some(timestamp as u32)
                } else {
                    None
                },
            }
        }
        FFITransactionContext::InChainLockedBlock => {
            let block_hash = if !block_hash.is_null() {
                use dashcore::hashes::Hash;
                let hash_bytes = slice::from_raw_parts(block_hash, 32);
                let mut hash_array = [0u8; 32];
                hash_array.copy_from_slice(hash_bytes);
                Some(dashcore::BlockHash::from_byte_array(hash_array))
            } else {
                None
            };
            TransactionContext::InChainLockedBlock {
                height: block_height,
                block_hash,
                timestamp: if timestamp > 0 {
                    Some(timestamp as u32)
                } else {
                    None
                },
            }
        }
    };

    // Check the transaction - wallet is now required
    if wallet.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Wallet pointer is required".to_string(),
        );
        return false;
    }

    let wallet_mut = match (*wallet).inner_mut() {
        Some(w) => w,
        None => {
            FFIError::set_error(
                error,
                FFIErrorCode::InternalError,
                "Cannot get mutable wallet reference (Arc has multiple owners)".to_string(),
            );
            return false;
        }
    };

    // Block on the async check_transaction call
    let check_result = tokio::runtime::Handle::current()
        .block_on(managed_wallet.check_core_transaction(&tx, context, wallet_mut, update_state));

    // Convert the result to FFI format
    let affected_accounts = if check_result.affected_accounts.is_empty() {
        std::ptr::null_mut()
    } else {
        let mut ffi_accounts = Vec::with_capacity(check_result.affected_accounts.len());

        for account_match in &check_result.affected_accounts {
            match &account_match.account_type_match {
                CoreAccountTypeMatch::StandardBIP44 {
                    account_index,
                    involved_receive_addresses,
                    involved_change_addresses,
                } => {
                    let external_count = involved_receive_addresses.len() as c_uint;
                    let internal_count = involved_change_addresses.len() as c_uint;
                    let ffi_match = FFIAccountMatch {
                        account_type: 0, // StandardBIP44
                        account_index: *account_index,
                        registration_index: 0,
                        received: account_match.received,
                        sent: account_match.sent,
                        external_addresses_count: external_count,
                        internal_addresses_count: internal_count,
                        has_external_addresses: external_count > 0,
                        has_internal_addresses: internal_count > 0,
                    };
                    ffi_accounts.push(ffi_match);
                    continue;
                }
                CoreAccountTypeMatch::StandardBIP32 {
                    account_index,
                    involved_receive_addresses,
                    involved_change_addresses,
                } => {
                    let external_count = involved_receive_addresses.len() as c_uint;
                    let internal_count = involved_change_addresses.len() as c_uint;
                    let ffi_match = FFIAccountMatch {
                        account_type: 1, // StandardBIP32
                        account_index: *account_index,
                        registration_index: 0,
                        received: account_match.received,
                        sent: account_match.sent,
                        external_addresses_count: external_count,
                        internal_addresses_count: internal_count,
                        has_external_addresses: external_count > 0,
                        has_internal_addresses: internal_count > 0,
                    };
                    ffi_accounts.push(ffi_match);
                    continue;
                }
                CoreAccountTypeMatch::CoinJoin {
                    account_index,
                    involved_addresses,
                } => {
                    let ffi_match = FFIAccountMatch {
                        account_type: 2, // CoinJoin
                        account_index: *account_index,
                        registration_index: 0,
                        received: account_match.received,
                        sent: account_match.sent,
                        external_addresses_count: involved_addresses.len() as c_uint,
                        internal_addresses_count: 0,
                        has_external_addresses: !involved_addresses.is_empty(),
                        has_internal_addresses: false,
                    };
                    ffi_accounts.push(ffi_match);
                    continue;
                }
                CoreAccountTypeMatch::IdentityRegistration {
                    involved_addresses,
                } => {
                    let ffi_match = FFIAccountMatch {
                        account_type: 3, // IdentityRegistration
                        account_index: 0,
                        registration_index: 0,
                        received: account_match.received,
                        sent: account_match.sent,
                        external_addresses_count: involved_addresses.len() as c_uint,
                        internal_addresses_count: 0,
                        has_external_addresses: !involved_addresses.is_empty(),
                        has_internal_addresses: false,
                    };
                    ffi_accounts.push(ffi_match);
                    continue;
                }
                CoreAccountTypeMatch::IdentityTopUp {
                    account_index,
                    involved_addresses,
                } => {
                    let ffi_match = FFIAccountMatch {
                        account_type: 4, // IdentityTopUp
                        account_index: 0,
                        registration_index: *account_index,
                        received: account_match.received,
                        sent: account_match.sent,
                        external_addresses_count: involved_addresses.len() as c_uint,
                        internal_addresses_count: 0,
                        has_external_addresses: !involved_addresses.is_empty(),
                        has_internal_addresses: false,
                    };
                    ffi_accounts.push(ffi_match);
                    continue;
                }
                CoreAccountTypeMatch::IdentityTopUpNotBound {
                    involved_addresses,
                } => {
                    let ffi_match = FFIAccountMatch {
                        account_type: 5, // IdentityTopUpNotBound
                        account_index: 0,
                        registration_index: 0,
                        received: account_match.received,
                        sent: account_match.sent,
                        external_addresses_count: involved_addresses.len() as c_uint,
                        internal_addresses_count: 0,
                        has_external_addresses: !involved_addresses.is_empty(),
                        has_internal_addresses: false,
                    };
                    ffi_accounts.push(ffi_match);
                    continue;
                }
                CoreAccountTypeMatch::IdentityInvitation {
                    involved_addresses,
                } => {
                    let ffi_match = FFIAccountMatch {
                        account_type: 6, // IdentityInvitation
                        account_index: 0,
                        registration_index: 0,
                        received: account_match.received,
                        sent: account_match.sent,
                        external_addresses_count: involved_addresses.len() as c_uint,
                        internal_addresses_count: 0,
                        has_external_addresses: !involved_addresses.is_empty(),
                        has_internal_addresses: false,
                    };
                    ffi_accounts.push(ffi_match);
                    continue;
                }
                CoreAccountTypeMatch::ProviderVotingKeys {
                    involved_addresses,
                } => {
                    let ffi_match = FFIAccountMatch {
                        account_type: 7, // ProviderVotingKeys
                        account_index: 0,
                        registration_index: 0,
                        received: account_match.received,
                        sent: account_match.sent,
                        external_addresses_count: involved_addresses.len() as c_uint,
                        internal_addresses_count: 0,
                        has_external_addresses: !involved_addresses.is_empty(),
                        has_internal_addresses: false,
                    };
                    ffi_accounts.push(ffi_match);
                    continue;
                }
                CoreAccountTypeMatch::ProviderOwnerKeys {
                    involved_addresses,
                } => {
                    let ffi_match = FFIAccountMatch {
                        account_type: 8, // ProviderOwnerKeys
                        account_index: 0,
                        registration_index: 0,
                        received: account_match.received,
                        sent: account_match.sent,
                        external_addresses_count: involved_addresses.len() as c_uint,
                        internal_addresses_count: 0,
                        has_external_addresses: !involved_addresses.is_empty(),
                        has_internal_addresses: false,
                    };
                    ffi_accounts.push(ffi_match);
                    continue;
                }
                CoreAccountTypeMatch::ProviderOperatorKeys {
                    involved_addresses,
                } => {
                    let ffi_match = FFIAccountMatch {
                        account_type: 9, // ProviderOperatorKeys
                        account_index: 0,
                        registration_index: 0,
                        received: account_match.received,
                        sent: account_match.sent,
                        external_addresses_count: involved_addresses.len() as c_uint,
                        internal_addresses_count: 0,
                        has_external_addresses: !involved_addresses.is_empty(),
                        has_internal_addresses: false,
                    };
                    ffi_accounts.push(ffi_match);
                    continue;
                }
                CoreAccountTypeMatch::ProviderPlatformKeys {
                    involved_addresses,
                } => {
                    let ffi_match = FFIAccountMatch {
                        account_type: 10, // ProviderPlatformKeys
                        account_index: 0,
                        registration_index: 0,
                        received: account_match.received,
                        sent: account_match.sent,
                        external_addresses_count: involved_addresses.len() as c_uint,
                        internal_addresses_count: 0,
                        has_external_addresses: !involved_addresses.is_empty(),
                        has_internal_addresses: false,
                    };
                    ffi_accounts.push(ffi_match);
                    continue;
                }
                CoreAccountTypeMatch::DashpayReceivingFunds {
                    account_index,
                    involved_addresses,
                } => {
                    let ffi_match = FFIAccountMatch {
                        account_type: 11, // DashpayReceivingFunds
                        account_index: *account_index,
                        registration_index: 0,
                        received: account_match.received,
                        sent: account_match.sent,
                        external_addresses_count: involved_addresses.len() as c_uint,
                        internal_addresses_count: 0,
                        has_external_addresses: !involved_addresses.is_empty(),
                        has_internal_addresses: false,
                    };
                    ffi_accounts.push(ffi_match);
                    continue;
                }
                CoreAccountTypeMatch::DashpayExternalAccount {
                    account_index,
                    involved_addresses,
                } => {
                    let ffi_match = FFIAccountMatch {
                        account_type: 12, // DashpayExternalAccount
                        account_index: *account_index,
                        registration_index: 0,
                        received: account_match.received,
                        sent: account_match.sent,
                        external_addresses_count: involved_addresses.len() as c_uint,
                        internal_addresses_count: 0,
                        has_external_addresses: !involved_addresses.is_empty(),
                        has_internal_addresses: false,
                    };
                    ffi_accounts.push(ffi_match);
                    continue;
                }
            }
        }

        // Convert vector to raw array
        let _len = ffi_accounts.len();
        let ptr = ffi_accounts.as_mut_ptr();
        std::mem::forget(ffi_accounts);
        ptr
    };

    // Fill the result
    *result_out = FFITransactionCheckResult {
        is_relevant: check_result.is_relevant,
        total_received: check_result.total_received,
        total_sent: check_result.total_sent,
        total_received_for_credit_conversion: check_result.total_received_for_credit_conversion,
        affected_accounts,
        affected_accounts_count: check_result.affected_accounts.len() as c_uint,
    };

    FFIError::set_success(error);
    true
}

/// Free a transaction check result
///
/// # Safety
///
/// - `result` must be a valid pointer to an FFITransactionCheckResult
/// - This function must only be called once per result
#[no_mangle]
pub unsafe extern "C" fn transaction_check_result_free(result: *mut FFITransactionCheckResult) {
    if !result.is_null() {
        let result = &mut *result;
        if !result.affected_accounts.is_null() && result.affected_accounts_count > 0 {
            // Reconstruct the vector and drop it
            let _ = Vec::from_raw_parts(
                result.affected_accounts,
                result.affected_accounts_count as usize,
                result.affected_accounts_count as usize,
            );
            result.affected_accounts = std::ptr::null_mut();
            result.affected_accounts_count = 0;
        }
    }
}

/// Free a managed wallet (FFIManagedWalletInfo type)
///
/// # Safety
///
/// - `managed_wallet` must be a valid pointer to an FFIManagedWalletInfo
/// - This function must only be called once per managed wallet
#[no_mangle]
pub unsafe extern "C" fn ffi_managed_wallet_free(managed_wallet: *mut FFIManagedWalletInfo) {
    // For compatibility, forward to canonical free
    managed_wallet_info_free(managed_wallet);
}

/// Get the transaction classification for routing
///
/// Returns a string describing the transaction type (e.g., "Standard", "CoinJoin",
/// "AssetLock", "AssetUnlock", "ProviderRegistration", etc.)
///
/// # Safety
///
/// - `tx_bytes` must be a valid pointer to transaction bytes with at least `tx_len` bytes
/// - `error` must be a valid pointer to an FFIError or null
/// - The returned string must be freed by the caller
#[no_mangle]
pub unsafe extern "C" fn transaction_classify(
    tx_bytes: *const u8,
    tx_len: usize,
    error: *mut FFIError,
) -> *mut c_char {
    if tx_bytes.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Transaction bytes are null".to_string(),
        );
        return std::ptr::null_mut();
    }

    let tx_slice = slice::from_raw_parts(tx_bytes, tx_len);

    // Parse the transaction
    let tx = match Transaction::consensus_decode(&mut &tx_slice[..]) {
        Ok(tx) => tx,
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                format!("Failed to decode transaction: {}", e),
            );
            return std::ptr::null_mut();
        }
    };

    // Classify the transaction
    use key_wallet::transaction_checking::transaction_router::TransactionRouter;
    let tx_type = TransactionRouter::classify_transaction(&tx);

    let type_str = format!("{:?}", tx_type);

    match CString::new(type_str) {
        Ok(c_str) => {
            FFIError::set_success(error);
            c_str.into_raw()
        }
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Failed to convert transaction type to C string".to_string(),
            );
            std::ptr::null_mut()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_context_conversion() {
        // Test that FFI transaction context values match expectations
        assert_eq!(FFITransactionContext::Mempool as u32, 0);
        assert_eq!(FFITransactionContext::InBlock as u32, 1);
        assert_eq!(FFITransactionContext::InChainLockedBlock as u32, 2);
    }
}
