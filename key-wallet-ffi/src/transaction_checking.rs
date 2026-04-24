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
use crate::types::{
    transaction_context_from_ffi, FFIBlockInfo, FFITransactionContextType, FFIWallet,
};
use crate::{check_ptr, deref_ptr, deref_ptr_mut, unwrap_or_return};
use dashcore::consensus::Decodable;
use dashcore::Transaction;
use key_wallet::transaction_checking::{
    account_checker::CoreAccountTypeMatch, TransactionContext, WalletTransactionChecker,
};
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;

// Transaction context for checking
// FFITransactionContextType is imported from types module at the top
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
/// - `error` must be a valid pointer to an FFIError
/// - The returned pointer must be freed with `managed_wallet_info_free` (or `ffi_managed_wallet_free` for compatibility)
#[no_mangle]
pub unsafe extern "C" fn wallet_create_managed_wallet(
    wallet: *const FFIWallet,
    error: *mut FFIError,
) -> *mut FFIManagedWalletInfo {
    let wallet = deref_ptr!(wallet, error);
    let managed_info = ManagedWalletInfo::from_wallet(wallet.inner());
    Box::into_raw(Box::new(FFIManagedWalletInfo::new(managed_info)))
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
    context_type: FFITransactionContextType,
    block_info: FFIBlockInfo,
    islock_data: *const u8,
    islock_len: usize,
    update_state: bool,
    result_out: *mut FFITransactionCheckResult,
    error: *mut FFIError,
) -> bool {
    let managed_wallet: &mut ManagedWalletInfo = deref_ptr_mut!(managed_wallet, error).inner_mut();
    check_ptr!(tx_bytes, error);
    check_ptr!(result_out, error);

    let tx_slice = slice::from_raw_parts(tx_bytes, tx_len);

    let tx = unwrap_or_return!(Transaction::consensus_decode(&mut &tx_slice[..]), error);

    // Build the transaction context
    let context = unwrap_or_return!(
        transaction_context_from_ffi(context_type, &block_info, islock_data, islock_len,),
        error
    );

    if let TransactionContext::InstantSend(ref lock) = context {
        if lock.txid != tx.txid() {
            (*error).set(FFIErrorCode::InvalidInput, "InstantLock txid does not match transaction");
            return false;
        }
    }

    let ff_wallet_mut = deref_ptr_mut!(wallet, error);
    let wallet_mut = unwrap_or_return!(ff_wallet_mut.inner_mut(), error);

    // Block on the async check_transaction call
    let check_result = tokio::runtime::Handle::current().block_on(
        managed_wallet.check_core_transaction(&tx, context, wallet_mut, update_state, true),
    );

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
                CoreAccountTypeMatch::AssetLockAddressTopUp {
                    involved_addresses,
                } => {
                    let ffi_match = FFIAccountMatch {
                        account_type: 14, // AssetLockAddressTopUp
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
                CoreAccountTypeMatch::AssetLockShieldedAddressTopUp {
                    involved_addresses,
                } => {
                    let ffi_match = FFIAccountMatch {
                        account_type: 15, // AssetLockShieldedAddressTopUp
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

    (*error).clean();
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
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed by the caller
#[no_mangle]
pub unsafe extern "C" fn transaction_classify(
    tx_bytes: *const u8,
    tx_len: usize,
    error: *mut FFIError,
) -> *mut c_char {
    check_ptr!(tx_bytes, error);
    let tx_slice = slice::from_raw_parts(tx_bytes, tx_len);
    let tx = unwrap_or_return!(Transaction::consensus_decode(&mut &tx_slice[..]), error);

    use key_wallet::transaction_checking::transaction_router::TransactionRouter;
    let tx_type = TransactionRouter::classify_transaction(&tx);
    unwrap_or_return!(CString::new(format!("{:?}", tx_type)), error).into_raw()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_context_conversion() {
        // Test that FFI transaction context values match expectations
        assert_eq!(FFITransactionContextType::Mempool as u32, 0);
        assert_eq!(FFITransactionContextType::InstantSend as u32, 1);
        assert_eq!(FFITransactionContextType::InBlock as u32, 2);
        assert_eq!(FFITransactionContextType::InChainLockedBlock as u32, 3);
    }
}
