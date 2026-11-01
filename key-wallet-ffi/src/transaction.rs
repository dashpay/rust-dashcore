//! Transaction building and management

use crate::check_ptr;
use crate::error::FFIError;
use crate::types::{
    transaction_context_from_ffi, FFIBlockInfo, FFITransactionContextType, FFIWallet,
};
use crate::{deref_ptr_mut, unwrap_or_return};
use std::os::raw::c_char;
use std::slice;
// MARK: - Transaction Types

/// Transaction output for building (legacy structure)
#[repr(C)]
pub struct FFITxOutput {
    pub address: *const c_char,
    pub amount: u64,
}

// Transaction context for checking
// FFITransactionContextType is imported from types module at the top
/// Transaction check result
#[repr(C)]
pub struct FFITransactionCheckResult {
    /// Whether the transaction belongs to the wallet
    pub is_relevant: bool,
    /// Total amount received
    pub total_received: u64,
    /// Total amount sent
    pub total_sent: u64,
    /// Number of affected accounts
    pub affected_accounts_count: u32,
}

/// Check if a transaction belongs to the wallet using ManagedWalletInfo
///
/// # Safety
///
/// - `wallet` must be a valid mutable pointer to an FFIWallet
/// - `tx_bytes` must be a valid pointer to transaction bytes with at least `tx_len` bytes
/// - `result_out` must be a valid pointer to store the result
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn wallet_check_transaction(
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
    let wallet = deref_ptr_mut!(wallet, error);
    check_ptr!(tx_bytes, error);
    check_ptr!(result_out, error);

    unsafe {
        let tx_slice = slice::from_raw_parts(tx_bytes, tx_len);

        use dashcore::consensus::Decodable;
        let tx =
            unwrap_or_return!(dashcore::Transaction::consensus_decode(&mut &tx_slice[..]), error);

        // Build the transaction context
        let context = unwrap_or_return!(
            transaction_context_from_ffi(context_type, &block_info, islock_data, islock_len),
            error
        );

        // Create a ManagedWalletInfo from the wallet
        use key_wallet::transaction_checking::WalletTransactionChecker;
        use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;

        let mut managed_info = ManagedWalletInfo::from_wallet(wallet.inner(), 0);

        // Check the transaction - wallet is always required now
        let wallet_mut = unwrap_or_return!(wallet.inner_mut(), error);

        // Block on the async check_transaction call
        let check_result = tokio::runtime::Handle::current().block_on(
            managed_info.check_core_transaction(&tx, context, wallet_mut, update_state, true),
        );

        // If we updated state, we need to update the wallet's managed info
        // Note: This would require storing ManagedWalletInfo in FFIWallet
        // For now, we just return the result without persisting changes

        // Fill the result
        *result_out = FFITransactionCheckResult {
            is_relevant: check_result.is_relevant,
            total_received: check_result.total_received,
            total_sent: check_result.total_sent,
            affected_accounts_count: check_result.affected_accounts.len() as u32,
        };

        (*error).clean();
        true
    }
}
