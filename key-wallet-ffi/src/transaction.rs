//! Transaction building and management

use std::ffi::CString;
use std::os::raw::{c_char, c_uint};
use std::ptr;
use std::slice;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFINetwork, FFIWallet};

/// Transaction output for building
#[repr(C)]
pub struct FFITxOutput {
    pub address: *const c_char,
    pub amount: u64,
}

/// Build a transaction
#[no_mangle]
pub extern "C" fn wallet_build_transaction(
    wallet: *mut FFIWallet,
    network: FFINetwork,
    account_index: c_uint,
    outputs: *const FFITxOutput,
    outputs_count: usize,
    fee_per_kb: u64,
    tx_bytes_out: *mut *mut u8,
    tx_len_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() || outputs.is_null() || tx_bytes_out.is_null() || tx_len_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    unsafe {
        let _wallet = &mut *wallet;
        let _network_rust: key_wallet::Network = network.into();
        let _outputs_slice = slice::from_raw_parts(outputs, outputs_count);
        let _account_index = account_index;
        let _fee_per_kb = fee_per_kb;

        // Note: Transaction building would require implementing wallet transaction creation
        // For now, return an error
        FFIError::set_error(
            error,
            FFIErrorCode::WalletError,
            "Transaction building not yet implemented".to_string(),
        );
        false
    }
}

/// Sign a transaction
#[no_mangle]
pub extern "C" fn wallet_sign_transaction(
    wallet: *const FFIWallet,
    network: FFINetwork,
    tx_bytes: *const u8,
    tx_len: usize,
    signed_tx_out: *mut *mut u8,
    signed_len_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() || tx_bytes.is_null() || signed_tx_out.is_null() || signed_len_out.is_null()
    {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    unsafe {
        let _wallet = &*wallet;
        let _network_rust: key_wallet::Network = network.into();
        let _tx_slice = slice::from_raw_parts(tx_bytes, tx_len);

        // Note: Transaction signing would require implementing wallet signing logic
        FFIError::set_error(
            error,
            FFIErrorCode::WalletError,
            "Transaction signing not yet implemented".to_string(),
        );
        false
    }
}

/// Transaction context for checking
#[repr(C)]
pub enum FFITransactionContext {
    /// Transaction is in mempool (unconfirmed)
    Mempool = 0,
    /// Transaction is in a block
    InBlock = 1,
    /// Transaction is in a chain-locked block  
    InChainLockedBlock = 2,
}

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
#[no_mangle]
pub extern "C" fn wallet_check_transaction(
    wallet: *mut FFIWallet,
    network: FFINetwork,
    tx_bytes: *const u8,
    tx_len: usize,
    context_type: FFITransactionContext,
    block_height: u32,
    block_hash: *const u8, // 32 bytes if not null
    timestamp: u64,
    update_state: bool,
    result_out: *mut FFITransactionCheckResult,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() || tx_bytes.is_null() || result_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    unsafe {
        let wallet = &mut *wallet;
        let network_rust: key_wallet::Network = network.into();
        let tx_slice = slice::from_raw_parts(tx_bytes, tx_len);

        // Parse the transaction
        use dashcore::consensus::Decodable;
        let tx = match dashcore::Transaction::consensus_decode(&mut &tx_slice[..]) {
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
        use key_wallet::transaction_checking::TransactionContext;
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

        // Create a ManagedWalletInfo from the wallet
        use key_wallet::transaction_checking::WalletTransactionChecker;
        use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;

        let mut managed_info = ManagedWalletInfo::from_wallet(wallet.inner());

        // Check the transaction
        let check_result = managed_info.check_transaction(&tx, network_rust, context, update_state);

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

        FFIError::set_success(error);
        true
    }
}

/// Free transaction bytes
#[no_mangle]
pub extern "C" fn transaction_bytes_free(tx_bytes: *mut u8) {
    if !tx_bytes.is_null() {
        unsafe {
            let _ = Box::from_raw(tx_bytes);
        }
    }
}

#[cfg(test)]
#[path = "transaction_tests.rs"]
mod tests;
