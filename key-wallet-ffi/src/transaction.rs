//! Transaction building and management

use std::ffi::CStr;
use std::os::raw::c_char;
use std::slice;

use dashcore::consensus;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet_manager::FeeRate;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFITransactionContext, FFIWallet};
use crate::FFIWalletManager;

// MARK: - Transaction Types

/// FFI-compatible transaction input
#[repr(C)]
pub struct FFITxIn {
    /// Transaction ID (32 bytes)
    pub txid: [u8; 32],
    /// Output index
    pub vout: u32,
    /// Script signature length
    pub script_sig_len: u32,
    /// Script signature data pointer
    pub script_sig: *const u8,
    /// Sequence number
    pub sequence: u32,
}

/// FFI-compatible transaction output
#[repr(C)]
pub struct FFITxOut {
    /// Amount in duffs
    pub amount: u64,
    /// Script pubkey length
    pub script_pubkey_len: u32,
    /// Script pubkey data pointer
    pub script_pubkey: *const u8,
}

/// Transaction output for building (legacy structure)
#[repr(C)]
pub struct FFITxOutput {
    pub address: *const c_char,
    pub amount: u64,
}

/// Build and sign a transaction using the wallet's managed info
///
/// This is the recommended way to build transactions. It handles:
/// - UTXO selection using coin selection algorithms
/// - Fee calculation
/// - Change address generation
/// - Transaction signing
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `account_index` must be a valid BIP44 account index present in the wallet
/// - `outputs` must be a valid pointer to an array of FFITxOutput with at least `outputs_count` elements
/// - `fee_rate` must be a valid variant of FFIFeeRate
/// - `fee_out` must be a valid, non-null pointer to a `u64`; on success it receives the
///   calculated transaction fee in duffs
/// - `tx_bytes_out` must be a valid pointer to store the transaction bytes pointer
/// - `tx_len_out` must be a valid pointer to store the transaction length
/// - `error` must be a valid pointer to an FFIError
/// - The returned transaction bytes must be freed with `transaction_bytes_free`
#[no_mangle]
pub unsafe extern "C" fn wallet_build_and_sign_transaction(
    manager: *const FFIWalletManager,
    wallet: *const FFIWallet,
    account_index: u32,
    outputs: *const FFITxOutput,
    outputs_count: usize,
    fee_per_kb: u64,
    fee_out: *mut u64,
    tx_bytes_out: *mut *mut u8,
    tx_len_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    // Validate inputs
    if manager.is_null()
        || wallet.is_null()
        || outputs.is_null()
        || tx_bytes_out.is_null()
        || tx_len_out.is_null()
        || fee_out.is_null()
    {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    if outputs_count == 0 {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "At least one output required".to_string(),
        );
        return false;
    }

    unsafe {
        use key_wallet::wallet::managed_wallet_info::coin_selection::SelectionStrategy;
        use key_wallet::wallet::managed_wallet_info::transaction_builder::TransactionBuilder;

        let manager_ref = &*manager;
        let wallet_ref = &*wallet;
        let network_rust = wallet_ref.inner().network;
        let outputs_slice = slice::from_raw_parts(outputs, outputs_count);

        manager_ref.runtime.block_on(async {
            let mut manager = manager_ref.manager.write().await;

            let managed_wallet = manager.get_wallet_info_mut(&wallet_ref.inner().wallet_id);

            let Some(managed_wallet) = managed_wallet else {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Could not obtain ManagedWalletInfo for the provided wallet".to_string(),
                );
                return false;
            };

            // Get the managed account
            let managed_account =
                match managed_wallet.accounts.standard_bip44_accounts.get_mut(&account_index) {
                    Some(account) => account,
                    None => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::WalletError,
                            format!("Account {} not found", account_index),
                        );
                        return false;
                    }
                };

            let wallet_account =
                match wallet_ref.inner().accounts.standard_bip44_accounts.get(&account_index) {
                    Some(account) => account,
                    None => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::WalletError,
                            format!("Wallet account {} not found", account_index),
                        );
                        return false;
                    }
                };

            // Convert FFI outputs to Rust outputs
            let mut tx_builder = TransactionBuilder::new();

            for output in outputs_slice {
                if output.address.is_null() {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::InvalidInput,
                        "Output address pointer is null".to_string(),
                    );
                    return false;
                }

                // Convert address from C string
                let address_str = match CStr::from_ptr(output.address).to_str() {
                    Ok(s) => s,
                    Err(_) => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::InvalidInput,
                            "Invalid UTF-8 in output address".to_string(),
                        );
                        return false;
                    }
                };

                // Parse address using dashcore
                use std::str::FromStr;
                let address = match dashcore::Address::from_str(address_str) {
                    Ok(addr) => {
                        // Verify network matches
                        let addr_network = addr.require_network(network_rust).map_err(|e| {
                            FFIError::set_error(
                                error,
                                FFIErrorCode::InvalidAddress,
                                format!("Address network mismatch: {}", e),
                            );
                        });
                        if addr_network.is_err() {
                            return false;
                        }
                        addr_network.unwrap()
                    }
                    Err(e) => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::InvalidAddress,
                            format!("Invalid address: {}", e),
                        );
                        return false;
                    }
                };

                // Add output
                tx_builder = match tx_builder.add_output(&address, output.amount) {
                    Ok(builder) => builder,
                    Err(e) => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::WalletError,
                            format!("Failed to add output: {}", e),
                        );
                        return false;
                    }
                };
            }

            // Get change address (next internal address)
            let xpub = wallet_account.extended_public_key();
            let change_address = match managed_account.next_change_address(Some(&xpub), true) {
                Ok(addr) => addr,
                Err(e) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::WalletError,
                        format!("Failed to get change address: {}", e),
                    );
                    return false;
                }
            };

            tx_builder = tx_builder
                .set_change_address(change_address)
                .set_fee_rate(FeeRate::new(fee_per_kb));

            // Get available UTXOs (collect owned UTXOs, not references)
            let utxos: Vec<key_wallet::Utxo> = managed_account.utxos.values().cloned().collect();

            // Get the wallet's root extended private key for signing
            use key_wallet::wallet::WalletType;

            let root_xpriv = match &wallet_ref.inner().wallet_type {
                WalletType::Mnemonic {
                    root_extended_private_key,
                    ..
                } => root_extended_private_key,
                WalletType::Seed {
                    root_extended_private_key,
                    ..
                } => root_extended_private_key,
                WalletType::ExtendedPrivKey(root_extended_private_key) => root_extended_private_key,
                _ => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::WalletError,
                        "Cannot sign with watch-only wallet".to_string(),
                    );
                    return false;
                }
            };

            // Build a map of address -> derivation path for all addresses in the account
            use std::collections::HashMap;
            let mut address_to_path: HashMap<dashcore::Address, key_wallet::DerivationPath> =
                HashMap::new();

            // Collect from all address pools (receive, change, etc.)
            for pool in managed_account.account_type.address_pools() {
                for addr_info in pool.addresses.values() {
                    address_to_path.insert(addr_info.address.clone(), addr_info.path.clone());
                }
            }

            // Select inputs and build transaction
            let mut tx_builder_with_inputs = match tx_builder.select_inputs(
                &utxos,
                SelectionStrategy::BranchAndBound,
                managed_wallet.synced_height(),
                |utxo| {
                    // Look up the derivation path for this UTXO's address
                    let path = address_to_path.get(&utxo.address)?;

                    // Convert root key to ExtendedPrivKey and derive the child key
                    let root_ext_priv = root_xpriv.to_extended_priv_key(network_rust);
                    let secp = secp256k1::Secp256k1::new();
                    let derived_xpriv = root_ext_priv.derive_priv(&secp, path).ok()?;

                    Some(derived_xpriv.private_key)
                },
            ) {
                Ok(builder) => builder,
                Err(e) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::WalletError,
                        format!("Coin selection failed: {}", e),
                    );
                    return false;
                }
            };

            // Build and sign the transaction
            let transaction = match tx_builder_with_inputs.build() {
                Ok(tx) => tx,
                Err(e) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::WalletError,
                        format!("Failed to build transaction: {}", e),
                    );
                    return false;
                }
            };

            // This is tricky, the transaction creation + fee calculation need a little
            // bit of love to avoid this kind of logic.
            //
            // First, we need to know that TransactionBuilder may add an extra output for change
            // to the final transaction but not to itself, with that knowledge, we can compare the
            // number of outputs in the transaction with the number of outputs in the TransactionBuilder
            // to then call the appropriate fee calculation method
            *fee_out = if transaction.output.len() > tx_builder_with_inputs.outputs().len() {
                tx_builder_with_inputs.calculate_fee_with_extra_output()
            } else {
                tx_builder_with_inputs.calculate_fee()
            };

            // Serialize the transaction
            let serialized = consensus::serialize(&transaction);
            let size = serialized.len();

            let boxed = serialized.into_boxed_slice();
            let tx_bytes = Box::into_raw(boxed) as *mut u8;

            *tx_bytes_out = tx_bytes;
            *tx_len_out = size;

            FFIError::set_success(error);
            true
        })
    }
}

// Transaction context for checking
// FFITransactionContext is imported from types module at the top
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
/// - `inputs_spent_out` must be a valid pointer to store the spent inputs count
/// - `addresses_used_out` must be a valid pointer to store the used addresses count
/// - `new_balance_out` must be a valid pointer to store the new balance
/// - `new_address_out` must be a valid pointer to store the address array pointer
/// - `new_address_count_out` must be a valid pointer to store the address count
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn wallet_check_transaction(
    wallet: *mut FFIWallet,
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

        // Check the transaction - wallet is always required now
        let wallet_mut = match wallet.inner_mut() {
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
            .block_on(managed_info.check_core_transaction(&tx, context, wallet_mut, update_state));

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
///
/// # Safety
///
/// - `tx_bytes` must be a valid pointer created by transaction functions or null
/// - After calling this function, the pointer becomes invalid
#[no_mangle]
pub unsafe extern "C" fn transaction_bytes_free(tx_bytes: *mut u8) {
    if !tx_bytes.is_null() {
        unsafe {
            let _ = Box::from_raw(tx_bytes);
        }
    }
}
