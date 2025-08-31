//! Transaction building and management

use std::ffi::CStr;
use std::os::raw::{c_char, c_uint};
use std::ptr;
use std::slice;

use dashcore::{
    consensus, hashes::Hash, sighash::SighashCache, EcdsaSighashType, Network, OutPoint, Script,
    ScriptBuf, Transaction, TxIn, TxOut, Txid,
};
use secp256k1::{Message, Secp256k1, SecretKey};

use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFINetwork, FFINetworks, FFITransactionContext, FFIWallet};

// MARK: - Transaction Types

/// Opaque handle for a transaction
pub struct FFITransaction {
    inner: Transaction,
}

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

/// Build a transaction
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `outputs` must be a valid pointer to an array of FFITxOutput with at least `outputs_count` elements
/// - `tx_bytes_out` must be a valid pointer to store the transaction bytes pointer
/// - `tx_len_out` must be a valid pointer to store the transaction length
/// - `error` must be a valid pointer to an FFIError
/// - The returned transaction bytes must be freed with `transaction_bytes_free`
#[no_mangle]
pub unsafe extern "C" fn wallet_build_transaction(
    wallet: *mut FFIWallet,
    _network: FFINetworks,
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
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `tx_bytes` must be a valid pointer to transaction bytes with at least `tx_len` bytes
/// - `signed_tx_out` must be a valid pointer to store the signed transaction bytes pointer
/// - `signed_len_out` must be a valid pointer to store the signed transaction length
/// - `error` must be a valid pointer to an FFIError
/// - The returned signed transaction bytes must be freed with `transaction_bytes_free`
#[no_mangle]
pub unsafe extern "C" fn wallet_sign_transaction(
    wallet: *const FFIWallet,
    _network: FFINetworks,
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
        let network_rust: Network = network.into();
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
        let wallet_opt = if update_state {
            Some(wallet.inner())
        } else {
            None
        };
        let check_result = managed_info.check_transaction(&tx, network_rust, context, wallet_opt);

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

// MARK: - Transaction Creation

/// Create a new empty transaction
///
/// # Returns
/// - Pointer to FFITransaction on success
/// - NULL on error
#[no_mangle]
pub extern "C" fn transaction_create() -> *mut FFITransaction {
    let tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![],
        output: vec![],
        special_transaction_payload: None,
    };

    Box::into_raw(Box::new(FFITransaction {
        inner: tx,
    }))
}

/// Add an input to a transaction
///
/// # Safety
/// - `tx` must be a valid pointer to an FFITransaction
/// - `input` must be a valid pointer to an FFITxIn
///
/// # Returns
/// - 0 on success
/// - -1 on error
#[no_mangle]
pub unsafe extern "C" fn transaction_add_input(
    tx: *mut FFITransaction,
    input: *const FFITxIn,
) -> i32 {
    if tx.is_null() || input.is_null() {
        return -1;
    }

    let tx = &mut *tx;
    let input = &*input;

    // Convert txid
    let txid = match Txid::from_slice(&input.txid) {
        Ok(txid) => txid,
        Err(_) => {
            return -1;
        }
    };

    // Convert script
    let script_sig = if input.script_sig.is_null() || input.script_sig_len == 0 {
        ScriptBuf::new()
    } else {
        let script_slice = slice::from_raw_parts(input.script_sig, input.script_sig_len as usize);
        ScriptBuf::from(script_slice.to_vec())
    };

    let tx_in = TxIn {
        previous_output: OutPoint {
            txid,
            vout: input.vout,
        },
        script_sig,
        sequence: input.sequence,
        witness: Default::default(),
    };

    tx.inner.input.push(tx_in);
    0
}

/// Add an output to a transaction
///
/// # Safety
/// - `tx` must be a valid pointer to an FFITransaction
/// - `output` must be a valid pointer to an FFITxOut
///
/// # Returns
/// - 0 on success
/// - -1 on error
#[no_mangle]
pub unsafe extern "C" fn transaction_add_output(
    tx: *mut FFITransaction,
    output: *const FFITxOut,
) -> i32 {
    if tx.is_null() || output.is_null() {
        return -1;
    }

    let tx = &mut *tx;
    let output = &*output;

    // Convert script
    let script_pubkey = if output.script_pubkey.is_null() || output.script_pubkey_len == 0 {
        return -1;
    } else {
        let script_slice =
            slice::from_raw_parts(output.script_pubkey, output.script_pubkey_len as usize);
        ScriptBuf::from(script_slice.to_vec())
    };

    let tx_out = TxOut {
        value: output.amount,
        script_pubkey,
    };

    tx.inner.output.push(tx_out);
    0
}

/// Get the transaction ID
///
/// # Safety
/// - `tx` must be a valid pointer to an FFITransaction
/// - `txid_out` must be a valid pointer to a buffer of at least 32 bytes
///
/// # Returns
/// - 0 on success
/// - -1 on error
#[no_mangle]
pub unsafe extern "C" fn transaction_get_txid(tx: *const FFITransaction, txid_out: *mut u8) -> i32 {
    if tx.is_null() || txid_out.is_null() {
        return -1;
    }

    let tx = &*tx;
    let txid = tx.inner.txid();

    let txid_bytes = txid.as_byte_array();
    ptr::copy_nonoverlapping(txid_bytes.as_ptr(), txid_out, 32);
    0
}

/// Serialize a transaction
///
/// # Safety
/// - `tx` must be a valid pointer to an FFITransaction
/// - `out_buf` can be NULL to get size only
/// - `out_len` must be a valid pointer to store the size
///
/// # Returns
/// - 0 on success
/// - -1 on error
#[no_mangle]
pub unsafe extern "C" fn transaction_serialize(
    tx: *const FFITransaction,
    out_buf: *mut u8,
    out_len: *mut u32,
) -> i32 {
    if tx.is_null() || out_len.is_null() {
        return -1;
    }

    let tx = &*tx;
    let serialized = consensus::serialize(&tx.inner);
    let size = serialized.len() as u32;

    if out_buf.is_null() {
        // Just return size
        *out_len = size;
        return 0;
    }

    let provided_size = *out_len;
    if provided_size < size {
        *out_len = size;
        return -1;
    }

    ptr::copy_nonoverlapping(serialized.as_ptr(), out_buf, serialized.len());
    *out_len = size;
    0
}

/// Deserialize a transaction
///
/// # Safety
/// - `data` must be a valid pointer to serialized transaction data
/// - `len` must be the correct length of the data
///
/// # Returns
/// - Pointer to FFITransaction on success
/// - NULL on error
#[no_mangle]
pub unsafe extern "C" fn transaction_deserialize(data: *const u8, len: u32) -> *mut FFITransaction {
    if data.is_null() {
        return ptr::null_mut();
    }

    let slice = slice::from_raw_parts(data, len as usize);

    match consensus::deserialize::<Transaction>(slice) {
        Ok(tx) => Box::into_raw(Box::new(FFITransaction {
            inner: tx,
        })),
        Err(_) => ptr::null_mut(),
    }
}

/// Destroy a transaction
///
/// # Safety
/// - `tx` must be a valid pointer to an FFITransaction created by transaction functions or null
/// - After calling this function, the pointer becomes invalid
#[no_mangle]
pub unsafe extern "C" fn transaction_destroy(tx: *mut FFITransaction) {
    if !tx.is_null() {
        let _ = Box::from_raw(tx);
    }
}

// MARK: - Transaction Signing

/// Calculate signature hash for an input
///
/// # Safety
/// - `tx` must be a valid pointer to an FFITransaction
/// - `script_pubkey` must be a valid pointer to the script pubkey
/// - `hash_out` must be a valid pointer to a buffer of at least 32 bytes
///
/// # Returns
/// - 0 on success
/// - -1 on error
#[no_mangle]
pub unsafe extern "C" fn transaction_sighash(
    tx: *const FFITransaction,
    input_index: u32,
    script_pubkey: *const u8,
    script_pubkey_len: u32,
    sighash_type: u32,
    hash_out: *mut u8,
) -> i32 {
    if tx.is_null() || script_pubkey.is_null() || hash_out.is_null() {
        return -1;
    }

    let tx = &*tx;
    let script_slice = slice::from_raw_parts(script_pubkey, script_pubkey_len as usize);
    let script = Script::from_bytes(script_slice);

    let sighash_type = EcdsaSighashType::from_consensus(sighash_type);
    let cache = SighashCache::new(&tx.inner);

    match cache.legacy_signature_hash(input_index as usize, script, sighash_type.to_u32()) {
        Ok(hash) => {
            let hash_bytes: &[u8] = hash.as_ref();
            ptr::copy_nonoverlapping(hash_bytes.as_ptr(), hash_out, 32);
            0
        }
        Err(_) => -1,
    }
}

/// Sign a transaction input
///
/// # Safety
/// - `tx` must be a valid pointer to an FFITransaction
/// - `private_key` must be a valid pointer to a 32-byte private key
/// - `script_pubkey` must be a valid pointer to the script pubkey
///
/// # Returns
/// - 0 on success
/// - -1 on error
#[no_mangle]
pub unsafe extern "C" fn transaction_sign_input(
    tx: *mut FFITransaction,
    input_index: u32,
    private_key: *const u8,
    script_pubkey: *const u8,
    script_pubkey_len: u32,
    sighash_type: u32,
) -> i32 {
    if tx.is_null() || private_key.is_null() || script_pubkey.is_null() {
        return -1;
    }

    let tx = &mut *tx;
    let input_index = input_index as usize;

    if input_index >= tx.inner.input.len() {
        return -1;
    }

    // Calculate sighash
    let mut sighash = [0u8; 32];
    if transaction_sighash(
        tx as *const FFITransaction,
        input_index as u32,
        script_pubkey,
        script_pubkey_len,
        sighash_type,
        sighash.as_mut_ptr(),
    ) != 0
    {
        return -1;
    }

    // Parse private key
    let privkey_slice = slice::from_raw_parts(private_key, 32);
    let privkey = match SecretKey::from_slice(privkey_slice) {
        Ok(k) => k,
        Err(_) => {
            return -1;
        }
    };

    // Sign
    let secp = Secp256k1::new();
    let message = Message::from_digest(sighash);
    let sig = secp.sign_ecdsa(&message, &privkey);

    // Build signature script (simplified P2PKH)
    let mut sig_bytes = sig.serialize_der().to_vec();
    sig_bytes.push(sighash_type as u8);

    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &privkey);
    let pubkey_bytes = pubkey.serialize();

    let mut script_sig = vec![];
    script_sig.push(sig_bytes.len() as u8);
    script_sig.extend_from_slice(&sig_bytes);
    script_sig.push(pubkey_bytes.len() as u8);
    script_sig.extend_from_slice(&pubkey_bytes);

    tx.inner.input[input_index].script_sig = ScriptBuf::from(script_sig);
    0
}

// MARK: - Script Utilities

/// Create a P2PKH script pubkey
///
/// # Safety
/// - `pubkey_hash` must be a valid pointer to a 20-byte public key hash
/// - `out_buf` can be NULL to get size only
/// - `out_len` must be a valid pointer to store the size
///
/// # Returns
/// - 0 on success
/// - -1 on error
#[no_mangle]
pub unsafe extern "C" fn script_p2pkh(
    pubkey_hash: *const u8,
    out_buf: *mut u8,
    out_len: *mut u32,
) -> i32 {
    if pubkey_hash.is_null() || out_len.is_null() {
        return -1;
    }

    let hash_slice = slice::from_raw_parts(pubkey_hash, 20);

    // Build P2PKH script: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
    let mut script = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 PUSH(20)
    script.extend_from_slice(hash_slice);
    script.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG

    let size = script.len() as u32;

    if out_buf.is_null() {
        *out_len = size;
        return 0;
    }

    let provided_size = *out_len;
    if provided_size < size {
        *out_len = size;
        return -1;
    }

    ptr::copy_nonoverlapping(script.as_ptr(), out_buf, script.len());
    *out_len = size;
    0
}

/// Extract public key hash from P2PKH address
///
/// # Safety
/// - `address` must be a valid pointer to a null-terminated C string
/// - `hash_out` must be a valid pointer to a buffer of at least 20 bytes
///
/// # Returns
/// - 0 on success
/// - -1 on error
#[no_mangle]
pub unsafe extern "C" fn address_to_pubkey_hash(
    address: *const c_char,
    network: FFINetwork,
    hash_out: *mut u8,
) -> i32 {
    if address.is_null() || hash_out.is_null() {
        return -1;
    }

    let address_str = match CStr::from_ptr(address).to_str() {
        Ok(s) => s,
        Err(_) => {
            return -1;
        }
    };

    let expected_network: Network = network.into();

    match address_str.parse::<dashcore::Address<_>>() {
        Ok(addr) => {
            if *addr.network() != expected_network {
                return -1;
            }

            match addr.payload() {
                dashcore::address::Payload::PubkeyHash(hash) => {
                    let hash_bytes = hash.as_byte_array();
                    ptr::copy_nonoverlapping(hash_bytes.as_ptr(), hash_out, 20);
                    0
                }
                _ => -1,
            }
        }
        Err(_) => -1,
    }
}

#[cfg(test)]
#[path = "transaction_tests.rs"]
mod transaction_tests;
