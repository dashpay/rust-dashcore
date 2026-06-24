//! Transaction building and management

use crate::error::{FFIError, FFIErrorCode};
use crate::types::{
    transaction_context_from_ffi, FFIBlockInfo, FFITransactionContextType, FFIWallet,
};
use crate::{check_ptr, FFIWalletManager};
use crate::{deref_ptr, deref_ptr_mut, unwrap_or_return};
use dash_network::ffi::FFINetwork;
use dashcore::{
    consensus, hashes::Hash, sighash::SighashCache, EcdsaSighashType, Network, OutPoint, Script,
    ScriptBuf, Transaction, TxIn, TxOut, Txid,
};
use key_wallet::wallet::managed_wallet_info::asset_lock_builder::{
    AssetLockFundingType, CreditOutputFunding,
};
use key_wallet::wallet::managed_wallet_info::coin_selection::SelectionStrategy::BranchAndBound;
use key_wallet::wallet::managed_wallet_info::fee::FeeRate;
use key_wallet::wallet::managed_wallet_info::transaction_building::AccountTypePreference;
use secp256k1::{Message, Secp256k1, SecretKey};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::slice;
use std::str::FromStr;
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
    let manager_ref = deref_ptr!(manager, error);
    let wallet_ref = deref_ptr!(wallet, error);
    check_ptr!(outputs, error);
    check_ptr!(tx_bytes_out, error);
    check_ptr!(tx_len_out, error);
    check_ptr!(fee_out, error);

    if outputs_count == 0 {
        (*error).set(FFIErrorCode::InvalidInput, "At least one output required");
        return false;
    }

    let ffi_outputs = slice::from_raw_parts(outputs, outputs_count);
    let mut outputs = Vec::with_capacity(outputs_count);

    for output in ffi_outputs {
        if output.address.is_null() {
            (*error).set(FFIErrorCode::InvalidInput, "Output address pointer is null");
            return false;
        }

        // Convert address from C string
        let address_str = unwrap_or_return!(CStr::from_ptr(output.address).to_str(), error);

        // Parse address using dashcore
        let address = unwrap_or_return!(dashcore::Address::from_str(address_str), error);

        outputs.push((address, output.amount));
    }

    let wallet_id = wallet_ref.inner().wallet_id;

    unsafe {
        manager_ref.runtime.block_on(async {
            let mut manager = manager_ref.manager.write().await;

            let (transaction, fee) = unwrap_or_return!(
                manager
                    .build_and_sign_transaction(
                        &wallet_id,
                        AccountTypePreference::BIP44,
                        account_index,
                        outputs,
                        FeeRate::new(fee_per_kb),
                        BranchAndBound
                    )
                    .await,
                error
            );
            *fee_out = fee;

            // Serialize the transaction
            let serialized = consensus::serialize(&transaction);
            let size = serialized.len();

            let boxed = serialized.into_boxed_slice();
            let tx_bytes = Box::into_raw(boxed) as *mut u8;

            *tx_bytes_out = tx_bytes;
            *tx_len_out = size;

            (*error).clean();
            true
        })
    }
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

/// Get transaction ID from raw transaction bytes
///
/// # Safety
/// - `tx_bytes` must be a valid pointer to transaction bytes
/// - `tx_len` must be the correct length of the transaction
/// - `error` must be a valid pointer to an FFIError
///
/// # Returns
/// - Pointer to null-terminated hex string of TXID (must be freed with string_free)
/// - NULL on error
#[no_mangle]
pub unsafe extern "C" fn transaction_get_txid_from_bytes(
    tx_bytes: *const u8,
    tx_len: usize,
    error: *mut FFIError,
) -> *mut c_char {
    check_ptr!(tx_bytes, error);
    let tx_slice = slice::from_raw_parts(tx_bytes, tx_len);
    let tx: Transaction = unwrap_or_return!(consensus::deserialize(tx_slice), error);
    unwrap_or_return!(CString::new(tx.txid().to_string()), error).into_raw()
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
            if !addr.is_valid_for_network(expected_network) {
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

// MARK: - Asset Lock Transaction

/// The type of funding account used for asset lock key derivation.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FFIAssetLockFundingType {
    /// Identity registration: m/9'/coinType'/5'/0'/index'
    IdentityRegistration = 0,
    /// Identity top-up (bound to a specific identity): m/9'/coinType'/5'/1'/reg_index'/index'
    IdentityTopUp = 1,
    /// Identity top-up (not bound to identity): m/9'/coinType'/5'/1'/index'
    IdentityTopUpNotBound = 2,
    /// Identity invitation: m/9'/coinType'/5'/3'/index'
    IdentityInvitation = 3,
    /// Asset lock address top-up: m/9'/coinType'/5'/4'/index'
    AssetLockAddressTopUp = 4,
    /// Asset lock shielded address top-up: m/9'/coinType'/5'/5'/index'
    AssetLockShieldedAddressTopUp = 5,
}

impl From<FFIAssetLockFundingType> for AssetLockFundingType {
    fn from(ffi: FFIAssetLockFundingType) -> Self {
        match ffi {
            FFIAssetLockFundingType::IdentityRegistration => Self::IdentityRegistration,
            FFIAssetLockFundingType::IdentityTopUp => Self::IdentityTopUp,
            FFIAssetLockFundingType::IdentityTopUpNotBound => Self::IdentityTopUpNotBound,
            FFIAssetLockFundingType::IdentityInvitation => Self::IdentityInvitation,
            FFIAssetLockFundingType::AssetLockAddressTopUp => Self::AssetLockAddressTopUp,
            FFIAssetLockFundingType::AssetLockShieldedAddressTopUp => {
                Self::AssetLockShieldedAddressTopUp
            }
        }
    }
}

/// Build and sign an asset lock transaction for Core to Platform transfers.
///
/// Creates a special transaction (type 8) with `AssetLockPayload` that locks
/// Dash for Platform credits. Derives one unique private key per credit output
/// from the specified funding account types.
///
/// # Parameters
///
/// - `funding_types`: Array of `credit_outputs_count` funding account types,
///   one per credit output (registration, top-up, invitation, etc.)
/// - `identity_indices`: Array of `credit_outputs_count` identity indices.
///   Only used for `IdentityTopUp` entries; ignored for other funding types.
/// - `private_keys_out`: Caller-allocated array of `credit_outputs_count` × 32-byte
///   buffers. On success, each `private_keys_out[i]` receives the one-time private
///   key corresponding to `credit_output_scripts[i]`.
///
/// # Safety
///
/// - All pointer parameters must be valid and non-null
/// - All parallel arrays must have at least `credit_outputs_count` elements
/// - `private_keys_out` must point to an array of `credit_outputs_count` × `[u8; 32]` buffers
/// - Caller must free `tx_bytes_out` with `transaction_bytes_free`
#[no_mangle]
pub unsafe extern "C" fn wallet_build_and_sign_asset_lock_transaction(
    manager: *const FFIWalletManager,
    wallet: *const FFIWallet,
    account_index: u32,
    funding_types: *const FFIAssetLockFundingType,
    identity_indices: *const u32,
    credit_output_scripts: *const *const u8,
    credit_output_script_lens: *const usize,
    credit_output_amounts: *const u64,
    credit_outputs_count: usize,
    fee_per_kb: u64,
    fee_out: *mut u64,
    tx_bytes_out: *mut *mut u8,
    tx_len_out: *mut usize,
    private_keys_out: *mut [u8; 32],
    error: *mut FFIError,
) -> bool {
    check_ptr!(manager, error);
    check_ptr!(wallet, error);
    check_ptr!(funding_types, error);
    check_ptr!(identity_indices, error);
    check_ptr!(credit_output_scripts, error);
    check_ptr!(credit_output_script_lens, error);
    check_ptr!(credit_output_amounts, error);
    check_ptr!(tx_bytes_out, error);
    check_ptr!(tx_len_out, error);
    check_ptr!(fee_out, error);
    check_ptr!(private_keys_out, error);

    if credit_outputs_count == 0 {
        (*error).set(FFIErrorCode::InvalidInput, "At least one credit output required");
        return false;
    }

    unsafe {
        let manager_ref = &*manager;
        let wallet_ref = &*wallet;

        let scripts_slice = slice::from_raw_parts(credit_output_scripts, credit_outputs_count);
        let lens_slice = slice::from_raw_parts(credit_output_script_lens, credit_outputs_count);
        let amounts_slice = slice::from_raw_parts(credit_output_amounts, credit_outputs_count);
        let funding_types_slice = slice::from_raw_parts(funding_types, credit_outputs_count);
        let identity_indices_slice = slice::from_raw_parts(identity_indices, credit_outputs_count);

        // Convert FFI arrays to domain types
        let mut fundings = Vec::with_capacity(credit_outputs_count);
        for i in 0..credit_outputs_count {
            if scripts_slice[i].is_null() {
                (*error).set(
                    FFIErrorCode::InvalidInput,
                    &format!("Credit output script {} is null", i),
                );
                return false;
            }
            let script_bytes = slice::from_raw_parts(scripts_slice[i], lens_slice[i]);
            fundings.push(CreditOutputFunding {
                output: TxOut {
                    value: amounts_slice[i],
                    script_pubkey: ScriptBuf::from(script_bytes.to_vec()),
                },
                funding_type: funding_types_slice[i].into(),
                identity_index: identity_indices_slice[i],
            });
        }

        manager_ref.runtime.block_on(async {
            let mut manager = manager_ref.manager.write().await;
            let wallet_id = wallet_ref.inner().wallet_id;

            let managed_wallet = unwrap_or_return!(manager.get_wallet_info_mut(&wallet_id), error);

            let result = unwrap_or_return!(managed_wallet.build_asset_lock(
                wallet_ref.inner(),
                account_index,
                fundings,
                fee_per_kb,
            ).await, error);

            // Write outputs
            *fee_out = result.fee;

            // `build_asset_lock` always returns private keys; the signer-variant
            // path uses a different FFI entry point.
            let private_keys = match &result.keys {
                key_wallet::wallet::managed_wallet_info::asset_lock_builder::AssetLockCreditKeys::Private(k) => k,
                key_wallet::wallet::managed_wallet_info::asset_lock_builder::AssetLockCreditKeys::Public(_) => {
                    (*error).set(FFIErrorCode::WalletError, "Unexpected public-key result from build_asset_lock");
                    return false;
                }
            };
            let keys_out = slice::from_raw_parts_mut(private_keys_out, credit_outputs_count);
            for (i, key) in private_keys.iter().enumerate() {
                if i < keys_out.len() {
                    keys_out[i] = *key;
                }
            }

            let serialized = consensus::serialize(&result.transaction);
            let size = serialized.len();
            let boxed = serialized.into_boxed_slice();
            *tx_bytes_out = Box::into_raw(boxed) as *mut u8;
            *tx_len_out = size;

            (*error).clean();
            true
        })
    }
}
