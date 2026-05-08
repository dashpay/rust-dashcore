//! FFI bindings for WalletManager

#[cfg(test)]
#[path = "wallet_manager_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "wallet_manager_serialization_tests.rs"]
mod serialization_tests;

use crate::error::FFIError;
use crate::{check_ptr, deref_ptr, deref_ptr_mut, unwrap_or_return};
use dash_network::ffi::FFINetwork;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::WalletInterface;
use key_wallet_manager::WalletManager;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};
use std::ptr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// FFI wrapper for WalletManager
///
/// This struct holds a cloned Arc reference to the WalletManager,
/// allowing FFI code to interact with it directly without going through
/// the SPV client.
pub struct FFIWalletManager {
    network: FFINetwork,
    pub(crate) manager: Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
    pub(crate) runtime: Arc<tokio::runtime::Runtime>,
}

impl FFIWalletManager {
    /// Create a new FFIWalletManager from an `Arc<RwLock<WalletManager>>`
    pub fn from_arc(
        manager: Arc<RwLock<WalletManager<ManagedWalletInfo>>>,
        runtime: Arc<tokio::runtime::Runtime>,
    ) -> Self {
        let network = runtime.block_on(async {
            let manager_guard = manager.read().await;
            manager_guard.network()
        });

        FFIWalletManager {
            network: FFINetwork::from(network),
            manager,
            runtime,
        }
    }

    pub fn network(&self) -> FFINetwork {
        self.network
    }
}

/// Describe the wallet manager for a given network and return a newly
/// allocated C string.
///
/// # Safety
/// - `manager` must be a valid pointer to an `FFIWalletManager`
/// - Callers must free the returned string with `wallet_manager_free_string`
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_describe(
    manager: *const FFIWalletManager,
    error: *mut FFIError,
) -> *mut c_char {
    let manager_ref = deref_ptr!(manager, error);
    let runtime = manager_ref.runtime.clone();
    let manager_arc = manager_ref.manager.clone();

    let description = runtime.block_on(async {
        let guard = manager_arc.read().await;
        guard.describe().await
    });

    unwrap_or_return!(CString::new(description), error).into_raw()
}

/// Free a string previously returned by wallet manager APIs.
///
/// # Safety
/// - `value` must be either null or a pointer obtained from
///   `wallet_manager_describe` (or other wallet manager FFI helpers that
///   specify this free function).
/// - The pointer must not be used after this call returns.
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_free_string(value: *mut c_char) {
    if value.is_null() {
        return;
    }

    drop(CString::from_raw(value));
}

/// Create a new wallet manager
///
/// # Safety
///
/// `error` must be a valid pointer to an `FFIError`. The returned pointer must be
/// freed with `wallet_manager_free`.
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_create(
    network: FFINetwork,
    error: *mut FFIError,
) -> *mut FFIWalletManager {
    let manager = WalletManager::new(network.into());
    let runtime = unwrap_or_return!(tokio::runtime::Runtime::new(), error);

    Box::into_raw(Box::new(FFIWalletManager {
        network,
        manager: Arc::new(RwLock::new(manager)),
        runtime: Arc::new(runtime),
    }))
}

/// Add a wallet from mnemonic to the manager with options
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `mnemonic` must be a valid pointer to a null-terminated C string
/// - `account_options` must be a valid pointer to FFIWalletAccountCreationOptions or null
/// - `error` must be a valid pointer to an FFIError structure
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_add_wallet_from_mnemonic_with_options(
    manager: *mut FFIWalletManager,
    mnemonic: *const c_char,
    account_options: *const crate::types::FFIWalletAccountCreationOptions,
    error: *mut FFIError,
) -> bool {
    let manager_ref = deref_ptr!(manager, error);
    let mnemonic = deref_ptr!(mnemonic, error);
    let mnemonic_str = unwrap_or_return!(CStr::from_ptr(mnemonic).to_str(), error);

    let creation_options = if account_options.is_null() {
        key_wallet::wallet::initialization::WalletAccountCreationOptions::Default
    } else {
        (*account_options).to_wallet_options()
    };

    let result = manager_ref.runtime.block_on(async {
        let mut manager_guard = manager_ref.manager.write().await;
        manager_guard.create_wallet_from_mnemonic(mnemonic_str, 0, creation_options)
    });
    let _ = unwrap_or_return!(result, error);
    true
}

/// Add a wallet from mnemonic to the manager (backward compatibility)
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `mnemonic` must be a valid pointer to a null-terminated C string
/// - `error` must be a valid pointer to an FFIError structure
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_add_wallet_from_mnemonic(
    manager: *mut FFIWalletManager,
    mnemonic: *const c_char,
    error: *mut FFIError,
) -> bool {
    wallet_manager_add_wallet_from_mnemonic_with_options(
        manager,
        mnemonic,
        ptr::null(), // Use default options
        error,
    )
}

/// Add a wallet from mnemonic to the manager and return serialized bytes
///
/// Creates a wallet from a mnemonic phrase, adds it to the manager, optionally downgrading it
/// to a pubkey-only wallet (watch-only or externally signable), and returns the serialized wallet bytes.
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `mnemonic` must be a valid pointer to a null-terminated C string
/// - `birth_height` is the block height to start syncing from (0 = sync from genesis)
/// - `account_options` must be a valid pointer to FFIWalletAccountCreationOptions or null
/// - `downgrade_to_pubkey_wallet` if true, creates a watch-only or externally signable wallet
/// - `allow_external_signing` if true AND downgrade_to_pubkey_wallet is true, creates an externally signable wallet
/// - `wallet_bytes_out` must be a valid pointer to a pointer that will receive the serialized bytes
/// - `wallet_bytes_len_out` must be a valid pointer that will receive the byte length
/// - `wallet_id_out` must be a valid pointer to a 32-byte array that will receive the wallet ID
/// - `error` must be a valid pointer to an FFIError structure
/// - The caller must ensure all pointers remain valid for the duration of this call
/// - The caller must free the returned wallet_bytes using wallet_manager_free_wallet_bytes()
#[cfg(feature = "bincode")]
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn wallet_manager_add_wallet_from_mnemonic_return_serialized_bytes(
    manager: *mut FFIWalletManager,
    mnemonic: *const c_char,
    birth_height: c_uint,
    account_options: *const crate::types::FFIWalletAccountCreationOptions,
    downgrade_to_pubkey_wallet: bool,
    allow_external_signing: bool,
    wallet_bytes_out: *mut *mut u8,
    wallet_bytes_len_out: *mut usize,
    wallet_id_out: *mut u8,
    error: *mut FFIError,
) -> bool {
    let manager_ref = deref_ptr!(manager, error);
    let mnemonic = deref_ptr!(mnemonic, error);
    check_ptr!(wallet_bytes_out, error);
    check_ptr!(wallet_bytes_len_out, error);
    check_ptr!(wallet_id_out, error);

    let mnemonic_str = unwrap_or_return!(CStr::from_ptr(mnemonic).to_str(), error);

    let creation_options = if account_options.is_null() {
        key_wallet::wallet::initialization::WalletAccountCreationOptions::Default
    } else {
        (*account_options).to_wallet_options()
    };

    let result = manager_ref.runtime.block_on(async {
        let mut manager_guard = manager_ref.manager.write().await;

        manager_guard.create_wallet_from_mnemonic_return_serialized_bytes(
            mnemonic_str,
            birth_height,
            creation_options,
            downgrade_to_pubkey_wallet,
            allow_external_signing,
        )
    });

    let (serialized, wallet_id) = unwrap_or_return!(result, error);

    // Allocate memory for the serialized bytes
    let boxed_bytes = serialized.into_boxed_slice();
    let bytes_len = boxed_bytes.len();
    let bytes_ptr = Box::into_raw(boxed_bytes) as *mut u8;

    // Write output values
    unsafe {
        *wallet_bytes_out = bytes_ptr;
        *wallet_bytes_len_out = bytes_len;
        ptr::copy_nonoverlapping(wallet_id.as_ptr(), wallet_id_out, 32);
    }

    (*error).clean();
    true
}

/// Free wallet bytes buffer
///
/// # Safety
///
/// - `wallet_bytes` must be a valid pointer to a buffer allocated by wallet_manager_add_wallet_from_mnemonic_return_serialized_bytes
/// - `bytes_len` must match the original allocation size
/// - The pointer must not be used after calling this function
/// - This function must only be called once per buffer
#[cfg(feature = "bincode")]
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_free_wallet_bytes(wallet_bytes: *mut u8, bytes_len: usize) {
    if !wallet_bytes.is_null() && bytes_len > 0 {
        unsafe {
            // Reconstruct the boxed slice with the correct DST pointer
            ptr::write_bytes(wallet_bytes, 0, bytes_len);
            let _ = Box::from_raw(ptr::slice_from_raw_parts_mut(wallet_bytes, bytes_len));
        }
    }
}

/// Import a wallet from bincode-serialized bytes
///
/// Deserializes a wallet from bytes and adds it to the manager.
/// Returns a 32-byte wallet ID on success.
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `wallet_bytes` must be a valid pointer to bincode-serialized wallet bytes
/// - `wallet_bytes_len` must be the exact length of the wallet bytes
/// - `wallet_id_out` must be a valid pointer to a 32-byte array that will receive the wallet ID
/// - `error` must be a valid pointer to an FFIError structure
/// - The caller must ensure all pointers remain valid for the duration of this call
#[cfg(feature = "bincode")]
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_import_wallet_from_bytes(
    manager: *mut FFIWalletManager,
    wallet_bytes: *const u8,
    wallet_bytes_len: usize,
    wallet_id_out: *mut u8,
    error: *mut FFIError,
) -> bool {
    let manager_ref = deref_ptr!(manager, error);
    check_ptr!(wallet_bytes, error);
    check_ptr!(wallet_id_out, error);

    let wallet_bytes_slice = std::slice::from_raw_parts(wallet_bytes, wallet_bytes_len);

    // Import the wallet using async runtime
    let result = manager_ref.runtime.block_on(async {
        let mut manager_guard = manager_ref.manager.write().await;
        manager_guard.import_wallet_from_bytes(wallet_bytes_slice)
    });

    let wallet_id = unwrap_or_return!(result, error);
    // Copy the wallet ID to the output buffer
    unsafe {
        ptr::copy_nonoverlapping(wallet_id.as_ptr(), wallet_id_out, 32);
    }
    true
}

/// Get wallet IDs
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager
/// - `wallet_ids_out` must be a valid pointer to a pointer that will receive the wallet IDs
/// - `count_out` must be a valid pointer to receive the count
/// - `error` must be a valid pointer to an FFIError structure
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_get_wallet_ids(
    manager: *const FFIWalletManager,
    wallet_ids_out: *mut *mut u8,
    count_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    let manager_ref = deref_ptr!(manager, error);
    check_ptr!(wallet_ids_out, error);
    check_ptr!(count_out, error);

    // Get wallet IDs from the manager
    let wallet_ids = manager_ref.runtime.block_on(async {
        let manager_guard = manager_ref.manager.read().await;
        manager_guard.list_wallets().into_iter().cloned().collect::<Vec<_>>()
    });

    let count = wallet_ids.len();
    if count == 0 {
        *count_out = 0;
        *wallet_ids_out = ptr::null_mut();
    } else {
        // Allocate memory for wallet IDs (32 bytes each) as a boxed slice
        let mut ids_buffer = Vec::with_capacity(count * 32);
        for wallet_id in wallet_ids.iter() {
            ids_buffer.extend_from_slice(wallet_id);
        }
        // Convert to boxed slice for consistent memory layout
        let boxed_slice = ids_buffer.into_boxed_slice();
        let ids_ptr = Box::into_raw(boxed_slice) as *mut u8;

        *wallet_ids_out = ids_ptr;
        *count_out = count;
    }
    true
}

/// Get a wallet from the manager
///
/// Returns a reference to the wallet if found
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `wallet_id` must be a valid pointer to a 32-byte wallet ID
/// - `error` must be a valid pointer to an FFIError structure
/// - The caller must ensure all pointers remain valid for the duration of this call
/// - The returned wallet must be freed with wallet_free_const()
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_get_wallet(
    manager: *const FFIWalletManager,
    wallet_id: *const u8,
    error: *mut FFIError,
) -> *const crate::types::FFIWallet {
    let manager_ref = deref_ptr!(manager, error);
    check_ptr!(wallet_id, error);

    let mut wallet_id_array = [0u8; 32];
    ptr::copy_nonoverlapping(wallet_id, wallet_id_array.as_mut_ptr(), 32);

    let wallet_opt = manager_ref.runtime.block_on(async {
        let manager_guard = manager_ref.manager.read().await;
        manager_guard.get_wallet(&wallet_id_array).cloned()
    });
    let wallet = unwrap_or_return!(wallet_opt, error);
    Box::into_raw(Box::new(crate::types::FFIWallet::new(wallet)))
}

/// Get managed wallet info from the manager
///
/// Returns a reference to the managed wallet info if found
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `wallet_id` must be a valid pointer to a 32-byte wallet ID
/// - `error` must be a valid pointer to an FFIError structure
/// - The caller must ensure all pointers remain valid for the duration of this call
/// - The returned managed wallet info must be freed with managed_wallet_info_free()
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_get_managed_wallet_info(
    manager: *const FFIWalletManager,
    wallet_id: *const u8,
    error: *mut FFIError,
) -> *mut crate::managed_wallet::FFIManagedWalletInfo {
    let manager_ref = deref_ptr!(manager, error);
    check_ptr!(wallet_id, error);

    let mut wallet_id_array = [0u8; 32];
    ptr::copy_nonoverlapping(wallet_id, wallet_id_array.as_mut_ptr(), 32);

    let wallet_info_opt = manager_ref.runtime.block_on(async {
        let manager_guard = manager_ref.manager.read().await;
        manager_guard.get_wallet_info(&wallet_id_array).cloned()
    });
    let wallet_info = unwrap_or_return!(wallet_info_opt, error);
    Box::into_raw(Box::new(crate::managed_wallet::FFIManagedWalletInfo::new(wallet_info)))
}

/// Get wallet balance
///
/// Returns the confirmed and unconfirmed balance for a specific wallet
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `wallet_id` must be a valid pointer to a 32-byte wallet ID
/// - `confirmed_out` must be a valid pointer to a u64 (maps to C uint64_t)
/// - `unconfirmed_out` must be a valid pointer to a u64 (maps to C uint64_t)
/// - `error` must be a valid pointer to an FFIError structure
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_get_wallet_balance(
    manager: *const FFIWalletManager,
    wallet_id: *const u8,
    confirmed_out: *mut u64,
    unconfirmed_out: *mut u64,
    error: *mut FFIError,
) -> bool {
    let manager_ref = deref_ptr!(manager, error);
    check_ptr!(wallet_id, error);
    check_ptr!(confirmed_out, error);
    check_ptr!(unconfirmed_out, error);

    let mut wallet_id_array = [0u8; 32];
    ptr::copy_nonoverlapping(wallet_id, wallet_id_array.as_mut_ptr(), 32);

    let result = manager_ref.runtime.block_on(async {
        let manager_guard = manager_ref.manager.read().await;
        manager_guard.get_wallet_balance(&wallet_id_array)
    });
    let balance = unwrap_or_return!(result, error);
    *confirmed_out = balance.confirmed();
    *unconfirmed_out = balance.unconfirmed();
    true
}

/// Process a transaction through all wallets
///
/// Checks a transaction against all wallets and updates their states if relevant.
/// Returns true if the transaction was relevant to at least one wallet.
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `tx_bytes` must be a valid pointer to transaction bytes
/// - `tx_len` must be the length of the transaction bytes
/// - `context` must be a valid pointer to FFITransactionContext
/// - `update_state_if_found` indicates whether to update wallet state when transaction is relevant
/// - `error` must be a valid pointer to an FFIError structure
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_process_transaction(
    manager: *mut FFIWalletManager,
    tx_bytes: *const u8,
    tx_len: usize,
    context: *const crate::types::FFITransactionContext,
    update_state_if_found: bool,
    error: *mut FFIError,
) -> bool {
    let manager_ref = deref_ptr_mut!(manager, error);
    check_ptr!(tx_bytes, error);
    check_ptr!(context, error);

    let tx_slice = std::slice::from_raw_parts(tx_bytes, tx_len);

    use dashcore::blockdata::transaction::Transaction;
    use dashcore::consensus::encode::deserialize;

    let tx: Transaction = unwrap_or_return!(deserialize::<Transaction>(tx_slice), error);

    // Convert FFI context to native TransactionContext
    let context = unwrap_or_return!(unsafe { (*context).to_transaction_context() }, error);

    // Process the transaction using async runtime
    let result = manager_ref.runtime.block_on(async {
        let mut manager_guard = manager_ref.manager.write().await;
        manager_guard
            .check_transaction_in_all_wallets(&tx, context, update_state_if_found, true)
            .await
    });

    (*error).clean();
    !result.affected_wallets.is_empty()
}

/// Get the network for this wallet manager
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager
/// - `error` must be a valid pointer to an FFIError structure
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_network(
    manager: *const FFIWalletManager,
    error: *mut FFIError,
) -> FFINetwork {
    let manager_ref = deref_ptr!(manager, error, FFINetwork::Mainnet);
    manager_ref.network()
}

/// Get current height for a network
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager
/// - `error` must be a valid pointer to an FFIError structure
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_current_height(
    manager: *const FFIWalletManager,
    error: *mut FFIError,
) -> c_uint {
    let manager_ref = deref_ptr!(manager, error);
    manager_ref.runtime.block_on(async {
        let manager_guard = manager_ref.manager.read().await;
        manager_guard.last_processed_height()
    })
}

/// Get wallet count
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager instance
/// - `error` must be a valid pointer to an FFIError structure
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_wallet_count(
    manager: *const FFIWalletManager,
    error: *mut FFIError,
) -> usize {
    let manager_ref = deref_ptr!(manager, error);
    manager_ref.runtime.block_on(async {
        let manager_guard = manager_ref.manager.read().await;
        manager_guard.wallet_count()
    })
}

/// Free wallet manager
///
/// # Safety
///
/// - `manager` must be a valid pointer to an FFIWalletManager that was created by this library
/// - The pointer must not be used after calling this function
/// - This function must only be called once per manager
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_free(manager: *mut FFIWalletManager) {
    if !manager.is_null() {
        unsafe {
            let _ = Box::from_raw(manager);
        }
    }
}

/// Free wallet IDs buffer
///
/// # Safety
///
/// - `wallet_ids` must be a valid pointer to a buffer allocated by this library
/// - `count` must match the number of wallet IDs in the buffer
/// - The pointer must not be used after calling this function
/// - This function must only be called once per buffer
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_free_wallet_ids(wallet_ids: *mut u8, count: usize) {
    if !wallet_ids.is_null() && count > 0 {
        unsafe {
            // Reconstruct the boxed slice with the correct DST pointer
            let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(wallet_ids, count * 32));
        }
    }
}

/// Free address array
///
/// # Safety
///
/// - `addresses` must be a valid pointer to an array of C string pointers allocated by this library
/// - `count` must match the original allocation size
/// - Each address pointer in the array must be either null or a valid C string allocated by this library
/// - The pointers must not be used after calling this function
/// - This function must only be called once per allocation
#[no_mangle]
pub unsafe extern "C" fn wallet_manager_free_addresses(addresses: *mut *mut c_char, count: usize) {
    if !addresses.is_null() {
        let slice = std::slice::from_raw_parts_mut(addresses, count);
        for addr in slice {
            if !addr.is_null() {
                let _ = CString::from_raw(*addr);
            }
        }
        // Free the array itself (matches boxed slice allocation)
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(addresses, count));
    }
}
