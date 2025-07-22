use crate::{set_last_error, FFIDashSpvClient, FFIErrorCode};
use std::os::raw::c_char;
use std::ptr;

/// Handle for Core SDK that can be passed to Platform SDK
#[repr(C)]
pub struct CoreSDKHandle {
    pub client: *mut FFIDashSpvClient,
}

/// FFIResult type for error handling
#[repr(C)]
pub struct FFIResult {
    pub error_code: i32,
    pub error_message: *const c_char,
}

impl FFIResult {
    fn error(code: FFIErrorCode, message: &str) -> Self {
        set_last_error(message);
        FFIResult {
            error_code: code as i32,
            error_message: crate::dash_spv_ffi_get_last_error(),
        }
    }
}

/// Creates a CoreSDKHandle from an FFIDashSpvClient
///
/// # Safety
///
/// This function is unsafe because:
/// - The caller must ensure the client pointer is valid
/// - The returned handle must be properly released with ffi_dash_spv_release_core_handle
#[no_mangle]
pub unsafe extern "C" fn ffi_dash_spv_get_core_handle(
    client: *mut FFIDashSpvClient,
) -> *mut CoreSDKHandle {
    if client.is_null() {
        set_last_error("Null client pointer");
        return ptr::null_mut();
    }

    Box::into_raw(Box::new(CoreSDKHandle { client }))
}

/// Releases a CoreSDKHandle
///
/// # Safety
///
/// This function is unsafe because:
/// - The caller must ensure the handle pointer is valid
/// - The handle must not be used after this call
#[no_mangle]
pub unsafe extern "C" fn ffi_dash_spv_release_core_handle(handle: *mut CoreSDKHandle) {
    if !handle.is_null() {
        let _ = Box::from_raw(handle);
    }
}

/// Gets a quorum public key from the Core chain
///
/// # Safety
///
/// This function is unsafe because:
/// - The caller must ensure all pointers are valid
/// - quorum_hash must point to a 32-byte array
/// - out_pubkey must point to a buffer of at least out_pubkey_size bytes
/// - out_pubkey_size must be at least 48 bytes
#[no_mangle]
pub unsafe extern "C" fn ffi_dash_spv_get_quorum_public_key(
    client: *mut FFIDashSpvClient,
    quorum_type: u32,
    quorum_hash: *const u8,
    core_chain_locked_height: u32,
    out_pubkey: *mut u8,
    out_pubkey_size: usize,
) -> FFIResult {
    // Validate client pointer
    if client.is_null() {
        return FFIResult::error(FFIErrorCode::NullPointer, "Null client pointer");
    }

    // Validate quorum_hash pointer
    if quorum_hash.is_null() {
        return FFIResult::error(FFIErrorCode::NullPointer, "Null quorum_hash pointer");
    }

    // Validate output buffer pointer
    if out_pubkey.is_null() {
        return FFIResult::error(FFIErrorCode::NullPointer, "Null out_pubkey pointer");
    }

    // Validate buffer size - quorum public keys are 48 bytes
    const QUORUM_PUBKEY_SIZE: usize = 48;
    if out_pubkey_size < QUORUM_PUBKEY_SIZE {
        return FFIResult::error(
            FFIErrorCode::InvalidArgument,
            &format!(
                "Buffer too small: {} bytes provided, {} bytes required",
                out_pubkey_size, QUORUM_PUBKEY_SIZE
            ),
        );
    }

    // Get the client reference
    let client = &*client;
    
    // Access the inner client through the mutex
    let inner_guard = match client.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return FFIResult::error(FFIErrorCode::RuntimeError, "Failed to lock client mutex");
        }
    };
    
    // Get the SPV client
    let spv_client = match inner_guard.as_ref() {
        Some(client) => client,
        None => {
            return FFIResult::error(FFIErrorCode::RuntimeError, "Client not initialized");
        }
    };
    
    // Read the quorum hash from the input pointer
    let quorum_hash_bytes = std::slice::from_raw_parts(quorum_hash, 32);
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(quorum_hash_bytes);
    
    // Get the quorum from the masternode list at the specified height
    match spv_client.get_quorum_at_height(core_chain_locked_height, quorum_type as u8, &hash_array) {
        Some(qualified_quorum_entry) => {
            // Get the public key bytes
            let pubkey = &qualified_quorum_entry.quorum_entry.quorum_public_key;
            
            // BLSPublicKey is 48 bytes
            const PUBKEY_SIZE: usize = 48;
            if out_pubkey_size < PUBKEY_SIZE {
                return FFIResult::error(
                    FFIErrorCode::InvalidArgument,
                    &format!("Buffer too small: {} bytes provided, {} bytes required", out_pubkey_size, PUBKEY_SIZE),
                );
            }
            
            // Copy the public key bytes using unsafe transmute
            let pubkey_ptr = pubkey as *const _ as *const u8;
            std::ptr::copy_nonoverlapping(pubkey_ptr, out_pubkey, PUBKEY_SIZE);
            
            // Return success
            FFIResult {
                error_code: 0,
                error_message: ptr::null(),
            }
        }
        None => {
            // Check if this is due to missing masternode list to provide better error message
            let has_mn_list = spv_client.get_masternode_list_at_height(core_chain_locked_height).is_some();
            
            if !has_mn_list {
                // Get the masternode list engine to check available heights
                let available_info = if let Some(engine) = spv_client.masternode_list_engine() {
                    let total_lists = engine.masternode_lists.len();
                    let min_height = engine.masternode_lists.keys().min().copied().unwrap_or(0);
                    let max_height = engine.masternode_lists.keys().max().copied().unwrap_or(0);
                    format!(
                        " Core SDK has {} masternode lists ranging from height {} to {}.",
                        total_lists,
                        min_height,
                        max_height
                    )
                } else {
                    String::from(" Core SDK masternode engine not initialized.")
                };
                
                FFIResult::error(
                    FFIErrorCode::ValidationError,
                    &format!(
                        "Masternode list not available at height {}.{} The Core SDK may still be syncing masternode lists. Please ensure Core SDK has completed masternode sync before querying quorum public keys.",
                        core_chain_locked_height,
                        available_info
                    ),
                )
            } else {
                // Masternode list exists but quorum not found
                FFIResult::error(
                    FFIErrorCode::ValidationError,
                    &format!(
                        "Quorum not found for type {} at height {} with hash {}. The masternode list exists at this height but does not contain the requested quorum.",
                        quorum_type,
                        core_chain_locked_height,
                        hex::encode(quorum_hash_bytes)
                    ),
                )
            }
        }
    }
}

/// Gets the platform activation height from the Core chain
///
/// # Safety
///
/// This function is unsafe because:
/// - The caller must ensure all pointers are valid
/// - out_height must point to a valid u32
#[no_mangle]
pub unsafe extern "C" fn ffi_dash_spv_get_platform_activation_height(
    client: *mut FFIDashSpvClient,
    out_height: *mut u32,
) -> FFIResult {
    // Validate client pointer
    if client.is_null() {
        return FFIResult::error(FFIErrorCode::NullPointer, "Null client pointer");
    }

    // Validate output pointer
    if out_height.is_null() {
        return FFIResult::error(FFIErrorCode::NullPointer, "Null out_height pointer");
    }

    // Get the client reference
    let client = &*client;
    
    // Access the inner client through the mutex
    let inner_guard = match client.inner.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return FFIResult::error(FFIErrorCode::RuntimeError, "Failed to lock client mutex");
        }
    };
    
    // Get the network from the client config
    let height = match inner_guard.as_ref() {
        Some(spv_client) => {
            // Platform activation heights per network
            match spv_client.network() {
                dashcore::Network::Dash => 1_888_888,     // Mainnet (placeholder - needs verification)
                dashcore::Network::Testnet => 1_289_520,  // Testnet confirmed height
                dashcore::Network::Devnet => 1,           // Devnet starts immediately
                _ => 0,                                    // Unknown network
            }
        }
        None => {
            return FFIResult::error(FFIErrorCode::RuntimeError, "Client not initialized");
        }
    };
    
    // Set the output value
    *out_height = height;
    
    // Return success
    FFIResult {
        error_code: 0,
        error_message: ptr::null(),
    }
}