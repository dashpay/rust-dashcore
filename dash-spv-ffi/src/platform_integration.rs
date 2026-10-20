use crate::{set_last_error, FFIDashSpvClient, FFIErrorCode};
use dashcore::hashes::Hash;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::QuorumHash;
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
    let spv_client = &client.inner;

    // Read the quorum hash from the input pointer
    let quorum_hash_bytes = std::slice::from_raw_parts(quorum_hash, 32);
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(quorum_hash_bytes);

    // Convert quorum type and hash for engine lookup (infallible)
    let llmq_type: LLMQType = (quorum_type as u8).into();
    let quorum_hash = QuorumHash::from_byte_array(hash_array);

    // Get the masternode list engine directly for efficient access
    let engine = match spv_client.masternode_list_engine() {
        Ok(engine) => engine,
        Err(e) => {
            return FFIResult::error(
                FFIErrorCode::RuntimeError,
                &format!(
                    "Masternode list engine not initialized: {}. Core SDK may still be syncing.",
                    e
                ),
            );
        }
    };

    let engine_guard = engine.blocking_read();
    match engine_guard.quorum_entry_for_hash_at_or_before_height(
        llmq_type,
        quorum_hash,
        core_chain_locked_height,
    ) {
        Some((_list_height, quorum)) => {
            let pubkey_bytes: &[u8; 48] = quorum.quorum_entry.quorum_public_key.as_ref();
            std::ptr::copy_nonoverlapping(pubkey_bytes.as_ptr(), out_pubkey, QUORUM_PUBKEY_SIZE);

            FFIResult {
                error_code: 0,
                error_message: ptr::null(),
            }
        }
        None => FFIResult::error(
            FFIErrorCode::ValidationError,
            &format!(
                "Quorum not found: type {} at or before height {} with hash {:x}",
                quorum_type, core_chain_locked_height, quorum_hash
            ),
        ),
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

    // Get the network from the client config
    let network = client.runtime.block_on(async { client.inner.network().await });

    // Platform activation heights per network
    let height = match network {
        dashcore::Network::Mainnet => 1_888_888, // Mainnet (placeholder - needs verification)
        dashcore::Network::Testnet => 1_289_520, // Testnet confirmed height
        dashcore::Network::Devnet => 1,          // Devnet starts immediately
        _ => 0,                                  // Unknown network
    };

    // Set the output value
    *out_height = height;

    // Return success
    FFIResult {
        error_code: 0,
        error_message: ptr::null(),
    }
}
