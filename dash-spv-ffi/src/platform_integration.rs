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

    Box::into_raw(Box::new(CoreSDKHandle {
        client,
    }))
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
    _quorum_type: u32,
    quorum_hash: *const u8,
    _core_chain_locked_height: u32,
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

    // TODO: Implement actual quorum public key retrieval
    // For now, return a placeholder error
    FFIResult::error(
        FFIErrorCode::NotImplemented,
        "Quorum public key retrieval not yet implemented",
    )
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

    // TODO: Implement actual platform activation height retrieval
    // For now, return a placeholder error
    FFIResult::error(
        FFIErrorCode::NotImplemented,
        "Platform activation height retrieval not yet implemented",
    )
}
