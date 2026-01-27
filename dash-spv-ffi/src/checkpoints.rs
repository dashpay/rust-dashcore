use crate::{set_last_error, FFIErrorCode};
use dash_spv::chain::CheckpointManager;
use dashcore::hashes::Hash;
use key_wallet_ffi::FFINetwork;

/// FFI representation of a checkpoint (height + block hash)
#[repr(C)]
pub struct FFICheckpoint {
    pub height: u32,
    pub block_hash: [u8; 32],
}

/// Get the latest checkpoint for the given network.
///
/// # Safety
/// - `out_height` must be a valid pointer to a `u32`.
/// - `out_hash` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_checkpoint_latest(
    network: FFINetwork,
    out_height: *mut u32,
    out_hash: *mut u8, // expects at least 32 bytes
) -> i32 {
    dash_spv_ffi_checkpoint_before_height(network, u32::MAX, out_height, out_hash)
}

/// Get the last checkpoint at or before a given height.
///
/// # Safety
/// - `out_height` must be a valid pointer to a `u32`.
/// - `out_hash` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_checkpoint_before_height(
    network: FFINetwork,
    height: u32,
    out_height: *mut u32,
    out_hash: *mut u8, // expects at least 32 bytes
) -> i32 {
    if out_height.is_null() || out_hash.is_null() {
        set_last_error("Null output pointer provided");
        return FFIErrorCode::NullPointer as i32;
    }

    let mgr = CheckpointManager::new(network.into());

    let (height, cp) = mgr.last_checkpoint_before_height(height);
    *out_height = height;
    let hash = cp.hash().to_byte_array();
    std::ptr::copy_nonoverlapping(hash.as_ptr(), out_hash, 32);
    FFIErrorCode::Success as i32
}

/// Get the last checkpoint at or before a given UNIX timestamp (seconds).
///
/// # Safety
/// - `out_height` must be a valid pointer to a `u32`.
/// - `out_hash` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_checkpoint_before_timestamp(
    network: FFINetwork,
    timestamp: u32,
    out_height: *mut u32,
    out_hash: *mut u8, // expects at least 32 bytes
) -> i32 {
    if out_height.is_null() || out_hash.is_null() {
        set_last_error("Null output pointer provided");
        return FFIErrorCode::NullPointer as i32;
    }

    let mgr = CheckpointManager::new(network.into());

    let (height, cp) = mgr.last_checkpoint_before_timestamp(timestamp);
    *out_height = height;
    let hash = cp.hash().to_byte_array();
    std::ptr::copy_nonoverlapping(hash.as_ptr(), out_hash, 32);
    FFIErrorCode::Success as i32
}
