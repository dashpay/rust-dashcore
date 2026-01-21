use crate::{set_last_error, FFIArray, SpvFFIErrorCode};
use dash_spv::chain::checkpoints::{mainnet_checkpoints, testnet_checkpoints, CheckpointManager};
use dashcore::hashes::Hash;
use dashcore::Network;
use key_wallet_ffi::FFINetwork;

/// FFI representation of a checkpoint (height + block hash)
#[repr(C)]
pub struct FFICheckpoint {
    pub height: u32,
    pub block_hash: [u8; 32],
}

fn manager_for_network(network: FFINetwork) -> Result<CheckpointManager, String> {
    let net: Network = network.into();
    match net {
        Network::Dash => Ok(CheckpointManager::new(mainnet_checkpoints())),
        Network::Testnet => Ok(CheckpointManager::new(testnet_checkpoints())),
        _ => Err("Checkpoints are only available for Dash and Testnet".to_string()),
    }
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
    if out_height.is_null() || out_hash.is_null() {
        set_last_error("Null output pointer provided");
        return SpvFFIErrorCode::NullPointer as i32;
    }
    let mgr = match manager_for_network(network) {
        Ok(m) => m,
        Err(e) => {
            set_last_error(&e);
            return SpvFFIErrorCode::InvalidArgument as i32;
        }
    };
    if let Some(cp) = mgr.last_checkpoint() {
        *out_height = cp.height;
        let hash = cp.block_hash.to_byte_array();
        std::ptr::copy_nonoverlapping(hash.as_ptr(), out_hash, 32);
        SpvFFIErrorCode::Success as i32
    } else {
        set_last_error("No checkpoints available for network");
        SpvFFIErrorCode::NotImplemented as i32
    }
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
        return SpvFFIErrorCode::NullPointer as i32;
    }
    let mgr = match manager_for_network(network) {
        Ok(m) => m,
        Err(e) => {
            set_last_error(&e);
            return SpvFFIErrorCode::InvalidArgument as i32;
        }
    };
    if let Some(cp) = mgr.last_checkpoint_before_height(height) {
        *out_height = cp.height;
        let hash = cp.block_hash.to_byte_array();
        std::ptr::copy_nonoverlapping(hash.as_ptr(), out_hash, 32);
        SpvFFIErrorCode::Success as i32
    } else {
        set_last_error("No checkpoint at or before given height");
        SpvFFIErrorCode::ValidationError as i32
    }
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
        return SpvFFIErrorCode::NullPointer as i32;
    }
    let mgr = match manager_for_network(network) {
        Ok(m) => m,
        Err(e) => {
            set_last_error(&e);
            return SpvFFIErrorCode::InvalidArgument as i32;
        }
    };
    if let Some(cp) = mgr.last_checkpoint_before_timestamp(timestamp) {
        *out_height = cp.height;
        let hash = cp.block_hash.to_byte_array();
        std::ptr::copy_nonoverlapping(hash.as_ptr(), out_hash, 32);
        SpvFFIErrorCode::Success as i32
    } else {
        set_last_error("No checkpoint at or before given timestamp");
        SpvFFIErrorCode::ValidationError as i32
    }
}

/// Get all checkpoints between two heights (inclusive).
///
/// Returns an `FFIArray` of `FFICheckpoint` items. The caller owns the memory and
/// must free the array buffer using `dash_spv_ffi_array_destroy` when done.
#[no_mangle]
pub extern "C" fn dash_spv_ffi_checkpoints_between_heights(
    network: FFINetwork,
    start_height: u32,
    end_height: u32,
) -> FFIArray {
    match manager_for_network(network) {
        Ok(mgr) => {
            // Collect checkpoints within inclusive range
            let mut out: Vec<FFICheckpoint> = Vec::new();
            for &h in mgr.checkpoint_heights() {
                if h >= start_height && h <= end_height {
                    if let Some(cp) = mgr.get_checkpoint(h) {
                        out.push(FFICheckpoint {
                            height: cp.height,
                            block_hash: cp.block_hash.to_byte_array(),
                        });
                    }
                }
            }
            FFIArray::new(out)
        }
        Err(e) => {
            set_last_error(&e);
            // Return empty array on error
            FFIArray {
                data: std::ptr::null_mut(),
                len: 0,
                capacity: 0,
                elem_size: std::mem::size_of::<FFICheckpoint>(),
                elem_align: std::mem::align_of::<FFICheckpoint>(),
            }
        }
    }
}
