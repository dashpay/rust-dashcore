use crate::{set_last_error, FFIErrorCode};
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
        return FFIErrorCode::NullPointer as i32;
    }
    let mgr = match manager_for_network(network) {
        Ok(m) => m,
        Err(e) => {
            set_last_error(&e);
            return FFIErrorCode::InvalidArgument as i32;
        }
    };
    if let Some(cp) = mgr.last_checkpoint() {
        *out_height = cp.height;
        let hash = cp.block_hash.to_byte_array();
        std::ptr::copy_nonoverlapping(hash.as_ptr(), out_hash, 32);
        FFIErrorCode::Success as i32
    } else {
        set_last_error("No checkpoints available for network");
        FFIErrorCode::NotImplemented as i32
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
        return FFIErrorCode::NullPointer as i32;
    }
    let mgr = match manager_for_network(network) {
        Ok(m) => m,
        Err(e) => {
            set_last_error(&e);
            return FFIErrorCode::InvalidArgument as i32;
        }
    };
    if let Some(cp) = mgr.last_checkpoint_before_height(height) {
        *out_height = cp.height;
        let hash = cp.block_hash.to_byte_array();
        std::ptr::copy_nonoverlapping(hash.as_ptr(), out_hash, 32);
        FFIErrorCode::Success as i32
    } else {
        set_last_error("No checkpoint at or before given height");
        FFIErrorCode::ValidationError as i32
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
        return FFIErrorCode::NullPointer as i32;
    }
    let mgr = match manager_for_network(network) {
        Ok(m) => m,
        Err(e) => {
            set_last_error(&e);
            return FFIErrorCode::InvalidArgument as i32;
        }
    };
    if let Some(cp) = mgr.last_checkpoint_before_timestamp(timestamp) {
        *out_height = cp.height;
        let hash = cp.block_hash.to_byte_array();
        std::ptr::copy_nonoverlapping(hash.as_ptr(), out_hash, 32);
        FFIErrorCode::Success as i32
    } else {
        set_last_error("No checkpoint at or before given timestamp");
        FFIErrorCode::ValidationError as i32
    }
}
