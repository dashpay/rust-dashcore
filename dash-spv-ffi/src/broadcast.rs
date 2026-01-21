use crate::{null_check, set_last_error, FFIDashSpvClient, SpvFFIErrorCode};
use std::ffi::CStr;
use std::os::raw::c_char;

/// Broadcasts a transaction to the Dash network via connected peers.
///
/// # Safety
///
/// - `client` must be a valid, non-null pointer to an initialized FFIDashSpvClient
/// - `tx_hex` must be a valid, non-null pointer to a NUL-terminated C string
///   containing a hex-encoded serialized transaction
#[no_mangle]
pub unsafe extern "C" fn dash_spv_ffi_client_broadcast_transaction(
    client: *mut FFIDashSpvClient,
    tx_hex: *const c_char,
) -> i32 {
    null_check!(client);
    null_check!(tx_hex);

    let tx_str = match CStr::from_ptr(tx_hex).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("Invalid UTF-8 in transaction: {}", e));
            return SpvFFIErrorCode::InvalidArgument as i32;
        }
    };

    let tx_bytes = match hex::decode(tx_str) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(&format!("Invalid hex in transaction: {}", e));
            return SpvFFIErrorCode::InvalidArgument as i32;
        }
    };

    let tx = match dashcore::consensus::deserialize::<dashcore::Transaction>(&tx_bytes) {
        Ok(t) => t,
        Err(e) => {
            set_last_error(&format!("Invalid transaction: {}", e));
            return SpvFFIErrorCode::InvalidArgument as i32;
        }
    };

    let client = &(*client);
    let inner = client.inner.clone();

    let result: Result<(), dash_spv::SpvError> = client.runtime.block_on(async {
        // Take the client out to avoid holding the lock across await
        let spv_client = {
            let mut guard = inner.lock().unwrap();
            match guard.take() {
                Some(client) => client,
                None => {
                    return Err(dash_spv::SpvError::Storage(dash_spv::StorageError::NotFound(
                        "Client not initialized".to_string(),
                    )))
                }
            }
        };

        // Broadcast the transaction over P2P
        let res = spv_client.broadcast_transaction(&tx).await;

        // Put the client back
        let mut guard = inner.lock().unwrap();
        *guard = Some(spv_client);
        res
    });

    match result {
        Ok(_) => SpvFFIErrorCode::Success as i32,
        Err(e) => {
            set_last_error(&format!("Failed to broadcast transaction: {}", e));
            SpvFFIErrorCode::from(e) as i32
        }
    }
}
