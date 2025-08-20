#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::error::{FFIError, FFIErrorCode};
    use crate::types::FFINetwork;
    use crate::wallet;
    use std::ffi::{CStr, CString};
    use std::ptr;

    #[test]
    fn test_ffi_utxo_new() {
        let txid = [1u8; 32];
        let vout = 0;
        let amount = 100000;
        let address = "yXdxAYfK7KGx7gNpVHUfRsQMNpMj5cAadG".to_string();
        let script = vec![0x76, 0xa9, 0x14]; // Sample script
        let height = 12345;
        let confirmations = 10;

        let utxo = FFIUTXO::new(
            txid,
            vout,
            amount,
            address.clone(),
            script.clone(),
            height,
            confirmations,
        );

        assert_eq!(utxo.txid, txid);
        assert_eq!(utxo.vout, vout);
        assert_eq!(utxo.amount, amount);
        assert!(!utxo.address.is_null());
        assert!(!utxo.script_pubkey.is_null());
        assert_eq!(utxo.script_len, script.len());
        assert_eq!(utxo.height, height);
        assert_eq!(utxo.confirmations, confirmations);

        // Verify address
        let addr_str = unsafe { CStr::from_ptr(utxo.address).to_str().unwrap() };
        assert_eq!(addr_str, address);

        // Clean up
        unsafe {
            utxo.free();
        }
    }

    #[test]
    fn test_ffi_utxo_new_empty_script() {
        let txid = [2u8; 32];
        let utxo = FFIUTXO::new(
            txid,
            1,
            50000,
            "yYNrYTYsV8xCTMAz5wXmKzn7eqUe5p5V8V".to_string(),
            vec![],
            100,
            5,
        );

        assert_eq!(utxo.txid, txid);
        assert!(utxo.script_pubkey.is_null());
        assert_eq!(utxo.script_len, 0);

        // Clean up
        unsafe {
            utxo.free();
        }
    }

    #[test]
    fn test_wallet_add_utxo_null_wallet() {
        let mut error = FFIError::success();
        let txid = [3u8; 32];
        let address = CString::new("yXdxAYfK7KGx7gNpVHUfRsQMNpMj5cAadG").unwrap();
        let script = vec![0x76, 0xa9];

        let success = unsafe {
            wallet_add_utxo(
                ptr::null_mut(),
                FFINetwork::Testnet,
                txid.as_ptr(),
                0,
                100000,
                address.as_ptr(),
                script.as_ptr(),
                script.len(),
                12345,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_wallet_add_utxo_null_txid() {
        let mut error = FFIError::success();

        // Create a wallet
        let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let passphrase = CString::new("").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                FFINetwork::Testnet,
                &mut error,
            )
        };

        let address = CString::new("yXdxAYfK7KGx7gNpVHUfRsQMNpMj5cAadG").unwrap();
        let script = vec![0x76, 0xa9];

        let success = unsafe {
            wallet_add_utxo(
                wallet,
                FFINetwork::Testnet,
                ptr::null(),
                0,
                100000,
                address.as_ptr(),
                script.as_ptr(),
                script.len(),
                12345,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Clean up
        unsafe {
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_wallet_get_utxos_null_wallet() {
        let mut error = FFIError::success();
        let mut utxos_out: *mut FFIUTXO = ptr::null_mut();
        let mut count_out: usize = 0;

        let success = unsafe {
            wallet_get_utxos(
                ptr::null(),
                FFINetwork::Testnet,
                &mut utxos_out,
                &mut count_out,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_wallet_remove_utxo_null_wallet() {
        let mut error = FFIError::success();
        let txid = [4u8; 32];

        let success = unsafe {
            wallet_remove_utxo(ptr::null_mut(), FFINetwork::Testnet, txid.as_ptr(), 0, &mut error)
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    // Note: There's no individual utxo_free function, only utxo_array_free

    #[test]
    fn test_utxo_array_free() {
        // Create some test UTXOs
        let mut utxos = Vec::new();
        for i in 0..3 {
            let utxo = FFIUTXO::new(
                [i as u8; 32],
                i as u32,
                (i as u64 + 1) * 10000,
                format!("address_{}", i),
                vec![0x76, 0xa9, i as u8],
                i as u32 * 100,
                i as u32,
            );
            utxos.push(Box::into_raw(Box::new(utxo)));
        }

        let mut utxos_ptrs = utxos.clone();
        let utxos_ptr = utxos_ptrs.as_mut_ptr();
        let count = utxos.len();
        std::mem::forget(utxos_ptrs);

        // Free the UTXOs
        unsafe {
            utxo_array_free(utxos_ptr, count);
        }
    }

    #[test]
    fn test_utxo_array_free_null() {
        // Should handle null gracefully
        unsafe {
            utxo_array_free(ptr::null_mut(), 0);
        }
    }
}
