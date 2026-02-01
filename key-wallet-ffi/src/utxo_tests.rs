#[cfg(test)]
mod utxo_tests {
    use super::super::*;
    use crate::error::{FFIError, FFIErrorCode};
    use key_wallet::managed_account::managed_account_type::ManagedAccountType;
    use key_wallet::Utxo;
    use std::ffi::CStr;
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
            let mut utxo = utxo;
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
            let mut utxo = utxo;
            utxo.free();
        }
    }

    #[test]
    fn test_deprecated_wallet_get_utxos() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;
        let mut utxos_out: *mut FFIUTXO = ptr::null_mut();
        let mut count_out: usize = 0;

        // The deprecated function should always return an empty list
        let success = unsafe {
            #[allow(deprecated)]
            wallet_get_utxos(ptr::null(), &mut utxos_out, &mut count_out, error)
        };

        assert!(success);
        assert_eq!(count_out, 0);
        assert!(utxos_out.is_null());
    }

    #[test]
    fn test_managed_wallet_get_utxos_null() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;
        let mut utxos_out: *mut FFIUTXO = ptr::null_mut();
        let mut count_out: usize = 0;

        // Test with null managed_info
        let result =
            unsafe { managed_wallet_get_utxos(ptr::null(), &mut utxos_out, &mut count_out, error) };
        assert!(!result);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        unsafe { (*error).free_message() };
    }

    #[test]
    fn test_managed_wallet_get_utxos_empty() {
        use crate::managed_wallet::FFIManagedWalletInfo;
        use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
        use key_wallet::Network;

        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;
        let mut utxos_out: *mut FFIUTXO = ptr::null_mut();
        let mut count_out: usize = 0;

        // Create an empty managed wallet info heap-allocated like C would do
        let managed_info = ManagedWalletInfo::new(Network::Testnet, [0u8; 32]);
        let ffi_managed_info = Box::into_raw(Box::new(FFIManagedWalletInfo::new(managed_info)));

        let result = unsafe {
            managed_wallet_get_utxos(&*ffi_managed_info, &mut utxos_out, &mut count_out, error)
        };

        assert!(result);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);
        assert_eq!(count_out, 0);
        assert!(utxos_out.is_null());

        unsafe { crate::managed_wallet::managed_wallet_free(ffi_managed_info) };
    }

    // Note: There's no individual utxo_free function, only utxo_array_free

    #[test]
    fn test_utxo_array_free() {
        // Create some test UTXOs in the same format as managed_wallet_get_utxos returns
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
            utxos.push(utxo);
        }

        // Convert to boxed slice and get raw pointer (same as in managed_wallet_get_utxos)
        let count = utxos.len();
        let mut boxed_utxos = utxos.into_boxed_slice();
        let utxos_ptr = boxed_utxos.as_mut_ptr();
        std::mem::forget(boxed_utxos);

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

    #[test]
    fn test_managed_wallet_get_utxos_with_data() {
        use crate::managed_wallet::FFIManagedWalletInfo;
        use dashcore::blockdata::script::ScriptBuf;
        use dashcore::{Address, OutPoint, TxOut, Txid};
        use key_wallet::account::account_type::StandardAccountType;
        use key_wallet::managed_account::ManagedCoreAccount;
        use key_wallet::utxo::Utxo;
        use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
        use key_wallet::Network;

        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;
        let mut utxos_out: *mut FFIUTXO = ptr::null_mut();
        let mut count_out: usize = 0;

        // Create a managed wallet info with some UTXOs
        let mut managed_info = ManagedWalletInfo::new(Network::Testnet, [1u8; 32]);

        // Create a BIP44 account with UTXOs
        let mut bip44_account = ManagedCoreAccount::new(
            ManagedAccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
                external_addresses:
                    key_wallet::managed_account::address_pool::AddressPoolBuilder::default()
                        .base_path(key_wallet::DerivationPath::from(vec![]))
                        .build()
                        .unwrap(),
                internal_addresses:
                    key_wallet::managed_account::address_pool::AddressPoolBuilder::default()
                        .base_path(key_wallet::DerivationPath::from(vec![]))
                        .build()
                        .unwrap(),
            },
            Network::Testnet,
            false,
        );

        // Add multiple UTXOs
        for i in 0..3 {
            let mut txid_bytes = [0u8; 32];
            txid_bytes[0] = i as u8;
            let outpoint = OutPoint {
                txid: Txid::from(txid_bytes),
                vout: i as u32,
            };
            let txout = TxOut {
                value: (i as u64 + 1) * 50000,
                script_pubkey: ScriptBuf::from(vec![]),
            };
            // Create a dummy P2PKH address
            let dummy_pubkey_hash = dashcore::PubkeyHash::from([0u8; 20]);
            let script = ScriptBuf::new_p2pkh(&dummy_pubkey_hash);
            let address = Address::from_script(&script, Network::Testnet).unwrap();
            let mut utxo = Utxo::new(outpoint, txout, address, 100 + i as u32, false);
            utxo.is_confirmed = true;

            bip44_account.utxos.insert(outpoint, utxo);
        }

        managed_info.accounts.insert(bip44_account);

        let ffi_managed_info = Box::into_raw(Box::new(FFIManagedWalletInfo::new(managed_info)));
        unsafe { (*ffi_managed_info).inner_mut() }.update_synced_height(300);
        let result = unsafe {
            managed_wallet_get_utxos(&*ffi_managed_info, &mut utxos_out, &mut count_out, error)
        };

        assert!(result);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);
        assert_eq!(count_out, 3);
        assert!(!utxos_out.is_null());

        // Verify UTXO data
        unsafe {
            let utxos = std::slice::from_raw_parts(utxos_out, count_out);

            // Check first UTXO
            assert_eq!(utxos[0].txid[0], 0);
            assert_eq!(utxos[0].vout, 0);
            assert_eq!(utxos[0].amount, 50000);
            assert_eq!(utxos[0].height, 100);
            assert_eq!(utxos[0].confirmations, 201);

            // Check second UTXO
            assert_eq!(utxos[1].txid[0], 1);
            assert_eq!(utxos[1].vout, 1);
            assert_eq!(utxos[1].amount, 100000);
            assert_eq!(utxos[1].height, 101);
            assert_eq!(utxos[1].confirmations, 200);

            // Check third UTXO
            assert_eq!(utxos[2].txid[0], 2);
            assert_eq!(utxos[2].vout, 2);
            assert_eq!(utxos[2].amount, 150000);
            assert_eq!(utxos[2].height, 102);
            assert_eq!(utxos[2].confirmations, 199);
        }

        // Clean up
        unsafe {
            utxo_array_free(utxos_out, count_out);
            crate::managed_wallet::managed_wallet_free(ffi_managed_info);
        }
    }

    #[test]
    fn test_managed_wallet_get_utxos_multiple_accounts() {
        use crate::managed_wallet::FFIManagedWalletInfo;
        use key_wallet::account::account_type::StandardAccountType;
        use key_wallet::managed_account::ManagedCoreAccount;
        use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
        use key_wallet::Network;

        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;
        let mut utxos_out: *mut FFIUTXO = ptr::null_mut();
        let mut count_out: usize = 0;

        let mut managed_info = ManagedWalletInfo::new(Network::Testnet, [2u8; 32]);

        // Create BIP44 account with 2 UTXOs
        let mut bip44_account = ManagedCoreAccount::new(
            ManagedAccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
                external_addresses:
                    key_wallet::managed_account::address_pool::AddressPoolBuilder::default()
                        .base_path(key_wallet::DerivationPath::from(vec![]))
                        .build()
                        .unwrap(),
                internal_addresses:
                    key_wallet::managed_account::address_pool::AddressPoolBuilder::default()
                        .base_path(key_wallet::DerivationPath::from(vec![]))
                        .build()
                        .unwrap(),
            },
            Network::Testnet,
            false,
        );

        let utxos = Utxo::dummy_batch(0..2, 10000, 100, false, false);
        for utxo in utxos {
            bip44_account.utxos.insert(utxo.outpoint, utxo);
        }
        managed_info.accounts.insert(bip44_account);

        // Create BIP32 account with 1 UTXO
        let mut bip32_account = ManagedCoreAccount::new(
            ManagedAccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP32Account,
                external_addresses:
                    key_wallet::managed_account::address_pool::AddressPoolBuilder::default()
                        .base_path(key_wallet::DerivationPath::from(vec![]))
                        .build()
                        .unwrap(),
                internal_addresses:
                    key_wallet::managed_account::address_pool::AddressPoolBuilder::default()
                        .base_path(key_wallet::DerivationPath::from(vec![]))
                        .build()
                        .unwrap(),
            },
            Network::Testnet,
            false,
        );

        let utxos = Utxo::dummy_batch(10..11, 20000, 200, false, false);
        for utxo in utxos {
            bip32_account.utxos.insert(utxo.outpoint, utxo);
        }
        managed_info.accounts.insert(bip32_account);

        // Create CoinJoin account with 2 UTXOs
        let mut coinjoin_account = ManagedCoreAccount::new(
            ManagedAccountType::CoinJoin {
                index: 0,
                addresses: key_wallet::managed_account::address_pool::AddressPoolBuilder::default()
                    .base_path(key_wallet::DerivationPath::from(vec![]))
                    .build()
                    .unwrap(),
            },
            Network::Testnet,
            false,
        );

        let utxos = Utxo::dummy_batch(20..22, 30000, 300, false, false);
        for utxo in utxos {
            coinjoin_account.utxos.insert(utxo.outpoint, utxo);
        }
        managed_info.accounts.insert(coinjoin_account);

        let ffi_managed_info = Box::into_raw(Box::new(FFIManagedWalletInfo::new(managed_info)));

        let result = unsafe {
            managed_wallet_get_utxos(&*ffi_managed_info, &mut utxos_out, &mut count_out, error)
        };

        assert!(result);
        assert_eq!(count_out, 5); // 2 from BIP44, 1 from BIP32, 2 from CoinJoin
        assert!(!utxos_out.is_null());

        // Clean up
        unsafe {
            utxo_array_free(utxos_out, count_out);
            crate::managed_wallet::managed_wallet_free(ffi_managed_info);
        }
    }

    #[test]
    fn test_managed_wallet_get_utxos() {
        use crate::managed_wallet::FFIManagedWalletInfo;
        use key_wallet::account::account_type::StandardAccountType;
        use key_wallet::managed_account::ManagedCoreAccount;
        use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
        use key_wallet::Network;

        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;
        let mut utxos_out: *mut FFIUTXO = ptr::null_mut();
        let mut count_out: usize = 0;

        // Create managed wallet info for testnet
        let mut managed_info = ManagedWalletInfo::new(Network::Testnet, [3u8; 32]);

        // Add a UTXO to Testnet account
        let mut testnet_account = ManagedCoreAccount::new(
            ManagedAccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
                external_addresses:
                    key_wallet::managed_account::address_pool::AddressPoolBuilder::default()
                        .base_path(key_wallet::DerivationPath::from(vec![]))
                        .build()
                        .unwrap(),
                internal_addresses:
                    key_wallet::managed_account::address_pool::AddressPoolBuilder::default()
                        .base_path(key_wallet::DerivationPath::from(vec![]))
                        .build()
                        .unwrap(),
            },
            Network::Testnet,
            false,
        );

        let utxos = Utxo::dummy_batch(1..2, 10000, 100, false, false);
        for utxo in utxos {
            testnet_account.utxos.insert(utxo.outpoint, utxo);
        }
        managed_info.accounts.insert(testnet_account);

        let ffi_managed_info = Box::into_raw(Box::new(FFIManagedWalletInfo::new(managed_info)));

        // Get UTXOs
        let result = unsafe {
            managed_wallet_get_utxos(&*ffi_managed_info, &mut utxos_out, &mut count_out, error)
        };
        assert!(result);
        assert_eq!(count_out, 1);
        unsafe {
            utxo_array_free(utxos_out, count_out);
            crate::managed_wallet::managed_wallet_free(ffi_managed_info);
        }
    }

    #[test]
    fn test_ffi_utxo_with_large_script() {
        let txid = [0xAAu8; 32];
        let vout = 42;
        let amount = 1000000;
        let address = "yXdxAYfK7KGx7gNpVHUfRsQMNpMj5cAadG".to_string();
        let script = vec![0x76; 1000]; // Large script
        let height = 654321;
        let confirmations = 100;

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
        assert_eq!(utxo.script_len, 1000);
        assert_eq!(utxo.height, height);
        assert_eq!(utxo.confirmations, confirmations);

        // Verify script content
        unsafe {
            let script_slice = std::slice::from_raw_parts(utxo.script_pubkey, utxo.script_len);
            assert!(script_slice.iter().all(|&b| b == 0x76));

            let mut utxo = utxo;
            utxo.free();
        }
    }

    #[test]
    fn test_ffi_utxo_edge_values() {
        // Test with maximum values
        let txid = [0xFFu8; 32];
        let vout = u32::MAX;
        let amount = u64::MAX;
        let address = "x".repeat(100); // Long address
        let script = vec![0x00];
        let height = u32::MAX;
        let confirmations = u32::MAX;

        let utxo = FFIUTXO::new(txid, vout, amount, address.clone(), script, height, confirmations);

        assert_eq!(utxo.vout, u32::MAX);
        assert_eq!(utxo.amount, u64::MAX);
        assert_eq!(utxo.height, u32::MAX);
        assert_eq!(utxo.confirmations, u32::MAX);

        // Clean up
        unsafe {
            let mut utxo = utxo;
            utxo.free();
        }
    }

    #[test]
    fn test_utxo_array_free_with_mixed_content() {
        // Create UTXOs with different properties
        let utxos = vec![
            // UTXO with normal values
            FFIUTXO::new([0x01u8; 32], 0, 10000, "address1".to_string(), vec![0x76, 0xa9], 100, 10),
            // UTXO with empty script
            FFIUTXO::new([0x02u8; 32], 1, 20000, "address2".to_string(), vec![], 200, 20),
            // UTXO with large script
            FFIUTXO::new([0x03u8; 32], 2, 30000, "address3".to_string(), vec![0xAB; 500], 300, 30),
        ];

        let count = utxos.len();
        let mut boxed_utxos = utxos.into_boxed_slice();
        let utxos_ptr = boxed_utxos.as_mut_ptr();
        std::mem::forget(boxed_utxos);

        // Free should handle all different UTXO types
        unsafe {
            utxo_array_free(utxos_ptr, count);
        }
    }

    #[test]
    fn test_managed_wallet_get_utxos_null_outputs() {
        use crate::managed_wallet::FFIManagedWalletInfo;
        use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
        use key_wallet::Network;

        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;
        let mut count_out: usize = 0;

        let managed_info = ManagedWalletInfo::new(Network::Testnet, [4u8; 32]);
        let ffi_managed_info = Box::into_raw(Box::new(FFIManagedWalletInfo::new(managed_info)));

        // Test with null utxos_out
        let result = unsafe {
            managed_wallet_get_utxos(&*ffi_managed_info, ptr::null_mut(), &mut count_out, error)
        };
        assert!(!result);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        // Test with null count_out
        let mut utxos_out: *mut FFIUTXO = ptr::null_mut();
        let result = unsafe {
            managed_wallet_get_utxos(&*ffi_managed_info, &mut utxos_out, ptr::null_mut(), error)
        };
        assert!(!result);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);

        unsafe {
            crate::managed_wallet::managed_wallet_free(ffi_managed_info);
            (*error).free_message();
        }
    }

    #[test]
    fn test_ffi_utxo_free_idempotent() {
        let utxo =
            FFIUTXO::new([0x05u8; 32], 0, 10000, "test_address".to_string(), vec![0x76], 100, 1);

        unsafe {
            let mut utxo = utxo;
            // First free
            utxo.free();

            // After free, pointers should be null
            assert!(utxo.address.is_null());
            assert!(utxo.script_pubkey.is_null());
            assert_eq!(utxo.script_len, 0);

            // Second free should be safe (no-op)
            utxo.free();
        }
    }
}
