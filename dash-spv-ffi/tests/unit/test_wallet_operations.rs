#[cfg(test)]
mod tests {
    use crate::*;
    use serial_test::serial;
    use std::ffi::CString;

    use std::sync::{Arc, Mutex};
    use std::thread;

    use tempfile::TempDir;

    fn create_test_wallet() -> (*mut FFIDashSpvClient, *mut FFIClientConfig, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        unsafe {
            let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
            let path = CString::new(temp_dir.path().to_str().unwrap()).unwrap();
            dash_spv_ffi_config_set_data_dir(config, path.as_ptr());
            dash_spv_ffi_config_set_validation_mode(config, FFIValidationMode::None);

            let client = dash_spv_ffi_client_new(config);
            (client, config, temp_dir)
        }
    }

    #[test]
    #[serial]
    fn test_address_validation() {
        unsafe {
            // Valid mainnet addresses
            let valid_mainnet =
                ["Xan9iCVe1q5jYRDZ4VSMCtBjq2VyQA3Dge", "XasTb9LP4wwsvtqXG6ZUZEggpiRFot8E4F"];

            for addr in &valid_mainnet {
                let c_addr = CString::new(*addr).unwrap();
                let result = dash_spv_ffi_validate_address(c_addr.as_ptr(), FFINetwork::Dash);
                assert_eq!(result, 1, "Address {} should be valid", addr);
            }

            // Valid testnet addresses
            let valid_testnet = ["yLbNV3FZZcU6f7P32Yzzwcbz6gpudmWgkx"];

            for addr in &valid_testnet {
                let c_addr = CString::new(*addr).unwrap();
                let result = dash_spv_ffi_validate_address(c_addr.as_ptr(), FFINetwork::Testnet);
                assert_eq!(result, 1, "Address {} should be valid", addr);
            }

            // Invalid addresses
            let invalid = [
                "",
                "invalid",
                "1BitcoinAddress",
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", // Bitcoin bech32
                "Xan9iCVe1q5jYRDZ4VSMCtBjq2VyQA3Dg",          // Missing character
                "Xan9iCVe1q5jYRDZ4VSMCtBjq2VyQA3Dgee",        // Extra character
            ];

            for addr in &invalid {
                let c_addr = CString::new(*addr).unwrap();
                let result = dash_spv_ffi_validate_address(c_addr.as_ptr(), FFINetwork::Dash);
                assert_eq!(result, 0, "Address {} should be invalid", addr);
            }

            // Test null address
            let result = dash_spv_ffi_validate_address(std::ptr::null(), FFINetwork::Dash);
            assert_eq!(result, 0);
        }
    }

    #[test]
    #[serial]
    fn test_watch_address_operations() {
        unsafe {
            let (client, config, _temp_dir) = create_test_wallet();
            assert!(!client.is_null());

            // Test adding valid address
            let addr = CString::new("Xan9iCVe1q5jYRDZ4VSMCtBjq2VyQA3Dge").unwrap();
            let result = dash_spv_ffi_client_watch_address(client, addr.as_ptr());
            assert_eq!(result, FFIErrorCode::ConfigError as i32); // Not implemented

            // Test adding same address again (should succeed)
            let result = dash_spv_ffi_client_watch_address(client, addr.as_ptr());
            assert_eq!(result, FFIErrorCode::ConfigError as i32); // Not implemented

            // Test unwatching address
            let result = dash_spv_ffi_client_unwatch_address(client, addr.as_ptr());
            assert_eq!(result, FFIErrorCode::ConfigError as i32); // Not implemented

            // Test unwatching non-watched address (should succeed)
            let result = dash_spv_ffi_client_unwatch_address(client, addr.as_ptr());
            assert_eq!(result, FFIErrorCode::ConfigError as i32); // Not implemented

            // Test with invalid address
            let invalid = CString::new("invalid_address").unwrap();
            let result = dash_spv_ffi_client_watch_address(client, invalid.as_ptr());
            assert_eq!(result, FFIErrorCode::InvalidArgument as i32);

            // Test with null
            let result = dash_spv_ffi_client_watch_address(client, std::ptr::null());
            assert_eq!(result, FFIErrorCode::NullPointer as i32);

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_watch_script_operations() {
        unsafe {
            let (client, config, _temp_dir) = create_test_wallet();
            assert!(!client.is_null());

            // Test adding valid script (P2PKH scriptPubKey)
            let script_hex = "76a9146b8cc98ec5080b0b7adb10d040fb1572be9c35f888ac";
            let c_script = CString::new(script_hex).unwrap();
            let result = dash_spv_ffi_client_watch_script(client, c_script.as_ptr());
            assert_eq!(result, FFIErrorCode::ConfigError as i32); // Not implemented

            // Test with invalid hex
            let invalid_hex = CString::new("not_hex").unwrap();
            let result = dash_spv_ffi_client_watch_script(client, invalid_hex.as_ptr());
            assert_eq!(result, FFIErrorCode::InvalidArgument as i32);

            // Test with odd-length hex
            let odd_hex = CString::new("76a9").unwrap();
            let result = dash_spv_ffi_client_watch_script(client, odd_hex.as_ptr());
            assert_eq!(result, FFIErrorCode::InvalidArgument as i32);

            // Test empty script
            let empty = CString::new("").unwrap();
            let result = dash_spv_ffi_client_watch_script(client, empty.as_ptr());
            assert_eq!(result, FFIErrorCode::InvalidArgument as i32);

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_get_address_balance() {
        unsafe {
            let (client, config, _temp_dir) = create_test_wallet();
            assert!(!client.is_null());

            // Test getting balance for unwatched address
            let addr = CString::new("XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E").unwrap();
            let balance = dash_spv_ffi_client_get_address_balance(client, addr.as_ptr());

            if !balance.is_null() {
                let bal = &*balance;
                // New wallet should have zero balance
                assert_eq!(bal.confirmed, 0);
                assert_eq!(bal.pending, 0);
                assert_eq!(bal.instantlocked, 0);

                dash_spv_ffi_balance_destroy(balance);
            }

            // Test with invalid address
            let invalid = CString::new("invalid_address").unwrap();
            let balance = dash_spv_ffi_client_get_address_balance(client, invalid.as_ptr());
            assert!(balance.is_null());

            // Check error was set
            let error_ptr = dash_spv_ffi_get_last_error();
            assert!(!error_ptr.is_null());

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_get_address_utxos() {
        unsafe {
            let (client, config, _temp_dir) = create_test_wallet();
            assert!(!client.is_null());

            // Test getting UTXOs for address
            let addr = CString::new("XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E").unwrap();
            let utxos = dash_spv_ffi_client_get_address_utxos(client, addr.as_ptr());

            // New wallet should have no UTXOs
            assert_eq!(utxos.len, 0);
            if !utxos.data.is_null() {
                dash_spv_ffi_array_destroy(Box::into_raw(Box::new(utxos)));
            }

            // Test with invalid address
            let invalid = CString::new("invalid_address").unwrap();
            let utxos = dash_spv_ffi_client_get_address_utxos(client, invalid.as_ptr());
            assert!(utxos.data.is_null());

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_get_address_history() {
        unsafe {
            let (client, config, _temp_dir) = create_test_wallet();
            assert!(!client.is_null());

            // Test getting history for address
            let addr = CString::new("XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E").unwrap();
            let history = dash_spv_ffi_client_get_address_history(client, addr.as_ptr());

            // New wallet should have no history
            assert_eq!(history.len, 0);
            if !history.data.is_null() {
                dash_spv_ffi_array_destroy(Box::into_raw(Box::new(history)));
            }

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_transaction_operations() {
        unsafe {
            let (client, config, _temp_dir) = create_test_wallet();
            assert!(!client.is_null());

            // Test getting transaction with valid format but non-existent txid
            let txid =
                CString::new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                    .unwrap();
            let tx = dash_spv_ffi_client_get_transaction(client, txid.as_ptr());
            assert!(tx.is_null()); // Not found

            // Test with invalid txid format
            let invalid_txid = CString::new("not_a_txid").unwrap();
            let tx = dash_spv_ffi_client_get_transaction(client, invalid_txid.as_ptr());
            assert!(tx.is_null());

            // Test with wrong length txid
            let short_txid = CString::new("0123456789abcdef").unwrap();
            let tx = dash_spv_ffi_client_get_transaction(client, short_txid.as_ptr());
            assert!(tx.is_null());

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_broadcast_transaction() {
        unsafe {
            let (client, config, _temp_dir) = create_test_wallet();
            assert!(!client.is_null());

            // Create a minimal valid transaction hex (empty tx for testing)
            // Version (4 bytes) + tx_in count (1 byte) + tx_out count (1 byte) + locktime (4 bytes)
            let tx_hex = CString::new("0100000000000000000").unwrap();
            let result = dash_spv_ffi_client_broadcast_transaction(client, tx_hex.as_ptr());
            // Will likely fail due to invalid tx, but should handle gracefully
            assert_ne!(result, FFIErrorCode::Success as i32);

            // Test with invalid hex
            let invalid_hex = CString::new("not_hex").unwrap();
            let result = dash_spv_ffi_client_broadcast_transaction(client, invalid_hex.as_ptr());
            assert_eq!(result, FFIErrorCode::InvalidArgument as i32);

            // Test with null
            let result = dash_spv_ffi_client_broadcast_transaction(client, std::ptr::null());
            assert_eq!(result, FFIErrorCode::NullPointer as i32);

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    // Wrapper to make pointer Send
    struct SendableClient(*mut FFIDashSpvClient);
    unsafe impl Send for SendableClient {}

    #[test]
    #[serial]
    fn test_concurrent_wallet_operations() {
        unsafe {
            let (client, config, _temp_dir) = create_test_wallet();
            assert!(!client.is_null());

            let client_ptr = Arc::new(Mutex::new(SendableClient(client)));
            let mut handles = vec![];

            // Multiple threads performing wallet operations
            for i in 0..5 {
                let client_clone = client_ptr.clone();
                let handle = thread::spawn(move || {
                    let client = client_clone.lock().unwrap().0;

                    // Each thread watches different addresses
                    let addr = format!("XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R{:02}", i);
                    let c_addr = CString::new(addr).unwrap();

                    // Try to watch address
                    let _ = dash_spv_ffi_client_watch_address(client, c_addr.as_ptr());

                    // Get balance
                    let balance = dash_spv_ffi_client_get_address_balance(client, c_addr.as_ptr());
                    if !balance.is_null() {
                        dash_spv_ffi_balance_destroy(balance);
                    }

                    // Get UTXOs
                    let utxos = dash_spv_ffi_client_get_address_utxos(client, c_addr.as_ptr());
                    if !utxos.data.is_null() {
                        dash_spv_ffi_array_destroy(Box::into_raw(Box::new(utxos)));
                    }
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }

            let client = client_ptr.lock().unwrap().0;
            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_wallet_error_recovery() {
        unsafe {
            let (client, config, _temp_dir) = create_test_wallet();
            assert!(!client.is_null());

            // Clear any previous errors
            dash_spv_ffi_clear_error();

            // Trigger an error
            let invalid = CString::new("invalid_address").unwrap();
            let result = dash_spv_ffi_client_watch_address(client, invalid.as_ptr());
            assert_eq!(result, FFIErrorCode::InvalidArgument as i32);

            // Verify error was set
            let error1 = dash_spv_ffi_get_last_error();
            assert!(!error1.is_null());

            // Perform successful operation
            let valid = CString::new("Xan9iCVe1q5jYRDZ4VSMCtBjq2VyQA3Dge").unwrap();
            let result = dash_spv_ffi_client_watch_address(client, valid.as_ptr());
            assert_eq!(result, FFIErrorCode::ConfigError as i32); // Not implemented

            // Error should still be the old one (success doesn't clear errors)
            let error2 = dash_spv_ffi_get_last_error();
            assert!(!error2.is_null());

            // Clear error
            dash_spv_ffi_clear_error();
            let error3 = dash_spv_ffi_get_last_error();
            assert!(error3.is_null());

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_empty_wallet_state() {
        unsafe {
            let (client, config, _temp_dir) = create_test_wallet();
            assert!(!client.is_null());

            // Test getting watched addresses (should be empty)
            let addresses = dash_spv_ffi_client_get_watched_addresses(client);
            assert_eq!(addresses.len, 0);
            if !addresses.data.is_null() {
                dash_spv_ffi_array_destroy(Box::into_raw(Box::new(addresses)));
            }

            // Test getting watched scripts (should be empty)
            let scripts = dash_spv_ffi_client_get_watched_scripts(client);
            assert_eq!(scripts.len, 0);
            if !scripts.data.is_null() {
                dash_spv_ffi_array_destroy(Box::into_raw(Box::new(scripts)));
            }

            // Test total balance (should be zero)
            let balance = dash_spv_ffi_client_get_total_balance(client);
            if !balance.is_null() {
                let bal = &*balance;
                assert_eq!(bal.confirmed, 0);
                assert_eq!(bal.pending, 0);
                assert_eq!(bal.instantlocked, 0);
                dash_spv_ffi_balance_destroy(balance);
            }

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_rescan_blockchain() {
        unsafe {
            let (client, config, _temp_dir) = create_test_wallet();
            assert!(!client.is_null());

            // Add some addresses to watch
            let addrs =
                ["Xan9iCVe1q5jYRDZ4VSMCtBjq2VyQA3Dge", "XasTb9LP4wwsvtqXG6ZUZEggpiRFot8E4F"];

            for addr in &addrs {
                let c_addr = CString::new(*addr).unwrap();
                let result = dash_spv_ffi_client_watch_address(client, c_addr.as_ptr());
                assert_eq!(result, FFIErrorCode::ConfigError as i32); // Not implemented
            }

            // Test rescan from height 0
            let _result = dash_spv_ffi_client_rescan_blockchain(client, 0);
            assert_eq!(_result, FFIErrorCode::ConfigError as i32); // Not implemented

            // Test rescan from specific height
            let _result = dash_spv_ffi_client_rescan_blockchain(client, 100000);
            assert_eq!(_result, FFIErrorCode::ConfigError as i32); // Not implemented

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_transaction_confirmation_status() {
        unsafe {
            let (client, config, _temp_dir) = create_test_wallet();
            assert!(!client.is_null());

            // Test with non-existent transaction
            let txid =
                CString::new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                    .unwrap();
            let confirmations =
                dash_spv_ffi_client_get_transaction_confirmations(client, txid.as_ptr());
            assert_eq!(confirmations, -1); // Not found

            // Test is_transaction_confirmed
            let confirmed = dash_spv_ffi_client_is_transaction_confirmed(client, txid.as_ptr());
            assert_eq!(confirmed, 0); // False

            dash_spv_ffi_client_destroy(client);
            dash_spv_ffi_config_destroy(config);
        }
    }

    #[test]
    #[serial]
    fn test_wallet_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let data_path = temp_dir.path().to_str().unwrap();

        unsafe {
            // Create wallet and add watched addresses
            {
                let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
                let path = CString::new(data_path).unwrap();
                dash_spv_ffi_config_set_data_dir(config, path.as_ptr());

                let client = dash_spv_ffi_client_new(config);
                assert!(!client.is_null());

                // Add addresses to watch
                let addrs =
                    ["Xan9iCVe1q5jYRDZ4VSMCtBjq2VyQA3Dge", "XasTb9LP4wwsvtqXG6ZUZEggpiRFot8E4F"];

                for addr in &addrs {
                    let c_addr = CString::new(*addr).unwrap();
                    let result = dash_spv_ffi_client_watch_address(client, c_addr.as_ptr());
                    assert_eq!(result, FFIErrorCode::ConfigError as i32); // Not implemented
                }

                dash_spv_ffi_client_destroy(client);
                dash_spv_ffi_config_destroy(config);
            }

            // Create new wallet with same data dir
            {
                let config = dash_spv_ffi_config_new(FFINetwork::Regtest);
                let path = CString::new(data_path).unwrap();
                dash_spv_ffi_config_set_data_dir(config, path.as_ptr());

                let client = dash_spv_ffi_client_new(config);
                assert!(!client.is_null());

                // Check if watched addresses were persisted
                let addresses = dash_spv_ffi_client_get_watched_addresses(client);
                // Depending on implementation, addresses may or may not persist
                if !addresses.data.is_null() {
                    dash_spv_ffi_array_destroy(Box::into_raw(Box::new(addresses)));
                }

                dash_spv_ffi_client_destroy(client);
                dash_spv_ffi_config_destroy(config);
            }
        }
    }

    #[test]
    #[serial]
    fn test_wallet_null_operations() {
        unsafe {
            // Test all wallet operations with null client
            let addr = CString::new("XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E").unwrap();

            assert_eq!(
                dash_spv_ffi_client_watch_address(std::ptr::null_mut(), addr.as_ptr()),
                FFIErrorCode::NullPointer as i32
            );

            assert_eq!(
                dash_spv_ffi_client_unwatch_address(std::ptr::null_mut(), addr.as_ptr()),
                FFIErrorCode::NullPointer as i32
            );

            assert_eq!(
                dash_spv_ffi_client_watch_script(std::ptr::null_mut(), addr.as_ptr()),
                FFIErrorCode::NullPointer as i32
            );

            assert_eq!(
                dash_spv_ffi_client_unwatch_script(std::ptr::null_mut(), addr.as_ptr()),
                FFIErrorCode::NullPointer as i32
            );

            assert!(dash_spv_ffi_client_get_address_balance(std::ptr::null_mut(), addr.as_ptr())
                .is_null());
            assert!(dash_spv_ffi_client_get_address_utxos(std::ptr::null_mut(), addr.as_ptr())
                .data
                .is_null());
            assert!(dash_spv_ffi_client_get_address_history(std::ptr::null_mut(), addr.as_ptr())
                .data
                .is_null());
            assert!(
                dash_spv_ffi_client_get_transaction(std::ptr::null_mut(), addr.as_ptr()).is_null()
            );

            assert_eq!(
                dash_spv_ffi_client_broadcast_transaction(std::ptr::null_mut(), addr.as_ptr()),
                FFIErrorCode::NullPointer as i32
            );

            assert!(dash_spv_ffi_client_get_watched_addresses(std::ptr::null_mut()).data.is_null());
            assert!(dash_spv_ffi_client_get_watched_scripts(std::ptr::null_mut()).data.is_null());
            assert!(dash_spv_ffi_client_get_total_balance(std::ptr::null_mut()).is_null());

            assert_eq!(
                dash_spv_ffi_client_rescan_blockchain(std::ptr::null_mut(), 0),
                FFIErrorCode::NullPointer as i32
            );
        }
    }
}
