//! Tests for account-level derivation FFI

#[cfg(test)]
mod tests {
    use crate::account::account_free;
    use crate::account_derivation::*;
    use crate::derivation::*;
    use crate::error::{FFIError, FFIErrorCode};
    use crate::keys::{extended_private_key_free, private_key_free};
    use crate::types::FFIAccountKind;
    use crate::wallet;
    use dash_network::ffi::FFINetwork;
    #[cfg(feature = "bls")]
    use key_wallet::account::{AccountType, BLSAccount};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_account_derive_private_key_at_receive_index() {
        let mut error = FFIError::default();

        let mnemonic = std::ffi::CString::new(MNEMONIC).unwrap();
        let passphrase = std::ffi::CString::new("").unwrap();

        // Create wallet on testnet with default accounts
        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(mnemonic.as_ptr(), FFINetwork::Testnet, &mut error)
        };
        assert!(!wallet.is_null());
        assert_eq!(error.code, FFIErrorCode::Success);

        // Get account 0 (BIP44)
        let account = unsafe {
            crate::account::wallet_get_account(wallet, 0, FFIAccountKind::StandardBIP44).account
        };
        assert!(!account.is_null());

        // Build a master xpriv from the same mnemonic seed
        let mut seed = [0u8; 64];
        // Deterministic seed from mnemonic helper
        let ok = unsafe {
            crate::mnemonic::mnemonic_to_seed(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                seed.as_mut_ptr(),
                &mut (seed.len()),
                &mut error,
            )
        };
        assert!(ok);

        let master_xpriv = unsafe {
            derivation_new_master_key(seed.as_ptr(), seed.len(), FFINetwork::Testnet, &mut error)
        };
        assert!(!master_xpriv.is_null());

        // For standard accounts with internal/external, this helper should fail
        let priv_key =
            unsafe { account_derive_private_key_at(account, master_xpriv, 0, &mut error) };
        assert!(priv_key.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Derive WIF should also fail for such accounts
        let wif =
            unsafe { account_derive_private_key_as_wif_at(account, master_xpriv, 0, &mut error) };
        assert!(wif.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Cleanup
        unsafe {
            crate::utils::string_free(wif);
            private_key_free(priv_key);
            extended_private_key_free(master_xpriv);
            account_free(account);
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_bls_and_eddsa_from_seed_and_mnemonic_null_safety() {
        let mut error = FFIError::default();

        // BLS nulls
        #[cfg(feature = "bls")]
        unsafe {
            assert!(super::super::bls_account_derive_private_key_from_seed(
                std::ptr::null(),
                std::ptr::null(),
                0,
                0,
                &mut error,
            )
            .is_null());
            assert_eq!(error.code, FFIErrorCode::InvalidInput);
        }

        // EdDSA nulls
        #[cfg(feature = "eddsa")]
        unsafe {
            assert!(super::super::eddsa_account_derive_private_key_from_seed(
                std::ptr::null(),
                std::ptr::null(),
                0,
                0,
                &mut error,
            )
            .is_null());
            assert_eq!(error.code, FFIErrorCode::InvalidInput);
        }
    }

    #[test]
    fn test_account_derive_extended_private_key_at_change_index() {
        let mut error = FFIError::default();

        let mnemonic = std::ffi::CString::new(MNEMONIC).unwrap();
        let passphrase = std::ffi::CString::new("").unwrap();

        // Create wallet on testnet with default accounts
        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(mnemonic.as_ptr(), FFINetwork::Testnet, &mut error)
        };
        assert!(!wallet.is_null());

        // Get account 0 (BIP44)
        let account = unsafe {
            crate::account::wallet_get_account(wallet, 0, FFIAccountKind::StandardBIP44).account
        };
        assert!(!account.is_null());

        // Seed and master xpriv
        let mut seed = [0u8; 64];
        let ok = unsafe {
            crate::mnemonic::mnemonic_to_seed(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                seed.as_mut_ptr(),
                &mut (seed.len()),
                &mut error,
            )
        };
        assert!(ok);
        let master_xpriv = unsafe {
            derivation_new_master_key(seed.as_ptr(), seed.len(), FFINetwork::Testnet, &mut error)
        };
        assert!(!master_xpriv.is_null());

        // Extended xpriv helper should also fail for standard accounts
        let xpriv =
            unsafe { account_derive_extended_private_key_at(account, master_xpriv, 5, &mut error) };
        assert!(xpriv.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Cleanup
        unsafe {
            extended_private_key_free(master_xpriv);
            account_free(account);
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_account_derive_from_seed_and_mnemonic_helpers_fail_for_standard() {
        let mut error = FFIError::default();

        let mnemonic = std::ffi::CString::new(MNEMONIC).unwrap();
        let passphrase = std::ffi::CString::new("").unwrap();

        // Create wallet and get account 0
        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(mnemonic.as_ptr(), FFINetwork::Testnet, &mut error)
        };
        assert!(!wallet.is_null());
        let account = unsafe {
            crate::account::wallet_get_account(wallet, 0, FFIAccountKind::StandardBIP44).account
        };
        assert!(!account.is_null());

        // Prepare seed
        let mut seed = [0u8; 64];
        let mut seed_len = seed.len();
        let ok = unsafe {
            crate::mnemonic::mnemonic_to_seed(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                seed.as_mut_ptr(),
                &mut seed_len,
                &mut error,
            )
        };
        assert!(ok);

        // account_derive_extended_private_key_from_seed should fail for standard accounts
        let xpriv_seed = unsafe {
            super::super::account_derive_extended_private_key_from_seed(
                account,
                seed.as_ptr(),
                seed_len,
                0,
                &mut error,
            )
        };
        assert!(xpriv_seed.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // account_derive_private_key_from_seed should fail
        let priv_seed = unsafe {
            super::super::account_derive_private_key_from_seed(
                account,
                seed.as_ptr(),
                seed_len,
                0,
                &mut error,
            )
        };
        assert!(priv_seed.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // account_derive_extended_private_key_from_mnemonic should fail
        let xpriv_mn = unsafe {
            super::super::account_derive_extended_private_key_from_mnemonic(
                account,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                0,
                &mut error,
            )
        };
        assert!(xpriv_mn.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // account_derive_private_key_from_mnemonic should fail
        let priv_mn = unsafe {
            super::super::account_derive_private_key_from_mnemonic(
                account,
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                0,
                &mut error,
            )
        };
        assert!(priv_mn.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        unsafe {
            account_free(account);
            wallet::wallet_free(wallet);
        }
    }

    /// Provider operator (BLS) and platform node (Ed25519) keys derived from a
    /// seed through the FFI must match the DashSync/dashbls reference vectors
    /// (see rust-dashcore issue #878 and
    /// key-wallet/src/tests/provider_key_derivation_tests.rs).
    #[test]
    #[cfg(all(feature = "bls", feature = "eddsa"))]
    fn test_provider_key_derivation_matches_dashsync_reference() {
        let mut error = FFIError::default();

        let mnemonic = std::ffi::CString::new(MNEMONIC).unwrap();
        let passphrase = std::ffi::CString::new("").unwrap();

        let wallet = unsafe {
            wallet::wallet_create_from_mnemonic(mnemonic.as_ptr(), FFINetwork::Mainnet, &mut error)
        };
        assert!(!wallet.is_null());

        let mut seed = [0u8; 64];
        let ok = unsafe {
            crate::mnemonic::mnemonic_to_seed(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                seed.as_mut_ptr(),
                &mut (seed.len()),
                &mut error,
            )
        };
        assert!(ok);

        let collection =
            unsafe { crate::account_collection::wallet_get_account_collection(wallet, &mut error) };
        assert!(!collection.is_null());

        unsafe {
            // BLS operator key 0 at m/9'/5'/3'/3'/0 (legacy HD chain).
            let operator_account =
                crate::account_collection::account_collection_get_provider_operator_keys(collection)
                    as *mut crate::account::FFIBLSAccount;
            assert!(!operator_account.is_null());

            let sk0_hex = super::super::bls_account_derive_private_key_from_seed(
                operator_account,
                seed.as_ptr(),
                seed.len(),
                0,
                &mut error,
            );
            assert!(!sk0_hex.is_null(), "BLS derivation failed: {:?}", error.code);
            let sk0 = std::ffi::CStr::from_ptr(sk0_hex).to_str().unwrap();
            assert_eq!(sk0, "11122e1ad656d0610ce0f80d40da874d67ea656a3e66ed371c915ec3a488a43a");
            crate::utils::string_free(sk0_hex);
            crate::account::bls_account_free(operator_account);

            // Ed25519 platform node key 0 at m/9'/5'/3'/4'/0' (SLIP-0010).
            let platform_account =
                crate::account_collection::account_collection_get_provider_platform_keys(collection)
                    as *mut crate::account::FFIEdDSAAccount;
            assert!(!platform_account.is_null());

            let node_sk0_hex = super::super::eddsa_account_derive_private_key_from_seed(
                platform_account,
                seed.as_ptr(),
                seed.len(),
                0,
                &mut error,
            );
            assert!(!node_sk0_hex.is_null(), "Ed25519 derivation failed: {:?}", error.code);
            let node_sk0 = std::ffi::CStr::from_ptr(node_sk0_hex).to_str().unwrap();
            assert_eq!(
                node_sk0,
                "5fa238b12be77347abf9b5957bd902d16c6aaca28d25c4267ffacbd7458dceb1"
            );
            crate::utils::string_free(node_sk0_hex);
            crate::account::eddsa_account_free(platform_account);

            crate::account_collection::account_collection_free(collection);
            wallet::wallet_free(wallet);
        }
    }

    #[cfg(feature = "bls")]
    #[test]
    fn test_bls_seed_helper_rejects_invalid_seed_lengths() {
        let mut error = FFIError::default();
        let account = BLSAccount::from_seed(
            None,
            AccountType::ProviderOperatorKeys,
            &[1u8; 32],
            dashcore::Network::Testnet,
        )
        .unwrap();
        let ffi_account = crate::account::FFIBLSAccount::new(&account);
        let short_seed = [0u8; 15];
        let long_seed = [0u8; 65];

        let too_short = unsafe {
            bls_account_derive_private_key_from_seed(
                &ffi_account,
                short_seed.as_ptr(),
                short_seed.len(),
                0,
                &mut error,
            )
        };
        assert!(too_short.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        error = FFIError::default();
        let too_long = unsafe {
            bls_account_derive_private_key_from_seed(
                &ffi_account,
                long_seed.as_ptr(),
                long_seed.len(),
                0,
                &mut error,
            )
        };
        assert!(too_long.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[cfg(feature = "eddsa")]
    #[test]
    fn test_eddsa_seed_helper_rejects_invalid_seed_lengths() {
        let mut error = FFIError::default();
        let account = key_wallet::account::EdDSAAccount::from_seed(
            None,
            FFIAccountKind::ProviderPlatformKeys.to_account_type(0),
            &[1u8; 32],
            FFINetwork::Testnet.into(),
        )
        .unwrap();
        let ffi_account = crate::account::FFIEdDSAAccount::new(&account);
        let short_seed = [0u8; 15];

        let too_short = unsafe {
            eddsa_account_derive_private_key_from_seed(
                &ffi_account,
                short_seed.as_ptr(),
                short_seed.len(),
                0,
                &mut error,
            )
        };
        assert!(too_short.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }
}
