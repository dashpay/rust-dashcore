//! Tests for account-level derivation FFI

#[cfg(test)]
mod tests {
    use crate::account::account_free;
    use crate::account_derivation::*;
    use crate::derivation::*;
    use crate::error::{FFIError, FFIErrorCode};
    use crate::keys::{extended_private_key_free, private_key_free};
    use crate::types::{FFIAccountType, FFINetworks};
    use crate::wallet;

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn test_account_derive_private_key_at_receive_index() {
        let mut error = FFIError::success();

        // Create wallet on testnet with default accounts
        let wallet = unsafe { wallet::wallet_create_from_mnemonic(c_str(MNEMONIC), c_str(""), FFINetworks::TestnetFlag, &mut error) };
        assert!(!wallet.is_null());
        assert_eq!(unsafe { (*(&mut error)).code }, FFIErrorCode::Success);

        // Get account 0 (BIP44)
        let account = unsafe {
            crate::account::wallet_get_account(wallet, crate::FFINetwork::Testnet, 0, FFIAccountType::StandardBIP44)
                .account
        };
        assert!(!account.is_null());

        // Build a master xpriv from the same mnemonic seed
        let mut seed = [0u8; 64];
        // Deterministic seed from mnemonic helper
        let ok = unsafe {
            crate::mnemonic::mnemonic_to_seed(c_str(MNEMONIC), c_str(""), seed.as_mut_ptr(), &mut (seed.len()), &mut error)
        };
        assert!(ok);

        let master_xpriv = unsafe { derivation_new_master_key(seed.as_ptr(), seed.len(), crate::FFINetwork::Testnet, &mut error) };
        assert!(!master_xpriv.is_null());

        // For standard accounts with internal/external, this helper should fail
        let priv_key = unsafe { account_derive_private_key_at(account, master_xpriv, 0, &mut error) };
        assert!(priv_key.is_null());
        assert_eq!(unsafe { (*(&mut error)).code }, FFIErrorCode::WalletError);

        // Derive WIF should also fail for such accounts
        let wif = unsafe { account_derive_private_key_as_wif_at(account, master_xpriv, 0, &mut error) };
        assert!(wif.is_null());
        assert_eq!(unsafe { (*(&mut error)).code }, FFIErrorCode::WalletError);

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
        let mut error = FFIError::success();

        // BLS nulls
        #[cfg(feature = "bls")]
        unsafe {
            assert!(
                super::super::account_derivation::bls_account_derive_private_key_from_seed(
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    0,
                    &mut error,
                )
                .is_null()
            );
            assert_eq!(error.code, FFIErrorCode::InvalidInput);
        }

        // EdDSA nulls
        #[cfg(feature = "eddsa")]
        unsafe {
            assert!(
                super::super::account_derivation::eddsa_account_derive_private_key_from_seed(
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    0,
                    &mut error,
                )
                .is_null()
            );
            assert_eq!(error.code, FFIErrorCode::InvalidInput);
        }
    }

    #[test]
    fn test_account_derive_extended_private_key_at_change_index() {
        let mut error = FFIError::success();

        // Create wallet on testnet with default accounts
        let wallet = unsafe { wallet::wallet_create_from_mnemonic(c_str(MNEMONIC), c_str(""), FFINetworks::TestnetFlag, &mut error) };
        assert!(!wallet.is_null());

        // Get account 0 (BIP44)
        let account = unsafe {
            crate::account::wallet_get_account(wallet, crate::FFINetwork::Testnet, 0, FFIAccountType::StandardBIP44)
                .account
        };
        assert!(!account.is_null());

        // Seed and master xpriv
        let mut seed = [0u8; 64];
        let ok = unsafe {
            crate::mnemonic::mnemonic_to_seed(c_str(MNEMONIC), c_str(""), seed.as_mut_ptr(), &mut (seed.len()), &mut error)
        };
        assert!(ok);
        let master_xpriv = unsafe { derivation_new_master_key(seed.as_ptr(), seed.len(), crate::FFINetwork::Testnet, &mut error) };
        assert!(!master_xpriv.is_null());

        // Extended xpriv helper should also fail for standard accounts
        let xpriv =
            unsafe { account_derive_extended_private_key_at(account, master_xpriv, 5, &mut error) };
        assert!(xpriv.is_null());
        assert_eq!(unsafe { (*(&mut error)).code }, FFIErrorCode::WalletError);

        // Cleanup
        unsafe {
            extended_private_key_free(master_xpriv);
            account_free(account);
            wallet::wallet_free(wallet);
        }
    }

    #[test]
    fn test_account_derive_from_seed_and_mnemonic_helpers_fail_for_standard() {
        let mut error = FFIError::success();

        // Create wallet and get account 0
        let wallet = unsafe { wallet::wallet_create_from_mnemonic(c_str(MNEMONIC), c_str(""), FFINetworks::TestnetFlag, &mut error) };
        assert!(!wallet.is_null());
        let account = unsafe {
            crate::account::wallet_get_account(wallet, crate::FFINetwork::Testnet, 0, FFIAccountType::StandardBIP44)
                .account
        };
        assert!(!account.is_null());

        // Prepare seed
        let mnemonic = std::ffi::CString::new(MNEMONIC).unwrap();
        let pass = std::ffi::CString::new("").unwrap();
        let mut seed = [0u8; 64];
        let mut seed_len = seed.len();
        let ok = unsafe { crate::mnemonic::mnemonic_to_seed(mnemonic.as_ptr(), pass.as_ptr(), seed.as_mut_ptr(), &mut seed_len, &mut error) };
        assert!(ok);

        // account_derive_extended_private_key_from_seed should fail for standard accounts
        let xpriv_seed = unsafe {
            super::super::account_derivation::account_derive_extended_private_key_from_seed(
                account,
                seed.as_ptr(),
                seed_len,
                0,
                &mut error,
            )
        };
        assert!(xpriv_seed.is_null());
        assert_eq!(unsafe { (*(&mut error)).code }, FFIErrorCode::WalletError);

        // account_derive_private_key_from_seed should fail
        let priv_seed = unsafe {
            super::super::account_derivation::account_derive_private_key_from_seed(
                account,
                seed.as_ptr(),
                seed_len,
                0,
                &mut error,
            )
        };
        assert!(priv_seed.is_null());
        assert_eq!(unsafe { (*(&mut error)).code }, FFIErrorCode::WalletError);

        // account_derive_extended_private_key_from_mnemonic should fail
        let xpriv_mn = unsafe {
            super::super::account_derivation::account_derive_extended_private_key_from_mnemonic(
                account,
                mnemonic.as_ptr(),
                pass.as_ptr(),
                0,
                &mut error,
            )
        };
        assert!(xpriv_mn.is_null());
        assert_eq!(unsafe { (*(&mut error)).code }, FFIErrorCode::WalletError);

        // account_derive_private_key_from_mnemonic should fail
        let priv_mn = unsafe {
            super::super::account_derivation::account_derive_private_key_from_mnemonic(
                account,
                mnemonic.as_ptr(),
                pass.as_ptr(),
                0,
                &mut error,
            )
        };
        assert!(priv_mn.is_null());
        assert_eq!(unsafe { (*(&mut error)).code }, FFIErrorCode::WalletError);

        unsafe {
            account_free(account);
            wallet::wallet_free(wallet);
        }
    }

    // Helper to make C string pointers
    fn c_str(s: &str) -> *const i8 {
        std::ffi::CString::new(s).unwrap().as_ptr()
    }
}
