//! Tests for wallet creation with passphrase
//! These tests demonstrate current issues with passphrase handling

#[cfg(test)]
mod tests {
    use crate::account::StandardAccountType;
    use crate::mnemonic::{Language, Mnemonic};
    use crate::wallet::initialization::WalletAccountCreationOptions;
    use crate::{AccountType, Network, Wallet};

    #[test]
    fn test_wallet_from_mnemonic_with_passphrase_account_creation() {
        // This test demonstrates the issue with creating accounts for wallets with passphrases

        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(mnemonic_str, Language::English).unwrap();
        let passphrase = "my_secure_passphrase";
        let network = Network::Testnet;

        // Create a wallet with passphrase
        let wallet = Wallet::from_mnemonic_with_passphrase(
            mnemonic.clone(),
            passphrase.to_string(),
            &[network],
            WalletAccountCreationOptions::None,
        )
        .expect("Should create wallet with passphrase");

        // Verify wallet was created
        // We can't easily check the wallet type from outside, but we know it's created

        // Try to get account 0 - should not exist yet
        assert!(wallet.get_bip44_account(network, 0).is_none());

        // Try to add account 0 without providing passphrase
        // THIS WILL FAIL because the wallet needs the passphrase to derive accounts
        let mut wallet_mut = wallet.clone();
        let account_type = AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP44Account,
        };

        // This should fail with an error about needing the passphrase
        let result = wallet_mut.add_account(account_type, network, None);

        // EXPECTED: This will fail because we can't derive the account without the passphrase
        assert!(result.is_err());

        if let Err(e) = result {
            println!("Expected error when adding account without passphrase: {}", e);
            // The error should mention needing a passphrase
            assert!(
                e.to_string().contains("passphrase")
                    || e.to_string().contains("Mnemonic with passphrase")
            );
        }
    }

    #[test]
    fn test_wallet_with_passphrase_cannot_derive_keys() {
        // This test shows that wallets with passphrases can't derive private keys
        // without the passphrase being provided

        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(mnemonic_str, Language::English).unwrap();
        let passphrase = "test_passphrase_123";
        let network = Network::Testnet;

        // Create wallet with passphrase
        let wallet = Wallet::from_mnemonic_with_passphrase(
            mnemonic,
            passphrase.to_string(),
            &[network],
            WalletAccountCreationOptions::None,
        )
        .expect("Should create wallet");

        // Try to get the root extended private key
        // THIS WILL FAIL because passphrase is needed
        let root_key_result = wallet.root_extended_priv_key();

        assert!(root_key_result.is_err());

        if let Err(e) = root_key_result {
            println!("Expected error when getting root key without passphrase: {}", e);
            // Should indicate that passphrase is required
            assert!(
                e.to_string().contains("passphrase")
                    || e.to_string().contains("Mnemonic with passphrase")
            );
        }
    }

    #[test]
    fn test_add_account_with_passphrase() {
        // This test demonstrates the new add_account_with_passphrase function

        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(mnemonic_str, Language::English).unwrap();
        let passphrase = "my_passphrase";
        let network = Network::Testnet;

        // Create wallet with passphrase
        let mut wallet = Wallet::from_mnemonic_with_passphrase(
            mnemonic,
            passphrase.to_string(),
            &[network],
            WalletAccountCreationOptions::None,
        )
        .expect("Should create wallet");

        // Verify no accounts exist initially
        assert!(wallet.get_bip44_account(network, 0).is_none());

        // Add account using the new function with the correct passphrase
        let account_type = AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP44Account,
        };

        let result = wallet.add_account_with_passphrase(account_type, network, passphrase);
        assert!(result.is_ok(), "Should successfully add account with correct passphrase");

        // Verify account was added
        assert!(wallet.get_bip44_account(network, 0).is_some());

        // Try to add the same account again - should fail
        let duplicate_result =
            wallet.add_account_with_passphrase(account_type, network, passphrase);
        assert!(duplicate_result.is_err());
        assert!(duplicate_result.unwrap_err().to_string().contains("already exists"));

        // Add a second account
        let account_type_2 = AccountType::Standard {
            index: 1,
            standard_account_type: StandardAccountType::BIP44Account,
        };
        let result2 = wallet.add_account_with_passphrase(account_type_2, network, passphrase);
        assert!(result2.is_ok());
        assert!(wallet.get_bip44_account(network, 1).is_some());
    }

    #[test]
    fn test_add_account_with_passphrase_wrong_wallet_type() {
        // Test that add_account_with_passphrase fails on non-passphrase wallets

        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(mnemonic_str, Language::English).unwrap();
        let network = Network::Testnet;

        // Create regular wallet WITHOUT passphrase
        let mut wallet =
            Wallet::from_mnemonic(mnemonic, &[network], WalletAccountCreationOptions::Default)
                .expect("Should create wallet");

        // Try to use add_account_with_passphrase - should fail
        let account_type = AccountType::Standard {
            index: 10,
            standard_account_type: StandardAccountType::BIP44Account,
        };

        let result = wallet.add_account_with_passphrase(account_type, network, "some_passphrase");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("can only be used with wallets created with a passphrase"));
    }
}
