#[cfg(feature = "bincode")]
#[cfg(test)]
mod tests {
    use key_wallet::wallet::initialization::WalletAccountCreationOptions;
    use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
    use key_wallet::Network;
    use key_wallet_manager::wallet_manager::WalletManager;

    #[test]
    fn test_create_wallet_return_serialized_bytes() {
        let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        // Test 1: Create full wallet with private keys
        let result = manager.create_wallet_from_mnemonic_return_serialized_bytes(
            test_mnemonic,
            "",
            100_000,
            WalletAccountCreationOptions::Default,
            false, // Don't downgrade
            false,
        );
        assert!(result.is_ok());
        let (bytes, wallet_id) = result.unwrap();
        assert!(!bytes.is_empty());
        println!("Full wallet ID: {}", hex::encode(wallet_id));

        // Test 2: Create watch-only wallet (no private keys)
        let mut manager2 = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);
        let result = manager2.create_wallet_from_mnemonic_return_serialized_bytes(
            test_mnemonic,
            "",
            100_000,
            WalletAccountCreationOptions::Default,
            true,  // Downgrade to pubkey wallet
            false, // Watch-only, not externally signable
        );
        assert!(result.is_ok());
        let (bytes2, wallet_id2) = result.unwrap();
        assert!(!bytes2.is_empty());

        // Same wallet ID because it's derived from the same root public key
        assert_eq!(wallet_id, wallet_id2);
        println!("Watch-only wallet ID: {}", hex::encode(wallet_id2));

        // Test 3: Create externally signable wallet (for hardware wallets)
        let mut manager3 = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);
        let result = manager3.create_wallet_from_mnemonic_return_serialized_bytes(
            test_mnemonic,
            "",
            100_000,
            WalletAccountCreationOptions::Default,
            true, // Downgrade to pubkey wallet
            true, // Externally signable (for hardware wallets)
        );
        assert!(result.is_ok());
        let (bytes3, wallet_id3) = result.unwrap();
        assert!(!bytes3.is_empty());
        assert_eq!(wallet_id, wallet_id3);
        println!("Externally signable wallet ID: {}", hex::encode(wallet_id3));

        // Test 4: Import the serialized wallet back
        let mut manager4 = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);
        let import_result = manager4.import_wallet_from_bytes(&bytes);
        assert!(import_result.is_ok());
        assert_eq!(import_result.unwrap(), wallet_id);
    }

    #[test]
    fn test_wallet_with_passphrase() {
        let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "test_passphrase";

        let result = manager.create_wallet_from_mnemonic_return_serialized_bytes(
            test_mnemonic,
            passphrase,
            0,
            WalletAccountCreationOptions::Default,
            false,
            false,
        );
        assert!(result.is_ok());
        let (bytes, wallet_id) = result.unwrap();
        assert!(!bytes.is_empty());

        // Wallet ID with passphrase should be different
        let mut manager2 = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);
        let result2 = manager2.create_wallet_from_mnemonic_return_serialized_bytes(
            test_mnemonic,
            "", // No passphrase
            0,
            WalletAccountCreationOptions::Default,
            false,
            false,
        );
        assert!(result2.is_ok());
        let (_bytes2, wallet_id2) = result2.unwrap();

        // Different wallet IDs because different passphrases
        assert_ne!(wallet_id, wallet_id2);
    }
}
