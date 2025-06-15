//! Internal tests for key-wallet-ffi
//!
//! These tests verify the FFI implementation works correctly.

#[cfg(test)]
mod tests {
    use crate::{
        validate_mnemonic, Address, AddressGenerator, ExtPrivKey, ExtPubKey, HDWallet, Language,
        Mnemonic, Network,
    };

    #[test]
    fn test_mnemonic_functionality() {
        // Test mnemonic validation
        let valid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let is_valid = validate_mnemonic(valid_phrase.clone(), Language::English).unwrap();
        assert!(is_valid);

        // Test creating from phrase
        let mnemonic = Mnemonic::new(valid_phrase, Language::English).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 12);

        // Test seed generation
        let seed = mnemonic.to_seed("".to_string());
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn test_hd_wallet_functionality() {
        // Create wallet from seed
        let seed = vec![0u8; 64];
        let wallet = HDWallet::from_seed(seed, Network::Testnet).unwrap();

        // Test getting account keys
        let account_xpriv = wallet.get_account_xpriv(0).unwrap();
        let account_xpub = wallet.get_account_xpub(0).unwrap();

        // Test deriving keys
        let path = "m/44'/1'/0'/0/0".to_string();
        let derived_xpriv = wallet.derive_xpriv(path.clone()).unwrap();
        let derived_xpub = wallet.derive_xpub(path.clone()).unwrap();
        // Verify we got keys
        assert!(!account_xpriv.xpriv.is_empty());
        assert!(!account_xpriv.derivation_path.is_empty());
        assert!(!account_xpub.xpub.is_empty());
        assert!(!derived_xpriv.is_empty());
        assert!(!derived_xpub.xpub.is_empty());
    }

    #[test]
    fn test_address_functionality() {
        // Test creating P2PKH address from public key
        let pubkey = vec![
            0x02, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82, 0x6d, 0xc6, 0x1c,
            0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32,
            0x5a, 0x0f, 0x46, 0x79, 0xef,
        ];
        let address = Address::from_public_key(pubkey, Network::Testnet).unwrap();
        let address_str = address.to_string();
        assert!(address_str.starts_with('y')); // Testnet P2PKH addresses start with 'y'

        // Test parsing from string
        let parsed = Address::from_string(address_str.clone(), Network::Testnet).unwrap();
        assert_eq!(parsed.to_string(), address_str);
        assert_eq!(parsed.get_network(), Network::Testnet);

        // Test script pubkey
        let script = address.get_script_pubkey();
        assert!(script.len() > 0);
    }

    #[test]
    fn test_address_generator_functionality() {
        let seed = vec![0u8; 64];
        let wallet = HDWallet::from_seed(seed, Network::Testnet).unwrap();

        // Get account extended public key
        let account_xpub = wallet.get_account_xpub(0).unwrap();

        let generator = AddressGenerator::new(Network::Testnet);

        // Test single address generation
        let single_addr = generator.generate(account_xpub.clone(), true, 0).unwrap();
        assert!(single_addr.to_string().starts_with('y'));

        // Test address range generation
        let addresses = generator.generate_range(account_xpub, true, 0, 5).unwrap();
        assert_eq!(addresses.len(), 5);
        for addr in &addresses {
            assert!(addr.to_string().starts_with('y'));
        }
    }

    #[test]
    fn test_extended_key_methods() {
        // Generate a valid extended key from a known seed
        let seed = vec![0u8; 64];
        let wallet = HDWallet::from_seed(seed, Network::Testnet).unwrap();
        let account_xpriv = wallet.get_account_xpriv(0).unwrap();

        // Test ExtPrivKey
        let xpriv = ExtPrivKey::from_string(account_xpriv.xpriv).unwrap();

        // Test getting xpub
        let xpub = xpriv.get_xpub();
        assert!(xpub.xpub.starts_with("tpub")); // Testnet public key

        // Test deriving child
        let child = xpriv.derive_child(0, false).unwrap();
        assert!(!child.to_string().is_empty());

        // Test ExtPubKey
        let xpub_obj = ExtPubKey::from_string(xpub.xpub).unwrap();
        let pubkey_bytes = xpub_obj.get_public_key();
        assert_eq!(pubkey_bytes.len(), 33); // Compressed public key
    }

    #[test]
    fn test_error_handling() {
        // Test invalid mnemonic
        let invalid_phrase = "invalid mnemonic phrase".to_string();
        let result = Mnemonic::new(invalid_phrase, Language::English);
        assert!(result.is_err());

        // Test invalid address
        let result = Address::from_string("invalid_address".to_string(), Network::Testnet);
        assert!(result.is_err());

        // Test invalid derivation path
        let seed = vec![0u8; 64];
        let wallet = HDWallet::from_seed(seed, Network::Testnet).unwrap();
        let result = wallet.derive_xpriv("invalid/path".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_network_compatibility_in_address_parsing() {
        // Create a testnet address
        let pubkey = vec![
            0x02, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82, 0x6d, 0xc6, 0x1c,
            0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32,
            0x5a, 0x0f, 0x46, 0x79, 0xef,
        ];
        let testnet_addr = Address::from_public_key(pubkey, Network::Testnet).unwrap();
        let addr_str = testnet_addr.to_string();

        // Should work with testnet
        let parsed = Address::from_string(addr_str.clone(), Network::Testnet);
        assert!(parsed.is_ok());

        // Should also work with devnet and regtest (same prefixes)
        let parsed = Address::from_string(addr_str.clone(), Network::Devnet);
        assert!(parsed.is_ok());

        let parsed = Address::from_string(addr_str.clone(), Network::Regtest);
        assert!(parsed.is_ok());

        // Should fail with mainnet (different prefix)
        let parsed = Address::from_string(addr_str.clone(), Network::Dash);
        assert!(parsed.is_err());
    }
}
