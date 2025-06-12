//! Internal tests for key-wallet-ffi
//!
//! These tests verify the FFI implementation works correctly.

#[cfg(test)]
mod tests {
    use crate::{
        validate_mnemonic, Address, AddressGenerator, ExtendedKey, HDWallet, Language, Mnemonic,
        Network,
    };

    #[test]
    fn test_mnemonic_functionality() {
        // Test mnemonic validation
        let valid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let is_valid = validate_mnemonic(valid_phrase.clone(), Language::English).unwrap();
        assert!(is_valid);

        // Test creating from phrase
        let mnemonic = Mnemonic::from_phrase(valid_phrase, Language::English).unwrap();
        assert_eq!(mnemonic.get_word_count(), 12);

        // Test seed generation
        let seed = mnemonic.to_seed("".to_string());
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn test_hd_wallet_functionality() {
        // Create wallet from seed
        let seed = vec![0u8; 64];
        let wallet = HDWallet::from_seed(seed, Network::Testnet).unwrap();

        // Test getting master keys
        let master_key = wallet.get_master_key().unwrap();
        let master_pub_key = wallet.get_master_pub_key().unwrap();

        // Test deriving keys
        let path = "m/44'/1'/0'/0/0".to_string();
        let derived_key = wallet.derive(path.clone()).unwrap();
        let derived_pub_key = wallet.derive_pub(path).unwrap();

        // Verify we got keys
        assert!(master_key.get_fingerprint().len() > 0);
        assert!(master_pub_key.get_fingerprint().len() > 0);
        assert!(derived_key.get_fingerprint().len() > 0);
        assert!(derived_pub_key.get_fingerprint().len() > 0);
    }

    #[test]
    fn test_address_functionality() {
        // Test creating P2PKH address from public key
        let pubkey = vec![
            0x02, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82, 0x6d, 0xc6, 0x1c,
            0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32,
            0x5a, 0x0f, 0x46, 0x79, 0xef,
        ];
        let address = Address::p2pkh(pubkey, Network::Testnet).unwrap();
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
        let account_pub = wallet.derive_pub("m/44'/1'/0'".to_string()).unwrap();

        let generator = AddressGenerator::new(Network::Testnet);

        // Test single address generation
        let single_addr = generator.generate_p2pkh(account_pub.clone()).unwrap();
        assert!(single_addr.to_string().starts_with('y'));

        // Test address range generation
        let addresses = generator.generate_range(account_pub, true, 0, 5).unwrap();
        assert_eq!(addresses.len(), 5);
        for addr in addresses {
            assert!(addr.to_string().starts_with('y'));
        }
    }

    #[test]
    fn test_extended_key_methods() {
        let seed = vec![0u8; 64];
        let wallet = HDWallet::from_seed(seed, Network::Testnet).unwrap();
        let key = wallet.get_master_key().unwrap();

        // Test all ExtendedKey methods
        let fingerprint = key.get_fingerprint();
        assert_eq!(fingerprint.len(), 4);

        let chain_code = key.get_chain_code();
        assert_eq!(chain_code.len(), 32);

        let depth = key.get_depth();
        assert_eq!(depth, 0); // Master key has depth 0

        let child_number = key.get_child_number();
        assert_eq!(child_number, 0); // Master key has child number 0

        let key_str = key.to_string();
        assert!(key_str.starts_with("tprv")); // Testnet private key
    }

    #[test]
    fn test_error_handling() {
        // Test invalid mnemonic
        let invalid_phrase = "invalid mnemonic phrase".to_string();
        let result = Mnemonic::from_phrase(invalid_phrase, Language::English);
        assert!(result.is_err());

        // Test invalid address
        let result = Address::from_string("invalid_address".to_string(), Network::Testnet);
        assert!(result.is_err());

        // Test invalid derivation path
        let seed = vec![0u8; 64];
        let wallet = HDWallet::from_seed(seed, Network::Testnet).unwrap();
        let result = wallet.derive("invalid/path".to_string());
        assert!(result.is_err());
    }
}
