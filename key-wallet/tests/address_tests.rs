//! Address tests

use bitcoin_hashes::{hash160, Hash};
use key_wallet::address::{Address, AddressGenerator, AddressType};
use key_wallet::derivation::HDWallet;
use key_wallet::Network;
use secp256k1::{PublicKey, Secp256k1};

#[test]
fn test_p2pkh_address_creation() {
    let secp = Secp256k1::new();

    // Create a public key
    let secret_key = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    // Create P2PKH address
    let address = Address::p2pkh(&public_key, Network::Dash);

    assert_eq!(address.network, Network::Dash);
    assert_eq!(address.address_type, AddressType::P2PKH);

    // Check that it generates a valid Dash address (starts with 'X')
    let addr_str = address.to_string();
    // Address starts with 'X' for mainnet
    assert!(addr_str.starts_with('X'));
}

#[test]
fn test_testnet_address() {
    let secp = Secp256k1::new();

    // Create a public key
    let secret_key = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    // Create testnet P2PKH address
    let address = Address::p2pkh(&public_key, Network::Testnet);

    // Check that it generates a valid testnet address (starts with 'y')
    let addr_str = address.to_string();
    assert!(addr_str.starts_with('y'));
}

#[test]
fn test_p2sh_address_creation() {
    // Create a script hash
    let script_hash = hash160::Hash::hash(b"test script");

    // Create P2SH address
    let address = Address::p2sh(script_hash, Network::Dash);

    assert_eq!(address.network, Network::Dash);
    assert_eq!(address.address_type, AddressType::P2SH);

    // Check that it generates a valid P2SH address (starts with '7')
    let addr_str = address.to_string();
    assert!(addr_str.starts_with('7'));
}

#[test]
fn test_address_parsing() {
    // Test mainnet P2PKH
    let addr_str = "XmnGSJav3CWVmzDv5U68k7XT9rRPqyavtE";
    let address = Address::from_string(addr_str).unwrap();

    assert_eq!(address.network, Network::Dash);
    assert_eq!(address.address_type, AddressType::P2PKH);
    assert_eq!(address.to_string(), addr_str);
}

#[test]
fn test_address_script_pubkey() {
    let secp = Secp256k1::new();

    // Create a public key
    let secret_key = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    // Create P2PKH address
    let address = Address::p2pkh(&public_key, Network::Dash);
    let script_pubkey = address.script_pubkey();

    // P2PKH script should be 25 bytes
    assert_eq!(script_pubkey.len(), 25);

    // Check script structure
    assert_eq!(script_pubkey[0], 0x76); // OP_DUP
    assert_eq!(script_pubkey[1], 0xa9); // OP_HASH160
    assert_eq!(script_pubkey[2], 0x14); // Push 20 bytes
    assert_eq!(script_pubkey[23], 0x88); // OP_EQUALVERIFY
    assert_eq!(script_pubkey[24], 0xac); // OP_CHECKSIG
}

#[test]
fn test_address_generator() {
    let seed = [0u8; 64];
    let wallet = HDWallet::from_seed(&seed, Network::Dash).unwrap();

    // Get account public key
    let _account = wallet.bip44_account(0).unwrap();
    let path = key_wallet::DerivationPath::from(vec![
        key_wallet::ChildNumber::from_hardened_idx(44).unwrap(),
        key_wallet::ChildNumber::from_hardened_idx(5).unwrap(),
        key_wallet::ChildNumber::from_hardened_idx(0).unwrap(),
    ]);
    let account_xpub = wallet.derive_pub(&path).unwrap();

    // Create address generator
    let generator = AddressGenerator::new(Network::Dash);

    // Generate single address
    let address = generator.generate_p2pkh(&account_xpub);
    assert_eq!(address.network, Network::Dash);
    assert_eq!(address.address_type, AddressType::P2PKH);
}

#[test]
fn test_address_range_generation() {
    let seed = [0u8; 64];
    let wallet = HDWallet::from_seed(&seed, Network::Dash).unwrap();

    // Get account public key
    let account = wallet.bip44_account(0).unwrap();
    let secp = Secp256k1::new();
    let account_xpub = key_wallet::ExtendedPubKey::from_priv(&secp, &account);

    // Create address generator
    let generator = AddressGenerator::new(Network::Dash);

    // Generate range of external addresses
    let addresses = generator.generate_range(&account_xpub, true, 0, 5).unwrap();
    assert_eq!(addresses.len(), 5);

    // All addresses should be different
    let addr_strings: Vec<_> = addresses.iter().map(|a| a.to_string()).collect();
    let unique_count = addr_strings.iter().collect::<std::collections::HashSet<_>>().len();
    assert_eq!(unique_count, 5);
}
