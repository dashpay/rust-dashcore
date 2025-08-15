//! Address tests

use core::str::FromStr;
use dashcore::{Address, AddressType, Network as DashNetwork, ScriptBuf};
use secp256k1::{PublicKey, Secp256k1};

#[test]
fn test_p2pkh_address_creation() {
    let secp = Secp256k1::new();

    // Create a public key
    let secret_key = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let dash_pubkey = dashcore::PublicKey::new(public_key);

    // Create P2PKH address
    let address = Address::p2pkh(&dash_pubkey, DashNetwork::Dash);

    assert_eq!(*address.network(), DashNetwork::Dash);
    assert_eq!(address.address_type(), Some(AddressType::P2pkh));

    // Check that it generates a valid Dash address (starts with 'X')
    let addr_str = address.to_string();
    // Address starts with 'X' for mainnet
    assert!(addr_str.starts_with('X'));
}

#[test]
fn test_p2sh_address_creation() {
    // Create a simple script
    let script = ScriptBuf::from_hex("76a914").unwrap();

    // Create P2SH address
    let address = Address::p2sh(&script, DashNetwork::Dash).unwrap();

    assert_eq!(*address.network(), DashNetwork::Dash);
    assert_eq!(address.address_type(), Some(AddressType::P2sh));

    // Check that it generates a valid Dash P2SH address (starts with '7')
    let addr_str = address.to_string();
    assert!(addr_str.starts_with('7'));
}

#[test]
fn test_testnet_address() {
    let secp = Secp256k1::new();

    // Create a public key
    let secret_key = secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let dash_pubkey = dashcore::PublicKey::new(public_key);

    // Create testnet P2PKH address
    let address = Address::p2pkh(&dash_pubkey, DashNetwork::Testnet);

    assert_eq!(*address.network(), DashNetwork::Testnet);
    assert_eq!(address.address_type(), Some(AddressType::P2pkh));

    // Check that it generates a valid testnet address (starts with 'y')
    let addr_str = address.to_string();
    assert!(addr_str.starts_with('y'));
}

#[test]
fn test_address_parsing() {
    // Instead of parsing potentially invalid addresses, let's create valid ones and test round-trip
    use dashcore::key::PrivateKey;
    use dashcore::secp256k1::Secp256k1;

    let secp = Secp256k1::new();

    // Create a mainnet address
    let privkey_mainnet = PrivateKey {
        compressed: true,
        network: DashNetwork::Dash,
        inner: dashcore::secp256k1::SecretKey::from_slice(&[0x01; 32]).unwrap(),
    };
    let pubkey_mainnet = privkey_mainnet.public_key(&secp);
    let mainnet_address = Address::p2pkh(&pubkey_mainnet, DashNetwork::Dash);

    // Test round-trip for mainnet
    let mainnet_str = mainnet_address.to_string();
    assert!(mainnet_str.starts_with('X')); // Dash mainnet addresses start with 'X'

    let parsed_mainnet =
        Address::<dashcore::address::NetworkUnchecked>::from_str(&mainnet_str).unwrap();
    let checked_mainnet = parsed_mainnet.require_network(DashNetwork::Dash).unwrap();
    assert_eq!(*checked_mainnet.network(), DashNetwork::Dash);
    assert_eq!(checked_mainnet.address_type(), Some(AddressType::P2pkh));

    // Create a testnet address
    let privkey_testnet = PrivateKey {
        compressed: true,
        network: DashNetwork::Testnet,
        inner: dashcore::secp256k1::SecretKey::from_slice(&[0x02; 32]).unwrap(),
    };
    let pubkey_testnet = privkey_testnet.public_key(&secp);
    let testnet_address = Address::p2pkh(&pubkey_testnet, DashNetwork::Testnet);

    // Test round-trip for testnet
    let testnet_str = testnet_address.to_string();
    assert!(testnet_str.starts_with('y')); // Dash testnet addresses start with 'y'

    let parsed_testnet =
        Address::<dashcore::address::NetworkUnchecked>::from_str(&testnet_str).unwrap();
    let checked_testnet = parsed_testnet.require_network(DashNetwork::Testnet).unwrap();
    assert_eq!(*checked_testnet.network(), DashNetwork::Testnet);
    assert_eq!(checked_testnet.address_type(), Some(AddressType::P2pkh));
}

#[test]
fn test_address_roundtrip() {
    let secp = Secp256k1::new();

    // Create a public key
    let secret_key = secp256k1::SecretKey::from_slice(&[3u8; 32]).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let dash_pubkey = dashcore::PublicKey::new(public_key);

    // Create address
    let address = Address::p2pkh(&dash_pubkey, DashNetwork::Dash);
    let addr_str = address.to_string();

    // Parse it back
    let parsed = Address::<dashcore::address::NetworkUnchecked>::from_str(&addr_str).unwrap();
    let checked = parsed.require_network(DashNetwork::Dash).unwrap();

    // Compare
    assert_eq!(address, checked);
}
