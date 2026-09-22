//! BIP32 tests

use key_wallet::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey, Network};
use std::str::FromStr;

#[test]
fn test_extended_key_derivation() {
    // Test vector from BIP32
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::new_master(Network::Mainnet, &seed).unwrap();

    // m/0'
    let child = master.ckd_priv(ChildNumber::from_hardened_idx(0).unwrap()).unwrap();
    assert_eq!(child.depth, 1);

    // m/0'/1
    let path = DerivationPath::from_str("m/0'/1").unwrap();
    let derived = master.derive_priv(&path).unwrap();
    assert_eq!(derived.depth, 2);
}

#[test]
fn test_derivation_path_parsing() {
    // Valid paths
    assert!(DerivationPath::from_str("m").is_ok());
    assert!(DerivationPath::from_str("m/0").is_ok());
    assert!(DerivationPath::from_str("m/0'").is_ok());
    assert!(DerivationPath::from_str("m/44'/5'/0'/0/0").is_ok());

    // Invalid paths
    assert!(DerivationPath::from_str("").is_err());
    assert!(DerivationPath::from_str("n/0").is_err());
    assert!(DerivationPath::from_str("m/").is_err());
}

#[test]
fn test_extended_key_serialization() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::new_master(Network::Mainnet, &seed).unwrap();

    // Serialize and deserialize
    let serialized = master.to_string();
    let deserialized = ExtendedPrivKey::from_str(&serialized).unwrap();

    assert_eq!(master.network, deserialized.network);
    assert_eq!(master.depth, deserialized.depth);
    assert_eq!(master.parent_fingerprint, deserialized.parent_fingerprint);
    assert_eq!(master.child_number, deserialized.child_number);
    assert_eq!(master.chain_code, deserialized.chain_code);
    assert_eq!(master.private_key, deserialized.private_key);
}

#[test]
fn test_public_key_derivation() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::new_master(Network::Mainnet, &seed).unwrap();
    let master_pub = ExtendedPubKey::from_priv(&master);

    // Can derive non-hardened child from public key
    let child_pub = master_pub.ckd_pub(ChildNumber::from_normal_idx(0).unwrap()).unwrap();

    // Should match derivation from private key
    let child_priv = master.ckd_priv(ChildNumber::from_normal_idx(0).unwrap()).unwrap();
    let child_pub_from_priv = ExtendedPubKey::from_priv(&child_priv);

    assert_eq!(child_pub.public_key, child_pub_from_priv.public_key);
}

#[test]
fn test_fingerprint_calculation() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::new_master(Network::Mainnet, &seed).unwrap();

    let child = master.ckd_priv(ChildNumber::from_normal_idx(0).unwrap()).unwrap();
    let master_fingerprint = master.fingerprint();

    assert_eq!(child.parent_fingerprint, master_fingerprint);
}
