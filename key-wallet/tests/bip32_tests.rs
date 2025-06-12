//! BIP32 tests

use key_wallet::mnemonic::{Language, Mnemonic};
use key_wallet::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey, Network};
use secp256k1::Secp256k1;
use std::str::FromStr;

#[test]
fn test_extended_key_derivation() {
    let secp = Secp256k1::new();

    // Test vector from BIP32
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::new_master(Network::Dash, &seed).unwrap();

    // m/0'
    let child = master.ckd_priv(&secp, ChildNumber::from_hardened_idx(0).unwrap()).unwrap();
    assert_eq!(child.depth, 1);

    // m/0'/1
    let path = DerivationPath::from_str("m/0'/1").unwrap();
    let derived = master.derive_priv(&secp, &path).unwrap();
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
    let master = ExtendedPrivKey::new_master(Network::Dash, &seed).unwrap();

    // Serialize and deserialize
    let serialized = master.to_string();
    let deserialized = ExtendedPrivKey::from_str(&serialized).unwrap();

    assert_eq!(master.network, deserialized.network);
    assert_eq!(master.depth, deserialized.depth);
    assert_eq!(master.parent_fingerprint, deserialized.parent_fingerprint);
    assert_eq!(master.child_number, deserialized.child_number);
    assert_eq!(master.chain_code, deserialized.chain_code);
}

#[test]
fn test_public_key_derivation() {
    let secp = Secp256k1::new();
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::new_master(Network::Dash, &seed).unwrap();
    let master_pub = ExtendedPubKey::from_priv(&secp, &master);

    // Can derive non-hardened child from public key
    let child_pub = master_pub.ckd_pub(&secp, ChildNumber::from_normal_idx(0).unwrap()).unwrap();

    // Should match derivation from private key
    let child_priv = master.ckd_priv(&secp, ChildNumber::from_normal_idx(0).unwrap()).unwrap();
    let child_pub_from_priv = ExtendedPubKey::from_priv(&secp, &child_priv);

    assert_eq!(child_pub.public_key, child_pub_from_priv.public_key);
}

#[test]
fn test_fingerprint_calculation() {
    let secp = Secp256k1::new();
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = ExtendedPrivKey::new_master(Network::Dash, &seed).unwrap();

    let child = master.ckd_priv(&secp, ChildNumber::from_normal_idx(0).unwrap()).unwrap();
    let master_fingerprint = master.fingerprint(&secp);

    assert_eq!(child.parent_fingerprint, master_fingerprint);
}
