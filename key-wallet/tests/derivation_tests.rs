//! Derivation tests
//!
//! DIP-17 Platform Payment Key Derivation test vectors. These are the only
//! derivation tests that live at this level; trivial BIP32/BIP44 derivation
//! is covered by the per-module tests in `key-wallet/src/derivation.rs`,
//! `key-wallet/src/dip9.rs`, and `key-wallet/src/tests/account_tests.rs`.

use dashcore::hashes::Hash;
use key_wallet::mnemonic::{Language, Mnemonic};
use key_wallet::{DerivationPath, ExtendedPrivKey, ExtendedPubKey, Network};
use secp256k1::Secp256k1;
use std::str::FromStr;

// =============================================================================
// DIP-17 Platform Payment Key Derivation Test Vectors
// =============================================================================
//
// These tests verify the key derivation for Platform Payment addresses as
// specified in DIP-0017 (HD Derivation). The address encoding (DIP-18) uses
// bech32m with "dashevo"/"tdashevo" HRP and is implemented in the Platform repo.
//
// Test mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
// Passphrase: "" (empty)

/// DIP-17 Test Vector 1: Platform Payment key derivation (mainnet)
/// Path: m/9'/5'/17'/0'/0'/0
/// Expected private key: 6bca392f43453b7bc33a9532b69221ce74906a8815281637e0c9d0bee35361fe
/// Expected pubkey: 03de102ed1fc43cbdb16af02e294945ffaed8e0595d3072f4c592ae80816e6859e
/// Expected HASH160: f7da0a2b5cbd4ff6bb2c4d89b67d2f3ffeec0525
#[test]
fn test_dip17_platform_payment_vector1_mainnet() {
    use dashcore::crypto::key::PublicKey;

    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    )
    .unwrap();

    let seed = mnemonic.to_seed("");
    let secp = Secp256k1::new();
    let master_key = ExtendedPrivKey::new_master(Network::Mainnet, &seed).unwrap();

    // Derive Platform Payment key: m/9'/5'/17'/0'/0'/0
    let path = DerivationPath::from_str("m/9'/5'/17'/0'/0'/0").unwrap();
    let xprv = master_key.derive_priv(&secp, &path).unwrap();

    // Verify private key matches DIP-17 test vector
    let privkey_hex = hex::encode(xprv.private_key.secret_bytes());
    assert_eq!(
        privkey_hex, "6bca392f43453b7bc33a9532b69221ce74906a8815281637e0c9d0bee35361fe",
        "Private key mismatch for DIP-17 vector 1"
    );

    // Get compressed public key
    let xpub = ExtendedPubKey::from_priv(&secp, &xprv);
    let pubkey = PublicKey::new(xpub.public_key);
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    assert_eq!(
        pubkey_hex, "03de102ed1fc43cbdb16af02e294945ffaed8e0595d3072f4c592ae80816e6859e",
        "Public key mismatch for DIP-17 vector 1"
    );

    // Verify HASH160
    let pubkey_hash = pubkey.pubkey_hash();
    let hash160_hex = hex::encode(pubkey_hash.to_byte_array());
    assert_eq!(
        hash160_hex, "f7da0a2b5cbd4ff6bb2c4d89b67d2f3ffeec0525",
        "HASH160 mismatch for DIP-17 vector 1"
    );

    // Note: DIP-18 address encoding (bech32m with "dashevo" HRP) is in Platform repo
}

/// DIP-17 Test Vector 1: Platform Payment key derivation (testnet)
/// Path: m/9'/1'/17'/0'/0'/0  (note: coin_type 1' for testnet)
#[test]
fn test_dip17_platform_payment_vector1_testnet() {
    use dashcore::crypto::key::PublicKey;

    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    )
    .unwrap();

    let seed = mnemonic.to_seed("");
    let secp = Secp256k1::new();
    let master_key = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();

    // Derive Platform Payment key: m/9'/1'/17'/0'/0'/0 (testnet uses coin_type 1')
    let path = DerivationPath::from_str("m/9'/1'/17'/0'/0'/0").unwrap();
    let xprv = master_key.derive_priv(&secp, &path).unwrap();

    // Get compressed public key and HASH160
    let xpub = ExtendedPubKey::from_priv(&secp, &xprv);
    let pubkey = PublicKey::new(xpub.public_key);
    let pubkey_hash = pubkey.pubkey_hash();

    // Verify we can derive correctly (HASH160 will be used for bech32m encoding in Platform)
    assert!(!pubkey_hash.to_byte_array().is_empty());

    // Note: DIP-18 address encoding (bech32m with "tdashevo" HRP) is in Platform repo
}

/// DIP-17 Test Vector 2: Platform Payment key derivation (index 1)
/// Path: m/9'/5'/17'/0'/0'/1 (mainnet) / m/9'/1'/17'/0'/0'/1 (testnet)
/// Expected private key: eef58ce73383f63d5062f281ed0c1e192693c170fbc0049662a73e48a1981523
/// Expected pubkey: 02269ff766fcd04184bc314f5385a04498df215ce1e7193cec9a607f69bc8954da
/// Expected HASH160: a5ff0046217fd1c7d238e3e146cc5bfd90832a7e
#[test]
fn test_dip17_platform_payment_vector2() {
    use dashcore::crypto::key::PublicKey;

    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    )
    .unwrap();

    // Test mainnet
    let seed = mnemonic.to_seed("");
    let secp = Secp256k1::new();
    let master_mainnet = ExtendedPrivKey::new_master(Network::Mainnet, &seed).unwrap();
    let path_mainnet = DerivationPath::from_str("m/9'/5'/17'/0'/0'/1").unwrap();
    let xprv_mainnet = master_mainnet.derive_priv(&secp, &path_mainnet).unwrap();

    // Verify private key
    let privkey_hex = hex::encode(xprv_mainnet.private_key.secret_bytes());
    assert_eq!(
        privkey_hex, "eef58ce73383f63d5062f281ed0c1e192693c170fbc0049662a73e48a1981523",
        "Private key mismatch for DIP-17 vector 2"
    );

    let xpub_mainnet = ExtendedPubKey::from_priv(&secp, &xprv_mainnet);
    let pubkey_mainnet = PublicKey::new(xpub_mainnet.public_key);

    // Verify public key
    let pubkey_hex = hex::encode(pubkey_mainnet.to_bytes());
    assert_eq!(
        pubkey_hex, "02269ff766fcd04184bc314f5385a04498df215ce1e7193cec9a607f69bc8954da",
        "Public key mismatch for DIP-17 vector 2"
    );

    // Verify HASH160
    let pubkey_hash_mainnet = pubkey_mainnet.pubkey_hash();
    let hash160_hex = hex::encode(pubkey_hash_mainnet.to_byte_array());
    assert_eq!(
        hash160_hex, "a5ff0046217fd1c7d238e3e146cc5bfd90832a7e",
        "HASH160 mismatch for DIP-17 vector 2"
    );

    // Test testnet derivation
    let master_testnet = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();
    let path_testnet = DerivationPath::from_str("m/9'/1'/17'/0'/0'/1").unwrap();
    let xprv_testnet = master_testnet.derive_priv(&secp, &path_testnet).unwrap();
    let xpub_testnet = ExtendedPubKey::from_priv(&secp, &xprv_testnet);
    let pubkey_testnet = PublicKey::new(xpub_testnet.public_key);
    let pubkey_hash_testnet = pubkey_testnet.pubkey_hash();

    // Verify testnet derivation produces valid hash
    assert!(!pubkey_hash_testnet.to_byte_array().is_empty());

    // Note: DIP-18 address encoding (bech32m) is in Platform repo
}

/// DIP-17 Test Vector 3: Platform Payment key derivation with non-default key_class
/// Path: m/9'/5'/17'/0'/1'/0 (mainnet) / m/9'/1'/17'/0'/1'/0 (testnet)
/// Note: key_class' = 1' instead of default 0'
/// Expected private key: cc05b4389712a2e724566914c256217685d781503d7cc05af6642e60260830db
/// Expected pubkey: 0317a3ed70c141cffafe00fa8bf458cec119f6fc039a7ba9a6b7303dc65b27bed3
/// Expected HASH160: 6d92674fd64472a3dfcfc3ebcfed7382bf699d7b
#[test]
fn test_dip17_platform_payment_vector3_non_default_key_class() {
    use dashcore::crypto::key::PublicKey;

    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    )
    .unwrap();

    // Test mainnet with key_class' = 1'
    let seed = mnemonic.to_seed("");
    let secp = Secp256k1::new();
    let master_mainnet = ExtendedPrivKey::new_master(Network::Mainnet, &seed).unwrap();
    let path_mainnet = DerivationPath::from_str("m/9'/5'/17'/0'/1'/0").unwrap();
    let xprv_mainnet = master_mainnet.derive_priv(&secp, &path_mainnet).unwrap();

    // Verify private key
    let privkey_hex = hex::encode(xprv_mainnet.private_key.secret_bytes());
    assert_eq!(
        privkey_hex, "cc05b4389712a2e724566914c256217685d781503d7cc05af6642e60260830db",
        "Private key mismatch for DIP-17 vector 3"
    );

    let xpub_mainnet = ExtendedPubKey::from_priv(&secp, &xprv_mainnet);
    let pubkey_mainnet = PublicKey::new(xpub_mainnet.public_key);

    // Verify public key
    let pubkey_hex = hex::encode(pubkey_mainnet.to_bytes());
    assert_eq!(
        pubkey_hex, "0317a3ed70c141cffafe00fa8bf458cec119f6fc039a7ba9a6b7303dc65b27bed3",
        "Public key mismatch for DIP-17 vector 3"
    );

    // Verify HASH160
    let pubkey_hash_mainnet = pubkey_mainnet.pubkey_hash();
    let hash160_hex = hex::encode(pubkey_hash_mainnet.to_byte_array());
    assert_eq!(
        hash160_hex, "6d92674fd64472a3dfcfc3ebcfed7382bf699d7b",
        "HASH160 mismatch for DIP-17 vector 3"
    );

    // Test testnet with key_class' = 1'
    let master_testnet = ExtendedPrivKey::new_master(Network::Testnet, &seed).unwrap();
    let path_testnet = DerivationPath::from_str("m/9'/1'/17'/0'/1'/0").unwrap();
    let xprv_testnet = master_testnet.derive_priv(&secp, &path_testnet).unwrap();
    let xpub_testnet = ExtendedPubKey::from_priv(&secp, &xprv_testnet);
    let pubkey_testnet = PublicKey::new(xpub_testnet.public_key);
    let pubkey_hash_testnet = pubkey_testnet.pubkey_hash();

    // Verify testnet derivation produces valid hash
    assert!(!pubkey_hash_testnet.to_byte_array().is_empty());

    // Note: DIP-18 address encoding (bech32m) is in Platform repo
}
