//! Derivation tests

use dashcore::hashes::Hash;
use key_wallet::derivation::{AccountDerivation, HDWallet};
use key_wallet::mnemonic::{Language, Mnemonic};
use key_wallet::{DerivationPath, ExtendedPubKey, Network};
use secp256k1::Secp256k1;
use std::str::FromStr;

#[test]
fn test_hd_wallet_creation() {
    let seed = [0u8; 64];
    let wallet = HDWallet::from_seed(&seed, Network::Dash).unwrap();

    // Master key should be at depth 0
    assert_eq!(wallet.master_key().depth, 0);
}

#[test]
fn test_bip44_account_derivation() {
    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English
    ).unwrap();

    let seed = mnemonic.to_seed("");
    let wallet = HDWallet::from_seed(&seed, Network::Dash).unwrap();

    // Derive first account
    let account0 = wallet.bip44_account(0).unwrap();
    assert_eq!(account0.depth, 3); // m/44'/5'/0'

    // Derive second account
    let account1 = wallet.bip44_account(1).unwrap();
    assert_eq!(account1.depth, 3); // m/44'/5'/1'

    // Keys should be different
    assert_ne!(account0.private_key.secret_bytes(), account1.private_key.secret_bytes());
}

#[test]
fn test_coinjoin_account_derivation() {
    let seed = [0u8; 64];
    let wallet = HDWallet::from_seed(&seed, Network::Dash).unwrap();

    // Derive CoinJoin account
    let coinjoin_account = wallet.coinjoin_account(0).unwrap();
    assert_eq!(coinjoin_account.depth, 4); // m/9'/5'/4'/0'
}

#[test]
fn test_identity_key_derivation() {
    let seed = [0u8; 64];
    let wallet = HDWallet::from_seed(&seed, Network::Dash).unwrap();

    // Derive identity authentication key
    let identity_key = wallet.identity_authentication_key(0, 0).unwrap();
    assert_eq!(identity_key.depth, 6); // m/5'/5'/3'/0'/0'/0'
}

#[test]
fn test_custom_path_derivation() {
    let seed = [0u8; 64];
    let wallet = HDWallet::from_seed(&seed, Network::Dash).unwrap();

    // Derive custom path
    let path = DerivationPath::from_str("m/0/1/2").unwrap();
    let derived = wallet.derive(&path).unwrap();
    assert_eq!(derived.depth, 3);
}

#[test]
fn test_account_address_derivation() {
    let seed = [0u8; 64];
    let wallet = HDWallet::from_seed(&seed, Network::Dash).unwrap();

    // Get account
    let account = wallet.bip44_account(0).unwrap();
    let account_derivation = AccountDerivation::new(account);

    // Derive receive addresses
    let addr0 = account_derivation.receive_address(0).unwrap();
    let addr1 = account_derivation.receive_address(1).unwrap();

    // Addresses should be different
    assert_ne!(addr0.public_key, addr1.public_key);

    // Derive change addresses
    let change0 = account_derivation.change_address(0).unwrap();
    let change1 = account_derivation.change_address(1).unwrap();

    // Change addresses should be different from receive addresses
    assert_ne!(addr0.public_key, change0.public_key);
    assert_ne!(change0.public_key, change1.public_key);
}

#[test]
fn test_public_key_derivation() {
    let seed = [0u8; 64];
    let wallet = HDWallet::from_seed(&seed, Network::Dash).unwrap();

    // Derive public key directly
    let path = DerivationPath::from_str("m/44'/5'/0'/0/0").unwrap();
    let xpub = wallet.derive_pub(&path).unwrap();

    // Should match derivation from private key
    let xprv = wallet.derive(&path).unwrap();
    let secp = Secp256k1::new();
    let xpub_from_prv = ExtendedPubKey::from_priv(&secp, &xprv);

    assert_eq!(xpub.public_key, xpub_from_prv.public_key);
}

// =============================================================================
// DIP-17/DIP-18 Platform Payment Address Test Vectors
// =============================================================================
//
// These tests verify the complete derivation and encoding of Platform Payment
// addresses as specified in DIP-0017 (HD Derivation) and DIP-0018 (Address Encoding).
//
// Test mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
// Passphrase: "" (empty)

/// DIP-17 Test Vector 1: Platform Payment address derivation (mainnet)
/// Path: m/9'/5'/17'/0'/0'/0
/// Expected private key: 6bca392f43453b7bc33a9532b69221ce74906a8815281637e0c9d0bee35361fe
/// Expected pubkey: 03de102ed1fc43cbdb16af02e294945ffaed8e0595d3072f4c592ae80816e6859e
/// Expected HASH160: f7da0a2b5cbd4ff6bb2c4d89b67d2f3ffeec0525
/// Expected mainnet address (DIP-18): DTjceJiEqrNkCsSizK65fojEANTKoQMtsR
#[test]
fn test_dip17_platform_payment_vector1_mainnet() {
    use dashcore::address::{Address, Payload};
    use dashcore::crypto::key::PublicKey;

    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English
    ).unwrap();

    let seed = mnemonic.to_seed("");
    let wallet = HDWallet::from_seed(&seed, Network::Dash).unwrap();

    // Derive Platform Payment key: m/9'/5'/17'/0'/0'/0
    let path = DerivationPath::from_str("m/9'/5'/17'/0'/0'/0").unwrap();
    let xprv = wallet.derive(&path).unwrap();

    // Verify private key matches DIP-17 test vector
    let privkey_hex = hex::encode(xprv.private_key.secret_bytes());
    assert_eq!(
        privkey_hex, "6bca392f43453b7bc33a9532b69221ce74906a8815281637e0c9d0bee35361fe",
        "Private key mismatch for DIP-17 vector 1"
    );

    // Get compressed public key
    let secp = Secp256k1::new();
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

    // Create Platform P2PKH address and verify DIP-18 encoding
    let addr = Address::new(dashcore::Network::Dash, Payload::PlatformPubkeyHash(pubkey_hash));
    assert_eq!(
        addr.to_string(),
        "DTjceJiEqrNkCsSizK65fojEANTKoQMtsR",
        "DIP-18 mainnet address mismatch for vector 1"
    );
}

/// DIP-17 Test Vector 1: Platform Payment address derivation (testnet)
/// Path: m/9'/1'/17'/0'/0'/0  (note: coin_type 1' for testnet)
/// Expected testnet address (DIP-18): dSqV2orinasFpYAMGQTLy6uYpW9Dnge563
#[test]
fn test_dip17_platform_payment_vector1_testnet() {
    use dashcore::address::{Address, Payload};
    use dashcore::crypto::key::PublicKey;

    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English
    ).unwrap();

    let seed = mnemonic.to_seed("");
    let wallet = HDWallet::from_seed(&seed, Network::Testnet).unwrap();

    // Derive Platform Payment key: m/9'/1'/17'/0'/0'/0 (testnet uses coin_type 1')
    let path = DerivationPath::from_str("m/9'/1'/17'/0'/0'/0").unwrap();
    let xprv = wallet.derive(&path).unwrap();

    // Get compressed public key and HASH160
    let secp = Secp256k1::new();
    let xpub = ExtendedPubKey::from_priv(&secp, &xprv);
    let pubkey = PublicKey::new(xpub.public_key);
    let pubkey_hash = pubkey.pubkey_hash();

    // Create Platform P2PKH address and verify DIP-18 encoding
    let addr = Address::new(dashcore::Network::Testnet, Payload::PlatformPubkeyHash(pubkey_hash));
    assert_eq!(
        addr.to_string(),
        "dSqV2orinasFpYAMGQTLy6uYpW9Dnge563",
        "DIP-18 testnet address mismatch for vector 1"
    );
}

/// DIP-17 Test Vector 2: Platform Payment address (index 1)
/// Path: m/9'/5'/17'/0'/0'/1 (mainnet) / m/9'/1'/17'/0'/0'/1 (testnet)
/// Expected private key: eef58ce73383f63d5062f281ed0c1e192693c170fbc0049662a73e48a1981523
/// Expected pubkey: 02269ff766fcd04184bc314f5385a04498df215ce1e7193cec9a607f69bc8954da
/// Expected HASH160: a5ff0046217fd1c7d238e3e146cc5bfd90832a7e
/// Expected mainnet address: DLGoWhHfAyFcJafRgt2fFN7fxgLqNrfCXm
/// Expected testnet address: dZoepEc46ivSfm3VYr8mJeA4hZXYytgkKZ
#[test]
fn test_dip17_platform_payment_vector2() {
    use dashcore::address::{Address, Payload};
    use dashcore::crypto::key::PublicKey;

    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English
    ).unwrap();

    // Test mainnet
    let seed = mnemonic.to_seed("");
    let wallet_mainnet = HDWallet::from_seed(&seed, Network::Dash).unwrap();
    let path_mainnet = DerivationPath::from_str("m/9'/5'/17'/0'/0'/1").unwrap();
    let xprv_mainnet = wallet_mainnet.derive(&path_mainnet).unwrap();

    // Verify private key
    let privkey_hex = hex::encode(xprv_mainnet.private_key.secret_bytes());
    assert_eq!(
        privkey_hex, "eef58ce73383f63d5062f281ed0c1e192693c170fbc0049662a73e48a1981523",
        "Private key mismatch for DIP-17 vector 2"
    );

    let secp = Secp256k1::new();
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

    // Verify mainnet address
    let addr_mainnet =
        Address::new(dashcore::Network::Dash, Payload::PlatformPubkeyHash(pubkey_hash_mainnet));
    assert_eq!(
        addr_mainnet.to_string(),
        "DLGoWhHfAyFcJafRgt2fFN7fxgLqNrfCXm",
        "DIP-18 mainnet address mismatch for vector 2"
    );

    // Test testnet
    let wallet_testnet = HDWallet::from_seed(&seed, Network::Testnet).unwrap();
    let path_testnet = DerivationPath::from_str("m/9'/1'/17'/0'/0'/1").unwrap();
    let xprv_testnet = wallet_testnet.derive(&path_testnet).unwrap();
    let xpub_testnet = ExtendedPubKey::from_priv(&secp, &xprv_testnet);
    let pubkey_testnet = PublicKey::new(xpub_testnet.public_key);
    let pubkey_hash_testnet = pubkey_testnet.pubkey_hash();

    let addr_testnet =
        Address::new(dashcore::Network::Testnet, Payload::PlatformPubkeyHash(pubkey_hash_testnet));
    assert_eq!(
        addr_testnet.to_string(),
        "dZoepEc46ivSfm3VYr8mJeA4hZXYytgkKZ",
        "DIP-18 testnet address mismatch for vector 2"
    );
}

/// DIP-17 Test Vector 3: Platform Payment address with non-default key_class
/// Path: m/9'/5'/17'/0'/1'/0 (mainnet) / m/9'/1'/17'/0'/1'/0 (testnet)
/// Note: key_class' = 1' instead of default 0'
/// Expected private key: cc05b4389712a2e724566914c256217685d781503d7cc05af6642e60260830db
/// Expected pubkey: 0317a3ed70c141cffafe00fa8bf458cec119f6fc039a7ba9a6b7303dc65b27bed3
/// Expected HASH160: 6d92674fd64472a3dfcfc3ebcfed7382bf699d7b
/// Expected mainnet address: DF8TaTy7YrLdGYqq6cwapSUqdM3qJxLQbo
/// Expected testnet address: dFQSkGujaeDNwWTQDDVfbrurQ9ChXXYDov
#[test]
fn test_dip17_platform_payment_vector3_non_default_key_class() {
    use dashcore::address::{Address, Payload};
    use dashcore::crypto::key::PublicKey;

    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English
    ).unwrap();

    // Test mainnet with key_class' = 1'
    let seed = mnemonic.to_seed("");
    let wallet_mainnet = HDWallet::from_seed(&seed, Network::Dash).unwrap();
    let path_mainnet = DerivationPath::from_str("m/9'/5'/17'/0'/1'/0").unwrap();
    let xprv_mainnet = wallet_mainnet.derive(&path_mainnet).unwrap();

    // Verify private key
    let privkey_hex = hex::encode(xprv_mainnet.private_key.secret_bytes());
    assert_eq!(
        privkey_hex, "cc05b4389712a2e724566914c256217685d781503d7cc05af6642e60260830db",
        "Private key mismatch for DIP-17 vector 3"
    );

    let secp = Secp256k1::new();
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

    // Verify mainnet address
    let addr_mainnet =
        Address::new(dashcore::Network::Dash, Payload::PlatformPubkeyHash(pubkey_hash_mainnet));
    assert_eq!(
        addr_mainnet.to_string(),
        "DF8TaTy7YrLdGYqq6cwapSUqdM3qJxLQbo",
        "DIP-18 mainnet address mismatch for vector 3"
    );

    // Test testnet with key_class' = 1'
    let wallet_testnet = HDWallet::from_seed(&seed, Network::Testnet).unwrap();
    let path_testnet = DerivationPath::from_str("m/9'/1'/17'/0'/1'/0").unwrap();
    let xprv_testnet = wallet_testnet.derive(&path_testnet).unwrap();
    let xpub_testnet = ExtendedPubKey::from_priv(&secp, &xprv_testnet);
    let pubkey_testnet = PublicKey::new(xpub_testnet.public_key);
    let pubkey_hash_testnet = pubkey_testnet.pubkey_hash();

    let addr_testnet =
        Address::new(dashcore::Network::Testnet, Payload::PlatformPubkeyHash(pubkey_hash_testnet));
    assert_eq!(
        addr_testnet.to_string(),
        "dFQSkGujaeDNwWTQDDVfbrurQ9ChXXYDov",
        "DIP-18 testnet address mismatch for vector 3"
    );
}
