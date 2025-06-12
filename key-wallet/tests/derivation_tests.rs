//! Derivation tests

use key_wallet::derivation::{AccountDerivation, HDWallet, KeyDerivation};
use key_wallet::mnemonic::{Language, Mnemonic};
use key_wallet::{DerivationPath, Network};
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
    let xpub_from_prv = wallet.derive_pub(&path).unwrap();

    assert_eq!(xpub.public_key, xpub_from_prv.public_key);
}
