//! Comprehensive tests for wallet functionality
//!
//! Tests wallet creation, initialization, recovery, and management.

use crate::account::{AccountType, StandardAccountType};
use crate::mnemonic::{Language, Mnemonic};
use crate::seed::Seed;
use crate::wallet::root_extended_keys::RootExtendedPrivKey;
use crate::wallet::{Wallet, WalletType};
use crate::Network;
use alloc::collections::BTreeMap;
use alloc::string::ToString;

/// Known test mnemonic for deterministic testing
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn test_wallet_creation_random() {
    let wallet = Wallet::new_random(
        &[Network::Testnet],
        crate::wallet::initialization::WalletAccountCreationOptions::Default,
    )
    .unwrap();

    // Verify wallet was created with mnemonic
    assert!(wallet.has_mnemonic());
    assert!(!wallet.is_watch_only());
    assert!(wallet.can_sign());

    // Verify default accounts were created (BIP44, CoinJoin, and special purpose)
    assert!(wallet.accounts.get(&Network::Testnet).unwrap().count() >= 2);

    // Verify wallet ID is set
    assert_ne!(wallet.wallet_id, [0u8; 32]);
}

#[test]
fn test_wallet_creation_from_mnemonic() {
    let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();

    let wallet = Wallet::from_mnemonic(
        mnemonic.clone(),
        &[Network::Testnet],
        crate::wallet::initialization::WalletAccountCreationOptions::Default,
    )
    .unwrap();

    // Verify wallet properties
    assert!(wallet.has_mnemonic());
    assert!(!wallet.is_watch_only());
    assert!(wallet.can_sign());

    // Verify we can recover the mnemonic
    match &wallet.wallet_type {
        WalletType::Mnemonic {
            mnemonic: wallet_mnemonic,
            ..
        } => {
            assert_eq!(wallet_mnemonic.to_string(), mnemonic.to_string());
        }
        _ => panic!("Expected mnemonic wallet type"),
    }
}

#[test]
fn test_wallet_creation_from_seed() {
    let seed = Seed::new([0x42; 64]);

    let wallet = Wallet::from_seed(
        seed.clone(),
        &[Network::Testnet],
        crate::wallet::initialization::WalletAccountCreationOptions::Default,
    )
    .unwrap();

    // Verify wallet properties
    assert!(wallet.has_seed());
    assert!(!wallet.has_mnemonic());
    assert!(!wallet.is_watch_only());
    assert!(wallet.can_sign());

    // Verify seed is stored
    match &wallet.wallet_type {
        WalletType::Seed {
            seed: wallet_seed,
            ..
        } => {
            assert_eq!(wallet_seed.as_bytes(), seed.as_bytes());
        }
        _ => panic!("Expected seed wallet type"),
    }
}

#[test]
fn test_wallet_creation_from_extended_key() {
    let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();
    let seed = mnemonic.to_seed("");
    let root_key = RootExtendedPrivKey::new_master(&seed).unwrap();
    let master_key = root_key.to_extended_priv_key(Network::Testnet);

    let wallet = Wallet::from_extended_key(
        master_key.clone(),
        &[Network::Testnet],
        crate::wallet::initialization::WalletAccountCreationOptions::Default,
    )
    .unwrap();

    // Verify wallet properties
    assert!(!wallet.has_mnemonic());
    assert!(!wallet.has_seed());
    assert!(!wallet.is_watch_only());
    assert!(wallet.can_sign());

    // Verify extended key is stored
    match &wallet.wallet_type {
        WalletType::ExtendedPrivKey(wallet_key) => {
            assert_eq!(wallet_key.root_private_key, master_key.private_key);
        }
        _ => panic!("Expected extended private key wallet type"),
    }
}

#[test]
fn test_wallet_creation_watch_only() {
    // First create a normal wallet to get the public key
    let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();
    let seed = mnemonic.to_seed("");
    let root_priv_key = RootExtendedPrivKey::new_master(&seed).unwrap();
    let root_pub_key = root_priv_key.to_root_extended_pub_key();
    let master_xpub = root_pub_key.to_extended_pub_key(Network::Testnet);

    let wallet = Wallet::from_xpub(master_xpub, BTreeMap::new(), false).unwrap();

    // Verify wallet properties
    assert!(wallet.is_watch_only());
    assert!(!wallet.can_sign());
    assert!(!wallet.has_mnemonic());
    assert!(!wallet.is_external_signable());

    // Verify public key is stored
    match &wallet.wallet_type {
        WalletType::WatchOnly(_) => {
            // Check that it's a watch-only wallet type
            assert!(wallet.is_watch_only());
        }
        _ => panic!("Expected watch-only wallet type"),
    }
}

#[test]
fn test_wallet_creation_with_passphrase() {
    let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();
    let passphrase = "test_passphrase";
    let seed = mnemonic.to_seed(passphrase);
    let root_priv_key = RootExtendedPrivKey::new_master(&seed).unwrap();
    let root_pub_key = root_priv_key.to_root_extended_pub_key();

    let wallet = Wallet::from_mnemonic_with_passphrase(
        mnemonic.clone(),
        passphrase.to_string(),
        &[Network::Testnet],
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    // Verify wallet properties
    assert!(wallet.has_mnemonic());
    assert!(wallet.needs_passphrase());
    assert!(wallet.can_sign()); // Can sign but needs passphrase
    assert!(!wallet.is_watch_only());

    // Verify mnemonic and public key are stored
    match &wallet.wallet_type {
        WalletType::MnemonicWithPassphrase {
            mnemonic: wallet_mnemonic,
            root_extended_public_key,
        } => {
            assert_eq!(wallet_mnemonic.to_string(), mnemonic.to_string());
            assert_eq!(root_extended_public_key.root_public_key, root_pub_key.root_public_key);
        }
        _ => panic!("Expected mnemonic with passphrase wallet type"),
    }
}

#[test]
fn test_wallet_id_computation() {
    let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();
    let seed = mnemonic.to_seed("");
    let root_priv_key = RootExtendedPrivKey::new_master(&seed).unwrap();
    let root_pub_key = root_priv_key.to_root_extended_pub_key();

    let wallet_id = Wallet::compute_wallet_id_from_root_extended_pub_key(&root_pub_key);

    // Wallet ID should be deterministic
    let wallet_id_2 = Wallet::compute_wallet_id_from_root_extended_pub_key(&root_pub_key);
    assert_eq!(wallet_id, wallet_id_2);

    // Create wallet and verify ID matches

    let wallet = Wallet::from_mnemonic(
        mnemonic,
        &[Network::Testnet],
        crate::wallet::initialization::WalletAccountCreationOptions::Default,
    )
    .unwrap();
    assert_eq!(wallet.wallet_id, wallet_id);
}

#[test]
fn test_wallet_recovery_same_mnemonic() {
    let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();

    // Create two wallets from the same mnemonic
    let wallet1 = Wallet::from_mnemonic(
        mnemonic.clone(),
        &[Network::Testnet],
        crate::wallet::initialization::WalletAccountCreationOptions::Default,
    )
    .unwrap();
    let wallet2 = Wallet::from_mnemonic(
        mnemonic,
        &[Network::Testnet],
        crate::wallet::initialization::WalletAccountCreationOptions::Default,
    )
    .unwrap();

    // Both wallets should have the same ID
    assert_eq!(wallet1.wallet_id, wallet2.wallet_id);

    // Both should generate the same addresses
    let account1 = wallet1
        .accounts
        .get(&Network::Testnet)
        .and_then(|c| c.standard_bip44_accounts.get(&0))
        .unwrap();
    let account2 = wallet2
        .accounts
        .get(&Network::Testnet)
        .and_then(|c| c.standard_bip44_accounts.get(&0))
        .unwrap();

    assert_eq!(account1.extended_public_key(), account2.extended_public_key());
}

#[test]
fn test_wallet_multiple_networks() {
    let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();

    // Create wallet with Testnet account
    let mut wallet = Wallet::from_mnemonic(
        mnemonic,
        &[Network::Testnet],
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    // Add Testnet account 0
    wallet
        .add_account(
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            Network::Testnet,
            None,
        )
        .unwrap();

    // Add Mainnet account
    wallet
        .add_account(
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            Network::Dash,
            None,
        )
        .unwrap();

    // Verify accounts exist for both networks
    assert!(wallet.accounts.get(&Network::Testnet).is_some());
    assert!(wallet.accounts.get(&Network::Dash).is_some());
}

#[test]
fn test_wallet_account_addition() {
    let mut wallet = Wallet::new_random(
        &[Network::Testnet],
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    // Add account 0 first
    wallet
        .add_account(
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            Network::Testnet,
            None,
        )
        .unwrap();

    // Add multiple accounts
    for i in 1..5 {
        wallet
            .add_account(
                AccountType::Standard {
                    index: i,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                Network::Testnet,
                None,
            )
            .unwrap();
    }

    // Verify all accounts were added
    let collection = wallet.accounts.get(&Network::Testnet).unwrap();
    assert_eq!(collection.standard_bip44_accounts.len(), 5); // 0-4
}

#[test]
fn test_wallet_duplicate_account_error() {
    let mut wallet = Wallet::new_random(
        &[Network::Testnet],
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    // Add account 0 first
    wallet
        .add_account(
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            Network::Testnet,
            None,
        )
        .unwrap();

    // Try to add the same account twice
    let result = wallet.add_account(
        AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP44Account,
        },
        Network::Testnet,
        None,
    );

    assert!(result.is_err());
}

#[test]
fn test_wallet_to_watch_only() {
    let wallet = Wallet::new_random(
        &[Network::Testnet],
        crate::wallet::initialization::WalletAccountCreationOptions::Default,
    )
    .unwrap();

    // Convert to watch-only
    let watch_only = wallet.to_watch_only();

    assert!(watch_only.is_watch_only());
    assert!(!watch_only.can_sign());

    // Wallet ID should remain the same
    assert_eq!(wallet.wallet_id, watch_only.wallet_id);
}

#[test]
fn test_wallet_special_accounts() {
    let mut wallet = Wallet::new_random(
        &[Network::Testnet],
        crate::wallet::initialization::WalletAccountCreationOptions::Default,
    )
    .unwrap();

    // Default already creates special accounts, just add identity top-up for registration 0
    wallet
        .add_account(
            AccountType::IdentityTopUp {
                registration_index: 0,
            },
            Network::Testnet,
            None,
        )
        .unwrap();

    let collection = wallet.accounts.get(&Network::Testnet).unwrap();
    assert!(collection.identity_registration.is_some());
    assert!(collection.identity_topup.contains_key(&0));
    assert!(collection.provider_voting_keys.is_some());
}

#[test]
fn test_wallet_deterministic_key_derivation() {
    let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();

    let wallet = Wallet::from_mnemonic(
        mnemonic,
        &[Network::Testnet],
        crate::wallet::initialization::WalletAccountCreationOptions::Default,
    )
    .unwrap();

    // Add same account multiple times to different wallets
    for _ in 0..3 {
        let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();

        let mut test_wallet = Wallet::from_mnemonic(
            mnemonic,
            &[Network::Testnet],
            crate::wallet::initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        test_wallet
            .add_account(
                AccountType::Standard {
                    index: 1,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                Network::Testnet,
                None,
            )
            .unwrap();

        // Verify keys match
        let account1 = wallet
            .accounts
            .get(&Network::Testnet)
            .and_then(|c| c.standard_bip44_accounts.get(&0))
            .unwrap();
        let account2 = test_wallet
            .accounts
            .get(&Network::Testnet)
            .and_then(|c| c.standard_bip44_accounts.get(&0))
            .unwrap();

        assert_eq!(account1.extended_public_key(), account2.extended_public_key());
    }
}

#[test]
fn test_wallet_external_signable() {
    let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();
    let seed = mnemonic.to_seed("");
    let root_priv_key = RootExtendedPrivKey::new_master(&seed).unwrap();
    let root_pub_key = root_priv_key.to_root_extended_pub_key();

    // Convert root public key to extended public key for the network
    let xpub = root_pub_key.to_extended_pub_key(Network::Testnet);
    let wallet = Wallet::from_external_signable(
        xpub,
        BTreeMap::new(), // Empty accounts for external signable wallet
    )
    .unwrap();

    assert!(wallet.is_external_signable());
    assert!(wallet.can_sign()); // Can sign with external signer
    assert!(!wallet.is_watch_only()); // Not purely watch-only

    match &wallet.wallet_type {
        WalletType::ExternalSignable(key) => {
            assert_eq!(key.root_public_key, root_pub_key.root_public_key);
        }
        _ => panic!("Expected external signable wallet type"),
    }
}
