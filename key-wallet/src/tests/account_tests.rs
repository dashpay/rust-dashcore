//! Comprehensive tests for account management
//!
//! Tests all account types and their operations.

use crate::account::{Account, AccountType, StandardAccountType};
use crate::bip32::{ExtendedPrivKey, ExtendedPubKey};
use crate::derivation::HDWallet;
use crate::error::Result;
use crate::mnemonic::{Language, Mnemonic};
use crate::Network;
use dashcore::hashes::{sha256, Hash};
use secp256k1::Secp256k1;

/// Helper function to create a test wallet with deterministic mnemonic
fn create_test_mnemonic() -> Mnemonic {
    Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    ).unwrap()
}

/// Helper function to create a test extended private key
fn create_test_extended_priv_key(network: Network) -> ExtendedPrivKey {
    let mnemonic = create_test_mnemonic();
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivKey::new_master(network.into(), &seed).unwrap();
    master
}

#[test]
fn test_bip44_account_creation() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let hd_wallet = HDWallet::new(master);

    // Create multiple BIP44 accounts with different indices
    for index in 0..10 {
        let account_type = AccountType::Standard {
            index,
            standard_account_type: StandardAccountType::BIP44Account,
        };

        let derivation_path = account_type.derivation_path(network).unwrap();
        let account_key = hd_wallet.derive(&derivation_path).unwrap();

        let account = Account::from_xpriv(
            Some([0u8; 32]), // wallet_id
            account_type.clone(),
            account_key,
            network,
        )
        .unwrap();

        // Verify account properties
        match &account.account_type {
            AccountType::Standard {
                index: acc_index,
                standard_account_type,
            } => {
                assert_eq!(*acc_index, index);
                assert_eq!(*standard_account_type, StandardAccountType::BIP44Account);
            }
            _ => panic!("Expected Standard account type"),
        }

        // Verify derivation path follows BIP44 standard: m/44'/1'/index'/0 (testnet)
        assert_eq!(derivation_path.to_string(), format!("m/44'/1'/{}'", index));
    }
}

#[test]
fn test_bip32_account_creation() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let hd_wallet = HDWallet::new(master);

    // Create multiple BIP32 accounts with different indices
    for index in 0..5 {
        let account_type = AccountType::Standard {
            index,
            standard_account_type: StandardAccountType::BIP32Account,
        };

        let derivation_path = account_type.derivation_path(network).unwrap();
        let account_key = hd_wallet.derive(&derivation_path).unwrap();

        let account =
            Account::from_xpriv(Some([0u8; 32]), account_type.clone(), account_key, network)
                .unwrap();

        // Verify account properties
        match &account.account_type {
            AccountType::Standard {
                index: acc_index,
                standard_account_type,
            } => {
                assert_eq!(*acc_index, index);
                assert_eq!(*standard_account_type, StandardAccountType::BIP32Account);
            }
            _ => panic!("Expected Standard account type"),
        }

        // Verify derivation path follows simple BIP32: m/index'
        assert_eq!(derivation_path.to_string(), format!("m/{}'", index));
    }
}

#[test]
fn test_coinjoin_account_creation() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let hd_wallet = HDWallet::new(master);

    // Create CoinJoin accounts
    for index in 0..3 {
        let account_type = AccountType::CoinJoin {
            index,
        };

        let derivation_path = account_type.derivation_path(network).unwrap();
        let account_key = hd_wallet.derive(&derivation_path).unwrap();

        let account =
            Account::from_xpriv(Some([0u8; 32]), account_type.clone(), account_key, network)
                .unwrap();

        // Verify account properties
        match &account.account_type {
            AccountType::CoinJoin {
                index: acc_index,
            } => {
                assert_eq!(*acc_index, index);
            }
            _ => panic!("Expected CoinJoin account type"),
        }

        // Verify derivation path for CoinJoin: m/9'/1'/index' (testnet coin type)
        assert_eq!(derivation_path.to_string(), format!("m/9'/1'/{}'", index));
    }
}

#[test]
fn test_identity_registration_account() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let hd_wallet = HDWallet::new(master);

    let account_type = AccountType::IdentityRegistration;

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = hd_wallet.derive(&derivation_path).unwrap();

    let account =
        Account::from_xpriv(Some([0u8; 32]), account_type.clone(), account_key, network).unwrap();

    // Verify account type
    assert!(matches!(account.account_type, AccountType::IdentityRegistration));

    // Verify derivation path for identity registration: m/9'/1'/5'/1' (testnet)
    assert_eq!(derivation_path.to_string(), "m/9'/1'/5'/1'");
}

#[test]
fn test_identity_topup_account() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let hd_wallet = HDWallet::new(master);

    // Test multiple identity topup accounts with different registration indices
    for registration_index in 0..3 {
        let account_type = AccountType::IdentityTopUp {
            registration_index,
        };

        let derivation_path = account_type.derivation_path(network).unwrap();
        let account_key = hd_wallet.derive(&derivation_path).unwrap();

        let account =
            Account::from_xpriv(Some([0u8; 32]), account_type.clone(), account_key, network)
                .unwrap();

        // Verify account properties
        match &account.account_type {
            AccountType::IdentityTopUp {
                registration_index: reg_idx,
            } => {
                assert_eq!(*reg_idx, registration_index);
            }
            _ => panic!("Expected IdentityTopUp account type"),
        }

        // Verify derivation path for identity topup: m/9'/1'/5'/2'/registration_index' (testnet)
        assert_eq!(derivation_path.to_string(), format!("m/9'/1'/5'/2'/{}'", registration_index));
    }
}

#[test]
fn test_identity_topup_not_bound_account() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let hd_wallet = HDWallet::new(master);

    let account_type = AccountType::IdentityTopUpNotBoundToIdentity;

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = hd_wallet.derive(&derivation_path).unwrap();

    let account =
        Account::from_xpriv(Some([0u8; 32]), account_type.clone(), account_key, network).unwrap();

    // Verify account type
    assert!(matches!(account.account_type, AccountType::IdentityTopUpNotBoundToIdentity));

    // Verify derivation path: m/9'/1'/5'/2' (testnet) - identity topup not bound (base path)
    assert_eq!(derivation_path.to_string(), "m/9'/1'/5'/2'");
}

#[test]
fn test_identity_invitation_account() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let hd_wallet = HDWallet::new(master);

    let account_type = AccountType::IdentityInvitation;

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = hd_wallet.derive(&derivation_path).unwrap();

    let account =
        Account::from_xpriv(Some([0u8; 32]), account_type.clone(), account_key, network).unwrap();

    // Verify account type
    assert!(matches!(account.account_type, AccountType::IdentityInvitation));

    // Verify derivation path: m/9'/1'/5'/3' (testnet) - identity invitation
    assert_eq!(derivation_path.to_string(), "m/9'/1'/5'/3'");
}

#[test]
fn test_provider_voting_keys_account() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let hd_wallet = HDWallet::new(master);

    let account_type = AccountType::ProviderVotingKeys;

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = hd_wallet.derive(&derivation_path).unwrap();

    let account =
        Account::from_xpriv(Some([0u8; 32]), account_type.clone(), account_key, network).unwrap();

    // Verify account type
    assert!(matches!(account.account_type, AccountType::ProviderVotingKeys));

    // Verify derivation path for provider voting: m/9'/1'/3'/1' (testnet)
    assert_eq!(derivation_path.to_string(), "m/9'/1'/3'/1'");
}

#[test]
fn test_provider_owner_keys_account() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let hd_wallet = HDWallet::new(master);

    let account_type = AccountType::ProviderOwnerKeys;

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = hd_wallet.derive(&derivation_path).unwrap();

    let account =
        Account::from_xpriv(Some([0u8; 32]), account_type.clone(), account_key, network).unwrap();

    // Verify account type
    assert!(matches!(account.account_type, AccountType::ProviderOwnerKeys));

    // Verify derivation path for provider owner: m/9'/1'/3'/2' (testnet)
    assert_eq!(derivation_path.to_string(), "m/9'/1'/3'/2'");
}

#[test]
fn test_provider_operator_keys_account() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let hd_wallet = HDWallet::new(master);

    let account_type = AccountType::ProviderOperatorKeys;

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = hd_wallet.derive(&derivation_path).unwrap();

    let account =
        Account::from_xpriv(Some([0u8; 32]), account_type.clone(), account_key, network).unwrap();

    // Verify account type
    assert!(matches!(account.account_type, AccountType::ProviderOperatorKeys));

    // Verify derivation path for provider operator: m/9'/1'/3'/3' (testnet)
    assert_eq!(derivation_path.to_string(), "m/9'/1'/3'/3'");
}

#[test]
fn test_provider_platform_keys_account() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let hd_wallet = HDWallet::new(master);

    let account_type = AccountType::ProviderPlatformKeys;

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = hd_wallet.derive(&derivation_path).unwrap();

    let account =
        Account::from_xpriv(Some([0u8; 32]), account_type.clone(), account_key, network).unwrap();

    // Verify account type
    assert!(matches!(account.account_type, AccountType::ProviderPlatformKeys));

    // Verify derivation path for provider platform: m/9'/1'/3'/4' (testnet)
    assert_eq!(derivation_path.to_string(), "m/9'/1'/3'/4'");
}

#[test]
fn test_account_extended_key_generation() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let hd_wallet = HDWallet::new(master);

    let account_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    };

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = hd_wallet.derive(&derivation_path).unwrap();

    let account =
        Account::from_xpriv(Some([0u8; 32]), account_type, account_key.clone(), network).unwrap();

    // Verify extended public key can be derived
    let xpub = account.extended_public_key();
    let secp = secp256k1::Secp256k1::new();
    let expected_xpub = ExtendedPubKey::from_priv(&secp, &account_key);
    assert_eq!(xpub, expected_xpub);

    // Verify the account can be created as watch-only
    let watch_only = account.to_watch_only();
    assert!(watch_only.is_watch_only);
    assert_eq!(watch_only.extended_public_key(), xpub);
}

#[test]
fn test_watch_only_account_creation() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let secp = Secp256k1::new();
    let xpub = ExtendedPubKey::from_priv(&secp, &master);

    let account_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    };

    let account =
        Account::from_xpub(Some([0u8; 32]), account_type.clone(), xpub.clone(), network).unwrap();

    // Verify it's watch-only
    assert!(account.is_watch_only);
    assert_eq!(account.extended_public_key(), xpub);

    // Verify account type is preserved
    match &account.account_type {
        AccountType::Standard {
            index,
            standard_account_type,
        } => {
            assert_eq!(*index, 0);
            assert_eq!(*standard_account_type, StandardAccountType::BIP44Account);
        }
        _ => panic!("Expected Standard account type"),
    }
}

#[test]
fn test_account_network_consistency() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let hd_wallet = HDWallet::new(master);

    let account_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    };

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = hd_wallet.derive(&derivation_path).unwrap();

    let account = Account::from_xpriv(Some([0u8; 32]), account_type, account_key, network).unwrap();

    // Account should know its network
    // Note: Account struct doesn't store network directly but uses it for address generation
    // This would be tested through address generation
}

#[test]
fn test_multiple_account_types_same_wallet() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let hd_wallet = HDWallet::new(master);
    let wallet_id = [1u8; 32];

    // Create one of each account type
    let account_types = vec![
        AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP44Account,
        },
        AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP32Account,
        },
        AccountType::CoinJoin {
            index: 0,
        },
        AccountType::IdentityRegistration,
        AccountType::IdentityTopUp {
            registration_index: 0,
        },
        AccountType::IdentityTopUpNotBoundToIdentity,
        AccountType::IdentityInvitation,
        AccountType::ProviderVotingKeys,
        AccountType::ProviderOwnerKeys,
        AccountType::ProviderOperatorKeys,
        AccountType::ProviderPlatformKeys,
    ];

    let mut accounts = Vec::new();

    for account_type in account_types {
        let derivation_path = account_type.derivation_path(network).unwrap();
        let account_key = hd_wallet.derive(&derivation_path).unwrap();

        let account =
            Account::from_xpriv(Some(wallet_id), account_type, account_key, network).unwrap();

        accounts.push(account);
    }

    // Verify all accounts have different extended public keys
    let mut xpubs = Vec::new();
    for account in &accounts {
        let xpub = account.extended_public_key();
        assert!(!xpubs.contains(&xpub), "Duplicate extended public key found");
        xpubs.push(xpub);
    }

    assert_eq!(accounts.len(), 11); // All account types created
}

#[test]
fn test_account_derivation_path_uniqueness() {
    let network = Network::Testnet;

    // Create various account types and verify unique derivation paths
    let account_types = vec![
        (
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            "m/44'/1'/0'".to_string(),
        ),
        (
            AccountType::Standard {
                index: 1,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            "m/44'/1'/1'".to_string(),
        ),
        (
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP32Account,
            },
            "m/0'".to_string(),
        ),
        (
            AccountType::CoinJoin {
                index: 0,
            },
            "m/9'/1'/0'".to_string(),
        ),
        (AccountType::IdentityRegistration, "m/9'/1'/5'/1'".to_string()),
        (
            AccountType::IdentityTopUp {
                registration_index: 0,
            },
            "m/9'/1'/5'/2'/0'".to_string(),
        ),
        (AccountType::IdentityTopUpNotBoundToIdentity, "m/9'/1'/5'/2'".to_string()),
        (AccountType::IdentityInvitation, "m/9'/1'/5'/3'".to_string()),
        (AccountType::ProviderVotingKeys, "m/9'/1'/3'/1'".to_string()),
        (AccountType::ProviderOwnerKeys, "m/9'/1'/3'/2'".to_string()),
        (AccountType::ProviderOperatorKeys, "m/9'/1'/3'/3'".to_string()),
        (AccountType::ProviderPlatformKeys, "m/9'/1'/3'/4'".to_string()),
    ];

    let mut paths = Vec::new();

    for (account_type, expected_path) in account_types {
        let derivation_path = account_type.derivation_path(network).unwrap();
        let path_str = derivation_path.to_string();

        assert_eq!(path_str, expected_path, "Unexpected derivation path for {:?}", account_type);
        assert!(!paths.contains(&path_str), "Duplicate derivation path: {}", path_str);

        paths.push(path_str);
    }
}
