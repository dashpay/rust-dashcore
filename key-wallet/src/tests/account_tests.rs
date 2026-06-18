//! Comprehensive tests for account management
//!
//! Tests all account types and their operations.

use crate::account::{Account, AccountType, StandardAccountType};
use crate::bip32::{ExtendedPrivKey, ExtendedPubKey};
use crate::managed_account::address_pool::KeySource;
use crate::managed_account::managed_account_type::ManagedAccountType;
use crate::mnemonic::{Language, Mnemonic};
use crate::Network;
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
    ExtendedPrivKey::new_master(network, &seed).unwrap()
}

#[test]
fn test_bip44_account_creation() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let secp = Secp256k1::new();

    // Create multiple BIP44 accounts with different indices
    for index in 0..10 {
        let account_type = AccountType::Standard {
            index,
            standard_account_type: StandardAccountType::BIP44Account,
        };

        let derivation_path = account_type.derivation_path(network).unwrap();
        let account_key = master.derive_priv(&secp, &derivation_path).unwrap();

        let account = Account::from_xpriv(
            Some([0u8; 32]), // wallet_id
            account_type,
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
    let secp = Secp256k1::new();

    // Create multiple BIP32 accounts with different indices
    for index in 0..5 {
        let account_type = AccountType::Standard {
            index,
            standard_account_type: StandardAccountType::BIP32Account,
        };

        let derivation_path = account_type.derivation_path(network).unwrap();
        let account_key = master.derive_priv(&secp, &derivation_path).unwrap();

        let account =
            Account::from_xpriv(Some([0u8; 32]), account_type, account_key, network).unwrap();

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
    let secp = Secp256k1::new();

    // Create CoinJoin accounts
    for index in 0..3 {
        let account_type = AccountType::CoinJoin {
            index,
        };

        let derivation_path = account_type.derivation_path(network).unwrap();
        let account_key = master.derive_priv(&secp, &derivation_path).unwrap();

        let account =
            Account::from_xpriv(Some([0u8; 32]), account_type, account_key, network).unwrap();

        // Verify account properties
        match &account.account_type {
            AccountType::CoinJoin {
                index: acc_index,
            } => {
                assert_eq!(*acc_index, index);
            }
            _ => panic!("Expected CoinJoin account type"),
        }

        // Verify the CoinJoin account derivation path matches Dash Core:
        // m/9'/1'/4'/account' (testnet coin type, FEATURE_PURPOSE_COINJOIN = 4').
        assert_eq!(derivation_path.to_string(), format!("m/9'/1'/4'/{}'", index));

        // The managed CoinJoin pool must derive addresses on the external (`/0`)
        // branch, so the first address sits at m/9'/1'/4'/account'/0/0.
        let key_source = KeySource::Public(account.account_xpub);
        let managed_type =
            ManagedAccountType::from_account_type(account.account_type, network, &key_source)
                .unwrap();
        let pool = match &managed_type {
            ManagedAccountType::CoinJoin {
                addresses,
                ..
            } => addresses,
            _ => panic!("Expected CoinJoin managed account type"),
        };
        let first_address =
            pool.address_at_index(0).expect("CoinJoin pool should pre-generate address 0");
        let first_info =
            pool.address_info(&first_address).expect("address info for index 0 should exist");
        assert_eq!(first_info.path.to_string(), format!("m/9'/1'/4'/{}'/0/0", index));
    }
}

#[test]
fn test_identity_registration_account() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let secp = Secp256k1::new();

    let account_type = AccountType::IdentityRegistration;

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = master.derive_priv(&secp, &derivation_path).unwrap();

    let account = Account::from_xpriv(Some([0u8; 32]), account_type, account_key, network).unwrap();

    // Verify account type
    assert!(matches!(account.account_type, AccountType::IdentityRegistration));

    // Verify derivation path for identity registration: m/9'/1'/5'/1' (testnet)
    assert_eq!(derivation_path.to_string(), "m/9'/1'/5'/1'");
}

#[test]
fn test_identity_topup_account() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let secp = Secp256k1::new();

    // Test multiple identity topup accounts with different registration indices
    for registration_index in 0..3 {
        let account_type = AccountType::IdentityTopUp {
            registration_index,
        };

        let derivation_path = account_type.derivation_path(network).unwrap();
        let account_key = master.derive_priv(&secp, &derivation_path).unwrap();

        let account =
            Account::from_xpriv(Some([0u8; 32]), account_type, account_key, network).unwrap();

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
    let secp = Secp256k1::new();

    let account_type = AccountType::IdentityTopUpNotBoundToIdentity;

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = master.derive_priv(&secp, &derivation_path).unwrap();

    let account = Account::from_xpriv(Some([0u8; 32]), account_type, account_key, network).unwrap();

    // Verify account type
    assert!(matches!(account.account_type, AccountType::IdentityTopUpNotBoundToIdentity));

    // Verify derivation path: m/9'/1'/5'/2' (testnet) - identity topup not bound (base path)
    assert_eq!(derivation_path.to_string(), "m/9'/1'/5'/2'");
}

#[test]
fn test_identity_invitation_account() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let secp = Secp256k1::new();

    let account_type = AccountType::IdentityInvitation;

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = master.derive_priv(&secp, &derivation_path).unwrap();

    let account = Account::from_xpriv(Some([0u8; 32]), account_type, account_key, network).unwrap();

    // Verify account type
    assert!(matches!(account.account_type, AccountType::IdentityInvitation));

    // Verify derivation path: m/9'/1'/5'/3' (testnet) - identity invitation
    assert_eq!(derivation_path.to_string(), "m/9'/1'/5'/3'");
}

#[test]
fn test_provider_voting_keys_account() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let secp = Secp256k1::new();

    let account_type = AccountType::ProviderVotingKeys;

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = master.derive_priv(&secp, &derivation_path).unwrap();

    let account = Account::from_xpriv(Some([0u8; 32]), account_type, account_key, network).unwrap();

    // Verify account type
    assert!(matches!(account.account_type, AccountType::ProviderVotingKeys));

    // Verify derivation path for provider voting: m/9'/1'/3'/1' (testnet)
    assert_eq!(derivation_path.to_string(), "m/9'/1'/3'/1'");
}

#[test]
fn test_provider_owner_keys_account() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let secp = Secp256k1::new();

    let account_type = AccountType::ProviderOwnerKeys;

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = master.derive_priv(&secp, &derivation_path).unwrap();

    let account = Account::from_xpriv(Some([0u8; 32]), account_type, account_key, network).unwrap();

    // Verify account type
    assert!(matches!(account.account_type, AccountType::ProviderOwnerKeys));

    // Verify derivation path for provider owner: m/9'/1'/3'/2' (testnet)
    assert_eq!(derivation_path.to_string(), "m/9'/1'/3'/2'");
}

#[test]
fn test_provider_operator_keys_account() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let secp = Secp256k1::new();

    let account_type = AccountType::ProviderOperatorKeys;

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = master.derive_priv(&secp, &derivation_path).unwrap();

    let account = Account::from_xpriv(Some([0u8; 32]), account_type, account_key, network).unwrap();

    // Verify account type
    assert!(matches!(account.account_type, AccountType::ProviderOperatorKeys));

    // Verify derivation path for provider operator: m/9'/1'/3'/3' (testnet)
    assert_eq!(derivation_path.to_string(), "m/9'/1'/3'/3'");
}

#[test]
fn test_provider_platform_keys_account() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let secp = Secp256k1::new();

    let account_type = AccountType::ProviderPlatformKeys;

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = master.derive_priv(&secp, &derivation_path).unwrap();

    let account = Account::from_xpriv(Some([0u8; 32]), account_type, account_key, network).unwrap();

    // Verify account type
    assert!(matches!(account.account_type, AccountType::ProviderPlatformKeys));

    // Verify derivation path for provider platform: m/9'/1'/3'/4' (testnet)
    assert_eq!(derivation_path.to_string(), "m/9'/1'/3'/4'");
}

#[test]
fn test_account_extended_key_generation() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let secp = Secp256k1::new();

    let account_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    };

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = master.derive_priv(&secp, &derivation_path).unwrap();

    let account = Account::from_xpriv(Some([0u8; 32]), account_type, account_key, network).unwrap();

    // Verify extended public key can be derived
    let xpub = account.extended_public_key();
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

    let account = Account::from_xpub(Some([0u8; 32]), account_type, xpub, network).unwrap();

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
    let secp = Secp256k1::new();

    let account_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    };

    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = master.derive_priv(&secp, &derivation_path).unwrap();

    let account = Account::from_xpriv(Some([0u8; 32]), account_type, account_key, network).unwrap();

    // Verify account stores the correct network
    assert_eq!(account.network, network);

    // Test that wrong network would be rejected when deriving addresses
    // The account should generate addresses for the network it was created with

    // Derive a child key for address generation (m/44'/1'/0'/0/0 for first receive address)
    let receive_path = [
        crate::bip32::ChildNumber::from_normal_idx(0).unwrap(), // receive chain
        crate::bip32::ChildNumber::from_normal_idx(0).unwrap(), // first address
    ];

    let address_xpub = account.account_xpub.derive_pub(&secp, &receive_path).unwrap();
    let pubkey = dashcore::PublicKey::from_slice(&address_xpub.public_key.serialize()).unwrap();
    let address = dashcore::Address::p2pkh(&pubkey, network);

    // Verify the address is for the correct network
    assert!(
        address.to_string().starts_with('y') || address.to_string().starts_with('8'),
        "Testnet addresses should start with 'y' or '8'"
    );

    // Test creating account with different network
    let dash_mainnet = Network::Mainnet;
    let mainnet_account =
        Account::from_xpriv(Some([0u8; 32]), account_type, account_key, dash_mainnet).unwrap();

    // Verify the mainnet account has the correct network
    assert_eq!(mainnet_account.network, dash_mainnet);
    assert_ne!(account.network, mainnet_account.network);
}

#[test]
fn test_multiple_account_types_same_wallet() {
    let network = Network::Testnet;
    let master = create_test_extended_priv_key(network);
    let secp = Secp256k1::new();
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
        let account_key = master.derive_priv(&secp, &derivation_path).unwrap();

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
            "m/9'/1'/4'/0'".to_string(),
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

#[test]
fn test_dashpay_account_index_in_derivation_path() {
    use crate::bip32::ChildNumber;

    // The DashPay friendship path is m/9'/coin'/15'/account'/<id>/<id> (DIP-15 "Account
    // Reference" + DIP-14 256-bit indices). The account segment is the sender's DashPay
    // account and MUST reflect the account index carried on the account type — not a fixed
    // 0'. A multi-account wallet that derived every relationship under account 0 would
    // watch the wrong addresses and miss funds paid to a non-zero account. Account 0 must
    // stay byte-identical to the legacy single-account path (backward compatibility).
    let network = Network::Testnet;
    let user_id = [0x11u8; 32];
    let friend_id = [0x22u8; 32];

    for account in [0u32, 1, 7, 42] {
        // Receiving funds: identity ids ordered user/friend.
        let recv = AccountType::DashpayReceivingFunds {
            index: account,
            user_identity_id: user_id,
            friend_identity_id: friend_id,
        };
        let recv_path = recv.derivation_path(network).unwrap();
        let recv_comps: Vec<ChildNumber> = recv_path.clone().into();
        assert_eq!(recv_comps.len(), 6, "root(3) + account' + two 256-bit ids");
        assert_eq!(
            recv_comps[3],
            ChildNumber::Hardened {
                index: account
            },
            "receiving account segment must honor the account index"
        );
        assert_eq!(
            recv_comps[4],
            ChildNumber::Normal256 {
                index: user_id
            }
        );
        assert_eq!(
            recv_comps[5],
            ChildNumber::Normal256 {
                index: friend_id
            }
        );
        assert!(
            recv_path.to_string().starts_with(&format!("m/9'/1'/15'/{}'/", account)),
            "receiving path should carry account {}': got {}",
            account,
            recv_path
        );

        // External account: the reverse channel, ids ordered friend/user.
        let ext = AccountType::DashpayExternalAccount {
            index: account,
            user_identity_id: user_id,
            friend_identity_id: friend_id,
        };
        let ext_comps: Vec<ChildNumber> = ext.derivation_path(network).unwrap().into();
        assert_eq!(
            ext_comps[3],
            ChildNumber::Hardened {
                index: account
            },
            "external account segment must honor the account index"
        );
        assert_eq!(
            ext_comps[4],
            ChildNumber::Normal256 {
                index: friend_id
            }
        );
        assert_eq!(
            ext_comps[5],
            ChildNumber::Normal256 {
                index: user_id
            }
        );
    }
}
