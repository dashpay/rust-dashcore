//! Integration tests for complete wallet workflows
//!
//! Tests full wallet lifecycle, account discovery, and complex scenarios.

use crate::account::{AccountType, StandardAccountType};
use crate::mnemonic::{Language, Mnemonic};
use crate::wallet::Wallet;
use crate::Network;

#[test]
fn test_wallet_multiple_accounts() {
    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    )
    .unwrap();

    // Create wallet and add accounts
    let mut wallet = Wallet::from_mnemonic(
        mnemonic,
        Network::Testnet,
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    // Add testnet accounts
    for i in 0..3 {
        wallet
            .add_account(
                AccountType::Standard {
                    index: i,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .ok();
    }

    // Verify accounts were added
    assert_eq!(wallet.accounts.standard_bip44_accounts.len(), 3);
    assert_eq!(wallet.network, Network::Testnet);
}

#[test]
fn test_separate_wallets_per_network() {
    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    )
    .unwrap();

    // Create separate wallets for each network
    let mut testnet_wallet = Wallet::from_mnemonic(
        mnemonic.clone(),
        Network::Testnet,
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    let mut mainnet_wallet = Wallet::from_mnemonic(
        mnemonic.clone(),
        Network::Dash,
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    let mut devnet_wallet = Wallet::from_mnemonic(
        mnemonic,
        Network::Devnet,
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    // Add accounts to each wallet
    for i in 0..3 {
        testnet_wallet
            .add_account(
                AccountType::Standard {
                    index: i,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .ok();
    }

    for i in 0..2 {
        mainnet_wallet
            .add_account(
                AccountType::Standard {
                    index: i,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .ok();
        devnet_wallet
            .add_account(
                AccountType::Standard {
                    index: i,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .ok();
    }

    // Verify network separation
    assert_eq!(testnet_wallet.network, Network::Testnet);
    assert_eq!(testnet_wallet.accounts.standard_bip44_accounts.len(), 3);

    assert_eq!(mainnet_wallet.network, Network::Dash);
    assert_eq!(mainnet_wallet.accounts.standard_bip44_accounts.len(), 2);

    assert_eq!(devnet_wallet.network, Network::Devnet);
    assert_eq!(devnet_wallet.accounts.standard_bip44_accounts.len(), 2);

    // All share the same wallet_id
    assert_eq!(testnet_wallet.wallet_id, mainnet_wallet.wallet_id);
    assert_eq!(testnet_wallet.wallet_id, devnet_wallet.wallet_id);
}

#[test]
fn test_wallet_with_all_account_types() {
    let wallet = Wallet::new_random(
        Network::Testnet,
        crate::wallet::initialization::WalletAccountCreationOptions::AllAccounts(
            [0, 1].into(),
            [0].into(),
            [0, 1].into(),
            [0, 1].into(),
            std::collections::BTreeSet::new(), // PlatformPayment accounts
        ),
    )
    .unwrap();

    // Verify all accounts were added
    assert_eq!(wallet.accounts.standard_bip44_accounts.len(), 2); // indices 0 and 1
    assert_eq!(wallet.accounts.standard_bip32_accounts.len(), 1); // index 0
    assert_eq!(wallet.accounts.coinjoin_accounts.len(), 2); // indices 0 and 1
    assert!(wallet.accounts.identity_registration.is_some());
    assert_eq!(wallet.accounts.identity_topup.len(), 2); // registration indices 0 and 1
    assert!(wallet.accounts.identity_topup_not_bound.is_some());
    assert!(wallet.accounts.identity_invitation.is_some());
    assert!(wallet.accounts.provider_voting_keys.is_some());
    assert!(wallet.accounts.provider_owner_keys.is_some());
    assert!(wallet.accounts.provider_operator_keys.is_some());
    assert!(wallet.accounts.provider_platform_keys.is_some());
}
