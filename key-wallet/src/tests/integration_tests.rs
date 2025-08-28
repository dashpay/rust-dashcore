//! Integration tests for complete wallet workflows
//!
//! Tests full wallet lifecycle, account discovery, and complex scenarios.

use crate::account::{AccountType, StandardAccountType};
use crate::mnemonic::{Language, Mnemonic};
use crate::wallet::Wallet;
use crate::Network;

#[test]
fn test_multi_network_wallet_management() {
    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    ).unwrap();

    // Create wallet and add accounts on different networks
    let mut wallet = Wallet::from_mnemonic(
        mnemonic,
        &[Network::Testnet],
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    // Add testnet accounts (account 0 already exists)
    for i in 0..3 {
        wallet
            .add_account(
                AccountType::Standard {
                    index: i,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                Network::Testnet,
                None,
            )
            .ok();
    }

    // Add mainnet accounts
    for i in 0..2 {
        wallet
            .add_account(
                AccountType::Standard {
                    index: i,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                Network::Dash,
                None,
            )
            .ok();
    }

    // Add devnet accounts
    for i in 0..2 {
        wallet
            .add_account(
                AccountType::Standard {
                    index: i,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                Network::Devnet,
                None,
            )
            .ok();
    }

    // Verify network separation
    assert_eq!(wallet.accounts.get(&Network::Testnet).unwrap().standard_bip44_accounts.len(), 3);
    assert_eq!(wallet.accounts.get(&Network::Dash).unwrap().standard_bip44_accounts.len(), 2);
    assert_eq!(wallet.accounts.get(&Network::Devnet).unwrap().standard_bip44_accounts.len(), 2);
}

#[test]
fn test_wallet_with_all_account_types() {
    let wallet = Wallet::new_random(
        &[Network::Testnet],
        crate::wallet::initialization::WalletAccountCreationOptions::AllAccounts(
            [0, 1].into(),
            [0].into(),
            [0, 1].into(),
            [0, 1].into(),
        ),
    )
    .unwrap();

    // Verify all accounts were added
    let collection = wallet.accounts.get(&Network::Testnet).unwrap();
    assert_eq!(collection.standard_bip44_accounts.len(), 2); // indices 0 and 1
    assert_eq!(collection.standard_bip32_accounts.len(), 1); // index 0
    assert_eq!(collection.coinjoin_accounts.len(), 2); // indices 0 and 1
    assert!(collection.identity_registration.is_some());
    assert_eq!(collection.identity_topup.len(), 2); // registration indices 0 and 1
    assert!(collection.identity_topup_not_bound.is_some());
    assert!(collection.identity_invitation.is_some());
    assert!(collection.provider_voting_keys.is_some());
    assert!(collection.provider_owner_keys.is_some());
    assert!(collection.provider_operator_keys.is_some());
    assert!(collection.provider_platform_keys.is_some());
}
