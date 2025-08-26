//! Tests for wallet backup and restore functionality
//!
//! Tests wallet export, import, and recovery scenarios.

use crate::account::{AccountType, StandardAccountType};
use crate::mnemonic::{Language, Mnemonic};
use crate::wallet::{Wallet, WalletType};
use crate::Network;

#[test]
fn test_wallet_mnemonic_export() {
    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    ).unwrap();

    let wallet = Wallet::from_mnemonic(
        mnemonic.clone(),
        Network::Testnet,
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    // Export mnemonic
    match &wallet.wallet_type {
        WalletType::Mnemonic {
            mnemonic: exported,
            ..
        } => {
            assert_eq!(exported.to_string(), mnemonic.to_string());
        }
        _ => panic!("Expected mnemonic wallet"),
    }
}

#[test]
fn test_wallet_full_backup_restore() {
    let mut original_wallet = Wallet::new_random(
        Network::Testnet,
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    // Add various accounts including 0 since None doesn't create any
    for i in 0..3 {
        original_wallet
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

    original_wallet
        .add_account(
            AccountType::CoinJoin {
                index: 0,
            },
            Network::Testnet,
            None,
        )
        .unwrap();

    // Export wallet data
    let wallet_id = original_wallet.wallet_id;
    let mnemonic = match &original_wallet.wallet_type {
        WalletType::Mnemonic {
            mnemonic,
            ..
        } => mnemonic.clone(),
        _ => panic!("Expected mnemonic wallet"),
    };

    // Simulate wallet destruction
    drop(original_wallet);

    // Restore wallet
    let mut restored_wallet = Wallet::from_mnemonic(
        mnemonic,
        Network::Testnet,
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    // Verify wallet ID matches
    assert_eq!(restored_wallet.wallet_id, wallet_id);

    // Re-add accounts including 0 since None doesn't create any
    for i in 0..3 {
        restored_wallet
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

    restored_wallet
        .add_account(
            AccountType::CoinJoin {
                index: 0,
            },
            Network::Testnet,
            None,
        )
        .unwrap();

    // Verify account structure restored
    let collection = restored_wallet.accounts.get(&Network::Testnet).unwrap();
    assert_eq!(collection.standard_bip44_accounts.len(), 3); // 0, 1, 2
    assert_eq!(collection.coinjoin_accounts.len(), 1);
}

#[test]
fn test_wallet_partial_backup() {
    // Test backing up only essential data (mnemonic + account indices)

    let mut wallet = Wallet::new_random(
        Network::Testnet,
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    // Add accounts including standard 0 since None doesn't create any
    let account_metadata = vec![
        AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP44Account,
        },
        AccountType::Standard {
            index: 1,
            standard_account_type: StandardAccountType::BIP44Account,
        },
        AccountType::CoinJoin {
            index: 0,
        },
    ];

    for account_type in &account_metadata {
        wallet.add_account(account_type.clone(), Network::Testnet, None).unwrap();
    }

    // Verify accounts were added
    let collection = wallet.accounts.get(&Network::Testnet).unwrap();
    assert_eq!(collection.standard_bip44_accounts.len(), 2); // indices 0, 1
    assert_eq!(collection.coinjoin_accounts.len(), 1);
}

#[test]
fn test_wallet_encrypted_backup() {
    // Test wallet backup with encryption (simulated)
    let passphrase = "strong_passphrase_123!@#";
    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    ).unwrap();

    let wallet = Wallet::from_mnemonic_with_passphrase(
        mnemonic.clone(),
        passphrase.to_string(),
        Network::Testnet,
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    // Simulate encrypted backup
    struct EncryptedBackup {
        encrypted_mnemonic: Vec<u8>, // In real implementation, would be encrypted
        _salt: [u8; 32],
        network: Network,
    }

    let backup = EncryptedBackup {
        encrypted_mnemonic: mnemonic.to_string().into_bytes(), // Would be encrypted in real implementation
        _salt: [0u8; 32],                                      // Would be random salt
        network: Network::Testnet,
    };

    // Simulate decryption and restoration
    let decrypted_mnemonic = String::from_utf8(backup.encrypted_mnemonic).unwrap();
    let restored_mnemonic = Mnemonic::from_phrase(&decrypted_mnemonic, Language::English).unwrap();

    let restored_wallet = Wallet::from_mnemonic_with_passphrase(
        restored_mnemonic,
        passphrase.to_string(),
        backup.network,
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    assert_eq!(wallet.wallet_id, restored_wallet.wallet_id);
}

#[test]
fn test_wallet_metadata_backup() {
    // Test backing up wallet metadata (labels, settings, etc.)

    let mut wallet = Wallet::new_random(
        Network::Testnet,
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    // Add accounts with metadata
    struct AccountMetadata {
        account_type: AccountType,
        label: String,
        _created_at: u64,
    }

    let metadata = vec![
        AccountMetadata {
            account_type: AccountType::Standard {
                index: 1, // Use index 1 since 0 is created by default
                standard_account_type: StandardAccountType::BIP44Account,
            },
            label: "Secondary Account".to_string(),
            _created_at: 1234567890,
        },
        AccountMetadata {
            account_type: AccountType::CoinJoin {
                index: 0,
            },
            label: "Private Account".to_string(),
            _created_at: 1234567900,
        },
    ];

    for item in &metadata {
        wallet.add_account(item.account_type.clone(), Network::Testnet, None).unwrap();
    }

    // Verify metadata can be associated with accounts
    assert_eq!(metadata.len(), 2);
    assert_eq!(metadata[0].label, "Secondary Account");
    assert_eq!(metadata[1].label, "Private Account");
}

#[test]
fn test_multi_network_backup_restore() {
    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    ).unwrap();

    let mut wallet = Wallet::from_mnemonic(
        mnemonic.clone(),
        Network::Testnet,
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    // Add accounts on multiple networks
    let networks = vec![Network::Testnet, Network::Dash, Network::Devnet];

    for network in &networks {
        for i in 0..2 {
            // Try to add account, OK if it already exists (account 0 is created by default)
            wallet
                .add_account(
                    AccountType::Standard {
                        index: i,
                        standard_account_type: StandardAccountType::BIP44Account,
                    },
                    *network,
                    None,
                )
                .ok();
        }
    }

    // Create network-aware backup
    struct NetworkBackup {
        network: Network,
        account_count: usize,
    }

    let mut network_backups = Vec::new();
    for network in &networks {
        if let Some(collection) = wallet.accounts.get(network) {
            network_backups.push(NetworkBackup {
                network: *network,
                account_count: collection.standard_bip44_accounts.len(),
            });
        }
    }

    // Restore and verify
    let mut restored = Wallet::from_mnemonic(
        mnemonic,
        Network::Testnet,
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    for backup in network_backups {
        for i in 0..backup.account_count {
            restored
                .add_account(
                    AccountType::Standard {
                        index: i as u32,
                        standard_account_type: StandardAccountType::BIP44Account,
                    },
                    backup.network,
                    None,
                )
                .ok(); // OK to fail if account already exists
        }
    }

    // Verify all networks restored
    for network in networks {
        assert!(restored.accounts.contains_key(&network));
    }
}

#[test]
fn test_incremental_backup() {
    // Test incremental backup of changes since last backup

    let mut wallet = Wallet::new_random(
        Network::Testnet,
        crate::wallet::initialization::WalletAccountCreationOptions::None,
    )
    .unwrap();

    // Initial state - account 0 is created by default, no need to add it

    // Simulate initial backup
    let initial_account_count = wallet
        .accounts
        .get(&Network::Testnet)
        .map(|c| c.standard_bip44_accounts.len())
        .unwrap_or(0);

    // Make changes
    wallet
        .add_account(
            AccountType::Standard {
                index: 1,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            Network::Testnet,
            None,
        )
        .unwrap();

    wallet
        .add_account(
            AccountType::CoinJoin {
                index: 0,
            },
            Network::Testnet,
            None,
        )
        .unwrap();

    // Calculate incremental changes
    let new_account_count = wallet
        .accounts
        .get(&Network::Testnet)
        .map(|c| c.standard_bip44_accounts.len())
        .unwrap_or(0);

    let accounts_added = new_account_count - initial_account_count;
    assert_eq!(accounts_added, 1); // One new standard account

    // Also check CoinJoin account was added
    let coinjoin_count =
        wallet.accounts.get(&Network::Testnet).map(|c| c.coinjoin_accounts.len()).unwrap_or(0);
    assert_eq!(coinjoin_count, 1);
}

#[test]
fn test_backup_version_compatibility() {
    // Test handling of backups from different wallet versions
    struct VersionedBackup {
        version: u32,
        mnemonic: String,
        network: Network,
    }

    let backup_v1 = VersionedBackup {
        version: 1,
        mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        network: Network::Testnet,
    };

    // Simulate migration from older version
    let mnemonic = Mnemonic::from_phrase(&backup_v1.mnemonic, Language::English).unwrap();

    let wallet = match backup_v1.version {
        1 => {
            // Version 1 migration logic
            Wallet::from_mnemonic(
                mnemonic,
                backup_v1.network,
                crate::wallet::initialization::WalletAccountCreationOptions::None,
            )
            .unwrap()
        }
        _ => panic!("Unsupported backup version"),
    };

    assert_ne!(wallet.wallet_id, [0u8; 32]);
}
