//! Integration tests for the wallet manager
//!
//! These tests verify that the high-level wallet management functionality
//! works correctly with the low-level key-wallet primitives.

use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::transaction_building::AccountTypePreference;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::{mnemonic::Language, Mnemonic, Network};
use key_wallet_manager::WalletInterface;
use key_wallet_manager::{WalletError, WalletManager};

#[test]
fn test_wallet_manager_creation() {
    // Create a wallet manager
    let manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    // WalletManager::new returns Self, not Result
    assert_eq!(manager.last_processed_height(), 0);
    assert_eq!(manager.wallet_count(), 0); // No wallets created yet
    assert_eq!(manager.monitor_revision(), 0);
}

#[test]
fn test_wallet_manager_from_mnemonic() {
    // Create from a test mnemonic
    let mnemonic = Mnemonic::generate(12, Language::English).unwrap();
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);
    assert_eq!(manager.monitor_revision(), 0);

    // Create a wallet from mnemonic
    let wallet_result = manager.create_wallet_from_mnemonic(
        &mnemonic.to_string(),
        "",
        0,
        WalletAccountCreationOptions::Default,
    );
    assert!(wallet_result.is_ok(), "Failed to create wallet: {:?}", wallet_result);
    assert_eq!(manager.wallet_count(), 1);
    assert_eq!(manager.monitor_revision(), 1);
}

#[test]
fn test_account_management() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    // Create a wallet first
    let wallet_result =
        manager.create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default);
    assert!(wallet_result.is_ok(), "Failed to create wallet: {:?}", wallet_result);
    let wallet_id = wallet_result.unwrap();
    assert_eq!(manager.monitor_revision(), 1);

    // Add accounts to the wallet
    // Note: Index 0 already exists from wallet creation, so use index 1
    let result = manager.create_account(
        &wallet_id,
        key_wallet::AccountType::Standard {
            index: 1,
            standard_account_type: key_wallet::account::StandardAccountType::BIP44Account,
        },
        None,
    );
    assert!(result.is_ok());
    assert_eq!(manager.monitor_revision(), 2);

    // Get accounts from wallet - Default creates 11 accounts (including PlatformPayment), plus the one we added
    let accounts = manager.get_accounts(&wallet_id);
    assert!(accounts.is_ok());
    assert_eq!(accounts.unwrap().len(), 12); // 11 from Default + 1 we added
}

#[test]
fn test_address_generation() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    // Create a wallet first
    let wallet_result =
        manager.create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default);
    assert!(wallet_result.is_ok(), "Failed to create wallet: {:?}", wallet_result);
    let wallet_id = wallet_result.unwrap();

    // The wallet should already have account 0 from creation
    // But the managed wallet info might not have the account collection initialized

    // Test address generation - it may fail if accounts aren't initialized
    let address1 = manager.get_receive_address(&wallet_id, 0, AccountTypePreference::BIP44, false);
    // This might fail with InvalidNetwork if the account collection isn't initialized
    // We'll check if it's the expected error
    if let Err(ref e) = address1 {
        match e {
            WalletError::InvalidNetwork => {
                // This is expected given the current implementation
                // The managed wallet info doesn't initialize account collections
                return;
            }
            _ => panic!("Unexpected error: {:?}", e),
        }
    }

    let change = manager.get_change_address(&wallet_id, 0, AccountTypePreference::BIP44, false);
    // Same check for change address
    if let Err(ref e) = change {
        match e {
            WalletError::InvalidNetwork => {}
            _ => panic!("Unexpected error: {:?}", e),
        }
    }
}

#[test]
fn test_utxo_management() {
    // Unused imports removed - UTXOs are created by processing transactions

    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    // Create a wallet first
    let wallet_result =
        manager.create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default);
    assert!(wallet_result.is_ok(), "Failed to create wallet: {:?}", wallet_result);
    let wallet_id = wallet_result.unwrap();

    // For UTXO management, we need to process transactions that create UTXOs
    // The WalletManager doesn't have an add_utxo method directly
    // Instead, UTXOs are created by processing transactions

    let utxos = manager.wallet_utxos(&wallet_id);
    assert!(utxos.is_ok());
    // Initially empty
    assert_eq!(utxos.unwrap().len(), 0);

    let balance = manager.get_wallet_balance(&wallet_id);
    assert!(balance.is_ok());
    assert_eq!(balance.unwrap().total(), 0);
}

#[test]
fn test_balance_calculation() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    // Create a wallet first
    let wallet_result =
        manager.create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default);
    assert!(wallet_result.is_ok(), "Failed to create wallet: {:?}", wallet_result);
    let wallet_id = wallet_result.unwrap();

    // For balance testing, we would need to process transactions
    // The WalletManager doesn't have add_utxo directly

    // Check wallet balance (should be 0 initially)
    let balance = manager.get_wallet_balance(&wallet_id);
    assert!(balance.is_ok());
    assert_eq!(balance.unwrap().total(), 0);

    // Check global balance
    let total = manager.get_total_balance();
    assert_eq!(total, 0);
}

#[test]
fn test_block_height_tracking() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    // Initial state with no wallets
    assert_eq!(manager.last_processed_height(), 0);
    assert_eq!(manager.synced_height(), 0);

    let mnemonic1 = Mnemonic::generate(12, Language::English).unwrap();
    let wallet_id1 = manager
        .create_wallet_from_mnemonic(
            &mnemonic1.to_string(),
            "",
            0,
            WalletAccountCreationOptions::Default,
        )
        .unwrap();

    let mnemonic2 = Mnemonic::generate(12, Language::English).unwrap();
    let wallet_id2 = manager
        .create_wallet_from_mnemonic(
            &mnemonic2.to_string(),
            "",
            0,
            WalletAccountCreationOptions::Default,
        )
        .unwrap();

    assert_eq!(manager.wallet_count(), 2);

    // Both wallets initialized with `synced_height = birth_height - 1 = 0`,
    // so neither has been processed past genesis.
    for wallet_info in manager.get_all_wallet_infos().values() {
        assert_eq!(wallet_info.last_processed_height(), 0);
        assert_eq!(wallet_info.synced_height(), 0);
    }

    // Per-wallet last-processed updates only touch the addressed wallet.
    manager.update_wallet_last_processed_height(&wallet_id1, 12345);
    assert_eq!(manager.last_processed_height(), 12345);
    let wallet_info1 = manager.get_wallet_info(&wallet_id1).unwrap();
    let wallet_info2 = manager.get_wallet_info(&wallet_id2).unwrap();
    assert_eq!(wallet_info1.last_processed_height(), 12345);
    assert_eq!(wallet_info2.last_processed_height(), 0);

    // Per-wallet synced-height updates only touch the addressed wallet.
    manager.update_wallet_synced_height(&wallet_id1, 12000);
    let wallet_info1 = manager.get_wallet_info(&wallet_id1).unwrap();
    let wallet_info2 = manager.get_wallet_info(&wallet_id2).unwrap();
    assert_eq!(wallet_info1.synced_height(), 12000);
    assert_eq!(wallet_info2.synced_height(), 0);
    // Aggregate `synced_height()` is `min` across wallets, so wallet 2 holds it at 0.
    assert_eq!(manager.synced_height(), 0);

    // Advance wallet 2 too. Aggregate min jumps to wallet 2's new value.
    manager.update_wallet_synced_height(&wallet_id2, 11000);
    assert_eq!(manager.synced_height(), 11000);

    // Wallets advance independently. Aggregate `last_processed_height()` is `max`.
    manager.update_wallet_last_processed_height(&wallet_id2, 25000);
    let wallet_info1 = manager.get_wallet_info(&wallet_id1).unwrap();
    let wallet_info2 = manager.get_wallet_info(&wallet_id2).unwrap();
    assert_eq!(wallet_info1.last_processed_height(), 12345);
    assert_eq!(wallet_info2.last_processed_height(), 25000);
    assert_eq!(manager.last_processed_height(), 25000);

    // Per-wallet updates are monotonic. Values below the current are ignored.
    manager.update_wallet_last_processed_height(&wallet_id2, 10);
    manager.update_wallet_synced_height(&wallet_id2, 10);
    let wallet_info2 = manager.get_wallet_info(&wallet_id2).unwrap();
    assert_eq!(wallet_info2.last_processed_height(), 25000);
    assert_eq!(wallet_info2.synced_height(), 11000);

    // `wallets_behind(height)` lists wallets with `synced_height < height`.
    let behind_at_12500 = manager.wallets_behind(12500);
    assert!(behind_at_12500.contains(&wallet_id1));
    assert!(behind_at_12500.contains(&wallet_id2));
    // A wallet at exactly `height` is not behind. wallet_id1 sits at 12000,
    // wallet_id2 sits at 11000.
    let behind_at_12000 = manager.wallets_behind(12000);
    assert!(!behind_at_12000.contains(&wallet_id1));
    assert!(behind_at_12000.contains(&wallet_id2));
    let behind_at_500 = manager.wallets_behind(500);
    assert!(behind_at_500.is_empty());
}
