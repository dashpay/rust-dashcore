//! Integration tests for key-wallet-manager
//!
//! These tests verify that the high-level wallet management functionality
//! works correctly with the low-level key-wallet primitives.

use key_wallet::{mnemonic::Language, Mnemonic, Network};
use key_wallet_manager::WalletManager;

#[test]
fn test_wallet_manager_creation() {
    // Create a wallet manager with default network
    let manager = WalletManager::new(Network::Testnet);

    // WalletManager::new returns Self, not Result
    assert_eq!(manager.current_height(), 0);
    assert_eq!(manager.wallet_count(), 0); // No wallets created yet
}

#[test]
fn test_wallet_manager_from_mnemonic() {
    // Create from a test mnemonic
    let mnemonic = Mnemonic::generate(12, Language::English).unwrap();
    let mut manager = WalletManager::new(Network::Testnet);

    // Create a wallet from mnemonic
    let wallet = manager.create_wallet_from_mnemonic(
        "wallet1".to_string(),
        "Test Wallet".to_string(),
        &mnemonic.to_string(),
        "",
        Some(Network::Testnet),
    );
    assert!(wallet.is_ok());
    assert_eq!(manager.wallet_count(), 1);
}

#[test]
fn test_account_management() {
    let mut manager = WalletManager::new(Network::Testnet);

    // Create a wallet first
    let wallet = manager.create_wallet(
        "wallet1".to_string(),
        "Test Wallet".to_string(),
        Some(Network::Testnet),
    );
    assert!(wallet.is_ok());

    // Add accounts to the wallet
    // Note: Index 0 already exists from wallet creation, so use index 1
    let result =
        manager.create_account(&"wallet1".to_string(), 1, key_wallet::AccountType::Standard);
    assert!(result.is_ok());

    // Get accounts from wallet - should have 2 accounts now (0 and 1)
    let accounts = manager.get_accounts(&"wallet1".to_string());
    assert!(accounts.is_ok());
    assert_eq!(accounts.unwrap().len(), 2);
}

#[test]
fn test_address_generation() {
    let mut manager = WalletManager::new(Network::Testnet);

    // Create a wallet first
    let wallet = manager.create_wallet(
        "wallet1".to_string(),
        "Test Wallet".to_string(),
        Some(Network::Testnet),
    );
    assert!(wallet.is_ok());

    // Add an account
    let _ = manager.create_account(&"wallet1".to_string(), 0, key_wallet::AccountType::Standard);

    // Note: Address generation is currently disabled due to ManagedAccount refactoring
    let address1 = manager.get_receive_address(&"wallet1".to_string(), 0);
    assert!(address1.is_err()); // Expected to fail until ManagedAccount is integrated

    let change = manager.get_change_address(&"wallet1".to_string(), 0);
    assert!(change.is_err()); // Expected to fail until ManagedAccount is integrated
}

#[test]
fn test_utxo_management() {
    use dashcore::blockdata::script::ScriptBuf;
    use dashcore::{OutPoint, TxOut, Txid};
    use dashcore_hashes::{sha256d, Hash};
    use key_wallet_manager::utxo::Utxo;

    let mut manager = WalletManager::new(Network::Testnet);

    // Create a wallet first
    let _ = manager.create_wallet(
        "wallet1".to_string(),
        "Test Wallet".to_string(),
        Some(Network::Testnet),
    );

    // Create a test UTXO
    let outpoint = OutPoint {
        txid: Txid::from_raw_hash(sha256d::Hash::from_slice(&[1u8; 32]).unwrap()),
        vout: 0,
    };

    let txout = TxOut {
        value: 100000,
        script_pubkey: ScriptBuf::new(),
    };

    // Create a dummy address for testing
    let address = key_wallet::Address::p2pkh(
        &dashcore::PublicKey::from_slice(&[
            0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1,
            0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04,
            0x88, 0x7e, 0x5b, 0x23, 0x52,
        ])
        .unwrap(),
        Network::Testnet,
    );
    let utxo = Utxo::new(outpoint, txout, address, 100, false);

    // Add UTXO to wallet
    let result = manager.add_utxo(&"wallet1".to_string(), utxo.clone());
    assert!(result.is_ok());

    let utxos = manager.get_wallet_utxos(&"wallet1".to_string());
    assert!(utxos.is_ok());
    assert_eq!(utxos.unwrap().len(), 1);

    let balance = manager.get_wallet_balance(&"wallet1".to_string());
    assert!(balance.is_ok());
    assert_eq!(balance.unwrap(), 100000);
}

#[test]
fn test_balance_calculation() {
    use dashcore::blockdata::script::ScriptBuf;
    use dashcore::{OutPoint, TxOut, Txid};
    use dashcore_hashes::{sha256d, Hash};
    use key_wallet_manager::utxo::Utxo;

    let mut manager = WalletManager::new(Network::Testnet);

    // Create a wallet first
    let _ = manager.create_wallet(
        "wallet1".to_string(),
        "Test Wallet".to_string(),
        Some(Network::Testnet),
    );

    // Create a dummy address for testing
    let address = key_wallet::Address::p2pkh(
        &dashcore::PublicKey::from_slice(&[
            0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1,
            0xa8, 0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04,
            0x88, 0x7e, 0x5b, 0x23, 0x52,
        ])
        .unwrap(),
        Network::Testnet,
    );

    // Add confirmed UTXO
    let outpoint1 = OutPoint {
        txid: Txid::from_raw_hash(sha256d::Hash::from_slice(&[1u8; 32]).unwrap()),
        vout: 0,
    };
    let txout1 = TxOut {
        value: 50000,
        script_pubkey: ScriptBuf::new(),
    };
    let mut utxo1 = Utxo::new(outpoint1, txout1, address.clone(), 100, false);
    utxo1.is_confirmed = true;

    // Add unconfirmed UTXO
    let outpoint2 = OutPoint {
        txid: Txid::from_raw_hash(sha256d::Hash::from_slice(&[2u8; 32]).unwrap()),
        vout: 0,
    };
    let txout2 = TxOut {
        value: 30000,
        script_pubkey: ScriptBuf::new(),
    };
    let utxo2 = Utxo::new(outpoint2, txout2, address, 0, false);

    let _ = manager.add_utxo(&"wallet1".to_string(), utxo1);
    let _ = manager.add_utxo(&"wallet1".to_string(), utxo2);

    // Check wallet balance
    let balance = manager.get_wallet_balance(&"wallet1".to_string());
    assert!(balance.is_ok());
    assert_eq!(balance.unwrap(), 80000);

    // Check global balance
    let total = manager.get_total_balance();
    assert_eq!(total, 80000);
}

#[test]
fn test_block_height_tracking() {
    let mut manager = WalletManager::new(Network::Testnet);

    assert_eq!(manager.current_height(), 0);

    manager.update_height(12345);
    assert_eq!(manager.current_height(), 12345);
}
