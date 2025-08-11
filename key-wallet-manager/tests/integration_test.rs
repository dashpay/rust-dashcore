//! Integration tests for key-wallet-manager
//!
//! These tests verify that the high-level wallet management functionality
//! works correctly with the low-level key-wallet primitives.

use key_wallet::{Mnemonic, Network, WalletConfig};
use key_wallet_manager::{FeeLevel, SelectionStrategy, WalletManager};

#[test]
fn test_wallet_manager_creation() {
    // Create a wallet manager with default config
    let config = WalletConfig::new().network(Network::Testnet).account_count(1);

    let manager = WalletManager::new(config);
    assert!(manager.is_ok());

    let mut manager = manager.unwrap();
    assert_eq!(manager.block_height(), 0);
    assert_eq!(manager.accounts().len(), 1);
}

#[test]
fn test_wallet_manager_from_mnemonic() {
    // Create from a test mnemonic
    let mnemonic = Mnemonic::generate();
    let config = WalletConfig::new().network(Network::Testnet).account_count(2);

    let manager = WalletManager::from_mnemonic(mnemonic.clone(), config);
    assert!(manager.is_ok());

    let manager = manager.unwrap();
    assert!(manager.mnemonic().is_some());
    assert_eq!(manager.mnemonic().unwrap(), &mnemonic);
    assert_eq!(manager.accounts().len(), 2);
}

#[test]
fn test_account_management() {
    let config = WalletConfig::new().network(Network::Testnet).account_count(1);

    let mut manager = WalletManager::new(config).unwrap();

    // Add a new account
    let account = manager.add_account("Savings");
    assert!(account.is_ok());
    assert_eq!(manager.accounts().len(), 2);

    // Get account by index
    let account = manager.get_account(0);
    assert!(account.is_some());
    assert_eq!(account.unwrap().name(), "Main Account");

    let account = manager.get_account(1);
    assert!(account.is_some());
    assert_eq!(account.unwrap().name(), "Savings");
}

#[test]
fn test_address_generation() {
    let config = WalletConfig::new().network(Network::Testnet).account_count(1);

    let mut manager = WalletManager::new(config).unwrap();

    // Generate receive address
    let address1 = manager.get_receive_address(0);
    assert!(address1.is_ok());

    let address2 = manager.get_receive_address(0);
    assert!(address2.is_ok());

    // Addresses should be different
    assert_ne!(address1.unwrap(), address2.unwrap());

    // Generate change address
    let change = manager.get_change_address(0);
    assert!(change.is_ok());
}

#[test]
fn test_utxo_management() {
    use dashcore::blockdata::script::ScriptBuf;
    use dashcore::blockdata::transaction::{OutPoint, TxOut};
    use dashcore::hash_types::Txid;
    use dashcore_hashes::Hash;
    use key_wallet::Address;
    use key_wallet_manager::Utxo;

    let config = WalletConfig::new().network(Network::Testnet).account_count(1);

    let mut manager = WalletManager::new(config).unwrap();

    // Create a test UTXO
    let outpoint = OutPoint {
        txid: Txid::from_slice(&[1u8; 32]).unwrap(),
        vout: 0,
    };

    let txout = TxOut {
        value: 100000,
        script_pubkey: ScriptBuf::new(),
    };

    let address = manager.get_receive_address(0).unwrap();
    let utxo = Utxo::new(outpoint, txout, address, 100, false);

    // Add UTXO
    manager.add_utxo(utxo.clone());
    assert_eq!(manager.utxo_set().count(), 1);
    assert_eq!(manager.utxo_set().total_balance(), 100000);

    // Remove UTXO
    let removed = manager.remove_utxo(&outpoint);
    assert!(removed.is_some());
    assert_eq!(manager.utxo_set().count(), 0);
}

#[test]
fn test_balance_calculation() {
    use dashcore::blockdata::script::ScriptBuf;
    use dashcore::blockdata::transaction::{OutPoint, TxOut};
    use dashcore::hash_types::Txid;
    use dashcore_hashes::Hash;
    use key_wallet_manager::Utxo;

    let config = WalletConfig::new().network(Network::Testnet).account_count(1);

    let mut manager = WalletManager::new(config).unwrap();
    let address = manager.get_receive_address(0).unwrap();

    // Add confirmed UTXO
    let outpoint1 = OutPoint {
        txid: Txid::from_slice(&[1u8; 32]).unwrap(),
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
        txid: Txid::from_slice(&[2u8; 32]).unwrap(),
        vout: 0,
    };
    let txout2 = TxOut {
        value: 30000,
        script_pubkey: ScriptBuf::new(),
    };
    let utxo2 = Utxo::new(outpoint2, txout2, address, 0, false);

    manager.add_utxo(utxo1);
    manager.add_utxo(utxo2);

    let balance = manager.total_balance();
    assert_eq!(balance.confirmed, 50000);
    assert_eq!(balance.unconfirmed, 30000);
    assert_eq!(balance.total, 80000);
}

#[test]
fn test_block_height_tracking() {
    let config = WalletConfig::new().network(Network::Testnet).account_count(1);

    let mut manager = WalletManager::new(config).unwrap();

    assert_eq!(manager.block_height(), 0);

    manager.set_block_height(12345);
    assert_eq!(manager.block_height(), 12345);
}
