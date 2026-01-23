//! Tests for update_balance() UTXO categorization.

use crate::managed_account::ManagedCoreAccount;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::managed_wallet_info::ManagedWalletInfo;
use crate::{Utxo, WalletCoreBalance};

#[test]
fn test_balance_with_mixed_utxo_types() {
    let mut wallet_info = ManagedWalletInfo::dummy(1);
    let mut account = ManagedCoreAccount::dummy_bip44();

    // Regular confirmed UTXO
    let utxo1 = Utxo::dummy(1, 100_000, 1000, false, true);
    account.utxos.insert(utxo1.outpoint, utxo1);
    // Mature coinbase (100+ confirmations at height 1100)
    let utxo2 = Utxo::dummy(2, 10_000_000, 1000, true, true);
    account.utxos.insert(utxo2.outpoint, utxo2);
    // Immature coinbase (<100 confirmations at height 1100)
    let utxo3 = Utxo::dummy(3, 20_000_000, 1050, true, true);
    account.utxos.insert(utxo3.outpoint, utxo3);
    wallet_info.accounts.insert(account);

    assert_eq!(wallet_info.balance(), WalletCoreBalance::default());
    wallet_info.update_synced_height(1100);
    let expected = WalletCoreBalance::new(10_100_000, 0, 20_000_000, 0);
    assert_eq!(wallet_info.balance(), expected);
}

#[test]
fn test_coinbase_maturity_boundary() {
    let mut wallet_info = ManagedWalletInfo::dummy(2);
    let mut account = ManagedCoreAccount::dummy_bip44();

    // Coinbase at height 1000
    let utxo = Utxo::dummy(1, 50_000_000, 1000, true, true);
    account.utxos.insert(utxo.outpoint, utxo);
    wallet_info.accounts.insert(account);

    assert_eq!(wallet_info.balance(), WalletCoreBalance::default());
    // 99 confirmations: immature
    wallet_info.update_synced_height(1099);
    let expected_immature = WalletCoreBalance::new(0, 0, 50_000_000, 0);
    assert_eq!(wallet_info.balance(), expected_immature);

    // 100 confirmations: mature
    wallet_info.update_synced_height(1100);
    let expected_mature = WalletCoreBalance::new(50_000_000, 0, 0, 0);
    assert_eq!(wallet_info.balance(), expected_mature);
}

#[test]
fn test_locked_utxos_in_locked_balance() {
    let mut wallet_info = ManagedWalletInfo::dummy(3);
    let mut account = ManagedCoreAccount::dummy_bip44();

    let mut utxo = Utxo::dummy(1, 100_000, 1000, false, true);
    utxo.is_locked = true;
    account.utxos.insert(utxo.outpoint, utxo);
    wallet_info.accounts.insert(account);

    assert_eq!(wallet_info.balance(), WalletCoreBalance::default());
    wallet_info.update_synced_height(1100);
    let expected = WalletCoreBalance::new(0, 0, 0, 100_000);
    assert_eq!(wallet_info.balance(), expected);
}

#[test]
fn test_unconfirmed_utxos_in_unconfirmed_balance() {
    let mut wallet_info = ManagedWalletInfo::dummy(4);
    let mut account = ManagedCoreAccount::dummy_bip44();

    let utxo = Utxo::dummy(1, 100_000, 0, false, false);
    account.utxos.insert(utxo.outpoint, utxo);
    wallet_info.accounts.insert(account);

    assert_eq!(wallet_info.balance(), WalletCoreBalance::default());
    wallet_info.update_synced_height(1100);
    let expected = WalletCoreBalance::new(0, 100_000, 0, 0);
    assert_eq!(wallet_info.balance(), expected);
}
