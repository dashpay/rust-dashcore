//! Tests for methods added to support changeset-based persistence:
//! - `ManagedCoreAccount::insert_utxo` / `remove_utxo` (idempotent wrappers)
//! - `ManagedAccountCollection::get_by_account_type_mut` (apply routing)
//! - `Wallet::add_account` idempotency (deterministic derivation path)

use crate::account::{AccountType, StandardAccountType};
use crate::managed_account::ManagedCoreAccount;
use crate::wallet::managed_wallet_info::ManagedWalletInfo;
use crate::wallet::{initialization::WalletAccountCreationOptions, Wallet};
use crate::{Network, Utxo};

// ---------------------------------------------------------------------------
// ManagedCoreAccount::insert_utxo / remove_utxo
// ---------------------------------------------------------------------------

#[test]
fn insert_utxo_returns_true_on_new_entry() {
    let mut account = ManagedCoreAccount::dummy_bip44();
    let utxo = Utxo::dummy(1, 100_000, 10, false, true);
    let outpoint = utxo.outpoint;

    assert!(account.insert_utxo(outpoint, utxo), "new insert should return true");
    assert_eq!(account.utxos.len(), 1);
    assert!(account.utxos.contains_key(&outpoint));
}

#[test]
fn insert_utxo_returns_false_on_existing_entry() {
    let mut account = ManagedCoreAccount::dummy_bip44();
    let utxo = Utxo::dummy(1, 100_000, 10, false, true);
    let outpoint = utxo.outpoint;

    // First insert — new
    assert!(account.insert_utxo(outpoint, utxo.clone()));
    // Second insert with same outpoint — replace, returns false
    assert!(!account.insert_utxo(outpoint, utxo), "duplicate insert should return false");
    // Still only one UTXO in the map
    assert_eq!(account.utxos.len(), 1);
}

#[test]
fn remove_utxo_returns_the_removed_value() {
    let mut account = ManagedCoreAccount::dummy_bip44();
    let utxo = Utxo::dummy(1, 100_000, 10, false, true);
    let outpoint = utxo.outpoint;
    let expected_value = utxo.txout.value;
    account.insert_utxo(outpoint, utxo);

    let removed = account.remove_utxo(&outpoint);
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().txout.value, expected_value);
    assert!(account.utxos.is_empty());
}

#[test]
fn remove_utxo_returns_none_for_missing_entry() {
    let mut account = ManagedCoreAccount::dummy_bip44();
    let utxo = Utxo::dummy(1, 100_000, 10, false, true);
    let outpoint = utxo.outpoint;

    // No insert — removal is a no-op that returns None.
    assert!(account.remove_utxo(&outpoint).is_none());
}

#[test]
fn insert_remove_is_idempotent_for_replay() {
    // Simulates `apply(changeset)` replaying the same changeset twice:
    // the end state must be identical.
    let mut account = ManagedCoreAccount::dummy_bip44();
    let utxo = Utxo::dummy(1, 100_000, 10, false, true);
    let outpoint = utxo.outpoint;

    // First replay
    account.insert_utxo(outpoint, utxo.clone());
    let snapshot_after_first = account.utxos.clone();

    // Second replay with same data — should be a no-op semantically
    account.insert_utxo(outpoint, utxo);
    assert_eq!(account.utxos, snapshot_after_first);
}

// ---------------------------------------------------------------------------
// Wallet::add_account idempotency (Phase 1 change)
// ---------------------------------------------------------------------------

#[test]
fn add_account_idempotent_when_xpub_is_none() {
    let mut wallet = Wallet::new_random(
        Network::Testnet,
        WalletAccountCreationOptions::None,
    )
    .unwrap();

    let acct_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    };

    // First call creates the account.
    assert!(wallet.add_account(acct_type, None).is_ok());
    let count_after_first = wallet.accounts.count();

    // Second call with None xpub is idempotent (derived from seed → same result).
    assert!(wallet.add_account(acct_type, None).is_ok());
    assert_eq!(
        wallet.accounts.count(),
        count_after_first,
        "idempotent add should not create a duplicate"
    );

    // Third call — same idempotency.
    assert!(wallet.add_account(acct_type, None).is_ok());
    assert_eq!(wallet.accounts.count(), count_after_first);
}

#[test]
fn add_account_errors_when_explicit_xpub_collides() {
    // If an explicit xpub is provided for an already-existing account type,
    // we must reject it to avoid silently overwriting with different keys.
    let mut wallet = Wallet::new_random(
        Network::Testnet,
        WalletAccountCreationOptions::None,
    )
    .unwrap();

    let acct_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    };

    // Create the account via derivation.
    wallet.add_account(acct_type, None).unwrap();

    // Get the derived xpub so we can try to re-add with it.
    let existing_xpub = wallet
        .accounts
        .account_of_type(acct_type)
        .expect("account should exist")
        .account_xpub;

    // Explicit xpub for existing account type → error (even if it's the same xpub).
    let result = wallet.add_account(acct_type, Some(existing_xpub));
    assert!(
        result.is_err(),
        "explicit xpub for existing account type must return an error"
    );
}

// ---------------------------------------------------------------------------
// ManagedAccountCollection::get_by_account_type_mut — direct routing for
// apply_changeset's per_account bucket delegation.
// ---------------------------------------------------------------------------

#[test]
fn get_by_account_type_mut_finds_bip44_account() {
    let wallet =
        Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::Default)
            .expect("wallet");
    let mut info = ManagedWalletInfo::from_wallet(&wallet);

    let ty = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    };
    let found = info.accounts.get_by_account_type_mut(ty);
    assert!(found.is_some(), "default wallet must expose BIP44-0 by AccountType");
}

#[test]
fn get_by_account_type_mut_returns_none_for_missing_account_type() {
    let wallet =
        Wallet::new_random(Network::Testnet, WalletAccountCreationOptions::None)
            .expect("wallet");
    let mut info = ManagedWalletInfo::from_wallet(&wallet);

    let ty = AccountType::Standard {
        index: 42,
        standard_account_type: StandardAccountType::BIP44Account,
    };
    assert!(info.accounts.get_by_account_type_mut(ty).is_none());
}
