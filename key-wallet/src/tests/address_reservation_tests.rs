//! End-to-end coverage for receive-address reservation through the managed
//! wallet: two reserved hand-outs are distinct, a reservation survives until
//! funds arrive, and the normal transaction-checking path promotes the
//! reserved address to used (clearing the reservation).

use crate::account::{Account, AccountType, ManagedCoreFundsAccount};
use crate::managed_account::address_pool::KeySource;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::managed_account_type::ManagedAccountType;
use crate::mnemonic::{Language, Mnemonic};
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::TransactionContext;
use crate::{ExtendedPrivKey, Network};
use dashcore::{Address, Transaction};
use secp256k1::Secp256k1;
use std::str::FromStr;

#[tokio::test]
async fn test_reserved_receive_address_promotes_on_funding() {
    let mut ctx = TestWalletContext::new_random();
    let xpub = ctx.xpub;

    let revision_before = ctx
        .managed_wallet
        .first_bip44_managed_account_mut()
        .expect("managed account")
        .monitor_revision();

    let a = ctx
        .managed_wallet
        .first_bip44_managed_account_mut()
        .expect("managed account")
        .next_receive_address_and_reserve(Some(&xpub), 1_000)
        .expect("reserve a");
    let b = ctx
        .managed_wallet
        .first_bip44_managed_account_mut()
        .expect("managed account")
        .next_receive_address_and_reserve(Some(&xpub), 1_000)
        .expect("reserve b");

    // Each reservation must bump the monitor revision so observers re-read the
    // address set.
    let revision_after_reserve = ctx
        .managed_wallet
        .first_bip44_managed_account_mut()
        .expect("managed account")
        .monitor_revision();
    assert!(revision_after_reserve > revision_before);

    // Two sequential receive hand-outs return distinct addresses: reserving the
    // first removes it from the available pool seen by the second.
    assert_ne!(a, b);

    // Funds arriving at `a` promote it Reserved -> Used through the normal
    // checker, which clears the reservation at the single mark_used chokepoint.
    let tx = Transaction::dummy(&a, 0..1, &[150_000]);
    let result = ctx.check_transaction(&tx, TransactionContext::Mempool).await;
    assert!(result.is_relevant);

    let acc = ctx.managed_wallet.first_bip44_managed_account_mut().expect("managed account");
    // `a` is used now, so its reservation is already gone: releasing is a no-op.
    assert!(!acc.release_receive_reservation(&a));
    // `b` is still reserved, so releasing it returns it to the available pool
    // and bumps the monitor revision again.
    let revision_before_release = acc.monitor_revision();
    assert!(acc.release_receive_reservation(&b));
    assert!(acc.monitor_revision() > revision_before_release);

    // Releasing an address the pool has never seen is a no-op.
    let stray = Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs")
        .unwrap()
        .require_network(Network::Testnet)
        .unwrap();
    assert!(!acc.release_receive_reservation(&stray));
}

#[test]
fn test_reserve_receive_without_key_source_errors() {
    // A standard account whose external pool has no pre-generated addresses
    // and no key source cannot hand out a reservation.
    let mut account = ManagedCoreFundsAccount::dummy_bip44();
    let err = account
        .next_receive_address_and_reserve(None, 1_000)
        .expect_err("no key source and an empty pool must fail");
    assert_eq!(err, "No unused addresses available and no key source provided");
}

#[test]
fn test_reserve_receive_on_non_standard_account_errors() {
    let network = Network::Testnet;
    let mnemonic = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Language::English,
    )
    .unwrap();
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivKey::new_master(network, &seed).unwrap();
    let secp = Secp256k1::new();

    let account_type = AccountType::CoinJoin {
        index: 0,
    };
    let derivation_path = account_type.derivation_path(network).unwrap();
    let account_key = master.derive_priv(&secp, &derivation_path).unwrap();
    let account = Account::from_xpriv(Some([0u8; 32]), account_type, account_key, network).unwrap();

    let key_source = KeySource::Public(account.account_xpub);
    let managed_type =
        ManagedAccountType::from_account_type(account.account_type, network, &key_source).unwrap();
    let mut managed = ManagedCoreFundsAccount::new(managed_type, network);

    let err = managed
        .next_receive_address_and_reserve(Some(&account.account_xpub), 1_000)
        .expect_err("non-standard account must not hand out receive reservations");
    assert_eq!(err, "Cannot generate receive address for non-standard account type");

    // The sweep wrapper is likewise inert on a non-standard account.
    assert_eq!(managed.sweep_expired_receive_reservations(10_000, 1), 0);
}

#[test]
fn test_sweep_expired_receive_reservations_reclaims_through_account() {
    let mut ctx = TestWalletContext::new_random();
    let xpub = ctx.xpub;

    let acc = ctx.managed_wallet.first_bip44_managed_account_mut().expect("managed account");
    let reserved = acc.next_receive_address_and_reserve(Some(&xpub), 1_000).expect("reserve");
    let revision_after_reserve = acc.monitor_revision();

    // A sweep before the ttl elapses leaves the reservation intact and does not
    // bump the monitor revision.
    assert_eq!(acc.sweep_expired_receive_reservations(1_000, 500), 0);
    assert_eq!(acc.monitor_revision(), revision_after_reserve);

    // Once the reservation is older than the ttl it is reclaimed, the revision
    // bumps, and releasing the now-available address is a no-op.
    assert_eq!(acc.sweep_expired_receive_reservations(2_000, 500), 1);
    assert!(acc.monitor_revision() > revision_after_reserve);
    assert!(!acc.release_receive_reservation(&reserved));
}
