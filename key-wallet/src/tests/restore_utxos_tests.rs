//! `ManagedWalletInfo::restore_utxos` places each UTXO in the account that
//! owns its address (#1294).

use dashcore::hashes::Hash;
use dashcore::{Address, BlockHash, OutPoint, Transaction};
use test_case::test_case;

use crate::account::AccountType;
use crate::managed_account::address_pool::AddressPool;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext};
use crate::wallet::managed_wallet_info::managed_account_operations::ManagedAccountOperations;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::{KeySource, ManagedAccountType, Utxo};

/// The external pool of CoinJoin account 0.
fn coinjoin_pool(ctx: &TestWalletContext) -> &AddressPool {
    match ctx.managed_wallet.accounts.coinjoin_accounts[&0].managed_account_type() {
        ManagedAccountType::CoinJoin {
            external_addresses,
            ..
        } => external_addresses,
        _ => unreachable!("a CoinJoin account carries the CoinJoin managed type"),
    }
}

/// The CoinJoin account 0 external address at `index`, derived on a copy of
/// the pool so the wallet's own pool stays as it is.
fn coinjoin_address(ctx: &TestWalletContext, index: u32) -> Address {
    let xpub = ctx.wallet.get_coinjoin_account(0).expect("CoinJoin account").account_xpub;
    let mut pool = coinjoin_pool(ctx).clone();
    pool.generate_up_to(index, &KeySource::Public(xpub)).expect("derives");
    pool.address_at_index(index).expect("derived")
}

/// A confirmed UTXO paying `value` to `address`, with its funding transaction.
fn funded(address: &Address, input: u8, value: u64) -> (Transaction, Utxo) {
    let tx = Transaction::dummy(address, input..input + 1, &[value]);
    let mut utxo =
        Utxo::new(OutPoint::new(tx.txid(), 0), tx.output[0].clone(), address.clone(), 1_000, false);
    utxo.is_confirmed = true;
    (tx, utxo)
}

fn held_by_any_funds_account(ctx: &TestWalletContext, outpoint: &OutPoint) -> bool {
    ctx.managed_wallet
        .accounts
        .all_funding_accounts()
        .iter()
        .any(|account| account.utxos.contains_key(outpoint))
}

/// A CoinJoin address first derived during a sync is beyond the window a
/// fresh wallet holds. Its UTXO restores into CoinJoin once the UTXO at the
/// window's last address marks that address used, not into BIP44, and a
/// rescan of its funding transaction counts it once.
#[tokio::test]
async fn a_coinjoin_utxo_past_the_stored_window_restores_into_coinjoin() {
    let mut ctx = TestWalletContext::new_random();
    let gap = coinjoin_pool(&ctx).gap_limit;
    assert_eq!(coinjoin_pool(&ctx).highest_generated, Some(gap - 1));
    let (_, inside) = funded(&coinjoin_address(&ctx, gap - 1), 0, 100_000);
    let (beyond_tx, beyond) = funded(&coinjoin_address(&ctx, 2 * gap - 1), 1, 200_000);

    let unmatched = ctx
        .managed_wallet
        .restore_utxos(&ctx.wallet, [beyond.clone(), inside.clone()])
        .expect("restores");

    assert!(unmatched.is_empty());
    let accounts = &ctx.managed_wallet.accounts;
    for utxo in [&inside, &beyond] {
        assert!(accounts.coinjoin_accounts[&0].utxos.contains_key(&utxo.outpoint));
        assert!(!accounts.standard_bip44_accounts[&0].utxos.contains_key(&utxo.outpoint));
    }

    let block = TransactionContext::InBlock(BlockInfo::new(
        1_000,
        BlockHash::from_byte_array([0x10; 32]),
        1_700_000_000,
    ));
    ctx.check_transaction(&beyond_tx, block).await;
    assert_eq!(ctx.managed_wallet.balance.total(), 300_000);
}

/// A UTXO no account's pools reach comes back to the caller and is placed in
/// no account.
#[test_case(false; "foreign script")]
#[test_case(true; "coinjoin address past the reach")]
fn a_utxo_matching_no_account_comes_back(ours_but_unreachable: bool) {
    let mut ctx = TestWalletContext::new_random();
    let address = if ours_but_unreachable {
        let gap = coinjoin_pool(&ctx).gap_limit;
        coinjoin_address(&ctx, 2 * gap)
    } else {
        TestWalletContext::new_random().receive_address
    };
    let (_, utxo) = funded(&address, 0, 100_000);

    let unmatched =
        ctx.managed_wallet.restore_utxos(&ctx.wallet, [utxo.clone()]).expect("restores");

    assert_eq!(unmatched, std::slice::from_ref(&utxo));
    assert!(!held_by_any_funds_account(&ctx, &utxo.outpoint));
}

/// A wallet holding both identities of a friendship derives the same
/// addresses for its receiving chain and for the reverse external chain. A
/// UTXO at such an address restores into the receiving account, whose coins
/// are the wallet's.
#[test]
fn a_utxo_both_a_receiving_and_a_contact_account_hold_restores_into_the_receiving_one() {
    let mut ctx = TestWalletContext::new_random();
    let (us, them) = ([0xaa; 32], [0xbb; 32]);
    let receiving = AccountType::DashpayReceivingFunds {
        index: 0,
        user_identity_id: us,
        friend_identity_id: them,
    };
    let reverse_external = AccountType::DashpayExternalAccount {
        index: 0,
        user_identity_id: them,
        friend_identity_id: us,
    };
    for contact in [receiving, reverse_external] {
        ctx.wallet.add_account(contact, None).expect("contact account is addable");
        ctx.managed_wallet
            .add_managed_account(&ctx.wallet, contact)
            .expect("contact account is manageable");
    }
    let accounts = &ctx.managed_wallet.accounts;
    let address = accounts
        .dashpay_receival_accounts
        .values()
        .next()
        .expect("receiving account")
        .managed_account_type()
        .address_pools()[0]
        .address_at_index(0)
        .expect("first address");
    let external = accounts.dashpay_external_accounts.values().next().expect("external account");
    assert!(external.contains_script_pub_key(&address.script_pubkey()));
    let (_, utxo) = funded(&address, 0, 29_000);

    let unmatched =
        ctx.managed_wallet.restore_utxos(&ctx.wallet, [utxo.clone()]).expect("restores");

    assert!(unmatched.is_empty());
    let accounts = &ctx.managed_wallet.accounts;
    assert!(accounts
        .dashpay_receival_accounts
        .values()
        .any(|a| a.utxos.contains_key(&utxo.outpoint)));
    assert!(!accounts
        .dashpay_external_accounts
        .values()
        .any(|a| a.utxos.contains_key(&utxo.outpoint)));
}

/// A pool already marked used up to the end of its window, as restored pool
/// state can leave it, is extended before matching, so a UTXO one gap past
/// that address restores without a UTXO at the used address.
#[test]
fn a_pool_restored_as_used_is_extended_before_matching() {
    let mut ctx = TestWalletContext::new_random();
    let gap = coinjoin_pool(&ctx).gap_limit;
    let used = coinjoin_address(&ctx, gap - 1);
    ctx.managed_wallet.accounts.coinjoin_accounts.get_mut(&0).unwrap().mark_address_used(&used);
    let (_, utxo) = funded(&coinjoin_address(&ctx, 2 * gap - 1), 0, 100_000);

    let unmatched =
        ctx.managed_wallet.restore_utxos(&ctx.wallet, [utxo.clone()]).expect("restores");

    assert!(unmatched.is_empty());
    assert!(ctx.managed_wallet.accounts.coinjoin_accounts[&0].utxos.contains_key(&utxo.outpoint));
}

/// A copy BIP44 already holds of a CoinJoin UTXO, as an earlier restore into
/// account 0 leaves it, is taken out when the UTXO is restored, so the
/// balance counts it once.
#[test]
fn a_copy_another_account_holds_is_taken_out_on_restore() {
    let mut ctx = TestWalletContext::new_random();
    let (_, utxo) = funded(&coinjoin_address(&ctx, 0), 0, 100_000);
    let bip44 = ctx.managed_wallet.accounts.standard_bip44_accounts.get_mut(&0).unwrap();
    bip44.utxos.insert(utxo.outpoint, utxo.clone());
    let bip44_revision = bip44.monitor_revision();

    let unmatched =
        ctx.managed_wallet.restore_utxos(&ctx.wallet, [utxo.clone()]).expect("restores");

    assert!(unmatched.is_empty());
    let accounts = &ctx.managed_wallet.accounts;
    assert!(accounts.coinjoin_accounts[&0].utxos.contains_key(&utxo.outpoint));
    assert!(!accounts.standard_bip44_accounts[&0].utxos.contains_key(&utxo.outpoint));
    assert!(accounts.standard_bip44_accounts[&0].monitor_revision() > bip44_revision);
    ctx.managed_wallet.update_balance();
    assert_eq!(ctx.managed_wallet.balance.total(), 100_000);
}
