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

/// Add the DashPay receiving account of a friendship and the reverse
/// external account a wallet holding both identities also has. Both derive
/// the same addresses. Returns their account types.
fn befriend_both_ways(ctx: &mut TestWalletContext) -> (AccountType, AccountType) {
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
    (receiving, reverse_external)
}

fn receiving_pool(ctx: &TestWalletContext) -> &AddressPool {
    let account = ctx.managed_wallet.accounts.dashpay_receival_accounts.values().next();
    account.expect("receiving account").managed_account_type().address_pools()[0]
}

fn held_by_receiving(ctx: &TestWalletContext, outpoint: &OutPoint) -> bool {
    let accounts = &ctx.managed_wallet.accounts.dashpay_receival_accounts;
    accounts.values().any(|account| account.utxos.contains_key(outpoint))
}

fn held_by_contact(ctx: &TestWalletContext, outpoint: &OutPoint) -> bool {
    let accounts = &ctx.managed_wallet.accounts.dashpay_external_accounts;
    accounts.values().any(|account| account.utxos.contains_key(outpoint))
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
    befriend_both_ways(&mut ctx);
    let address = receiving_pool(&ctx).address_at_index(0).expect("first address");
    let external = ctx.managed_wallet.accounts.dashpay_external_accounts.values().next();
    assert!(external.expect("external account").contains_script_pub_key(&address.script_pubkey()));
    let (_, utxo) = funded(&address, 0, 29_000);

    let unmatched =
        ctx.managed_wallet.restore_utxos(&ctx.wallet, [utxo.clone()]).expect("restores");

    assert!(unmatched.is_empty());
    assert!(held_by_receiving(&ctx, &utxo.outpoint));
    assert!(!held_by_contact(&ctx, &utxo.outpoint));
}

/// The contact account's pool, derived further, holds a script from the
/// start, while the receiving account reaches it only once the UTXO at the
/// end of its window marks that address used. The UTXO still restores into
/// the receiving account.
#[test]
fn a_receiving_pool_that_reaches_a_script_in_a_later_pass_claims_it() {
    let mut ctx = TestWalletContext::new_random();
    let (receiving, reverse_external) = befriend_both_ways(&mut ctx);
    let pool = receiving_pool(&ctx);
    let last = pool.highest_generated.expect("an initial window");
    let far_index = last + pool.gap_limit;
    let mut far_pool = pool.clone();
    far_pool
        .generate_up_to(far_index, &ctx.wallet.key_source_for_account(receiving))
        .expect("derives");
    let edge = pool.address_at_index(last).expect("derived");
    let far = far_pool.address_at_index(far_index).expect("derived");
    let key_source = ctx.wallet.key_source_for_account(reverse_external);
    let external = ctx.managed_wallet.accounts.dashpay_external_accounts.values_mut().next();
    let external_pools = external.expect("external account").managed_account_type_mut();
    let external_pool = external_pools.address_pools_mut().into_iter().next().expect("a pool");
    external_pool.generate_up_to(far_index, &key_source).expect("derives");
    assert!(external_pool.contains_address(&far));
    let (_, at_edge) = funded(&edge, 0, 10_000);
    let (_, beyond) = funded(&far, 1, 20_000);

    let unmatched = ctx
        .managed_wallet
        .restore_utxos(&ctx.wallet, [beyond.clone(), at_edge.clone()])
        .expect("restores");

    assert!(unmatched.is_empty());
    for utxo in [&at_edge, &beyond] {
        assert!(held_by_receiving(&ctx, &utxo.outpoint));
        assert!(!held_by_contact(&ctx, &utxo.outpoint));
    }
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

/// The restored UTXO keeps the InstantSend lock and trust of the copy it
/// takes out of BIP44, and takes the coin lock of the copies it replaces in
/// place of its own: locked if either the copy CoinJoin held or the one taken
/// out of BIP44 is locked.
#[test_case(true, true, true; "a held lock stays")]
#[test_case(false, false, false; "a held unlock stays")]
#[test_case(false, true, true; "a lock on the misplaced copy stays")]
fn a_restored_utxo_keeps_the_flags_of_the_copies_it_replaces(
    held_locked: bool,
    misplaced_locked: bool,
    expected_locked: bool,
) {
    let mut ctx = TestWalletContext::new_random();
    let (_, mut utxo) = funded(&coinjoin_address(&ctx, 0), 0, 100_000);
    let accounts = &mut ctx.managed_wallet.accounts;
    let mut held = utxo.clone();
    held.is_locked = held_locked;
    accounts.coinjoin_accounts.get_mut(&0).unwrap().utxos.insert(utxo.outpoint, held);
    let mut misplaced = utxo.clone();
    misplaced.is_instantlocked = true;
    misplaced.is_trusted = true;
    misplaced.is_locked = misplaced_locked;
    accounts.standard_bip44_accounts.get_mut(&0).unwrap().utxos.insert(utxo.outpoint, misplaced);
    utxo.is_locked = !(held_locked || misplaced_locked);

    ctx.managed_wallet.restore_utxos(&ctx.wallet, [utxo.clone()]).expect("restores");

    let restored = &ctx.managed_wallet.accounts.coinjoin_accounts[&0].utxos[&utxo.outpoint];
    assert_eq!(restored.is_locked, expected_locked);
    assert!(restored.is_instantlocked);
    assert!(restored.is_trusted);
}

enum SeenSpent {
    InABlock,
    BeforeFunded,
    ByTheAccount,
    ClaimOnly,
}

/// An outpoint the wallet already saw spent is not credited or returned, as
/// when its funding transaction is processed. One spent in a processed block
/// is held as spent before funded; a spent-output claim alone does not hold
/// the UTXO back.
#[test_case(SeenSpent::InABlock, false, true; "spent in a processed block")]
#[test_case(SeenSpent::BeforeFunded, false, true; "held as spent before funded")]
#[test_case(SeenSpent::ByTheAccount, false, false; "spent by the owning account")]
#[test_case(SeenSpent::ClaimOnly, true, false; "only claimed spent")]
#[tokio::test]
async fn an_outpoint_already_seen_spent_is_not_credited(
    seen: SeenSpent,
    credited: bool,
    held_as_spent_before_funded: bool,
) {
    let mut ctx = TestWalletContext::new_random();
    let (_, utxo) = funded(&coinjoin_address(&ctx, 0), 0, 100_000);
    let outpoint = utxo.outpoint;
    match seen {
        SeenSpent::InABlock => {
            ctx.managed_wallet.observed_spent_outpoints.insert(outpoint, 1_001);
        }
        SeenSpent::BeforeFunded => {
            let coinjoin = ctx.managed_wallet.accounts.coinjoin_accounts.get_mut(&0).unwrap();
            coinjoin.spent_before_funded.insert(outpoint, utxo.clone());
        }
        SeenSpent::ByTheAccount => {
            ctx.managed_wallet.restore_utxos(&ctx.wallet, [utxo.clone()]).expect("restores");
            let mut spend = Transaction::dummy(&coinjoin_address(&ctx, 1), 9..10, &[90_000]);
            spend.input[0].previous_output = outpoint;
            let block = TransactionContext::InBlock(BlockInfo::new(
                1_001,
                BlockHash::from_byte_array([0x11; 32]),
                1_700_000_100,
            ));
            ctx.check_transaction(&spend, block).await;
            assert!(!held_by_any_funds_account(&ctx, &outpoint));
            // Only the account's own record of the spend is left to guard it.
            ctx.managed_wallet.observed_spent_outpoints.clear();
        }
        SeenSpent::ClaimOnly => {
            ctx.managed_wallet.spent_claims.insert(outpoint, None);
        }
    }

    let unmatched =
        ctx.managed_wallet.restore_utxos(&ctx.wallet, [utxo.clone()]).expect("restores");

    assert!(unmatched.is_empty());
    assert_eq!(held_by_any_funds_account(&ctx, &outpoint), credited);
    let coinjoin = &ctx.managed_wallet.accounts.coinjoin_accounts[&0];
    assert_eq!(coinjoin.spent_before_funded.contains_key(&outpoint), held_as_spent_before_funded);
}

/// A coin the owning account already recorded spending is held under that
/// spend, as when its funding transaction is processed, so a fork dropping
/// the spend gives the coin back.
#[tokio::test]
async fn a_restored_coin_whose_recorded_spend_a_fork_drops_comes_back() {
    let mut ctx = TestWalletContext::new_random();
    let (_, coin) = funded(&ctx.receive_address, 0, 1_000_000);
    let second_receive = ctx.managed_wallet.accounts.standard_bip44_accounts[&0]
        .managed_account_type()
        .address_pools()[0]
        .address_at_index(1)
        .expect("a second receive address");
    let mut spend = Transaction::dummy(&second_receive, 9..10, &[900_000]);
    spend.input[0].previous_output = coin.outpoint;
    let block = BlockInfo::new(1_001, BlockHash::from_byte_array([0x12; 32]), 1_700_000_200);
    assert!(ctx.check_transaction(&spend, TransactionContext::InBlock(block)).await.is_relevant);

    ctx.managed_wallet.restore_utxos(&ctx.wallet, [coin.clone()]).expect("restores");
    assert!(!held_by_any_funds_account(&ctx, &coin.outpoint));

    ctx.managed_wallet.truncate_above(1_000).expect("truncates");
    ctx.managed_wallet.update_balance();

    assert!(held_by_any_funds_account(&ctx, &coin.outpoint));
    assert_eq!(ctx.managed_wallet.balance.total(), 1_000_000);
}

/// A claimed coin whose funding was processed is kept aside for the claim.
/// Restoring it credits it and no longer keeps it aside, so it is never in
/// both.
#[tokio::test]
async fn a_restored_coin_kept_aside_for_a_claim_leaves_it() {
    let mut ctx = TestWalletContext::new_random();
    let (funding, coin) = funded(&ctx.receive_address, 0, 1_000_000);
    ctx.managed_wallet.restore_spent_outpoints(&[(coin.outpoint, None)]);
    let block = BlockInfo::new(1_000, BlockHash::from_byte_array([0x13; 32]), 1_700_000_300);
    ctx.check_transaction(&funding, TransactionContext::InBlock(block)).await;
    assert!(ctx.bip44_account().claim_guarded_outputs.contains_key(&coin.outpoint));

    ctx.managed_wallet.restore_utxos(&ctx.wallet, [coin.clone()]).expect("restores");

    let bip44 = ctx.bip44_account();
    assert!(bip44.utxos.contains_key(&coin.outpoint));
    assert!(!bip44.claim_guarded_outputs.contains_key(&coin.outpoint));
}
