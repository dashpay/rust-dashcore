//! Tests for spent_outpoints deserialization and tracking.

use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, TxIn, Txid};

use crate::account::{AccountType, StandardAccountType, TransactionRecord};
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::reservation::ReservationToken;
use crate::managed_account::transaction_record::TransactionDirection;
use crate::managed_account::ManagedCoreFundsAccount;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{
    BlockInfo, TransactionCheckResult, TransactionContext, TransactionType,
};
use crate::wallet::initialization::WalletAccountCreationOptions;
use crate::wallet::managed_wallet_info::managed_account_operations::ManagedAccountOperations;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::{ManagedWalletInfo, Wallet};
use crate::Network;

/// The next receive address of BIP44 account `index`.
fn receive_address(wallet: &Wallet, info: &mut ManagedWalletInfo, index: u32) -> dashcore::Address {
    let xpub = wallet.accounts.standard_bip44_accounts[&index].account_xpub;
    let account = info.accounts.standard_bip44_accounts.get_mut(&index).unwrap();
    account.next_receive_address(Some(&xpub), true).unwrap()
}

/// A wallet with `count` BIP44 accounts, and a receive address of each.
fn context_with_accounts(count: u32) -> (TestWalletContext, Vec<dashcore::Address>) {
    let wallet = Wallet::from_seed_bytes(
        [42; 64],
        Network::Testnet,
        WalletAccountCreationOptions::BIP44AccountsOnly((0..count).collect()),
    )
    .unwrap();
    let mut managed_wallet = ManagedWalletInfo::from_wallet(&wallet, 0);
    let addresses: Vec<_> =
        (0..count).map(|index| receive_address(&wallet, &mut managed_wallet, index)).collect();
    let xpub = wallet.accounts.standard_bip44_accounts[&0].account_xpub;
    (
        TestWalletContext {
            wallet,
            managed_wallet,
            receive_address: addresses[0].clone(),
            xpub,
        },
        addresses,
    )
}

fn restore_context() -> (TestWalletContext, dashcore::Address) {
    let (ctx, mut addresses) = context_with_accounts(2);
    (ctx, addresses.remove(1))
}

/// The wallet's claim on `outpoint`: `None` when it holds none, `Some(None)`
/// for a permanent one.
fn claim_on(ctx: &TestWalletContext, outpoint: &OutPoint) -> Option<Option<Txid>> {
    ctx.managed_wallet.spent_claims.get(outpoint).copied()
}

fn second_account(ctx: &TestWalletContext) -> &ManagedCoreFundsAccount {
    &ctx.managed_wallet.accounts.standard_bip44_accounts[&1]
}

fn in_block(height: u32) -> TransactionContext {
    TransactionContext::InBlock(BlockInfo::new(
        height,
        BlockHash::from([height as u8; 32]),
        1_700_000_000,
    ))
}

/// A transaction spending `inputs` and paying `address`.
fn spend_paying(inputs: &[OutPoint], address: &dashcore::Address) -> Transaction {
    let mut tx = spending_tx(inputs);
    tx.output = Transaction::dummy(address, 30..31, &[140_000]).output;
    tx
}

#[tokio::test]
async fn restored_spends_survive_finality_without_records() {
    let (mut ctx, address) = restore_context();
    let funding = Transaction::dummy(&address, 10..11, &[150_000, 90_000]);
    let claims = [
        (OutPoint::new(funding.txid(), 0), None),
        (OutPoint::new(funding.txid(), 1), Some(Txid::from([0x99; 32]))),
    ];
    ctx.managed_wallet.restore_spent_outpoints(&claims);
    ctx.managed_wallet.restore_spent_outpoints(&claims);
    ctx.managed_wallet.restore_spent_outpoints(&[]);
    assert!(ctx.managed_wallet.accounts.all_accounts().iter().all(|a| a.transactions().is_empty()));
    assert!(ctx.managed_wallet.accounts.all_funding_accounts().iter().all(|a| a.utxos.is_empty()));
    assert_eq!(ctx.managed_wallet.balance.total(), 0);
    assert!(ctx.managed_wallet.observed_spent_outpoints().is_empty());
    ctx.managed_wallet.update_synced_height(200);
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(200));
    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    assert!(
        second_account(&ctx).utxos.is_empty(),
        "restored claims must prevent credit without any spending transaction body"
    );
    assert_eq!(ctx.managed_wallet.balance.total(), 0);
}

#[test_case::test_case(false; "conflict")]
#[test_case::test_case(true; "abandonment")]
#[tokio::test]
async fn restored_spends_release_only_removed_claimants(abandon: bool) {
    for kind in 0..3 {
        let (mut ctx, address) = restore_context();
        let funding = Transaction::dummy(&address, 20..21, &[150_000, 90_000]);
        let spent = OutPoint::new(funding.txid(), 0);
        let unrelated = OutPoint::new(funding.txid(), 1);
        let contested = OutPoint::new(Txid::from([0x55; 32]), 0);
        let loser = spend_paying(&[contested, spent], &ctx.receive_address);
        let claimant = match kind {
            0 => Some(loser.txid()),
            1 => None,
            _ => Some(Txid::from([0x99; 32])),
        };
        ctx.managed_wallet.restore_spent_outpoints(&[(spent, claimant), (unrelated, None)]);
        ctx.check_transaction(&loser, TransactionContext::Mempool).await;
        assert!(ctx.bip44_account().has_transaction(&loser.txid()));
        assert!(!second_account(&ctx).has_transaction(&loser.txid()));
        if abandon {
            assert_eq!(ctx.managed_wallet.abandon_transaction(loser.txid()).records_removed, 1);
        } else {
            let result = ctx.check_transaction(&spending_tx(&[contested]), in_block(100)).await;
            assert_eq!(result.swept_transactions, vec![loser.txid()]);
            assert_eq!(result.released_outpoints, Vec::from_iter((kind == 0).then_some(spent)));
        }
        assert_eq!(claim_on(&ctx, &spent), (kind != 0).then_some(claimant));
        assert_eq!(claim_on(&ctx, &unrelated), Some(None));
        ctx.check_transaction(&funding, TransactionContext::Mempool).await;
        let account = second_account(&ctx);
        assert_eq!(
            account.utxos.contains_key(&spent),
            kind == 0,
            "claimant kind {kind}, abandon={abandon}"
        );
        assert!(!account.utxos.contains_key(&unrelated));
    }
}

/// Fund account 0, spend the coin and ChainLock the spend, which leaves the
/// spend as a txid-only record unless `keep-finalized-transactions` is on.
async fn chainlocked_spend_in_first_account(
    ctx: &mut TestWalletContext,
) -> (Transaction, OutPoint) {
    let funding = Transaction::dummy(&ctx.receive_address, 20..21, &[150_000]);
    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    let coin = OutPoint::new(funding.txid(), 0);
    ctx.check_transaction(&spending_tx(&[coin]), in_block(100)).await;
    ctx.managed_wallet.update_synced_height(200);
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(200));
    assert!(ctx.bip44_account().is_outpoint_spent(&coin));
    (funding, coin)
}

/// Releasing a restored claim must not take a mark the claim did not create:
/// account 0 holds its own mark for the coin from a ChainLocked spend.
#[tokio::test]
async fn finalized_mark_outlives_a_released_restored_claim() {
    let (mut ctx, _) = restore_context();
    let (funding, coin) = chainlocked_spend_in_first_account(&mut ctx).await;
    let claimant = Txid::from([0x77; 32]);
    ctx.managed_wallet.restore_spent_outpoints(&[(coin, Some(claimant))]);

    ctx.managed_wallet.abandon_transaction(claimant);

    assert_eq!(claim_on(&ctx, &coin), None);
    assert!(ctx.bip44_account().is_outpoint_spent(&coin));
    ctx.check_transaction(&funding, in_block(90)).await;
    assert!(!ctx.bip44_account().utxos.contains_key(&coin));
}

#[derive(Debug, Clone, Copy)]
enum Claimant {
    Unknown,
    Loser,
    Other,
}

/// One outpoint restored twice, then the loser is abandoned: only an
/// unchanged claimant stays releasable.
#[test_case::test_case(Claimant::Loser, Claimant::Loser, true; "same claimant is idempotent")]
#[test_case::test_case(Claimant::Unknown, Claimant::Loser, false; "unknown then known")]
#[test_case::test_case(Claimant::Loser, Claimant::Unknown, false; "known then unknown")]
#[test_case::test_case(Claimant::Other, Claimant::Loser, false; "other then loser")]
#[test_case::test_case(Claimant::Loser, Claimant::Other, false; "loser then other")]
#[tokio::test]
async fn restoring_an_outpoint_twice_merges_claimants(
    first: Claimant,
    second: Claimant,
    released: bool,
) {
    for one_call in [false, true] {
        let (mut ctx, address) = restore_context();
        let funding = Transaction::dummy(&address, 20..21, &[150_000]);
        let spent = OutPoint::new(funding.txid(), 0);
        let contested = OutPoint::new(Txid::from([0x55; 32]), 0);
        let loser = spend_paying(&[contested, spent], &ctx.receive_address);
        let claim = |claimant| {
            let txid = match claimant {
                Claimant::Unknown => None,
                Claimant::Loser => Some(loser.txid()),
                Claimant::Other => Some(Txid::from([0x99; 32])),
            };
            (spent, txid)
        };
        if one_call {
            ctx.managed_wallet.restore_spent_outpoints(&[claim(first), claim(second)]);
        } else {
            ctx.managed_wallet.restore_spent_outpoints(&[claim(first)]);
            ctx.managed_wallet.restore_spent_outpoints(&[claim(second)]);
        }
        ctx.check_transaction(&loser, TransactionContext::Mempool).await;

        assert_eq!(ctx.managed_wallet.abandon_transaction(loser.txid()).records_removed, 1);

        assert_eq!(claim_on(&ctx, &spent).is_none(), released);
        ctx.check_transaction(&funding, TransactionContext::Mempool).await;
        assert_eq!(
            second_account(&ctx).utxos.contains_key(&spent),
            released,
            "{first:?} then {second:?}, one_call={one_call}"
        );
    }
}

/// The final winner spends the claimed outpoint itself, so the claim turns
/// permanent: a later removed record listing that outpoint cannot release it.
#[tokio::test]
async fn claim_on_winner_input_stays_guarded_after_claimant_is_swept() {
    let (mut ctx, address) = restore_context();
    let funding = Transaction::dummy(&address, 20..21, &[150_000]);
    let spent = OutPoint::new(funding.txid(), 0);
    let loser = spend_paying(&[spent], &ctx.receive_address);
    ctx.managed_wallet.restore_spent_outpoints(&[(spent, Some(loser.txid()))]);
    ctx.check_transaction(&loser, TransactionContext::Mempool).await;

    let result = ctx.check_transaction(&spending_tx(&[spent]), in_block(100)).await;
    assert_eq!(result.swept_transactions, vec![loser.txid()]);
    assert!(result.released_outpoints.is_empty());

    let other = OutPoint::new(Txid::from([0x56; 32]), 0);
    let later = spend_paying(&[spent, other], &ctx.receive_address);
    ctx.check_transaction(&later, TransactionContext::Mempool).await;
    let result = ctx.check_transaction(&spending_tx(&[other]), in_block(101)).await;
    assert_eq!(result.swept_transactions, vec![later.txid()]);
    assert!(result.released_outpoints.is_empty());

    // Past the ChainLock the wallet-level observed-spent entry is pruned, so
    // only the restored claim still guards the outpoint.
    ctx.managed_wallet.update_synced_height(200);
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(200));
    assert!(ctx.managed_wallet.observed_spent_outpoints().is_empty());
    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    assert!(!second_account(&ctx).utxos.contains_key(&spent));
}

/// A final spend settles a recordless claim, so abandoning its claimant then
/// releases nothing; an unconfirmed spend does not, and neither creates a claim.
#[test_case::test_case(in_block(100), true; "spend in a block")]
#[test_case::test_case(
    TransactionContext::InstantSend(InstantLock::default()), true;
    "InstantSend-locked spend"
)]
#[test_case::test_case(TransactionContext::Mempool, false; "unconfirmed spend")]
#[tokio::test]
async fn final_spend_makes_a_recordless_claim_permanent(
    context: TransactionContext,
    is_final: bool,
) {
    let (mut ctx, address) = restore_context();
    let funding = Transaction::dummy(&address, 20..21, &[150_000]);
    let spent = OutPoint::new(funding.txid(), 0);
    let claimant = Txid::from([0x77; 32]);
    ctx.managed_wallet.restore_spent_outpoints(&[(spent, Some(claimant))]);
    let unclaimed = OutPoint::new(Txid::from([0x56; 32]), 0);
    let spend = spending_tx(&[spent, unclaimed]);

    assert!(ctx.managed_wallet.sweep_conflicts(&spend, &context).is_empty());
    assert_eq!(claim_on(&ctx, &unclaimed), None);
    ctx.managed_wallet.abandon_transaction(claimant);

    assert_eq!(claim_on(&ctx, &spent), is_final.then_some(None));
    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    assert_eq!(second_account(&ctx).utxos.contains_key(&spent), !is_final);
}

/// A claim on a loser's own output, naming the loser's child: both are swept,
/// and the output of a deleted transaction is not a coin coming free.
#[tokio::test]
async fn released_claim_on_a_swept_transactions_output_is_not_reported() {
    let (mut ctx, _) = restore_context();
    let contested = OutPoint::new(Txid::from([0x55; 32]), 0);
    let loser = spend_paying(&[contested], &ctx.receive_address);
    let change = OutPoint::new(loser.txid(), 0);
    let child = spend_paying(&[change], &ctx.receive_address);
    ctx.managed_wallet.restore_spent_outpoints(&[(change, Some(child.txid()))]);
    ctx.check_transaction(&loser, TransactionContext::Mempool).await;
    ctx.check_transaction(&child, TransactionContext::Mempool).await;

    let result = ctx.check_transaction(&spending_tx(&[contested]), in_block(100)).await;

    assert_eq!(result.swept_transactions.len(), 2);
    assert!(result.released_outpoints.is_empty());
}

/// Restoring after the funding was delivered cannot take the coin back: the
/// caller is told which guards came too late and the claim is stored all the
/// same, while the coin stays credited and goes on following its funding.
#[tokio::test]
async fn restore_reports_outpoints_still_held_as_utxos() {
    let (mut ctx, address) = restore_context();
    let funding = Transaction::dummy(&address, 20..21, &[150_000]);
    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    let held = OutPoint::new(funding.txid(), 0);
    let absent = OutPoint::new(Txid::from([0x88; 32]), 0);
    let balance = ctx.managed_wallet.balance.total();
    assert_eq!(balance, 150_000);

    let still_held = ctx.managed_wallet.restore_spent_outpoints(&[
        (absent, None),
        (held, None),
        (held, Some(Txid::from([0x99; 32]))),
    ]);

    assert_eq!(still_held, vec![held]);
    assert_eq!(claim_on(&ctx, &held), Some(None));
    assert!(second_account(&ctx).utxos.contains_key(&held));
    assert_eq!(ctx.managed_wallet.balance.total(), balance);
    assert!(ctx.managed_wallet.restore_spent_outpoints(&[(absent, None)]).is_empty());

    ctx.check_transaction(&funding, in_block(100)).await;
    assert!(second_account(&ctx).utxos[&held].is_confirmed);
    assert_eq!(ctx.managed_wallet.balance.confirmed(), balance);
}

/// Claims belong to the wallet, so an account created after the restore is
/// guarded without restoring again.
#[tokio::test]
async fn account_added_after_the_restore_is_guarded() {
    // The seed is fixed, so a twin wallet yields the address account 1 will have.
    let (_, address) = restore_context();
    let funding = Transaction::dummy(&address, 20..21, &[150_000]);
    let coin = OutPoint::new(funding.txid(), 0);
    let (mut ctx, _) = context_with_accounts(1);
    ctx.managed_wallet.restore_spent_outpoints(&[(coin, None)]);

    let account_type = AccountType::Standard {
        index: 1,
        standard_account_type: StandardAccountType::BIP44Account,
    };
    ctx.wallet.add_account(account_type, None).unwrap();
    ctx.managed_wallet.add_managed_account(&ctx.wallet, account_type).unwrap();
    assert_eq!(receive_address(&ctx.wallet, &mut ctx.managed_wallet, 1), address);

    ctx.check_transaction(&funding, TransactionContext::Mempool).await;

    assert!(!second_account(&ctx).utxos.contains_key(&coin));
    assert_eq!(ctx.managed_wallet.balance.total(), 0);
}

/// A wallet with BIP44 account 0 and a contact's watch-only DashPay chain,
/// and an address of the latter.
fn contact_context() -> (TestWalletContext, dashcore::Address) {
    let (mut ctx, _) = context_with_accounts(1);
    let contact = AccountType::DashpayExternalAccount {
        index: 0,
        user_identity_id: [0xaa; 32],
        friend_identity_id: [0xbb; 32],
    };
    ctx.wallet.add_account(contact, None).unwrap();
    ctx.managed_wallet.add_managed_account(&ctx.wallet, contact).unwrap();
    let pool = contact_account(&ctx).managed_account_type().address_pools()[0];
    let address = pool.address_at_index(0).unwrap();
    (ctx, address)
}

fn contact_account(ctx: &TestWalletContext) -> &ManagedCoreFundsAccount {
    ctx.managed_wallet.accounts.dashpay_external_accounts.values().next().unwrap()
}

/// Claims cover a contact's watch-only chain like any account that holds
/// funds: credit blocked, kept output released with the claim, held coin reported.
#[tokio::test]
async fn claims_cover_a_watch_only_contact_account() {
    let (mut ctx, address) = contact_context();
    let funding = Transaction::dummy(&address, 20..21, &[150_000]);
    let coin = OutPoint::new(funding.txid(), 0);
    let claimant = Txid::from([0x77; 32]);
    assert!(ctx.managed_wallet.restore_spent_outpoints(&[(coin, Some(claimant))]).is_empty());

    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    assert!(!contact_account(&ctx).utxos.contains_key(&coin));
    assert!(contact_account(&ctx).claim_guarded_outputs.contains_key(&coin));

    assert_eq!(ctx.managed_wallet.abandon_transaction(claimant).records_removed, 0);
    assert_eq!(claim_on(&ctx, &coin), None);
    assert!(contact_account(&ctx).claim_guarded_outputs.is_empty());
    ctx.check_transaction(&funding, in_block(90)).await;
    assert!(contact_account(&ctx).utxos.contains_key(&coin));

    assert_eq!(ctx.managed_wallet.restore_spent_outpoints(&[(coin, None)]), vec![coin]);
}

/// The mark a contact's watch-only chain keeps from its own ChainLocked spend
/// withholds the coin when a double spend recorded in account 0 is swept.
#[tokio::test]
async fn sweep_withholds_outpoints_a_watch_only_contact_account_still_marks() {
    let (mut ctx, address) = contact_context();
    let funding = Transaction::dummy(&address, 20..21, &[150_000]);
    let coin = OutPoint::new(funding.txid(), 0);
    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    ctx.check_transaction(&spending_tx(&[coin]), in_block(100)).await;
    ctx.managed_wallet.update_synced_height(200);
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(200));
    assert!(contact_account(&ctx).is_outpoint_spent(&coin));
    let contested = OutPoint::new(Txid::from([0x55; 32]), 0);
    let double_spend = spend_paying(&[contested, coin], &ctx.receive_address);
    ctx.check_transaction(&double_spend, TransactionContext::Mempool).await;
    assert!(ctx.bip44_account().has_transaction(&double_spend.txid()));

    let result = ctx.check_transaction(&spending_tx(&[contested]), in_block(201)).await;

    assert_eq!(result.swept_transactions, vec![double_spend.txid()]);
    assert!(result.released_outpoints.is_empty());
    assert!(contact_account(&ctx).is_outpoint_spent(&coin));
    ctx.check_transaction(&funding, in_block(90)).await;
    assert!(!contact_account(&ctx).utxos.contains_key(&coin));
}

/// How a transaction reaches the wallet.
#[derive(Debug, Clone, Copy)]
enum Delivery {
    Mempool,
    Block,
    ChainLockedBlock,
}

impl Delivery {
    fn context(self, height: u32) -> TransactionContext {
        let info = BlockInfo::new(height, BlockHash::from([height as u8; 32]), 1_700_000_000);
        match self {
            Delivery::Mempool => TransactionContext::Mempool,
            Delivery::Block => TransactionContext::InBlock(info),
            Delivery::ChainLockedBlock => TransactionContext::InChainLockedBlock(info),
        }
    }
}

/// When the claim on the coin is restored, relative to its funding.
#[derive(Debug, Clone, Copy)]
enum Restore {
    Never,
    BeforeFunding,
    /// The account holds the funding's record but neither the coin nor its
    /// spender, as after loading a snapshot taken without the spender.
    AfterFundingWasRecorded,
}

/// Direction, net amount, and index and value of each resolved input.
type RecordSummary = (TransactionDirection, i64, Vec<(u32, u64)>);

/// A summary of each record a delivery created.
fn recorded(result: &TransactionCheckResult) -> Vec<RecordSummary> {
    result
        .new_records
        .iter()
        .map(|record| {
            let inputs = record.input_details.iter().map(|d| (d.index, d.value)).collect();
            (record.direction, record.net_amount, inputs)
        })
        .collect()
}

/// Fund account 1 with a 150000 coin, then deliver a spender of it that pays
/// 140000 back to the account or to an outside address. Returns what the
/// spender's delivery reported, the wallet and the coin.
async fn deliver_funding_then_spender(
    restore: Restore,
    claim_names_spender: bool,
    pays_change: bool,
    delivery: Delivery,
) -> (TransactionCheckResult, TestWalletContext, OutPoint) {
    let (mut ctx, address) = restore_context();
    let funding = Transaction::dummy(&address, 20..21, &[150_000]);
    let coin = OutPoint::new(funding.txid(), 0);
    let payee = if pays_change {
        address
    } else {
        dashcore::Address::dummy(Network::Testnet, 0)
    };
    let spender = spend_paying(&[coin], &payee);
    let claim = [(coin, claim_names_spender.then(|| spender.txid()))];
    if matches!(restore, Restore::BeforeFunding) {
        assert!(ctx.managed_wallet.restore_spent_outpoints(&claim).is_empty());
    }
    ctx.check_transaction(&funding, delivery.context(90)).await;
    if matches!(restore, Restore::AfterFundingWasRecorded) {
        let account = ctx.managed_wallet.accounts.standard_bip44_accounts.get_mut(&1).unwrap();
        account.utxos.remove(&coin);
        assert!(ctx.managed_wallet.restore_spent_outpoints(&claim).is_empty());
    }
    let result = ctx.check_transaction(&spender, delivery.context(100)).await;
    (result, ctx, coin)
}

/// The spender of a claimed coin must be recorded exactly as it is in a
/// wallet without the claim, while the coin itself is never credited.
async fn assert_spender_recorded_as_without_the_claim(
    restore: Restore,
    claim_names_spender: bool,
    pays_change: bool,
    delivery: Delivery,
) {
    let (control, control_ctx, _) =
        deliver_funding_then_spender(Restore::Never, claim_names_spender, pays_change, delivery)
            .await;
    let (result, ctx, coin) =
        deliver_funding_then_spender(restore, claim_names_spender, pays_change, delivery).await;

    let expected = if pays_change {
        (TransactionDirection::Internal, -10_000, vec![(0, 150_000)])
    } else {
        (TransactionDirection::Outgoing, -150_000, vec![(0, 150_000)])
    };
    assert_eq!(recorded(&control), vec![expected.clone()], "without the claim");
    assert_eq!(recorded(&result), vec![expected], "with the claim");
    assert!(!second_account(&ctx).utxos.contains_key(&coin));
    assert!(second_account(&ctx).is_outpoint_spent(&coin));
    let balance = ctx.managed_wallet.balance.total();
    assert_eq!(
        balance,
        if pays_change {
            140_000
        } else {
            0
        }
    );
    assert_eq!(balance, control_ctx.managed_wallet.balance.total());
}

/// The claim is restored first, then the funding and its spender arrive.
#[test_case::test_matrix(
    [true, false],
    [true, false],
    [Delivery::Mempool, Delivery::Block, Delivery::ChainLockedBlock]
)]
#[tokio::test]
async fn spender_delivered_after_a_claimed_funding_is_recorded_as_a_spend(
    claim_names_spender: bool,
    pays_change: bool,
    delivery: Delivery,
) {
    assert_spender_recorded_as_without_the_claim(
        Restore::BeforeFunding,
        claim_names_spender,
        pays_change,
        delivery,
    )
    .await;
}

/// The funding's record is already held when the claim is restored, and the
/// funding is not delivered again before the spender.
#[test_case::test_matrix(
    [true, false],
    [true, false],
    [Delivery::Mempool, Delivery::Block]
)]
#[tokio::test]
async fn spender_of_a_coin_claimed_after_its_funding_was_recorded_is_recorded_as_a_spend(
    claim_names_spender: bool,
    pays_change: bool,
    delivery: Delivery,
) {
    assert_spender_recorded_as_without_the_claim(
        Restore::AfterFundingWasRecorded,
        claim_names_spender,
        pays_change,
        delivery,
    )
    .await;
}

/// As above with a ChainLocked funding, whose full record only survives
/// with `keep-finalized-transactions`.
#[cfg(feature = "keep-finalized-transactions")]
#[test_case::test_matrix([true, false], [true, false])]
#[tokio::test]
async fn spender_of_a_coin_claimed_after_its_chainlocked_funding_is_recorded_as_a_spend(
    claim_names_spender: bool,
    pays_change: bool,
) {
    assert_spender_recorded_as_without_the_claim(
        Restore::AfterFundingWasRecorded,
        claim_names_spender,
        pays_change,
        Delivery::ChainLockedBlock,
    )
    .await;
}

/// The spender is seen in a block before the claimed funding, as an out-of-order
/// rescan delivers them: the funding reports the spend's height, and the replay is recorded.
#[tokio::test]
async fn spender_seen_in_a_block_before_a_claimed_funding_is_replayed_and_recorded() {
    let (mut ctx, address) = restore_context();
    let funding = Transaction::dummy(&address, 20..21, &[150_000]);
    let coin = OutPoint::new(funding.txid(), 0);
    let spender = spend_paying(&[coin], &dashcore::Address::dummy(Network::Testnet, 0));
    ctx.managed_wallet.restore_spent_outpoints(&[(coin, Some(spender.txid()))]);
    assert!(!ctx.check_transaction(&spender, in_block(100)).await.is_relevant);

    ctx.check_transaction(&funding, in_block(90)).await;

    assert_eq!(ctx.managed_wallet.unrecorded_spend_heights(&funding), [100].into());
    let replayed = ctx.check_transaction(&spender, in_block(100)).await;
    assert_eq!(
        recorded(&replayed),
        vec![(TransactionDirection::Outgoing, -150_000, vec![(0, 150_000)])]
    );
    assert!(!second_account(&ctx).utxos.contains_key(&coin));
    assert_eq!(ctx.managed_wallet.balance.total(), 0);
}

/// Recording the spender through the kept output adds a mark of its own.
/// Removing that spender again must not free a coin a permanent claim holds.
#[tokio::test]
async fn permanent_claim_outlives_a_recorded_then_abandoned_spender() {
    let (mut ctx, address) = restore_context();
    let funding = Transaction::dummy(&address, 20..21, &[150_000]);
    let coin = OutPoint::new(funding.txid(), 0);
    ctx.managed_wallet.restore_spent_outpoints(&[(coin, None)]);
    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    let spender = spend_paying(&[coin], &address);
    ctx.check_transaction(&spender, TransactionContext::Mempool).await;

    assert_eq!(ctx.managed_wallet.abandon_transaction(spender.txid()).records_removed, 1);

    assert!(!second_account(&ctx).is_outpoint_spent(&coin));
    assert_eq!(claim_on(&ctx, &coin), Some(None));
    ctx.check_transaction(&funding, in_block(90)).await;
    assert!(!second_account(&ctx).utxos.contains_key(&coin));
}

/// Neither the claim nor the output kept for it reaches a snapshot: a wallet
/// reloaded without restoring credits the coin when its funding is delivered
/// again.
#[tokio::test]
async fn output_kept_for_a_claim_is_not_part_of_the_snapshot() {
    let (mut ctx, address) = restore_context();
    let funding = Transaction::dummy(&address, 20..21, &[150_000]);
    let coin = OutPoint::new(funding.txid(), 0);
    ctx.managed_wallet.restore_spent_outpoints(&[(coin, None)]);
    ctx.check_transaction(&funding, TransactionContext::Mempool).await;

    let snapshot = serde_json::to_string(&ctx.managed_wallet).unwrap();
    assert!(!snapshot.contains("spent_claims"));
    ctx.managed_wallet = serde_json::from_str(&snapshot).unwrap();

    assert!(second_account(&ctx).claim_guarded_outputs.is_empty());
    assert!(second_account(&ctx).spent_before_funded.is_empty());
    ctx.check_transaction(&funding, in_block(90)).await;
    assert!(second_account(&ctx).utxos.contains_key(&coin));
}

/// The kept output belongs to its funding transaction and goes when that
/// transaction is removed.
#[test_case::test_case(false; "conflict")]
#[test_case::test_case(true; "abandonment")]
#[tokio::test]
async fn output_kept_for_a_claim_goes_with_its_funding_transaction(abandon: bool) {
    let (mut ctx, address) = restore_context();
    let funding = Transaction::dummy(&address, 20..21, &[150_000]);
    let coin = OutPoint::new(funding.txid(), 0);
    ctx.managed_wallet.restore_spent_outpoints(&[(coin, None)]);
    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    assert!(second_account(&ctx).claim_guarded_outputs.contains_key(&coin));

    if abandon {
        assert_eq!(ctx.managed_wallet.abandon_transaction(funding.txid()).records_removed, 1);
    } else {
        let winner = spending_tx(&[funding.input[0].previous_output]);
        let result = ctx.check_transaction(&winner, in_block(100)).await;
        assert_eq!(result.swept_transactions, vec![funding.txid()]);
    }

    assert!(second_account(&ctx).claim_guarded_outputs.is_empty());
}

/// Create a transaction that spends the given outpoints.
fn spending_tx(spent: &[OutPoint]) -> Transaction {
    Transaction {
        version: 1,
        lock_time: 0,
        input: spent
            .iter()
            .map(|op| TxIn {
                previous_output: *op,
                ..Default::default()
            })
            .collect(),
        output: Vec::new(),
        special_transaction_payload: None,
    }
}

/// Create a receive-only transaction (no meaningful inputs).
fn receive_only_tx() -> Transaction {
    Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn::default()],
        output: Vec::new(),
        special_transaction_payload: None,
    }
}

fn record_from_tx(tx: &Transaction) -> TransactionRecord {
    TransactionRecord::new(
        tx.clone(),
        AccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP44Account,
        },
        TransactionContext::Mempool,
        TransactionType::Standard,
        TransactionDirection::Incoming,
        Vec::new(),
        Vec::new(),
        0,
    )
}

#[test]
fn fresh_account_has_empty_spent_outpoints() {
    let account = ManagedCoreFundsAccount::dummy_bip44();
    assert!(account.transactions().is_empty());

    let probe = OutPoint::new(Txid::from([0xAA; 32]), 0);
    // Accessing spent_outpoints on a fresh account should not panic or misbehave.
    // We verify indirectly via serde round-trip (spent_outpoints is private).
    let json = serde_json::to_string(&account).unwrap();
    let deserialized: ManagedCoreFundsAccount = serde_json::from_str(&json).unwrap();
    // No transactions, so spent_outpoints stays empty after round-trip.
    assert!(deserialized.transactions().is_empty());
    // Confirm the serialized form does not contain spent_outpoints.
    assert!(!json.contains("spent_outpoints"));
    let _ = probe; // used only for clarity of intent
}

#[test]
fn reservations_are_not_persisted() {
    let account = ManagedCoreFundsAccount::dummy_bip44();
    let outpoint = OutPoint::new(Txid::from([0x42; 32]), 0);

    account.reservations().reserve(&[outpoint], 0, ReservationToken::next());
    assert!(account.reservations().reserved(0).contains(&outpoint));

    let json = serde_json::to_string(&account).unwrap();
    assert!(!json.contains("reservations"));

    // After a round-trip the reservation set is empty: it is ephemeral, and on
    // restart chain/mempool sync is the source of truth for spent coins.
    let deserialized: ManagedCoreFundsAccount = serde_json::from_str(&json).unwrap();
    assert!(!deserialized.reservations().reserved(0).contains(&outpoint));
}

#[tokio::test]
async fn processing_a_spend_releases_its_reservation() {
    let (mut ctx, funding_tx) = TestWalletContext::new_random().with_mempool_funding(150_000).await;
    let funded = OutPoint::new(funding_tx.txid(), 0);

    let account = ctx.managed_wallet.first_bip44_managed_account_mut().expect("BIP44 account");
    assert!(account.utxos.contains_key(&funded));
    account.reservations().reserve(&[funded], 0, ReservationToken::next());
    assert!(account.reservations().reserved(0).contains(&funded));

    let spend = spending_tx(&[funded]);
    ctx.check_transaction(&spend, TransactionContext::Mempool).await;

    let account = ctx.managed_wallet.first_bip44_managed_account().expect("BIP44 account");
    assert!(!account.reservations().reserved(0).contains(&funded));

    // The confirmed path releases reservations too: a separate funding tx with
    // a distinct input range yields a second outpoint that is reserved and then
    // spent in a block.
    let second_funding = Transaction::dummy(&ctx.receive_address, 1..2, &[120_000]);
    ctx.check_transaction(&second_funding, TransactionContext::Mempool).await;
    let second_funded = OutPoint::new(second_funding.txid(), 0);

    let account = ctx.managed_wallet.first_bip44_managed_account_mut().expect("BIP44 account");
    assert!(account.utxos.contains_key(&second_funded));
    account.reservations().reserve(&[second_funded], 0, ReservationToken::next());
    assert!(account.reservations().reserved(0).contains(&second_funded));

    let block_hash = BlockHash::from_slice(&[7u8; 32]).expect("hash");
    let confirmed_spend = spending_tx(&[second_funded]);
    ctx.check_transaction(
        &confirmed_spend,
        TransactionContext::InBlock(BlockInfo::new(100, block_hash, 1_700_000_000)),
    )
    .await;

    let account = ctx.managed_wallet.first_bip44_managed_account().expect("BIP44 account");
    assert!(!account.reservations().reserved(0).contains(&second_funded));
}

#[test]
fn serde_round_trip_rebuilds_spent_outpoints() {
    let mut account = ManagedCoreFundsAccount::dummy_bip44();

    let outpoint_a = OutPoint::new(Txid::from([0x01; 32]), 0);
    let outpoint_b = OutPoint::new(Txid::from([0x02; 32]), 1);
    let tx = spending_tx(&[outpoint_a, outpoint_b]);
    let txid = tx.txid();
    account.transactions_mut().insert(txid, record_from_tx(&tx));

    // Serialize (spent_outpoints is skipped)
    let json = serde_json::to_string(&account).unwrap();
    assert!(!json.contains("spent_outpoints"));

    // Deserialize: spent_outpoints should be rebuilt from transactions
    let deserialized: ManagedCoreFundsAccount = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.transactions().len(), 1);

    // Verify the rebuilt set by serializing again and comparing transactions
    // (spent_outpoints is private, so we test behavior through a second round-trip
    //  to confirm stability)
    let json2 = serde_json::to_string(&deserialized).unwrap();
    let deserialized2: ManagedCoreFundsAccount = serde_json::from_str(&json2).unwrap();
    assert_eq!(deserialized2.transactions().len(), 1);
}

#[test]
fn receive_only_account_round_trips_correctly() {
    let mut account = ManagedCoreFundsAccount::dummy_bip44();

    // Add a receive-only transaction (coinbase-like, no real spent outpoints)
    let tx = receive_only_tx();
    let txid = tx.txid();
    account.transactions_mut().insert(txid, record_from_tx(&tx));

    assert_eq!(account.transactions().len(), 1);

    // Round-trip should work without issues (no rebuild loop)
    let json = serde_json::to_string(&account).unwrap();
    let deserialized: ManagedCoreFundsAccount = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.transactions().len(), 1);

    // A second round-trip should be stable
    let json2 = serde_json::to_string(&deserialized).unwrap();
    let deserialized2: ManagedCoreFundsAccount = serde_json::from_str(&json2).unwrap();
    assert_eq!(deserialized2.transactions().len(), 1);
}

#[test]
fn multiple_transactions_all_inputs_tracked_after_round_trip() {
    let mut account = ManagedCoreFundsAccount::dummy_bip44();

    let outpoint_1 = OutPoint::new(Txid::from([0x10; 32]), 0);
    let outpoint_2 = OutPoint::new(Txid::from([0x20; 32]), 0);
    let outpoint_3 = OutPoint::new(Txid::from([0x30; 32]), 2);

    let tx1 = spending_tx(&[outpoint_1]);
    let tx2 = spending_tx(&[outpoint_2, outpoint_3]);

    account.transactions_mut().insert(tx1.txid(), record_from_tx(&tx1));
    account.transactions_mut().insert(tx2.txid(), record_from_tx(&tx2));

    let json = serde_json::to_string(&account).unwrap();
    let deserialized: ManagedCoreFundsAccount = serde_json::from_str(&json).unwrap();

    // All three outpoints should be in the rebuilt spent set.
    // We verify by confirming the transaction inputs survived the round-trip.
    let all_spent: Vec<OutPoint> = deserialized
        .transactions()
        .values()
        .flat_map(|r| &r.transaction.input)
        .map(|inp| inp.previous_output)
        .collect();
    assert!(all_spent.contains(&outpoint_1));
    assert!(all_spent.contains(&outpoint_2));
    assert!(all_spent.contains(&outpoint_3));
    assert_eq!(all_spent.len(), 3);
}
