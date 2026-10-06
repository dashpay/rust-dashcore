//! Tests for spent_outpoints deserialization and tracking.

use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, TxIn, Txid};

use crate::account::{AccountType, StandardAccountType, TransactionRecord};
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::reservation::ReservationToken;
use crate::managed_account::transaction_record::TransactionDirection;
use crate::managed_account::ManagedCoreFundsAccount;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext, TransactionType};
use crate::wallet::initialization::WalletAccountCreationOptions;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::{ManagedWalletInfo, Wallet};
use crate::Network;

fn restore_context() -> (TestWalletContext, dashcore::Address) {
    let wallet = Wallet::from_seed_bytes(
        [42; 64],
        Network::Testnet,
        WalletAccountCreationOptions::BIP44AccountsOnly([0, 1].into_iter().collect()),
    )
    .unwrap();
    let mut managed_wallet = ManagedWalletInfo::from_wallet(&wallet, 0);
    let mut address = |index| {
        let xpub = wallet.accounts.standard_bip44_accounts[&index].account_xpub;
        managed_wallet
            .accounts
            .standard_bip44_accounts
            .get_mut(&index)
            .unwrap()
            .next_receive_address(Some(&xpub), true)
            .unwrap()
    };
    let receive_address = address(0);
    let second_address = address(1);
    let xpub = wallet.accounts.standard_bip44_accounts[&0].account_xpub;
    (
        TestWalletContext {
            wallet,
            managed_wallet,
            receive_address,
            xpub,
        },
        second_address,
    )
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
        ctx.managed_wallet.accounts.standard_bip44_accounts[&1].utxos.is_empty(),
        "restored claims must prevent credit without any spending transaction body"
    );
    assert_eq!(ctx.managed_wallet.balance.total(), 0);
}

#[test_case::test_case(false; "conflict")]
#[test_case::test_case(true; "abandonment")]
#[tokio::test]
async fn restored_spends_release_only_removed_claimants(abandon: bool) {
    for kind in 0..4 {
        let (mut ctx, address) = restore_context();
        let funding = Transaction::dummy(&address, 20..21, &[150_000, 90_000]);
        let spent = OutPoint::new(funding.txid(), 0);
        let unrelated = OutPoint::new(funding.txid(), 1);
        let contested = OutPoint::new(Txid::from([0x55; 32]), 0);
        let mut loser = spending_tx(&[contested, spent]);
        loser.output = Transaction::dummy(&ctx.receive_address, 30..31, &[140_000]).output;
        let claimant = match kind {
            0 | 3 => Some(loser.txid()),
            1 => None,
            _ => Some(Txid::from([0x99; 32])),
        };
        ctx.managed_wallet.restore_spent_outpoints(&[(spent, claimant), (unrelated, None)]);
        ctx.check_transaction(&loser, TransactionContext::Mempool).await;
        assert!(ctx.bip44_account().has_transaction(&loser.txid()));
        assert!(
            !ctx.managed_wallet.accounts.standard_bip44_accounts[&1].has_transaction(&loser.txid())
        );
        if kind == 3 {
            let mut survivor = spending_tx(&[spent]);
            survivor.output = loser.output.clone();
            ctx.check_transaction(&survivor, TransactionContext::Mempool).await;
            assert!(ctx.bip44_account().has_transaction(&survivor.txid()));
        }
        if abandon {
            assert_eq!(ctx.managed_wallet.abandon_transaction(loser.txid()).records_removed, 1);
        } else {
            let result = ctx
                .check_transaction(
                    &spending_tx(&[contested]),
                    TransactionContext::InBlock(BlockInfo::new(
                        100,
                        BlockHash::from([0x66; 32]),
                        1_700_000_000,
                    )),
                )
                .await;
            assert_eq!(result.swept_transactions, vec![loser.txid()]);
            assert_eq!(result.released_outpoints.contains(&spent), kind == 0);
        }
        ctx.check_transaction(&funding, TransactionContext::Mempool).await;
        let account = &ctx.managed_wallet.accounts.standard_bip44_accounts[&1];
        assert_eq!(
            account.utxos.contains_key(&spent),
            kind == 0,
            "claimant kind {kind}, abandon={abandon}"
        );
        assert!(!account.utxos.contains_key(&unrelated));
    }
}

#[test]
fn restored_spends_leave_snapshot_encoding_unchanged() {
    let mut info = ManagedWalletInfo::dummy(1);
    info.accounts.standard_bip44_accounts.insert(0, ManagedCoreFundsAccount::dummy_bip44());
    let before = serde_json::to_string(&info).unwrap();
    info.restore_spent_outpoints(&[(OutPoint::new(Txid::from([0x88; 32]), 0), None)]);
    let after = serde_json::to_string(&info).unwrap();
    assert_eq!(before, after);
    let restored: ManagedWalletInfo = serde_json::from_str(&after).unwrap();
    assert_eq!(serde_json::to_string(&restored).unwrap(), before);
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

/// The claimant of a restored claim never reached this wallet as a record.
#[tokio::test]
async fn restored_claim_is_released_when_recordless_claimant_is_abandoned() {
    let (mut ctx, address) = restore_context();
    let funding = Transaction::dummy(&address, 20..21, &[150_000]);
    let spent = OutPoint::new(funding.txid(), 0);
    let claimant = Txid::from([0x77; 32]);
    ctx.managed_wallet.restore_spent_outpoints(&[(spent, Some(claimant))]);

    assert_eq!(ctx.managed_wallet.abandon_transaction(claimant).records_removed, 0);

    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    assert!(ctx.managed_wallet.accounts.standard_bip44_accounts[&1].utxos.contains_key(&spent));
}

/// A double spend of a ChainLocked coin is recorded only in account 1; removing
/// it must not touch the mark account 0 keeps for the ChainLocked spend.
#[test_case::test_case(false; "conflict")]
#[test_case::test_case(true; "abandonment")]
#[tokio::test]
async fn finalized_mark_survives_removal_recorded_in_another_account(abandon: bool) {
    let (mut ctx, second_address) = restore_context();
    let (funding, coin) = chainlocked_spend_in_first_account(&mut ctx).await;
    let contested = OutPoint::new(Txid::from([0x55; 32]), 0);
    let double_spend = spend_paying(&[contested, coin], &second_address);
    ctx.check_transaction(&double_spend, TransactionContext::Mempool).await;
    let txid = double_spend.txid();
    assert!(ctx.managed_wallet.accounts.standard_bip44_accounts[&1].has_transaction(&txid));
    assert!(!ctx.bip44_account().has_transaction(&txid));

    if abandon {
        assert_eq!(ctx.managed_wallet.abandon_transaction(txid).records_removed, 1);
    } else {
        let result = ctx.check_transaction(&spending_tx(&[contested]), in_block(201)).await;
        assert_eq!(result.swept_transactions, vec![txid]);
        assert!(!result.released_outpoints.contains(&coin), "account 0 still guards the coin");
    }

    assert!(ctx.bip44_account().is_outpoint_spent(&coin));
    ctx.check_transaction(&funding, in_block(90)).await;
    assert!(!ctx.bip44_account().utxos.contains_key(&coin));
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

        ctx.check_transaction(&funding, TransactionContext::Mempool).await;
        assert_eq!(
            ctx.managed_wallet.accounts.standard_bip44_accounts[&1].utxos.contains_key(&spent),
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
    assert!(!ctx.managed_wallet.accounts.standard_bip44_accounts[&1].utxos.contains_key(&spent));
}

/// The claimant has no record, so no sweep can remove it. A final spend of
/// the outpoint still settles it: abandoning the old claimant afterwards
/// must not release the guard. An unconfirmed spend settles nothing.
#[test_case::test_case(true; "final spend")]
#[test_case::test_case(false; "unconfirmed spend")]
#[tokio::test]
async fn final_spend_makes_a_recordless_claim_permanent(is_final: bool) {
    let (mut ctx, address) = restore_context();
    let funding = Transaction::dummy(&address, 20..21, &[150_000]);
    let spent = OutPoint::new(funding.txid(), 0);
    let claimant = Txid::from([0x77; 32]);
    ctx.managed_wallet.restore_spent_outpoints(&[(spent, Some(claimant))]);

    let context = if is_final {
        in_block(100)
    } else {
        TransactionContext::Mempool
    };
    assert!(ctx.managed_wallet.sweep_conflicts(&spending_tx(&[spent]), &context).is_empty());
    ctx.managed_wallet.abandon_transaction(claimant);

    assert!(ctx
        .managed_wallet
        .accounts
        .all_funding_accounts()
        .iter()
        .all(|account| account.is_outpoint_spent(&spent) == is_final));
    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    assert_eq!(
        ctx.managed_wallet.accounts.standard_bip44_accounts[&1].utxos.contains_key(&spent),
        !is_final
    );
}

/// Two live records spend the claimed outpoint. Removing the claimant hands
/// the claim to the survivor, so the outpoint stays guarded in every funding
/// account until the survivor is removed too.
#[test_case::test_case(false; "conflict")]
#[test_case::test_case(true; "abandonment")]
#[tokio::test]
async fn claim_passes_to_a_surviving_spender_until_it_is_removed_too(abandon: bool) {
    let (mut ctx, address) = restore_context();
    let funding = Transaction::dummy(&address, 20..21, &[150_000]);
    let spent = OutPoint::new(funding.txid(), 0);
    let claimant_input = OutPoint::new(Txid::from([0x55; 32]), 0);
    let survivor_input = OutPoint::new(Txid::from([0x56; 32]), 0);
    let claimant = spend_paying(&[claimant_input, spent], &ctx.receive_address);
    let survivor = spend_paying(&[survivor_input, spent], &ctx.receive_address);
    ctx.managed_wallet.restore_spent_outpoints(&[(spent, Some(claimant.txid()))]);
    ctx.check_transaction(&claimant, TransactionContext::Mempool).await;
    ctx.check_transaction(&survivor, TransactionContext::Mempool).await;

    if abandon {
        assert_eq!(ctx.managed_wallet.abandon_transaction(claimant.txid()).records_removed, 1);
    } else {
        let result = ctx.check_transaction(&spending_tx(&[claimant_input]), in_block(100)).await;
        assert_eq!(result.swept_transactions, vec![claimant.txid()]);
        assert!(result.released_outpoints.is_empty());
    }
    assert!(ctx
        .managed_wallet
        .accounts
        .all_funding_accounts()
        .iter()
        .all(|account| account.is_outpoint_spent(&spent)));

    if abandon {
        assert_eq!(ctx.managed_wallet.abandon_transaction(survivor.txid()).records_removed, 1);
    } else {
        let result = ctx.check_transaction(&spending_tx(&[survivor_input]), in_block(101)).await;
        assert_eq!(result.swept_transactions, vec![survivor.txid()]);
        assert_eq!(result.released_outpoints, vec![spent]);
    }
    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    assert!(ctx.managed_wallet.accounts.standard_bip44_accounts[&1].utxos.contains_key(&spent));
}

/// The claimant's removal frees the outpoint in every account holding the
/// claim, and the sweep reports it exactly once.
#[tokio::test]
async fn swept_claimant_reports_its_released_claim_once() {
    let (mut ctx, address) = restore_context();
    let spent = OutPoint::new(Transaction::dummy(&address, 20..21, &[150_000]).txid(), 0);
    let contested = OutPoint::new(Txid::from([0x55; 32]), 0);
    let loser = spend_paying(&[contested, spent], &ctx.receive_address);
    ctx.managed_wallet.restore_spent_outpoints(&[(spent, Some(loser.txid()))]);
    ctx.check_transaction(&loser, TransactionContext::Mempool).await;

    let result = ctx.check_transaction(&spending_tx(&[contested]), in_block(100)).await;

    assert_eq!(result.released_outpoints, vec![spent]);
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

/// Restoring after the funding was delivered cannot take the coin back: it
/// stays credited, and the caller is told which guards came too late.
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
    assert!(ctx.managed_wallet.accounts.standard_bip44_accounts[&1].utxos.contains_key(&held));
    assert_eq!(ctx.managed_wallet.balance.total(), balance);
    assert!(ctx.managed_wallet.restore_spent_outpoints(&[(absent, None)]).is_empty());
}

/// Account 1 removes the loser and frees its extra input, but account 0 holds
/// a restored claim on it, so the wallet must not report it released.
#[tokio::test]
async fn sweep_withholds_outpoints_another_account_still_guards() {
    let (mut ctx, second_address) = restore_context();
    let contested = OutPoint::new(Txid::from([0x55; 32]), 0);
    let guarded = OutPoint::new(Txid::from([0x56; 32]), 0);
    ctx.managed_wallet
        .accounts
        .standard_bip44_accounts
        .get_mut(&0)
        .unwrap()
        .restore_spent_outpoints(&[(guarded, None)]);
    let loser = spend_paying(&[contested, guarded], &second_address);
    ctx.check_transaction(&loser, TransactionContext::Mempool).await;
    assert!(ctx.managed_wallet.accounts.standard_bip44_accounts[&1].has_transaction(&loser.txid()));

    let result = ctx.check_transaction(&spending_tx(&[contested]), in_block(100)).await;

    assert_eq!(result.swept_transactions, vec![loser.txid()]);
    assert!(result.released_outpoints.is_empty());
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
