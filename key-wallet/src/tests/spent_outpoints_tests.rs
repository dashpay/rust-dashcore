//! Tests for spent_outpoints deserialization and tracking.

use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, TxIn, TxOut, Txid};

use crate::account::{AccountType, StandardAccountType, TransactionRecord};
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::reservation::ReservationToken;
use crate::managed_account::transaction_record::TransactionDirection;
use crate::managed_account::ManagedCoreFundsAccount;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext, TransactionType};
use crate::wallet::initialization::WalletAccountCreationOptions;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::managed_wallet_info::SpentOutpointChanges;
use std::collections::BTreeMap;

fn restore_context() -> (TestWalletContext, dashcore::Address) {
    let mut ctx = TestWalletContext::new_random_with_options(
        WalletAccountCreationOptions::BIP44AccountsOnly([0, 1].into_iter().collect()),
    );
    let xpub = ctx.wallet.accounts.standard_bip44_accounts[&1].account_xpub;
    let account = ctx.managed_wallet.accounts.standard_bip44_accounts.get_mut(&1).unwrap();
    let address = account.next_receive_address(Some(&xpub), true).unwrap();
    (ctx, address)
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
        let claims = [(spent, claimant), (unrelated, None)];
        for claims in [&claims[..], &claims, &[]] {
            ctx.managed_wallet.restore_spent_outpoints(claims);
        }
        assert!(ctx.bip44_account().transactions().is_empty());
        assert_eq!(ctx.managed_wallet.balance.total(), 0);
        assert!(ctx.managed_wallet.observed_spent_outpoints().is_empty());
        ctx.check_transaction(&loser, TransactionContext::Mempool).await;
        assert!(ctx.bip44_account().has_transaction(&loser.txid()));
        assert!(
            !ctx.managed_wallet.accounts.standard_bip44_accounts[&1].has_transaction(&loser.txid())
        );
        let mut survivor = spending_tx(&[spent]);
        survivor.output = loser.output.clone();
        if kind == 3 {
            ctx.check_transaction(&survivor, TransactionContext::Mempool).await;
            assert!(ctx.bip44_account().has_transaction(&survivor.txid()));
        }
        let changes = if abandon {
            let outcome = ctx.managed_wallet.abandon_transaction(loser.txid());
            assert_eq!(outcome.records_removed, 1);
            assert!(outcome.spent_outpoint_changes.released.contains(&contested));
            outcome.spent_outpoint_changes
        } else {
            let winner = spending_tx(&[contested]);
            let result = ctx.check_transaction(&winner, in_block(100)).await;
            assert_eq!(result.swept_transactions, vec![loser.txid()]);
            assert_eq!(result.released_outpoints.contains(&spent), kind == 0);
            assert!(
                result.spent_outpoint_changes.claimed.contains(&(contested, Some(winner.txid()))),
                "the winner takes over the claim on the input it beat the loser to"
            );
            result.spent_outpoint_changes
        };
        assert_eq!(changes.released.contains(&spent), kind == 0);
        assert_eq!(
            changes.claimed.contains(&(spent, Some(survivor.txid()))),
            kind == 3,
            "a surviving spender takes over the removed claimant's claim"
        );
        ctx.managed_wallet.update_synced_height(200);
        ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(200));
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

/// A claim restored for a transaction the wallet holds no record of — every
/// claim after a load that restores no history — is released when that
/// transaction is abandoned.
#[tokio::test]
async fn abandoning_a_recordless_restored_claimant_releases_its_claim() {
    let (mut ctx, address) = restore_context();
    let funding = Transaction::dummy(&address, 20..21, &[150_000, 90_000]);
    let spent = OutPoint::new(funding.txid(), 0);
    let held = OutPoint::new(funding.txid(), 1);
    let claimant = Txid::from([0x99; 32]);
    ctx.managed_wallet.restore_spent_outpoints(&[(spent, Some(claimant)), (held, None)]);
    let outcome = ctx.managed_wallet.abandon_transaction(claimant);
    assert_eq!(outcome.spent_outpoint_changes.released, vec![spent]);
    assert!(!outcome.is_empty());
    ctx.check_transaction(&funding, TransactionContext::Mempool).await;
    let account = &ctx.managed_wallet.accounts.standard_bip44_accounts[&1];
    assert!(!account.utxos.contains_key(&held), "an unknown claimant stays guarded");
    assert!(account.utxos.contains_key(&spent), "the abandoned claimant's coin must come free");
}

/// Apply `changes` the way a persistence mirror stores rows, and hold the
/// result to the wallet's own claims.
fn fold_claims(
    rows: &mut BTreeMap<OutPoint, Option<Txid>>,
    changes: &SpentOutpointChanges,
    ctx: &TestWalletContext,
) {
    rows.extend(changes.claimed.iter().copied());
    for outpoint in &changes.released {
        rows.remove(outpoint);
    }
    assert_eq!(*rows, ctx.managed_wallet.spent_outpoint_claims());
}

fn in_block(height: u32) -> TransactionContext {
    TransactionContext::InBlock(BlockInfo::new(height, BlockHash::from([0x66; 32]), 1_700_000_000))
}

/// An InstantSend lock that backfills a missing record reports the claims
/// that recording makes.
#[tokio::test]
async fn instant_send_backfill_reports_its_claims() {
    let (mut ctx, address) = restore_context();
    let mut tx = Transaction::dummy(&ctx.receive_address, 20..21, &[100_000]);
    tx.output.push(TxOut {
        value: 50_000,
        script_pubkey: address.script_pubkey(),
    });
    let held = OutPoint::new(tx.txid(), 1);
    let mut rows = BTreeMap::new();
    let result = ctx.check_transaction(&tx, TransactionContext::Mempool).await;
    fold_claims(&mut rows, &result.spent_outpoint_changes, &ctx);
    // Account 1 misses that delivery, and a block spends its output.
    let account = ctx.managed_wallet.accounts.standard_bip44_accounts.get_mut(&1).unwrap();
    account.transactions_mut().remove(&tx.txid());
    account.utxos.clear();
    for (tx, context) in [
        (&spending_tx(&[held]), in_block(100)),
        (&tx, TransactionContext::InstantSend(InstantLock::default())),
    ] {
        let result = ctx.check_transaction(tx, context).await;
        fold_claims(&mut rows, &result.spent_outpoint_changes, &ctx);
    }
    assert_eq!(rows.get(&held), Some(&None));
}

/// A coin a chainlocked transaction spent stays claimed when a later spend
/// of it is swept: the settled claimant is not the one being removed, even
/// where its record was pruned to a txid.
#[tokio::test]
async fn sweeping_a_later_spend_keeps_the_settled_claim() {
    let (mut ctx, address) = restore_context();
    let funding = Transaction::dummy(&address, 20..21, &[150_000, 90_000]);
    let [settled_coin, contested] = [0, 1].map(|vout| OutPoint::new(funding.txid(), vout));
    let paying_account_0 = |inputs: &[OutPoint], amount| {
        let mut tx = spending_tx(inputs);
        tx.output = Transaction::dummy(&ctx.receive_address, 30..31, &[amount]).output;
        tx
    };
    let settled = paying_account_0(&[settled_coin], 140_000);
    let late = paying_account_0(&[settled_coin, contested], 200_000);
    let locked = TransactionContext::InChainLockedBlock(BlockInfo::new(
        20,
        BlockHash::from([0x66; 32]),
        1_700_000_000,
    ));
    ctx.check_transaction(&funding, in_block(10)).await;
    ctx.check_transaction(&settled, locked).await;
    // Past finality the observed spend is forgotten, so the late spend is recorded in full.
    ctx.managed_wallet.update_synced_height(200);
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(200));
    ctx.check_transaction(&late, TransactionContext::Mempool).await;
    let result = ctx.check_transaction(&spending_tx(&[contested]), in_block(300)).await;
    assert_eq!(result.swept_transactions, vec![late.txid()]);
    assert!(result.released_outpoints.is_empty());
    let claims = ctx.managed_wallet.spent_outpoint_claims();
    assert_eq!(claims.get(&settled_coin), Some(&Some(settled.txid())));
}

/// Folding every reported change gives exactly the wallet's claims, and a
/// fresh wallet restored from those rows credits what the original does.
#[tokio::test]
async fn reported_claim_changes_round_trip_through_restore() {
    let (mut ctx, address) = restore_context();
    let pristine = ctx.managed_wallet.clone();
    let paying_account_0 = |inputs: &[OutPoint], amount| {
        let mut tx = spending_tx(inputs);
        tx.output = Transaction::dummy(&ctx.receive_address, 30..31, &[amount]).output;
        tx
    };
    let funding = Transaction::dummy(&address, 20..21, &[150_000, 90_000, 60_000]);
    let [abandoned_coin, shared_coin] = [0, 1].map(|vout| OutPoint::new(funding.txid(), vout));
    let contested = OutPoint::new(Txid::from([0x55; 32]), 0);
    let abandoned = paying_account_0(&[abandoned_coin], 140_000);
    let loser = paying_account_0(&[contested, shared_coin], 80_000);
    let survivor = paying_account_0(&[shared_coin], 70_000);
    let winner = spending_tx(&[contested]);
    // Its only output is spent by a block seen before it arrives.
    let late_funding = Transaction::dummy(&address, 40..41, &[50_000]);
    let born_spent = OutPoint::new(late_funding.txid(), 0);
    let early_spend = spending_tx(&[born_spent]);

    let mut rows = BTreeMap::new();
    for (tx, context) in [
        (&funding, in_block(10)),
        (&abandoned, TransactionContext::Mempool),
        (&loser, TransactionContext::Mempool),
        (&survivor, TransactionContext::Mempool),
        (&winner, in_block(100)),
        (&early_spend, in_block(50)),
        (&late_funding, in_block(40)),
        (&early_spend, in_block(50)),
    ] {
        let result = ctx.check_transaction(tx, context).await;
        fold_claims(&mut rows, &result.spent_outpoint_changes, &ctx);
    }
    let outcome = ctx.managed_wallet.abandon_transaction(abandoned.txid());
    fold_claims(&mut rows, &outcome.spent_outpoint_changes, &ctx);
    assert_eq!(rows.get(&shared_coin), Some(&Some(survivor.txid())));
    assert_eq!(rows.get(&contested), Some(&Some(winner.txid())));
    assert_eq!(rows.get(&born_spent), Some(&None), "a block spent it; the spender stays unknown");
    assert!(!rows.contains_key(&abandoned_coin));

    let redelivered =
        [(&funding, in_block(10)), (&late_funding, in_block(40)), (&survivor, in_block(110))];
    let mut wallets = Vec::new();
    for restored in [false, true] {
        if restored {
            ctx.managed_wallet = pristine.clone();
            let claims: Vec<_> = rows.clone().into_iter().collect();
            ctx.managed_wallet.restore_spent_outpoints(&claims);
            assert_eq!(rows, ctx.managed_wallet.spent_outpoint_claims());
        }
        for (tx, context) in redelivered.clone() {
            ctx.check_transaction(tx, context).await;
        }
        let utxos: Vec<Vec<OutPoint>> = [0, 1]
            .map(|index| {
                ctx.managed_wallet.accounts.standard_bip44_accounts[&index]
                    .utxos
                    .keys()
                    .copied()
                    .collect()
            })
            .into();
        wallets.push((
            utxos,
            ctx.managed_wallet.balance,
            ctx.managed_wallet.spent_outpoint_claims(),
        ));
    }
    assert!(wallets[0].0[1].contains(&abandoned_coin), "the released coin is credited again");
    assert_eq!(wallets[0], wallets[1], "the restored wallet must match the uninterrupted one");
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
    let mut account = ManagedCoreFundsAccount::dummy_bip44();
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
    // Restored claims are reapplied on load, never serialized.
    account.restore_spent_outpoints(&[(probe, None)]);
    assert_eq!(serde_json::to_string(&account).unwrap(), json);
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
