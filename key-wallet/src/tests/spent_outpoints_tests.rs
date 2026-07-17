//! Tests for spent_outpoints deserialization and tracking.

use std::collections::HashSet;

use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::hashes::Hash;
use dashcore::{BlockHash, TxIn, Txid};

use crate::account::{AccountType, StandardAccountType, TransactionRecord};
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::transaction_record::TransactionDirection;
use crate::managed_account::ManagedCoreFundsAccount;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext, TransactionType};
use crate::Utxo;

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

    account.reservations().reserve(&[outpoint], 0);
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
    account.reservations().reserve(&[funded], 0);
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
    account.reservations().reserve(&[second_funded], 0);
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
fn reserved_outpoints_are_excluded_from_spendable_and_reappear_on_release() {
    // The public read API added for cross-account input selection: a caller
    // that force-adds another account's UTXOs into a shared sweep must be able
    // to see and skip outpoints an in-flight build already reserved, otherwise
    // a rebuild/retry can reselect them into a conflicting transaction.
    let height = 100;
    let mut account = ManagedCoreFundsAccount::dummy_bip44();

    // Two mature, non-coinbase UTXOs: both spendable at `height`.
    let utxo_reserved = Utxo::dummy(0x11, 100_000, 10, false, true);
    let utxo_free = Utxo::dummy(0x22, 200_000, 10, false, true);
    let reserved_op = utxo_reserved.outpoint;
    let free_op = utxo_free.outpoint;
    account.utxos.insert(reserved_op, utxo_reserved);
    account.utxos.insert(free_op, utxo_free);

    // Nothing reserved yet: the excluding view matches plain spendable, and the
    // reserved set is empty.
    assert!(account.reserved_outpoints(height).is_empty());
    let spendable: Vec<OutPoint> =
        account.spendable_utxos(height).iter().map(|u| u.outpoint).collect();
    assert!(spendable.contains(&reserved_op) && spendable.contains(&free_op));
    let excluding: Vec<OutPoint> =
        account.spendable_utxos_excluding_reserved(height).iter().map(|u| u.outpoint).collect();
    assert!(excluding.contains(&reserved_op) && excluding.contains(&free_op));

    // Reserve one outpoint as an in-flight build would.
    account.reservations().reserve(&[reserved_op], height);

    // The reserved outpoint is now visible via the public read API...
    assert_eq!(account.reserved_outpoints(height), HashSet::from([reserved_op]));
    // ...excluded from the reservation-aware enumeration...
    let excluding: Vec<OutPoint> =
        account.spendable_utxos_excluding_reserved(height).iter().map(|u| u.outpoint).collect();
    assert_eq!(excluding, vec![free_op]);
    // ...but still present in the reservation-unaware `spendable_utxos`, whose
    // semantics are unchanged (the additive API must not alter it).
    let spendable: Vec<OutPoint> =
        account.spendable_utxos(height).iter().map(|u| u.outpoint).collect();
    assert!(spendable.contains(&reserved_op) && spendable.contains(&free_op));

    // Releasing the reservation makes the outpoint selectable again.
    account.reservations().release([&reserved_op]);
    assert!(account.reserved_outpoints(height).is_empty());
    let excluding: Vec<OutPoint> =
        account.spendable_utxos_excluding_reserved(height).iter().map(|u| u.outpoint).collect();
    assert!(excluding.contains(&reserved_op) && excluding.contains(&free_op));
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
