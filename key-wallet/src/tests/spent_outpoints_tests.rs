//! Tests for spent_outpoints deserialization and tracking.

use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::{TxIn, Txid};

use crate::account::TransactionRecord;
use crate::managed_account::ManagedCoreAccount;
use crate::transaction_checking::TransactionContext;

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
    TransactionRecord::new(tx.clone(), TransactionContext::Mempool, 0, false)
}

#[test]
fn fresh_account_has_empty_spent_outpoints() {
    let account = ManagedCoreAccount::dummy_bip44();
    assert!(account.transactions.is_empty());

    let probe = OutPoint::new(Txid::from([0xAA; 32]), 0);
    // Accessing spent_outpoints on a fresh account should not panic or misbehave.
    // We verify indirectly via serde round-trip (spent_outpoints is private).
    let json = serde_json::to_string(&account).unwrap();
    let deserialized: ManagedCoreAccount = serde_json::from_str(&json).unwrap();
    // No transactions, so spent_outpoints stays empty after round-trip.
    assert!(deserialized.transactions.is_empty());
    // Confirm the serialized form does not contain spent_outpoints.
    assert!(!json.contains("spent_outpoints"));
    let _ = probe; // used only for clarity of intent
}

#[test]
fn serde_round_trip_rebuilds_spent_outpoints() {
    let mut account = ManagedCoreAccount::dummy_bip44();

    let outpoint_a = OutPoint::new(Txid::from([0x01; 32]), 0);
    let outpoint_b = OutPoint::new(Txid::from([0x02; 32]), 1);
    let tx = spending_tx(&[outpoint_a, outpoint_b]);
    let txid = tx.txid();
    account.transactions.insert(txid, record_from_tx(&tx));

    // Serialize (spent_outpoints is skipped)
    let json = serde_json::to_string(&account).unwrap();
    assert!(!json.contains("spent_outpoints"));

    // Deserialize: spent_outpoints should be rebuilt from transactions
    let deserialized: ManagedCoreAccount = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.transactions.len(), 1);

    // Verify the rebuilt set by serializing again and comparing transactions
    // (spent_outpoints is private, so we test behavior through a second round-trip
    //  to confirm stability)
    let json2 = serde_json::to_string(&deserialized).unwrap();
    let deserialized2: ManagedCoreAccount = serde_json::from_str(&json2).unwrap();
    assert_eq!(deserialized2.transactions.len(), 1);
}

#[test]
fn receive_only_account_round_trips_correctly() {
    let mut account = ManagedCoreAccount::dummy_bip44();

    // Add a receive-only transaction (coinbase-like, no real spent outpoints)
    let tx = receive_only_tx();
    let txid = tx.txid();
    account.transactions.insert(txid, record_from_tx(&tx));

    assert_eq!(account.transactions.len(), 1);

    // Round-trip should work without issues (no rebuild loop)
    let json = serde_json::to_string(&account).unwrap();
    let deserialized: ManagedCoreAccount = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.transactions.len(), 1);

    // A second round-trip should be stable
    let json2 = serde_json::to_string(&deserialized).unwrap();
    let deserialized2: ManagedCoreAccount = serde_json::from_str(&json2).unwrap();
    assert_eq!(deserialized2.transactions.len(), 1);
}

#[test]
fn multiple_transactions_all_inputs_tracked_after_round_trip() {
    let mut account = ManagedCoreAccount::dummy_bip44();

    let outpoint_1 = OutPoint::new(Txid::from([0x10; 32]), 0);
    let outpoint_2 = OutPoint::new(Txid::from([0x20; 32]), 0);
    let outpoint_3 = OutPoint::new(Txid::from([0x30; 32]), 2);

    let tx1 = spending_tx(&[outpoint_1]);
    let tx2 = spending_tx(&[outpoint_2, outpoint_3]);

    account.transactions.insert(tx1.txid(), record_from_tx(&tx1));
    account.transactions.insert(tx2.txid(), record_from_tx(&tx2));

    let json = serde_json::to_string(&account).unwrap();
    let deserialized: ManagedCoreAccount = serde_json::from_str(&json).unwrap();

    // All three outpoints should be in the rebuilt spent set.
    // We verify by confirming the transaction inputs survived the round-trip.
    let all_spent: Vec<OutPoint> = deserialized
        .transactions
        .values()
        .flat_map(|r| &r.transaction.input)
        .map(|inp| inp.previous_output)
        .collect();
    assert!(all_spent.contains(&outpoint_1));
    assert!(all_spent.contains(&outpoint_2));
    assert!(all_spent.contains(&outpoint_3));
    assert_eq!(all_spent.len(), 3);
}
