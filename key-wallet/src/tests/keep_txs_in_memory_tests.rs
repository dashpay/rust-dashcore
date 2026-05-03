//! Tests for the `keep_txs_in_memory` flag on `ManagedCoreAccount`.

use crate::managed_account::ManagedCoreAccount;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::TransactionContext;
use dashcore::Transaction;

#[test]
fn default_keeps_txs_in_memory() {
    let account = ManagedCoreAccount::dummy_bip44();
    assert!(account.keep_txs_in_memory);
}

#[test]
fn disabling_clears_existing_transactions() {
    use crate::account::{StandardAccountType, TransactionRecord};
    use crate::managed_account::transaction_record::TransactionDirection;
    use crate::transaction_checking::TransactionType;
    use crate::AccountType;
    use dashcore::blockdata::transaction::Transaction;
    use dashcore::TxIn;

    let mut account = ManagedCoreAccount::dummy_bip44();
    let tx = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn::default()],
        output: Vec::new(),
        special_transaction_payload: None,
    };
    let record = TransactionRecord::new(
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
    );
    account.transactions.insert(tx.txid(), record);
    assert_eq!(account.transactions.len(), 1);

    account.set_keep_txs_in_memory(false);
    assert!(!account.keep_txs_in_memory);
    assert!(account.transactions.is_empty());
}

#[tokio::test]
async fn record_transaction_skips_storage_when_disabled() {
    let mut ctx = TestWalletContext::new_random();
    ctx.managed_wallet
        .first_bip44_managed_account_mut()
        .expect("Should have BIP44 account")
        .set_keep_txs_in_memory(false);

    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[200_000]);
    let result = ctx.check_transaction(&tx, TransactionContext::Mempool).await;
    assert!(result.is_relevant);

    let account = ctx.bip44_account();
    assert!(
        account.transactions.is_empty(),
        "transactions should not be stored when keep_txs_in_memory is false"
    );
    assert_eq!(
        account.utxos.len(),
        1,
        "UTXOs should still be tracked even with txs disabled"
    );
    assert_eq!(account.balance.spendable(), 200_000);
}

#[cfg(feature = "serde")]
#[test]
fn serde_round_trip_preserves_flag() {
    let mut account = ManagedCoreAccount::dummy_bip44();
    account.set_keep_txs_in_memory(false);

    let json = serde_json::to_string(&account).unwrap();
    let deserialized: ManagedCoreAccount = serde_json::from_str(&json).unwrap();
    assert!(!deserialized.keep_txs_in_memory);
}

#[cfg(feature = "serde")]
#[test]
fn serde_defaults_when_field_missing_from_legacy_payload() {
    // Simulate a serialized account written before the `keep_txs_in_memory`
    // field existed by stripping it from a freshly-serialized account.
    let account = ManagedCoreAccount::dummy_bip44();
    let mut value = serde_json::to_value(&account).unwrap();
    value
        .as_object_mut()
        .expect("object")
        .remove("keep_txs_in_memory");
    let json = serde_json::to_string(&value).unwrap();

    let restored: ManagedCoreAccount = serde_json::from_str(&json).unwrap();
    assert!(
        restored.keep_txs_in_memory,
        "missing flag should default to true to preserve legacy behavior"
    );
}
