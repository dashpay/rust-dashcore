//! Tests for the `keep_txs_in_memory` Cargo feature.
//!
//! When the feature is enabled (the default), `ManagedCoreAccount` keeps a
//! per-account `transactions` map populated as transactions are processed.
//! When the feature is disabled, the field does not exist and processing a
//! transaction only updates UTXOs and balance.

use crate::test_utils::TestWalletContext;
use crate::transaction_checking::TransactionContext;
use dashcore::Transaction;

#[tokio::test]
async fn record_transaction_updates_utxos_and_balance() {
    let mut ctx = TestWalletContext::new_random();

    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[200_000]);
    let result = ctx.check_transaction(&tx, TransactionContext::Mempool).await;
    assert!(result.is_relevant);

    let account = ctx.bip44_account();
    assert_eq!(account.utxos.len(), 1, "UTXOs are tracked regardless of feature");
    assert_eq!(account.balance.spendable(), 200_000);
}

#[cfg(feature = "keep_txs_in_memory")]
#[tokio::test]
async fn transactions_are_stored_when_feature_enabled() {
    let mut ctx = TestWalletContext::new_random();

    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[200_000]);
    let _ = ctx.check_transaction(&tx, TransactionContext::Mempool).await;

    let account = ctx.bip44_account();
    assert_eq!(account.transactions.len(), 1);
    assert!(account.has_transaction(&tx.txid()));
    assert!(account.get_transaction(&tx.txid()).is_some());
}

#[cfg(not(feature = "keep_txs_in_memory"))]
#[tokio::test]
async fn transactions_are_not_stored_when_feature_disabled() {
    let mut ctx = TestWalletContext::new_random();

    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[200_000]);
    let _ = ctx.check_transaction(&tx, TransactionContext::Mempool).await;

    let account = ctx.bip44_account();
    assert!(!account.has_transaction(&tx.txid()));
    assert!(account.get_transaction(&tx.txid()).is_none());
}

#[cfg(feature = "keep_txs_in_memory")]
#[test]
fn helper_methods_proxy_transactions_field() {
    use crate::account::{StandardAccountType, TransactionRecord};
    use crate::managed_account::transaction_record::TransactionDirection;
    use crate::managed_account::ManagedCoreAccount;
    use crate::transaction_checking::TransactionType;
    use crate::AccountType;
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
    let txid = tx.txid();

    assert!(!account.has_transaction(&txid));
    assert!(account.get_transaction(&txid).is_none());

    account.transactions.insert(txid, record);
    assert!(account.has_transaction(&txid));
    assert!(account.get_transaction(&txid).is_some());
}
