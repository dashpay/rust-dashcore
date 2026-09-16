//! Persistence rehydration must restore transaction lifecycle markers without
//! replaying records through UTXO mutation in an arbitrary storage order.

use crate::account::StandardAccountType;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::transaction_record::{
    InputDetail, TransactionDirection, TransactionRecord,
};
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{
    BlockInfo, TransactionContext, TransactionType, WalletTransactionChecker,
};
use crate::wallet::ManagedWalletInfo;
use crate::AccountType;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Witness};

fn bip44() -> AccountType {
    AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    }
}

fn spend(parent: OutPoint) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: parent,
            script_sig: ScriptBuf::new(),
            sequence: u32::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: 999_000,
            script_pubkey: ScriptBuf::new(),
        }],
        special_transaction_payload: None,
    }
}

fn competing_spend(parent: OutPoint) -> Transaction {
    let mut transaction = spend(parent);
    transaction.output[0].value -= 1_000;
    transaction
}

fn spending_record(
    tx: Transaction,
    address: dashcore::Address,
    context: TransactionContext,
) -> TransactionRecord {
    TransactionRecord::new(
        tx,
        bip44(),
        context,
        TransactionType::Standard,
        TransactionDirection::Outgoing,
        vec![InputDetail {
            index: 0,
            value: 1_000_000,
            address,
        }],
        Vec::new(),
        -1_000_000,
    )
}

#[tokio::test]
async fn restored_spend_mark_blocks_funding_until_the_claim_is_released() {
    let template = TestWalletContext::new_random();
    let funding = Transaction::dummy(&template.receive_address, 0..1, &[1_000_000]);
    let parent = OutPoint {
        txid: funding.txid(),
        vout: 0,
    };
    let claimant = spend(parent);
    let claimant_txid = claimant.txid();
    let claimant_record =
        spending_record(claimant, template.receive_address.clone(), TransactionContext::Mempool);

    let mut restored = template.managed_wallet.clone();
    let mut wallet = template.wallet.clone();
    let funding_context = TransactionContext::InBlock(BlockInfo::new(
        40,
        BlockHash::from_byte_array([0x40; 32]),
        1_699_999_000,
    ));
    let unmatched = restored.restore_persisted_transactions([claimant_record]);
    assert!(unmatched.is_empty());
    restored
        .first_bip44_managed_account_mut()
        .expect("BIP44 account")
        .restore_spent_outpoints([parent]);

    restored
        .check_core_transaction(&funding, funding_context.clone(), &mut wallet, true, true)
        .await;
    assert!(
        !restored.first_bip44_managed_account().expect("BIP44 account").utxos.contains_key(&parent),
        "a persisted live claim must suppress funding redelivery"
    );

    let abandoned = restored.abandon_transaction(claimant_txid);
    assert!(abandoned.abandoned.contains(&claimant_txid));
    restored.check_core_transaction(&funding, funding_context, &mut wallet, true, true).await;
    assert!(
        restored.first_bip44_managed_account().expect("BIP44 account").utxos.contains_key(&parent),
        "releasing the restored claim must allow rediscovery"
    );
}

#[test]
fn restored_chainlocked_record_uses_finalized_compaction() {
    let template = TestWalletContext::new_random();
    let parent = OutPoint {
        txid: Transaction::dummy(&template.receive_address, 0..1, &[1_000_000]).txid(),
        vout: 0,
    };
    let claimant = spend(parent);
    let claimant_txid = claimant.txid();
    let record = spending_record(
        claimant,
        template.receive_address,
        TransactionContext::InChainLockedBlock(BlockInfo::new(
            50,
            BlockHash::from_byte_array([0x50; 32]),
            1_700_000_000,
        )),
    );

    let mut restored: ManagedWalletInfo = template.managed_wallet;
    assert!(restored.restore_persisted_transactions([record]).is_empty());
    assert_eq!(restored.observed_spent_outpoints().get(&parent), Some(&50));
    let account = restored.first_bip44_managed_account().expect("BIP44 account");
    assert!(account.transaction_is_finalized(&claimant_txid));
    #[cfg(not(feature = "keep-finalized-transactions"))]
    assert!(
        !account.transactions().contains_key(&claimant_txid),
        "default retention keeps only the finalized txid"
    );
}

#[test]
fn unmatched_record_does_not_restore_wallet_level_spend_state() {
    let template = TestWalletContext::new_random();
    let parent = OutPoint {
        txid: Transaction::dummy(&template.receive_address, 0..1, &[1_000_000]).txid(),
        vout: 0,
    };
    let mut record = spending_record(
        spend(parent),
        template.receive_address,
        TransactionContext::InBlock(BlockInfo::new(
            50,
            BlockHash::from_byte_array([0x50; 32]),
            1_700_000_000,
        )),
    );
    record.account_type = AccountType::Standard {
        index: 7,
        standard_account_type: StandardAccountType::BIP44Account,
    };

    let mut restored = template.managed_wallet;
    let unmatched = restored.restore_persisted_transactions([record]);

    assert_eq!(unmatched.len(), 1);
    assert!(
        !restored.observed_spent_outpoints().contains_key(&parent),
        "a record rejected for missing account ownership must not mutate wallet spend state"
    );
}

#[test]
fn restored_unconfirmed_records_participate_in_conflict_descendant_sweeps() {
    let template = TestWalletContext::new_random();
    let parent = OutPoint {
        txid: Transaction::dummy(&template.receive_address, 0..1, &[1_000_000]).txid(),
        vout: 0,
    };
    let root = spend(parent);
    let root_txid = root.txid();
    let root_output = OutPoint {
        txid: root_txid,
        vout: 0,
    };
    let child = spend(root_output);
    let child_txid = child.txid();
    let winner = competing_spend(parent);

    let root_record =
        spending_record(root, template.receive_address.clone(), TransactionContext::Mempool);
    let child_record =
        spending_record(child, template.receive_address, TransactionContext::Mempool);
    let mut restored = template.managed_wallet;
    assert!(restored.restore_persisted_transactions([root_record, child_record]).is_empty());
    restored
        .first_bip44_managed_account_mut()
        .expect("BIP44 account")
        .restore_spent_outpoints([parent, root_output]);

    let swept = restored.sweep_conflicts(
        &winner,
        &TransactionContext::InBlock(BlockInfo::new(
            60,
            BlockHash::from_byte_array([0x60; 32]),
            1_700_001_000,
        )),
    );
    assert!(swept.txids.contains(&root_txid));
    assert!(swept.txids.contains(&child_txid));
}
