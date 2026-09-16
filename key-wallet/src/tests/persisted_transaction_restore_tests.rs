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
use crate::utxo::Utxo;
use crate::wallet::managed_wallet_info::{PersistedWalletState, RestoreError};
use crate::wallet::ManagedWalletInfo;
use crate::AccountType;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Witness};
use std::collections::BTreeMap;

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
    restored
        .restore_persisted_state(PersistedWalletState {
            transactions: vec![claimant_record],
            additional_spent_outpoints: BTreeMap::from([(parent, None)]),
            ..Default::default()
        })
        .unwrap();

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
    restored
        .restore_persisted_state(PersistedWalletState {
            transactions: vec![record],
            ..Default::default()
        })
        .unwrap();
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
    let result = restored.restore_persisted_state(PersistedWalletState {
        transactions: vec![record.clone()],
        ..Default::default()
    });

    assert_eq!(result, Err(RestoreError::MissingAccount(record.account_type)));
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
    restored
        .restore_persisted_state(PersistedWalletState {
            transactions: vec![child_record, root_record],
            ..Default::default()
        })
        .unwrap();

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

fn coin(tx: &Transaction, address: &dashcore::Address) -> Utxo {
    Utxo::new(
        OutPoint {
            txid: tx.txid(),
            vout: 0,
        },
        tx.output[0].clone(),
        address.clone(),
        40,
        false,
    )
}

#[test]
fn should_reject_entire_snapshot_before_mutating_any_account() {
    let template = TestWalletContext::new_random();
    let funding = Transaction::dummy(&template.receive_address, 0..1, &[1_000_000]);
    let parent = OutPoint {
        txid: funding.txid(),
        vout: 0,
    };
    let valid = spending_record(
        spend(parent),
        template.receive_address.clone(),
        TransactionContext::Mempool,
    );
    let mut invalid = valid.clone();
    invalid.txid = funding.txid();
    let mut wallet = template.managed_wallet.clone();
    let state = PersistedWalletState {
        transactions: vec![valid.clone(), invalid],
        ..Default::default()
    };
    assert_eq!(
        wallet.restore_persisted_state(state),
        Err(RestoreError::InvalidRecord(funding.txid()))
    );
    assert!(wallet.first_bip44_managed_account().unwrap().transactions().is_empty());
    assert!(wallet.observed_spent_outpoints().is_empty());
    let mut missing = valid.clone();
    missing.account_type = AccountType::Standard {
        index: 7,
        standard_account_type: StandardAccountType::BIP44Account,
    };
    assert_eq!(
        wallet.restore_persisted_state(PersistedWalletState {
            transactions: vec![valid.clone(), missing.clone()],
            ..Default::default()
        }),
        Err(RestoreError::MissingAccount(missing.account_type))
    );
    assert!(wallet.first_bip44_managed_account().unwrap().transactions().is_empty());
    wallet
        .restore_persisted_state(PersistedWalletState {
            transactions: vec![valid],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        wallet.restore_persisted_state(PersistedWalletState::default()),
        Err(RestoreError::NonEmptyWallet)
    );
}

#[test]
fn should_reject_spent_unspent_contradiction_and_bad_coin_without_mutation() {
    let template = TestWalletContext::new_random();
    let funding = Transaction::dummy(&template.receive_address, 0..1, &[1_000_000]);
    let utxo = coin(&funding, &template.receive_address);
    let record = spending_record(
        spend(utxo.outpoint),
        template.receive_address.clone(),
        TransactionContext::Mempool,
    );
    let mut wallet = template.managed_wallet;
    assert_eq!(
        wallet.restore_persisted_state(PersistedWalletState {
            transactions: vec![record],
            utxos: vec![(bip44(), utxo.clone())],
            ..Default::default()
        }),
        Err(RestoreError::SpentUtxo(utxo.outpoint))
    );
    let mut invalid = utxo.clone();
    invalid.txout.script_pubkey = ScriptBuf::new();
    assert_eq!(
        wallet.restore_persisted_state(PersistedWalletState {
            utxos: vec![(bip44(), invalid)],
            ..Default::default()
        }),
        Err(RestoreError::InvalidUtxo(utxo.outpoint))
    );
    assert!(wallet.first_bip44_managed_account().unwrap().utxos.is_empty());
    assert!(wallet.first_bip44_managed_account().unwrap().transactions().is_empty());
}

#[tokio::test]
async fn should_preserve_unattributed_spend_without_inventing_block_height() {
    let mut template = TestWalletContext::new_random();
    let funding = Transaction::dummy(&template.receive_address, 0..1, &[1_000_000]);
    let parent = OutPoint {
        txid: funding.txid(),
        vout: 0,
    };
    template
        .managed_wallet
        .restore_persisted_state(PersistedWalletState {
            additional_spent_outpoints: BTreeMap::from([(parent, None)]),
            ..Default::default()
        })
        .unwrap();
    assert!(template.managed_wallet.observed_spent_outpoints().is_empty());
    template
        .managed_wallet
        .check_core_transaction(
            &funding,
            TransactionContext::Mempool,
            &mut template.wallet,
            true,
            true,
        )
        .await;
    assert!(!template
        .managed_wallet
        .first_bip44_managed_account()
        .unwrap()
        .utxos
        .contains_key(&parent));
}

#[tokio::test]
async fn should_keep_external_block_evidence_when_abandoning_record_claim() {
    let mut template = TestWalletContext::new_random();
    let funding = Transaction::dummy(&template.receive_address, 0..1, &[1_000_000]);
    let parent = OutPoint {
        txid: funding.txid(),
        vout: 0,
    };
    let record = spending_record(
        spend(parent),
        template.receive_address.clone(),
        TransactionContext::Mempool,
    );
    let txid = record.txid;
    template
        .managed_wallet
        .restore_persisted_state(PersistedWalletState {
            transactions: vec![record],
            additional_spent_outpoints: BTreeMap::from([(parent, Some(80))]),
            ..Default::default()
        })
        .unwrap();
    template.managed_wallet.abandon_transaction(txid);
    template
        .managed_wallet
        .check_core_transaction(
            &funding,
            TransactionContext::Mempool,
            &mut template.wallet,
            true,
            true,
        )
        .await;
    assert_eq!(template.managed_wallet.observed_spent_outpoints().get(&parent), Some(&80));
    assert!(!template
        .managed_wallet
        .first_bip44_managed_account()
        .unwrap()
        .utxos
        .contains_key(&parent));
}

#[tokio::test]
async fn should_match_uninterrupted_wallet_across_restore_abandon_and_conflict() {
    let mut uninterrupted = TestWalletContext::new_random();
    let mut restored = uninterrupted.managed_wallet.clone();
    let funding = Transaction::dummy(&uninterrupted.receive_address, 0..1, &[1_000_000]);
    let parent = OutPoint {
        txid: funding.txid(),
        vout: 0,
    };
    let funding_context = TransactionContext::InBlock(BlockInfo::new(
        40,
        BlockHash::from_byte_array([0x40; 32]),
        1_699_999_000,
    ));
    uninterrupted
        .managed_wallet
        .check_core_transaction(
            &funding,
            funding_context.clone(),
            &mut uninterrupted.wallet,
            true,
            true,
        )
        .await;
    let mut root = spend(parent);
    root.output[0].script_pubkey = uninterrupted.receive_address.script_pubkey();
    uninterrupted
        .managed_wallet
        .check_core_transaction(
            &root,
            TransactionContext::Mempool,
            &mut uninterrupted.wallet,
            true,
            true,
        )
        .await;
    let root_output = OutPoint {
        txid: root.txid(),
        vout: 0,
    };
    let mut child = spend(root_output);
    child.output[0].script_pubkey = uninterrupted.receive_address.script_pubkey();
    child.output[0].value = 998_000;
    uninterrupted
        .managed_wallet
        .check_core_transaction(
            &child,
            TransactionContext::Mempool,
            &mut uninterrupted.wallet,
            true,
            true,
        )
        .await;
    let account = uninterrupted.managed_wallet.first_bip44_managed_account().unwrap();
    let mut records: Vec<_> = account.transactions().values().cloned().collect();
    records.reverse();
    restored
        .restore_persisted_state(PersistedWalletState {
            transactions: records,
            utxos: account.utxos.values().cloned().map(|utxo| (bip44(), utxo)).collect(),
            additional_spent_outpoints: BTreeMap::from([(parent, None), (root_output, None)]),
        })
        .unwrap();
    assert_funds_equal(&uninterrupted.managed_wallet, &restored);
    for state in [&mut uninterrupted.managed_wallet, &mut restored] {
        state
            .check_core_transaction(
                &funding,
                funding_context.clone(),
                &mut uninterrupted.wallet,
                true,
                true,
            )
            .await;
    }
    assert_funds_equal(&uninterrupted.managed_wallet, &restored);
    let mut restored_for_abandon = restored.clone();
    let mut live_for_abandon = uninterrupted.managed_wallet.clone();
    assert_eq!(
        live_for_abandon.abandon_transaction(root.txid()).abandoned,
        restored_for_abandon.abandon_transaction(root.txid()).abandoned
    );
    for state in [&mut live_for_abandon, &mut restored_for_abandon] {
        state
            .check_core_transaction(
                &funding,
                funding_context.clone(),
                &mut uninterrupted.wallet,
                true,
                true,
            )
            .await;
    }
    assert_funds_equal(&live_for_abandon, &restored_for_abandon);
    assert!(restored_for_abandon
        .first_bip44_managed_account()
        .unwrap()
        .utxos
        .contains_key(&parent));
    let winner = competing_spend(parent);
    for state in [&mut uninterrupted.managed_wallet, &mut restored] {
        state
            .check_core_transaction(
                &winner,
                TransactionContext::InBlock(BlockInfo::new(
                    60,
                    BlockHash::from_byte_array([0x60; 32]),
                    1_700_000_000,
                )),
                &mut uninterrupted.wallet,
                true,
                true,
            )
            .await;
    }
    assert_funds_equal(&uninterrupted.managed_wallet, &restored);
    assert!(!restored
        .first_bip44_managed_account()
        .unwrap()
        .transactions()
        .contains_key(&child.txid()));
}

fn assert_funds_equal(left: &ManagedWalletInfo, right: &ManagedWalletInfo) {
    let left_account = left.first_bip44_managed_account().unwrap();
    let right_account = right.first_bip44_managed_account().unwrap();
    assert_eq!(left_account.utxos, right_account.utxos);
    assert_eq!(left_account.balance, right_account.balance);
    assert_eq!(left.balance, right.balance);
    assert_eq!(left_account.tx_count(), right_account.tx_count());
    assert_eq!(left.observed_spent_outpoints(), right.observed_spent_outpoints());
}

#[tokio::test]
async fn should_match_finalized_wallet_after_compaction_and_funding_redelivery() {
    let mut live = TestWalletContext::new_random();
    let mut restored = live.managed_wallet.clone();
    let funding = Transaction::dummy(&live.receive_address, 0..1, &[1_000_000]);
    let parent = OutPoint {
        txid: funding.txid(),
        vout: 0,
    };
    let finalized = TransactionContext::InChainLockedBlock(BlockInfo::new(
        40,
        BlockHash::from_byte_array([0x40; 32]),
        1_699_999_000,
    ));
    let funding_result = live
        .managed_wallet
        .check_core_transaction(&funding, finalized.clone(), &mut live.wallet, true, true)
        .await;
    let spending = spend(parent);
    let spend_result = live
        .managed_wallet
        .check_core_transaction(&spending, finalized.clone(), &mut live.wallet, true, true)
        .await;
    let records = funding_result.new_records.into_iter().chain(spend_result.new_records).collect();
    restored
        .restore_persisted_state(PersistedWalletState {
            transactions: records,
            ..Default::default()
        })
        .unwrap();
    assert_funds_equal(&live.managed_wallet, &restored);
    for state in [&mut live.managed_wallet, &mut restored] {
        state
            .check_core_transaction(&funding, finalized.clone(), &mut live.wallet, true, true)
            .await;
    }
    assert_funds_equal(&live.managed_wallet, &restored);
    assert!(restored
        .first_bip44_managed_account()
        .unwrap()
        .transaction_is_finalized(&spending.txid()));
    assert!(restored.first_bip44_managed_account().unwrap().utxos.is_empty());
}

#[tokio::test]
async fn should_restore_spend_before_funding_input_recognition() {
    let mut live = TestWalletContext::new_random();
    let mut restored = live.managed_wallet.clone();
    let funding = Transaction::dummy(&live.receive_address, 0..1, &[1_000_000]);
    let parent = OutPoint {
        txid: funding.txid(),
        vout: 0,
    };
    let spending = spend(parent);
    let context = TransactionContext::InBlock(BlockInfo::new(
        40,
        BlockHash::from_byte_array([0x40; 32]),
        1_699_999_000,
    ));
    live.managed_wallet
        .check_core_transaction(&spending, context.clone(), &mut live.wallet, true, true)
        .await;
    let funding_result = live
        .managed_wallet
        .check_core_transaction(&funding, context.clone(), &mut live.wallet, true, true)
        .await;
    restored
        .restore_persisted_state(PersistedWalletState {
            transactions: funding_result.new_records,
            additional_spent_outpoints: live
                .managed_wallet
                .observed_spent_outpoints()
                .iter()
                .map(|(outpoint, height)| (*outpoint, Some(*height)))
                .collect(),
            ..Default::default()
        })
        .unwrap();
    let live_result = live
        .managed_wallet
        .check_core_transaction(&spending, context.clone(), &mut live.wallet, true, true)
        .await;
    let restored_result =
        restored.check_core_transaction(&spending, context, &mut live.wallet, true, true).await;
    assert_eq!(live_result.new_records.len(), 1);
    assert_eq!(restored_result.new_records.len(), 1);
    assert_eq!(live_result.new_records[0].net_amount, restored_result.new_records[0].net_amount);
    assert_eq!(
        live_result.new_records[0].input_details.len(),
        restored_result.new_records[0].input_details.len()
    );
    assert_funds_equal(&live.managed_wallet, &restored);
}

#[test_case::test_case(false; "funds_record")]
#[test_case::test_case(true; "keys_record")]
#[tokio::test]
async fn should_block_cross_account_funding_with_one_persisted_spend_record_and_release_it(
    keys_only: bool,
) {
    use crate::wallet::managed_wallet_info::ManagedAccountOperations;
    let mut template = TestWalletContext::new_random();
    let other = TestWalletContext::new_random();
    let other_type = if keys_only {
        AccountType::IdentityRegistration
    } else {
        AccountType::Standard {
            index: 1,
            standard_account_type: StandardAccountType::BIP44Account,
        }
    };
    if !template
        .managed_wallet
        .accounts
        .all_accounts()
        .iter()
        .any(|account| account.managed_account_type().to_account_type() == other_type)
    {
        template.managed_wallet.add_managed_account_from_xpub(other_type, other.xpub).unwrap();
    }
    let funding = Transaction::dummy(&template.receive_address, 0..1, &[1_000_000]);
    let parent = OutPoint {
        txid: funding.txid(),
        vout: 0,
    };
    let mut record = spending_record(
        spend(parent),
        template.receive_address.clone(),
        TransactionContext::Mempool,
    );
    record.account_type = other_type;
    let claimant = record.txid;
    template
        .managed_wallet
        .restore_persisted_state(PersistedWalletState {
            transactions: vec![record],
            additional_spent_outpoints: BTreeMap::from([(parent, None)]),
            ..Default::default()
        })
        .unwrap();
    let context = TransactionContext::InBlock(BlockInfo::new(
        40,
        BlockHash::from_byte_array([0x40; 32]),
        1_699_999_000,
    ));
    template
        .managed_wallet
        .check_core_transaction(&funding, context.clone(), &mut template.wallet, true, true)
        .await;
    assert!(
        !template.managed_wallet.first_bip44_managed_account().unwrap().utxos.contains_key(&parent),
        "another account's claim must block the funding owner too"
    );
    template.managed_wallet.abandon_transaction(claimant);
    template
        .managed_wallet
        .check_core_transaction(&funding, context, &mut template.wallet, true, true)
        .await;
    assert!(
        template.managed_wallet.first_bip44_managed_account().unwrap().utxos.contains_key(&parent),
        "the cross-account guard must release when its record is abandoned"
    );
}

#[tokio::test]
async fn should_sweep_restored_keys_loser_and_funds_descendant_and_release_extra_input() {
    let mut template = TestWalletContext::new_random();
    let funding = Transaction::dummy(&template.receive_address, 0..1, &[1_000_000, 2_000_000]);
    let parent = OutPoint {
        txid: funding.txid(),
        vout: 0,
    };
    let extra = OutPoint {
        txid: funding.txid(),
        vout: 1,
    };
    let mut root = spend(parent);
    root.input.push(TxIn {
        previous_output: extra,
        script_sig: ScriptBuf::new(),
        sequence: u32::MAX,
        witness: Witness::new(),
    });
    let root_txid = root.txid();
    let mut root_record =
        spending_record(root, template.receive_address.clone(), TransactionContext::Mempool);
    root_record.account_type = AccountType::IdentityRegistration;
    let mut child = spend(OutPoint {
        txid: root_txid,
        vout: 0,
    });
    child.output[0].script_pubkey = template.receive_address.script_pubkey();
    let child_coin = coin(&child, &template.receive_address);
    let child_txid = child.txid();
    let child_record =
        spending_record(child, template.receive_address.clone(), TransactionContext::Mempool);
    template
        .managed_wallet
        .restore_persisted_state(PersistedWalletState {
            transactions: vec![root_record, child_record],
            utxos: vec![(bip44(), child_coin)],
            additional_spent_outpoints: BTreeMap::from([(parent, None), (extra, None)]),
        })
        .unwrap();
    let context = TransactionContext::InBlock(BlockInfo::new(
        80,
        BlockHash::from_byte_array([0x80; 32]),
        1_699_999_000,
    ));
    let result = template
        .managed_wallet
        .check_core_transaction(
            &competing_spend(parent),
            context.clone(),
            &mut template.wallet,
            true,
            true,
        )
        .await;
    assert!(result.swept_transactions.contains(&root_txid));
    assert!(result.swept_transactions.contains(&child_txid));
    assert_eq!(result.released_outpoints, vec![extra]);
    assert!(template.managed_wallet.first_bip44_managed_account().unwrap().utxos.is_empty());
    template
        .managed_wallet
        .check_core_transaction(&funding, context, &mut template.wallet, true, true)
        .await;
    let coins = &template.managed_wallet.first_bip44_managed_account().unwrap().utxos;
    assert!(!coins.contains_key(&parent));
    assert!(coins.contains_key(&extra));
}

#[test]
fn should_reject_balance_overflow_before_installing_coins() {
    let template = TestWalletContext::new_random();
    let funding = Transaction::dummy(&template.receive_address, 0..1, &[u64::MAX, 1]);
    let first = coin(&funding, &template.receive_address);
    let mut second = first.clone();
    second.outpoint.vout = 1;
    second.txout = funding.output[1].clone();
    let mut wallet = template.managed_wallet;
    assert!(wallet
        .restore_persisted_state(PersistedWalletState {
            utxos: vec![(bip44(), first), (bip44(), second)],
            ..Default::default()
        })
        .is_err());
    assert!(wallet.first_bip44_managed_account().unwrap().utxos.is_empty());
}
