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
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::managed_wallet_info::{PersistedWalletState, RestoreError};
use crate::wallet::ManagedWalletInfo;
use crate::AccountType;
use dashcore::hashes::Hash;
use dashcore::{
    BlockHash, ChainLock, InstantLock, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Witness,
};
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

#[test_case::test_case(false, false; "sync_checkpoint")]
#[test_case::test_case(true, false; "chain_lock")]
#[test_case::test_case(false, true; "sync_checkpoint_after_abandon")]
#[test_case::test_case(true, true; "chain_lock_after_abandon")]
#[tokio::test]
async fn should_preserve_supplemental_block_spends_after_pruning(
    chain_lock_trigger: bool,
    with_record_claim: bool,
) {
    let mut ctx = TestWalletContext::from_seed([21; 64]);
    let funding = Transaction::dummy(&ctx.receive_address, 0..1, &[1_000_000]);
    let parent = OutPoint {
        txid: funding.txid(),
        vout: 0,
    };
    let claimant = spend(parent);
    let claimant_txid = claimant.txid();
    ctx.managed_wallet.apply_chain_lock(ChainLock {
        block_height: 100,
        block_hash: BlockHash::from_byte_array([100; 32]),
        signature: [0; 96].into(),
    });
    ctx.managed_wallet.update_synced_height(100);
    ctx.managed_wallet
        .restore_persisted_state(PersistedWalletState {
            transactions: if with_record_claim {
                vec![spending_record(
                    claimant,
                    ctx.receive_address.clone(),
                    TransactionContext::Mempool,
                )]
            } else {
                Vec::new()
            },
            additional_spent_outpoints: BTreeMap::from([(parent, Some(80))]),
            ..Default::default()
        })
        .unwrap();

    for round in 0..2 {
        if chain_lock_trigger {
            ctx.managed_wallet.apply_chain_lock(ChainLock {
                block_height: 101 + round,
                block_hash: BlockHash::from_byte_array([101; 32]),
                signature: [0; 96].into(),
            });
        } else {
            ctx.managed_wallet.update_synced_height(100);
        }
        if with_record_claim {
            ctx.managed_wallet.abandon_transaction(claimant_txid);
        }

        ctx.managed_wallet
            .check_core_transaction(
                &funding,
                TransactionContext::Mempool,
                &mut ctx.wallet,
                true,
                true,
            )
            .await;
        assert!(
            !ctx.managed_wallet.first_bip44_managed_account().unwrap().utxos.contains_key(&parent),
            "pruning must not resurrect a coin protected only by restored block evidence"
        );

        let mut conflicting = competing_spend(parent);
        conflicting.output[0].script_pubkey = ctx.receive_address.script_pubkey();
        ctx.managed_wallet
            .check_core_transaction(
                &conflicting,
                TransactionContext::Mempool,
                &mut ctx.wallet,
                true,
                true,
            )
            .await;
        assert!(
            ctx.managed_wallet.first_bip44_managed_account().unwrap().utxos.is_empty(),
            "restored block evidence must still reject outputs of a conflicting mempool spend"
        );
        assert_eq!(ctx.managed_wallet.observed_spent_outpoints().get(&parent), Some(&80));

        // Redelivery after serialization must exercise insertion, not known-record deduplication.
        ctx.managed_wallet.abandon_transaction(funding.txid());
        ctx.managed_wallet.abandon_transaction(conflicting.txid());
        #[cfg(feature = "serde")]
        if round == 0 {
            // Address pools have non-string JSON map keys; round-trip the wallet evidence alone.
            let accounts = std::mem::take(&mut ctx.managed_wallet.accounts);
            let json = serde_json::to_string(&ctx.managed_wallet).unwrap();
            ctx.managed_wallet = serde_json::from_str(&json).unwrap();
            ctx.managed_wallet.accounts = accounts;
        }
    }
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
async fn should_preserve_restored_keys_record_spends_after_pruning() {
    let mut ctx = TestWalletContext::from_seed([22; 64]);
    let funding = Transaction::dummy(&ctx.receive_address, 0..1, &[1_000_000]);
    let parent = OutPoint {
        txid: funding.txid(),
        vout: 0,
    };
    let mut record = spending_record(
        spend(parent),
        ctx.receive_address.clone(),
        TransactionContext::InChainLockedBlock(BlockInfo::new(
            80,
            BlockHash::from_byte_array([80; 32]),
            1_700_000_000,
        )),
    );
    record.account_type = AccountType::IdentityRegistration;
    ctx.managed_wallet
        .restore_persisted_state(PersistedWalletState {
            transactions: vec![record],
            ..Default::default()
        })
        .unwrap();
    ctx.managed_wallet.update_synced_height(100);
    ctx.managed_wallet.apply_chain_lock(ChainLock {
        block_height: 100,
        block_hash: BlockHash::from_byte_array([100; 32]),
        signature: [0; 96].into(),
    });
    ctx.managed_wallet
        .check_core_transaction(&funding, TransactionContext::Mempool, &mut ctx.wallet, true, true)
        .await;
    assert!(ctx.managed_wallet.first_bip44_managed_account().unwrap().utxos.is_empty());
}

#[tokio::test]
async fn restored_spend_mark_blocks_funding_until_the_claim_is_released() {
    let template = TestWalletContext::from_seed([1; 64]);
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
    let template = TestWalletContext::from_seed([2; 64]);
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
    let template = TestWalletContext::from_seed([3; 64]);
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
    let template = TestWalletContext::from_seed([4; 64]);
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
fn should_invalidate_monitor_after_restoring_coins() {
    let mut ctx = TestWalletContext::from_seed([21; 64]);
    let funding = Transaction::dummy(&ctx.receive_address, 0..1, &[1_000_000]);
    let revision = ctx.managed_wallet.monitor_revision();
    let elements = ctx.managed_wallet.monitored_filter_elements();
    ctx.managed_wallet
        .restore_persisted_state(PersistedWalletState {
            utxos: vec![(bip44(), coin(&funding, &ctx.receive_address))],
            ..Default::default()
        })
        .unwrap();
    assert_ne!(elements, ctx.managed_wallet.monitored_filter_elements());
    assert!(ctx.managed_wallet.monitor_revision() > revision);
}

#[test_case::test_case(0, true; "mempool_confirmed")]
#[test_case::test_case(0, false; "mempool_instantlocked")]
#[test_case::test_case(1, true; "instant_send_confirmed")]
#[test_case::test_case(1, false; "instant_send_without_lock_flag")]
#[test_case::test_case(2, true; "block_unconfirmed")]
#[test_case::test_case(3, true; "chainlock_unconfirmed")]
#[tokio::test]
async fn should_reject_inconsistent_coin_finality(context_kind: u8, flip_confirmed: bool) {
    let mut live = TestWalletContext::from_seed([22; 64]);
    let mut restored = live.managed_wallet.clone();
    let funding = Transaction::dummy(&live.receive_address, 0..1, &[1_000_000]);
    let block = BlockInfo::new(40, BlockHash::from_byte_array([40; 32]), 1_700_000_000);
    let context = match context_kind {
        0 => TransactionContext::Mempool,
        1 => TransactionContext::InstantSend(InstantLock {
            txid: funding.txid(),
            ..Default::default()
        }),
        2 => TransactionContext::InBlock(block),
        _ => TransactionContext::InChainLockedBlock(block),
    };
    let result = live.check_transaction(&funding, context).await;
    let mut utxo = live.first_utxo().clone();
    let snapshot = PersistedWalletState {
        transactions: result.new_records,
        utxos: vec![(bip44(), utxo.clone())],
        ..Default::default()
    };
    let mut control = restored.clone();
    control.restore_persisted_state(snapshot.clone()).unwrap();
    assert_eq!(control.balance(), live.managed_wallet.balance());
    if flip_confirmed {
        utxo.is_confirmed = !utxo.is_confirmed;
    } else {
        utxo.is_instantlocked = !utxo.is_instantlocked;
    }
    let revision = restored.monitor_revision();
    let elements = restored.monitored_filter_elements();
    assert_eq!(
        restored.restore_persisted_state(PersistedWalletState {
            utxos: vec![(bip44(), utxo.clone())],
            ..snapshot
        }),
        Err(RestoreError::InvalidUtxo(utxo.outpoint))
    );
    assert_eq!(restored.monitor_revision(), revision);
    assert_eq!(restored.monitored_filter_elements(), elements);
    assert!(restored.transaction_history().is_empty());
    assert!(restored.observed_spent_outpoints().is_empty());
    assert!(restored.instant_send_locks.is_empty());
    assert_eq!(restored.balance().total(), 0);
}

#[test_case::test_case(0, false; "mempool_block")]
#[test_case::test_case(0, true; "block_mempool")]
#[test_case::test_case(1, false; "mempool_instant_send")]
#[test_case::test_case(1, true; "instant_send_mempool")]
#[test_case::test_case(2, false; "different_height")]
#[test_case::test_case(2, true; "different_height_reversed")]
#[test_case::test_case(3, false; "different_hash")]
#[test_case::test_case(4, false; "block_chainlock")]
#[test_case::test_case(5, false; "same_block")]
#[test_case::test_case(6, false; "optional_block_position")]
fn should_validate_lifecycle_across_accounts(context_kind: u8, reverse: bool) {
    use crate::wallet::managed_wallet_info::ManagedAccountOperations;
    let mut ctx = TestWalletContext::from_seed([23; 64]);
    let other = TestWalletContext::from_seed([24; 64]);
    let other_type = AccountType::Standard {
        index: 1,
        standard_account_type: StandardAccountType::BIP44Account,
    };
    ctx.managed_wallet.add_managed_account_from_xpub(other_type, other.xpub).unwrap();
    let funding = Transaction::dummy(&ctx.receive_address, 0..1, &[1_000_000]);
    let tx = spend(OutPoint {
        txid: funding.txid(),
        vout: 0,
    });
    let block = BlockInfo::new(40, BlockHash::from_byte_array([40; 32]), 1_700_000_000);
    let (first, second) = match context_kind {
        0 => (TransactionContext::Mempool, TransactionContext::InBlock(block)),
        1 => (
            TransactionContext::Mempool,
            TransactionContext::InstantSend(InstantLock {
                txid: tx.txid(),
                ..Default::default()
            }),
        ),
        2 => (
            TransactionContext::InBlock(block),
            TransactionContext::InBlock(BlockInfo::new(41, block.block_hash(), block.timestamp())),
        ),
        3 => (
            TransactionContext::InBlock(block),
            TransactionContext::InBlock(BlockInfo::new(
                40,
                BlockHash::from_byte_array([41; 32]),
                block.timestamp(),
            )),
        ),
        4 => (TransactionContext::InBlock(block), TransactionContext::InChainLockedBlock(block)),
        5 => (TransactionContext::InBlock(block), TransactionContext::InBlock(block)),
        _ => (
            TransactionContext::InBlock(block),
            TransactionContext::InBlock(block.with_position(2)),
        ),
    };
    let first_record = spending_record(tx.clone(), ctx.receive_address.clone(), first);
    let mut second_record = spending_record(tx.clone(), ctx.receive_address.clone(), second);
    second_record.account_type = other_type;
    let mut records = vec![first_record, second_record];
    if reverse {
        records.reverse();
    }
    let revision = ctx.managed_wallet.monitor_revision();
    let result = ctx.managed_wallet.restore_persisted_state(PersistedWalletState {
        transactions: records,
        ..Default::default()
    });
    if context_kind >= 5 {
        assert_eq!(result, Ok(()));
        assert_eq!(ctx.managed_wallet.transaction_history().len(), 2);
    } else {
        assert_eq!(result, Err(RestoreError::InvalidRecord(tx.txid())));
        assert!(ctx.managed_wallet.transaction_history().is_empty());
        assert!(ctx.managed_wallet.observed_spent_outpoints().is_empty());
        assert!(ctx.managed_wallet.instant_send_locks.is_empty());
    }
    assert_eq!(ctx.managed_wallet.monitor_revision(), revision);
}

#[test]
fn should_reject_entire_snapshot_before_mutating_any_account() {
    let template = TestWalletContext::from_seed([5; 64]);
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
    let template = TestWalletContext::from_seed([6; 64]);
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
    let mut template = TestWalletContext::from_seed([7; 64]);
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
    let mut template = TestWalletContext::from_seed([8; 64]);
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
    let mut uninterrupted = TestWalletContext::from_seed([9; 64]);
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
    let mut live = TestWalletContext::from_seed([10; 64]);
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
    let mut live = TestWalletContext::from_seed([11; 64]);
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
    let mut template = TestWalletContext::from_seed([12; 64]);
    let other = TestWalletContext::from_seed([13; 64]);
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

#[test_case::test_case(false; "block_winner")]
#[test_case::test_case(true; "instant_send_winner")]
#[tokio::test]
async fn should_sweep_restored_keys_loser_and_funds_descendant_and_release_extra_input(
    instant_send: bool,
) {
    let mut template = TestWalletContext::from_seed([14; 64]);
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
            if instant_send {
                TransactionContext::InstantSend(InstantLock::default())
            } else {
                context.clone()
            },
            &mut template.wallet,
            true,
            true,
        )
        .await;
    assert!(result.new_records.is_empty(), "the external winner has no retained wallet record");
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
    let template = TestWalletContext::from_seed([15; 64]);
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

#[tokio::test]
async fn should_preserve_cross_account_input_recognition_after_restore() {
    let mut template = TestWalletContext::from_seed([16; 64]);
    let other_xpub = template.wallet.accounts.standard_bip32_accounts.get(&0).unwrap().account_xpub;
    let other_address = template
        .managed_wallet
        .first_bip32_managed_account_mut()
        .unwrap()
        .next_receive_address(Some(&other_xpub), true)
        .unwrap();
    let mut restored = template.managed_wallet.clone();
    let funding = Transaction::dummy(&template.receive_address, 0..1, &[1_000_000]);
    let parent = OutPoint {
        txid: funding.txid(),
        vout: 0,
    };
    let mut spending = spend(parent);
    spending.output[0].script_pubkey = other_address.script_pubkey();
    template
        .managed_wallet
        .check_core_transaction(
            &spending,
            TransactionContext::Mempool,
            &mut template.wallet,
            true,
            true,
        )
        .await;
    let context = TransactionContext::InBlock(BlockInfo::new(
        40,
        BlockHash::from_byte_array([40; 32]),
        1_700_000_000,
    ));
    template
        .managed_wallet
        .check_core_transaction(&funding, context.clone(), &mut template.wallet, true, true)
        .await;
    let records = template
        .managed_wallet
        .accounts
        .all_accounts()
        .into_iter()
        .flat_map(|account| account.transactions().values().cloned())
        .collect();
    restored
        .restore_persisted_state(PersistedWalletState {
            transactions: records,
            utxos: template
                .managed_wallet
                .accounts
                .all_accounts()
                .into_iter()
                .filter_map(|account| account.as_funds())
                .flat_map(|account| {
                    account
                        .utxos
                        .values()
                        .cloned()
                        .map(|utxo| (account.managed_account_type().to_account_type(), utxo))
                })
                .collect(),
            additional_spent_outpoints: template
                .managed_wallet
                .observed_spent_outpoints()
                .iter()
                .map(|(outpoint, height)| (*outpoint, Some(*height)))
                .chain([(parent, None)])
                .collect(),
        })
        .unwrap();
    let live_result = template
        .managed_wallet
        .check_core_transaction(&spending, context.clone(), &mut template.wallet, true, true)
        .await;
    let restored_result =
        restored.check_core_transaction(&spending, context, &mut template.wallet, true, true).await;
    assert_eq!(live_result.new_records.len(), 1);
    assert_eq!(live_result.new_records[0].account_type, bip44());
    assert_eq!(live_result.new_records[0].net_amount, -1_000_000);
    assert_eq!(live_result.new_records[0].input_details.len(), 1);
    assert_eq!(restored_result.new_records.len(), live_result.new_records.len());
    let debit = &restored_result.new_records[0];
    assert_eq!(debit.account_type, bip44());
    assert_eq!(debit.net_amount, -1_000_000);
    assert_eq!(debit.input_details.len(), 1);
    assert_eq!(debit.input_details[0].value, 1_000_000);
}

#[test]
fn should_reject_coin_owned_by_another_wallet() {
    let owner = TestWalletContext::from_seed([17; 64]);
    let mut receiver = TestWalletContext::from_seed([18; 64]);
    assert!(!receiver.bip44_account().contains_address(&owner.receive_address));
    let tx = Transaction::dummy(&owner.receive_address, 0..1, &[1_000_000]);
    let outpoint = OutPoint {
        txid: tx.txid(),
        vout: 0,
    };
    let mut coin = Utxo::new(outpoint, tx.output[0].clone(), owner.receive_address, 100, false);
    coin.is_confirmed = true;
    let result = receiver.managed_wallet.restore_persisted_state(PersistedWalletState {
        utxos: vec![(bip44(), coin)],
        ..Default::default()
    });
    assert_eq!(result, Err(RestoreError::InvalidUtxo(outpoint)));
    assert!(receiver.bip44_account().utxos.is_empty());
}

#[test_case::test_case(false; "coinbase_flag")]
#[test_case::test_case(true; "block_height")]
fn should_reject_coinbase_metadata_disagreeing_with_record(invalid_height: bool) {
    let mut receiver = TestWalletContext::from_seed([19; 64]);
    receiver.managed_wallet.update_last_processed_height(100);
    let mut tx = Transaction::dummy(&receiver.receive_address, 0..1, &[1_000_000]);
    tx.input[0].previous_output = OutPoint::null();
    assert!(tx.is_coin_base());
    let outpoint = OutPoint {
        txid: tx.txid(),
        vout: 0,
    };
    let mut coin =
        Utxo::new(outpoint, tx.output[0].clone(), receiver.receive_address.clone(), 100, true);
    coin.is_confirmed = true;
    let record = TransactionRecord::new(
        tx,
        bip44(),
        TransactionContext::InBlock(BlockInfo::new(100, BlockHash::all_zeros(), 0)),
        TransactionType::Standard,
        TransactionDirection::Incoming,
        vec![],
        vec![],
        1_000_000,
    );
    let mut control = receiver.managed_wallet.clone();
    control
        .restore_persisted_state(PersistedWalletState {
            transactions: vec![record.clone()],
            utxos: vec![(bip44(), coin.clone())],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(control.balance().immature(), 1_000_000);
    assert!(!control.first_bip44_managed_account().unwrap().utxos[&outpoint].is_spendable(100));
    if invalid_height {
        coin.height = 0;
    } else {
        coin.is_coinbase = false;
    }
    let result = receiver.managed_wallet.restore_persisted_state(PersistedWalletState {
        transactions: vec![record],
        utxos: vec![(bip44(), coin)],
        ..Default::default()
    });
    assert_eq!(result, Err(RestoreError::InvalidUtxo(outpoint)));
    assert!(receiver.bip44_account().utxos.is_empty());
    assert!(receiver.bip44_account().transactions().is_empty());
    assert!(receiver.managed_wallet.observed_spent_outpoints().is_empty());
}

#[test_case::test_case(false; "unspent")]
#[test_case::test_case(true; "fully_spent")]
#[tokio::test]
async fn should_preserve_restored_block_context_on_duplicate_instant_lock(fully_spent: bool) {
    let mut live = TestWalletContext::from_seed([20; 64]);
    let mut restored = live.managed_wallet.clone();
    let funding = Transaction::dummy(&live.receive_address, 0..1, &[1_000_000]);
    let txid = funding.txid();
    let lock = InstantLock {
        txid,
        ..InstantLock::default()
    };
    live.check_transaction(&funding, TransactionContext::Mempool).await;
    assert!(live.managed_wallet.mark_instant_send_utxos(&txid, &lock));
    let block_info = BlockInfo::new(40, BlockHash::from_byte_array([40; 32]), 1_700_000_000);
    let block = TransactionContext::InBlock(block_info);
    live.check_transaction(&funding, block.clone()).await;
    assert_eq!(live.transaction(&txid).context, block);
    if fully_spent {
        live.check_transaction(
            &spend(OutPoint {
                txid,
                vout: 0,
            }),
            block.clone(),
        )
        .await;
        assert!(live.bip44_account().utxos.is_empty());
    }
    let account = live.bip44_account();
    restored
        .restore_persisted_state(PersistedWalletState {
            transactions: account.transactions().values().cloned().collect(),
            utxos: account.utxos.values().cloned().map(|coin| (bip44(), coin)).collect(),
            additional_spent_outpoints: live
                .managed_wallet
                .observed_spent_outpoints()
                .iter()
                .map(|(outpoint, height)| (*outpoint, Some(*height)))
                .collect(),
        })
        .unwrap();
    assert!(!live.managed_wallet.mark_instant_send_utxos(&txid, &lock));
    restored.mark_instant_send_utxos(&txid, &lock);
    assert_eq!(
        restored.first_bip44_managed_account().unwrap().transactions()[&txid].context,
        block
    );
    assert!(!restored.mark_instant_send_utxos(&txid, &lock));
    restored.apply_chain_lock(dashcore::ChainLock {
        block_height: 40,
        block_hash: BlockHash::from_byte_array([40; 32]),
        signature: [0u8; 96].into(),
    });
    let account = restored.first_bip44_managed_account().unwrap();
    assert!(account.transaction_is_finalized(&txid));
    #[cfg(feature = "keep-finalized-transactions")]
    assert_eq!(
        account.transactions()[&txid].context,
        TransactionContext::InChainLockedBlock(block_info)
    );
    // A further delivery must also leave finalized history intact.
    restored.instant_send_locks.remove(&txid);
    restored.mark_instant_send_utxos(&txid, &lock);
    assert!(restored.first_bip44_managed_account().unwrap().transaction_is_finalized(&txid));
}
