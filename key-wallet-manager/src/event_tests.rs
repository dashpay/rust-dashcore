use super::test_helpers::*;
use super::*;
use crate::wallet_interface::WalletInterface;
use dashcore::block::{Block, Header, Version};
use dashcore::blockdata::script::Builder;
use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::hash_types::CycleHash;
use dashcore::hashes::Hash;
use dashcore::opcodes;
use dashcore::{
    BlockHash, CompactTarget, OutPoint, ScriptBuf, TxIn, TxMerkleNode, TxOut, Txid, Witness,
};
use key_wallet::account::StandardAccountType;
use key_wallet::AccountType;

fn make_block(txdata: Vec<Transaction>, seed: u8, time: u32) -> Block {
    Block {
        header: Header {
            version: Version::default(),
            prev_blockhash: BlockHash::from_byte_array([seed; 32]),
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        },
        txdata,
    }
}

fn make_coinbase_paying_to(addr: &Address, value: u64) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0xffffffff,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value,
            script_pubkey: addr.script_pubkey(),
        }],
        special_transaction_payload: None,
    }
}

// ---------------------------------------------------------------------------
// Mempool path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mempool_tx_emits_single_event_with_balance() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&addr, 0xaa);

    manager.process_mempool_transaction(&tx, None).await;

    let events = drain_events(&mut rx);
    assert_eq!(events.len(), 1, "exactly one event expected, got {:?}", events);
    match &events[0] {
        WalletEvent::TransactionDetected {
            wallet_id: wid,
            record,
            balance,
        } => {
            assert_eq!(*wid, wallet_id);
            assert_eq!(record.txid, tx.txid());
            assert_eq!(record.context, TransactionContext::Mempool);
            assert_eq!(record.net_amount, TX_AMOUNT as i64);
            assert!(matches!(
                record.account_type,
                AccountType::Standard {
                    index: 0,
                    standard_account_type: StandardAccountType::BIP44Account
                }
            ));
            assert_eq!(balance.unconfirmed(), TX_AMOUNT);
            assert_eq!(balance.confirmed(), 0);
        }
        other => panic!("expected TransactionDetected, got {:?}", other),
    }
}

#[tokio::test]
async fn test_mempool_tx_with_instant_lock_emits_detected_event_with_locked_balance() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&addr, 0xbb);

    manager.process_mempool_transaction(&tx, Some(dummy_instant_lock(tx.txid()))).await;

    let events = drain_events(&mut rx);
    assert_eq!(events.len(), 1, "one event expected for first-seen IS-locked tx, got {:?}", events);
    match &events[0] {
        WalletEvent::TransactionDetected {
            wallet_id: wid,
            record,
            balance,
        } => {
            assert_eq!(*wid, wallet_id);
            assert!(matches!(record.context, TransactionContext::InstantSend(_)));
            assert_eq!(balance.confirmed(), TX_AMOUNT);
            assert_eq!(balance.unconfirmed(), 0);
        }
        other => panic!("expected TransactionDetected with IS context, got {:?}", other),
    }
}

#[tokio::test]
async fn test_irrelevant_mempool_tx_emits_no_events() {
    use dashcore::{PublicKey, ScriptBuf};

    let (mut manager, _wallet_id, _addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();

    let random_script =
        ScriptBuf::new_p2pkh(&PublicKey::from_slice(&[2; 33]).unwrap().pubkey_hash());
    let tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![dashcore::TxIn {
            previous_output: dashcore::OutPoint {
                txid: dashcore::Txid::from_byte_array([0xe4; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: u32::MAX,
            witness: dashcore::Witness::default(),
        }],
        output: vec![dashcore::TxOut {
            value: TX_AMOUNT,
            script_pubkey: random_script,
        }],
        special_transaction_payload: None,
    };

    let result = manager.process_mempool_transaction(&tx, None).await;
    assert!(!result.is_relevant);
    assert_no_events(&mut rx);
}

// ---------------------------------------------------------------------------
// InstantSend path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_instant_send_lock_on_known_mempool_tx_emits_instant_locked_event() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let tx = create_tx_paying_to(&addr, 0xe1);

    // First see the tx as plain mempool
    manager.process_mempool_transaction(&tx, None).await;
    let pre_lock_balance = manager.get_wallet_info(&wallet_id).unwrap().balance();
    assert_eq!(pre_lock_balance.confirmed(), 0);
    assert_eq!(pre_lock_balance.unconfirmed(), TX_AMOUNT);
    let mut rx = manager.subscribe_events();

    let lock = InstantLock {
        txid: tx.txid(),
        cyclehash: CycleHash::from_byte_array([0xab; 32]),
        signature: BLSSignature::from([0xcd; 96]),
        ..InstantLock::default()
    };
    manager.process_instant_send_lock(lock.clone());

    let events = drain_events(&mut rx);
    assert_eq!(events.len(), 1, "exactly one event expected, got {:?}", events);
    match &events[0] {
        WalletEvent::TransactionInstantLocked {
            wallet_id: wid,
            txid,
            instant_lock,
            balance,
        } => {
            assert_eq!(*wid, wallet_id);
            assert_eq!(*txid, tx.txid());
            assert_eq!(*instant_lock, lock);
            assert_eq!(balance.confirmed(), TX_AMOUNT);
            assert_eq!(balance.unconfirmed(), 0);
        }
        other => panic!("expected TransactionInstantLocked, got {:?}", other),
    }
}

#[tokio::test]
async fn test_instant_send_lock_dedup_second_is_silent() {
    let (mut manager, _wallet_id, addr) = setup_manager_with_wallet();
    let tx = create_tx_paying_to(&addr, 0xe2);

    manager.process_mempool_transaction(&tx, None).await;
    manager.process_instant_send_lock(dummy_instant_lock(tx.txid()));

    let mut rx = manager.subscribe_events();
    manager.process_instant_send_lock(dummy_instant_lock(tx.txid()));
    assert_no_events(&mut rx);
}

#[tokio::test]
async fn test_instant_send_lock_for_unknown_txid_is_silent() {
    let (mut manager, _wallet_id, _addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let unknown_txid = Txid::from_byte_array([0xee; 32]);

    manager.process_instant_send_lock(dummy_instant_lock(unknown_txid));
    assert_no_events(&mut rx);
}

#[tokio::test]
async fn test_late_instant_send_lock_after_block_confirmation_emits_event() {
    // A late IS-lock for a transaction that was already confirmed in a block
    // currently downgrades the record context from `InBlock(_)` back to
    // `InstantSend(_)` and re-emits `TransactionInstantLocked`. This test
    // pins down that observable behavior so any future change (silently
    // ignoring the late lock, rejecting it at the record layer) shows up as a
    // test failure rather than a silent semantic drift.
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let tx = create_tx_paying_to(&addr, 0xe3);

    // Confirm the transaction in a block first.
    let block = make_block(vec![tx.clone()], 0xe3, 4000);
    manager.process_block(&block, 300).await;

    let mut rx = manager.subscribe_events();
    let lock = InstantLock {
        txid: tx.txid(),
        cyclehash: CycleHash::from_byte_array([0xab; 32]),
        signature: BLSSignature::from([0xcd; 96]),
        ..InstantLock::default()
    };
    manager.process_instant_send_lock(lock.clone());

    let events = drain_events(&mut rx);
    let lock_event = events
        .iter()
        .find(|e| matches!(e, WalletEvent::TransactionInstantLocked { .. }))
        .unwrap_or_else(|| {
            panic!(
                "late IS-lock for an already-confirmed tx currently emits \
                 TransactionInstantLocked, got: {:?}",
                events
            )
        });
    match lock_event {
        WalletEvent::TransactionInstantLocked {
            wallet_id: wid,
            txid,
            instant_lock,
            ..
        } => {
            assert_eq!(*wid, wallet_id);
            assert_eq!(*txid, tx.txid());
            assert_eq!(*instant_lock, lock);
        }
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// Block path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_block_with_new_tx_emits_inserted_record() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&addr, 0xcc);
    let block = make_block(vec![tx.clone()], 0xcc, 1000);

    let result = manager.process_block(&block, 100).await;
    assert_eq!(result.new_txids.len(), 1);

    let events = drain_events(&mut rx);
    assert_eq!(events.len(), 1, "one event per affected wallet expected, got {:?}", events);
    match &events[0] {
        WalletEvent::BlockProcessed {
            wallet_id: wid,
            height,
            inserted,
            updated,
            matured,
            balance,
        } => {
            assert_eq!(*wid, wallet_id);
            assert_eq!(*height, 100);
            assert_eq!(inserted.len(), 1);
            assert!(updated.is_empty());
            assert!(matured.is_empty());
            assert!(matches!(
                inserted[0].account_type,
                AccountType::Standard {
                    index: 0,
                    standard_account_type: StandardAccountType::BIP44Account
                }
            ));
            assert_eq!(inserted[0].txid, tx.txid());
            assert!(matches!(
                inserted[0].context,
                TransactionContext::InBlock(info) if info.height() == 100
            ));
            assert_eq!(balance.confirmed(), TX_AMOUNT);
        }
        other => panic!("expected BlockProcessed, got {:?}", other),
    }
}

#[tokio::test]
async fn test_block_confirming_known_mempool_tx_emits_updated_record() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let tx = create_tx_paying_to(&addr, 0xdd);

    // Seen in mempool first
    manager.process_mempool_transaction(&tx, None).await;

    let mut rx = manager.subscribe_events();
    let block = make_block(vec![tx.clone()], 0xdd, 2000);
    manager.process_block(&block, 200).await;

    let events = drain_events(&mut rx);
    assert_eq!(events.len(), 1, "one BlockProcessed expected, got {:?}", events);
    match &events[0] {
        WalletEvent::BlockProcessed {
            wallet_id: wid,
            height,
            inserted,
            updated,
            matured,
            balance,
        } => {
            assert_eq!(*wid, wallet_id);
            assert_eq!(*height, 200);
            assert!(inserted.is_empty());
            assert_eq!(updated.len(), 1);
            assert!(matured.is_empty());
            assert_eq!(updated[0].txid, tx.txid());
            // Confirmation moves balance from unconfirmed to confirmed
            assert_eq!(balance.confirmed(), TX_AMOUNT);
            assert_eq!(balance.unconfirmed(), 0);
        }
        other => panic!("expected BlockProcessed with updated record, got {:?}", other),
    }
}

#[tokio::test]
async fn test_block_with_index_less_account_tx_carries_account_type() {
    // Index-less account variants (`IdentityRegistration`, `IdentityTopUpNotBound`,
    // `IdentityInvitation`, `AssetLockAddressTopUp`, `AssetLockShieldedAddressTopUp`,
    // `Provider*`) used to be silently dropped on the way out of `wallet_checker.rs`
    // because the old emission code only kept matches whose `account_index()` was
    // `Some(_)`. Verify they now flow through with the right `AccountType`.
    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();

    let xpub = manager
        .get_wallet(&wallet_id)
        .expect("wallet")
        .accounts
        .identity_registration
        .as_ref()
        .expect("default wallet should have an IdentityRegistration account")
        .account_xpub;
    let identity_address = manager
        .get_wallet_info_mut(&wallet_id)
        .expect("wallet info")
        .identity_registration_managed_account_mut()
        .expect("managed IdentityRegistration account")
        .next_address(Some(&xpub), true)
        .expect("identity registration address");

    // Build a DIP-2 AssetLock transaction whose `credit_outputs` pay to the
    // identity registration address. AssetLock funds aren't spendable on the
    // Core chain, so balance does not shift, but the account does receive a
    // record — which is exactly what we want to observe in `BlockProcessed`.
    let tx = Transaction {
        version: 3,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0xee; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: u32::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: 100_000_000,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::all::OP_RETURN)
                .push_slice([0u8; 20])
                .into_script(),
        }],
        special_transaction_payload: Some(TransactionPayload::AssetLockPayloadType(
            AssetLockPayload {
                version: 1,
                credit_outputs: vec![TxOut {
                    value: 100_000_000,
                    script_pubkey: identity_address.script_pubkey(),
                }],
            },
        )),
    };

    let mut rx = manager.subscribe_events();
    let block = make_block(vec![tx.clone()], 0xee, 9999);
    manager.process_block(&block, 9000).await;

    let events = drain_events(&mut rx);
    let block_event = events
        .iter()
        .find(|e| matches!(e, WalletEvent::BlockProcessed { .. }))
        .unwrap_or_else(|| panic!("expected a BlockProcessed event, got {:?}", events));

    match block_event {
        WalletEvent::BlockProcessed {
            wallet_id: wid,
            inserted,
            ..
        } => {
            assert_eq!(*wid, wallet_id);
            let identity_record = inserted
                .iter()
                .find(|r| matches!(r.account_type, AccountType::IdentityRegistration))
                .unwrap_or_else(|| {
                    panic!(
                        "expected an inserted record for AccountType::IdentityRegistration, \
                         got: {:?}",
                        inserted
                    )
                });
            assert_eq!(identity_record.txid, tx.txid());
        }
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn test_empty_block_for_idle_wallet_emits_nothing() {
    let (mut manager, _wallet_id, _addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let block = make_block(Vec::new(), 0x55, 3000);

    manager.process_block(&block, 50).await;
    assert_no_events(&mut rx);
}

#[tokio::test]
async fn test_block_processed_carries_matured_coinbase_record() {
    // A coinbase received at height H matures at H + 100. Process the
    // coinbase block first, then advance the chain past maturity by
    // processing further blocks. The block whose height crosses H + 100
    // must carry the matured coinbase in `BlockProcessed.matured`.
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let coinbase_tx = make_coinbase_paying_to(&addr, 5_000_000_000);
    let coinbase_height = 100;
    let coinbase_block = make_block(vec![coinbase_tx.clone()], 0xc0, 4000);
    manager.process_block(&coinbase_block, coinbase_height).await;

    // Advance to maturity height. With coinbase_height = 100, maturity is at
    // height 200. Processing block 200 must surface the matured record.
    let mut rx = manager.subscribe_events();
    let mature_block = make_block(Vec::new(), 0xc1, 5000);
    manager.process_block(&mature_block, coinbase_height + 100).await;

    let events = drain_events(&mut rx);
    let block_event = events
        .iter()
        .find(|e| matches!(e, WalletEvent::BlockProcessed { matured, .. } if !matured.is_empty()))
        .unwrap_or_else(|| {
            panic!("expected a BlockProcessed carrying matured coinbase, got {:?}", events)
        });

    match block_event {
        WalletEvent::BlockProcessed {
            wallet_id: wid,
            height,
            inserted,
            updated,
            matured,
            ..
        } => {
            assert_eq!(*wid, wallet_id);
            assert_eq!(*height, coinbase_height + 100);
            assert!(inserted.is_empty());
            assert!(updated.is_empty());
            assert_eq!(matured.len(), 1);
            assert_eq!(matured[0].txid, coinbase_tx.txid());
        }
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// SyncHeightAdvanced
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_update_synced_height_emits_event_per_wallet() {
    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();

    manager.update_synced_height(1000);

    let synced_events: Vec<_> = drain_events(&mut rx)
        .into_iter()
        .filter_map(|e| match e {
            WalletEvent::SyncHeightAdvanced {
                wallet_id,
                height,
            } => Some((wallet_id, height)),
            _ => None,
        })
        .collect();
    assert_eq!(synced_events, vec![(wallet_id, 1000)]);
}

#[tokio::test]
async fn test_update_synced_height_does_not_re_emit_when_unchanged() {
    let (mut manager, _wallet_id, _addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();

    manager.update_synced_height(2000);
    drain_events(&mut rx);

    // Re-calling with the same height must not emit another SyncHeightAdvanced
    manager.update_synced_height(2000);
    let events = drain_events(&mut rx);
    assert!(
        !events.iter().any(|e| matches!(e, WalletEvent::SyncHeightAdvanced { .. })),
        "no SyncHeightAdvanced should fire when height did not advance, got {:?}",
        events
    );

    // Going backwards also must not emit
    manager.update_synced_height(1500);
    let events = drain_events(&mut rx);
    assert!(
        !events.iter().any(|e| matches!(e, WalletEvent::SyncHeightAdvanced { .. })),
        "no SyncHeightAdvanced should fire when height went backwards, got {:?}",
        events
    );
}

// ---------------------------------------------------------------------------
// Dry run and irrelevant paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_check_transaction_does_not_emit_events_directly() {
    // Event emission is the caller's responsibility; the low-level check
    // function never emits so batch callers can defer emission until after
    // their own balance refresh.
    let (mut manager, _wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&addr, 0xd1);

    let result = manager
        .check_transaction_in_all_wallets(&tx, TransactionContext::Mempool, true, true)
        .await;
    assert!(!result.affected_wallets.is_empty());
    assert!(!result.per_wallet_new_records.is_empty());
    assert_no_events(&mut rx);
}

#[tokio::test]
async fn test_check_transaction_dry_run_does_not_persist_state() {
    let (mut manager, _wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&addr, 0xd2);

    let result = manager
        .check_transaction_in_all_wallets(&tx, TransactionContext::Mempool, false, false)
        .await;
    assert!(!result.affected_wallets.is_empty());
    assert_no_events(&mut rx);

    // Subsequent persist should still see the tx as new
    let result = manager
        .check_transaction_in_all_wallets(&tx, TransactionContext::Mempool, true, true)
        .await;
    assert!(result.is_new_transaction);
}
