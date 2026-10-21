use super::test_helpers::*;
use super::*;
use crate::wallet_interface::WalletInterface;
use dashcore::block::{Block, Header, Version};
use dashcore::blockdata::script::Builder;
use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::hash_types::CycleHash;
use dashcore::hashes::Hash;
use dashcore::opcodes;
use dashcore::{
    BlockHash, CompactTarget, OutPoint, PublicKey, ScriptBuf, TxIn, TxMerkleNode, TxOut, Txid,
    Witness,
};
use key_wallet::account::StandardAccountType;
use key_wallet::managed_account::address_pool::{AddressPoolType, PublicKeyType};
use key_wallet::managed_account::managed_account_trait::ManagedAccountTrait;
use key_wallet::managed_account::managed_account_type::ManagedAccountType;
use key_wallet::wallet::managed_wallet_info::transaction_building::AccountTypePreference;
use key_wallet::AccountType;
use std::collections::BTreeSet;

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
            account_balances,
            addresses_derived: _,
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
            // Only the BIP44 account that received the funds should be in
            // the diff; idle accounts are omitted.
            assert_eq!(
                account_balances.len(),
                1,
                "only the receiving account's balance should appear, got {:?}",
                account_balances
            );
            let receiving = AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            };
            let acct_balance = account_balances
                .get(&receiving)
                .expect("receiving account balance should be present");
            assert_eq!(acct_balance.unconfirmed(), TX_AMOUNT);
            assert_eq!(acct_balance.confirmed(), 0);
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
            account_balances,
            addresses_derived: _,
        } => {
            assert_eq!(*wid, wallet_id);
            assert!(matches!(record.context, TransactionContext::InstantSend(_)));
            assert_eq!(balance.confirmed(), TX_AMOUNT);
            assert_eq!(balance.unconfirmed(), 0);
            assert_eq!(account_balances.len(), 1, "only the receiving account should appear");
            let receiving = AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            };
            let acct_balance = account_balances
                .get(&receiving)
                .expect("receiving account balance should be present");
            assert_eq!(acct_balance.confirmed(), TX_AMOUNT);
            assert_eq!(acct_balance.unconfirmed(), 0);
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
            account_balances,
        } => {
            assert_eq!(*wid, wallet_id);
            assert_eq!(*txid, tx.txid());
            assert_eq!(*instant_lock, lock);
            assert_eq!(balance.confirmed(), TX_AMOUNT);
            assert_eq!(balance.unconfirmed(), 0);
            // The receiving account moved from unconfirmed -> confirmed,
            // so it must appear in the diff. Other accounts must not.
            assert_eq!(
                account_balances.len(),
                1,
                "only the affected account should appear, got {:?}",
                account_balances
            );
            let receiving = AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            };
            let acct_balance = account_balances
                .get(&receiving)
                .expect("receiving account balance should be present");
            assert_eq!(acct_balance.confirmed(), TX_AMOUNT);
            assert_eq!(acct_balance.unconfirmed(), 0);
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
    let wallets = BTreeSet::from([wallet_id]);
    manager.process_block_for_wallets(&block, 300, &wallets).await;

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

    let wallets = BTreeSet::from([wallet_id]);
    let result = manager.process_block_for_wallets(&block, 100, &wallets).await;
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
            account_balances,
            addresses_derived: _,
            chain_lock: _,
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
            // Only the receiving BIP44 account moved; idle accounts must
            // be omitted from the diff.
            assert_eq!(
                account_balances.len(),
                1,
                "only the receiving account should appear, got {:?}",
                account_balances
            );
            let receiving = AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            };
            let acct_balance = account_balances
                .get(&receiving)
                .expect("receiving account balance should be present");
            assert_eq!(acct_balance.confirmed(), TX_AMOUNT);
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
    let wallets = BTreeSet::from([wallet_id]);
    manager.process_block_for_wallets(&block, 200, &wallets).await;

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
            account_balances,
            addresses_derived: _,
            chain_lock: _,
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
            // The receiving account moved from unconfirmed -> confirmed,
            // so it must appear in the diff.
            let receiving = AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            };
            let acct_balance = account_balances
                .get(&receiving)
                .expect("receiving account balance should be present");
            assert_eq!(acct_balance.confirmed(), TX_AMOUNT);
            assert_eq!(acct_balance.unconfirmed(), 0);
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
    let wallets = BTreeSet::from([wallet_id]);
    manager.process_block_for_wallets(&block, 9000, &wallets).await;

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
    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let block = make_block(Vec::new(), 0x55, 3000);

    let wallets = BTreeSet::from([wallet_id]);
    manager.process_block_for_wallets(&block, 50, &wallets).await;
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
    let wallets = BTreeSet::from([wallet_id]);
    manager.process_block_for_wallets(&coinbase_block, coinbase_height, &wallets).await;

    // Advance to maturity height. With coinbase_height = 100, maturity is at
    // height 200. Processing block 200 must surface the matured record.
    let mut rx = manager.subscribe_events();
    let mature_block = make_block(Vec::new(), 0xc1, 5000);
    manager.process_block_for_wallets(&mature_block, coinbase_height + 100, &wallets).await;

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
async fn test_update_wallet_synced_height_emits_event_per_wallet() {
    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();

    manager.update_wallet_synced_height(&wallet_id, 1000);

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
async fn test_update_wallet_synced_height_does_not_re_emit_when_unchanged() {
    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();

    manager.update_wallet_synced_height(&wallet_id, 2000);
    drain_events(&mut rx);

    // Re-calling with the same height must not emit another SyncHeightAdvanced
    manager.update_wallet_synced_height(&wallet_id, 2000);
    let events = drain_events(&mut rx);
    assert!(
        !events.iter().any(|e| matches!(e, WalletEvent::SyncHeightAdvanced { .. })),
        "no SyncHeightAdvanced should fire when height did not advance, got {:?}",
        events
    );

    // Going backwards also must not emit
    manager.update_wallet_synced_height(&wallet_id, 1500);
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

// ---------------------------------------------------------------------------
// addresses_derived (gap-limit extension piggy-backed on the event)
// ---------------------------------------------------------------------------

/// Pull `(highest_generated_index, gap_limit)` and the address at the given
/// index for the BIP44 account 0 pool of the given type.
fn pool_state(
    manager: &WalletManager,
    wallet_id: &WalletId,
    pool_type: AddressPoolType,
) -> (u32, u32, Address) {
    let info = manager.get_wallet_info(wallet_id).expect("wallet info");
    let acct = info
        .accounts
        .standard_bip44_accounts
        .get(&0)
        .expect("BIP44 account 0 should exist on the default test wallet");
    let pool = match (acct.managed_account_type(), pool_type) {
        (
            ManagedAccountType::Standard {
                external_addresses,
                ..
            },
            AddressPoolType::External,
        ) => external_addresses,
        (
            ManagedAccountType::Standard {
                internal_addresses,
                ..
            },
            AddressPoolType::Internal,
        ) => internal_addresses,
        _ => panic!("unexpected pool type {:?}", pool_type),
    };
    let highest = pool.highest_generated.expect("pre-generated pool must have addresses");
    let gap_limit = pool.gap_limit;
    let addr = pool.address_at_index(highest).expect("highest index must exist");
    (highest, gap_limit, addr)
}

/// Build a tx whose only output pays to `addr`. `seed` differentiates the
/// input prevout so two different txs can pay to the same address without
/// being deduped on `txid`.
fn create_tx_paying_to_with_input_seed(addr: &Address, txid_seed: u8, vout: u32) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([txid_seed; 32]),
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: u32::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: TX_AMOUNT,
            script_pubkey: addr.script_pubkey(),
        }],
        special_transaction_payload: None,
    }
}

#[tokio::test]
async fn test_mempool_tx_to_highest_external_carries_addresses_derived() {
    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
    let (highest_before, gap_limit, highest_addr) =
        pool_state(&manager, &wallet_id, AddressPoolType::External);

    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&highest_addr, 0xa0);
    manager.process_mempool_transaction(&tx, None).await;

    let events = drain_events(&mut rx);
    let detected = events
        .iter()
        .find(|e| matches!(e, WalletEvent::TransactionDetected { .. }))
        .unwrap_or_else(|| panic!("expected TransactionDetected, got {:?}", events));
    let WalletEvent::TransactionDetected {
        addresses_derived,
        ..
    } = detected
    else {
        unreachable!()
    };

    // Receiving to the highest pre-generated External address must extend
    // the pool by exactly `gap_limit`, with all entries on the External
    // pool of the BIP44 account 0, and contiguous derivation indices
    // starting just past `highest_before`.
    assert_eq!(
        addresses_derived.len() as u32,
        gap_limit,
        "expected gap_limit ({}) new addresses, got {}",
        gap_limit,
        addresses_derived.len()
    );
    let expected_account = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    };

    // Snapshot the pool state *after* extension so we can pin every
    // emitted (address, public_key) pair against what the wallet
    // actually stored. The persistence contract this PR enforces is
    // that each `DerivedAddress` row matches the wallet's
    // `AddressInfo` for the same `(account, pool, index)` — drift
    // here would silently corrupt downstream `CoreAddress` rows.
    let info_after = manager.get_wallet_info(&wallet_id).expect("wallet info");
    let acct_after = info_after.accounts.standard_bip44_accounts.get(&0).expect("BIP44 0");
    let external_pool_after = match acct_after.managed_account_type() {
        ManagedAccountType::Standard {
            external_addresses,
            ..
        } => external_addresses,
        _ => panic!("expected Standard account"),
    };

    for (i, derived) in addresses_derived.iter().enumerate() {
        assert_eq!(derived.account_type, expected_account);
        assert_eq!(derived.pool_type, AddressPoolType::External);
        assert_eq!(
            derived.derivation_index,
            highest_before + 1 + i as u32,
            "derivation indices must be contiguous starting just past the prior highest"
        );

        // Pin the persistence-critical payload against the wallet's
        // own AddressInfo for the same index.
        let stored = external_pool_after
            .info_at_index(derived.derivation_index)
            .unwrap_or_else(|| panic!("pool missing index {}", derived.derivation_index));
        assert_eq!(
            derived.address, stored.address,
            "address mismatch at index {}",
            derived.derivation_index
        );
        let stored_pubkey = match stored.public_key.as_ref().expect("ECDSA pool stores pubkey") {
            PublicKeyType::ECDSA(b) => b,
            other => panic!("BIP44 external pool produced non-ECDSA key: {:?}", other),
        };
        let expected = PublicKey::from_slice(stored_pubkey)
            .expect("BIP44 external pool must store a valid compressed ECDSA key");
        assert_eq!(
            derived.public_key, expected,
            "public key mismatch at index {}",
            derived.derivation_index
        );
    }
}

#[tokio::test]
async fn test_mempool_tx_to_already_buffered_external_carries_no_addresses_derived() {
    // After a first hit on the highest-index External address, the pool
    // is already extended by `gap_limit` past that index. A subsequent
    // tx to a LOWER index sits well inside the buffer and must not
    // trigger any further derivation.
    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
    let (highest_before, _gap, highest_addr) =
        pool_state(&manager, &wallet_id, AddressPoolType::External);

    // Prime: first tx pushes the boundary and extends the pool.
    let tx_prime = create_tx_paying_to(&highest_addr, 0xa1);
    manager.process_mempool_transaction(&tx_prime, None).await;

    // Now send a second tx to an index that is well within the new
    // buffer (e.g. index 0). The pool is already at highest_before +
    // gap_limit; using a lower index does not push it further.
    let info = manager.get_wallet_info(&wallet_id).expect("wallet info");
    let acct = info.accounts.standard_bip44_accounts.get(&0).expect("BIP44 0");
    let buffered_addr = match acct.managed_account_type() {
        ManagedAccountType::Standard {
            external_addresses,
            ..
        } => external_addresses.address_at_index(0).expect("low-index external address must exist"),
        _ => panic!("expected Standard account type"),
    };
    assert!(
        buffered_addr != highest_addr,
        "test setup mismatch: low-index addr should differ from highest"
    );
    let _ = highest_before;

    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&buffered_addr, 0xa2);
    manager.process_mempool_transaction(&tx, None).await;

    let events = drain_events(&mut rx);
    let detected = events
        .iter()
        .find(|e| matches!(e, WalletEvent::TransactionDetected { .. }))
        .unwrap_or_else(|| panic!("expected TransactionDetected, got {:?}", events));
    let WalletEvent::TransactionDetected {
        addresses_derived,
        ..
    } = detected
    else {
        unreachable!()
    };
    assert!(
        addresses_derived.is_empty(),
        "no derivation expected when the second hit sits inside the existing buffer, got {:?}",
        addresses_derived
    );
}

#[tokio::test]
async fn test_block_with_external_and_internal_high_index_extends_both_pools() {
    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
    let (ext_highest_before, ext_gap, ext_highest_addr) =
        pool_state(&manager, &wallet_id, AddressPoolType::External);
    let (int_highest_before, int_gap, int_highest_addr) =
        pool_state(&manager, &wallet_id, AddressPoolType::Internal);

    let tx_ext = create_tx_paying_to(&ext_highest_addr, 0xb0);
    let tx_int = create_tx_paying_to(&int_highest_addr, 0xb1);
    let block = make_block(vec![tx_ext, tx_int], 0xb2, 6000);

    let mut rx = manager.subscribe_events();
    let wallets = BTreeSet::from([wallet_id]);
    manager.process_block_for_wallets(&block, 700, &wallets).await;

    let events = drain_events(&mut rx);
    let block_event = events
        .iter()
        .find(|e| matches!(e, WalletEvent::BlockProcessed { .. }))
        .unwrap_or_else(|| panic!("expected BlockProcessed, got {:?}", events));
    let WalletEvent::BlockProcessed {
        addresses_derived,
        ..
    } = block_event
    else {
        unreachable!()
    };

    let ext_count =
        addresses_derived.iter().filter(|d| d.pool_type == AddressPoolType::External).count()
            as u32;
    let int_count =
        addresses_derived.iter().filter(|d| d.pool_type == AddressPoolType::Internal).count()
            as u32;
    assert_eq!(ext_count, ext_gap, "External pool must extend by gap_limit");
    assert_eq!(int_count, int_gap, "Internal pool must extend by gap_limit");

    // De-dup invariant: each (pool, index) appears once.
    let mut ext_indices: Vec<u32> = addresses_derived
        .iter()
        .filter(|d| d.pool_type == AddressPoolType::External)
        .map(|d| d.derivation_index)
        .collect();
    ext_indices.sort_unstable();
    ext_indices.dedup();
    assert_eq!(ext_indices.len() as u32, ext_gap);
    let expected_first_ext = ext_highest_before + 1;
    assert_eq!(ext_indices.first().copied(), Some(expected_first_ext));

    let mut int_indices: Vec<u32> = addresses_derived
        .iter()
        .filter(|d| d.pool_type == AddressPoolType::Internal)
        .map(|d| d.derivation_index)
        .collect();
    int_indices.sort_unstable();
    int_indices.dedup();
    assert_eq!(int_indices.len() as u32, int_gap);
    let expected_first_int = int_highest_before + 1;
    assert_eq!(int_indices.first().copied(), Some(expected_first_int));
}

#[tokio::test]
async fn test_block_with_two_records_pushing_external_boundary_dedupes() {
    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
    let (_, gap_limit, highest_addr) = pool_state(&manager, &wallet_id, AddressPoolType::External);

    // Two distinct txs (different prevouts → different txids) both paying
    // to the same highest-index External address. Both records will be
    // processed within the same block. The first triggers gap-limit
    // extension; the second hits an already-extended boundary and must not
    // double-extend.
    let tx1 = create_tx_paying_to_with_input_seed(&highest_addr, 0xc0, 0);
    let tx2 = create_tx_paying_to_with_input_seed(&highest_addr, 0xc1, 0);
    let block = make_block(vec![tx1, tx2], 0xc2, 7000);

    let mut rx = manager.subscribe_events();
    let wallets = BTreeSet::from([wallet_id]);
    manager.process_block_for_wallets(&block, 800, &wallets).await;

    let events = drain_events(&mut rx);
    let block_event = events
        .iter()
        .find(|e| matches!(e, WalletEvent::BlockProcessed { .. }))
        .unwrap_or_else(|| panic!("expected BlockProcessed, got {:?}", events));
    let WalletEvent::BlockProcessed {
        addresses_derived,
        ..
    } = block_event
    else {
        unreachable!()
    };

    // Exactly `gap_limit` entries — not `2 * gap_limit`, despite both
    // records nominally pushing the boundary.
    assert_eq!(
        addresses_derived.len() as u32,
        gap_limit,
        "two records pushing the same boundary must dedup to gap_limit, got {}",
        addresses_derived.len()
    );
    // And every entry must be distinct on (account, pool, index).
    let mut keys: Vec<(AccountType, AddressPoolType, u32)> = addresses_derived
        .iter()
        .map(|d| (d.account_type, d.pool_type, d.derivation_index))
        .collect();
    keys.sort();
    let total = keys.len();
    keys.dedup();
    assert_eq!(keys.len(), total, "duplicate (account, pool, index) entries leaked through");
}

#[tokio::test]
async fn test_instant_send_lock_event_does_not_carry_addresses_derived_field() {
    // IS-lock application doesn't extend the pool — addresses are
    // already marked used at mempool time. The InstantLocked event
    // intentionally has no `addresses_derived` field; this test pins
    // that down so a future "defensively add the field everywhere"
    // refactor surfaces here.
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let tx = create_tx_paying_to(&addr, 0xd0);
    manager.process_mempool_transaction(&tx, None).await;

    let mut rx = manager.subscribe_events();
    let lock = InstantLock {
        txid: tx.txid(),
        cyclehash: CycleHash::from_byte_array([0xab; 32]),
        signature: BLSSignature::from([0xcd; 96]),
        ..InstantLock::default()
    };
    manager.process_instant_send_lock(lock);

    let events = drain_events(&mut rx);
    let lock_event = events
        .iter()
        .find(|e| matches!(e, WalletEvent::TransactionInstantLocked { .. }))
        .unwrap_or_else(|| panic!("expected TransactionInstantLocked, got {:?}", events));
    // Pattern-match on every field; if a future change adds
    // `addresses_derived`, this fails to compile and forces a
    // deliberate decision.
    match lock_event {
        WalletEvent::TransactionInstantLocked {
            wallet_id: wid,
            txid,
            instant_lock: _,
            balance: _,
            account_balances: _,
        } => {
            assert_eq!(*wid, wallet_id);
            assert_eq!(*txid, tx.txid());
        }
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// ChainLock path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_apply_chain_lock_promotes_in_block_record_and_emits_event() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let tx = create_tx_paying_to(&addr, 0xa1);
    let block = make_block(vec![tx.clone()], 0xa1, 1000);
    let wallets = BTreeSet::from([wallet_id]);
    manager.process_block_for_wallets(&block, 100, &wallets).await;

    let mut rx = manager.subscribe_events();
    manager.apply_chain_lock(ChainLock::dummy(100));

    let events = drain_events(&mut rx);
    // First chainlock advances the wallet's metadata AND promotes a
    // record, so a single atomic `ChainLockProcessed` fires carrying
    // both the chainlock proof and the per-account promotions.
    assert_eq!(events.len(), 1, "ChainLockProcessed expected, got {events:?}");
    match &events[0] {
        WalletEvent::ChainLockProcessed {
            wallet_id: wid,
            chain_lock,
            locked_transactions,
        } => {
            assert_eq!(*wid, wallet_id);
            assert_eq!(chain_lock.block_height, 100);
            let receiving = AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            };
            let txids = locked_transactions
                .get(&receiving)
                .expect("the receiving account should have a promotion entry");
            assert_eq!(txids, &vec![tx.txid()]);
        }
        other => panic!("expected ChainLockProcessed, got {:?}", other),
    }
}

#[tokio::test]
async fn test_apply_chain_lock_with_no_records_emits_chain_lock_processed_and_advances_boundary() {
    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    manager.apply_chain_lock(ChainLock::dummy(500));

    // Even though no record was promoted, the wallet's
    // `last_applied_chain_lock` advanced from `None` to `Some(500)` —
    // durable consumers (e.g. asset-lock persisters) must observe a
    // single `ChainLockProcessed` (with empty `locked_transactions`)
    // to know the metadata moved.
    let advance_events = drain_events(&mut rx);
    assert_eq!(
        advance_events.len(),
        1,
        "exactly one ChainLockProcessed expected, got {advance_events:?}"
    );
    match &advance_events[0] {
        WalletEvent::ChainLockProcessed {
            wallet_id: wid,
            chain_lock,
            locked_transactions,
        } => {
            assert_eq!(*wid, wallet_id);
            assert_eq!(chain_lock.block_height, 500);
            assert!(
                locked_transactions.is_empty(),
                "metadata advance without records must carry empty locked_transactions, got {locked_transactions:?}"
            );
        }
        other => panic!("expected ChainLockProcessed, got {:?}", other),
    }

    // Subsequent block below the new finality boundary must be born chainlocked.
    let addr = manager
        .next_receive_address(&wallet_id, 0, AccountTypePreference::BIP44, true)
        .expect("address generation");
    let tx = create_tx_paying_to(&addr, 0xa2);
    let block = make_block(vec![tx.clone()], 0xa2, 1100);
    let wallets = BTreeSet::from([wallet_id]);
    manager.process_block_for_wallets(&block, 100, &wallets).await;

    let events = drain_events(&mut rx);
    let bp = events
        .iter()
        .find(|e| matches!(e, WalletEvent::BlockProcessed { .. }))
        .expect("BlockProcessed expected after late block below finality boundary");
    match bp {
        WalletEvent::BlockProcessed {
            chain_lock,
            inserted,
            ..
        } => {
            assert!(chain_lock.is_some(), "block below finality boundary must carry the chainlock");
            assert!(
                matches!(inserted[0].context, TransactionContext::InChainLockedBlock(_)),
                "late-block path must record the tx as InChainLockedBlock, got {:?}",
                inserted[0].context
            );
        }
        _ => unreachable!(),
    }
    let chainlock_event_count =
        events.iter().filter(|e| matches!(e, WalletEvent::ChainLockProcessed { .. })).count();
    assert_eq!(
        chainlock_event_count, 0,
        "late-block path must not double-emit ChainLockProcessed for newly-born chainlocked txs"
    );
}

#[tokio::test]
async fn test_apply_chain_lock_is_idempotent_on_already_finalized() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let tx = create_tx_paying_to(&addr, 0xa3);
    let block = make_block(vec![tx.clone()], 0xa3, 1200);
    let wallets = BTreeSet::from([wallet_id]);
    manager.process_block_for_wallets(&block, 50, &wallets).await;

    let mut rx = manager.subscribe_events();
    manager.apply_chain_lock(ChainLock::dummy(50));
    let first = drain_events(&mut rx);
    let chainlock_events: Vec<_> = first
        .iter()
        .filter_map(|e| match e {
            WalletEvent::ChainLockProcessed {
                locked_transactions,
                ..
            } => Some(locked_transactions),
            _ => None,
        })
        .collect();
    assert_eq!(
        chainlock_events.len(),
        1,
        "first chainlock must emit exactly one ChainLockProcessed, got {first:?}"
    );
    assert!(
        !chainlock_events[0].is_empty(),
        "first chainlock at height 50 must promote the InBlock record"
    );

    // Replaying the same chainlock must not re-emit anything: no
    // promotions and no metadata advance.
    manager.apply_chain_lock(ChainLock::dummy(50));
    assert_no_events(&mut rx);

    // A higher chainlock with no outstanding InBlock records below it
    // still advances the metadata boundary, so emits exactly one
    // `ChainLockProcessed` with empty `locked_transactions`.
    manager.apply_chain_lock(ChainLock::dummy(80));
    let advance = drain_events(&mut rx);
    let advance_events: Vec<_> = advance
        .iter()
        .filter_map(|e| match e {
            WalletEvent::ChainLockProcessed {
                locked_transactions,
                ..
            } => Some(locked_transactions),
            _ => None,
        })
        .collect();
    assert_eq!(
        advance_events.len(),
        1,
        "metadata advance from 50 -> 80 must emit exactly one ChainLockProcessed, got {advance:?}"
    );
    assert!(
        advance_events[0].is_empty(),
        "no records to promote => empty locked_transactions, got {:?}",
        advance_events[0]
    );
}

#[tokio::test]
async fn test_block_processed_chainlocked_flag_matches_record_context() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();

    // Below the finality boundary: chain_lock=Some, records InChainLockedBlock.
    manager.apply_chain_lock(ChainLock::dummy(1000));
    let tx_below = create_tx_paying_to(&addr, 0xa4);
    let block_below = make_block(vec![tx_below.clone()], 0xa4, 1300);
    let wallets = BTreeSet::from([wallet_id]);
    let mut rx = manager.subscribe_events();
    manager.process_block_for_wallets(&block_below, 500, &wallets).await;

    let events_below = drain_events(&mut rx);
    let bp_below = events_below
        .iter()
        .find(|e| matches!(e, WalletEvent::BlockProcessed { .. }))
        .expect("BlockProcessed expected");
    if let WalletEvent::BlockProcessed {
        chain_lock,
        inserted,
        ..
    } = bp_below
    {
        let cl = chain_lock.as_ref().expect("block below finality boundary must carry chainlock");
        assert_eq!(cl.block_height, 1000);
        assert!(matches!(inserted[0].context, TransactionContext::InChainLockedBlock(_)));
    }

    // Above the finality boundary: chain_lock=None, records InBlock.
    let addr2 = manager
        .next_receive_address(&wallet_id, 0, AccountTypePreference::BIP44, true)
        .expect("address generation");
    let tx_above = create_tx_paying_to(&addr2, 0xa5);
    let block_above = make_block(vec![tx_above.clone()], 0xa5, 1400);
    manager.process_block_for_wallets(&block_above, 2000, &wallets).await;

    let events_above = drain_events(&mut rx);
    let bp_above = events_above
        .iter()
        .find(|e| matches!(e, WalletEvent::BlockProcessed { .. }))
        .expect("BlockProcessed expected");
    if let WalletEvent::BlockProcessed {
        chain_lock,
        inserted,
        ..
    } = bp_above
    {
        assert!(chain_lock.is_none());
        assert!(matches!(inserted[0].context, TransactionContext::InBlock(_)));
    }
}
