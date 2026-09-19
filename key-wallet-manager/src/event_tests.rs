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
use key_wallet::transaction_checking::{TransactionRouter, TransactionType};
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
    manager.process_block_for_wallets(&block, block.block_hash(), 300, &wallets).await;

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
    let result = manager.process_block_for_wallets(&block, block.block_hash(), 100, &wallets).await;
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
    manager.process_block_for_wallets(&block, block.block_hash(), 200, &wallets).await;

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

async fn setup_known_mempool_spend_only_asset_lock(
) -> (WalletManager<ManagedWalletInfo>, WalletId, Transaction, OutPoint, BTreeSet<WalletId>) {
    let (mut manager, wallet_id, _default_addr) = setup_manager_with_wallet();

    let funding_address = {
        let info = manager.get_wallet_info(&wallet_id).expect("wallet info");
        let account = info.accounts.standard_bip44_accounts.get(&0).expect("BIP44 account 0");
        match account.managed_account_type() {
            ManagedAccountType::Standard {
                external_addresses,
                ..
            } => external_addresses.address_at_index(0).expect("BIP44 receive address 0"),
            other => panic!("expected Standard BIP44 account, got {other:?}"),
        }
    };

    let funding_tx = create_tx_paying_to(&funding_address, 0x43);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let funding_block = make_block(vec![funding_tx], 0x44, 4_000);
    let wallets = BTreeSet::from([wallet_id]);
    manager
        .process_block_for_wallets(&funding_block, funding_block.block_hash(), 400, &wallets)
        .await;

    let funding_script = funding_address.script_pubkey();
    let funded_account = manager
        .get_wallet_info(&wallet_id)
        .expect("wallet info")
        .accounts
        .standard_bip44_accounts
        .get(&0)
        .expect("BIP44 account 0");
    assert!(
        funded_account.utxos.contains_key(&funding_outpoint),
        "funding block must create the confirmed wallet UTXO"
    );
    assert!(
        funded_account.utxos[&funding_outpoint].is_confirmed,
        "funding UTXO must be confirmed before the spend"
    );

    let external_address = Address::p2pkh(
        &PublicKey::from_slice(&[2u8; 33]).expect("valid external public key"),
        key_wallet::Network::Testnet,
    );
    let regular_external_script =
        Builder::new().push_opcode(opcodes::all::OP_RETURN).push_slice([0x52u8; 20]).into_script();
    let asset_lock_tx = Transaction {
        version: 3,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: u32::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: TX_AMOUNT - 1_000,
            script_pubkey: regular_external_script.clone(),
        }],
        special_transaction_payload: Some(TransactionPayload::AssetLockPayloadType(
            AssetLockPayload::new(vec![TxOut {
                value: TX_AMOUNT - 1_000,
                script_pubkey: external_address.script_pubkey(),
            }]),
        )),
    };
    assert_eq!(
        TransactionRouter::classify_transaction(&asset_lock_tx),
        TransactionType::AssetLock,
        "fixture must take the production AssetLock routing path"
    );
    let monitored_scripts = manager.monitored_script_pubkeys_for(&wallet_id);
    assert!(
        !monitored_scripts.contains(&regular_external_script),
        "regular AssetLock output must not pay the wallet"
    );
    assert!(
        !monitored_scripts.contains(&external_address.script_pubkey()),
        "AssetLock credit output must not pay the wallet"
    );

    let mempool_result = manager.process_mempool_transaction(&asset_lock_tx, None).await;
    assert!(mempool_result.is_relevant, "mempool sighting must spend the wallet UTXO");
    assert_eq!(mempool_result.net_amount, -(TX_AMOUNT as i64));

    let account_after_mempool = manager
        .get_wallet_info(&wallet_id)
        .expect("wallet info")
        .accounts
        .standard_bip44_accounts
        .get(&0)
        .expect("BIP44 account 0");
    assert_eq!(
        account_after_mempool
            .transactions()
            .get(&asset_lock_tx.txid())
            .expect("mempool sighting must create a transaction record")
            .context,
        TransactionContext::Mempool
    );
    assert!(
        !account_after_mempool.utxos.contains_key(&funding_outpoint),
        "mempool processing must remove the spent live UTXO"
    );
    assert!(
        !manager
            .get_wallet_info(&wallet_id)
            .expect("wallet info")
            .observed_spent_outpoints()
            .contains_key(&funding_outpoint),
        "mempool sightings must not populate block-only observed spends"
    );
    assert!(
        manager.scan_script_pubkeys_for(&wallet_id).contains(&funding_script),
        "the Standard BIP44 funding script must still match a compact filter"
    );

    (manager, wallet_id, asset_lock_tx, funding_outpoint, wallets)
}

#[tokio::test]
async fn test_block_promotes_known_mempool_asset_lock_spending_wallet_utxo() {
    let (mut manager, wallet_id, asset_lock_tx, funding_outpoint, wallets) =
        setup_known_mempool_spend_only_asset_lock().await;
    let mut rx = manager.subscribe_events();
    let block = make_block(vec![asset_lock_tx.clone()], 0x45, 4_100);

    let block_result =
        manager.process_block_for_wallets(&block, block.block_hash(), 401, &wallets).await;
    let block_events = drain_events(&mut rx);
    let account_after_block = manager
        .get_wallet_info(&wallet_id)
        .expect("wallet info")
        .accounts
        .standard_bip44_accounts
        .get(&0)
        .expect("BIP44 account 0");
    let stored_context = &account_after_block
        .transactions()
        .get(&asset_lock_tx.txid())
        .expect("mempool record must remain stored")
        .context;
    let updated = block_events.iter().find_map(|event| match event {
        WalletEvent::BlockProcessed {
            updated,
            ..
        } => Some(updated),
        _ => None,
    });

    assert_eq!(
        manager
            .get_wallet_info(&wallet_id)
            .expect("wallet info")
            .observed_spent_outpoints()
            .get(&funding_outpoint),
        Some(&401),
        "the block transaction must reach the checker before relevance gating"
    );
    assert!(block_result.new_txids.is_empty());
    assert_eq!(block_result.existing_txids, vec![asset_lock_tx.txid()]);
    assert!(
        matches!(stored_context, TransactionContext::InBlock(info) if info.height() == 401),
        "known spend-only transaction must be promoted to its block context, got {stored_context:?}"
    );
    let updated =
        updated.unwrap_or_else(|| panic!("BlockProcessed update expected: {block_events:?}"));
    assert_eq!(updated.len(), 1);
    assert_eq!(updated[0].txid, asset_lock_tx.txid());
}

#[tokio::test]
async fn test_chainlocked_block_promotes_known_mempool_spend_only_transaction() {
    let (mut manager, wallet_id, asset_lock_tx, _funding_outpoint, wallets) =
        setup_known_mempool_spend_only_asset_lock().await;
    manager.apply_chain_lock(ChainLock::dummy(500));
    let mut rx = manager.subscribe_events();
    let block = make_block(vec![asset_lock_tx.clone()], 0x46, 4_200);

    let block_result =
        manager.process_block_for_wallets(&block, block.block_hash(), 401, &wallets).await;
    let events = drain_events(&mut rx);
    let updated = events
        .iter()
        .find_map(|event| match event {
            WalletEvent::BlockProcessed {
                updated,
                ..
            } => Some(updated),
            _ => None,
        })
        .unwrap_or_else(|| panic!("chainlocked BlockProcessed update expected: {events:?}"));

    assert_eq!(block_result.existing_txids, vec![asset_lock_tx.txid()]);
    assert_eq!(updated.len(), 1);
    assert!(matches!(
        updated[0].context,
        TransactionContext::InChainLockedBlock(info) if info.height() == 401
    ));

    let account = manager
        .get_wallet_info(&wallet_id)
        .expect("wallet info")
        .accounts
        .standard_bip44_accounts
        .get(&0)
        .expect("BIP44 account 0");
    assert!(account.transaction_is_finalized(&asset_lock_tx.txid()));
    #[cfg(feature = "keep-finalized-transactions")]
    assert!(matches!(
        account
            .transactions()
            .get(&asset_lock_tx.txid())
            .expect("retained finalized record")
            .context,
        TransactionContext::InChainLockedBlock(_)
    ));
    #[cfg(not(feature = "keep-finalized-transactions"))]
    assert!(!account.transactions().contains_key(&asset_lock_tx.txid()));
}

#[tokio::test]
async fn test_spend_only_promotion_never_demotes_chainlocked_context() {
    let (mut manager, wallet_id, asset_lock_tx, _funding_outpoint, wallets) =
        setup_known_mempool_spend_only_asset_lock().await;
    manager.apply_chain_lock(ChainLock::dummy(500));
    let chainlocked_block = make_block(vec![asset_lock_tx.clone()], 0x47, 4_300);
    manager
        .process_block_for_wallets(
            &chainlocked_block,
            chainlocked_block.block_hash(),
            401,
            &wallets,
        )
        .await;

    let mut rx = manager.subscribe_events();
    let weaker_block = make_block(vec![asset_lock_tx.clone()], 0x48, 4_400);
    let replay = manager
        .process_block_for_wallets(&weaker_block, weaker_block.block_hash(), 600, &wallets)
        .await;

    assert!(replay.new_txids.is_empty());
    assert!(replay.existing_txids.is_empty());
    assert_no_events(&mut rx);
    let account = manager
        .get_wallet_info(&wallet_id)
        .expect("wallet info")
        .accounts
        .standard_bip44_accounts
        .get(&0)
        .expect("BIP44 account 0");
    assert!(account.transaction_is_finalized(&asset_lock_tx.txid()));
    #[cfg(feature = "keep-finalized-transactions")]
    assert!(matches!(
        account
            .transactions()
            .get(&asset_lock_tx.txid())
            .expect("retained finalized record")
            .context,
        TransactionContext::InChainLockedBlock(_)
    ));
}

#[tokio::test]
async fn test_block_does_not_promote_unknown_irrelevant_transaction() {
    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
    let external_address = Address::p2pkh(
        &PublicKey::from_slice(&[2u8; 33]).expect("valid external public key"),
        key_wallet::Network::Testnet,
    );
    let tx = make_coinbase_paying_to(&external_address, TX_AMOUNT);
    let block = make_block(vec![tx.clone()], 0x49, 4_500);
    let wallets = BTreeSet::from([wallet_id]);
    let mut rx = manager.subscribe_events();

    let result = manager.process_block_for_wallets(&block, block.block_hash(), 450, &wallets).await;

    assert!(result.new_txids.is_empty());
    assert!(result.existing_txids.is_empty());
    assert_no_events(&mut rx);
    let info = manager.get_wallet_info(&wallet_id).expect("wallet info");
    assert!(
        info.accounts
            .all_accounts()
            .into_iter()
            .all(|account| !account.has_transaction(&tx.txid())),
        "an unknown transaction with no wallet evidence must remain irrelevant"
    );
}

#[tokio::test]
async fn test_spend_only_block_promotion_is_idempotent() {
    let (mut manager, _wallet_id, asset_lock_tx, _funding_outpoint, wallets) =
        setup_known_mempool_spend_only_asset_lock().await;
    let block = make_block(vec![asset_lock_tx.clone()], 0x4a, 4_600);
    let mut rx = manager.subscribe_events();

    let first = manager.process_block_for_wallets(&block, block.block_hash(), 401, &wallets).await;
    let first_events = drain_events(&mut rx);
    assert_eq!(first.existing_txids, vec![asset_lock_tx.txid()]);
    assert!(first_events.iter().any(|event| matches!(
        event,
        WalletEvent::BlockProcessed { updated, .. }
            if updated.iter().any(|record| record.txid == asset_lock_tx.txid())
    )));

    let second = manager.process_block_for_wallets(&block, block.block_hash(), 401, &wallets).await;
    assert!(second.new_txids.is_empty());
    assert!(second.existing_txids.is_empty());
    assert_no_events(&mut rx);
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
    manager.process_block_for_wallets(&block, block.block_hash(), 9000, &wallets).await;

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

/// The sweep event's own coverage at the manager level: a block whose
/// transaction beats a recorded mempool spend must emit `TransactionsSwept`
/// naming the removed transaction and the coins its removal freed.
///
/// The released set is the half a consumer cannot recompute, so it is worth
/// pinning where it is actually assembled — this exercises the per-wallet
/// aggregation in `check_transactions` and the block path's emission
/// together, neither of which the account-level sweep tests reach.
#[tokio::test]
async fn test_block_winner_emits_swept_event_naming_the_released_outpoints() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();

    // One funding transaction pays us twice, so the loser can spend a coin
    // the winner does not.
    let funding = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x5a; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: u32::MAX,
            witness: Witness::default(),
        }],
        output: vec![
            TxOut {
                value: 500_000,
                script_pubkey: addr.script_pubkey(),
            },
            TxOut {
                value: 400_000,
                script_pubkey: addr.script_pubkey(),
            },
        ],
        special_transaction_payload: None,
    };
    let funding_block = make_block(vec![funding.clone()], 0x5a, 1000);
    let wallets = BTreeSet::from([wallet_id]);
    manager
        .process_block_for_wallets(&funding_block, funding_block.block_hash(), 100, &wallets)
        .await;

    let coin_a = OutPoint {
        txid: funding.txid(),
        vout: 0,
    };
    let coin_b = OutPoint {
        txid: funding.txid(),
        vout: 1,
    };
    let spend = |inputs: Vec<OutPoint>, value: u64| Transaction {
        version: 2,
        lock_time: 0,
        input: inputs
            .into_iter()
            .map(|previous_output| TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: u32::MAX,
                witness: Witness::default(),
            })
            .collect(),
        output: vec![TxOut {
            value,
            script_pubkey: addr.script_pubkey(),
        }],
        special_transaction_payload: None,
    };

    let loser = spend(vec![coin_a, coin_b], 800_000);
    manager.process_mempool_transaction(&loser, None).await;

    // Subscribe only now: the funding block and the loser's arrival are
    // setup, and the sweep is what this test is about.
    let mut rx = manager.subscribe_events();

    let winner = spend(vec![coin_a], 400_000);
    let winner_block = make_block(vec![winner.clone()], 0x5b, 1100);
    manager
        .process_block_for_wallets(&winner_block, winner_block.block_hash(), 101, &wallets)
        .await;

    let events = drain_events(&mut rx);
    let swept = events
        .iter()
        .find_map(|event| match event {
            WalletEvent::TransactionsSwept {
                wallet_id: wid,
                txids,
                superseded_by,
                winner_mined_height,
                released_outpoints,
                ..
            } => Some((wid, txids, superseded_by, winner_mined_height, released_outpoints)),
            _ => None,
        })
        .unwrap_or_else(|| panic!("a sweep must be emitted, got {:?}", events));

    assert_eq!(swept.0, &wallet_id);
    assert_eq!(swept.1, &vec![loser.txid()], "the beaten transaction is named");
    assert_eq!(swept.2, &winner.txid(), "attributed to the transaction that beat it");
    assert_eq!(
        swept.3,
        &Some(101),
        "a block-context sweep must carry the winner's mined height — the height of \
         the block whose processing triggered the sweep, not None and not any other \
         height the manager has seen"
    );
    assert_eq!(swept.4, &vec![coin_b], "only the coin the winner did not take is released");
}

/// The mempool emission site's counterpart to the block test above, pinning
/// the other half of `winner_mined_height`'s contract: a sweep triggered by
/// an InstantSend-locked winner that has not been mined carries `None`. This
/// is the distinction the field exists to make — a consumer retiring durable
/// records of the swept spends can anchor a block-context sweep to the
/// winner's height, while an IS-locked winner has no mining deadline, so
/// conflating the two (a height where there is none, or vice versa) would
/// let those records be retired while the conflict is still unmined.
#[tokio::test]
async fn test_is_locked_mempool_winner_sweeps_with_no_mined_height() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();

    // Same shape as the block test: one funding transaction pays us twice so
    // the loser spends a coin the winner does not.
    let funding = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x6a; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: u32::MAX,
            witness: Witness::default(),
        }],
        output: vec![
            TxOut {
                value: 500_000,
                script_pubkey: addr.script_pubkey(),
            },
            TxOut {
                value: 400_000,
                script_pubkey: addr.script_pubkey(),
            },
        ],
        special_transaction_payload: None,
    };
    let funding_block = make_block(vec![funding.clone()], 0x6a, 2000);
    let wallets = BTreeSet::from([wallet_id]);
    manager
        .process_block_for_wallets(&funding_block, funding_block.block_hash(), 100, &wallets)
        .await;

    let coin_a = OutPoint {
        txid: funding.txid(),
        vout: 0,
    };
    let coin_b = OutPoint {
        txid: funding.txid(),
        vout: 1,
    };
    let spend = |inputs: Vec<OutPoint>, value: u64| Transaction {
        version: 2,
        lock_time: 0,
        input: inputs
            .into_iter()
            .map(|previous_output| TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: u32::MAX,
                witness: Witness::default(),
            })
            .collect(),
        output: vec![TxOut {
            value,
            script_pubkey: addr.script_pubkey(),
        }],
        special_transaction_payload: None,
    };

    let loser = spend(vec![coin_a, coin_b], 800_000);
    manager.process_mempool_transaction(&loser, None).await;

    let mut rx = manager.subscribe_events();

    // The winner arrives off-chain with an InstantSend lock — final enough
    // to sweep the loser, but not mined anywhere.
    let winner = spend(vec![coin_a], 400_000);
    manager.process_mempool_transaction(&winner, Some(dummy_instant_lock(winner.txid()))).await;

    let events = drain_events(&mut rx);
    let swept = events
        .iter()
        .find_map(|event| match event {
            WalletEvent::TransactionsSwept {
                wallet_id: wid,
                txids,
                superseded_by,
                winner_mined_height,
                released_outpoints,
                ..
            } => Some((wid, txids, superseded_by, winner_mined_height, released_outpoints)),
            _ => None,
        })
        .unwrap_or_else(|| panic!("a sweep must be emitted, got {:?}", events));

    assert_eq!(swept.0, &wallet_id);
    assert_eq!(swept.1, &vec![loser.txid()], "the beaten transaction is named");
    assert_eq!(swept.2, &winner.txid(), "attributed to the transaction that beat it");
    assert_eq!(
        swept.3, &None,
        "an IS-locked winner is not mined: fabricating a height here would give the \
         consumer a finality horizon the winner does not have"
    );
    assert_eq!(swept.4, &vec![coin_b], "only the coin the winner did not take is released");
}

#[tokio::test]
async fn test_empty_block_for_idle_wallet_emits_nothing() {
    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let block = make_block(Vec::new(), 0x55, 3000);

    let wallets = BTreeSet::from([wallet_id]);
    manager.process_block_for_wallets(&block, block.block_hash(), 50, &wallets).await;
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
    manager
        .process_block_for_wallets(
            &coinbase_block,
            coinbase_block.block_hash(),
            coinbase_height,
            &wallets,
        )
        .await;

    // Advance to maturity height. With coinbase_height = 100, maturity is at
    // height 200. Processing block 200 must surface the matured record.
    let mut rx = manager.subscribe_events();
    let mature_block = make_block(Vec::new(), 0xc1, 5000);
    manager
        .process_block_for_wallets(
            &mature_block,
            mature_block.block_hash(),
            coinbase_height + 100,
            &wallets,
        )
        .await;

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

#[tokio::test]
async fn test_maturity_clock_advance_carries_matured_coinbase_record() {
    // The clock can advance with no block of its own: dash-spv calls this at
    // every committed filter batch, including ranges that match nothing
    // (dashpay/rust-dashcore#995).
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let coinbase_tx = make_coinbase_paying_to(&addr, 5_000_000_000);
    let coinbase_block = make_block(vec![coinbase_tx.clone()], 0xc2, 4000);
    let wallets = BTreeSet::from([wallet_id]);
    manager
        .process_block_for_wallets(&coinbase_block, coinbase_block.block_hash(), 100, &wallets)
        .await;

    let mut rx = manager.subscribe_events();
    manager.update_wallet_last_processed_height(&wallet_id, 200);

    let events = drain_events(&mut rx);
    let block_event = events
        .iter()
        .find(|e| matches!(e, WalletEvent::BlockProcessed { .. }))
        .unwrap_or_else(|| panic!("expected a BlockProcessed, got {:?}", events));

    match block_event {
        WalletEvent::BlockProcessed {
            height,
            matured,
            balance,
            ..
        } => {
            assert_eq!(*height, 200);
            assert_eq!(matured.len(), 1);
            assert_eq!(matured[0].txid, coinbase_tx.txid());
            assert_eq!(balance.immature(), 0);
            assert_eq!(balance.confirmed(), 5_000_000_000);
        }
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn test_coinbase_found_below_the_maturity_clock_is_spendable_but_unannounced() {
    // A rescan can surface a matched block the clock already passed. The
    // coinbase in it is mature on arrival, so it counts as confirmed, but its
    // maturity window is behind us and no `matured` record can name it.
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    manager.update_wallet_last_processed_height(&wallet_id, 300);

    let mut rx = manager.subscribe_events();
    let coinbase_tx = make_coinbase_paying_to(&addr, 5_000_000_000);
    let late_block = make_block(vec![coinbase_tx.clone()], 0xc3, 4000);
    let wallets = BTreeSet::from([wallet_id]);
    manager.process_block_for_wallets(&late_block, late_block.block_hash(), 150, &wallets).await;

    let events = drain_events(&mut rx);
    let block_event = events
        .iter()
        .find(|e| matches!(e, WalletEvent::BlockProcessed { .. }))
        .unwrap_or_else(|| panic!("expected a BlockProcessed, got {:?}", events));

    match block_event {
        WalletEvent::BlockProcessed {
            height,
            inserted,
            matured,
            balance,
            ..
        } => {
            assert_eq!(*height, 150);
            assert_eq!(inserted.len(), 1);
            assert_eq!(inserted[0].txid, coinbase_tx.txid());
            assert!(matured.is_empty());
            assert_eq!(balance.immature(), 0);
            assert_eq!(balance.confirmed(), 5_000_000_000);
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

#[tokio::test]
async fn test_rewind_wallet_synced_height_lowers_and_emits() {
    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    manager.update_wallet_synced_height(&wallet_id, 2000);
    drain_events(&mut rx);

    // A rewind lowers the checkpoint and is reported through the same event
    // an advance emits, so persisters store it verbatim and the rewind
    // survives a restart.
    manager.rewind_wallet_synced_height(&wallet_id, 1200);
    assert_eq!(manager.wallet_synced_height(&wallet_id), 1200);
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
    assert_eq!(synced_events, vec![(wallet_id, 1200)]);

    // At or above the current checkpoint is ignored — no change, no event.
    manager.rewind_wallet_synced_height(&wallet_id, 1200);
    manager.rewind_wallet_synced_height(&wallet_id, 5000);
    assert_eq!(manager.wallet_synced_height(&wallet_id), 1200);
    let events = drain_events(&mut rx);
    assert!(
        !events.iter().any(|e| matches!(e, WalletEvent::SyncHeightAdvanced { .. })),
        "no SyncHeightAdvanced for a non-lowering rewind, got {:?}",
        events
    );

    // An unknown wallet is a no-op.
    manager.rewind_wallet_synced_height(&[9u8; 32], 0);
    assert!(drain_events(&mut rx).is_empty());
}

#[tokio::test]
async fn test_rewind_wallet_synced_height_clamps_to_own_birth_height() {
    // The caller passes one floor for every wallet it rewinds; a wallet must
    // never be dragged below its own start by another wallet's lower birth.
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);
    let wallet_id = manager
        .create_wallet_from_mnemonic(
            TEST_MNEMONIC,
            500,
            key_wallet::wallet::initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();
    manager.update_wallet_synced_height(&wallet_id, 3000);
    let mut rx = manager.subscribe_events();

    manager.rewind_wallet_synced_height(&wallet_id, 0);
    assert_eq!(manager.wallet_synced_height(&wallet_id), 499);
    let synced_events: Vec<_> = drain_events(&mut rx)
        .into_iter()
        .filter_map(|e| match e {
            WalletEvent::SyncHeightAdvanced {
                height,
                ..
            } => Some(height),
            _ => None,
        })
        .collect();
    assert_eq!(synced_events, vec![499]);

    // Already at the floor: a second rewind changes nothing.
    manager.rewind_wallet_synced_height(&wallet_id, 0);
    assert_eq!(manager.wallet_synced_height(&wallet_id), 499);
    assert!(drain_events(&mut rx).is_empty());
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
    manager.process_block_for_wallets(&block, block.block_hash(), 700, &wallets).await;

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
    manager.process_block_for_wallets(&block, block.block_hash(), 800, &wallets).await;

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
    manager.process_block_for_wallets(&block, block.block_hash(), 100, &wallets).await;

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
    manager.process_block_for_wallets(&block, block.block_hash(), 100, &wallets).await;

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
    manager.process_block_for_wallets(&block, block.block_hash(), 50, &wallets).await;

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
    manager.process_block_for_wallets(&block_below, block_below.block_hash(), 500, &wallets).await;

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
    manager.process_block_for_wallets(&block_above, block_above.block_hash(), 2000, &wallets).await;

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

// ---------------------------------------------------------------------------
// In-block position stamping
// ---------------------------------------------------------------------------

/// Records inserted by block processing must carry their `block.txdata`
/// index in `BlockInfo::position`, so consumers can replay Core's
/// same-block apply order (e.g. multiple provider special transactions
/// for one masternode in a single block resolve latest-wins by this
/// position in `RebuildListFromBlock`).
#[tokio::test]
async fn test_block_processing_stamps_in_block_position() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();

    let tx_first = create_tx_paying_to(&addr, 0xb1);
    let tx_second = create_tx_paying_to(&addr, 0xb2);
    let block = make_block(vec![tx_first.clone(), tx_second.clone()], 0xb1, 1500);
    let wallets = BTreeSet::from([wallet_id]);
    manager.process_block_for_wallets(&block, block.block_hash(), 300, &wallets).await;

    let events = drain_events(&mut rx);
    let bp = events
        .iter()
        .find(|e| matches!(e, WalletEvent::BlockProcessed { .. }))
        .expect("BlockProcessed expected");
    let WalletEvent::BlockProcessed {
        inserted,
        ..
    } = bp
    else {
        unreachable!()
    };
    assert_eq!(inserted.len(), 2, "both txs pay the wallet, got {inserted:?}");

    let position_of = |txid| {
        inserted
            .iter()
            .find(|r| r.txid == txid)
            .expect("record for txid")
            .context
            .block_info()
            .expect("confirmed record must carry block info")
            .position()
    };
    assert_eq!(
        position_of(tx_first.txid()),
        Some(0),
        "first tx in block.txdata must be stamped position 0"
    );
    assert_eq!(
        position_of(tx_second.txid()),
        Some(1),
        "second tx in block.txdata must be stamped position 1"
    );
}

// ---------------------------------------------------------------------------
// Lossless persistence channel (dashpay/platform#4069)
// ---------------------------------------------------------------------------

/// A large burst of watermark events that the durable-persistence consumer
/// does not drain until the very end is delivered **losslessly and in order**
/// over the unbounded persistence channel — the exact property the platform
/// consumer's durable sync watermark relies on. The bounded broadcast, by
/// contrast, drops events (`Lagged`) under the same burst; that drop is the
/// freeze root cause this dedicated channel removes.
///
/// This models a stalled/slow persistence consumer during a heavy SPV
/// catch-up: neither receiver is drained while `BURST` monotonically
/// increasing `SyncHeightAdvanced` watermarks are emitted. On the unbounded
/// channel every watermark survives, so the watermark can keep advancing to
/// the tip after the stall clears; on the broadcast it lags and the watermark
/// would freeze.
#[tokio::test]
async fn persistence_channel_is_lossless_under_a_large_burst() {
    // `BURST` far exceeds the broadcast ring (`DEFAULT_WALLET_EVENT_CAPACITY`
    // == 1000), so the bounded broadcast is guaranteed to lag.
    const BURST: u32 = 5000;

    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
    // Take the lossless persistence receiver AND subscribe a bounded broadcast
    // receiver before emitting; neither is drained during the burst.
    let mut persistence_rx =
        manager.take_persistence_receiver().expect("persistence receiver available once");
    let mut broadcast_rx = manager.subscribe_events();

    for h in 1..=BURST {
        manager.update_wallet_synced_height(&wallet_id, h);
    }

    // Persistence channel: every watermark arrived, in order, no gaps.
    let mut received: Vec<u32> = Vec::with_capacity(BURST as usize);
    while let Ok(event) = persistence_rx.try_recv() {
        match event {
            WalletEvent::SyncHeightAdvanced {
                wallet_id: w,
                height,
            } => {
                assert_eq!(w, wallet_id, "watermark for the wrong wallet");
                received.push(height);
            }
            other => panic!("unexpected event on persistence channel: {other:?}"),
        }
    }
    assert_eq!(
        received.len(),
        BURST as usize,
        "persistence channel dropped events: got {} of {BURST}",
        received.len()
    );
    assert!(
        received.windows(2).all(|w| w[0] + 1 == w[1]),
        "persistence channel reordered or gapped the watermark stream"
    );
    assert_eq!(received.first().copied(), Some(1));
    assert_eq!(received.last().copied(), Some(BURST), "final watermark must reach the tip");

    // Broadcast channel: the same burst overflows the bounded ring and drops
    // events — demonstrating why the persistence consumer must NOT use it.
    let mut broadcast_lagged = false;
    let mut broadcast_delivered = 0usize;
    loop {
        match broadcast_rx.try_recv() {
            Ok(_) => broadcast_delivered += 1,
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => broadcast_lagged = true,
            Err(_) => break,
        }
    }
    assert!(
        broadcast_lagged,
        "the bounded broadcast should have lagged under a {BURST}-event burst"
    );
    assert!(
        broadcast_delivered < BURST as usize,
        "broadcast should have dropped events but delivered all {BURST}"
    );
}

/// The receiver is taken exactly once: the second call returns `None` and the
/// first receiver keeps working. Platform's manager construction relies on
/// exactly this (`take_persistence_receiver().expect(..)` on a fresh manager).
#[tokio::test]
async fn persistence_receiver_is_taken_exactly_once() {
    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
    let mut first = manager.take_persistence_receiver().expect("first take must succeed");
    assert!(manager.take_persistence_receiver().is_none(), "second take must return None");
    manager.update_wallet_synced_height(&wallet_id, 1);
    assert!(
        matches!(
            first.try_recv(),
            Ok(WalletEvent::SyncHeightAdvanced {
                height: 1,
                ..
            })
        ),
        "the first receiver must keep receiving after a second take attempt"
    );
}

/// Late install (contract violation): events emitted before
/// `take_persistence_receiver` are permanently absent from the persistence
/// stream — the channel is created empty and only delivers from installation
/// onward. The accessor warns (see its docs); this pins the behavioural half:
/// no silent replay is invented.
#[tokio::test]
async fn late_install_delivers_only_post_install_events() {
    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
    // Emitted BEFORE any consumer exists: reaches only the lossy broadcast.
    manager.update_wallet_synced_height(&wallet_id, 7);

    let mut rx =
        manager.take_persistence_receiver().expect("late install still returns the receiver");
    manager.update_wallet_synced_height(&wallet_id, 8);

    match rx.try_recv() {
        Ok(WalletEvent::SyncHeightAdvanced {
            height,
            ..
        }) => {
            assert_eq!(height, 8, "only post-install events may be delivered");
        }
        other => panic!("expected the post-install watermark, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "the pre-install event must not be replayed into the persistence stream"
    );
}

/// A consumer that drops its receiver while the manager is running must not
/// wedge or panic the emit paths: in-memory processing continues and the
/// broadcast fan-out still delivers (the lost-consumer anomaly is logged once
/// inside `emit_event`).
#[tokio::test]
async fn dropped_persistence_consumer_does_not_wedge_emission() {
    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
    let rx = manager.take_persistence_receiver().expect("receiver available once");
    drop(rx);

    let mut broadcast_rx = manager.subscribe_events();
    // Two emissions: the first trips the log-once latch, the second proves
    // emission keeps flowing afterwards.
    manager.update_wallet_synced_height(&wallet_id, 21);
    manager.update_wallet_synced_height(&wallet_id, 22);

    let mut heights = Vec::new();
    while let Ok(event) = broadcast_rx.try_recv() {
        if let WalletEvent::SyncHeightAdvanced {
            height,
            ..
        } = event
        {
            heights.push(height);
        }
    }
    assert_eq!(
        heights,
        vec![21, 22],
        "broadcast delivery must be unaffected by a lost persistence consumer"
    );
}
