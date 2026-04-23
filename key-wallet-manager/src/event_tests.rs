use super::test_helpers::*;
use super::*;
use crate::wallet_interface::WalletInterface;
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::hash_types::CycleHash;
use dashcore::hashes::Hash;
use dashcore::BlockHash;
use key_wallet::transaction_checking::BlockInfo;

// ---------------------------------------------------------------------------
// Lifecycle flow tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mempool_to_confirmed_event_flow() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&addr, 0xaa);

    // First time in mempool — validate all event fields
    manager.check_transaction_in_all_wallets(&tx, TransactionContext::Mempool, true, true).await;
    let event = assert_single_event(&mut rx);
    match event {
        WalletEvent::MempoolTransactionReceived {
            wallet_id: ev_wid,
            record,
            balance,
        } => {
            assert_eq!(record.context, TransactionContext::Mempool);
            assert_eq!(record.txid, tx.txid());
            assert_eq!(ev_wid, wallet_id);
            assert_eq!(record.net_amount, TX_AMOUNT as i64);
            assert_eq!(balance.unconfirmed(), TX_AMOUNT);
            assert_eq!(balance.confirmed(), 0);
        }
        other => panic!("expected MempoolTransactionReceived, got {:?}", other),
    }

    // Same tx now confirmed in a block
    let block_ctx = TransactionContext::InBlock(BlockInfo::new(
        100,
        BlockHash::from_byte_array([0xaa; 32]),
        1000,
    ));
    manager.check_transaction_in_all_wallets(&tx, block_ctx, true, true).await;
    let event = assert_single_event(&mut rx);
    match event {
        WalletEvent::BlockProcessChange {
            wallet_id: ev_wid,
            height,
            transactions_updated,
            balance,
        } => {
            assert_eq!(ev_wid, wallet_id);
            assert_eq!(height, 100);
            assert_eq!(transactions_updated.len(), 1);
            assert_eq!(transactions_updated[0].txid, tx.txid());
            assert!(
                matches!(
                    transactions_updated[0].context,
                    TransactionContext::InBlock(info) if info.height() == 100
                ),
                "expected record context InBlock(100)"
            );
            assert_eq!(balance.confirmed(), TX_AMOUNT);
            assert_eq!(balance.unconfirmed(), 0);
        }
        other => panic!("expected BlockProcessChange, got {:?}", other),
    }
}

#[tokio::test]
async fn test_mempool_to_instantsend_to_confirmed_event_flow() {
    assert_lifecycle_flow(
        &[
            TransactionContext::Mempool,
            TransactionContext::InstantSend(InstantLock::default()),
            TransactionContext::InBlock(BlockInfo::new(
                200,
                BlockHash::from_byte_array([0xbb; 32]),
                2000,
            )),
        ],
        0xbb,
    )
    .await;
}

#[tokio::test]
async fn test_first_seen_in_block_event_flow() {
    assert_lifecycle_flow(
        &[TransactionContext::InBlock(BlockInfo::new(
            1000,
            BlockHash::from_byte_array([0xdd; 32]),
            10000,
        ))],
        0xdd,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Duplicate suppression tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_duplicate_mempool_emits_no_event() {
    assert_context_suppressed(
        &[TransactionContext::Mempool],
        TransactionContext::Mempool,
        None,
        0x11,
    )
    .await;
}

#[tokio::test]
async fn test_duplicate_instantsend_emits_no_event() {
    assert_context_suppressed(
        &[TransactionContext::Mempool, TransactionContext::InstantSend(InstantLock::default())],
        TransactionContext::InstantSend(InstantLock::default()),
        None,
        0x22,
    )
    .await;
}

#[tokio::test]
async fn test_duplicate_confirmed_emits_no_event() {
    let block_ctx = TransactionContext::InBlock(BlockInfo::new(
        300,
        BlockHash::from_byte_array([0x33; 32]),
        3000,
    ));
    let block_ctx2 = block_ctx.clone();
    assert_context_suppressed(&[block_ctx], block_ctx2, Some(300), 0x33).await;
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_first_seen_as_instantsend_then_duplicate() {
    assert_context_suppressed(
        &[TransactionContext::InstantSend(InstantLock::default())],
        TransactionContext::InstantSend(InstantLock::default()),
        None,
        0x55,
    )
    .await;
}

#[tokio::test]
async fn test_late_instantsend_after_confirmation_is_ignored() {
    assert_context_suppressed(
        &[
            TransactionContext::Mempool,
            TransactionContext::InBlock(BlockInfo::new(
                800,
                BlockHash::from_byte_array([0x77; 32]),
                8000,
            )),
        ],
        TransactionContext::InstantSend(InstantLock::default()),
        Some(800),
        0x77,
    )
    .await;
}

#[tokio::test]
async fn test_mempool_after_instantsend_is_suppressed() {
    assert_context_suppressed(
        &[TransactionContext::Mempool, TransactionContext::InstantSend(InstantLock::default())],
        TransactionContext::Mempool,
        None,
        0xab,
    )
    .await;
}

// ---------------------------------------------------------------------------
// BalanceUpdated event tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_mempool_tx_emits_balance_updated() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&addr, 0xf1);

    manager.process_mempool_transaction(&tx, None).await;

    let events = drain_events(&mut rx);
    let received_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, WalletEvent::MempoolTransactionReceived { .. }))
        .collect();
    assert_eq!(
        received_events.len(),
        1,
        "expected exactly 1 MempoolTransactionReceived, got {:?}",
        events
    );
    assert!(
        matches!(
            received_events[0],
            WalletEvent::MempoolTransactionReceived {
                wallet_id: wid,
                balance,
                ..
            } if *wid == wallet_id && balance.unconfirmed() == TX_AMOUNT && balance.confirmed() == 0
        ),
        "expected balance.unconfirmed={TX_AMOUNT}, confirmed=0, got {:?}",
        received_events[0]
    );
}

#[tokio::test]
async fn test_instantsend_tx_emits_balance_updated_spendable() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&addr, 0xf2);

    manager.process_mempool_transaction(&tx, Some(dummy_instant_lock(tx.txid()))).await;

    let events = drain_events(&mut rx);
    let received_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, WalletEvent::MempoolTransactionReceived { .. }))
        .collect();
    assert_eq!(
        received_events.len(),
        1,
        "expected exactly 1 MempoolTransactionReceived, got {:?}",
        events
    );
    assert!(
        matches!(
            received_events[0],
            WalletEvent::MempoolTransactionReceived {
                wallet_id: wid,
                record,
                balance,
            } if *wid == wallet_id
                && matches!(record.context, TransactionContext::InstantSend(_))
                && balance.confirmed() == TX_AMOUNT
                && balance.unconfirmed() == 0
        ),
        "expected IS-context record + balance.confirmed={TX_AMOUNT}, got {:?}",
        received_events[0]
    );
}

#[tokio::test]
async fn test_mempool_to_instantsend_transitions_balance() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&addr, 0xf3);

    // Mempool tx: balance should be unconfirmed
    manager.process_mempool_transaction(&tx, None).await;
    let events = drain_events(&mut rx);
    assert!(
        events.iter().any(|e| matches!(
            e,
            WalletEvent::MempoolTransactionReceived {
                wallet_id: wid,
                balance,
                ..
            } if *wid == wallet_id && balance.unconfirmed() == TX_AMOUNT && balance.confirmed() == 0
        )),
        "expected MempoolTransactionReceived with unconfirmed={TX_AMOUNT}, got {:?}",
        events
    );

    // IS lock: balance should move from unconfirmed to confirmed
    manager.process_instant_send_lock(dummy_instant_lock(tx.txid()));
    let events = drain_events(&mut rx);
    assert!(
        events.iter().any(|e| matches!(
            e,
            WalletEvent::TransactionInstantSendLocked {
                wallet_id: wid,
                balance,
                ..
            } if *wid == wallet_id && balance.confirmed() == TX_AMOUNT && balance.unconfirmed() == 0
        )),
        "expected TransactionInstantSendLocked with confirmed={TX_AMOUNT}, got {:?}",
        events
    );
}

#[tokio::test]
async fn test_process_instant_send_lock_updates_transaction_record_context() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let tx = create_tx_paying_to(&addr, 0xf4);

    // Process as mempool transaction first
    manager.process_mempool_transaction(&tx, None).await;

    // Verify record starts with Mempool context
    let history = manager.wallet_transaction_history(&wallet_id).unwrap();
    let record = history.iter().find(|r| r.txid == tx.txid()).unwrap();
    assert_eq!(record.context, TransactionContext::Mempool);

    // Create a rich InstantLock with a non-default cyclehash
    let lock = InstantLock {
        txid: tx.txid(),
        cyclehash: CycleHash::from_byte_array([0xab; 32]),
        signature: BLSSignature::from([0xcd; 96]),
        ..InstantLock::default()
    };

    manager.process_instant_send_lock(lock.clone());

    // Verify the transaction record context was updated to InstantSend
    let history = manager.wallet_transaction_history(&wallet_id).unwrap();
    let record = history.iter().find(|r| r.txid == tx.txid()).unwrap();
    assert_eq!(
        record.context,
        TransactionContext::InstantSend(lock),
        "transaction record context should be updated to InstantSend with matching lock"
    );
}

// ---------------------------------------------------------------------------
// Production API tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_process_instant_send_lock_for_unknown_txid() {
    let (mut manager, wallet_id, _addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();

    let unknown_txid = dashcore::Txid::from_byte_array([0xee; 32]);
    let balance_before = manager.wallet_infos.get(&wallet_id).unwrap().balance();

    manager.process_instant_send_lock(dummy_instant_lock(unknown_txid));

    assert_no_events(&mut rx);
    let balance_after = manager.wallet_infos.get(&wallet_id).unwrap().balance();
    assert_eq!(balance_before, balance_after);
}

#[tokio::test]
async fn test_process_instant_send_lock_dedup() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let tx = create_tx_paying_to(&addr, 0xe1);

    manager.process_mempool_transaction(&tx, None).await;
    let mut rx = manager.subscribe_events();

    // First IS lock should emit one TransactionInstantSendLocked (balance embedded)
    manager.process_instant_send_lock(dummy_instant_lock(tx.txid()));
    let events = drain_events(&mut rx);
    let is_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, WalletEvent::TransactionInstantSendLocked { .. }))
        .collect();
    assert_eq!(
        is_events.len(),
        1,
        "expected exactly 1 TransactionInstantSendLocked, got {:?}",
        events
    );
    assert!(
        matches!(
            is_events[0],
            WalletEvent::TransactionInstantSendLocked {
                wallet_id: wid,
                balance,
                ..
            } if *wid == wallet_id && balance.confirmed() == TX_AMOUNT
        ),
        "expected TransactionInstantSendLocked for wallet with confirmed balance, got {:?}",
        is_events[0]
    );

    // Second IS lock should be a no-op
    manager.process_instant_send_lock(dummy_instant_lock(tx.txid()));
    assert_no_events(&mut rx);
}

#[tokio::test]
async fn test_process_instant_send_lock_after_block_confirmation() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let tx = create_tx_paying_to(&addr, 0xe2);

    // Process as IS mempool tx, then confirm in block
    manager.process_mempool_transaction(&tx, Some(dummy_instant_lock(tx.txid()))).await;
    let block_ctx = TransactionContext::InBlock(BlockInfo::new(
        500,
        BlockHash::from_byte_array([0xe2; 32]),
        5000,
    ));
    manager.check_transaction_in_all_wallets(&tx, block_ctx, true, true).await;

    // IS lock after block confirmation is a no-op (already tracked via mempool IS)
    let mut rx = manager.subscribe_events();
    manager.process_instant_send_lock(dummy_instant_lock(tx.txid()));
    assert_no_events(&mut rx);

    // Confirm height preserved
    let history = manager.wallet_transaction_history(&wallet_id).unwrap();
    let records: Vec<_> = history.iter().filter(|r| r.txid == tx.txid()).collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].height(), Some(500));
}

#[tokio::test]
async fn test_mixed_instantsend_paths_no_duplicate_events() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&addr, 0xf0);

    // Mempool first
    manager.check_transaction_in_all_wallets(&tx, TransactionContext::Mempool, true, true).await;
    drain_events(&mut rx);

    // IS lock via process_instant_send_lock (network IS lock message)
    manager.process_instant_send_lock(dummy_instant_lock(tx.txid()));
    let events = drain_events(&mut rx);
    assert!(
        events.iter().any(|e| matches!(
            e,
            WalletEvent::TransactionInstantSendLocked {
                wallet_id: wid,
                ..
            } if *wid == wallet_id
        )),
        "expected TransactionInstantSendLocked with correct wallet_id, got {:?}",
        events
    );

    // Same IS lock via check_transaction_in_all_wallets (block/tx processing path)
    // should be suppressed — no duplicate event
    let is_lock = dummy_instant_lock(tx.txid());
    manager
        .check_transaction_in_all_wallets(&tx, TransactionContext::InstantSend(is_lock), true, true)
        .await;
    assert_no_events(&mut rx);
}

#[tokio::test]
async fn test_mixed_instantsend_paths_reverse_no_duplicate_events() {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&addr, 0xf1);

    // Mempool first
    manager.check_transaction_in_all_wallets(&tx, TransactionContext::Mempool, true, true).await;
    drain_events(&mut rx);

    // IS lock via check_transaction_in_all_wallets first
    let is_lock = dummy_instant_lock(tx.txid());
    manager
        .check_transaction_in_all_wallets(
            &tx,
            TransactionContext::InstantSend(is_lock.clone()),
            true,
            true,
        )
        .await;
    let events = drain_events(&mut rx);
    assert!(
        events.iter().any(|e| matches!(
            e,
            WalletEvent::TransactionInstantSendLocked {
                wallet_id: wid,
                ..
            } if *wid == wallet_id
        )),
        "expected TransactionInstantSendLocked with correct wallet_id, got {:?}",
        events
    );

    // Same IS lock via process_instant_send_lock — should be suppressed
    manager.process_instant_send_lock(is_lock);
    assert_no_events(&mut rx);
}

#[tokio::test]
async fn test_process_block_emits_events() {
    use dashcore::blockdata::block::{Block, Header, Version};
    use dashcore::hashes::Hash;
    use dashcore::{BlockHash, CompactTarget, TxMerkleNode};

    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&addr, 0xe3);

    let block = Block {
        header: Header {
            version: Version::default(),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 12345,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        },
        txdata: vec![tx],
    };

    let result = manager.process_block(&block, 1000).await;
    assert_eq!(result.new_txids.len(), 1);

    let events = drain_events(&mut rx);
    let block_events: Vec<_> =
        events.iter().filter(|e| matches!(e, WalletEvent::BlockProcessChange { .. })).collect();
    assert_eq!(block_events.len(), 1, "expected exactly one BlockProcessChange, got {:?}", events);

    match block_events[0] {
        WalletEvent::BlockProcessChange {
            wallet_id: wid,
            height,
            transactions_updated,
            balance,
        } => {
            assert_eq!(*wid, wallet_id);
            assert_eq!(*height, 1000);
            assert_eq!(transactions_updated.len(), 1);
            let record = &transactions_updated[0];
            assert!(
                matches!(
                    record.context,
                    TransactionContext::InBlock(info) if info.height() == 1000
                ),
                "expected InBlock at height 1000, got {:?}",
                record.context
            );
            assert!(
                !record.input_details.is_empty() || !record.output_details.is_empty(),
                "expected non-empty details"
            );
            assert_eq!(balance.confirmed(), TX_AMOUNT);
        }
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn test_irrelevant_mempool_tx_emits_no_events() {
    use dashcore::{PublicKey, ScriptBuf};

    let (mut manager, _wallet_id, _addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();

    // Create a tx paying to a random script that doesn't match any wallet address
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
    assert_eq!(result.net_amount, 0);
    assert_no_events(&mut rx);
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_instantsend_to_chainlocked_event_flow() {
    assert_lifecycle_flow(
        &[
            TransactionContext::InstantSend(InstantLock::default()),
            TransactionContext::InChainLockedBlock(BlockInfo::new(
                1600,
                BlockHash::from_byte_array([0xc3; 32]),
                16000,
            )),
        ],
        0xc3,
    )
    .await;
}

#[tokio::test]
async fn test_mempool_to_block_to_chainlocked_event_flow() {
    let (mut manager, _wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&addr, 0xc4);

    // Step 1: mempool — emits MempoolTransactionReceived
    manager.check_transaction_in_all_wallets(&tx, TransactionContext::Mempool, true, true).await;
    let event = assert_single_event(&mut rx);
    assert!(
        matches!(
            &event,
            WalletEvent::MempoolTransactionReceived { record, .. }
            if record.context == TransactionContext::Mempool
        ),
        "expected MempoolTransactionReceived(Mempool), got {:?}",
        event
    );

    // Step 2: block confirmation — emits BlockProcessChange
    let block_ctx = TransactionContext::InBlock(BlockInfo::new(
        1700,
        BlockHash::from_byte_array([0xc4; 32]),
        17000,
    ));
    manager.check_transaction_in_all_wallets(&tx, block_ctx, true, true).await;
    let event = assert_single_event(&mut rx);
    assert!(
        matches!(
            &event,
            WalletEvent::BlockProcessChange {
                height,
                transactions_updated,
                ..
            } if *height == 1700 && transactions_updated.len() == 1
        ),
        "expected BlockProcessChange(height=1700, 1 tx), got {:?}",
        event
    );

    // Step 3: chain lock on already-confirmed tx — no event (wallet doesn't
    // track chain lock state separately from block confirmation)
    let cl_ctx = TransactionContext::InChainLockedBlock(BlockInfo::new(
        1700,
        BlockHash::from_byte_array([0xc4; 32]),
        17000,
    ));
    manager.check_transaction_in_all_wallets(&tx, cl_ctx, true, true).await;
    assert_no_events(&mut rx);
}

#[tokio::test]
async fn test_chainlocked_block_event_flow() {
    let (mut manager, _wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&addr, 0xc1);

    let ctx = TransactionContext::InChainLockedBlock(BlockInfo::new(
        2000,
        BlockHash::from_byte_array([0xc1; 32]),
        20000,
    ));
    manager.check_transaction_in_all_wallets(&tx, ctx, true, true).await;
    let event = assert_single_event(&mut rx);
    assert!(
        matches!(
            &event,
            WalletEvent::BlockProcessChange { height, transactions_updated, .. }
            if *height == 2000 && transactions_updated.len() == 1 && matches!(transactions_updated[0].context, TransactionContext::InChainLockedBlock(info) if info.height() == 2000)
        ),
        "expected BlockProcessChange(InChainLockedBlock at 2000, 1 tx), got {:?}",
        event
    );
}

#[tokio::test]
async fn test_check_transaction_dry_run_does_not_persist_state() {
    let (mut manager, _wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&addr, 0xd1);

    // Dry run: update_state_if_found = false
    let result = manager
        .check_transaction_in_all_wallets(&tx, TransactionContext::Mempool, false, false)
        .await;

    assert!(!result.affected_wallets.is_empty());
    assert_eq!(result.total_received, TX_AMOUNT);
    assert_no_events(&mut rx);

    // Call again — should still report as relevant (state not persisted)
    let result2 = manager
        .check_transaction_in_all_wallets(&tx, TransactionContext::Mempool, false, false)
        .await;
    assert!(!result2.affected_wallets.is_empty());
    assert_eq!(result2.total_received, TX_AMOUNT);
    assert_no_events(&mut rx);

    // Now persist — should still report as new since dry runs didn't record it
    let result3 = manager
        .check_transaction_in_all_wallets(&tx, TransactionContext::Mempool, true, true)
        .await;
    assert!(result3.is_new_transaction);
}
