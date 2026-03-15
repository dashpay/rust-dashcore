use super::test_helpers::*;
use super::*;
use crate::manager::wallet_interface::WalletInterface;
use crate::transaction_checking::BlockInfo;
use dashcore::hashes::Hash;
use dashcore::BlockHash;

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
        WalletEvent::TransactionReceived {
            txid: ev_txid,
            wallet_id: ev_wid,
            status,
            amount,
            ..
        } => {
            assert_eq!(status, TransactionContext::Mempool);
            assert_eq!(ev_txid, tx.txid());
            assert_eq!(ev_wid, wallet_id);
            assert_eq!(amount, TX_AMOUNT as i64);
        }
        other => panic!("expected TransactionReceived, got {:?}", other),
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
        WalletEvent::TransactionStatusChanged {
            wallet_id: ev_wid,
            txid: ev_txid,
            status,
        } => {
            assert_eq!(ev_wid, wallet_id);
            assert_eq!(ev_txid, tx.txid());
            assert!(
                matches!(
                                    status,
                TransactionContext::InBlock(info) if info.height() == 100
                                ),
                "expected InBlock(100), got {:?}",
                status
            );
        }
        other => panic!("expected TransactionStatusChanged, got {:?}", other),
    }
}

#[tokio::test]
async fn test_mempool_to_instantsend_to_confirmed_event_flow() {
    assert_lifecycle_flow(
        &[
            TransactionContext::Mempool,
            TransactionContext::InstantSend,
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
        &[TransactionContext::Mempool, TransactionContext::InstantSend],
        TransactionContext::InstantSend,
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
    assert_context_suppressed(&[block_ctx], block_ctx, Some(300), 0x33).await;
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_first_seen_as_instantsend_then_duplicate() {
    assert_context_suppressed(
        &[TransactionContext::InstantSend],
        TransactionContext::InstantSend,
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
        TransactionContext::InstantSend,
        Some(800),
        0x77,
    )
    .await;
}

#[tokio::test]
async fn test_mempool_after_instantsend_is_suppressed() {
    assert_context_suppressed(
        &[TransactionContext::Mempool, TransactionContext::InstantSend],
        TransactionContext::Mempool,
        None,
        0xab,
    )
    .await;
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

    manager.process_instant_send_lock(unknown_txid);

    assert_no_events(&mut rx);
    let balance_after = manager.wallet_infos.get(&wallet_id).unwrap().balance();
    assert_eq!(balance_before, balance_after);
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
    manager.process_instant_send_lock(tx.txid());
    let events = drain_events(&mut rx);
    assert!(
        events.iter().any(|e| matches!(
            e,
            WalletEvent::TransactionStatusChanged {
                wallet_id: wid,
                status: TransactionContext::InstantSend,
                ..
            } if *wid == wallet_id
        )),
        "expected TransactionStatusChanged(InstantSend) with correct wallet_id, got {:?}",
        events
    );

    // Same IS lock via check_transaction_in_all_wallets (block/tx processing path)
    // should be suppressed — no duplicate event
    manager
        .check_transaction_in_all_wallets(&tx, TransactionContext::InstantSend, true, true)
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
    manager
        .check_transaction_in_all_wallets(&tx, TransactionContext::InstantSend, true, true)
        .await;
    let events = drain_events(&mut rx);
    assert!(
        events.iter().any(|e| matches!(
            e,
            WalletEvent::TransactionStatusChanged {
                wallet_id: wid,
                status: TransactionContext::InstantSend,
                ..
            } if *wid == wallet_id
        )),
        "expected TransactionStatusChanged(InstantSend) with correct wallet_id, got {:?}",
        events
    );

    // Same IS lock via process_instant_send_lock — should be suppressed
    manager.process_instant_send_lock(tx.txid());
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
    let event = events
        .iter()
        .find(|e| matches!(e, WalletEvent::TransactionReceived { .. }))
        .unwrap_or_else(|| {
            panic!("expected TransactionReceived from process_block, got {:?}", events)
        });

    match event {
        WalletEvent::TransactionReceived {
            status,
            account_index,
            addresses,
            ..
        } => {
            assert!(
                matches!(
                                    status,
                TransactionContext::InBlock(info) if info.height() == 1000
                                ),
                "expected InBlock at height 1000, got {:?}",
                status
            );
            assert_eq!(*account_index, 0);
            assert!(!addresses.is_empty(), "expected non-empty addresses");
        }
        _ => unreachable!(),
    }
    assert!(
        events.iter().any(
            |e| matches!(e, WalletEvent::BalanceUpdated { wallet_id: wid, .. } if *wid == wallet_id)
        ),
        "expected BalanceUpdated from process_block, got {:?}",
        events
    );
}

#[tokio::test]
async fn test_instantsend_to_chainlocked_event_flow() {
    assert_lifecycle_flow(
        &[
            TransactionContext::InstantSend,
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
            event,
            WalletEvent::TransactionReceived {
                status: TransactionContext::InChainLockedBlock(info),
                ..
            } if info.height() == 2000
        ),
        "expected TransactionReceived(InChainLockedBlock at 2000), got {:?}",
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
    assert_no_events(&mut rx);

    // Call again — should still report as relevant (state not persisted)
    let result2 = manager
        .check_transaction_in_all_wallets(&tx, TransactionContext::Mempool, false, false)
        .await;
    assert!(!result2.affected_wallets.is_empty());
    assert_no_events(&mut rx);

    // Now persist — should still report as new since dry runs didn't record it
    let result3 = manager
        .check_transaction_in_all_wallets(&tx, TransactionContext::Mempool, true, true)
        .await;
    assert!(result3.is_new_transaction);
}
