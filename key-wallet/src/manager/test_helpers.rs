use super::*;
use crate::wallet::initialization::WalletAccountCreationOptions;
use crate::wallet::managed_wallet_info::ManagedWalletInfo;
use crate::Network;
use dashcore::hashes::Hash;
use dashcore::{OutPoint, ScriptBuf, TxIn, TxOut, Txid, Witness};
use tokio::sync::broadcast;

pub(crate) const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

pub(crate) const TX_AMOUNT: u64 = 100_000;

pub(crate) fn setup_manager_with_wallet() -> (WalletManager<ManagedWalletInfo>, WalletId, Address) {
    let mut manager = WalletManager::new(Network::Testnet);
    let wallet_id = manager
        .create_wallet_from_mnemonic(TEST_MNEMONIC, "", 0, WalletAccountCreationOptions::Default)
        .unwrap();
    let addresses = manager.monitored_addresses();
    assert!(!addresses.is_empty(), "wallet should have monitored addresses");
    let addr = addresses[0].clone();
    (manager, wallet_id, addr)
}

pub(crate) fn create_tx_paying_to(addr: &Address, input_seed: u8) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([input_seed; 32]),
                vout: 0,
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

pub(crate) fn drain_events(rx: &mut broadcast::Receiver<WalletEvent>) -> Vec<WalletEvent> {
    let mut events = Vec::new();
    while let Ok(e) = rx.try_recv() {
        events.push(e);
    }
    events
}

/// Drain events from the receiver, assert exactly one was emitted, and return it.
pub(crate) fn assert_single_event(rx: &mut broadcast::Receiver<WalletEvent>) -> WalletEvent {
    let events = drain_events(rx);
    assert_eq!(events.len(), 1, "expected 1 event, got {}: {:?}", events.len(), events);
    events.into_iter().next().unwrap()
}

/// Drain events and assert none were emitted.
pub(crate) fn assert_no_events(rx: &mut broadcast::Receiver<WalletEvent>) {
    let events = drain_events(rx);
    assert!(events.is_empty(), "expected no events, got {}: {:?}", events.len(), events);
}

/// Submit a transaction through a sequence of contexts and verify the event flow.
///
/// The first context produces a `TransactionReceived` event; each subsequent
/// context produces a `TransactionStatusChanged` event.
pub(crate) async fn assert_lifecycle_flow(contexts: &[TransactionContext], input_seed: u8) {
    assert!(!contexts.is_empty(), "at least one context required");

    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&addr, input_seed);

    for (i, ctx) in contexts.iter().enumerate() {
        manager.check_transaction_in_all_wallets(&tx, *ctx, true, true).await;
        let event = assert_single_event(&mut rx);

        if i == 0 {
            assert!(
                matches!(event, WalletEvent::TransactionReceived { wallet_id: wid, status, .. } if wid == wallet_id && status == *ctx),
                "context[{}]: expected TransactionReceived with wallet_id and status {:?}, got {:?}",
                i,
                ctx,
                event
            );
        } else {
            assert!(
                matches!(event, WalletEvent::TransactionStatusChanged { wallet_id: wid, status, .. } if wid == wallet_id && status == *ctx),
                "context[{}]: expected TransactionStatusChanged with wallet_id and status {:?}, got {:?}",
                i,
                ctx,
                event
            );
        }
    }
}

/// Submit a transaction through `setup_contexts`, drain events, then submit with
/// `suppressed_context` and assert no event is emitted. Optionally verify
/// the stored height.
pub(crate) async fn assert_context_suppressed(
    setup_contexts: &[TransactionContext],
    suppressed_context: TransactionContext,
    expected_height: Option<u32>,
    input_seed: u8,
) {
    let (mut manager, wallet_id, addr) = setup_manager_with_wallet();
    let mut rx = manager.subscribe_events();
    let tx = create_tx_paying_to(&addr, input_seed);

    for ctx in setup_contexts {
        manager.check_transaction_in_all_wallets(&tx, *ctx, true, true).await;
        drain_events(&mut rx);
    }

    manager.check_transaction_in_all_wallets(&tx, suppressed_context, true, true).await;
    assert_no_events(&mut rx);

    let history = manager.wallet_transaction_history(&wallet_id).unwrap();
    let records: Vec<_> = history.iter().filter(|r| r.txid == tx.txid()).collect();
    assert_eq!(records.len(), 1);
    if let Some(height) = expected_height {
        assert_eq!(records[0].height, Some(height));
    }
}
