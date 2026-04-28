use super::*;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::hashes::Hash;
use dashcore::{OutPoint, ScriptBuf, TxIn, TxOut, Txid, Witness};
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::Network;
use tokio::sync::broadcast;

pub(crate) const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

pub(crate) const TX_AMOUNT: u64 = 100_000;

pub(crate) fn dummy_instant_lock(txid: Txid) -> InstantLock {
    InstantLock {
        txid,
        ..InstantLock::default()
    }
}

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

/// Drain events and assert none were emitted.
pub(crate) fn assert_no_events(rx: &mut broadcast::Receiver<WalletEvent>) {
    let events = drain_events(rx);
    assert!(events.is_empty(), "expected no events, got {}: {:?}", events.len(), events);
}
