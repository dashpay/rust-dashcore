//! Multi-wallet isolation for the observed-spent-outpoint guard
//! (dashpay/rust-dashcore#649).
//!
//! `observed_spent_outpoints` lives on `ManagedWalletInfo` (per wallet), not on
//! a shared `WalletManager` structure. So one wallet observing a spend for an
//! outpoint must never suppress a *different* wallet's legitimate funding of the
//! same outpoint — even when both wallets, in the same process, happen to match
//! it (e.g. a synthetic/colliding outpoint, or a reused xpub-derived address
//! across two independently imported wallets, which the SDK does not forbid).

use dashcore::blockdata::block::Block;
use dashcore::blockdata::transaction::OutPoint;
use dashcore::{Network, ScriptBuf, Transaction, TxIn, TxOut, Witness};
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::{WalletId, WalletInterface, WalletManager};
use std::collections::BTreeSet;

async fn process_block_for(
    manager: &mut WalletManager<ManagedWalletInfo>,
    block: &Block,
    height: u32,
    wallets: &BTreeSet<WalletId>,
) {
    manager.process_block_for_wallets(block, block.block_hash(), height, wallets).await;
}

#[tokio::test]
async fn observed_spends_are_isolated_per_wallet() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);

    // Create wallet B first and capture one of its own addresses while it is the
    // only wallet, so the funding transaction pays an address B recognizes.
    let wallet_b = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("create wallet B");
    let b_address = manager.monitored_addresses().first().cloned().expect("wallet B has addresses");

    // Then create wallet A, which observes the spend but never funds the coin.
    let wallet_a = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("create wallet A");

    // Funding pays B's address; the outpoint it creates is O.
    let funding_value = 1_000_000u64;
    let funding_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(dashcore::Txid::from([0xB0u8; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: funding_value,
            script_pubkey: b_address.script_pubkey(),
        }],
        special_transaction_payload: None,
    };
    let outpoint = OutPoint::new(funding_tx.txid(), 0);

    // A spend of O, delivered to wallet A out of order (before any funding A sees).
    let external = dashcore::Address::dummy(Network::Testnet, 77);
    let spend_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: funding_value - 1_000,
            script_pubkey: external.script_pubkey(),
        }],
        special_transaction_payload: None,
    };

    let only_a: BTreeSet<WalletId> = [wallet_a].into_iter().collect();
    let only_b: BTreeSet<WalletId> = [wallet_b].into_iter().collect();

    // Wallet A observes the spend (records O in A's set only).
    let spend_block = Block::dummy(200, vec![spend_tx]);
    process_block_for(&mut manager, &spend_block, 200, &only_a).await;

    // Wallet B funds O in order — B never saw the spend, so B's set is empty.
    let funding_block = Block::dummy(100, vec![funding_tx]);
    process_block_for(&mut manager, &funding_block, 100, &only_b).await;

    let b_utxos = manager.wallet_utxos(&wallet_b).expect("wallet B registered");
    assert!(
        b_utxos.iter().any(|u| u.outpoint == outpoint),
        "wallet B's legitimate funding must NOT be suppressed by wallet A's spend observation"
    );
    let a_utxos = manager.wallet_utxos(&wallet_a).expect("wallet A registered");
    assert!(
        !a_utxos.iter().any(|u| u.outpoint == outpoint),
        "wallet A never funded O and must not track it"
    );
}
