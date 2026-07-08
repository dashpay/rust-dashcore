//! Multi-wallet isolation for the observed-spent-outpoint guard
//! (dashpay/rust-dashcore#649).
//!
//! `observed_spent_outpoints` lives on `ManagedWalletInfo` (per wallet), not on
//! a shared `WalletManager` structure. So one wallet observing a spend for an
//! outpoint must never suppress a *different* wallet's legitimate funding of the
//! same outpoint — even when both wallets, in the same process, happen to match
//! it (e.g. a synthetic/colliding outpoint, or a reused xpub-derived address
//! across two independently imported wallets, which the SDK does not forbid).

mod common;

use common::{funding_tx, process_block_for, spend_tx};
use dashcore::blockdata::block::Block;
use dashcore::blockdata::transaction::OutPoint;
use dashcore::Network;
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::{WalletId, WalletManager};
use std::collections::BTreeSet;

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
    let funding = funding_tx(&b_address, funding_value, 0xB0);
    let outpoint = OutPoint::new(funding.txid(), 0);

    // A spend of O, delivered to wallet A out of order (before any funding A sees).
    let spend = spend_tx(outpoint, funding_value - 1_000, 77);

    let only_a: BTreeSet<WalletId> = [wallet_a].into_iter().collect();
    let only_b: BTreeSet<WalletId> = [wallet_b].into_iter().collect();

    // Wallet A observes the spend (records O in A's set only).
    let spend_block = Block::dummy(200, vec![spend]);
    process_block_for(&mut manager, &spend_block, 200, &only_a).await;

    // Wallet B funds O in order — B never saw the spend, so B's set is empty.
    let funding_block = Block::dummy(100, vec![funding]);
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
