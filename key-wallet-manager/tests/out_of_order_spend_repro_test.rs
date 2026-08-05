//! A spend that is processed BEFORE the transaction that created the UTXO it
//! spends (out-of-order block delivery during rescan) must not leave that UTXO
//! permanently in the wallet's tracked set (dashpay/rust-dashcore#649).
//!
//! Guard site: `key-wallet/src/managed_account/managed_core_funds_account.rs`
//! (`update_utxos`). The function guards exactly this ordering ("Check if this
//! outpoint was already spent by a transaction we've seen. This handles
//! out-of-order block processing during rescan...") via
//! `self.is_outpoint_spent(&outpoint)` checked against `self.spent_outpoints`,
//! populated by the same function's spend-processing loop
//! (`self.spent_outpoints.insert(input.previous_output)` for every input of
//! every processed transaction, regardless of whether that input is recognized
//! as one of this account's own UTXOs).
//!
//! During a cold rescan, block heights are processed in essentially arbitrary
//! order (the parallel-filters matching completes in whatever order worker
//! threads finish, not height order). A spend can therefore be processed before
//! the funding transaction that created the coin it spends — the spending
//! transaction shows `sent = 0` because the wallet does not yet recognize the
//! input as its own, and the funding transaction is then inserted as a fresh,
//! spendable UTXO. If the guard fails, `key-wallet` can later select that coin
//! as `require_final_inputs`-eligible funding for an asset-lock transaction the
//! network rejects because the input is already spent.
//!
//! This test reproduces the same ORDER — process the spending block first, then
//! the funding block — deterministically, and checks that the out-of-order
//! guard prevents the funding UTXO from being (re-)inserted once its spend has
//! already been observed.

mod common;

use common::{funding_tx, process_block_all_wallets, spend_tx};
use dashcore::blockdata::block::Block;
use dashcore::blockdata::transaction::OutPoint;
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::WalletManager;

#[tokio::test]
async fn spend_processed_before_its_funding_tx_leaves_utxo_permanently_tracked() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(dashcore::Network::Testnet);
    let wallet_id = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("failed to create wallet");

    // The address that will receive the funding output — this account's first
    // monitored (external, index 0) address.
    let funding_address =
        manager.monitored_addresses().first().cloned().expect("wallet must have addresses");

    // Funding pays 1,000,000 duffs to our own address; only its own txid/vout
    // (the coin later spent) matters.
    let funding_value = 1_000_000u64;
    let funding = funding_tx(&funding_address, funding_value, 0xAB);
    let funding_outpoint = OutPoint::new(funding.txid(), 0);

    // Spend the funding UTXO (by its already-known txid) out to an external
    // address, so the wallet no longer owns this specific output afterward.
    let spend = spend_tx(dashcore::Network::Testnet, funding_outpoint, funding_value - 1_000, 99);

    // Out-of-order delivery: the spend's block (height 200) is processed before
    // the funding's block (height 100).
    let spend_block = Block::dummy(200, vec![spend]);
    process_block_all_wallets(&mut manager, &spend_block, 200).await;

    let funding_block = Block::dummy(100, vec![funding]);
    process_block_all_wallets(&mut manager, &funding_block, 100).await;

    let utxos_after = manager.wallet_utxos(&wallet_id).expect("wallet must be registered");
    let still_tracked = utxos_after.iter().any(|u| u.outpoint == funding_outpoint);

    assert!(
        !still_tracked,
        "BUG #649 regression: funding outpoint {funding_outpoint} is still present in the \
         wallet's tracked UTXO set after its spend was processed FIRST (height 200) and its \
         funding transaction was processed SECOND (height 100). `update_utxos`'s own \
         `is_outpoint_spent` guard (managed_core_funds_account.rs) exists to handle this \
         out-of-order case but did not prevent the funding output from being (re-)inserted as \
         tracked/spendable once its spend had already been observed."
    );
}
