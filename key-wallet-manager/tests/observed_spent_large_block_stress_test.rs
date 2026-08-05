//! Adversarial stress test for the observed-spent-outpoint guard
//! (dashpay/rust-dashcore#649) at the *single-block* granularity, as opposed
//! to spreading growth across many small blocks.
//!
//! `process_block_for_wallets` (`key-wallet-manager/src/process_block.rs`)
//! iterates every transaction in `block.txdata` and calls
//! `check_transaction_in_wallets` for EACH ONE, unconditionally — a matched
//! block is delivered whole once ANY of its transactions matches a wallet's
//! compact filter. `ManagedWalletInfo::check_core_transaction`
//! (`key-wallet/src/transaction_checking/wallet_checker.rs`) then records
//! every input of every transaction it sees in block context into
//! `observed_spent_outpoints`, and — for transactions it judges irrelevant —
//! also calls `remove_spent_from_accounts`, which allocates a
//! `Vec<&mut ManagedCoreFundsAccount>` via `all_funding_accounts_mut()` and
//! attempts a UTXO-map removal per input, for every one of those irrelevant
//! transactions.
//!
//! The sibling `many_orphaned_spend_blocks_stay_bounded_and_linear`
//! (`key-wallet/src/tests/observed_spent_outpoints_tests.rs`) spreads growth
//! across many separate `check_transaction` calls at distinct heights. That
//! does not exercise what a real matched block looks like: many transactions
//! sharing ONE height/block, most of them entirely unrelated to the wallet.
//! This test constructs a single `Block` with 5,000 unrelated 3-input
//! transactions plus one wallet-relevant spend, and verifies both correctness
//! (the bug is still caught when the relevant tx is buried in a large noisy
//! block) and the actual growth/cost this produces.

mod common;

use common::process_block_all_wallets;
use dashcore::blockdata::block::Block;
use dashcore::blockdata::transaction::OutPoint;
use dashcore::{Network, ScriptBuf, Transaction, TxIn, TxOut, Witness};
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::WalletManager;
use std::time::Instant;

const NOISE_TXS_PER_BLOCK: usize = 5_000;
const INPUTS_PER_NOISE_TX: usize = 3;

/// An unrelated 3-input transaction paying an external address, with inputs
/// deterministically derived from `seed` so every one is distinct and none
/// resolves to any outpoint the wallet will ever fund.
fn noise_tx(seed: u32) -> Transaction {
    let input = (0..INPUTS_PER_NOISE_TX as u32)
        .map(|v| {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&seed.to_le_bytes());
            bytes[4] = v as u8;
            TxIn {
                previous_output: OutPoint::new(dashcore::Txid::from(bytes), v),
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: Witness::new(),
            }
        })
        .collect();
    Transaction {
        version: 2,
        lock_time: 0,
        input,
        output: vec![TxOut {
            value: 1_000,
            script_pubkey: dashcore::Address::dummy(Network::Testnet, (seed % 90) as usize + 1)
                .script_pubkey(),
        }],
        special_transaction_payload: None,
    }
}

#[tokio::test]
async fn wallet_relevant_spend_buried_in_large_noisy_block_still_caught() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);
    let wallet_id = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("failed to create wallet");
    let funding_address =
        manager.monitored_addresses().first().cloned().expect("wallet must have addresses");

    let funding_value = 1_000_000u64;
    let funding_tx = common::funding_tx(&funding_address, funding_value, 0xAB);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);

    let spend_tx = common::spend_tx(Network::Testnet, funding_outpoint, funding_value - 1_000, 99);

    // One large block: 5,000 unrelated noise transactions with the single
    // wallet-relevant spend buried in the middle — this is the realistic
    // shape of "a matched block" (dash-spv delivers the whole block once any
    // tx in it matches the filter), not 5,000 separate block deliveries.
    let mut txdata: Vec<Transaction> = (0..NOISE_TXS_PER_BLOCK as u32).map(noise_tx).collect();
    let mid = txdata.len() / 2;
    txdata.insert(mid, spend_tx.clone());
    let expected_inputs_in_spend_block =
        NOISE_TXS_PER_BLOCK * INPUTS_PER_NOISE_TX + 1 /* spend_tx's own input */;

    let spend_block = Block::dummy(200, txdata);

    let start = Instant::now();
    process_block_all_wallets(&mut manager, &spend_block, 200).await;
    let large_block_elapsed = start.elapsed();

    let funding_block = Block::dummy(100, vec![funding_tx.clone()]);
    process_block_all_wallets(&mut manager, &funding_block, 100).await;

    let utxos_after = manager.wallet_utxos(&wallet_id).expect("wallet must be registered");
    let still_tracked = utxos_after.iter().any(|u| u.outpoint == funding_outpoint);
    assert!(
        !still_tracked,
        "BUG #649 regression: the relevant spend buried among {NOISE_TXS_PER_BLOCK} unrelated \
         transactions in the same block was not correctly reconciled against its \
         out-of-order funding"
    );

    let observed_len =
        manager.get_wallet_info(&wallet_id).expect("wallet info").observed_spent_outpoints().len();
    let expected_total = expected_inputs_in_spend_block + 1 /* funding_tx's own input */;
    assert_eq!(
        observed_len, expected_total,
        "a single matched block with {NOISE_TXS_PER_BLOCK} unrelated txs records one \
         observed-spent entry per input in the WHOLE block, not just the relevant tx — \
         set grew to {observed_len} entries from ONE block, confirming growth scales with \
         transactions-per-block, not with block count"
    );

    eprintln!(
        "single block with {} txs ({} inputs) processed in {:?} ({:.1} us/input); \
         observed_spent_outpoints now holds {} entries after ONE block",
        NOISE_TXS_PER_BLOCK + 1,
        expected_inputs_in_spend_block,
        large_block_elapsed,
        large_block_elapsed.as_micros() as f64 / expected_inputs_in_spend_block as f64,
        observed_len,
    );

    // Per-block processing cost, reported as a diagnostic rather than asserted:
    // a wall-clock threshold flakes on shared CI runners, while correctness is
    // already pinned above. A multi-second time here would flag the un-gated
    // recording/removal seam as a production concern for busy blocks.
    eprintln!(
        "single block with {NOISE_TXS_PER_BLOCK} unrelated txs processed in {large_block_elapsed:?}"
    );
}
