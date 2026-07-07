//! A spend that is processed BEFORE the transaction that created the UTXO
//! it spends (out-of-order block delivery during rescan) leaves that UTXO
//! permanently in the wallet's tracked set — the exact mechanism forensically
//! traced from a real backend-e2e failure log, not a guessed structure.
//!
//! Defect site: `key-wallet/src/managed_account/managed_core_funds_account.rs`
//! (`update_utxos`). The function already has a guard for exactly this
//! ordering ("Check if this outpoint was already spent by a transaction
//! we've seen. This handles out-of-order block processing during rescan...")
//! via `self.is_outpoint_spent(&outpoint)` checked against `self
//! .spent_outpoints`, populated by the SAME function's spend-processing loop
//! a few lines below (`self.spent_outpoints.insert(input.previous_output)`
//! for every input of every processed transaction, regardless of whether
//! that input is recognized as one of this account's own UTXOs).
//!
//! ## Forensic basis — this is not a guessed scenario
//!
//! Traced from a real backend-e2e run against Dash testnet
//! (`/data/tmp/backend-e2e-tc004-realfund-run1-9j4HEx.log` and
//! `/data/tmp/backend-e2e-tc004-coldstart-JyD9Vy.log`, per
//! `docs/ai-design/2026-07-07-asset-lock-finality-retest/retest-findings.md`
//! §16-20 in dash-evo-tool). Block heights during a cold rescan are
//! processed in essentially arbitrary order (heights jump backward and
//! forward across thousands of blocks — the `parallel-filters` matching
//! feature completes matches in whatever order worker threads finish, not
//! height order). For the specific failing case: a real spend at height
//! 1,474,746 was logged as processed at 08:45:45.155707Z with the spending
//! transaction showing `sent=0 DASH` (the wallet did not yet recognize the
//! input as its own — because the funding UTXO had not been inserted into
//! `self.utxos` yet). The transaction that CREATED that same UTXO, at the
//! earlier height 1,474,688, was processed 0.87 seconds later, at
//! 08:45:46.028186Z, and was inserted as a fresh, spendable UTXO
//! (`WalletEvent: BlockProcessed(height=1474688, ..., inserted=1, ...)`).
//! That UTXO stayed in this state through the rest of the investigation:
//! `key-wallet` later selected it as `require_final_inputs`-eligible funding
//! for a real asset-lock transaction, which the real network rejected
//! (`FinalityTimeout`) because the input was already spent.
//!
//! This test reproduces the same ORDER — process the spending block first,
//! then the funding block — synthetically and deterministically, to check
//! whether the code's own out-of-order guard (`is_outpoint_spent`) actually
//! prevents the funding UTXO from being (re-)inserted once its spend has
//! already been observed.
//!
//! ## Relationship to the CoinJoin gap-limit precedent on this branch
//!
//! `dash-spv/src/sync/filters/coinjoin_gap_discovery_tests.rs`'s RED case
//! (`coinjoin_gap_limit_stall_across_committed_batch`) is about a *funding*
//! output in an already-COMMITTED batch never being rescanned once its
//! owning address is derived later — a CROSS-batch defect (rescans never
//! reopen committed ranges). This test's forensic basis shows a DIFFERENT,
//! narrower defect: the funding and its spend were both processed within
//! the SAME committed batch (`1474001-1479000`, per the coldstart log) —
//! this is an INTRA-batch ordering defect in the guard that is supposed to
//! compensate for scrambled in-batch processing order, not the cross-batch
//! commit-pruning issue. Related in theme (rescan reordering breaking
//! wallet-state invariants), not the same specific mechanism.
//!
//! ## Test lifecycle
//!
//! If red: the `is_outpoint_spent` guard does not prevent the funding UTXO
//! from surfacing as tracked/spendable once its spend was already observed
//! first — this is the primary, concretely-reproduced defect. If green:
//! the guard works correctly for this exact ordering and the real-world
//! failure needs a different or additional triggering condition than
//! traced here — reported either way, not forced.

use dashcore::blockdata::block::Block;
use dashcore::blockdata::transaction::OutPoint;
use dashcore::{Network, ScriptBuf, Transaction, TxIn, TxOut, Witness};
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet_manager::{WalletId, WalletInterface, WalletManager};
use std::collections::BTreeSet;

async fn process_block_all_wallets(
    manager: &mut WalletManager<ManagedWalletInfo>,
    block: &Block,
    height: u32,
) {
    let wallet_ids: BTreeSet<WalletId> = manager.list_wallets().into_iter().copied().collect();
    manager.process_block_for_wallets(block, block.block_hash(), height, &wallet_ids).await;
}

#[tokio::test]
async fn spend_processed_before_its_funding_tx_leaves_utxo_permanently_tracked() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);
    let wallet_id = manager
        .create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default)
        .expect("failed to create wallet");

    // The address that will receive the funding output — this account's
    // first monitored (external, index 0) address.
    let funding_address =
        manager.monitored_addresses().first().cloned().expect("wallet must have addresses");

    // Funding transaction: pays 1,000,000 duffs to our own address. Built
    // with a synthetic, unrelated input (its previous_output is irrelevant
    // to this account) — only its OWN txid/vout (as the thing spent below)
    // matters.
    let funding_value = 1_000_000u64;
    let funding_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(dashcore::Txid::from([0xABu8; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: funding_value,
            script_pubkey: funding_address.script_pubkey(),
        }],
        special_transaction_payload: None,
    };
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);

    // Spending transaction: spends the funding UTXO above (by its
    // already-known txid — no need to have processed it yet) and pays out
    // to an unrelated external address, exactly like the real observed
    // failure (change/self-send is irrelevant here — the point is that the
    // wallet no longer owns this specific output afterward).
    let external_address = dashcore::Address::dummy(Network::Testnet, 99);
    let spend_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: funding_value - 1_000,
            script_pubkey: external_address.script_pubkey(),
        }],
        special_transaction_payload: None,
    };

    // The real observed order: the SPEND's block (higher real height,
    // 1,474,746) was processed before the FUNDING's block (lower real
    // height, 1,474,688). Reproduce the same inversion with synthetic
    // heights 200 (spend) processed before 100 (funding).
    let spend_block = Block::dummy(200, vec![spend_tx.clone()]);
    process_block_all_wallets(&mut manager, &spend_block, 200).await;

    let funding_block = Block::dummy(100, vec![funding_tx.clone()]);
    process_block_all_wallets(&mut manager, &funding_block, 100).await;

    let utxos_after = manager.wallet_utxos(&wallet_id).expect("wallet must be registered");
    let still_tracked = utxos_after.iter().any(|u| u.outpoint == funding_outpoint);

    assert!(
        !still_tracked,
        "BUG: funding outpoint {funding_outpoint} is still present in the wallet's tracked \
         UTXO set after its spend was processed FIRST (height 200) and its funding \
         transaction was processed SECOND (height 100) — the exact real-world ordering \
         traced from a live testnet rescan. `update_utxos`'s own `is_outpoint_spent` guard \
         (managed_core_funds_account.rs) exists specifically to handle this case \
         (\"out-of-order block processing during rescan\") but did not prevent the funding \
         output from being (re-)inserted as tracked/spendable once its spend had already \
         been observed."
    );
}
