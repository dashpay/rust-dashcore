//! Marvin's adversarial verification of decision-doc §5's "gap #5" closure
//! claim for dashpay/rust-dashcore#649's restructure.
//!
//! Gap #5 (decision doc §2, trigger 3): `apply_chain_lock`
//! (`key-wallet-manager/src/process_block.rs:301`) is driven asynchronously,
//! entirely decoupled from funding/spend processing. Scenario: a funding
//! transaction is recorded `InBlock` (record fully live), a ChainLock event
//! arrives and prunes the record to `finalized_txids` under the default
//! `keep-finalized-transactions = OFF` feature, and only THEN does an
//! out-of-order, unattributed spend of that coin arrive. Before the
//! restructure this would have hit `finalize_guard_removed_utxo`'s
//! read-modify-write on a record that had, in the interim, ceased to exist.
//!
//! Per decision doc §5, this is claimed to be dissolved (not patched): the
//! record's absence is a no-op for the (declarative, not incremental)
//! recompute, and balance correctness (α) never depended on the record at
//! all. This test constructs the exact race and checks that claim holds:
//! no panic, no phantom balance, and reprocessing safety (the account-local
//! spent marker is still set even though the record lookup was a no-op).
//!
//! The whole scenario is specific to the default `keep-finalized-transactions
//! = OFF` pruning path (see `plain_chainlocked_funding_diverges_history_from_balance_by_design`
//! in `observed_spent_outpoints_tests.rs` for why): with the feature on,
//! records are never pruned and this race cannot occur, so the module is
//! gated out entirely under `--features keep-finalized-transactions`.
#![cfg(not(feature = "keep-finalized-transactions"))]

use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{
    BlockInfo, TransactionContext, TransactionRouter, TransactionType,
};
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::blockdata::transaction::OutPoint;
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::{Address, Network, ScriptBuf, Transaction, TxIn, TxOut, Witness};

fn block_ctx(height: u32) -> TransactionContext {
    TransactionContext::InBlock(BlockInfo::new(
        height,
        dashcore::BlockHash::dummy(height),
        1_650_000_000 + height,
    ))
}

fn spend_to_external(inputs: &[OutPoint], value: u64, ext_id: usize) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: inputs
            .iter()
            .map(|op| TxIn {
                previous_output: *op,
                script_sig: ScriptBuf::new(),
                sequence: 0xffffffff,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value,
            script_pubkey: Address::dummy(Network::Testnet, ext_id).script_pubkey(),
        }],
        special_transaction_payload: None,
    }
}

fn utxo_tracked(wallet: &crate::wallet::ManagedWalletInfo, outpoint: &OutPoint) -> bool {
    wallet.accounts.all_funding_accounts().iter().any(|a| a.utxos.contains_key(outpoint))
}

fn history_net(wallet: &crate::wallet::ManagedWalletInfo) -> i64 {
    wallet.transaction_history().iter().map(|r| r.net_amount).sum()
}

#[tokio::test]
async fn async_chain_lock_prune_races_unattributed_spend_gap5() {
    let mut ctx = TestWalletContext::new_random();

    let cj_xpub = ctx.wallet.get_coinjoin_account(0).expect("coinjoin account").account_xpub;
    let cj_address = ctx
        .managed_wallet
        .first_coinjoin_managed_account_mut()
        .expect("managed coinjoin account")
        .next_address(Some(&cj_xpub), true)
        .expect("coinjoin address");

    let funding_value = 1_700_000u64;
    let funding_tx = Transaction::dummy(&cj_address, 0..1, &[funding_value]);
    let funding_txid = funding_tx.txid();
    let funding_outpoint = OutPoint::new(funding_txid, 0);

    // Funding recorded InBlock — NOT chainlocked at first sighting, so the
    // record is fully live (unlike gap #4's chainlocked-first-sighting case).
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    assert!(utxo_tracked(&ctx.managed_wallet, &funding_outpoint), "coin live after funding");
    assert!(
        ctx.managed_wallet
            .first_coinjoin_managed_account()
            .expect("account")
            .transactions()
            .contains_key(&funding_txid),
        "record must be live before the chainlock — this is NOT gap #4's chainlocked-first-sighting case"
    );

    // Async chain-lock event prunes the record — entirely decoupled from any
    // spend processing (gap #5's mechanism, process_block.rs:301).
    ctx.managed_wallet.update_last_processed_height(100);
    let outcome = ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(100));
    assert!(!outcome.locked_transactions.is_empty(), "the funding record must have been promoted");
    assert!(
        !ctx.managed_wallet
            .first_coinjoin_managed_account()
            .expect("account")
            .transactions()
            .contains_key(&funding_txid),
        "record pruned by the chainlock BEFORE any spend is known to the wallet"
    );
    assert!(
        utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "the coin remains live in the UTXO set — balance (α) never depended on the record"
    );

    // The out-of-order, unattributed spend now arrives (AssetLock-classified,
    // routes away from the CoinJoin account — same routing gap exercised by
    // `coinjoin_utxo_spent_by_asset_lock_classified_tx_still_invalidated` in
    // observed_spent_outpoints_tests.rs) — but this time the funding record
    // is ALREADY gone, which is the exact premise `finalize_guard_removed_utxo`
    // used to assume false.
    let mut spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 120);
    spend_tx.special_transaction_payload =
        Some(TransactionPayload::AssetLockPayloadType(AssetLockPayload::new(vec![])));
    assert_eq!(
        TransactionRouter::classify_transaction(&spend_tx),
        TransactionType::AssetLock,
        "spend must classify as AssetLock for the unattributed routing gap to bite"
    );

    // Must not panic on a record-lookup miss.
    ctx.check_transaction(&spend_tx, block_ctx(200)).await;

    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "coin correctly invalidated regardless of the record's prior pruning (α holds)"
    );
    assert_eq!(ctx.managed_wallet.balance.total(), 0, "no phantom balance");
    assert_eq!(
        history_net(&ctx.managed_wallet),
        0,
        "no live record survives to contribute to history — pruned by design, not a #649 defect"
    );

    // Reprocessing the now-fully-spent funding transaction (rescan/duplicate
    // delivery) must not resurrect the coin: `finalize_guard_removed_utxo`
    // must still call `mark_outpoint_spent` even though the record lookup
    // was a no-op, so `update_utxos`'s guard rejects the reinsertion.
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "reprocessing the funding after the pruned-record race must not resurrect the coin"
    );
    assert_eq!(ctx.managed_wallet.balance.total(), 0, "balance stays zero across reprocessing");
}
