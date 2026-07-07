//! Regression tests for the #649-restructure follow-up fix (converged QA
//! finding, Adams' RUST-001 / Smythe's SEC-02): `TransactionRecord::
//! compensate_for_observed_spends` must never re-derive `net_amount`'s base
//! from `output_details`/`input_details` sums — `account_match.received -
//! account_match.sent` is the sole authoritative source. These tests pin
//! `net_amount == account_match.received - account_match.sent` with
//! `observed_spent` EMPTY (no #649 spend involved at all), for the two cases
//! where the narrower output_details/input_details view would otherwise have
//! silently diverged from that authoritative value.

use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext, TransactionRouter};
use dashcore::blockdata::transaction::OutPoint;
use dashcore::{Address, Network, ScriptBuf, Transaction, TxIn, TxOut, Txid, Witness};
use std::collections::BTreeMap;

fn block_ctx(height: u32) -> TransactionContext {
    TransactionContext::InBlock(BlockInfo::new(
        height,
        dashcore::BlockHash::dummy(height),
        1_650_000_000 + height,
    ))
}

/// A synthetic-input transaction paying each `(address, value)` pair in
/// `targets` to its own output, in order.
fn fund_multi(targets: &[(&Address, u64)]) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from([0xABu8; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::new(),
        }],
        output: targets
            .iter()
            .map(|(addr, value)| TxOut {
                value: *value,
                script_pubkey: addr.script_pubkey(),
            })
            .collect(),
        special_transaction_payload: None,
    }
}

/// (a) An output the account owns by script (`contains_script_pub_key`
/// matches `AddressPool::script_pubkey_index`) but whose address is missing
/// from `address_index` — the same asymmetry `AddressPool::prune_unused` can
/// leave behind (forced here by direct field removal, independent of that
/// function, so this test isolates the `net_amount` fix from that separate,
/// already-tracked bug). `account_match.received` counts this output (a
/// script-keyed match, unconditional on address resolution); the
/// output-role classifier does not (it requires `get_address_info`). Before
/// the fix, `net_amount` silently dropped this output's value; it must not.
#[tokio::test]
async fn net_amount_matches_account_match_when_output_resolves_by_script_only() {
    let mut ctx = TestWalletContext::new_random();

    let desynced_address = {
        let account = ctx.managed_wallet.first_bip44_managed_account_mut().expect("account");
        let pool = account
            .managed_account_type_mut()
            .address_pools_mut()
            .into_iter()
            .next()
            .expect("external pool");
        let addr = pool.address_at_index(1).expect("pool pre-generates past index 0");
        assert!(pool.contains_address(&addr), "sanity: address_index has it before removal");
        pool.address_index.remove(&addr);
        assert!(!pool.contains_address(&addr), "address_index no longer resolves it");
        assert!(
            pool.contains_script_pubkey(&addr.script_pubkey()),
            "script_pubkey_index still matches — the constructed desync"
        );
        addr
    };

    let value0 = 500_000u64;
    let value1 = 750_000u64;
    let funding_tx = fund_multi(&[(&ctx.receive_address, value0), (&desynced_address, value1)]);

    let account = ctx.managed_wallet.first_bip44_managed_account().expect("account");
    let account_match =
        account.check_transaction_for_match(&funding_tx, Some(0)).expect("relevant via output 0");
    assert_eq!(
        account_match.received,
        value0 + value1,
        "sanity: account_match counts the script-only match too"
    );
    let expected_net = account_match.received as i64 - account_match.sent as i64;

    ctx.check_transaction(&funding_tx, block_ctx(100)).await;

    let record = ctx.transaction(&funding_tx.txid());
    assert_eq!(
        record.net_amount, expected_net,
        "net_amount must stay anchored to account_match.received - account_match.sent, not a \
         narrower output_details-driven recompute that drops the unresolved-address output"
    );
}

/// (b) `account_match.sent` can be nonzero while `input_details` ends up
/// empty — documented at `managed_core_funds_account.rs`'s own comment on a
/// partial rescan (an incomplete UTXO set). Simulated directly: capture a
/// real `account_match` for an outgoing spend while the funding UTXO is
/// still present, then clear the account's UTXO set (as a rescan gap would)
/// before `record_transaction` runs, and call it directly with the
/// now-stale — but still authoritative — `account_match`.
#[tokio::test]
async fn net_amount_matches_account_match_when_input_details_incomplete() {
    let mut ctx = TestWalletContext::new_random();
    let funding_value = 2_000_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;

    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let external = Address::dummy(Network::Testnet, 210);
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
            script_pubkey: external.script_pubkey(),
        }],
        special_transaction_payload: None,
    };

    let account = ctx.managed_wallet.first_bip44_managed_account().expect("account");
    let account_match = account
        .check_transaction_for_match(&spend_tx, Some(0))
        .expect("spend must match (spends our own UTXO)");
    assert_eq!(account_match.sent, funding_value, "sanity: sent captured while UTXO was present");
    assert_eq!(account_match.received, 0, "pure outgoing spend");

    // Simulate the partial-rescan gap: the UTXO set becomes incomplete
    // between account_match capture and record_transaction running.
    let account = ctx.managed_wallet.first_bip44_managed_account_mut().expect("account");
    account.utxos.clear();

    let tx_type = TransactionRouter::classify_transaction(&spend_tx);
    let record = account.record_transaction(
        &spend_tx,
        &account_match,
        block_ctx(101),
        tx_type,
        &BTreeMap::new(),
    );

    assert!(record.input_details.is_empty(), "sanity: input_details empty, UTXO gone");
    assert_eq!(
        record.net_amount,
        account_match.received as i64 - account_match.sent as i64,
        "net_amount must stay anchored to account_match even when input_details can't see the \
         spent UTXO (partial rescan) — must not silently become account_match.received - 0"
    );
}
