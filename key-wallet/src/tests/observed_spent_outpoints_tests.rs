//! Tests for the wallet-level observed-spent-outpoint guard
//! (dashpay/rust-dashcore#649).
//!
//! Issue #649: a spend delivered out of order (before the transaction that
//! funded the coin it spends, as happens during a scrambled rescan) left the
//! funding UTXO permanently tracked once its funding block was finally
//! processed. The fix records every outpoint observed spent in a processed
//! block into a wallet-level, classification-independent, persisted set
//! (`ManagedWalletInfo::observed_spent_outpoints`) and reconciles it against
//! both the spend side (drop the coin whichever account holds it) and the
//! funding side (drop a just-inserted output already observed spent).
//!
//! Invariants exercised here:
//! - **K-INV-649** (primary): an outpoint observed spent in a block is never
//!   present in any account's live `utxos`, in either delivery order.
//! - **K-INV-649-PERSIST**: the invalidation survives a serialize/deserialize
//!   (restart) cycle.
//! - **K-INV-649-BOUND**: set growth is bounded by the inputs of matched
//!   blocks — no dedup loss, no superlinear cost.
//! - **K-INV-649-SCOPE**: only block-confirmed contexts populate the set;
//!   mempool / InstantSend-only spends do not, and self-heal on confirmation.
//! - **K-INV-649-NOREGRESS**: in-order matched spends behave exactly as before.

use std::collections::BTreeMap;
use std::time::Instant;

use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::prelude::CoreBlockHeight;
use dashcore::Network;

use crate::account::{AccountType, StandardAccountType};
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::managed_account::ManagedCoreFundsAccount;
use crate::test_utils::{
    block_ctx, chain_locked_block_ctx, history_net, spend_to_external, utxo_tracked,
    TestWalletContext,
};
use crate::transaction_checking::{TransactionContext, TransactionRouter, TransactionType};
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::managed_wallet_info::{ManagedAccountOperations, ManagedWalletInfo};

/// Round-trip only the `observed_spent_outpoints` field through JSON (its
/// persisted, `(OutPoint, height)`-pair form) and return the reloaded map.
///
/// This helper round-trips the field alone rather than the whole wallet because
/// a full `ManagedWalletInfo` cannot serialize to JSON once its address pools
/// are populated: `AddressPool::script_pubkey_index` is a
/// `HashMap<ScriptBuf, u32>`, and `ScriptBuf` is not a valid JSON object key.
/// That pool limitation is unrelated to this field — `OutPoint` *is* a valid
/// JSON key; the field's pair-form adapter exists for format-agnosticism across
/// non-human-readable encoders (validated by
/// `observed_spent_outpoints_round_trips_through_serde` on a pool-free wallet).
/// The helper exercises that same pair encoding to model what a reload restores.
fn reload_observed_field(wallet: &ManagedWalletInfo) -> BTreeMap<OutPoint, CoreBlockHeight> {
    let pairs: Vec<(OutPoint, CoreBlockHeight)> =
        wallet.observed_spent_outpoints().iter().map(|(k, v)| (*k, *v)).collect();
    let json = serde_json::to_string(&pairs).expect("serialize field");
    serde_json::from_str::<Vec<(OutPoint, CoreBlockHeight)>>(&json)
        .expect("deserialize field")
        .into_iter()
        .collect()
}

// ── observed_spent_outpoints serde round-trip + default ──────

/// The field's `#[serde(default, with = ...)]` adapter round-trips through a
/// real full-struct JSON serialize/deserialize (on a pool-free wallet, which is
/// the only kind that can JSON-serialize) and defaults to empty when the key is
/// absent — the persistence + backward-compat contract (K-INV-649-PERSIST).
#[test]
fn observed_spent_outpoints_round_trips_through_serde() {
    let mut wallet = ManagedWalletInfo::new(Network::Testnet, [7u8; 32]);
    let outpoint = OutPoint::new(dashcore::Txid::from([0x5A; 32]), 3);
    wallet.record_observed_spends(&spend_to_external(&[outpoint], 1, 70), 1234);

    // Full-struct round-trip (pool-free wallet → JSON works).
    let json = serde_json::to_string(&wallet).expect("serialize minimal wallet");
    let restored: ManagedWalletInfo = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        restored.observed_spent_outpoints().get(&outpoint).copied(),
        Some(1234),
        "the field survives a full-struct serde round-trip"
    );

    // Backward compat: a snapshot missing the key loads to an empty set.
    let mut value: serde_json::Value = serde_json::from_str(&json).expect("to value");
    value.as_object_mut().expect("object").remove("observed_spent_outpoints");
    let stripped = serde_json::to_string(&value).expect("reserialize");
    let loaded: ManagedWalletInfo =
        serde_json::from_str(&stripped).expect("load pre-field snapshot");
    assert!(loaded.observed_spent_outpoints().is_empty(), "#[serde(default)] supplies empty set");
}

// ── reject funding after a reload of the persisted set ──

/// The spend recorded in session 1 both (a) already excludes the coin in-memory
/// before the restart and (b) still excludes it after the persisted set is
/// reloaded and the funding arrives post-restart — proving the reject depends
/// solely on the persisted `observed_spent_outpoints`, not transient state.
#[tokio::test]
async fn restored_observed_spend_rejects_funding_after_reload() {
    let mut ctx = TestWalletContext::new_random();

    let funding_value = 1_000_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 51);

    // Session 1: process the spend block first; assert the pre-restart state.
    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    assert!(
        ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "spend seen in a block must record the observed-spent outpoint"
    );
    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "coin must not be tracked pre-restart (recording actually happened)"
    );

    // Restart: wipe the in-memory set and reload it from its persisted form.
    let reloaded = reload_observed_field(&ctx.managed_wallet);
    ctx.managed_wallet.observed_spent_outpoints.clear();
    ctx.managed_wallet.observed_spent_outpoints = reloaded;
    assert!(
        ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "persisted set restores the recorded spend"
    );

    // Session 2: the funding block finally arrives.
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "BUG #649: funding coin resurrected after restart despite reloaded spend record"
    );
}

// ── normal order unaffected, no double removal ───────────────────────

/// In-order funding-then-spend: the coin is inserted then removed exactly once
/// via the existing `update_utxos` path, the spend record still attributes the
/// input value (recording is insert-only, so `input_details` survive), and the
/// new seam adds no second monitor-revision bump (K-INV-649-NOREGRESS).
#[tokio::test]
async fn in_order_spend_records_observed_outpoint_without_double_removal() {
    let mut ctx = TestWalletContext::new_random();

    let funding_value = 5_000_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);

    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    let account = ctx.managed_wallet.first_bip44_managed_account().expect("account");
    assert!(account.utxos.contains_key(&funding_outpoint), "funding coin inserted in order");
    let rev_after_funding = account.monitor_revision();

    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 52);
    ctx.check_transaction(&spend_tx, block_ctx(101)).await;

    let account = ctx.managed_wallet.first_bip44_managed_account().expect("account");
    assert!(account.utxos.is_empty(), "spent coin removed");
    assert_eq!(
        account.monitor_revision(),
        rev_after_funding + 1,
        "the spend must bump the monitor revision exactly once — no double removal"
    );
    assert_eq!(ctx.managed_wallet.balance.total(), 0, "no phantom balance after the spend");
    assert!(
        ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "the input is recorded even on the in-order (matched) path"
    );
    // The record still carries the spent input's value: recording is insert-only
    // and never removes the coin before `record_transaction` reads it.
    let record = account.transactions().get(&spend_tx.txid()).expect("spend recorded");
    assert_eq!(record.net_amount, -(funding_value as i64), "input value attributed to the spend");
    assert_eq!(record.input_details.len(), 1, "input_details preserved by insert-only recording");
}

// ── multi-input spend, partial ownership ─────────────────────────────

/// A single spend consuming two owned outpoints (A, B) and one the wallet never
/// tracks (C), delivered before any funding: every input is recorded (set grows
/// by exactly 3), processing never panics on the unowned C, and neither A nor B
/// resurfaces once their funding blocks arrive.
#[tokio::test]
async fn multi_input_spend_records_each_input_including_unowned() {
    let mut ctx = TestWalletContext::new_random();

    let fund_a = Transaction::dummy(&ctx.receive_address, 0..1, &[700_000]);
    let fund_b = Transaction::dummy(&ctx.receive_address, 1..2, &[800_000]);
    let outpoint_a = OutPoint::new(fund_a.txid(), 0);
    let outpoint_b = OutPoint::new(fund_b.txid(), 0);
    // C belongs to nobody the wallet tracks.
    let outpoint_c = OutPoint::new(dashcore::Txid::from([0xCC; 32]), 7);

    let spend = spend_to_external(&[outpoint_a, outpoint_b, outpoint_c], 1_400_000, 53);
    let before = ctx.managed_wallet.observed_spent_outpoints().len();
    ctx.check_transaction(&spend, block_ctx(300)).await; // must not panic on C
    let after = ctx.managed_wallet.observed_spent_outpoints().len();
    assert_eq!(after - before, 3, "one observed-spent entry per input, not conflated per-tx");
    for op in [outpoint_a, outpoint_b, outpoint_c] {
        assert!(ctx.managed_wallet.observed_spent_outpoints().contains_key(&op));
    }

    // Funding for A then B arrives out of order — neither may become live.
    ctx.check_transaction(&fund_a, block_ctx(200)).await;
    ctx.check_transaction(&fund_b, block_ctx(201)).await;
    assert!(!utxo_tracked(&ctx.managed_wallet, &outpoint_a), "A must not resurface");
    assert!(!utxo_tracked(&ctx.managed_wallet, &outpoint_b), "B must not resurface");
}

// ── irrelevant-block noise, bounded growth ───────────────────────────

/// Interleaving many unrelated multi-input spends with the wallet's own
/// funding/spend pair yields the same final wallet state as the pair alone, and
/// grows the set by exactly the total input count observed — never the whole
/// chain (K-INV-649-BOUND).
#[tokio::test]
async fn irrelevant_block_noise_grows_set_by_total_inputs_only() {
    let mut ctx = TestWalletContext::new_random();

    let funding_value = 2_000_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 54);

    let mut expected_inputs = 0usize;
    // 50 unrelated 2-input spends touching nothing of ours.
    for i in 0..50u32 {
        let a = OutPoint::new(dashcore::Txid::from([(i as u8).wrapping_add(1); 32]), 0);
        let b = OutPoint::new(dashcore::Txid::from([(i as u8).wrapping_add(1); 32]), 1);
        let noise = spend_to_external(&[a, b], 10_000, 100 + i as usize);
        expected_inputs += 2;
        ctx.check_transaction(&noise, block_ctx(400 + i)).await;
    }

    ctx.check_transaction(&funding_tx, block_ctx(500)).await;
    expected_inputs += 1; // funding's own synthetic input
    ctx.check_transaction(&spend_tx, block_ctx(501)).await;
    expected_inputs += 1; // the spend's input (= funding_outpoint)

    assert_eq!(
        ctx.managed_wallet.observed_spent_outpoints().len(),
        expected_inputs,
        "set size equals total observed inputs — bounded to block activity, not chain history"
    );
    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "the real funding/spend pair still resolves correctly amid the noise"
    );
    assert_eq!(ctx.managed_wallet.balance.total(), 0);
}

// ── backward-compatible load of a pre-fix snapshot ───────────────────

/// A wallet loaded from a pre-fix snapshot (empty `observed_spent_outpoints`, as
/// `#[serde(default)]` supplies) protects newly observed out-of-order spends, and
/// is explicitly NOT retroactively corrected for spends it processed incorrectly
/// before the fix existed — the empty loaded set means no magic backfill.
#[tokio::test]
async fn pre_fix_snapshot_without_field_loads_and_protects_new_spends() {
    let mut ctx = TestWalletContext::new_random();
    // A pre-fix load presents an empty set (the #[serde(default)] result, checked
    // directly in `observed_spent_outpoints_round_trips_through_serde`).
    assert!(
        ctx.managed_wallet.observed_spent_outpoints().is_empty(),
        "no historical record is fabricated for a pre-fix wallet"
    );

    // A new out-of-order spend observed post-load IS protected.
    let funding_value = 3_000_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 55);

    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "post-load out-of-order spend is protected"
    );
}

// ── unbounded-growth stress, bounded and roughly linear ──────────────

/// Many filter-matched blocks of orphaned spends (funding never arrives) do not
/// panic, keep exactly one entry per observed input (no dedup loss), and do not
/// exhibit superlinear per-block cost as the set grows (K-INV-649-BOUND, §5.5).
#[tokio::test]
async fn many_orphaned_spend_blocks_stay_bounded_and_linear() {
    let mut ctx = TestWalletContext::new_random();

    const CHUNKS: u32 = 4;
    const PER_CHUNK: u32 = 500;
    const INPUTS_PER_TX: usize = 3;
    let mut durations = Vec::new();

    for chunk in 0..CHUNKS {
        let start = Instant::now();
        for i in 0..PER_CHUNK {
            let n = chunk * PER_CHUNK + i;
            // Distinct, never-owned outpoints per tx (unique txid seed per block).
            let seed = n.to_le_bytes();
            let inputs: Vec<OutPoint> = (0..INPUTS_PER_TX as u32)
                .map(|v| {
                    let mut b = [0u8; 32];
                    b[..4].copy_from_slice(&seed);
                    b[4] = v as u8;
                    OutPoint::new(dashcore::Txid::from(b), v)
                })
                .collect();
            let tx = spend_to_external(&inputs, 1_000, 200 + (n as usize % 40));
            ctx.check_transaction(&tx, block_ctx(1_000 + n)).await;
        }
        durations.push(start.elapsed());
    }

    let total = (CHUNKS * PER_CHUNK) as usize * INPUTS_PER_TX;
    assert_eq!(
        ctx.managed_wallet.observed_spent_outpoints().len(),
        total,
        "exactly one entry per observed input — no silent dedup or loss"
    );
    // Superlinear (O(n^2)) growth would make the last chunk dramatically slower
    // than the first. Reported as a diagnostic rather than asserted: wall-clock
    // ratios flake on shared CI runners, and correctness is already pinned by
    // the exact-entry-count assertion above.
    let first = durations.first().copied().unwrap().as_secs_f64().max(1e-4);
    let last = durations.last().copied().unwrap().as_secs_f64();
    eprintln!(
        "per-chunk cost: first={first:.4}s last={last:.4}s (ratio {:.1}x, flat expected)",
        last / first
    );
}

// ── same outpoint spent in two blocks, last-write-wins ───────────────

/// Recording the same outpoint from two different-height blocks keeps a single
/// entry at the last-inserted height (`BTreeMap::insert` overwrite semantics) —
/// pinned so a future height-keyed pruning policy can rely on it.
#[tokio::test]
async fn same_outpoint_spent_in_two_blocks_keeps_last_height() {
    let ctx = TestWalletContext::new_random();
    let mut wallet = ctx.managed_wallet;

    let outpoint = OutPoint::new(dashcore::Txid::from([0xA1; 32]), 0);
    let spend = spend_to_external(&[outpoint], 9_000, 60);

    wallet.record_observed_spends(&spend, 111);
    wallet.record_observed_spends(&spend, 222);

    assert_eq!(wallet.observed_spent_outpoints().len(), 1, "single entry, not a multimap");
    assert_eq!(
        wallet.observed_spent_outpoints().get(&outpoint).copied(),
        Some(222),
        "last write wins on height"
    );
}

// ── last_processed_height alone does not prune ───────────────────────

/// Pruning is gated only on the finality boundary (chainlock + synced_height),
/// not on `last_processed_height` (#649): however far `last_processed_height`
/// advances past the observed spend, with no chainlock the entry is retained and
/// the funding coin is still rejected when it finally arrives.
#[tokio::test]
async fn orphaned_spend_not_pruned_by_last_processed_height() {
    let mut ctx = TestWalletContext::new_random();

    let funding_value = 4_000_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 61);

    ctx.check_transaction(&spend_tx, block_ctx(50)).await;
    // Advance far past any plausible pruning horizon.
    ctx.managed_wallet.update_last_processed_height(1_000_050);

    ctx.check_transaction(&funding_tx, block_ctx(60)).await;
    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "no TTL/expiry: the observed spend still invalidates the funding a million blocks later"
    );
    assert!(ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint));
}

// ── cross-account-type routing gap ───────────────────────────────────

/// A CoinJoin-owned coin spent by an AssetLock-classified transaction (whose
/// `relevant_types` exclude CoinJoin) must still be invalidated when its funding
/// arrives later — recording and reconciliation are independent of the spending
/// transaction's classification (the cross-account-type routing gap).
#[tokio::test]
async fn coinjoin_utxo_spent_by_asset_lock_classified_tx_still_invalidated() {
    let mut ctx = TestWalletContext::new_random();

    // Derive a CoinJoin address (Default account options create the account).
    // CoinJoin accounts are spend-only for the Standard receive/change paths, so
    // their addresses come from the generic `next_address` pool accessor.
    let cj_xpub = ctx.wallet.get_coinjoin_account(0).expect("coinjoin account").account_xpub;
    let cj_address = ctx
        .managed_wallet
        .first_coinjoin_managed_account_mut()
        .expect("managed coinjoin account")
        .next_address(Some(&cj_xpub), true)
        .expect("coinjoin address");

    let funding_value = 1_500_000u64;
    let funding_tx = Transaction::dummy(&cj_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);

    // The spend classifies as AssetLock via its special payload, which narrows
    // relevant account types to exclude CoinJoin.
    let mut spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 62);
    spend_tx.special_transaction_payload =
        Some(TransactionPayload::AssetLockPayloadType(AssetLockPayload::new(vec![])));
    assert_eq!(
        TransactionRouter::classify_transaction(&spend_tx),
        TransactionType::AssetLock,
        "spend must classify as AssetLock for this scenario to bite",
    );

    // Spend block processed before the CoinJoin funding block.
    ctx.check_transaction(&spend_tx, block_ctx(700)).await;
    assert!(
        ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "recording must be un-gated by the spend's AssetLock classification"
    );

    ctx.check_transaction(&funding_tx, block_ctx(600)).await;
    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "BUG #649: CoinJoin coin resurrected because the spend routed away from CoinJoin"
    );
}

// ── dual bookkeeping consistency ─────────────────────────────────────

/// An in-order matched spend populates both the per-account derived
/// `spent_outpoints` (via the existing `update_utxos` path — proven behaviorally
/// by a re-processed funding staying rejected) and the wallet-level
/// `observed_spent_outpoints`, with no double-decrement or double bump.
#[tokio::test]
async fn in_order_spend_populates_both_peraccount_and_wallet_sets() {
    let mut ctx = TestWalletContext::new_random();

    let funding_value = 6_000_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    let rev_after_funding =
        ctx.managed_wallet.first_bip44_managed_account().expect("account").monitor_revision();

    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 63);
    ctx.check_transaction(&spend_tx, block_ctx(101)).await;

    // Wallet-level set: directly observable.
    assert!(ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint));
    let account = ctx.managed_wallet.first_bip44_managed_account().expect("account");
    assert!(account.utxos.is_empty());
    assert_eq!(account.monitor_revision(), rev_after_funding + 1, "exactly one bump for the spend");
    assert_eq!(ctx.managed_wallet.balance.total(), 0, "no double-decrement");

    // Per-account derived set: proven behaviorally — re-processing the funding
    // (as a rescan would) must not re-insert the coin.
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "re-processed funding stays rejected — both guards agree"
    );
}

// ── account created after the spend was observed ─────────────────────

/// The wallet-level (not per-account) placement of the set means a spend
/// observed while an owning account does not yet exist still invalidates the
/// funding once that account is added and its funding block is processed.
#[tokio::test]
async fn account_created_after_spend_observed_still_rejects_funding() {
    let mut ctx = TestWalletContext::new_random();

    // Build account 1 and its first receive address off to the side (in the
    // wallet + a detached managed account), so we can construct the funding tx
    // that pays it — but do NOT put the managed account into the collection yet.
    // At spend-observation time the managed wallet still only knows account 0.
    ctx.wallet
        .add_account(
            AccountType::Standard {
                index: 1,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            None,
        )
        .expect("add account 1");
    let acct1 = ctx.wallet.get_bip44_account(1).expect("account 1");
    let xpub1 = acct1.account_xpub;
    let mut managed_acct1 = ManagedCoreFundsAccount::from_account(acct1);
    let addr1 = managed_acct1.next_receive_address(Some(&xpub1), true).expect("addr1");

    let funding_value = 2_500_000u64;
    let funding_tx = Transaction::dummy(&addr1, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 64);

    // Observe the spend while account 1 is NOT yet in the managed collection.
    ctx.check_transaction(&spend_tx, block_ctx(800)).await;
    assert!(ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint));

    // Now the managed account 1 appears (gap-limit/lazy discovery).
    ctx.managed_wallet
        .accounts
        .insert_funds_bearing_account(managed_acct1)
        .expect("insert managed account 1");

    // Its funding block is processed — the coin must not become live.
    ctx.check_transaction(&funding_tx, block_ctx(700)).await;
    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "wallet-level recording protects an account that did not exist at spend time"
    );
}

// ── mempool / InstantSend spends excluded, self-heal on block ────────

/// Mempool- and InstantSend-only spends do not populate the set (K-INV-649-SCOPE)
/// — so the coin is momentarily spendable — and the state self-heals when the
/// same spend is later seen in a block.
#[tokio::test]
async fn mempool_and_instantsend_spends_not_recorded_but_self_heal_on_block() {
    for non_block_ctx in
        [TransactionContext::Mempool, TransactionContext::InstantSend(InstantLock::default())]
    {
        let mut ctx = TestWalletContext::new_random();

        let funding_value = 1_200_000u64;
        let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
        let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
        let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 65);

        // Spend seen only via a non-block context: NOT recorded.
        ctx.check_transaction(&spend_tx, non_block_ctx.clone()).await;
        assert!(
            ctx.managed_wallet.observed_spent_outpoints().is_empty(),
            "non-block spend must not populate the observed-spent set: {non_block_ctx}"
        );

        // Funding arrives: the coin is (correctly, per current scope) spendable.
        ctx.check_transaction(&funding_tx, block_ctx(100)).await;
        assert!(
            utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
            "transient window: coin is spendable until the spend confirms in a block"
        );

        // The same spend is later mined: now it records and self-heals.
        ctx.check_transaction(&spend_tx, block_ctx(200)).await;
        assert!(
            ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
            "block confirmation records the spend"
        );
        assert!(
            !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
            "self-healed: the coin is dropped on the block-confirmed spend"
        );
    }
}

// ── idempotent re-processing of the same spend block ─────────────────

/// Re-delivering the identical spend block (rescan overlap / retry) is
/// idempotent: one entry for the outpoint, no extra monitor bump, and the
/// funding is still rejected afterward.
#[tokio::test]
async fn duplicate_spend_block_is_idempotent() {
    let mut ctx = TestWalletContext::new_random();

    let funding_value = 1_800_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 66);

    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    let len_after_first = ctx.managed_wallet.observed_spent_outpoints().len();
    let rev_after_first =
        ctx.managed_wallet.first_bip44_managed_account().expect("account").monitor_revision();

    // Byte-identical re-delivery at the same height.
    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    assert_eq!(
        ctx.managed_wallet.observed_spent_outpoints().len(),
        len_after_first,
        "duplicate delivery keeps a single entry (BTreeMap keyed by OutPoint)"
    );
    assert_eq!(
        ctx.managed_wallet.first_bip44_managed_account().expect("account").monitor_revision(),
        rev_after_first,
        "nothing changed on re-delivery: no extra monitor-revision bump"
    );

    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    assert!(!utxo_tracked(&ctx.managed_wallet, &funding_outpoint), "funding still rejected");
}

// ── pre-fix load composed with an in-flight out-of-order spend ───────

/// The real cold-rescan shape: a wallet that started from a pre-fix snapshot
/// (empty observed set) runs the whole out-of-order sequence in the same
/// session. Outcome must match a fresh wallet — no latent state alters the fix.
#[tokio::test]
async fn pre_fix_snapshot_then_out_of_order_matches_fresh_wallet() {
    let mut ctx = TestWalletContext::new_random();
    // Model the loaded old snapshot: the observed set starts empty.
    assert!(ctx.managed_wallet.observed_spent_outpoints().is_empty());

    let funding_value = 3_300_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 67);

    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;

    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "old-format load + out-of-order delivery behaves identically to a fresh wallet"
    );
    assert_eq!(ctx.managed_wallet.balance.total(), 0);
}

// ── bounded permanence: removal only at the finality boundary ────────

/// Pins the bounded-permanence invariant (#649): an observed spend is removed
/// ONLY at or below the finality boundary `min(chainlock, synced_height)`, and
/// only through [`ManagedWalletInfo::prune_finalized_observed_spends`]. No
/// contributor may add another removal path — reorg/rollback, age, or recency —
/// without a deliberate decision, since that would reintroduce #649.
#[tokio::test]
async fn observed_spend_removal_only_via_finality_boundary() {
    let mut ctx = TestWalletContext::new_random();

    let funding_value = 2_100_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 68);

    // Observe the spend in a block at height 200.
    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    assert!(ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint));

    // A context flip to Mempool must NOT retract the entry (no reorg/rollback path).
    ctx.check_transaction(&spend_tx, TransactionContext::Mempool).await;
    assert!(
        ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "no reorg/rollback removal path: a context flip to Mempool does not retract the entry"
    );

    // Advancing synced_height alone, with no chainlock, must NOT prune: without
    // a chainlock there is no finality boundary.
    ctx.managed_wallet.update_synced_height(1_000_000);
    assert!(
        ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "synced_height without a chainlock defines no boundary, so nothing is pruned"
    );

    // A chainlock BELOW the entry height must NOT prune it (boundary 199 < 200).
    ctx.managed_wallet.update_last_processed_height(1_000_000);
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(199));
    assert!(
        ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "a chainlock below the spend height leaves the entry (height 200 > boundary 199)"
    );

    // Only a chainlock at/above the entry height (with synced_height past it)
    // removes it — exactly at the finality boundary and nowhere else.
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(200));
    assert!(
        !ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "removal happens exactly at the finality boundary min(chainlock, synced_height)"
    );

    // Adding an account invalidates the sync certificate (the boundary input):
    // a freshly observed spend is not removed until the checkpoint re-advances
    // past it, even though the chainlock is already well ahead.
    ctx.managed_wallet.metadata.birth_height = 100;
    let op2 = OutPoint::new(dashcore::Txid::from([0x7C; 32]), 0);
    ctx.managed_wallet.record_observed_spends(&spend_to_external(&[op2], 1, 69), 150);
    ctx.wallet
        .add_account(
            AccountType::Standard {
                index: 1,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            None,
        )
        .expect("add wallet account 1");
    ctx.managed_wallet
        .add_managed_account(
            &ctx.wallet,
            AccountType::Standard {
                index: 1,
                standard_account_type: StandardAccountType::BIP44Account,
            },
        )
        .expect("add managed account 1");
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(300));
    assert!(
        ctx.managed_wallet.observed_spent_outpoints().contains_key(&op2),
        "after an account addition, no removal occurs until the checkpoint re-advances past it"
    );

    // Re-advancing the checkpoint re-certifies coverage and the entry prunes.
    ctx.managed_wallet.update_synced_height(300);
    assert!(
        !ctx.managed_wallet.observed_spent_outpoints().contains_key(&op2),
        "entry prunable again once synced_height re-advances past it"
    );
}

// ── history/balance consistency — no phantom "received" after a guarded spend ──

/// Documents the #649-restructure architectural finding: `history_net ==
/// balance.total()` is NOT a system invariant under default features
/// (`keep-finalized-transactions = OFF`) — it never holds for ANY
/// chainlocked-and-pruned funding, #649 or not. `transaction_history()`
/// returns only live records; a funding record whose first sighting is
/// already chainlocked (as in a full historical rescan) is dropped to
/// `finalized_txids` immediately, while its coin stays live in `balance`.
/// No spend, no #649 guard, no compensation involved — pinned here so this
/// divergence is recognized as by-design, not a regression (#649).
#[cfg(not(feature = "keep-finalized-transactions"))]
#[tokio::test]
async fn plain_chainlocked_funding_diverges_history_from_balance_by_design() {
    let mut ctx = TestWalletContext::new_random();

    let funding_value = 900_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);

    ctx.check_transaction(&funding_tx, chain_locked_block_ctx(50)).await;

    assert!(utxo_tracked(&ctx.managed_wallet, &funding_outpoint), "coin is live");
    assert_eq!(
        ctx.managed_wallet.balance.total(),
        funding_value,
        "balance correctly reflects the live coin"
    );
    assert_eq!(
        history_net(&ctx.managed_wallet),
        0,
        "the record was pruned to finalized_txids on first sighting, so history omits it \
         entirely — NOT a #649 regression, this holds for any chainlocked-and-pruned funding"
    );
    assert_ne!(
        history_net(&ctx.managed_wallet),
        ctx.managed_wallet.balance.total() as i64,
        "documents: history_net == balance.total() is not a system invariant under default \
         features for finalized (pruned) records"
    );
}

/// Mirror of the above under `keep-finalized-transactions`: with the feature
/// on, the record is never pruned, so β (`history_net == balance.total()`)
/// DOES hold — confirming the divergence above is purely a consequence of
/// pruning, not of anything #649-specific.
#[cfg(feature = "keep-finalized-transactions")]
#[tokio::test]
async fn plain_chainlocked_funding_matches_balance_when_records_are_kept() {
    let mut ctx = TestWalletContext::new_random();

    let funding_value = 900_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);

    ctx.check_transaction(&funding_tx, chain_locked_block_ctx(50)).await;

    assert!(utxo_tracked(&ctx.managed_wallet, &funding_outpoint), "coin is live");
    assert_eq!(
        history_net(&ctx.managed_wallet),
        ctx.managed_wallet.balance.total() as i64,
        "with keep-finalized-transactions on, the record is never pruned, so history net \
         matches balance even for a chainlocked-first-sighting funding"
    );
}

/// Spend-first ordering: when the funding block arrives after its spend was
/// observed, the funding UTXO is reconciled away — and the funding transaction's
/// "received" history record must be compensated so `transaction_history()`'s
/// net equals `balance.total()`. Without the fix the record shows "+funding"
/// against a zero balance with no transaction explaining where it went.
#[tokio::test]
async fn transaction_history_net_matches_balance_after_spend_before_funding() {
    let mut ctx = TestWalletContext::new_random();

    let funding_value = 1_000_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 90);

    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;

    assert!(!utxo_tracked(&ctx.managed_wallet, &funding_outpoint), "coin invalidated");
    assert_eq!(ctx.managed_wallet.balance.total(), 0, "no phantom balance");
    assert_eq!(history_net(&ctx.managed_wallet), 0, "no phantom 'received' in history");
    assert_eq!(
        history_net(&ctx.managed_wallet),
        ctx.managed_wallet.balance.total() as i64,
        "transaction_history net must equal balance",
    );
    // The fully-compensated funding record is KEPT at net 0 (not deleted), so a
    // later reprocessing takes the already-known path instead of re-recording a
    // positive net. Net 0 keeps history consistent with the zero balance.
    let records = ctx.managed_wallet.transaction_history();
    assert_eq!(records.len(), 1, "the funding record is kept, fully compensated");
    assert_eq!(records[0].net_amount, 0, "kept record sits at net 0");
    assert!(records[0].output_details.is_empty(), "its received output is compensated away");
}

/// Funding-first mirror: a coin funded and recorded, then spent by a transaction
/// whose classification excludes the owning account (AssetLock spend of a
/// CoinJoin coin), is removed via the un-gated spend path. Its funding record
/// must likewise be compensated so history net stays equal to balance.
#[tokio::test]
async fn transaction_history_net_matches_balance_after_unattributed_spend() {
    let mut ctx = TestWalletContext::new_random();

    let cj_xpub = ctx.wallet.get_coinjoin_account(0).expect("coinjoin account").account_xpub;
    let cj_address = ctx
        .managed_wallet
        .first_coinjoin_managed_account_mut()
        .expect("managed coinjoin account")
        .next_address(Some(&cj_xpub), true)
        .expect("coinjoin address");

    let funding_value = 1_500_000u64;
    let funding_tx = Transaction::dummy(&cj_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);

    // Funding first: recorded and tracked on the CoinJoin account.
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    assert!(utxo_tracked(&ctx.managed_wallet, &funding_outpoint));
    assert_eq!(history_net(&ctx.managed_wallet), funding_value as i64);

    // Spend classified as AssetLock — excludes CoinJoin from relevant types, so
    // it is unattributed and removed by the un-gated spend path.
    let mut spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 91);
    spend_tx.special_transaction_payload =
        Some(TransactionPayload::AssetLockPayloadType(AssetLockPayload::new(vec![])));
    assert_eq!(TransactionRouter::classify_transaction(&spend_tx), TransactionType::AssetLock);
    ctx.check_transaction(&spend_tx, block_ctx(200)).await;

    assert!(!utxo_tracked(&ctx.managed_wallet, &funding_outpoint), "coin invalidated");
    assert_eq!(ctx.managed_wallet.balance.total(), 0, "no phantom balance");
    assert_eq!(
        history_net(&ctx.managed_wallet),
        ctx.managed_wallet.balance.total() as i64,
        "transaction_history net must equal balance after an unattributed spend",
    );
}

// ── reconciliation is intentionally NOT gated to block context ────────────────

/// Recording is restricted to block contexts, but reconciliation is not: the
/// observed-spent set only ever holds block-confirmed spends, so a coin present
/// in it is genuinely spent on-chain and must be dropped even when its funding
/// is (re)delivered via mempool. This pins that intentional asymmetry.
#[tokio::test]
async fn mempool_funding_is_reconciled_against_block_observed_spend() {
    let mut ctx = TestWalletContext::new_random();

    let funding_value = 1_100_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 92);

    // The spend is seen in a block first (records the observed spend).
    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    assert!(ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint));

    // The funding is then delivered via mempool (unconfirmed) — it must still be
    // reconciled away, because the spend it collides with was block-confirmed.
    ctx.check_transaction(&funding_tx, TransactionContext::Mempool).await;
    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "a mempool funding must not resurrect a coin whose spend was seen in a block"
    );
    assert_eq!(ctx.managed_wallet.balance.total(), 0);
    assert_eq!(history_net(&ctx.managed_wallet), 0, "history stays consistent for mempool funding");
}

// ── serde adapter streams many entries (defensive-cap path) ───────────

/// The capped, streaming deserialize visitor round-trips many entries correctly
/// (well under the defensive cap). Exercises the visitor beyond the trivial
/// single-entry case; the multi-hundred-MB cap boundary itself is not asserted
/// here as constructing >10M entries is impractical for a unit test.
#[test]
fn observed_spent_outpoints_serde_streams_many_entries() {
    let mut wallet = ManagedWalletInfo::new(Network::Testnet, [9u8; 32]);
    for i in 0..3_000u32 {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&i.to_le_bytes());
        let op = OutPoint::new(dashcore::Txid::from(bytes), i % 4);
        wallet.record_observed_spends(&spend_to_external(&[op], 1, 70), 1_000 + i);
    }
    assert_eq!(wallet.observed_spent_outpoints().len(), 3_000);

    let json = serde_json::to_string(&wallet).expect("serialize");
    let restored: ManagedWalletInfo = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        restored.observed_spent_outpoints(),
        wallet.observed_spent_outpoints(),
        "the streaming adapter round-trips every entry with no loss or reordering"
    );
}

// ── multi-output partial compensation: idempotency + output_details sync ──────

/// A funding tx with two of our outputs where only one is observed-spent, then
/// reprocessed (guaranteed by rescan/duplicate-block delivery). The guard must
/// be idempotent: reprocessing must not compensate the removed output a second
/// time and drive `net_amount` negative.
#[tokio::test]
async fn reprocessing_partially_compensated_funding_does_not_double_compensate() {
    let mut ctx = TestWalletContext::new_random();

    let out0_value = 2_000_000u64;
    let out1_value = 500_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[out0_value, out1_value]);
    let funding_txid = funding_tx.txid();
    let out0 = OutPoint::new(funding_txid, 0);
    let out1 = OutPoint::new(funding_txid, 1);
    let spend_tx = spend_to_external(&[out0], out0_value - 1_000, 93);

    // Spend of out0 observed first, then the funding, then the funding AGAIN.
    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    ctx.check_transaction(&funding_tx, block_ctx(100)).await; // rescan/duplicate delivery

    // out1 survives; out0 stays invalidated.
    assert!(utxo_tracked(&ctx.managed_wallet, &out1), "surviving output stays tracked");
    assert!(!utxo_tracked(&ctx.managed_wallet, &out0), "observed-spent output stays invalidated");
    assert_eq!(ctx.managed_wallet.balance.total(), out1_value, "balance is the surviving output");

    let account = ctx.managed_wallet.first_bip44_managed_account().expect("account");
    let record = account.transactions().get(&funding_txid).expect("funding record");
    assert_eq!(
        record.net_amount, out1_value as i64,
        "net_amount reflects only the surviving output — not compensated twice",
    );
    assert_eq!(
        history_net(&ctx.managed_wallet),
        ctx.managed_wallet.balance.total() as i64,
        "history net stays equal to balance across reprocessing",
    );
}

/// Single pass, multi-output partial compensation: the removed output's
/// `output_details` entry must be dropped so per-output line items agree with
/// the compensated `net_amount`.
#[tokio::test]
async fn partial_compensation_updates_output_details() {
    let mut ctx = TestWalletContext::new_random();

    let out0_value = 2_000_000u64;
    let out1_value = 500_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[out0_value, out1_value]);
    let funding_txid = funding_tx.txid();
    let out0 = OutPoint::new(funding_txid, 0);
    let spend_tx = spend_to_external(&[out0], out0_value - 1_000, 94);

    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;

    let account = ctx.managed_wallet.first_bip44_managed_account().expect("account");
    let record = account.transactions().get(&funding_txid).expect("funding record");

    assert_eq!(record.net_amount, out1_value as i64, "net_amount reflects surviving output");
    assert!(
        !record.output_details.iter().any(|d| d.index == 0),
        "the removed output must not remain in output_details as a phantom received entry",
    );
    let received_sum: u64 = record.output_details.iter().map(|d| d.value).sum();
    assert_eq!(
        received_sum, out1_value,
        "sum of surviving output_details values equals the compensated net_amount",
    );
}

/// A fully-spent-before-seen funding tx (single output, all of it observed
/// spent) is reprocessed. The fully-compensated record is kept at net 0 rather
/// than dropped, so the reprocess takes the `is_new == false` path and does not
/// re-record a positive net with no coin to reconcile it against.
#[tokio::test]
async fn reprocessing_fully_compensated_funding_stays_consistent() {
    let mut ctx = TestWalletContext::new_random();
    let value = 2_000_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[value]);
    let funding_txid = funding_tx.txid();
    let out0 = OutPoint::new(funding_txid, 0);
    let spend_tx = spend_to_external(&[out0], value - 1_000, 95);

    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    ctx.check_transaction(&funding_tx, block_ctx(100)).await; // reprocess

    assert!(!utxo_tracked(&ctx.managed_wallet, &out0), "coin stays invalidated");
    assert_eq!(ctx.managed_wallet.balance.total(), 0);
    assert_eq!(
        history_net(&ctx.managed_wallet),
        0,
        "history net stays equal to balance across reprocessing"
    );
    // The record is kept, fully compensated to net 0, with no surviving output.
    let account = ctx.managed_wallet.first_bip44_managed_account().expect("account");
    let record = account.transactions().get(&funding_txid).expect("record kept");
    assert_eq!(record.net_amount, 0, "fully-compensated record sits at net 0");
    assert!(record.output_details.is_empty(), "no surviving received output remains");
}

// ── deeper idempotency / persistence stress ────────────────────────────────
//
// Pins the compensation guard across harder cases (#649): repeated
// reprocessing beyond a single retry, a multi-output tx where every output is
// eventually observed spent, and the cross-serialize/deserialize boundary.

/// Idempotency must hold for an unbounded number of replays, not just one
/// extra retry. Reprocess the funding tx a 2nd, 3rd, AND 4th time and assert
/// `net_amount`/balance are stable after every single pass, not just at the
/// end.
#[tokio::test]
async fn reprocessing_partially_compensated_funding_stays_idempotent_across_many_replays() {
    let mut ctx = TestWalletContext::new_random();

    let out0_value = 2_000_000u64;
    let out1_value = 500_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[out0_value, out1_value]);
    let funding_txid = funding_tx.txid();
    let out0 = OutPoint::new(funding_txid, 0);
    let out1 = OutPoint::new(funding_txid, 1);
    let spend_tx = spend_to_external(&[out0], out0_value - 1_000, 96);

    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;

    for replay in 1..=4 {
        ctx.check_transaction(&funding_tx, block_ctx(100)).await;

        assert!(utxo_tracked(&ctx.managed_wallet, &out1), "replay {replay}: out1 stays tracked");
        assert!(
            !utxo_tracked(&ctx.managed_wallet, &out0),
            "replay {replay}: out0 stays invalidated"
        );
        assert_eq!(
            ctx.managed_wallet.balance.total(),
            out1_value,
            "replay {replay}: balance unaffected"
        );
        let account = ctx.managed_wallet.first_bip44_managed_account().expect("account");
        let record = account.transactions().get(&funding_txid).expect("funding record");
        assert_eq!(
            record.net_amount, out1_value as i64,
            "replay {replay}: net_amount must not drift with repeated replay"
        );
        assert_eq!(
            history_net(&ctx.managed_wallet),
            ctx.managed_wallet.balance.total() as i64,
            "replay {replay}: history net stays equal to balance"
        );
    }
}

/// A multi-output funding tx where BOTH outputs are independently observed
/// spent (by two separate spending transactions, not one) before the funding
/// is processed. The record must reach net 0 in a single pass and stay
/// consistent — not just the single-output-fully-spent case, and not just
/// the single-output-partially-spent case already covered.
#[tokio::test]
async fn all_outputs_independently_observed_spent_reaches_net_zero_and_stays_consistent() {
    let mut ctx = TestWalletContext::new_random();

    let out0_value = 2_000_000u64;
    let out1_value = 500_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[out0_value, out1_value]);
    let funding_txid = funding_tx.txid();
    let out0 = OutPoint::new(funding_txid, 0);
    let out1 = OutPoint::new(funding_txid, 1);
    let spend_tx0 = spend_to_external(&[out0], out0_value - 1_000, 97);
    let spend_tx1 = spend_to_external(&[out1], out1_value - 1_000, 98);

    // Both spends observed, independently, before the funding tx is seen.
    ctx.check_transaction(&spend_tx0, block_ctx(200)).await;
    ctx.check_transaction(&spend_tx1, block_ctx(201)).await;
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;

    assert!(!utxo_tracked(&ctx.managed_wallet, &out0), "out0 invalidated");
    assert!(!utxo_tracked(&ctx.managed_wallet, &out1), "out1 invalidated");
    assert_eq!(ctx.managed_wallet.balance.total(), 0, "no surviving output");

    let account = ctx.managed_wallet.first_bip44_managed_account().expect("account");
    let record = account.transactions().get(&funding_txid).expect("record kept");
    assert_eq!(record.net_amount, 0, "both outputs compensated in one pass reaches net 0");
    assert!(record.output_details.is_empty(), "both output_details entries are gone");
    assert_eq!(history_net(&ctx.managed_wallet), 0, "history net stays equal to the zero balance");

    // Reprocess: must stay at net 0, not go negative.
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    let account = ctx.managed_wallet.first_bip44_managed_account().expect("account");
    let record = account.transactions().get(&funding_txid).expect("record kept");
    assert_eq!(record.net_amount, 0, "reprocess after both-outputs-spent stays at net 0");
    assert_eq!(ctx.managed_wallet.balance.total(), 0);
}

/// Pins that the `output_details` compensation survives a serialize/deserialize
/// even though the account-local `spent_outpoints` set does NOT (it is rebuilt
/// from recorded transactions on load and omits the never-recorded spend). This
/// exercises that boundary
/// directly via `simulate_reload_rebuild_spent_outpoints`, which performs the
/// exact same reconstruction the real `Deserialize` impl does — a literal
/// full-struct serde round-trip is unavailable for a populated account (see
/// that helper's doc comment).
///
/// Two reload cycles are exercised, not one, to confirm the persisted
/// wallet-level `observed_spent_outpoints` set — not the transient
/// account-local mark — is what makes this survive a restart.
#[tokio::test]
async fn compensation_survives_simulated_reload_across_two_restart_cycles() {
    let mut ctx = TestWalletContext::new_random();

    let out0_value = 2_000_000u64;
    let out1_value = 500_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[out0_value, out1_value]);
    let funding_txid = funding_tx.txid();
    let out0 = OutPoint::new(funding_txid, 0);
    let out1 = OutPoint::new(funding_txid, 1);
    let spend_tx = spend_to_external(&[out0], out0_value - 1_000, 99);

    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;

    let assert_consistent = |ctx: &TestWalletContext, cycle: u32| {
        assert!(utxo_tracked(&ctx.managed_wallet, &out1), "cycle {cycle}: out1 tracked");
        assert!(!utxo_tracked(&ctx.managed_wallet, &out0), "cycle {cycle}: out0 invalidated");
        assert_eq!(
            ctx.managed_wallet.balance.total(),
            out1_value,
            "cycle {cycle}: balance is the surviving output only"
        );
        let account = ctx.managed_wallet.first_bip44_managed_account().expect("account");
        let record = account.transactions().get(&funding_txid).expect("funding record");
        assert_eq!(
            record.net_amount, out1_value as i64,
            "cycle {cycle}: net_amount must not be compensated twice across a reload"
        );
        assert_eq!(
            history_net(&ctx.managed_wallet),
            ctx.managed_wallet.balance.total() as i64,
            "cycle {cycle}: history net stays equal to balance across a reload"
        );
    };
    assert_consistent(&ctx, 0);

    for cycle in 1..=2 {
        // Simulate a restart: rebuild the account-local `spent_outpoints`
        // from recorded transactions exactly as `Deserialize` would. The
        // persisted wallet-level `observed_spent_outpoints` is left intact,
        // as it would be across a real save/reload.
        ctx.managed_wallet
            .first_bip44_managed_account_mut()
            .expect("account")
            .simulate_reload_rebuild_spent_outpoints();

        // Post-restart rescan / duplicate delivery reprocesses the funding tx.
        ctx.check_transaction(&funding_tx, block_ctx(100)).await;

        assert_consistent(&ctx, cycle);
    }
}

/// A full historical rescan can deliver a funding tx whose FIRST sighting is
/// already `InChainLockedBlock`. `record_transaction` builds the record with
/// out0 excluded (its spend is in `observed_spent_outpoints`) before the
/// default feature prunes the record to `finalized_txids`. So `history_net`
/// is 0 while `balance` keeps out1 — the general pruning non-invariant pinned
/// by [`plain_chainlocked_funding_diverges_history_from_balance_by_design`],
/// not a #649 defect.
#[cfg(not(feature = "keep-finalized-transactions"))]
#[tokio::test]
async fn spend_first_ordering_with_chainlocked_first_sighting_prunes_record_by_design() {
    let mut ctx = TestWalletContext::new_random();

    let out0_value = 2_000_000u64;
    let out1_value = 500_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[out0_value, out1_value]);
    let funding_txid = funding_tx.txid();
    let out0 = OutPoint::new(funding_txid, 0);
    let out1 = OutPoint::new(funding_txid, 1);
    let spend_tx = spend_to_external(&[out0], out0_value - 1_000, 100);

    // Spend of out0 observed first (still an ordinary InBlock context — the
    // spend itself need not be chainlocked for this to trigger).
    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    // The funding tx's FIRST sighting is already chainlocked, as it would be
    // during a full rescan of old history.
    ctx.check_transaction(&funding_tx, chain_locked_block_ctx(100)).await;

    assert!(!utxo_tracked(&ctx.managed_wallet, &out0), "out0 stays invalidated");
    assert!(utxo_tracked(&ctx.managed_wallet, &out1), "out1 survives");
    assert_eq!(
        ctx.managed_wallet.balance.total(),
        out1_value,
        "balance correctly reflects the surviving output"
    );
    assert_eq!(
        history_net(&ctx.managed_wallet),
        0,
        "the born-correct record was pruned to finalized_txids on first sighting, so history \
         omits it entirely — the general pruning non-invariant, not a #649 defect"
    );
}

/// Mirror of the above under `keep-finalized-transactions`: the record is
/// never pruned, so β (`history_net == balance.total()`) holds — and it holds
/// because the record was born correct at construction, not because of any
/// post-hoc compensation. Confirms the pruning-driven divergence above is
/// purely a consequence of pruning, not an unclosed #649 gap.
#[cfg(feature = "keep-finalized-transactions")]
#[tokio::test]
async fn spend_first_ordering_with_chainlocked_first_sighting_matches_balance_when_kept() {
    let mut ctx = TestWalletContext::new_random();

    let out0_value = 2_000_000u64;
    let out1_value = 500_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[out0_value, out1_value]);
    let funding_txid = funding_tx.txid();
    let out0 = OutPoint::new(funding_txid, 0);
    let out1 = OutPoint::new(funding_txid, 1);
    let spend_tx = spend_to_external(&[out0], out0_value - 1_000, 100);

    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    ctx.check_transaction(&funding_tx, chain_locked_block_ctx(100)).await;

    assert!(!utxo_tracked(&ctx.managed_wallet, &out0), "out0 stays invalidated");
    assert!(utxo_tracked(&ctx.managed_wallet, &out1), "out1 survives");
    assert_eq!(
        history_net(&ctx.managed_wallet),
        ctx.managed_wallet.balance.total() as i64,
        "with keep-finalized-transactions on, the born-correct record stays live and \
         history net matches balance even for a chainlocked-first-sighting funding"
    );

    let account = ctx.managed_wallet.first_bip44_managed_account().expect("account");
    let record = account.transactions().get(&funding_txid).expect("record kept live");
    assert_eq!(record.net_amount, out1_value as i64, "born correct: only out1 counted");
    assert!(!record.output_details.iter().any(|d| d.index == 0), "out0 was never inserted");
}

// ── guard-removal path releases reservations ─────────────────────────────

/// A coin removed by the wallet-level #649 guard (funding-first ordering, via
/// `remove_spent_from_accounts` → `finalize_guard_removed_utxo`) must release
/// any build reservation held on it immediately, exactly as the normal spend
/// path in `update_utxos` does — not leave it reserved until the TTL backstop.
///
/// Uses a CoinJoin coin: the AssetLock-classified spend routes away from the
/// CoinJoin account, so the coin is removed through the guard path rather than
/// the normal `update_utxos` spend path (which already releases reservations).
#[tokio::test]
async fn guard_removed_coin_releases_its_reservation_immediately() {
    let mut ctx = TestWalletContext::new_random();

    let cj_xpub = ctx.wallet.get_coinjoin_account(0).expect("coinjoin account").account_xpub;
    let cj_address = ctx
        .managed_wallet
        .first_coinjoin_managed_account_mut()
        .expect("managed coinjoin account")
        .next_address(Some(&cj_xpub), true)
        .expect("coinjoin address");

    // Fund the coin in order, so the funding record is live and the coin tracked.
    let funding_value = 1_500_000u64;
    let funding_tx = Transaction::dummy(&cj_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;

    // Reserve it as an in-flight transaction build would.
    let account = ctx.managed_wallet.first_coinjoin_managed_account().expect("account");
    assert!(account.utxos.contains_key(&funding_outpoint), "coin tracked before the guard removal");
    account.reservations().reserve(&[funding_outpoint], 0);
    assert!(
        account.reservations().reserved(0).contains(&funding_outpoint),
        "reservation is held before the spend arrives"
    );

    // An AssetLock-classified spend routes away from the CoinJoin account, so the
    // coin is removed via the wallet-level guard path (funding-first ordering),
    // not the normal `update_utxos` spend path.
    let mut spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 121);
    spend_tx.special_transaction_payload =
        Some(TransactionPayload::AssetLockPayloadType(AssetLockPayload::new(vec![])));
    assert_eq!(
        TransactionRouter::classify_transaction(&spend_tx),
        TransactionType::AssetLock,
        "spend must classify as AssetLock to route through the guard-removal path"
    );

    ctx.check_transaction(&spend_tx, block_ctx(200)).await;

    let account = ctx.managed_wallet.first_coinjoin_managed_account().expect("account");
    assert!(
        !account.utxos.contains_key(&funding_outpoint),
        "the guard removed the coin from the tracked set"
    );
    assert!(
        !account.reservations().reserved(0).contains(&funding_outpoint),
        "the guard-removal path must release the reservation immediately, not wait out the TTL"
    );
}

// ── Phase 1: finality-boundary pruning (dashpay/rust-dashcore#649) ────────

/// Advance chainlock + synced_height past an observed spend's height so its
/// entry is evicted, then redeliver the funding tx in block context. The
/// finalized funding record short-circuits reinsertion, so the coin is not
/// resurrected and balance/history are unchanged.
#[tokio::test]
async fn pruned_entry_does_not_resurrect_on_funding_redelivery() {
    let mut ctx = TestWalletContext::new_random();

    let funding_value = 1_000_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 130);

    // Spend-first at height 200, funding at height 100.
    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    assert!(!utxo_tracked(&ctx.managed_wallet, &funding_outpoint), "coin reconciled away");
    assert!(ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint));

    // Advance the finality boundary to the spend height (200): evicts the entry.
    ctx.managed_wallet.update_last_processed_height(200);
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(200));
    ctx.managed_wallet.update_synced_height(200);
    assert!(
        !ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "entry at height 200 evicted once chainlock and synced_height reach 200"
    );

    let balance_before = ctx.managed_wallet.balance.total();
    let history_before = history_net(&ctx.managed_wallet);

    // Redeliver the funding tx: the finalized record must short-circuit.
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "a pruned entry must not resurrect the coin on funding redelivery"
    );
    assert_eq!(ctx.managed_wallet.balance.total(), balance_before, "balance unchanged");
    assert_eq!(history_net(&ctx.managed_wallet), history_before, "history unchanged");
}

/// As above, but rebuild the account-local `spent_outpoints` from records (a
/// reload) before the redelivery. The account-local set never held this spend
/// (it was never recorded there), so this pins that the durable protection is
/// the finalized/chainlocked record, not the account-local spent set.
#[tokio::test]
async fn pruned_entry_does_not_resurrect_across_reload() {
    let mut ctx = TestWalletContext::new_random();

    let funding_value = 1_000_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 131);

    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;

    ctx.managed_wallet.update_last_processed_height(200);
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(200));
    ctx.managed_wallet.update_synced_height(200);
    assert!(!ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint));

    // Reload: rebuild the account-local spent set from recorded transactions.
    ctx.managed_wallet
        .first_bip44_managed_account_mut()
        .expect("account")
        .simulate_reload_rebuild_spent_outpoints();

    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "protection survives reload via the finalized record, not the rebuilt spent set"
    );
    assert_eq!(ctx.managed_wallet.balance.total(), 0, "no phantom balance after reload");
}

/// Direct pin of the §2 disproof: a guard-removed spend's protection is the
/// wallet-level map (the account-local set does not hold it after a reload).
/// The entry must survive the reload and keep guarding; only once its height is
/// final may it be pruned, and even then the finalized record prevents
/// resurrection.
#[tokio::test]
async fn guard_removed_entry_survives_reload_then_prunes_safely() {
    let mut ctx = TestWalletContext::new_random();

    // Fund a CoinJoin coin in order (AssetLock spend routes away from it).
    let cj_xpub = ctx.wallet.get_coinjoin_account(0).expect("coinjoin account").account_xpub;
    let cj_address = ctx
        .managed_wallet
        .first_coinjoin_managed_account_mut()
        .expect("managed coinjoin account")
        .next_address(Some(&cj_xpub), true)
        .expect("coinjoin address");

    let funding_value = 1_500_000u64;
    let funding_tx = Transaction::dummy(&cj_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;

    // Guard-remove via an AssetLock-classified spend at height 200.
    let mut spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 132);
    spend_tx.special_transaction_payload =
        Some(TransactionPayload::AssetLockPayloadType(AssetLockPayload::new(vec![])));
    assert_eq!(TransactionRouter::classify_transaction(&spend_tx), TransactionType::AssetLock);
    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    assert!(!utxo_tracked(&ctx.managed_wallet, &funding_outpoint), "guard removed the coin");
    assert!(ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint));

    // Reload: the rebuilt account-local set lacks the spend (never recorded),
    // so the wallet-level map is the sole guard.
    ctx.managed_wallet
        .first_coinjoin_managed_account_mut()
        .expect("account")
        .simulate_reload_rebuild_spent_outpoints();
    assert!(
        ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "the wallet-level entry survives reload and remains the guard"
    );
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "the surviving map entry still guards the coin after reload"
    );

    // Finalize past the spend height, then prune: the finalized record now
    // guards, so eviction is safe.
    ctx.managed_wallet.update_last_processed_height(200);
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(200));
    ctx.managed_wallet.update_synced_height(200);
    assert!(
        !ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "entry pruned once its spend height is final"
    );
    ctx.managed_wallet
        .first_coinjoin_managed_account_mut()
        .expect("account")
        .simulate_reload_rebuild_spent_outpoints();
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    assert!(
        !utxo_tracked(&ctx.managed_wallet, &funding_outpoint),
        "after prune the finalized record short-circuits any resurrection"
    );
}

/// Nothing is pruned above the finality boundary: entries with height above the
/// chainlock height are retained regardless of `synced_height`, and entries at
/// or below the chainlock but above `synced_height` are retained too (the
/// rescan-in-progress guard).
#[test]
fn no_prune_above_finality_boundary() {
    let op = |b: u8| OutPoint::new(dashcore::Txid::from([b; 32]), 0);

    let mut wallet = ManagedWalletInfo::new(Network::Testnet, [21u8; 32]);
    wallet.record_observed_spends(&spend_to_external(&[op(1)], 1, 70), 100);
    wallet.record_observed_spends(&spend_to_external(&[op(2)], 1, 71), 200);
    wallet.record_observed_spends(&spend_to_external(&[op(3)], 1, 72), 300);

    // boundary = min(chainlock 200, synced 250) = 200.
    wallet.update_last_processed_height(250);
    wallet.apply_chain_lock(ChainLock::dummy(200));
    wallet.update_synced_height(250);
    assert!(
        wallet.observed_spent_outpoints().contains_key(&op(3)),
        "entry above the chainlock height (300 > 200) retained regardless of synced_height"
    );
    assert!(
        !wallet.observed_spent_outpoints().contains_key(&op(1))
            && !wallet.observed_spent_outpoints().contains_key(&op(2)),
        "entries at or below the boundary (100, 200) evicted"
    );

    // Rescan-in-progress: chainlock ahead, synced behind → boundary follows synced.
    let mut w2 = ManagedWalletInfo::new(Network::Testnet, [22u8; 32]);
    w2.record_observed_spends(&spend_to_external(&[op(4)], 1, 73), 150);
    w2.update_last_processed_height(300);
    w2.apply_chain_lock(ChainLock::dummy(300));
    w2.update_synced_height(100);
    assert!(
        w2.observed_spent_outpoints().contains_key(&op(4)),
        "entry at 150 retained while synced_height (100) < its height, despite chainlock 300"
    );
}

/// Anti-LRU pin: an old entry above the boundary survives arbitrary block-height
/// advances as long as no chainlock defines a finality boundary. Pruning is
/// event-driven (chainlock/checkpoint), never age- or recency-based.
#[test]
fn prune_is_event_driven_not_age_based() {
    let mut wallet = ManagedWalletInfo::new(Network::Testnet, [23u8; 32]);
    let op = OutPoint::new(dashcore::Txid::from([9u8; 32]), 0);
    wallet.record_observed_spends(&spend_to_external(&[op], 1, 70), 100);

    // Advance processed/synced height far ahead, but never apply a chainlock.
    wallet.update_last_processed_height(1_000_000);
    wallet.update_synced_height(1_000_000);
    assert!(
        wallet.observed_spent_outpoints().contains_key(&op),
        "no chainlock ⇒ no finality boundary ⇒ entry retained regardless of height/age"
    );
}

/// After an entry is evicted, replaying the funding and spend blocks in either
/// order converges to the correct final state (no live UTXO, no double-counted
/// `net_amount`) and repopulates the map so it is re-prunable.
#[tokio::test]
async fn evicted_entry_self_heals_on_replay() {
    let mut ctx = TestWalletContext::new_random();

    let funding_value = 1_000_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let spend_tx = spend_to_external(&[funding_outpoint], funding_value - 1_000, 133);

    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    ctx.managed_wallet.update_last_processed_height(200);
    ctx.managed_wallet.apply_chain_lock(ChainLock::dummy(200));
    ctx.managed_wallet.update_synced_height(200);
    assert!(!ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint));

    let balance = ctx.managed_wallet.balance.total();
    let history = history_net(&ctx.managed_wallet);

    // Replay order A — spend first: repopulates the map, coin stays reconciled.
    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    assert!(
        ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "replaying the spend block repopulates the observed-spent entry"
    );
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    assert!(!utxo_tracked(&ctx.managed_wallet, &funding_outpoint), "order A: no resurrection");
    assert_eq!(ctx.managed_wallet.balance.total(), balance, "order A: balance not double-counted");
    assert_eq!(history_net(&ctx.managed_wallet), history, "order A: history not double-counted");

    // The repopulated entry is re-prunable at the same, already-final boundary.
    ctx.managed_wallet.prune_finalized_observed_spends();
    assert!(!ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint));

    // Replay order B — funding first: the finalized record short-circuits, then
    // the spend re-guards; final state is identical.
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    assert!(!utxo_tracked(&ctx.managed_wallet, &funding_outpoint), "order B: no resurrection");
    ctx.check_transaction(&spend_tx, block_ctx(200)).await;
    assert!(
        ctx.managed_wallet.observed_spent_outpoints().contains_key(&funding_outpoint),
        "order B: the replayed spend re-guards the coin"
    );
    assert_eq!(ctx.managed_wallet.balance.total(), balance, "order B: balance stable");
    assert_eq!(history_net(&ctx.managed_wallet), history, "order B: history stable");
}
