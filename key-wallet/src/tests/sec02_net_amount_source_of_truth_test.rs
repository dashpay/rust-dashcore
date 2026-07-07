//! Marvin's follow-up to Smythe's SEC-02 finding (security pass on the #649
//! restructure): `record_transaction` now calls
//! `TransactionRecord::compensate_for_observed_spends` UNCONDITIONALLY, so
//! `net_amount`'s source of truth silently shifted from
//! `account_match.received - account_match.sent` to a recompute driven by
//! `output_details`/`input_details`. Smythe rated this LOW because the two
//! are equal in the normal flow and no non-forged trigger for a standard
//! wallet was confirmed — but asked for (a) a regression test pinning that
//! equivalence in the common case, and (b) a constructed instance of the
//! specific divergence condition (`contains_script_pub_key` matches a
//! scriptPubKey whose address then fails `get_address_info` resolution).

use crate::managed_account::address_pool::PublicKeyType;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext};
use dashcore::blockdata::transaction::OutPoint;
use dashcore::{Address, PublicKey, ScriptBuf, Transaction, TxIn, TxOut, Txid, Witness};

fn block_ctx(height: u32) -> TransactionContext {
    TransactionContext::InBlock(BlockInfo::new(
        height,
        dashcore::BlockHash::dummy(height),
        1_650_000_000 + height,
    ))
}

/// A synthetic-input transaction paying each `(address, value)` pair in
/// `targets` to its own output, in order. Unlike `Transaction::dummy` (which
/// sends every output to the SAME address), this allows constructing a
/// multi-recipient funding transaction.
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

// ── (a) equivalence in the common case (observed_spent empty) ─────────────

/// Incoming funding: `net_amount` must equal `account_match.received -
/// account_match.sent`, computed independently via the same
/// `check_transaction_for_match` `record_transaction` itself calls.
#[tokio::test]
async fn net_amount_matches_account_match_formula_for_incoming_funding() {
    let mut ctx = TestWalletContext::new_random();
    let funding_value = 1_234_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);

    let account_match = ctx
        .managed_wallet
        .first_bip44_managed_account()
        .expect("account")
        .check_transaction_for_match(&funding_tx, Some(0))
        .expect("funding must match the account");
    let expected_net = account_match.received as i64 - account_match.sent as i64;
    assert_eq!(expected_net, funding_value as i64, "sanity: account_match sees the funding");

    ctx.check_transaction(&funding_tx, block_ctx(100)).await;

    let record = ctx.transaction(&funding_tx.txid());
    assert_eq!(
        record.net_amount, expected_net,
        "net_amount must equal account_match.received - account_match.sent with an empty \
         observed_spent set — B3's unconditional compensate_for_observed_spends call must not \
         silently change the common-case value"
    );
}

/// Outgoing spend to an external address: same equivalence check, this time
/// with `sent > 0` and `received == 0`.
#[tokio::test]
async fn net_amount_matches_account_match_formula_for_outgoing_spend() {
    let mut ctx = TestWalletContext::new_random();
    let funding_value = 2_000_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;

    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let external = Address::dummy(dashcore::Network::Testnet, 200);
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

    // Computed against the SAME pre-spend account state `record_transaction`
    // itself observes (input_details/account_match are built before
    // `update_utxos` removes the spent coin).
    let account_match = ctx
        .managed_wallet
        .first_bip44_managed_account()
        .expect("account")
        .check_transaction_for_match(&spend_tx, Some(0))
        .expect("spend must match the account (spends our own UTXO)");
    let expected_net = account_match.received as i64 - account_match.sent as i64;
    assert_eq!(expected_net, -(funding_value as i64), "sanity: pure spend, nothing received back");

    ctx.check_transaction(&spend_tx, block_ctx(101)).await;

    let record = ctx.transaction(&spend_tx.txid());
    assert_eq!(
        record.net_amount, expected_net,
        "net_amount must equal account_match.received - account_match.sent for an outgoing spend"
    );
}

/// Self-transfer / consolidation: funding spent entirely into this account's
/// own change address (no fee modeled), so both `received` and `sent` are
/// nonzero and, absent any #649 concern, must cancel out.
#[tokio::test]
async fn net_amount_matches_account_match_formula_for_self_transfer() {
    let mut ctx = TestWalletContext::new_random();
    let funding_value = 3_000_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;

    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let change_address = ctx
        .managed_wallet
        .first_bip44_managed_account_mut()
        .expect("account")
        .next_change_address(Some(&ctx.xpub), true)
        .expect("change address");
    let self_transfer_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: funding_value, // no fee modeled: exact round-trip
            script_pubkey: change_address.script_pubkey(),
        }],
        special_transaction_payload: None,
    };

    let account_match = ctx
        .managed_wallet
        .first_bip44_managed_account()
        .expect("account")
        .check_transaction_for_match(&self_transfer_tx, Some(0))
        .expect("self-transfer must match the account");
    let expected_net = account_match.received as i64 - account_match.sent as i64;
    assert_eq!(expected_net, 0, "sanity: exact round-trip self-transfer nets to zero");

    ctx.check_transaction(&self_transfer_tx, block_ctx(101)).await;

    let record = ctx.transaction(&self_transfer_tx.txid());
    assert_eq!(
        record.net_amount, expected_net,
        "net_amount must equal account_match.received - account_match.sent for a self-transfer"
    );
}

// ── (b) the specific divergence condition Smythe describes ────────────────

/// Constructs the exact edge case: an address whose scriptPubKey is present
/// in `AddressPool::script_pubkey_index` but whose `address_index` entry is
/// missing, forced via direct field manipulation. (`AddressPool::prune_unused`
/// used to leave exactly this desync behind, the concrete mechanism behind
/// Smythe's hypothetical — but it now keeps both maps in sync, so this exact
/// state is no longer reachable through it; both maps remain independently
/// `pub` fields, so nothing rules the desync out at the type level.)
///
/// A funding tx pays two outputs: one to a live, tracked address (so the
/// transaction is still recognized as relevant — `has_addresses` requires at
/// least one resolved address or `sent > 0`, and `received > 0` alone does
/// NOT satisfy that in `account_checker.rs`) and one to the desynced address
/// (`contains_script_pub_key` still matches it, but `get_address_info` now
/// returns `None`).
///
/// Result: `account_match.received` (account_checker.rs:646-665) counts BOTH
/// outputs (the `received += output.value` at line 664 is unconditional on
/// `get_address_info` success), so the OLD pre-restructure net_amount formula
/// would have shown `value0 + value1`. But `update_utxos`'s UTXO-insertion
/// eligibility (`involved_addrs`, built from the SAME `get_address_info`-
/// gated `involved_receive_addresses`/`involved_change_addresses` sets) never
/// inserts a UTXO for the pruned output either — so `balance.total()` was
/// ALREADY only ever going to be `value0` regardless of this diff. The new
/// `compensate_for_observed_spends`-driven recompute (which uses the same
/// `get_address_info`-gated address sets via `record_transaction`'s
/// `receive_addrs`/`change_addrs`) produces `net_amount == value0` — LOWER
/// than the old formula's `value0 + value1`, confirming Smythe's "under-
/// report relative to the old formula" is real, but ALSO confirming the new
/// number is the one that agrees with `balance`, not a new inconsistency:
/// the old formula was already reporting money the wallet could never
/// actually spend or see as a UTXO. The restructure does not create a new
/// spendable-fund miscount; it removes a pre-existing (unrelated,
/// `prune_unused`-only-reachable) history/balance mismatch in this exact
/// corner instead of preserving it.
#[tokio::test]
async fn pruned_address_script_desync_does_not_under_report_relative_to_balance() {
    let mut ctx = TestWalletContext::new_random();

    let desynced_address = {
        let account = ctx.managed_wallet.first_bip44_managed_account_mut().expect("account");
        let pools = account.managed_account_type_mut().address_pools_mut();
        let external_pool = pools.into_iter().next().expect("external pool");

        let desynced_address =
            external_pool.address_at_index(1).expect("pool pre-generates past index 0");
        assert!(external_pool.contains_address(&desynced_address), "generated, so indexed");

        // Force the desync directly: prune_unused itself keeps both maps in
        // sync now, so removing only the address-keyed entry is the only way
        // left to construct this state.
        external_pool.address_index.remove(&desynced_address);

        assert!(
            !external_pool.contains_address(&desynced_address),
            "address_index no longer resolves the desynced address"
        );
        assert!(
            external_pool.contains_script_pubkey(&desynced_address.script_pubkey()),
            "script_pubkey_index still matches — the constructed desync"
        );
        desynced_address
    };

    let value0 = 500_000u64;
    let value1 = 750_000u64;
    let funding_tx = fund_multi(&[(&ctx.receive_address, value0), (&desynced_address, value1)]);

    // The OLD net_amount formula, evaluated for real via the account's own
    // (unchanged-by-this-diff) `check_transaction_for_match`.
    let account_match = ctx
        .managed_wallet
        .first_bip44_managed_account()
        .expect("account")
        .check_transaction_for_match(&funding_tx, Some(0))
        .expect("tx must still be relevant via output 0");
    assert_eq!(
        account_match.received,
        value0 + value1,
        "confirms the divergence mechanism: account_match.received counts the stale \
         script-only match (value1) despite get_address_info failing for it"
    );
    let old_formula_net = account_match.received as i64 - account_match.sent as i64;

    ctx.check_transaction(&funding_tx, block_ctx(100)).await;

    // Balance was ALWAYS going to exclude value1 — it was never a real UTXO,
    // independent of the #649 restructure (update_utxos gates insertion on
    // the same get_address_info-derived address sets).
    assert_eq!(
        ctx.managed_wallet.balance.total(),
        value0,
        "value1 was never inserted as a spendable UTXO — a pre-existing address_pool gap, \
         not a #649 regression"
    );

    let record = ctx.transaction(&funding_tx.txid());
    assert_eq!(
        record.net_amount, value0 as i64,
        "the new declarative recompute reports only the actually-spendable value0"
    );
    assert_ne!(
        record.net_amount, old_formula_net,
        "confirms Smythe's SEC-02: the new number genuinely differs from the old \
         account_match-derived formula in this constructed edge case"
    );
    assert_eq!(
        record.net_amount,
        ctx.managed_wallet.balance.total() as i64,
        "critically: the NEW net_amount agrees with balance — the OLD formula (value0+value1) \
         would have been the one diverging from balance, not the new one. The restructure does \
         not introduce a new spendable-fund miscount here; it happens to resolve a pre-existing, \
         prune_unused-only-reachable history/balance mismatch instead of preserving it"
    );
}

// ── follow-up: Adams's RUST-001 scenarios (independent structural finding) ─

/// Adams's scenario 1 (RUST-001): "a bare P2PK scriptPubKey the account owns
/// matches `contains_script_pub_key` but can't resolve via `Address::from_script`
/// / `get_address_info`." Attempts this literally, using the account's OWN
/// derived public key (the most favorable case for triggering it) built into
/// a real P2PK scriptPubKey via `ScriptBuf::new_p2pk`.
///
/// Result: UNREACHABLE as literally stated. `contains_script_pub_key` is an
/// exact byte-match against `AddressPool::script_pubkey_index`
/// (`address_pool.rs::contains_script_pubkey`), and nothing in this crate
/// ever inserts a P2PK-shaped script into that index: `AddressType`
/// (`dash/src/address.rs`) has no P2PK variant (only P2pkh/P2sh/P2wpkh/P2wsh/
/// P2tr), and `AddressPool::generate_address_at_index` always builds
/// `Address::p2pkh(&dash_pubkey, network)` for the ECDSA path regardless of
/// `address_type`. So `contains_script_pub_key(p2pk_script)` is always
/// `false` for a script this crate did not itself register — and it never
/// registers a P2PK script. The transaction below is not even recognized
/// as touching this account at all (confirmed below), let alone reaching
/// the `received += value` unconditional-counting line Adams cites.
///
/// This does NOT mean Adams's underlying concern is unfounded, though: the
/// GENERAL class — `contains_script_pub_key` true but `Address::from_script`/
/// `get_address_info` resolution failing — is real and already demonstrated
/// with a different, genuinely constructible trigger in
/// `pruned_address_script_desync_does_not_under_report_relative_to_balance`
/// above (an `AddressPool::prune_unused`-induced `script_pubkey_index` /
/// `address_index` desync). P2PK specifically just isn't how it happens in
/// this codebase.
#[tokio::test]
async fn scenario1_bare_p2pk_is_structurally_unreachable() {
    let ctx = TestWalletContext::new_random();
    let account = ctx.managed_wallet.first_bip44_managed_account().expect("account");
    let info = account.get_address_info(&ctx.receive_address).expect("own address info");
    let public_key = info.public_key.clone().expect("ECDSA key");
    let PublicKeyType::ECDSA(pubkey_bytes) = &public_key else {
        panic!("BIP44 account must derive ECDSA keys");
    };
    let pubkey = PublicKey::from_slice(pubkey_bytes).expect("valid pubkey");
    let p2pk_script = ScriptBuf::new_p2pk(&pubkey);

    assert_ne!(
        p2pk_script,
        ctx.receive_address.script_pubkey(),
        "sanity: P2PK and P2PKH scripts for the same key are byte-distinct"
    );
    assert!(
        !account.managed_account_type().contains_script_pub_key(&p2pk_script),
        "the account's own script_pubkey_index never contains a P2PK-shaped script — \
         confirms contains_script_pub_key cannot match a bare P2PK output for OUR key, \
         so Adams's scenario 1 cannot trigger via this exact mechanism"
    );

    let funding_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from([0xEEu8; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: 1_000_000,
            script_pubkey: p2pk_script,
        }],
        special_transaction_payload: None,
    };
    assert!(
        account.check_transaction_for_match(&funding_tx, Some(0)).is_none(),
        "a P2PK-only output to our own key is not even recognized as relevant to the account \
         — confirms the whole scenario never reaches record_transaction/compensate_for_observed_spends"
    );
}

/// Adams's scenario 2 (RUST-001): "the code's own comment
/// (`managed_core_funds_account.rs:473-476`) admits `account_match.sent` can
/// be nonzero while `input_details` is empty (partial rescan) — the
/// unconditional recompute then subtracts 0 instead of the real spend."
///
/// Result: UNREACHABLE given the CURRENT implementation. Grep-confirmed
/// there is exactly ONE `sent =`/`sent +=` assignment site in the entire
/// `account_checker.rs` (`check_transaction_for_match`, line ~672):
/// `sent = sent.saturating_add(utxo.txout.value)`, gated by
/// `self.utxos.get(&input.previous_output)` — the IDENTICAL predicate, on
/// the SAME `ManagedCoreFundsAccount` instance, that
/// `record_transaction`'s `input_details` loop uses
/// (`managed_core_funds_account.rs:463`). Traced the call path in
/// `wallet_checker.rs` (lines 61, 188): `account_match` is computed once via
/// `self.accounts.check_transaction`, then `record_transaction` runs on the
/// SAME account handle with no intervening mutation of `self.utxos` for this
/// transaction. So for the standard funds-account path, `account_match.sent
/// > 0` structurally IMPLIES `input_details` is non-empty — they cannot
/// diverge. The doc comment's stated rationale ("UTXO set may be incomplete")
/// does not correspond to any live divergence in this exact code today; it
/// reads as defensive/historical rationale rather than a description of
/// current behavior — itself worth a documentation fix, but not a functional
/// bug in `compensate_for_observed_spends`.
///
/// Demonstrated empirically below: the same "partial rescan" precondition
/// (this account's `utxos` genuinely lacks the spent coin) drives BOTH
/// signals to zero/empty together, never one without the other.
#[tokio::test]
async fn scenario2_sent_and_input_details_cannot_diverge_in_current_code() {
    let mut ctx = TestWalletContext::new_random();

    // Model "partial rescan": a coin this account actually owns on-chain,
    // but whose funding was never processed, so `self.utxos` never learned
    // about it — the exact condition the code comment names.
    let unscanned_outpoint = OutPoint::new(Txid::from([0x77u8; 32]), 3);
    let external = Address::dummy(dashcore::Network::Testnet, 210);
    let spend_of_unscanned_coin = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: unscanned_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: 999_000,
            script_pubkey: external.script_pubkey(),
        }],
        special_transaction_payload: None,
    };

    let account = ctx.managed_wallet.first_bip44_managed_account().expect("account");
    assert!(
        !account.utxos.contains_key(&unscanned_outpoint),
        "sanity: the coin is genuinely absent from this account's utxo set"
    );
    let match_result = account.check_transaction_for_match(&spend_of_unscanned_coin, Some(0));
    assert!(
        match_result.is_none_or(|m| m.sent == 0),
        "when self.utxos lacks the coin, account_match.sent is ALSO 0 (not '> 0 with empty \
         input_details' as scenario 2 hypothesizes) — sent and input_details are governed by \
         the identical predicate and cannot diverge in the current code"
    );

    // Contrast: once the SAME coin is genuinely funded and tracked, both
    // signals become nonzero together — never independently.
    let funding_value = 999_000u64;
    let funding_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    ctx.check_transaction(&funding_tx, block_ctx(100)).await;
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
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
    let account_match = ctx
        .managed_wallet
        .first_bip44_managed_account()
        .expect("account")
        .check_transaction_for_match(&spend_tx, Some(0))
        .expect("must match — the coin is tracked");
    assert_eq!(account_match.sent, funding_value, "tracked coin: sent is populated");
    ctx.check_transaction(&spend_tx, block_ctx(101)).await;
    let record = ctx.transaction(&spend_tx.txid());
    assert_eq!(
        record.input_details.len(),
        1,
        "input_details is populated in lockstep with account_match.sent, never independently"
    );
}
