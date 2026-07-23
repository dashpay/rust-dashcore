//! Unit-level coverage for the wallet-level observed-spent-outpoint machinery
//! (dashpay/rust-dashcore#649).
//!
//! The manager-level integration tests (`key-wallet-manager/tests/`) drive the
//! *spend-first* ordering end-to-end through the public `WalletManager` surface:
//! a spend delivered before its funding, reconciled at `update_utxos` insert
//! time. That path leaves several branches of the fix unexercised, because they
//! only trigger on orderings or lifecycle events a black-box manager test cannot
//! reach directly:
//!
//! * the serde adapter for `observed_spent_outpoints` (no manager test
//!   serializes a wallet holding entries),
//! * `prune_finalized_observed_spends` and its finality boundary,
//! * the *funding-first* removal guard `remove_spent_from_accounts` /
//!   `finalize_guard_removed_utxo` (the coin is already live and must be dropped
//!   un-gated by classification),
//! * the account-add sync rewind for a standalone (from-xpub) account, and
//! * the account-local vs. wallet-level source-of-truth split across a reload.
//!
//! These white-box tests exercise those branches directly against the
//! `pub(crate)` surface.

use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, TxIn, Txid};

use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext};
use crate::wallet::managed_wallet_info::managed_account_operations::ManagedAccountOperations;
use crate::wallet::ManagedWalletInfo;
use crate::AccountType;

/// A transaction whose inputs spend exactly `spent`, with no outputs. Enough to
/// drive `record_observed_spends` (reads inputs) and the removal guard.
fn spending_tx(spent: &[OutPoint]) -> Transaction {
    Transaction {
        version: 1,
        lock_time: 0,
        input: spent
            .iter()
            .map(|op| TxIn {
                previous_output: *op,
                ..Default::default()
            })
            .collect(),
        output: Vec::new(),
        special_transaction_payload: None,
    }
}

/// A syntactically-valid `ChainLock` at `height`; only `block_height` is read by
/// the prune boundary, the signature is never verified here.
fn dummy_chain_lock(height: u32) -> ChainLock {
    ChainLock {
        block_height: height,
        block_hash: BlockHash::from_slice(&[height as u8; 32]).expect("hash"),
        signature: BLSSignature::from([0u8; 96]),
    }
}

/// The `observed_spent_outpoints` serde adapter round-trips: it encodes the map
/// as a `(OutPoint, height)` sequence (format-agnostic), and reloads it. An
/// account-less wallet serializes cleanly — the populated-account blocker is
/// `AddressPool::script_pubkey_index` (a non-string JSON map key), not this
/// field — so it isolates the adapter under test.
#[cfg(feature = "serde")]
#[test]
fn observed_spent_outpoints_survive_serde_round_trip() {
    let mut info = ManagedWalletInfo::dummy(7);
    let op_a = OutPoint::new(Txid::from([0x11; 32]), 0);
    let op_b = OutPoint::new(Txid::from([0x22; 32]), 3);
    info.record_observed_spends(&spending_tx(&[op_a]), 100);
    info.record_observed_spends(&spending_tx(&[op_b]), 250);
    assert_eq!(info.observed_spent_outpoints().len(), 2);

    let json = serde_json::to_string(&info).expect("serialize");
    let restored: ManagedWalletInfo = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(restored.observed_spent_outpoints().get(&op_a), Some(&100));
    assert_eq!(restored.observed_spent_outpoints().get(&op_b), Some(&250));
    assert_eq!(restored.observed_spent_outpoints().len(), 2);

    // An empty map round-trips through the sequence adapter too (empty-seq
    // serialize + visitor path), and `#[serde(default)]` still yields an empty
    // set rather than erroring.
    let empty = ManagedWalletInfo::dummy(8);
    let json_empty = serde_json::to_string(&empty).expect("serialize empty");
    let restored_empty: ManagedWalletInfo =
        serde_json::from_str(&json_empty).expect("deserialize empty");
    assert!(restored_empty.observed_spent_outpoints().is_empty());
}

/// `prune_finalized_observed_spends` is a no-op without a chainlock, and
/// otherwise evicts exactly the entries at or below
/// `min(chainlock height, synced_height)` — the finality boundary — keeping
/// everything above it.
#[test]
fn prune_finalized_observed_spends_respects_finality_boundary() {
    let mut info = ManagedWalletInfo::dummy(9);
    let op_low = OutPoint::new(Txid::from([0x01; 32]), 0); // height 50
    let op_bnd = OutPoint::new(Txid::from([0x02; 32]), 0); // height 100 (== boundary)
    let op_high = OutPoint::new(Txid::from([0x03; 32]), 0); // height 150
    info.record_observed_spends(&spending_tx(&[op_low]), 50);
    info.record_observed_spends(&spending_tx(&[op_bnd]), 100);
    info.record_observed_spends(&spending_tx(&[op_high]), 150);

    // No chainlock has been applied: there is no provable finality boundary, so
    // nothing may be pruned regardless of how high `synced_height` is.
    info.metadata.synced_height = 1_000_000;
    info.prune_finalized_observed_spends();
    assert_eq!(
        info.observed_spent_outpoints().len(),
        3,
        "no chainlock => nothing is provably final => no eviction"
    );

    // Boundary = min(chainlock height 200, synced_height 100) = 100. The
    // chainlock being higher than the sync checkpoint is the exact case an
    // in-progress rescan produces, and it must not over-prune.
    info.metadata.synced_height = 100;
    info.metadata.last_applied_chain_lock = Some(dummy_chain_lock(200));
    info.prune_finalized_observed_spends();

    let remaining = info.observed_spent_outpoints();
    assert!(!remaining.contains_key(&op_low), "height 50 <= boundary 100: evicted");
    assert!(!remaining.contains_key(&op_bnd), "height 100 == boundary 100: evicted");
    assert!(remaining.contains_key(&op_high), "height 150 > boundary 100: retained");
    assert_eq!(remaining.len(), 1);
}

/// The funding-first guard: a coin that is already live in a funding account,
/// whose spend the matched-account path could not attribute, is dropped
/// un-gated by `remove_spent_from_accounts`, which also marks it spent, releases
/// its build reservation, and compensates the funding record. Idempotent, and a
/// coinbase is skipped.
#[tokio::test]
async fn funding_first_guard_removes_held_coin_and_compensates_record() {
    let (mut ctx, funding_tx) =
        TestWalletContext::new_random().with_mempool_funding(1_000_000).await;
    let funded = OutPoint::new(funding_tx.txid(), 0);

    // Reserve the coin so we can prove the guard frees the reservation too.
    ctx.managed_wallet
        .first_bip44_managed_account()
        .expect("BIP44 account")
        .reservations()
        .reserve(&[funded], 0);
    assert!(ctx
        .managed_wallet
        .first_bip44_managed_account()
        .unwrap()
        .reservations()
        .reserved(0)
        .contains(&funded));

    // The two decomposed steps the checker runs on a block spend it cannot
    // attribute to the owning account (routed away by tx-type narrowing, or the
    // funding lives in another account): record the observed spend, then drop
    // the coin un-gated by classification.
    let spend = spending_tx(&[funded]);
    ctx.managed_wallet.record_observed_spends(&spend, 200);
    let (removed, rewritten) = ctx.managed_wallet.remove_spent_from_accounts(&spend);
    assert!(removed, "guard must remove the live coin the matched path missed");
    assert_eq!(rewritten.len(), 1, "the compensated funding record is surfaced for consumers");
    assert_eq!(rewritten[0].txid, funding_tx.txid());
    assert_eq!(rewritten[0].net_amount, 0, "the surfaced clone is the post-compensation record");

    let account = ctx.managed_wallet.first_bip44_managed_account().unwrap();
    assert!(!account.utxos.contains_key(&funded), "coin dropped from the funding account");
    assert!(
        !account.reservations().reserved(0).contains(&funded),
        "guard releases the build reservation immediately, not at the TTL backstop"
    );
    let record = account.transactions().get(&funding_tx.txid()).expect("funding record kept");
    assert_eq!(record.net_amount, 0, "the spent output is compensated out of net_amount");
    assert!(record.output_details.is_empty(), "the spent Received output is dropped");

    // Idempotent: the coin is already gone, so a second call removes nothing.
    assert!(
        !ctx.managed_wallet.remove_spent_from_accounts(&spend).0,
        "second call has nothing left to remove"
    );
    // A coinbase's single input is the null prevout and spends nothing real.
    let coinbase = Transaction::dummy_coinbase(&ctx.receive_address, 5_000_000_000);
    assert!(
        !ctx.managed_wallet.remove_spent_from_accounts(&coinbase).0,
        "coinbase is skipped by the guard"
    );
}

/// After the funding-first guard drops a coin, the account-local `spent_outpoints`
/// set — rebuilt from recorded transactions on reload — forgets the unrecorded
/// spend, but the persisted wallet-level `observed_spent_outpoints` still keeps
/// the coin from being resurrected when the funding is re-delivered. This is the
/// source-of-truth split the fix relies on across a serialize/deserialize.
#[tokio::test]
async fn wallet_level_set_outlives_account_local_reload() {
    let (mut ctx, funding_tx) =
        TestWalletContext::new_random().with_mempool_funding(1_000_000).await;
    let funded = OutPoint::new(funding_tx.txid(), 0);
    let spend = spending_tx(&[funded]);

    // Observe + drop the coin via the funding-first guard.
    ctx.managed_wallet.record_observed_spends(&spend, 200);
    assert!(ctx.managed_wallet.remove_spent_from_accounts(&spend).0);

    // Simulate a save/reload: the account-local derived set is rebuilt from
    // recorded transactions only. The spend was never recorded as one of our
    // transactions, so the derived set forgets `funded` — exactly what a real
    // `Deserialize` would reconstruct.
    ctx.managed_wallet
        .first_bip44_managed_account_mut()
        .unwrap()
        .simulate_reload_rebuild_spent_outpoints();

    // The persisted wallet-level set is the durable source of truth: re-delivering
    // the funding in a block must NOT resurrect the coin.
    let block = BlockInfo::new(100, BlockHash::from_slice(&[9u8; 32]).unwrap(), 1_700_000_000);
    ctx.check_transaction(&funding_tx, TransactionContext::InBlock(block)).await;

    assert!(
        !ctx.managed_wallet.first_bip44_managed_account().unwrap().utxos.contains_key(&funded),
        "wallet-level observed_spent must keep the coin dropped even after the account-local \
         derived set is rebuilt from recorded transactions"
    );
}

/// Adding a standalone (from-xpub) account rewinds the sync checkpoint below
/// wallet birth, so the new account's coins get filter coverage before pruning
/// can consume the certificate (dashpay/rust-dashcore#649). A wallet still in
/// initial sync (already at/below the floor) is left untouched.
#[test]
fn adding_account_from_xpub_rewinds_sync_checkpoint() {
    let mut ctx = TestWalletContext::new_random();
    ctx.managed_wallet.metadata.birth_height = 1_000;
    ctx.managed_wallet.metadata.synced_height = 5_000;
    let generation_before = ctx.managed_wallet.account_generation();

    ctx.managed_wallet
        .add_managed_account_from_xpub(
            AccountType::IdentityTopUp {
                registration_index: 7,
            },
            ctx.xpub,
        )
        .expect("attach standalone IdentityTopUp account");

    assert_eq!(
        ctx.managed_wallet.metadata.synced_height, 999,
        "synced_height rewound to birth_height - 1 so the new account is re-scanned from birth"
    );
    assert_eq!(
        ctx.managed_wallet.account_generation(),
        generation_before + 1,
        "adding an account bumps the account generation so in-flight scans are invalidated"
    );

    // A wallet whose sync checkpoint is already below the birth floor is left
    // as-is: the rewind only ever collapses the certificate, never advances it.
    ctx.managed_wallet.metadata.synced_height = 10;
    ctx.managed_wallet
        .add_managed_account_from_xpub(
            AccountType::IdentityTopUp {
                registration_index: 8,
            },
            ctx.xpub,
        )
        .expect("attach second standalone account");
    assert_eq!(
        ctx.managed_wallet.metadata.synced_height, 10,
        "a still-behind sync checkpoint is not advanced by the rewind"
    );
    assert_eq!(
        ctx.managed_wallet.account_generation(),
        generation_before + 2,
        "the generation bumps even when the checkpoint does not move — this is the only \
         signal a commit-time check has for a height-invisible account add"
    );
}

/// Regression for the "born-fully-spent" history record-loss reported by
/// HashEngineering against #851/#866 (dashpay/rust-dashcore#649, and the
/// #846-class invisible-record family): a funding transaction recovered
/// *after* its spend was already observed — so every one of its
/// wallet-relevant outputs is in `observed_spent_outpoints` before the funding
/// itself is applied — must still be **recorded in history**, not silently
/// dropped. The balance and UTXO set are unaffected (the output is genuinely
/// spent on-chain), so this is purely about not losing the history record.
///
/// This is the spend-first / out-of-order ordering produced by the committed-
/// range rescan (`track_for_new_scripts`): the forward scan already processed
/// the spend, then the old funding block is re-applied. #649's fix keeps the
/// record: `check_transaction_for_match` classifies relevance by address
/// membership (never gated on spent-status, so the fully-spent funding is still
/// relevant), and `ManagedCoreFundsAccount::record_transaction` unconditionally
/// inserts the record after `TransactionRecord::compensate_for_observed_spends`
/// zeroes the already-spent outputs. This test pins that a born-fully-spent
/// funding tx (1) is surfaced as a new record and (2) lands in the account's
/// transaction history, while balance and UTXOs stay at zero.
#[tokio::test]
async fn born_fully_spent_funding_tx_is_recorded_in_history() {
    use dashcore::blockdata::script::ScriptBuf;
    use dashcore::TxOut;

    let mut ctx = TestWalletContext::new_random();

    // Funding F pays our receive address; its single output F:0 is ours.
    let funding_value = 1_000_000u64;
    let funding = Transaction::dummy(&ctx.receive_address, 0..1, &[funding_value]);
    let f_txid = funding.txid();
    let f_outpoint = OutPoint::new(f_txid, 0);

    // Spend S consumes F:0 entirely to an external address (no wallet output),
    // so the wallet cannot attribute it to any account when it arrives first.
    let external = dashcore::Address::p2pkh(
        &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
        dashcore::Network::Testnet,
    );
    let spend = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: f_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: dashcore::Witness::new(),
        }],
        output: vec![TxOut {
            value: funding_value - 1_000,
            script_pubkey: external.script_pubkey(),
        }],
        special_transaction_payload: None,
    };

    // Spend-first: the spend's block (height 200) is applied before the
    // funding's block (height 100), exactly as the committed-range rescan
    // re-applies old funding blocks after their spends.
    let spend_ctx = TransactionContext::InBlock(BlockInfo::new(
        200,
        BlockHash::from_slice(&[2u8; 32]).expect("hash"),
        1_650_000_200,
    ));
    let spend_res = ctx.check_transaction(&spend, spend_ctx).await;
    // The spend pays nothing to us and spends a coin we do not yet own, so it is
    // not attributable — but it must still be observed so the funding is
    // reconciled against it.
    assert!(!spend_res.is_relevant, "external spend of a not-yet-owned coin is unattributable");
    assert_eq!(
        ctx.managed_wallet.observed_spent_outpoints().get(&f_outpoint),
        Some(&200),
        "the spend must be recorded in observed_spent_outpoints"
    );

    // Now the funding block arrives. Every output of F is already observed
    // spent, i.e. F is born fully spent.
    let fund_ctx = TransactionContext::InBlock(BlockInfo::new(
        100,
        BlockHash::from_slice(&[1u8; 32]).expect("hash"),
        1_650_000_100,
    ));
    let fund_res = ctx.check_transaction(&funding, fund_ctx).await;

    // (1) The funding tx is still relevant and surfaced as a NEW record — this
    // is the detection event a consumer persists into history. Before #649's
    // record-keeping fix the spend-first path made it come out not-relevant and
    // produced no record and no event.
    assert!(fund_res.is_relevant, "a fully-spent funding tx paying our address is still relevant");
    assert!(
        fund_res.new_records.iter().any(|r| r.txid == f_txid),
        "born-fully-spent funding tx must be surfaced as a new record"
    );

    // (2) The record is present in the account's transaction history.
    let account = ctx.managed_wallet.first_bip44_managed_account().expect("BIP44 account");
    assert!(
        account.transactions().contains_key(&f_txid),
        "born-fully-spent funding tx must be recorded in the account's history"
    );

    // Balance and UTXO accounting are unchanged: the output is genuinely spent,
    // so it is never inserted as a UTXO and contributes zero to the balance.
    assert!(account.utxos.is_empty(), "the already-spent output must not become a UTXO");
    assert_eq!(ctx.managed_wallet.balance.total(), 0, "born-fully-spent tx must not add balance");

    // The record itself is compensated to a net-zero, output-less history entry.
    let record = account.transactions().get(&f_txid).expect("record present");
    assert_eq!(record.net_amount, 0, "the already-spent output is compensated out of net_amount");
    assert!(
        record.output_details.iter().all(|d| !matches!(
            d.role,
            crate::managed_account::transaction_record::OutputRole::Received
                | crate::managed_account::transaction_record::OutputRole::Change
        )),
        "no live Received/Change output detail should survive on a born-fully-spent record"
    );
}

/// Companion to [`born_fully_spent_funding_tx_is_recorded_in_history`] covering
/// the CoinJoin-style intermediate hop that HashEngineering measured missing: a
/// transaction that both **spends a live wallet coin** and pays its change back
/// to us, where that change output is itself already observed spent. It must be
/// recorded even though it nets to zero and leaves no UTXO.
#[tokio::test]
async fn born_fully_spent_intermediate_hop_is_recorded_in_history() {
    use dashcore::blockdata::script::ScriptBuf;
    use dashcore::TxOut;

    let mut ctx = TestWalletContext::new_random();

    // A second receive address for the hop's change output.
    let hop_addr = ctx
        .managed_wallet
        .first_bip44_managed_account_mut()
        .expect("BIP44 account")
        .next_receive_address(Some(&ctx.xpub), true)
        .expect("hop address");

    // C funds our first receive address (a live coin).
    let c = Transaction::dummy(&ctx.receive_address, 0..1, &[1_000_000]);
    let c_txid = c.txid();

    // Hop T spends C:0 and pays 990_000 back to our hop address (T:0).
    let t = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(c_txid, 0),
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: dashcore::Witness::new(),
        }],
        output: vec![TxOut {
            value: 990_000,
            script_pubkey: hop_addr.script_pubkey(),
        }],
        special_transaction_payload: None,
    };
    let t_txid = t.txid();

    // U spends T:0 out to an external address.
    let external = dashcore::Address::p2pkh(
        &dashcore::PublicKey::from_slice(&[0x02; 33]).expect("pubkey"),
        dashcore::Network::Testnet,
    );
    let u = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(t_txid, 0),
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: dashcore::Witness::new(),
        }],
        output: vec![TxOut {
            value: 980_000,
            script_pubkey: external.script_pubkey(),
        }],
        special_transaction_payload: None,
    };

    let blk = |h: u32, b: u8| {
        TransactionContext::InBlock(BlockInfo::new(
            h,
            BlockHash::from_slice(&[b; 32]).expect("hash"),
            1_650_000_000 + h,
        ))
    };

    // Order: fund C (live), then U (records T:0 observed spent), then the hop T
    // whose own output is already spent.
    ctx.check_transaction(&c, blk(1, 1)).await;
    let u_res = ctx.check_transaction(&u, blk(3, 3)).await;
    assert!(!u_res.is_relevant, "U is an external spend of a not-yet-owned coin");
    let t_res = ctx.check_transaction(&t, blk(2, 2)).await;

    // The hop is relevant (it spends our live coin C) and recorded, even though
    // its own output is compensated away.
    assert!(t_res.is_relevant, "a hop that spends our live coin is relevant");
    assert!(
        t_res.new_records.iter().any(|r| r.txid == t_txid),
        "the fully-spent hop must be surfaced as a new record"
    );

    let account = ctx.managed_wallet.first_bip44_managed_account().expect("BIP44 account");
    assert!(
        account.transactions().contains_key(&t_txid),
        "the fully-spent hop must be recorded in history"
    );
    assert!(
        account.transactions().contains_key(&c_txid),
        "the funding tx must also remain in history"
    );
    // Both C and T's outputs are consumed, so no UTXOs and zero balance remain.
    assert!(account.utxos.is_empty(), "no UTXO should remain after the hop chain");
    assert_eq!(ctx.managed_wallet.balance.total(), 0, "hop chain nets to zero balance");
}

/// Growing the observed-spent map is itself a state modification
/// (dashpay/rust-dashcore#649): the map is persisted wallet state, and a
/// consumer that persists only on reported modifications must not drop a
/// recorded spend across a restart. An irrelevant block spend therefore
/// reports `state_modified`, a byte-identical redelivery (map unchanged) does
/// not, and a mempool spend (never recorded) does not.
#[tokio::test]
async fn recording_observed_spend_reports_state_modified() {
    let mut ctx = TestWalletContext::new_random();
    let unrelated = OutPoint::new(Txid::from([0x77; 32]), 1);
    let spend = spending_tx(&[unrelated]);
    let block =
        BlockInfo::new(200, BlockHash::from_slice(&[3u8; 32]).expect("hash"), 1_700_000_000);

    let result = ctx.check_transaction(&spend, TransactionContext::InBlock(block)).await;
    assert!(!result.is_relevant, "the spend touches nothing the wallet owns");
    assert!(
        result.state_modified,
        "recording a new observed spend must surface as a state modification"
    );
    assert_eq!(ctx.managed_wallet.observed_spent_outpoints().get(&unrelated), Some(&200));

    // Same tx at the same height: the map entry is already present with the
    // same value, so nothing changed and nothing must be reported.
    let result = ctx.check_transaction(&spend, TransactionContext::InBlock(block)).await;
    assert!(!result.state_modified, "an unchanged map must not report a modification");

    // Mempool spends are never recorded, so they modify nothing either.
    let mempool_spend = spending_tx(&[OutPoint::new(Txid::from([0x78; 32]), 0)]);
    let result = ctx.check_transaction(&mempool_spend, TransactionContext::Mempool).await;
    assert!(!result.state_modified, "a mempool spend records nothing");
}
