//! Tests for BDK-style mutate-and-return changeset APIs on `ManagedCoreAccount`
//! and `ManagedWalletInfo`.
//!
//! Every mutation method now returns `(value, WalletChangeSet)` (or just
//! `WalletChangeSet` for void returns). These tests exercise:
//! - `ManagedCoreAccount::mark_address_used`
//! - `ManagedCoreAccount::mark_utxos_instant_send`
//! - `ManagedCoreAccount::update_transaction_context`
//! - `ManagedCoreAccount::update_balance`
//! - `ManagedCoreAccount::update_utxos` (indirectly via confirmation upgrade)
//! - End-to-end accumulation into `TransactionCheckResult::changeset` via
//!   `ManagedWalletInfo::check_core_transaction`.

use crate::changeset::Merge;
use crate::managed_account::ManagedCoreAccount;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::TransactionContext;
use crate::Utxo;

// ---------------------------------------------------------------------------
// mark_address_used
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mark_address_used_populates_changeset_then_becomes_idempotent() {
    let mut ctx = TestWalletContext::new_random();
    let addr = ctx.receive_address.clone();

    // First call: address transitions from unused → used, changeset carries it.
    let (changed, cs) = ctx
        .managed_wallet
        .first_bip44_managed_account_mut()
        .expect("bip44 account")
        .mark_address_used(&addr);

    assert!(changed, "first call should mark the address");
    let state_cs = cs.account_states.expect("account_states must be populated");
    assert_eq!(state_cs.addresses_used.len(), 1);
    assert!(state_cs.addresses_used.contains(&addr));
    assert!(state_cs.highest_used.is_empty());
    // No other sub-changesets for a pure address-mark.
    assert!(cs.utxos.is_none());
    assert!(cs.transactions.is_none());
    assert!(cs.balance.is_none());

    // Second call on the same address: no-op, empty changeset.
    let (changed, cs) = ctx
        .managed_wallet
        .first_bip44_managed_account_mut()
        .expect("bip44 account")
        .mark_address_used(&addr);

    assert!(!changed, "second call is a no-op");
    assert!(cs.is_empty(), "no-op must produce an empty changeset");
}

// ---------------------------------------------------------------------------
// mark_utxos_instant_send
// ---------------------------------------------------------------------------

#[test]
fn mark_utxos_instant_send_emits_outpoints_then_is_idempotent() {
    let mut account = ManagedCoreAccount::dummy_bip44();
    let utxo = Utxo::dummy(1, 100_000, 10, false, true);
    let outpoint = utxo.outpoint;
    let txid = outpoint.txid;
    account.insert_utxo(outpoint, utxo);

    // First call: UTXO transitions to IS-locked.
    let (changed, cs) = account.mark_utxos_instant_send(&txid);
    assert!(changed, "UTXO should transition to IS-locked");
    let utxo_cs = cs.utxos.expect("utxos must be populated");
    assert_eq!(utxo_cs.instant_locked.len(), 1);
    assert!(utxo_cs.instant_locked.contains(&outpoint));
    assert!(utxo_cs.added.is_empty(), "IS-lock must not add UTXOs");
    assert!(utxo_cs.spent.is_empty(), "IS-lock must not spend UTXOs");

    // Second call: no state change, empty changeset.
    let (changed, cs) = account.mark_utxos_instant_send(&txid);
    assert!(!changed, "idempotent replay");
    assert!(cs.is_empty());
}

// ---------------------------------------------------------------------------
// update_transaction_context — changeset-returning helper for in-place
// context updates on an already-recorded TransactionRecord.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_transaction_context_emits_record_only_when_context_changes() {
    use crate::transaction_checking::BlockInfo;
    use dashcore::BlockHash;
    use dashcore_hashes::Hash;

    let (mut ctx, tx) = TestWalletContext::new_random().with_mempool_funding(50_000).await;
    let txid = tx.txid();

    let account = ctx
        .managed_wallet
        .first_bip44_managed_account_mut()
        .expect("bip44 account");

    let block_hash = BlockHash::from_slice(&[42u8; 32]).expect("hash");
    let block_ctx = TransactionContext::InBlock(BlockInfo::new(500, block_hash, 1_700_000_000));

    // First call: context transitions mempool → block.
    let cs = account.update_transaction_context(&txid, block_ctx.clone());
    let tx_cs = cs.transactions.expect("context change must emit a transactions changeset");
    let updated = tx_cs.records.get(&txid).expect("updated record must be present");
    assert!(updated.is_confirmed());

    // Second call with the same context: no-op.
    let cs = account.update_transaction_context(&txid, block_ctx);
    assert!(cs.is_empty(), "same-context update must be a no-op");

    // Unknown txid: no-op.
    let phantom = dashcore::Txid::from_slice(&[99u8; 32]).expect("hash");
    let cs = account.update_transaction_context(
        &phantom,
        TransactionContext::Mempool,
    );
    assert!(cs.is_empty());
}

// ---------------------------------------------------------------------------
// update_balance
// ---------------------------------------------------------------------------

#[test]
fn update_balance_emits_signed_deltas_for_grows_and_shrinks() {
    let mut account = ManagedCoreAccount::dummy_bip44();

    // Baseline with one confirmed mature UTXO at 100k.
    let utxo = Utxo::dummy(1, 100_000, 10, false, true);
    let outpoint = utxo.outpoint;
    account.insert_utxo(outpoint, utxo);
    let cs = account.update_balance(100);
    let bal_cs = cs.balance.expect("first call must emit delta from zero baseline");
    assert_eq!(bal_cs.spendable_delta, 100_000);

    // No state change → empty changeset.
    let cs = account.update_balance(100);
    assert!(cs.is_empty(), "unchanged balance must emit empty changeset");

    // Add a second UTXO → positive delta.
    let utxo2 = Utxo::dummy(2, 250_000, 10, false, true);
    account.insert_utxo(utxo2.outpoint, utxo2);
    let cs = account.update_balance(100);
    let bal_cs = cs.balance.expect("balance must be populated");
    assert_eq!(bal_cs.spendable_delta, 250_000);
    assert_eq!(bal_cs.unconfirmed_delta, 0);
    assert_eq!(bal_cs.immature_delta, 0);
    assert_eq!(bal_cs.locked_delta, 0);

    // Remove the original UTXO → negative delta.
    account.remove_utxo(&outpoint);
    let cs = account.update_balance(100);
    let bal_cs = cs.balance.expect("balance must be populated");
    assert_eq!(bal_cs.spendable_delta, -100_000);
}

// ---------------------------------------------------------------------------
// update_utxos (via confirm_transaction): context upgrade must emit a
// changeset entry so a persister replay doesn't leave a stale Utxo.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn confirming_mempool_tx_emits_utxo_delta_for_context_upgrade() {
    use crate::transaction_checking::BlockInfo;
    use dashcore::BlockHash;
    use dashcore_hashes::Hash;

    let (mut ctx, tx) = TestWalletContext::new_random().with_mempool_funding(300_000).await;

    let block_hash = BlockHash::from_slice(&[7u8; 32]).expect("hash");
    let block_ctx = TransactionContext::InBlock(BlockInfo::new(600, block_hash, 1_700_000_000));
    let result = ctx.check_transaction(&tx, block_ctx).await;

    assert!(result.is_relevant);

    // The UTXO already existed from the mempool funding, but its
    // `is_confirmed` flag flipped from false → true. The changeset must
    // carry that transition so persistence replay can upsert the row.
    let utxo_cs = result
        .changeset
        .utxos
        .as_ref()
        .expect("confirmation upgrade must emit a utxo changeset");
    assert_eq!(utxo_cs.added.len(), 1, "the upgraded UTXO must be in `added`");
    let upgraded = utxo_cs.added.values().next().unwrap();
    assert!(upgraded.is_confirmed, "persisted UTXO must reflect the confirmation");
}

// ---------------------------------------------------------------------------
// Orchestrator: check_core_transaction accumulates changesets
// ---------------------------------------------------------------------------

#[tokio::test]
async fn check_core_transaction_populates_tx_utxo_balance_and_state_on_new_funding() {
    let mut ctx = TestWalletContext::new_random();
    let funding_tx = dashcore::Transaction::dummy(&ctx.receive_address, 0..1, &[500_000]);
    let result = ctx.check_transaction(&funding_tx, TransactionContext::Mempool).await;

    assert!(result.is_relevant);
    assert!(result.is_new_transaction);

    let tx_cs = result
        .changeset
        .transactions
        .as_ref()
        .expect("funding tx must populate transactions");
    assert!(tx_cs.records.contains_key(&funding_tx.txid()));

    let utxo_cs = result.changeset.utxos.as_ref().expect("funding tx must populate utxos");
    assert_eq!(utxo_cs.added.len(), 1);
    assert!(utxo_cs.spent.is_empty());

    let bal_cs = result.changeset.balance.as_ref().expect("balance must be populated");
    assert_eq!(bal_cs.unconfirmed_delta, 500_000);

    let state_cs = result
        .changeset
        .account_states
        .as_ref()
        .expect("account_states must be populated");
    assert!(state_cs.addresses_used.contains(&ctx.receive_address));
    // Gap-limit maintenance should have recorded the pool's highest reveal
    // for this account. We don't assert the exact index (depends on the
    // default gap limit) — just that *something* was recorded.
    assert!(
        !state_cs.highest_used.is_empty(),
        "gap-limit pass must record highest_used"
    );
}

#[tokio::test]
async fn check_core_transaction_confirmation_emits_transaction_context_delta() {
    use crate::transaction_checking::BlockInfo;
    use dashcore::BlockHash;
    use dashcore_hashes::Hash;

    let (mut ctx, tx) = TestWalletContext::new_random().with_mempool_funding(180_000).await;
    let txid = tx.txid();

    let block_hash = BlockHash::from_slice(&[17u8; 32]).expect("hash");
    let block_ctx = TransactionContext::InBlock(BlockInfo::new(700, block_hash, 1_700_000_000));
    let result = ctx.check_transaction(&tx, block_ctx).await;

    assert!(result.is_relevant);
    assert!(!result.is_new_transaction, "second call should not be 'new'");

    let tx_cs = result
        .changeset
        .transactions
        .as_ref()
        .expect("context update must emit a transactions changeset");
    let updated = tx_cs.records.get(&txid).expect("updated record must be present");
    assert!(updated.is_confirmed(), "updated record must reflect new block context");
}

// ---------------------------------------------------------------------------
// Merge semantics: multiple mutations accumulate into one changeset.
// (Kept here because it exercises the mutate-and-return pattern holistically
// rather than testing the Merge trait in isolation.)
// ---------------------------------------------------------------------------

#[test]
fn wallet_changeset_merge_combines_mutations_from_separate_sources() {
    use crate::changeset::{BalanceChangeSet, WalletChangeSet};

    let a_utxo = Utxo::dummy(1, 100, 1, false, true);
    let b_utxo = Utxo::dummy(2, 200, 1, false, true);

    let mut cs1 = WalletChangeSet::default();
    cs1.utxos
        .get_or_insert_with(Default::default)
        .added
        .insert(a_utxo.outpoint, a_utxo.clone());
    cs1.balance = Some(BalanceChangeSet {
        spendable_delta: 100,
        ..Default::default()
    });

    let mut cs2 = WalletChangeSet::default();
    {
        let utxo_cs = cs2.utxos.get_or_insert_with(Default::default);
        utxo_cs.added.insert(b_utxo.outpoint, b_utxo.clone());
        utxo_cs.instant_locked.insert(a_utxo.outpoint);
    }
    cs2.balance = Some(BalanceChangeSet {
        spendable_delta: 200,
        ..Default::default()
    });

    cs1.merge(cs2);

    let merged_utxos = cs1.utxos.expect("utxos should be present");
    assert_eq!(merged_utxos.added.len(), 2);
    assert_eq!(merged_utxos.instant_locked.len(), 1);

    let merged_bal = cs1.balance.expect("balance should be present");
    assert_eq!(merged_bal.spendable_delta, 300);
}
