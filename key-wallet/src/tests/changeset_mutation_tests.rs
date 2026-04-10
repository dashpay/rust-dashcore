//! Tests for BDK-style mutate-and-return changeset APIs on `ManagedCoreAccount`
//! and `ManagedWalletInfo`.
//!
//! All mutation methods return [`crate::changeset::WalletChangeSet`] with
//! the per-account delta already written into `cs.per_account[self_type]`.
//! Orchestrators accumulate via uniform `result.changeset.merge(cs)`; no
//! address-based routing happens at accumulation time.

use crate::account::{AccountType, StandardAccountType};
use crate::changeset::Merge;
use crate::managed_account::address_pool::AddressPoolType;
use crate::managed_account::ManagedCoreAccount;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::TransactionContext;
use crate::Utxo;

/// The default BIP44-0 account type produced by `TestWalletContext::new_random`.
fn bip44_0() -> AccountType {
    AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    }
}

// ---------------------------------------------------------------------------
// mark_address_used
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mark_address_used_populates_bucket_then_becomes_idempotent() {
    let mut ctx = TestWalletContext::new_random();
    let addr = ctx.receive_address.clone();

    // First call — address transitions from unused → used, per-account
    // bucket carries it.
    let (changed, cs) = ctx
        .managed_wallet
        .first_bip44_managed_account_mut()
        .expect("bip44 account")
        .mark_address_used(&addr);
    assert!(changed, "first call must mark the address");

    let bucket = cs.per_account.get(&bip44_0()).expect("bip44-0 bucket must exist");
    assert_eq!(bucket.addresses_used.len(), 1);
    assert!(bucket.addresses_used.contains(&addr));
    assert!(bucket.highest_used.is_empty());
    assert!(bucket.utxos_added.is_empty());
    assert!(bucket.transactions.is_empty());
    // No wallet-level sub-changesets for a pure address-mark.
    assert!(cs.balance.is_none());
    assert!(cs.chain.is_none());

    // Second call on the same address — no-op, empty changeset.
    let (changed, cs) = ctx
        .managed_wallet
        .first_bip44_managed_account_mut()
        .expect("bip44 account")
        .mark_address_used(&addr);
    assert!(!changed);
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

    // First call — UTXO transitions to IS-locked.
    let (changed, cs) = account.mark_utxos_instant_send(&txid);
    assert!(changed);
    let bucket = cs.per_account.get(&bip44_0()).expect("bip44-0 bucket");
    assert_eq!(bucket.utxos_instant_locked.len(), 1);
    assert!(bucket.utxos_instant_locked.contains(&outpoint));
    assert!(bucket.utxos_added.is_empty());
    assert!(bucket.utxos_spent.is_empty());

    // Second call — no state change, empty changeset.
    let (changed, cs) = account.mark_utxos_instant_send(&txid);
    assert!(!changed);
    assert!(cs.is_empty());
}

// ---------------------------------------------------------------------------
// update_transaction_context — in-place record update helper
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

    // First call — context transitions mempool → block.
    let cs = account.update_transaction_context(&txid, block_ctx.clone());
    let bucket = cs.per_account.get(&bip44_0()).expect("bip44-0 bucket");
    assert_eq!(bucket.transactions.len(), 1);
    assert!(bucket.transactions[0].is_confirmed());

    // Second call with the same context — no-op.
    let cs = account.update_transaction_context(&txid, block_ctx);
    assert!(cs.is_empty(), "same-context update must be a no-op");

    // Unknown txid — no-op.
    let phantom = dashcore::Txid::from_slice(&[99u8; 32]).expect("hash");
    let cs = account.update_transaction_context(&phantom, TransactionContext::Mempool);
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
    assert!(cs.is_empty());

    // Add a second UTXO → positive delta.
    let utxo2 = Utxo::dummy(2, 250_000, 10, false, true);
    account.insert_utxo(utxo2.outpoint, utxo2);
    let cs = account.update_balance(100);
    let bal_cs = cs.balance.expect("balance must be populated");
    assert_eq!(bal_cs.spendable_delta, 250_000);

    // Remove the first UTXO → negative delta.
    account.remove_utxo(&outpoint);
    let cs = account.update_balance(100);
    let bal_cs = cs.balance.expect("balance must be populated");
    assert_eq!(bal_cs.spendable_delta, -100_000);
}

// ---------------------------------------------------------------------------
// update_utxos (via confirm_transaction): context upgrade must emit a
// bucket entry so a persister replay doesn't leave a stale Utxo.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn confirming_mempool_tx_emits_utxo_delta_for_context_upgrade() {
    use crate::transaction_checking::BlockInfo;
    use dashcore::BlockHash;
    use dashcore_hashes::Hash;

    let (mut ctx, tx) = TestWalletContext::new_random().with_mempool_funding(300_000).await;

    let block_hash = BlockHash::from_slice(&[7u8; 32]).expect("hash");
    let block_ctx =
        TransactionContext::InBlock(BlockInfo::new(600, block_hash, 1_700_000_000));
    let result = ctx.check_transaction(&tx, block_ctx).await;
    assert!(result.is_relevant);

    let bucket = result
        .changeset
        .per_account
        .get(&bip44_0())
        .expect("bip44-0 bucket must be populated on confirmation upgrade");
    assert_eq!(bucket.utxos_added.len(), 1, "upgraded UTXO must be in utxos_added");
    let upgraded = bucket.utxos_added.values().next().expect("utxo");
    assert!(upgraded.is_confirmed);
}

// ---------------------------------------------------------------------------
// Orchestrator: check_core_transaction accumulates per_account deltas
// ---------------------------------------------------------------------------

#[tokio::test]
async fn check_core_transaction_populates_bucket_and_balance_on_new_funding() {
    let mut ctx = TestWalletContext::new_random();
    let funding_tx = dashcore::Transaction::dummy(&ctx.receive_address, 0..1, &[500_000]);
    let result = ctx.check_transaction(&funding_tx, TransactionContext::Mempool).await;
    assert!(result.is_relevant);
    assert!(result.is_new_transaction);

    let bucket = result
        .changeset
        .per_account
        .get(&bip44_0())
        .expect("bip44-0 bucket must be populated");
    assert_eq!(bucket.transactions.len(), 1);
    assert_eq!(bucket.transactions[0].transaction.txid(), funding_tx.txid());
    assert_eq!(bucket.utxos_added.len(), 1);
    assert!(bucket.utxos_spent.is_empty());
    assert!(
        bucket.addresses_used.contains(&ctx.receive_address),
        "funded address must be in addresses_used"
    );
    assert!(
        !bucket.highest_used.is_empty(),
        "gap-limit pass must record highest_used for the external pool"
    );
    assert!(bucket.highest_used.contains_key(&AddressPoolType::External));

    // Balance lives at the wallet level, not per-account.
    let bal_cs = result.changeset.balance.as_ref().expect("balance must be populated");
    assert_eq!(bal_cs.unconfirmed_delta, 500_000);
}

#[tokio::test]
async fn check_core_transaction_confirmation_emits_transaction_delta() {
    use crate::transaction_checking::BlockInfo;
    use dashcore::BlockHash;
    use dashcore_hashes::Hash;

    let (mut ctx, tx) = TestWalletContext::new_random().with_mempool_funding(180_000).await;
    let txid = tx.txid();

    let block_hash = BlockHash::from_slice(&[17u8; 32]).expect("hash");
    let block_ctx =
        TransactionContext::InBlock(BlockInfo::new(700, block_hash, 1_700_000_000));
    let result = ctx.check_transaction(&tx, block_ctx).await;
    assert!(result.is_relevant);
    assert!(!result.is_new_transaction);

    let bucket = result
        .changeset
        .per_account
        .get(&bip44_0())
        .expect("bip44-0 bucket must carry the updated record");
    let updated = bucket
        .transactions
        .iter()
        .find(|r| r.transaction.txid() == txid)
        .expect("updated record must be present");
    assert!(updated.is_confirmed());
}

// ---------------------------------------------------------------------------
// Merge semantics: multiple mutations accumulate into one changeset
// ---------------------------------------------------------------------------

#[test]
fn wallet_changeset_merge_combines_mutations_from_separate_sources() {
    use crate::changeset::{AccountChangeSet, BalanceChangeSet, WalletChangeSet};

    let a_utxo = Utxo::dummy(1, 100, 1, false, true);
    let b_utxo = Utxo::dummy(2, 200, 1, false, true);

    let mut cs1 = WalletChangeSet::default();
    cs1.account_bucket(bip44_0())
        .utxos_added
        .insert(a_utxo.outpoint, a_utxo.clone());
    cs1.balance = Some(BalanceChangeSet {
        spendable_delta: 100,
        ..Default::default()
    });

    let mut cs2 = WalletChangeSet::default();
    {
        let bucket: &mut AccountChangeSet = cs2.account_bucket(bip44_0());
        bucket.utxos_added.insert(b_utxo.outpoint, b_utxo.clone());
        bucket.utxos_instant_locked.insert(a_utxo.outpoint);
    }
    cs2.balance = Some(BalanceChangeSet {
        spendable_delta: 200,
        ..Default::default()
    });

    cs1.merge(cs2);

    let merged_bucket = cs1.per_account.get(&bip44_0()).expect("bip44-0 bucket");
    assert_eq!(merged_bucket.utxos_added.len(), 2);
    assert_eq!(merged_bucket.utxos_instant_locked.len(), 1);

    let merged_bal = cs1.balance.expect("balance should be present");
    assert_eq!(merged_bal.spendable_delta, 300);
}
