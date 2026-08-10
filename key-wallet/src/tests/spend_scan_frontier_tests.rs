//! Tests for the spend-scan frontier gate on coin selection.
//!
//! A wallet catching up on history applies blocks in ascending order, so a
//! receive it discovers says nothing about whether some higher, not-yet-scanned
//! block already spends it. Selecting such an output builds a transaction the
//! network settled as a double-spend long ago; peers drop it silently, with no
//! reject message, and whatever it was funding is stranded forever.
//!
//! The heights here are the ones from the incident that motivated this: a
//! restored wallet found a 1000 DASH receive in block 758983 and funded an
//! identity top-up from it three seconds later, while the block that had
//! already spent that outpoint — height 1510203 — was still six minutes of
//! scanning away.

use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::hashes::Hash;
use dashcore::{BlockHash, TxIn};

use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext};
use crate::wallet::managed_wallet_info::coin_selection::{
    CoinSelector, SelectionError, SelectionStrategy,
};
use crate::wallet::managed_wallet_info::fee::FeeRate;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;

/// Heights from the incident.
const RECEIVE_HEIGHT: u32 = 758_983;
const SPEND_HEIGHT: u32 = 1_510_203;
const CHAIN_TIP: u32 = 2_200_000;

fn block_at(height: u32) -> TransactionContext {
    TransactionContext::InBlock(BlockInfo::new(
        height,
        BlockHash::from_slice(&[(height % 251) as u8; 32]).expect("hash"),
        1_700_000_000,
    ))
}

/// A transaction spending `outpoint`, standing in for the wallet's own earlier
/// asset lock that consumed the coin long before this restore.
fn spending_tx(outpoint: OutPoint) -> Transaction {
    Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: outpoint,
            ..Default::default()
        }],
        output: Vec::new(),
        special_transaction_payload: None,
    }
}

/// Ask coin selection for `target` duffs out of the wallet's BIP44 account,
/// exactly as the transaction builder does.
fn select(ctx: &TestWalletContext, target: u64) -> Result<u64, SelectionError> {
    let account = ctx.bip44_account();
    let utxos: Vec<_> = account.utxos.values().collect();
    CoinSelector::new(SelectionStrategy::BranchAndBound)
        .select_coins(utxos, target, FeeRate::normal(), ctx.managed_wallet.last_processed_height())
        .map(|selection| selection.total_value)
}

/// Put the wallet in the state a restore lands in: scanning toward the chain
/// tip from far below it, having applied a receive at `RECEIVE_HEIGHT`.
async fn restored_wallet_mid_catch_up(amount: u64) -> (TestWalletContext, Transaction) {
    let mut ctx = TestWalletContext::new_random();
    ctx.managed_wallet.update_scan_target_height(CHAIN_TIP);
    ctx.managed_wallet.update_synced_height(RECEIVE_HEIGHT);
    ctx.managed_wallet.update_last_processed_height(RECEIVE_HEIGHT);

    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[amount]);
    let result = ctx.check_transaction(&tx, block_at(RECEIVE_HEIGHT)).await;
    assert!(result.is_relevant, "wallet must recognise its own receive");

    (ctx, tx)
}

#[tokio::test]
async fn receive_found_below_the_scan_target_is_tracked_but_not_selectable() {
    let (ctx, tx) = restored_wallet_mid_catch_up(100_000_000_000).await;

    let utxo = ctx.first_utxo();
    assert_eq!(utxo.outpoint.txid, tx.txid(), "the receive is tracked");
    assert!(utxo.is_confirmed, "and it is confirmed in a block");
    assert!(!utxo.spend_scanned, "but the scan has not passed it yet");

    assert!(
        !ctx.managed_wallet.spend_scan_complete(),
        "the wallet must report itself mid-catch-up"
    );
    assert!(
        ctx.managed_wallet.get_spendable_utxos().is_empty(),
        "nothing is spendable while the scan is behind"
    );
    assert!(
        matches!(select(&ctx, 1_000_000), Err(SelectionError::NoUtxosAvailable)),
        "coin selection must refuse to fund from an unscanned receive"
    );
}

#[tokio::test]
async fn scan_reaching_its_target_releases_the_held_back_receive() {
    let (mut ctx, _tx) = restored_wallet_mid_catch_up(100_000_000_000).await;

    // Catch-up finishes: every block up to the tip has been scanned and no
    // spend of this outpoint turned up, so the coin is genuinely unspent.
    ctx.managed_wallet.update_synced_height(CHAIN_TIP);
    ctx.managed_wallet.update_last_processed_height(CHAIN_TIP);

    assert!(ctx.managed_wallet.spend_scan_complete());
    assert!(ctx.first_utxo().spend_scanned, "the scan has now covered it");
    assert_eq!(ctx.managed_wallet.get_spendable_utxos().len(), 1, "and it becomes spendable");
    assert_eq!(select(&ctx, 1_000_000).expect("selection succeeds"), 100_000_000_000);
}

/// The incident itself: the coin was already spent, by this wallet's own
/// earlier transaction, in a block the restore had not reached yet.
#[tokio::test]
async fn coin_already_spent_above_the_frontier_is_never_selectable() {
    let (mut ctx, tx) = restored_wallet_mid_catch_up(100_000_000_000).await;
    let outpoint = ctx.first_utxo().outpoint;

    // This is the window in which the top-up asset lock was built.
    assert!(
        select(&ctx, 1_000_000).is_err(),
        "the double-spend must not be fundable during catch-up"
    );

    // The scan reaches the block that spent it.
    ctx.managed_wallet.update_synced_height(SPEND_HEIGHT);
    let spend = spending_tx(outpoint);
    ctx.check_transaction(&spend, block_at(SPEND_HEIGHT)).await;

    // ...and then finishes.
    ctx.managed_wallet.update_synced_height(CHAIN_TIP);
    ctx.managed_wallet.update_last_processed_height(CHAIN_TIP);

    assert!(ctx.bip44_account().utxos.get(&outpoint).is_none(), "the spend removed the coin");
    assert!(
        ctx.managed_wallet.get_spendable_utxos().is_empty(),
        "so a completed scan releases nothing"
    );
    assert_ne!(tx.txid(), spend.txid());
}

#[tokio::test]
async fn receive_at_the_scan_target_is_selectable_immediately() {
    let mut ctx = TestWalletContext::new_random();
    ctx.managed_wallet.update_scan_target_height(CHAIN_TIP);
    ctx.managed_wallet.update_synced_height(CHAIN_TIP);
    ctx.managed_wallet.update_last_processed_height(CHAIN_TIP);

    // A block at the tip: nothing above it exists to have spent this output,
    // so a caught-up wallet must not be made to wait for the next batch commit.
    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[500_000]);
    ctx.check_transaction(&tx, block_at(CHAIN_TIP)).await;

    assert!(ctx.first_utxo().spend_scanned);
    assert_eq!(select(&ctx, 100_000).expect("selection succeeds"), 500_000);
}

#[tokio::test]
async fn mempool_receive_during_catch_up_stays_selectable() {
    let mut ctx = TestWalletContext::new_random();
    ctx.managed_wallet.update_scan_target_height(CHAIN_TIP);
    ctx.managed_wallet.update_synced_height(RECEIVE_HEIGHT);
    ctx.managed_wallet.update_last_processed_height(RECEIVE_HEIGHT);

    // A mempool transaction is at the tip by definition — no historical block
    // can have spent an output that does not exist historically.
    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[500_000]);
    ctx.check_transaction(&tx, TransactionContext::Mempool).await;

    assert!(ctx.first_utxo().spend_scanned);
    assert_eq!(select(&ctx, 100_000).expect("selection succeeds"), 500_000);
}

/// Consumers with no scanner never report a target, and must keep the
/// pre-existing unconditional behavior.
#[tokio::test]
async fn without_a_reported_scan_target_the_gate_stays_open() {
    let mut ctx = TestWalletContext::new_random();
    ctx.managed_wallet.update_last_processed_height(RECEIVE_HEIGHT);

    let tx = Transaction::dummy(&ctx.receive_address, 0..1, &[500_000]);
    ctx.check_transaction(&tx, block_at(RECEIVE_HEIGHT)).await;

    assert_eq!(ctx.managed_wallet.scan_target_height(), 0);
    assert!(ctx.managed_wallet.spend_scan_complete());
    assert!(ctx.first_utxo().spend_scanned);
    assert_eq!(select(&ctx, 100_000).expect("selection succeeds"), 500_000);
}

/// A UTXO deserialized from persistence written before `spend_scanned` existed
/// must not become unspendable on upgrade.
#[cfg(feature = "serde")]
#[test]
fn utxo_missing_the_field_deserializes_as_scanned() {
    let utxo = crate::Utxo::dummy(1, 500_000, 100, false, true);
    let mut value = serde_json::to_value(&utxo).expect("serialize");
    value.as_object_mut().expect("object").remove("spend_scanned");

    let restored: crate::Utxo = serde_json::from_value(value).expect("deserialize");
    assert!(restored.spend_scanned, "legacy rows keep the old behavior");
    assert!(restored.is_spendable(200));
}
