//! Rescans of a block that pays addresses past the gap limit, re-delivered after each pass that
//! derives new addresses. The coins, the record the events carry and the balance must not depend on
//! when the ChainLock arrives: before the first pass, between passes, or never.

use super::test_helpers::*;
use super::*;
use crate::wallet_interface::WalletInterface;
use dashcore::block::Block;
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::{ScriptBuf, TxOut};
use key_wallet::managed_account::managed_account_trait::ManagedAccountTrait;
use key_wallet::managed_account::managed_account_type::ManagedAccountType;
use key_wallet::managed_account::managed_core_funds_account::ManagedCoreFundsAccount;
use key_wallet::managed_account::transaction_record::OutputRole;
use key_wallet::{AddressPool, KeySource};
use std::collections::BTreeSet;

const HEIGHT: CoreBlockHeight = 100;
const MAX_PASSES: usize = 16;

#[derive(Clone, Copy, Debug)]
enum ChainLockAt {
    BeforeFirstPass,
    BetweenPasses,
    Never,
}

fn account<'a>(manager: &'a WalletManager, wallet_id: &WalletId) -> &'a ManagedCoreFundsAccount {
    manager
        .get_wallet_info(wallet_id)
        .expect("wallet info")
        .first_bip44_managed_account()
        .expect("BIP44 account 0")
}

fn external_pool(manager: &WalletManager, wallet_id: &WalletId) -> AddressPool {
    match account(manager, wallet_id).managed_account_type() {
        ManagedAccountType::Standard {
            external_addresses,
            ..
        } => external_addresses.clone(),
        other => panic!("BIP44 account 0 has an unexpected type {other:?}"),
    }
}

/// The BIP44 account 0 external address at `index`, derived on a copy of the
/// pool so the wallet's own pool stays as it is.
fn external_address(manager: &WalletManager, wallet_id: &WalletId, index: u32) -> Address {
    let wallet = manager.get_wallet(wallet_id).expect("wallet");
    let xpub = wallet.get_bip44_account(0).expect("BIP44 account 0").account_xpub;
    let mut pool = external_pool(manager, wallet_id);
    pool.generate_up_to(index, &KeySource::Public(xpub)).expect("derives");
    pool.address_at_index(index).expect("derived")
}

fn paying_external(
    manager: &WalletManager,
    wallet_id: &WalletId,
    indices: impl IntoIterator<Item = u32>,
    input_seed: u8,
) -> Transaction {
    let output = indices
        .into_iter()
        .map(|index| TxOut {
            value: TX_AMOUNT,
            script_pubkey: external_address(manager, wallet_id, index).script_pubkey(),
        })
        .collect();
    create_tx([OutPoint::new(Txid::from_byte_array([input_seed; 32]), 0)], output)
}

fn spending_to_nobody(outpoints: impl IntoIterator<Item = OutPoint>) -> Transaction {
    let output = TxOut {
        value: TX_AMOUNT / 2,
        script_pubkey: ScriptBuf::new_op_return(&[0x57]),
    };
    create_tx(outpoints, vec![output])
}

/// One pass over `block`. Returns whether it derived new scripts, which is
/// what makes the filter rescan deliver the block again.
async fn pass(
    manager: &mut WalletManager,
    wallet_id: WalletId,
    block: &Block,
    height: CoreBlockHeight,
) -> bool {
    let wallets = BTreeSet::from([wallet_id]);
    let result =
        manager.process_block_for_wallets(block, block.block_hash(), height, &wallets).await;
    result.new_scripts.values().any(|scripts| !scripts.is_empty())
}

/// Processes `block` like the filter pipeline does: once, then again while a
/// pass derives new scripts. Applies the ChainLock at `chain_lock_at`.
async fn process_with_rescans(
    manager: &mut WalletManager,
    wallet_id: WalletId,
    block: &Block,
    chain_lock_at: ChainLockAt,
) {
    if matches!(chain_lock_at, ChainLockAt::BeforeFirstPass) {
        manager.apply_chain_lock(ChainLock::dummy(HEIGHT + 10));
    }
    let mut derived = pass(manager, wallet_id, block, HEIGHT).await;
    if matches!(chain_lock_at, ChainLockAt::BetweenPasses) {
        manager.apply_chain_lock(ChainLock::dummy(HEIGHT));
    }
    for _ in 0..MAX_PASSES {
        if !derived {
            return;
        }
        derived = pass(manager, wallet_id, block, HEIGHT).await;
    }
    panic!("the rescan passes did not settle");
}

/// The rescan re-delivers the funding block and the block after it in height
/// order, as the filters of the newly derived scripts match both, until no
/// pass derives new scripts.
async fn rescan_in_height_order(
    manager: &mut WalletManager,
    wallet_id: WalletId,
    funding: &Block,
    spends: &Block,
) {
    for _ in 0..MAX_PASSES {
        let derived = pass(manager, wallet_id, funding, HEIGHT).await;
        let derived_next = pass(manager, wallet_id, spends, HEIGHT + 1).await;
        if !derived && !derived_next {
            return;
        }
    }
    panic!("the rescan passes did not settle");
}

fn assert_no_observed_spends(manager: &WalletManager, wallet_id: &WalletId) {
    let info = manager.get_wallet_info(wallet_id).expect("wallet info");
    let observed = info.observed_spent_outpoints();
    assert!(observed.is_empty(), "the checkpoint left observed spends {observed:?}");
}

fn held_vouts(manager: &WalletManager, wallet_id: &WalletId, txid: &Txid) -> BTreeSet<u32> {
    let utxos = account(manager, wallet_id).utxos.keys();
    utxos.filter(|outpoint| outpoint.txid == *txid).map(|outpoint| outpoint.vout).collect()
}

/// The record for `txid` a store mirroring the `BlockProcessed` events would
/// hold: the last one any of them carried, inserted or updated.
fn last_emitted(events: &[WalletEvent], txid: &Txid) -> TransactionRecord {
    events
        .iter()
        .filter_map(|event| match event {
            WalletEvent::BlockProcessed {
                inserted,
                updated,
                ..
            } => Some(inserted.iter().chain(updated)),
            _ => None,
        })
        .flatten()
        .rfind(|record| record.txid == *txid)
        .cloned()
        .unwrap_or_else(|| panic!("no BlockProcessed event carried {txid}"))
}

fn owned_output_indices(record: &TransactionRecord) -> BTreeSet<u32> {
    record
        .output_details
        .iter()
        .filter(|detail| matches!(detail.role, OutputRole::Received | OutputRole::Change))
        .map(|detail| detail.index)
        .collect()
}

fn assert_credited_in_full(
    manager: &WalletManager,
    wallet_id: &WalletId,
    events: &[WalletEvent],
    tx: &Transaction,
    chain_lock_at: ChainLockAt,
) {
    let txid = tx.txid();
    let all: BTreeSet<u32> = (0..tx.output.len() as u32).collect();
    let paid = (TX_AMOUNT * tx.output.len() as u64) as i64;
    assert_eq!(held_vouts(manager, wallet_id, &txid), all, "{chain_lock_at:?}: coins held");
    let record = last_emitted(events, &txid);
    assert_eq!(owned_output_indices(&record), all, "{chain_lock_at:?}: emitted record owns");
    assert_eq!(record.net_amount, paid, "{chain_lock_at:?}: emitted net amount");
    if let Some(stored) = account(manager, wallet_id).transactions().get(&txid) {
        assert_eq!(owned_output_indices(stored), all, "{chain_lock_at:?}: stored record owns");
        assert_eq!(stored.net_amount, paid, "{chain_lock_at:?}: stored net amount");
    }
}

fn assert_balance(
    manager: &WalletManager,
    wallet_id: &WalletId,
    expected: u64,
    chain_lock_at: ChainLockAt,
) {
    let balance = manager.get_wallet_info(wallet_id).expect("wallet info").balance();
    assert_eq!(balance.total(), expected, "{chain_lock_at:?}: balance");
}

/// One transaction paying a contiguous run of external addresses from index 0
/// to well past the gap limit.
async fn run_past_the_gap_limit(chain_lock_at: ChainLockAt) {
    let (mut manager, wallet_id, _) = setup_manager_with_wallet();
    let gap = external_pool(&manager, &wallet_id).gap_limit;
    let tx = paying_external(&manager, &wallet_id, 0..gap + gap / 2, 0x57);
    let block = Block::dummy(HEIGHT, vec![tx.clone()]);
    let mut rx = manager.subscribe_events();

    process_with_rescans(&mut manager, wallet_id, &block, chain_lock_at).await;

    let events = drain_events(&mut rx);
    assert_credited_in_full(&manager, &wallet_id, &events, &tx, chain_lock_at);
    assert_balance(&manager, &wallet_id, TX_AMOUNT * tx.output.len() as u64, chain_lock_at);
}

#[tokio::test]
async fn test_born_chainlocked_rescan_credits_a_run_past_the_gap_limit() {
    run_past_the_gap_limit(ChainLockAt::BeforeFirstPass).await;
}

#[tokio::test]
async fn test_chain_lock_between_passes_keeps_a_run_past_the_gap_limit() {
    run_past_the_gap_limit(ChainLockAt::BetweenPasses).await;
}

#[tokio::test]
async fn test_unchainlocked_rescan_emits_a_record_owning_a_run_past_the_gap_limit() {
    run_past_the_gap_limit(ChainLockAt::Never).await;
}

/// The block's first transaction pays index 0 and an index the window only
/// reaches after the block's second transaction, which pays inside the
/// window, extends it: only a re-delivery can find the first one's far output.
fn late_and_extending(manager: &WalletManager, wallet_id: &WalletId) -> (Transaction, Transaction) {
    let gap = external_pool(manager, wallet_id).gap_limit;
    let late = paying_external(manager, wallet_id, [0, gap + gap / 3], 0x51);
    let extending = paying_external(manager, wallet_id, [gap * 2 / 3], 0x52);
    (late, extending)
}

async fn output_a_later_payment_derives(chain_lock_at: ChainLockAt) {
    let (mut manager, wallet_id, _) = setup_manager_with_wallet();
    let (late, extending) = late_and_extending(&manager, &wallet_id);
    let block = Block::dummy(HEIGHT, vec![late.clone(), extending.clone()]);
    let mut rx = manager.subscribe_events();

    process_with_rescans(&mut manager, wallet_id, &block, chain_lock_at).await;

    let events = drain_events(&mut rx);
    assert_credited_in_full(&manager, &wallet_id, &events, &late, chain_lock_at);
    assert_credited_in_full(&manager, &wallet_id, &events, &extending, chain_lock_at);
    assert_balance(&manager, &wallet_id, 3 * TX_AMOUNT, chain_lock_at);
}

#[tokio::test]
async fn test_born_chainlocked_rescan_credits_an_output_a_later_payment_derives() {
    output_a_later_payment_derives(ChainLockAt::BeforeFirstPass).await;
}

#[tokio::test]
async fn test_chain_lock_between_passes_credits_an_output_a_later_payment_derives() {
    output_a_later_payment_derives(ChainLockAt::BetweenPasses).await;
}

#[tokio::test]
async fn test_unchainlocked_rescan_emits_the_record_an_output_a_later_payment_derives_corrects() {
    output_a_later_payment_derives(ChainLockAt::Never).await;
}

/// A late output and a held output, both spent in the next block, must end spent once the rescan
/// has re-delivered both blocks. After the observed spends are pruned, the funding block's
/// re-delivery credits the late output until the next block's re-delivery spends it.
async fn spent_outputs_stay_spent(chain_lock_at: ChainLockAt) {
    let (mut manager, wallet_id, _) = setup_manager_with_wallet();
    let (late, extending) = late_and_extending(&manager, &wallet_id);
    let funding = Block::dummy(HEIGHT, vec![late.clone(), extending.clone()]);
    let spends = Block::dummy(
        HEIGHT + 1,
        vec![
            spending_to_nobody([OutPoint::new(late.txid(), 0)]),
            spending_to_nobody([OutPoint::new(late.txid(), 1)]),
        ],
    );
    if matches!(chain_lock_at, ChainLockAt::BeforeFirstPass) {
        manager.apply_chain_lock(ChainLock::dummy(HEIGHT + 10));
    }
    pass(&mut manager, wallet_id, &funding, HEIGHT).await;
    pass(&mut manager, wallet_id, &spends, HEIGHT + 1).await;
    if !matches!(chain_lock_at, ChainLockAt::Never) {
        manager.apply_chain_lock(ChainLock::dummy(HEIGHT + 10));
        // The committed checkpoint lifts the finality boundary over both
        // blocks, which prunes the spends observed in them.
        manager.update_wallet_synced_height(&wallet_id, HEIGHT + 1);
        assert_no_observed_spends(&manager, &wallet_id);
    }
    rescan_in_height_order(&mut manager, wallet_id, &funding, &spends).await;

    let late_coins = held_vouts(&manager, &wallet_id, &late.txid());
    assert!(late_coins.is_empty(), "{chain_lock_at:?}: late coins {late_coins:?}");
    let extending_coins = held_vouts(&manager, &wallet_id, &extending.txid());
    assert_eq!(extending_coins, BTreeSet::from([0]), "{chain_lock_at:?}: extending coins");
    assert_balance(&manager, &wallet_id, TX_AMOUNT, chain_lock_at);
}

#[tokio::test]
async fn test_born_chainlocked_rescan_keeps_late_outputs_spent() {
    spent_outputs_stay_spent(ChainLockAt::BeforeFirstPass).await;
}

#[tokio::test]
async fn test_chain_locked_rescan_keeps_late_outputs_spent() {
    spent_outputs_stay_spent(ChainLockAt::BetweenPasses).await;
}

#[tokio::test]
async fn test_unchainlocked_rescan_keeps_late_outputs_spent() {
    spent_outputs_stay_spent(ChainLockAt::Never).await;
}

/// One spender in the next block spends the held output and the late one. Reloading the account
/// through serde after the checkpoint rebuilds its spent marks from the records finality kept, and
/// the rescan must still end with both coins spent.
#[tokio::test]
async fn test_rescan_after_an_account_reload_keeps_late_outputs_spent() {
    let (mut manager, wallet_id, _) = setup_manager_with_wallet();
    let (late, extending) = late_and_extending(&manager, &wallet_id);
    let funding = Block::dummy(HEIGHT, vec![late.clone(), extending.clone()]);
    let both = [OutPoint::new(late.txid(), 0), OutPoint::new(late.txid(), 1)];
    let spends = Block::dummy(HEIGHT + 1, vec![spending_to_nobody(both)]);
    manager.apply_chain_lock(ChainLock::dummy(HEIGHT + 10));
    pass(&mut manager, wallet_id, &funding, HEIGHT).await;
    pass(&mut manager, wallet_id, &spends, HEIGHT + 1).await;
    manager.update_wallet_synced_height(&wallet_id, HEIGHT + 1);
    assert_no_observed_spends(&manager, &wallet_id);

    let info = manager.get_wallet_info_mut(&wallet_id).expect("wallet info");
    let account = info.first_bip44_managed_account_mut().expect("BIP44 account 0");
    let config = bincode::config::standard();
    let bytes = bincode::serde::encode_to_vec(&*account, config).expect("encodes");
    *account = bincode::serde::decode_from_slice(&bytes, config).expect("decodes").0;

    rescan_in_height_order(&mut manager, wallet_id, &funding, &spends).await;

    let late_coins = held_vouts(&manager, &wallet_id, &late.txid());
    assert!(late_coins.is_empty(), "late coins {late_coins:?}");
    assert_eq!(held_vouts(&manager, &wallet_id, &extending.txid()), BTreeSet::from([0]));
    assert_balance(&manager, &wallet_id, TX_AMOUNT, ChainLockAt::BeforeFirstPass);
}
