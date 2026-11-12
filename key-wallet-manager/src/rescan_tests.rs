use super::test_helpers::*;
use super::*;
use crate::wallet_interface::WalletInterface;
use dashcore::block::Block;
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::{ScriptBuf, TxIn, TxOut};
use key_wallet::managed_account::managed_account_trait::ManagedAccountTrait;
use key_wallet::managed_account::managed_account_type::ManagedAccountType;
use key_wallet::managed_account::managed_core_funds_account::ManagedCoreFundsAccount;
use key_wallet::managed_account::transaction_record::OutputRole;
use key_wallet::{AddressPool, KeySource};
use std::collections::BTreeSet;

const HEIGHT: CoreBlockHeight = 100;
const MAX_PASSES: usize = 16;

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

/// The BIP44 account 0 external addresses at `indices`, derived on a copy of the
/// pool so the wallet's own pool stays as it is.
fn external_addresses(
    manager: &WalletManager,
    wallet_id: &WalletId,
    indices: &[u32],
) -> Vec<Address> {
    let wallet = manager.get_wallet(wallet_id).expect("wallet");
    let xpub = wallet.get_bip44_account(0).expect("BIP44 account 0").account_xpub;
    let mut pool = external_pool(manager, wallet_id);
    indices
        .iter()
        .map(|&index| {
            pool.generate_up_to(index, &KeySource::Public(xpub)).expect("derives");
            pool.address_at_index(index).expect("derived")
        })
        .collect()
}

fn spending(outpoints: impl IntoIterator<Item = OutPoint>) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: outpoints
            .into_iter()
            .map(|previous_output| TxIn {
                previous_output,
                ..TxIn::default()
            })
            .collect(),
        output: vec![TxOut {
            value: TX_AMOUNT / 2,
            script_pubkey: ScriptBuf::new_op_return(&[0x57]),
        }],
        special_transaction_payload: None,
    }
}

/// Returns two payments for one block. `late` pays index 0 and an index past the window.
/// `extending` pays inside the window and extends it over that index, so only a re-delivery
/// credits `late`'s far output.
fn late_and_extending(manager: &WalletManager, wallet_id: &WalletId) -> (Transaction, Transaction) {
    let gap = external_pool(manager, wallet_id).gap_limit;
    let late = create_tx_paying(&external_addresses(manager, wallet_id, &[0, gap + gap / 3]), 0x51);
    let extending = create_tx_paying(&external_addresses(manager, wallet_id, &[gap * 2 / 3]), 0x52);
    (late, extending)
}

/// Delivers `blocks` in order, then again while a pass derives new scripts, as the filter
/// rescan does. `after_first_pass` runs between the first pass and the re-deliveries.
async fn rescan(
    manager: &mut WalletManager,
    wallet_id: WalletId,
    blocks: &[(CoreBlockHeight, &Block)],
    after_first_pass: impl FnOnce(&mut WalletManager),
) {
    let wallets = BTreeSet::from([wallet_id]);
    let mut after_first_pass = Some(after_first_pass);
    for _ in 0..MAX_PASSES {
        let mut derived = false;
        for &(height, block) in blocks {
            let result = manager
                .process_block_for_wallets(block, block.block_hash(), height, &wallets)
                .await;
            derived |= result.new_scripts.values().any(|scripts| !scripts.is_empty());
        }
        if let Some(after_first_pass) = after_first_pass.take() {
            assert!(derived, "the first pass derived no new scripts");
            after_first_pass(manager);
        } else if !derived {
            return;
        }
    }
    panic!("the rescan passes did not settle");
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
) {
    let txid = tx.txid();
    let all: BTreeSet<u32> = (0..tx.output.len() as u32).collect();
    let paid = (TX_AMOUNT * tx.output.len() as u64) as i64;
    assert_eq!(held_vouts(manager, wallet_id, &txid), all, "coins held");
    let record = last_emitted(events, &txid);
    assert_eq!(owned_output_indices(&record), all, "emitted record owns");
    assert_eq!(record.net_amount, paid, "emitted net amount");
    if let Some(stored) = account(manager, wallet_id).transactions().get(&txid) {
        assert_eq!(owned_output_indices(stored), all, "stored record owns");
        assert_eq!(stored.net_amount, paid, "stored net amount");
    }
}

fn assert_balance(manager: &WalletManager, wallet_id: &WalletId, expected: u64) {
    let balance = manager.get_wallet_info(wallet_id).expect("wallet info").balance();
    assert_eq!(balance.total(), expected, "balance");
}

#[tokio::test]
async fn test_chain_lock_between_passes_credits_an_output_a_later_payment_derives() {
    let (mut manager, wallet_id, _) = setup_manager_with_wallet();
    let (late, extending) = late_and_extending(&manager, &wallet_id);
    let block = Block::dummy(HEIGHT, vec![late.clone(), extending.clone()]);
    let mut rx = manager.subscribe_events();

    rescan(&mut manager, wallet_id, &[(HEIGHT, &block)], |manager| {
        manager.apply_chain_lock(ChainLock::dummy(HEIGHT));
    })
    .await;

    let events = drain_events(&mut rx);
    assert_credited_in_full(&manager, &wallet_id, &events, &late);
    assert_credited_in_full(&manager, &wallet_id, &events, &extending);
    assert_balance(&manager, &wallet_id, 3 * TX_AMOUNT);
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
    let spends = Block::dummy(HEIGHT + 1, vec![spending(both)]);
    manager.apply_chain_lock(ChainLock::dummy(HEIGHT + 10));

    rescan(&mut manager, wallet_id, &[(HEIGHT, &funding), (HEIGHT + 1, &spends)], |manager| {
        manager.update_wallet_synced_height(&wallet_id, HEIGHT + 1);
        let info = manager.get_wallet_info_mut(&wallet_id).expect("wallet info");
        let observed = info.observed_spent_outpoints();
        assert!(observed.is_empty(), "the checkpoint left observed spends {observed:?}");
        let account = info.first_bip44_managed_account_mut().expect("BIP44 account 0");
        let config = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(&*account, config).expect("encodes");
        *account = bincode::serde::decode_from_slice(&bytes, config).expect("decodes").0;
    })
    .await;

    let late_coins = held_vouts(&manager, &wallet_id, &late.txid());
    assert!(late_coins.is_empty(), "late coins {late_coins:?}");
    assert_eq!(held_vouts(&manager, &wallet_id, &extending.txid()), BTreeSet::from([0]));
    assert_balance(&manager, &wallet_id, TX_AMOUNT);
}
