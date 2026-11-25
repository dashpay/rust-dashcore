//! An InstantSend-locked record goes only once a ChainLock covers its conflict's block, whatever
//! the other fetched wallets' ChainLocks and after a fork unmines it. Once a ChainLock beats it,
//! everything built on it goes too, locked or not.

mod common;

use common::{funding_tx, process_block_for, spend_tx};
use dashcore::blockdata::block::Block;
use dashcore::blockdata::transaction::OutPoint;
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::{Address, Network, Transaction, TxOut};
use key_wallet::managed_account::managed_account_trait::ManagedAccountTrait;
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::transaction_builder::TransactionSigner;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::Utxo;
use key_wallet_manager::{WalletId, WalletInterface, WalletManager};
use std::collections::BTreeSet;

const FUNDED_AT: u32 = 100;

fn wallet(manager: &mut WalletManager<ManagedWalletInfo>) -> (WalletId, Address) {
    let id =
        manager.create_wallet_with_random_mnemonic(WalletAccountCreationOptions::Default).unwrap();
    let address = manager.get_wallet_info(&id).unwrap().monitored_addresses()[0].clone();
    (id, address)
}

fn set(ids: &[WalletId]) -> BTreeSet<WalletId> {
    ids.iter().copied().collect()
}

fn records(manager: &WalletManager<ManagedWalletInfo>, id: &WalletId, tx: &Transaction) -> bool {
    let txid = tx.txid();
    manager
        .get_wallet_info(id)
        .unwrap()
        .accounts()
        .all_accounts()
        .into_iter()
        .any(|account| account.has_transaction(&txid))
}

fn lock_for(tx: &Transaction) -> InstantLock {
    InstantLock {
        txid: tx.txid(),
        inputs: tx.input.iter().map(|input| input.previous_output).collect(),
        ..InstantLock::default()
    }
}

/// `tx`, whose one input is `funding`'s output to the wallet's `address`,
/// signed by the wallet, so an unlocked `tx` is taken in.
async fn signed(
    manager: &WalletManager<ManagedWalletInfo>,
    id: &WalletId,
    address: &Address,
    funding: &Transaction,
    tx: Transaction,
) -> Transaction {
    let account = manager.get_wallet_info(id).unwrap().first_bip44_managed_account().unwrap();
    let path = account.address_derivation_path(address).unwrap();
    let previous_output = tx.input[0].previous_output;
    let coin = Utxo::new(
        previous_output,
        funding.output[previous_output.vout as usize].clone(),
        address.clone(),
        0,
        false,
    );
    let wallet = manager.get_wallet(id).unwrap();
    wallet.sign_tx(tx, vec![coin], move |_| Some(path.clone())).await.unwrap()
}

/// A locked L of wallet A, a coin it spends, and A funded at [`FUNDED_AT`].
async fn locked_spend(
    manager: &mut WalletManager<ManagedWalletInfo>,
) -> (WalletId, OutPoint, Transaction) {
    let (a, address) = wallet(manager);
    let funding = funding_tx(&address, 1_000_000, 0xC0);
    let coin = OutPoint::new(funding.txid(), 0);
    process_block_for(manager, &Block::dummy(FUNDED_AT, vec![funding]), FUNDED_AT, &set(&[a]))
        .await;
    let locked = spend_tx(coin, 990_000, 1);
    manager.process_mempool_transaction(&locked, Some(lock_for(&locked))).await;
    assert!(records(manager, &a, &locked), "L is A's");
    (a, coin, locked)
}

/// A's ChainLock covers D's block but N, fetched with it, lags: the block
/// sweeps both with a plain block context, so A's locked L stays, and the
/// next ChainLock overturns it.
#[tokio::test]
async fn a_locked_spend_goes_at_the_next_chain_lock_when_another_fetched_wallet_lags() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);
    let (a, coin, locked) = locked_spend(&mut manager).await;
    let height = FUNDED_AT + 2;
    manager.apply_chain_lock(ChainLock::dummy(height));
    let (n, _) = wallet(&mut manager);
    assert!(manager.get_wallet_info(&n).unwrap().last_applied_chain_lock().is_none());

    let conflict = spend_tx(coin, 980_000, 2);
    process_block_for(&mut manager, &Block::dummy(height, vec![conflict]), height, &set(&[a, n]))
        .await;
    assert!(records(&manager, &a, &locked), "swept as a plain block, which overturns no lock");

    manager.apply_chain_lock(ChainLock::dummy(height + 1));
    assert!(!records(&manager, &a, &locked), "the ChainLock covers D's block");
}

/// L, locked, is mined and a fork unmines it; D spends L's coin in a plain
/// block of the new branch. L stays until a ChainLock covers D's block.
#[tokio::test]
async fn a_locked_spend_a_fork_unmines_stays_against_a_plain_block_until_a_chain_lock() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);
    let (a, coin, locked) = locked_spend(&mut manager).await;
    let height = FUNDED_AT + 5;
    let only = set(&[a]);
    process_block_for(&mut manager, &Block::dummy(height, vec![locked.clone()]), height, &only)
        .await;
    manager.truncate_above(height - 1).unwrap();
    assert!(records(&manager, &a, &locked), "the fork keeps L, unconfirmed");

    let conflict = spend_tx(coin, 980_000, 2);
    process_block_for(&mut manager, &Block::dummy(height, vec![conflict]), height, &only).await;
    assert!(records(&manager, &a, &locked), "a plain block overturns no lock");

    manager.apply_chain_lock(ChainLock::dummy(height));
    assert!(!records(&manager, &a, &locked), "the ChainLock covers D's block");
}

fn holds(manager: &WalletManager<ManagedWalletInfo>, id: &WalletId, coin: OutPoint) -> bool {
    manager.get_wallet_info(id).unwrap().utxos().iter().any(|utxo| utxo.outpoint == coin)
}

/// A locked L of wallet A with change to A, and A's locked C2 that spends
/// L's change and pays A again.
async fn locked_spend_and_its_locked_child(
    manager: &mut WalletManager<ManagedWalletInfo>,
) -> (WalletId, OutPoint, Transaction, Transaction) {
    let (a, address) = wallet(manager);
    let funding = funding_tx(&address, 1_000_000, 0xC0);
    let coin = OutPoint::new(funding.txid(), 0);
    process_block_for(manager, &Block::dummy(FUNDED_AT, vec![funding]), FUNDED_AT, &set(&[a]))
        .await;
    let own = manager.get_wallet_info(&a).unwrap().monitored_addresses();
    let mut locked = spend_tx(coin, 500_000, 1);
    locked.output.push(TxOut {
        value: 490_000,
        script_pubkey: own[1].script_pubkey(),
    });
    let mut child = spend_tx(OutPoint::new(locked.txid(), 1), 300_000, 2);
    child.output.push(TxOut {
        value: 180_000,
        script_pubkey: own[2].script_pubkey(),
    });
    manager.process_mempool_transaction(&locked, Some(lock_for(&locked))).await;
    manager.process_mempool_transaction(&child, Some(lock_for(&child))).await;
    assert!(records(manager, &a, &locked) && records(manager, &a, &child));
    assert!(holds(manager, &a, OutPoint::new(child.txid(), 1)), "C2's change is A's");
    (a, coin, locked, child)
}

/// L and its locked child C2 are mined and a fork unmines both; D spends L's
/// coin on the new branch and its ChainLock lands. L goes, and C2, which
/// spends L's change, goes with it.
#[tokio::test]
async fn a_locked_child_a_fork_unmines_goes_with_its_parent_at_the_chain_lock() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);
    let (a, coin, locked, child) = locked_spend_and_its_locked_child(&mut manager).await;
    let height = FUNDED_AT + 5;
    let only = set(&[a]);
    let mined = Block::dummy(height, vec![locked.clone(), child.clone()]);
    process_block_for(&mut manager, &mined, height, &only).await;
    manager.truncate_above(height - 1).unwrap();
    assert!(records(&manager, &a, &locked) && records(&manager, &a, &child));

    let conflict = spend_tx(coin, 980_000, 3);
    process_block_for(&mut manager, &Block::dummy(height, vec![conflict]), height, &only).await;
    manager.apply_chain_lock(ChainLock::dummy(height));
    assert!(!records(&manager, &a, &locked), "the ChainLock covers D's block");
    assert!(!records(&manager, &a, &child), "C2 spends L's change");
    assert!(manager.get_wallet_info(&a).unwrap().utxos().is_empty(), "C2's change never existed");
}

/// The same without a fork, as on main: L and its locked child C2 are in
/// the mempool, and D, in a ChainLocked block, spends L's coin. C2 goes with
/// L.
#[tokio::test]
async fn a_locked_child_goes_with_its_parent_a_chain_locked_conflict_beats() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);
    let (a, coin, locked, child) = locked_spend_and_its_locked_child(&mut manager).await;
    let height = FUNDED_AT + 5;
    manager.apply_chain_lock(ChainLock::dummy(height));
    let conflict = spend_tx(coin, 980_000, 3);
    process_block_for(&mut manager, &Block::dummy(height, vec![conflict]), height, &set(&[a]))
        .await;
    assert!(!records(&manager, &a, &locked), "D is ChainLocked");
    assert!(!records(&manager, &a, &child), "C2 spends L's change");
    assert!(manager.get_wallet_info(&a).unwrap().utxos().is_empty(), "C2's change never existed");
}

/// Only a block transaction conflicting with another transaction's unconfirmed record is kept for
/// a ChainLock, not a wallet's own payment mined. One that overturned an unlocked record at once
/// is kept too, in case that record's lock arrives late.
#[tokio::test]
async fn only_a_conflict_with_another_unconfirmed_record_is_kept_for_a_chain_lock() {
    let mut manager = WalletManager::<ManagedWalletInfo>::new(Network::Testnet);
    let (a, address) = wallet(&mut manager);
    let only = set(&[a]);
    let fundings: Vec<Transaction> =
        (0..4).map(|n| funding_tx(&address, 1_000_000, 0xD0 + n)).collect();
    let coin = |n: usize| OutPoint::new(fundings[n].txid(), 0);
    process_block_for(&mut manager, &Block::dummy(FUNDED_AT, fundings.clone()), FUNDED_AT, &only)
        .await;

    let plain = signed(&manager, &a, &address, &fundings[0], spend_tx(coin(0), 990_000, 1)).await;
    let locked = spend_tx(coin(1), 990_000, 2);
    let beaten_plain =
        signed(&manager, &a, &address, &fundings[2], spend_tx(coin(2), 990_000, 3)).await;
    let beaten_locked = spend_tx(coin(3), 990_000, 4);
    manager.process_mempool_transaction(&plain, None).await;
    manager.process_mempool_transaction(&locked, Some(lock_for(&locked))).await;
    manager.process_mempool_transaction(&beaten_plain, None).await;
    manager.process_mempool_transaction(&beaten_locked, Some(lock_for(&beaten_locked))).await;
    for tx in [&plain, &locked, &beaten_plain, &beaten_locked] {
        assert!(records(&manager, &a, tx), "each is A's");
    }
    assert_eq!(manager.awaiting_chain_lock_len(), 0);

    let height = FUNDED_AT + 1;
    let mined = Block::dummy(height, vec![plain, locked]);
    process_block_for(&mut manager, &mined, height, &only).await;
    assert_eq!(manager.awaiting_chain_lock_len(), 0, "the wallet's own payments are mined");

    let conflict = spend_tx(coin(2), 980_000, 5);
    process_block_for(&mut manager, &Block::dummy(height + 1, vec![conflict]), height + 1, &only)
        .await;
    assert!(!records(&manager, &a, &beaten_plain), "an unlocked record goes at once");
    assert_eq!(manager.awaiting_chain_lock_len(), 1, "kept in case its lock arrives late");

    let conflict = spend_tx(coin(3), 980_000, 6);
    process_block_for(&mut manager, &Block::dummy(height + 2, vec![conflict]), height + 2, &only)
        .await;
    assert!(records(&manager, &a, &beaten_locked), "a plain block overturns no lock");
    assert_eq!(manager.awaiting_chain_lock_len(), 2, "kept for its ChainLock");
}
