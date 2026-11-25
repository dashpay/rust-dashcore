//! Whether the wallet that abandoned a payment sweeps with a conflict beating a locked spend of
//! its change, when blocks are fetched per wallet by its own scripts against real BIP-158 filters.
//! C spends P's change and another coin X; D spends X only and pays elsewhere.

use super::*;
use crate::storage::{
    DiskStorageManager, PersistentBlockHeaderStorage, PersistentFilterHeaderStorage,
    PersistentFilterStorage, StorageManager,
};
use crate::test_utils::next_unused_receive_address;
use dashcore::bip158::Error as FilterError;
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::{
    Address, Block, BlockHash, ChainLock, Network, OutPoint, Transaction, TxIn, TxOut, Txid,
};
use key_wallet::managed_account::managed_account_trait::ManagedAccountTrait;
use key_wallet::transaction_checking::{BlockInfo, TransactionContext};
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::transaction_builder::TransactionSigner;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::Utxo;
use key_wallet_manager::WalletManager;

const MNEMONIC_A: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MNEMONIC_B: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const MNEMONIC_C: &str =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
const COIN: u64 = 1_000_000;
const CHANGE: u64 = 690_000;
const TIP: u32 = 971;

type Wallets = Arc<RwLock<WalletManager<ManagedWalletInfo>>>;

async fn register(wallets: &Wallets, mnemonic: &str) -> WalletId {
    let options = WalletAccountCreationOptions::Default;
    wallets.write().await.create_wallet_from_mnemonic(mnemonic, 0, options).unwrap()
}

fn in_block(height: u32) -> TransactionContext {
    TransactionContext::InBlock(BlockInfo::new(
        height,
        BlockHash::from_byte_array([height as u8; 32]),
        1_650_000_000 + height,
    ))
}

fn lock_for(tx: &Transaction) -> InstantLock {
    InstantLock {
        txid: tx.txid(),
        inputs: tx.input.iter().map(|input| input.previous_output).collect(),
        ..InstantLock::default()
    }
}

fn spend(inputs: &[OutPoint], outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: inputs
            .iter()
            .map(|previous_output| TxIn {
                previous_output: *previous_output,
                ..Default::default()
            })
            .collect(),
        output: outputs,
        special_transaction_payload: None,
    }
}

fn pay(to: &Address, value: u64) -> TxOut {
    TxOut {
        value,
        script_pubkey: to.script_pubkey(),
    }
}

/// Which wallets loaded here hold X, C's other input.
#[derive(Debug, Clone, Copy, PartialEq)]
enum OtherInput {
    SecondWallet,
    NoLoadedWallet,
}

/// When D's ChainLock arrives.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Lock {
    BeforeBlock,
    AfterBlock,
    AfterReorg,
    Never,
}

/// What the wallets saw of D.
#[derive(Debug, PartialEq)]
struct Outcome {
    fetched_for_a: bool,
    fetched_for_b: bool,
    change_offered: bool,
    a_total: u64,
    a_records_d: bool,
    b_keeps_c: bool,
}

/// Wallet A abandons P; locked C spends P's change and X; P comes back by its lock. D, spending X
/// only, is mined, handed to the wallets the filter scan names, and ChainLocked as `lock` says.
async fn beaten_spend(other: OtherInput, lock: Lock) -> Outcome {
    let wallets: Wallets = Arc::new(RwLock::new(WalletManager::new(Network::Testnet)));
    let a = register(&wallets, MNEMONIC_A).await;
    let b = register(&wallets, MNEMONIC_B).await;
    let elsewhere = {
        let unregistered: Wallets = Arc::new(RwLock::new(WalletManager::new(Network::Testnet)));
        let id = register(&unregistered, MNEMONIC_C).await;
        next_unused_receive_address(&unregistered, &id).await
    };

    let to_a = next_unused_receive_address(&wallets, &a).await;
    let change_a = next_unused_receive_address(&wallets, &a).await;
    let to_b = next_unused_receive_address(&wallets, &b).await;
    let holder_of_x = match other {
        OtherInput::SecondWallet => next_unused_receive_address(&wallets, &b).await,
        OtherInput::NoLoadedWallet => elsewhere.clone(),
    };
    let funding = Transaction::dummy(&to_a, 191..192, &[COIN]);
    let funding_x = Transaction::dummy(&holder_of_x, 192..193, &[COIN]);
    let x = OutPoint::new(funding_x.txid(), 0);
    {
        let mut wm = wallets.write().await;
        wm.check_transaction_in_all_wallets(&funding, in_block(960), true, true).await;
        wm.check_transaction_in_all_wallets(&funding_x, in_block(960), true, true).await;
    }

    let payment = {
        let unsigned = spend(
            &[OutPoint::new(funding.txid(), 0)],
            vec![pay(&elsewhere, 300_000), pay(&change_a, CHANGE)],
        );
        let wm = wallets.read().await;
        let account = wm.get_wallet_info(&a).unwrap().first_bip44_managed_account().unwrap();
        let path = account.address_derivation_path(&to_a).unwrap();
        let coin = Utxo::new(
            OutPoint::new(funding.txid(), 0),
            funding.output[0].clone(),
            to_a.clone(),
            0,
            false,
        );
        wm.get_wallet(&a)
            .unwrap()
            .sign_tx(unsigned, vec![coin], move |_| Some(path.clone()))
            .await
            .unwrap()
    };
    let change = OutPoint::new(payment.txid(), 1);
    let child = spend(&[change, x], vec![pay(&to_b, CHANGE)]);
    let winner = spend(&[x], vec![pay(&elsewhere, 500_000)]);
    {
        let mut wm = wallets.write().await;
        wm.process_mempool_transaction(&payment, None).await;
        let info = wm.get_wallet_info_mut(&a).unwrap();
        info.abandon_transaction(payment.txid());
        info.update_balance();
        wm.check_transaction_in_all_wallets(&funding, in_block(960), true, true).await;
        wm.process_mempool_transaction(&child, Some(lock_for(&child))).await;
        wm.process_mempool_transaction(&payment, Some(lock_for(&payment))).await;
        let again = wm.process_mempool_transaction(&child, Some(lock_for(&child))).await;
        assert!(again.is_relevant, "C spends P's change");
    }
    let offered = |wm: &WalletManager<ManagedWalletInfo>| {
        wm.get_wallet_info(&a).unwrap().utxos().iter().any(|utxo| utxo.outpoint == change)
    };
    assert!(!offered(&*wallets.read().await), "C spends P's change");

    let coinbase = spend(&[OutPoint::null()], vec![pay(&elsewhere, 50_000)]);
    let block = Block::dummy(TIP, vec![coinbase, winner]);
    let x_script = funding_x.output[0].script_pubkey.clone();
    let filter = BlockFilter::new_script_filter(&block, |outpoint| {
        if *outpoint == x {
            Ok(x_script.clone())
        } else {
            Err(FilterError::UtxoMissing(*outpoint))
        }
    })
    .unwrap();
    let key = FilterMatchKey::new(TIP, block.block_hash());

    let storage = DiskStorageManager::with_temp_dir().await.unwrap();
    let mut manager: FiltersManager<
        PersistentBlockHeaderStorage,
        PersistentFilterHeaderStorage,
        PersistentFilterStorage,
        WalletManager<ManagedWalletInfo>,
    > = FiltersManager::new(
        Arc::clone(&wallets),
        storage.block_headers(),
        storage.filter_headers(),
        storage.filters(),
        0,
    )
    .await;
    manager.set_state(SyncState::Syncing);
    let mut batch = FiltersBatch::new(0, 999, HashMap::from([(key, filter)]));
    batch.mark_verified();
    manager.active_batches.insert(0, batch);
    manager.progress.update_stored_height(999);

    let mut fetched_for = BTreeSet::new();
    for event in manager.try_process_batch().await.unwrap() {
        if let SyncEvent::BlocksNeeded {
            blocks,
        } = event
        {
            for (needed, ids) in blocks {
                assert_eq!(needed.height(), TIP);
                fetched_for.extend(ids);
            }
        }
    }

    let chain_lock = ChainLock {
        block_height: TIP,
        block_hash: block.block_hash(),
        signature: BLSSignature::from([0; 96]),
    };
    let mut wm = wallets.write().await;
    if lock == Lock::BeforeBlock {
        wm.apply_chain_lock(chain_lock.clone());
    }
    wm.process_block_for_wallets(&block, block.block_hash(), TIP, &fetched_for).await;
    if lock == Lock::AfterReorg {
        wm.truncate_above(TIP - 1).unwrap();
    }
    if matches!(lock, Lock::AfterBlock | Lock::AfterReorg) {
        wm.apply_chain_lock(chain_lock);
    }
    let records = |id: &WalletId, txid: &Txid| {
        wm.get_wallet_info(id)
            .unwrap()
            .accounts()
            .all_accounts()
            .into_iter()
            .any(|account| account.has_transaction(txid))
    };
    Outcome {
        fetched_for_a: fetched_for.contains(&a),
        fetched_for_b: fetched_for.contains(&b),
        change_offered: offered(&wm),
        a_total: wm.get_wallet_info(&a).unwrap().balance().total(),
        a_records_d: records(&a, &block.txdata[1].txid()),
        b_keeps_c: records(&b, &child.txid()),
    }
}

#[test_case::test_case(OtherInput::SecondWallet, Lock::AfterBlock; "second wallet, lock after block")]
#[test_case::test_case(OtherInput::SecondWallet, Lock::BeforeBlock; "second wallet, lock before block")]
#[test_case::test_case(OtherInput::NoLoadedWallet, Lock::AfterBlock; "no loaded wallet, lock after block")]
#[test_case::test_case(OtherInput::NoLoadedWallet, Lock::BeforeBlock; "no loaded wallet, lock before block")]
#[tokio::test]
async fn the_abandoning_wallet_never_fetches_a_conflict_that_touches_none_of_its_coins(
    other: OtherInput,
    lock: Lock,
) {
    let outcome = beaten_spend(other, lock).await;
    assert!(!outcome.fetched_for_a);
    assert_eq!(outcome.fetched_for_b, other == OtherInput::SecondWallet);
}

/// Once a loaded wallet fetches D's block and D is ChainLocked, in either order, A drops C and gets
/// P's change back, taking nothing else from D. When no loaded wallet fetches the block, nothing
/// changes.
#[test_case::test_case(OtherInput::SecondWallet, Lock::AfterBlock; "second wallet, lock after block")]
#[test_case::test_case(OtherInput::SecondWallet, Lock::BeforeBlock; "second wallet, lock before block")]
#[test_case::test_case(OtherInput::NoLoadedWallet, Lock::AfterBlock; "no loaded wallet, lock after block")]
#[test_case::test_case(OtherInput::NoLoadedWallet, Lock::BeforeBlock; "no loaded wallet, lock before block")]
#[tokio::test]
async fn a_chain_locked_conflict_another_wallet_fetches_frees_the_abandoned_change(
    other: OtherInput,
    lock: Lock,
) {
    let swept = other == OtherInput::SecondWallet;
    assert_eq!(
        beaten_spend(other, lock).await,
        Outcome {
            fetched_for_a: false,
            fetched_for_b: swept,
            change_offered: swept,
            a_total: if swept {
                CHANGE
            } else {
                0
            },
            a_records_d: false,
            b_keeps_c: !swept,
        }
    );
}

/// A plain block never overturns an InstantSend lock: with D fetched by
/// another wallet but never ChainLocked, C stays in both wallets and P's
/// change stays spent.
#[tokio::test]
async fn a_conflict_another_wallet_fetches_without_a_chain_lock_leaves_the_locked_spend() {
    assert_eq!(
        beaten_spend(OtherInput::SecondWallet, Lock::Never).await,
        Outcome {
            fetched_for_a: false,
            fetched_for_b: true,
            change_offered: false,
            a_total: 0,
            a_records_d: false,
            b_keeps_c: true,
        }
    );
}

/// D's block is reorganized away before a ChainLock at its height arrives:
/// D is forgotten with it, and the lock overturns nothing.
#[tokio::test]
async fn a_conflict_whose_block_a_reorg_drops_overturns_nothing_at_the_next_chain_lock() {
    assert_eq!(
        beaten_spend(OtherInput::SecondWallet, Lock::AfterReorg).await,
        Outcome {
            fetched_for_a: false,
            fetched_for_b: true,
            change_offered: false,
            a_total: 0,
            a_records_d: false,
            b_keeps_c: true,
        }
    );
}

/// A's unlocked L spends A's coin and B's X; D spends X in a block fetched for B only, so L goes
/// from A too. A reorg drops D: L stays dropped and A's coin is offered, as in a wallet that
/// fetched D, until L is mined and spends it, counted once.
#[tokio::test]
async fn an_unlocked_spend_a_conflict_beats_where_it_was_not_fetched_stays_dropped_after_a_reorg() {
    let wallets: Wallets = Arc::new(RwLock::new(WalletManager::new(Network::Testnet)));
    let a = register(&wallets, MNEMONIC_A).await;
    let b = register(&wallets, MNEMONIC_B).await;
    let elsewhere = {
        let unregistered: Wallets = Arc::new(RwLock::new(WalletManager::new(Network::Testnet)));
        let id = register(&unregistered, MNEMONIC_C).await;
        next_unused_receive_address(&unregistered, &id).await
    };
    let to_a = next_unused_receive_address(&wallets, &a).await;
    let to_b = next_unused_receive_address(&wallets, &b).await;
    let funding = Transaction::dummy(&to_a, 191..192, &[COIN]);
    let funding_x = Transaction::dummy(&to_b, 192..193, &[COIN]);
    let coin = OutPoint::new(funding.txid(), 0);
    let x = OutPoint::new(funding_x.txid(), 0);
    let mut wm = wallets.write().await;
    let funded = Block::dummy(TIP - 2, vec![funding.clone(), funding_x]);
    let both = BTreeSet::from([a, b]);
    wm.process_block_for_wallets(&funded, funded.block_hash(), TIP - 2, &both).await;

    let spend_l = {
        let unsigned = spend(&[coin, x], vec![pay(&elsewhere, 2 * COIN - 10_000)]);
        let account = wm.get_wallet_info(&a).unwrap().first_bip44_managed_account().unwrap();
        let path = account.address_derivation_path(&to_a).unwrap();
        let utxo = Utxo::new(coin, funding.output[0].clone(), to_a.clone(), 0, false);
        wm.get_wallet(&a)
            .unwrap()
            .sign_tx(unsigned, vec![utxo], move |_| Some(path.clone()))
            .await
            .unwrap()
    };
    let offered = |wm: &WalletManager<ManagedWalletInfo>| {
        wm.get_wallet_info(&a).unwrap().utxos().iter().any(|utxo| utxo.outpoint == coin)
    };
    let records = |wm: &WalletManager<ManagedWalletInfo>| {
        wm.get_wallet_info(&a)
            .unwrap()
            .accounts()
            .all_accounts()
            .into_iter()
            .any(|account| account.has_transaction(&spend_l.txid()))
    };
    wm.process_mempool_transaction(&spend_l, None).await;
    assert!(records(&wm) && !offered(&wm), "L spends A's coin");

    let winner = spend(&[x], vec![pay(&elsewhere, 500_000)]);
    let block = Block::dummy(TIP, vec![winner]);
    wm.process_block_for_wallets(&block, block.block_hash(), TIP, &BTreeSet::from([b])).await;
    assert!(!records(&wm), "D beats L in A too");
    assert!(offered(&wm), "only L spent A's coin");

    wm.truncate_above(TIP - 1).unwrap();
    assert!(!records(&wm), "L stays dropped");
    assert!(offered(&wm), "A's coin is offered until L is mined");

    let mined = Block::dummy(TIP, vec![spend_l.clone()]);
    wm.process_block_for_wallets(&mined, mined.block_hash(), TIP, &both).await;
    assert!(records(&wm), "L is mined");
    assert!(!offered(&wm));
    assert_eq!(wm.get_wallet_info(&a).unwrap().balance().total(), 0, "counted once");
}

/// A's unlocked R spends A's coin and X, with change to A. D beats R in a plain block that A, or
/// only B, fetches. R's lock then arrives late, before or after D's ChainLock: either way R and
/// its change go for good, and A's coin is back unless D spent it.
#[test_case::test_case(true, false; "a fetches the block, lock before the chain lock")]
#[test_case::test_case(false, false; "only another wallet fetches the block, lock before")]
#[test_case::test_case(true, true; "a fetches the block, lock after the chain lock")]
#[test_case::test_case(false, true; "only another wallet fetches the block, lock after")]
#[tokio::test]
async fn an_unlocked_spend_a_plain_block_beat_goes_at_the_chain_lock_after_its_lock_arrives_late(
    fetched: bool,
    chain_lock_first: bool,
) {
    let wallets: Wallets = Arc::new(RwLock::new(WalletManager::new(Network::Testnet)));
    let a = register(&wallets, MNEMONIC_A).await;
    let b = register(&wallets, MNEMONIC_B).await;
    let elsewhere = {
        let unregistered: Wallets = Arc::new(RwLock::new(WalletManager::new(Network::Testnet)));
        let id = register(&unregistered, MNEMONIC_C).await;
        next_unused_receive_address(&unregistered, &id).await
    };
    let to_a = next_unused_receive_address(&wallets, &a).await;
    let change_a = next_unused_receive_address(&wallets, &a).await;
    let funding = Transaction::dummy(&to_a, 191..192, &[COIN]);
    let coin = OutPoint::new(funding.txid(), 0);
    let x = OutPoint::new(Txid::from_byte_array([0x57; 32]), 0);
    let mut wm = wallets.write().await;
    let funded = Block::dummy(TIP - 2, vec![funding.clone()]);
    wm.process_block_for_wallets(&funded, funded.block_hash(), TIP - 2, &BTreeSet::from([a])).await;

    let spend_r = {
        let unsigned =
            spend(&[coin, x], vec![pay(&change_a, CHANGE), pay(&elsewhere, COIN - CHANGE)]);
        let account = wm.get_wallet_info(&a).unwrap().first_bip44_managed_account().unwrap();
        let path = account.address_derivation_path(&to_a).unwrap();
        let utxo = Utxo::new(coin, funding.output[0].clone(), to_a.clone(), 0, false);
        wm.get_wallet(&a)
            .unwrap()
            .sign_tx(unsigned, vec![utxo], move |_| Some(path.clone()))
            .await
            .unwrap()
    };
    let r_change = OutPoint::new(spend_r.txid(), 0);
    let offered = |wm: &WalletManager<ManagedWalletInfo>, outpoint: OutPoint| {
        wm.get_wallet_info(&a).unwrap().utxos().iter().any(|utxo| utxo.outpoint == outpoint)
    };
    let records = |wm: &WalletManager<ManagedWalletInfo>| {
        wm.get_wallet_info(&a)
            .unwrap()
            .accounts()
            .all_accounts()
            .into_iter()
            .any(|account| account.has_transaction(&spend_r.txid()))
    };
    wm.process_mempool_transaction(&spend_r, None).await;
    assert!(records(&wm) && offered(&wm, r_change), "R pays its change to A");

    let winner = spend(
        &[if fetched {
            coin
        } else {
            x
        }],
        vec![pay(&elsewhere, 500_000)],
    );
    let block = Block::dummy(TIP, vec![winner]);
    let fetcher = if fetched {
        a
    } else {
        b
    };
    let fetched_for = BTreeSet::from([fetcher]);
    wm.process_block_for_wallets(&block, block.block_hash(), TIP, &fetched_for).await;
    assert!(!records(&wm), "D beats R");

    let chain_lock = ChainLock {
        block_height: TIP,
        block_hash: block.block_hash(),
        signature: BLSSignature::from([0; 96]),
    };
    if chain_lock_first {
        wm.apply_chain_lock(chain_lock);
        let late = wm.process_mempool_transaction(&spend_r, Some(lock_for(&spend_r))).await;
        assert!(!late.is_relevant, "D's ChainLock overturned R before its lock came");
    } else {
        wm.process_mempool_transaction(&spend_r, Some(lock_for(&spend_r))).await;
        assert!(records(&wm) && offered(&wm, r_change), "R's late lock brings it back");
        wm.apply_chain_lock(chain_lock);
    }
    assert!(!records(&wm), "D's ChainLock overturns R");
    assert!(!offered(&wm, r_change), "R's change never existed");
    assert_eq!(offered(&wm, coin), !fetched, "A's coin is back unless D spent it");
    let total = wm.get_wallet_info(&a).unwrap().balance().total();
    assert_eq!(
        total,
        if fetched {
            0
        } else {
            COIN
        }
    );
}
