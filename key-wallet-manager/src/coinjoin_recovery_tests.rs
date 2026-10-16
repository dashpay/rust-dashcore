//! Manager-level CoinJoin recovery (ticket 32008): one wallet is reset and
//! replayed while another, already synced, stays as it is.

use super::test_helpers::*;
use super::*;
use crate::wallet_interface::WalletInterface;
use dashcore::block::{Block, Header, Version};
use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, CompactTarget, OutPoint, TxIn, TxMerkleNode, TxOut, Txid};
use key_wallet::bip32::ChildNumber;
use key_wallet::wallet::initialization::WalletAccountCreationOptions;

/// 0.001 DASH CoinJoin denomination, fee included.
const DENOM: u64 = 100_001;
/// An index past the generated end of a fresh CoinJoin pool.
const FAR: u32 = key_wallet::gap_limit::DEFAULT_COINJOIN_GAP_LIMIT + 250;
const OTHER_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn block(txdata: Vec<Transaction>, seed: u8) -> Block {
    Block {
        header: Header {
            version: Version::default(),
            prev_blockhash: BlockHash::from_byte_array([seed; 32]),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_650_000_000 + seed as u32,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        },
        txdata,
    }
}

/// The external CoinJoin address at `index` of `wallet_id`.
fn coinjoin_address(manager: &WalletManager, wallet_id: &WalletId, index: u32) -> Address {
    let wallet = manager.get_wallet(wallet_id).expect("wallet");
    let xpub = wallet.accounts.coinjoin_accounts.get(&0).expect("CoinJoin account").account_xpub;
    let key = xpub
        .derive_pub(&[
            ChildNumber::from_normal_idx(0).unwrap(),
            ChildNumber::from_normal_idx(index).unwrap(),
        ])
        .expect("derive");
    Address::p2pkh(&dashcore::PublicKey::new(key.public_key), Network::Testnet)
}

fn tx(input: Vec<OutPoint>, output: Vec<(u64, &Address)>) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: input
            .into_iter()
            .map(|previous_output| TxIn {
                previous_output,
                ..Default::default()
            })
            .collect(),
        output: output
            .into_iter()
            .map(|(value, address)| TxOut {
                value,
                script_pubkey: address.script_pubkey(),
            })
            .collect(),
        special_transaction_payload: None,
    }
}

fn foreign(n: u8) -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([n; 32]),
        vout: 0,
    }
}

#[tokio::test]
async fn recovery_replays_one_wallet_and_leaves_the_synced_one_alone() {
    let (mut manager, synced, synced_address) = setup_manager_with_wallet();
    let recovering = manager
        .create_wallet_from_mnemonic(OTHER_MNEMONIC, 0, WalletAccountCreationOptions::Default)
        .expect("second wallet");
    let both = BTreeSet::from([synced, recovering]);

    // Block 10 pays both wallets; block 20 mixes the recovering wallet's coin
    // onto a CoinJoin address past its gap limit, where a normal sync never
    // looks.
    let near = coinjoin_address(&manager, &recovering, 0);
    let far = coinjoin_address(&manager, &recovering, FAR);
    let funding = tx(vec![foreign(0x01)], vec![(TX_AMOUNT, &synced_address), (DENOM, &near)]);
    let mix = tx(
        vec![
            foreign(0x02),
            OutPoint {
                txid: funding.txid(),
                vout: 1,
            },
        ],
        vec![(DENOM, &Address::dummy(Network::Testnet, 1)), (DENOM, &far)],
    );
    let block10 = block(vec![funding.clone()], 10);
    let block20 = block(vec![mix.clone()], 20);
    manager.process_block_for_wallets(&block10, block10.block_hash(), 10, &both).await;
    manager.process_block_for_wallets(&block20, block20.block_hash(), 20, &both).await;
    manager.update_wallet_synced_height(&synced, 100);
    manager.update_wallet_synced_height(&recovering, 100);
    manager.apply_chain_lock(ChainLock::dummy(100));
    assert_eq!(
        manager.get_wallet_balance(&recovering).unwrap().total(),
        0,
        "the far coin is missing"
    );

    let synced_info = manager.get_wallet_info(&synced).expect("info");
    let synced_balance = synced_info.balance();
    let synced_history: Vec<Txid> =
        synced_info.transaction_history().iter().map(|record| record.txid).collect();
    assert_eq!(synced_balance.total(), TX_AMOUNT);

    let mut rx = manager.subscribe_events();
    let until = manager.begin_coinjoin_recovery(&recovering, 0).expect("recovery starts");
    assert_eq!(until, 100);
    let events = drain_events(&mut rx);
    assert_eq!(events.len(), 1, "one reset event, got {:?}", events);
    let WalletEvent::WalletReset {
        wallet_id,
        synced_height: 0,
        coinjoin_addresses,
        ..
    } = &events[0]
    else {
        panic!("expected WalletReset, got {:?}", events[0]);
    };
    assert_eq!(*wallet_id, recovering);
    assert!(
        coinjoin_addresses.iter().any(|address| address.address == near),
        "the rebuilt CoinJoin pools are announced"
    );
    assert!(coinjoin_addresses.iter().all(|address| address.derivation_index < FAR));
    assert!(matches!(
        manager.begin_coinjoin_recovery(&synced, 0),
        Err(WalletError::CoinJoinRecoveryInProgress(running)) if running == recovering
    ));
    assert!(
        matches!(
            manager.begin_coinjoin_recovery(&[9u8; 32], 0),
            Err(WalletError::WalletNotFound(_))
        ),
        "an unknown wallet is reported as such while another recovers"
    );
    assert_eq!(manager.wallets_behind(100), BTreeSet::from([recovering]));

    // The sync layer replays the recovering wallet alone.
    let only = BTreeSet::from([recovering]);
    manager.process_block_for_wallets(&block10, block10.block_hash(), 10, &only).await;
    manager.process_block_for_wallets(&block20, block20.block_hash(), 20, &only).await;
    assert_eq!(
        manager.get_wallet_balance(&recovering).unwrap().total(),
        DENOM,
        "the replay credits the far coin"
    );

    let synced_info = manager.get_wallet_info(&synced).expect("info");
    assert_eq!(synced_info.balance(), synced_balance, "the synced wallet's balance is untouched");
    assert_eq!(
        synced_info.transaction_history().iter().map(|record| record.txid).collect::<Vec<_>>(),
        synced_history,
        "the synced wallet's records are untouched"
    );
    assert_eq!(synced_info.synced_height(), 100);

    assert_eq!(
        manager.coinjoin_recovery_progress(&recovering).map(|progress| progress.found),
        Some(1)
    );
    drain_events(&mut rx);
    manager.update_wallet_synced_height(&recovering, 50);
    assert!(drain_events(&mut rx)
        .iter()
        .all(|event| !matches!(event, WalletEvent::CoinJoinRecoveryFinished { .. })));
    manager.update_wallet_synced_height(&recovering, 100);
    let events = drain_events(&mut rx);
    assert!(matches!(
        events.last(),
        Some(WalletEvent::CoinJoinRecoveryFinished { wallet_id, height: 100, found: 1, cancelled: false })
            if *wallet_id == recovering
    ));
    assert!(manager.begin_coinjoin_recovery(&synced, 0).is_ok(), "the next recovery may start");
}

#[tokio::test]
async fn recovery_of_an_unknown_wallet_fails() {
    let (mut manager, _, _) = setup_manager_with_wallet();
    assert!(matches!(
        manager.begin_coinjoin_recovery(&[9u8; 32], 0),
        Err(WalletError::WalletNotFound(_))
    ));
    assert!(!manager.cancel_coinjoin_recovery(&[9u8; 32]));
}

#[tokio::test]
async fn a_cancelled_recovery_reports_its_end_when_the_replay_completes() {
    let (mut manager, wallet_id, _) = setup_manager_with_wallet();
    manager.update_wallet_last_processed_height(&wallet_id, 300);
    manager.update_wallet_synced_height(&wallet_id, 300);
    let mut rx = manager.subscribe_events();
    manager.begin_coinjoin_recovery(&wallet_id, 0).expect("recovery starts");
    assert!(manager.cancel_coinjoin_recovery(&wallet_id));
    assert!(!manager.cancel_coinjoin_recovery(&wallet_id), "the probe is already off");
    drain_events(&mut rx);

    // Builds come back, and the end is reported, once the replay is done.
    manager.update_wallet_synced_height(&wallet_id, 300);
    assert!(matches!(
        drain_events(&mut rx).last(),
        Some(WalletEvent::CoinJoinRecoveryFinished {
            height: 300,
            found: 0,
            cancelled: true,
            ..
        })
    ));
    assert!(manager.coinjoin_recovery_progress(&wallet_id).is_none());
}

/// A cancelled recovery's replay still holds the shared scan pipeline, so
/// another wallet waits; the cancelled wallet itself may start over.
#[tokio::test]
async fn a_cancelled_replay_still_holds_the_slot_for_other_wallets() {
    let (mut manager, first, _) = setup_manager_with_wallet();
    let second = manager
        .create_wallet_from_mnemonic(OTHER_MNEMONIC, 0, WalletAccountCreationOptions::Default)
        .expect("second wallet");
    manager.update_wallet_synced_height(&first, 300);
    manager.update_wallet_synced_height(&second, 300);

    manager.begin_coinjoin_recovery(&first, 0).expect("recovery starts");
    assert!(manager.cancel_coinjoin_recovery(&first));
    assert!(matches!(
        manager.coinjoin_recovery_progress(&first),
        Some(progress) if !progress.probing
    ));
    assert!(matches!(
        manager.begin_coinjoin_recovery(&second, 0),
        Err(WalletError::CoinJoinRecoveryInProgress(running)) if running == first
    ));
    assert_eq!(manager.begin_coinjoin_recovery(&first, 0).expect("starts over"), 300);

    manager.update_wallet_synced_height(&first, 300);
    assert!(manager.coinjoin_recovery_progress(&first).is_none(), "the replay is done");
    assert!(manager.begin_coinjoin_recovery(&second, 0).is_ok());
}

/// A wallet born below where the sync layer's headers start could not get its
/// history there back, so it is refused before anything is dropped.
#[tokio::test]
async fn a_wallet_born_below_the_replayable_range_is_refused() {
    let (mut manager, wallet_id, _) = setup_manager_with_wallet();
    manager.update_wallet_synced_height(&wallet_id, 300);
    assert!(matches!(
        manager.begin_coinjoin_recovery(&wallet_id, 200),
        Err(WalletError::InvalidState(_))
    ));
    assert_eq!(manager.get_wallet_info(&wallet_id).expect("info").synced_height(), 300);
}
