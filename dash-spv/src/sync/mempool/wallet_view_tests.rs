//! The mempool manager against real wallets: a transaction it holds or found
//! irrelevant is looked at again when the wallets' view changes.

use std::net::SocketAddr;
use std::sync::Arc;

use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::Inventory;
use dashcore::{Address, BlockHash, Network, OutPoint, Transaction, TxIn, TxOut, Txid};
use key_wallet::managed_account::managed_account_trait::ManagedAccountTrait;
use key_wallet::transaction_checking::{BlockInfo, TransactionContext};
use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::wallet::managed_wallet_info::transaction_builder::TransactionSigner;
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::Utxo;
use key_wallet_manager::{WalletEvent, WalletId, WalletInterface, WalletManager};
use tokio::sync::{broadcast, RwLock};

use super::{BroadcastConfig, MempoolManager};
use crate::client::config::MempoolStrategy;
use crate::network::NetworkManager;
use crate::sync::{SyncEvent, SyncManager, SyncState};
use crate::test_utils::{next_unused_receive_address, test_socket_address, MockNetworkManager};

const MNEMONIC_A: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MNEMONIC_B: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const MNEMONIC_C: &str =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";

const COIN: u64 = 1_000_000;
const PAYMENT: u64 = 990_000;
const TIP: u32 = 1000;

type Wallets = Arc<RwLock<WalletManager<ManagedWalletInfo>>>;

struct Harness {
    wallets: Wallets,
    manager: MempoolManager<WalletManager<ManagedWalletInfo>>,
    network: Arc<dyn NetworkManager>,
    network_mock: Arc<MockNetworkManager>,
    peer: SocketAddr,
}

impl Harness {
    /// Wallets made from `mnemonics`, and a mempool manager relaying from one
    /// peer while filter sync still runs.
    async fn new(mnemonics: &[&str]) -> (Self, Vec<WalletId>) {
        let wallets: Wallets = Arc::new(RwLock::new(WalletManager::new(Network::Testnet)));
        let mut ids = Vec::new();
        for mnemonic in mnemonics {
            ids.push(register(&wallets, mnemonic).await);
        }
        let network_mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = network_mock.clone();
        let monitor_hash = wallets.read().await.monitor_hash();
        let mut manager = MempoolManager::new(
            wallets.clone(),
            MempoolStrategy::FetchAll,
            1000,
            monitor_hash,
            BroadcastConfig::default(),
        )
        .with_activation_during_sync(true);
        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);
        manager.activate_peer(peer, &network).await.unwrap();
        manager.set_state(SyncState::Synced);
        network_mock.clear_sent().await;
        let harness = Self {
            wallets,
            manager,
            network,
            network_mock,
            peer,
        };
        (harness, ids)
    }

    async fn sent_messages(&self) -> Vec<NetworkMessage> {
        let messages = self.network_mock.sent_to_messages().await;
        self.network_mock.clear_sent().await;
        messages.into_iter().map(|(_, message)| message).collect()
    }

    /// Announce `tx` and deliver it if the manager asks for it. Returns whether it asked.
    async fn announce(&mut self, tx: &Transaction) -> bool {
        self.manager
            .handle_inv(&[Inventory::Transaction(tx.txid())], self.peer, &self.network)
            .await
            .unwrap();
        let asked = self.sent_messages().await.iter().any(|message| {
            matches!(message, NetworkMessage::GetData(items)
                if items.contains(&Inventory::Transaction(tx.txid())))
        });
        if asked {
            self.manager.handle_tx(tx.clone(), self.peer, &self.network).await.unwrap();
        }
        asked
    }

    /// Every wallet reaches the tip and filter sync reports completion.
    async fn filters_synced(&mut self) {
        {
            let mut wallets = self.wallets.write().await;
            let ids: Vec<WalletId> = wallets.list_wallets().into_iter().copied().collect();
            for id in ids {
                wallets.update_wallet_synced_height(&id, TIP);
            }
        }
        let event = SyncEvent::FiltersSyncComplete {
            tip_height: TIP,
        };
        self.manager.handle_sync_event(&event, &self.network).await.unwrap();
    }

    async fn tick(&mut self) {
        self.manager.tick(&self.network).await.unwrap();
    }

    async fn total(&self, wallet_id: &WalletId) -> u64 {
        self.wallets.read().await.get_wallet_info(wallet_id).unwrap().balance().total()
    }

    async fn context_of(&self, wallet_id: &WalletId, txid: &Txid) -> Option<TransactionContext> {
        let wallets = self.wallets.read().await;
        let info = wallets.get_wallet_info(wallet_id).unwrap();
        let account = info.first_bip44_managed_account().unwrap();
        account.transactions().get(txid).map(|record| record.context.clone())
    }

    async fn events(&self) -> broadcast::Receiver<WalletEvent> {
        self.wallets.read().await.subscribe_events()
    }
}

async fn register(wallets: &Wallets, mnemonic: &str) -> WalletId {
    let options = WalletAccountCreationOptions::Default;
    wallets.write().await.create_wallet_from_mnemonic(mnemonic, 0, options).unwrap()
}

/// The first receive address of the wallet `mnemonic` makes, without registering it.
async fn address_of_unregistered(mnemonic: &str) -> Address {
    let elsewhere: Wallets = Arc::new(RwLock::new(WalletManager::new(Network::Testnet)));
    let id = register(&elsewhere, mnemonic).await;
    next_unused_receive_address(&elsewhere, &id).await
}

fn lock_for(tx: &Transaction) -> InstantLock {
    InstantLock {
        txid: tx.txid(),
        inputs: tx.input.iter().map(|input| input.previous_output).collect(),
        ..InstantLock::default()
    }
}

fn drain(rx: &mut broadcast::Receiver<WalletEvent>) -> Vec<WalletEvent> {
    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    events
}

fn detections_for(events: &[WalletEvent], wallet: &WalletId) -> usize {
    events
        .iter()
        .filter(|event| {
            matches!(event, WalletEvent::TransactionDetected { wallet_id, .. } if wallet_id == wallet)
        })
        .count()
}

/// A spend of `funding`'s first output, which pays `owner`'s `from`, paying `PAYMENT` to
/// `to`, signed with `owner`'s key.
async fn signed_spend(
    wallets: &Wallets,
    owner: &WalletId,
    from: &Address,
    funding: &Transaction,
    to: &Address,
) -> Transaction {
    let output = TxOut {
        value: PAYMENT,
        script_pubkey: to.script_pubkey(),
    };
    signed_spend_to(wallets, owner, from, funding, vec![output]).await
}

/// A spend of `funding`'s first output, which pays `owner`'s `from`, with `outputs`,
/// signed with `owner`'s key.
async fn signed_spend_to(
    wallets: &Wallets,
    owner: &WalletId,
    from: &Address,
    funding: &Transaction,
    outputs: Vec<TxOut>,
) -> Transaction {
    let outpoint = OutPoint::new(funding.txid(), 0);
    let spend = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: outpoint,
            ..Default::default()
        }],
        output: outputs,
        special_transaction_payload: None,
    };
    let wallets = wallets.read().await;
    let account = wallets.get_wallet_info(owner).unwrap().first_bip44_managed_account().unwrap();
    let path = account.address_derivation_path(from).unwrap();
    let coin = Utxo::new(outpoint, funding.output[0].clone(), from.clone(), 0, false);
    let wallet = wallets.get_wallet(owner).unwrap();
    wallet.sign_tx(spend, vec![coin], move |_| Some(path.clone())).await.unwrap()
}

fn in_block(height: u32) -> TransactionContext {
    TransactionContext::InBlock(BlockInfo::new(
        height,
        BlockHash::from_byte_array([height as u8; 32]),
        1_650_000_000 + height,
    ))
}

#[tokio::test]
async fn a_held_spend_reaches_a_wallet_whose_scan_finds_the_coin_later() {
    let (mut h, ids) = Harness::new(&[MNEMONIC_A, MNEMONIC_B]).await;
    let (a, b) = (ids[0], ids[1]);
    let to_a = next_unused_receive_address(&h.wallets, &a).await;
    let to_b = next_unused_receive_address(&h.wallets, &b).await;

    // B's coin is in a block B's scan has not reached; a spend of it, signed
    // by B on another device, pays A and is InstantSend-locked.
    let funding = Transaction::dummy(&to_b, 0..1, &[COIN]);
    let spend = signed_spend(&h.wallets, &b, &to_b, &funding, &to_a).await;
    assert!(h.announce(&spend).await);
    h.manager.process_instant_send(lock_for(&spend)).await;
    assert_eq!(h.total(&a).await, PAYMENT);
    assert!(!h.announce(&spend).await, "a held transaction is not fetched again");

    // B's scan finds the coin: B now shows it as available.
    h.wallets
        .write()
        .await
        .check_transaction_in_all_wallets(&funding, in_block(900), true, true)
        .await;
    assert_eq!(h.total(&b).await, COIN);

    let mut events = h.events().await;
    h.filters_synced().await;
    let events = drain(&mut events);

    assert_eq!(h.total(&b).await, 0, "B's coin is spent by the held transaction");
    assert!(
        matches!(h.context_of(&b, &spend.txid()).await, Some(TransactionContext::InstantSend(_))),
        "the held lock comes with the transaction"
    );
    assert_eq!(h.total(&a).await, PAYMENT, "A's output is not credited twice");
    assert_eq!(detections_for(&events, &a), 0, "A is told nothing new: {:?}", events);
}

#[tokio::test]
async fn a_wallet_registered_after_sync_gets_payments_already_in_the_mempool() {
    let (mut h, _) = Harness::new(&[MNEMONIC_A]).await;
    h.filters_synced().await;
    h.tick().await;
    h.sent_messages().await;

    let to_c = address_of_unregistered(MNEMONIC_C).await;
    let payment = Transaction::dummy(&to_c, 7..8, &[COIN]);
    assert!(h.announce(&payment).await);
    assert!(!h.manager.transactions.contains_key(&payment.txid()), "no wallet matches it yet");

    let c = register(&h.wallets, MNEMONIC_C).await;
    h.tick().await;
    assert!(
        h.sent_messages().await.iter().any(|message| matches!(message, NetworkMessage::MemPool)),
        "the peer is asked for its mempool again"
    );
    assert!(h.announce(&payment).await, "the earlier non-match is fetched again");
    assert_eq!(h.total(&c).await, COIN);
}

#[tokio::test]
async fn a_lock_that_came_before_an_unmatched_transaction_survives_its_retry() {
    let (mut h, _) = Harness::new(&[MNEMONIC_A]).await;
    h.filters_synced().await;
    h.tick().await;

    let to_c = address_of_unregistered(MNEMONIC_C).await;
    let payment = Transaction::dummy(&to_c, 9..10, &[COIN]);
    h.manager.process_instant_send(lock_for(&payment)).await;
    assert!(h.announce(&payment).await);
    assert!(!h.manager.transactions.contains_key(&payment.txid()));

    let c = register(&h.wallets, MNEMONIC_C).await;
    h.tick().await;
    assert!(h.announce(&payment).await);

    assert!(matches!(
        h.context_of(&c, &payment.txid()).await,
        Some(TransactionContext::InstantSend(_))
    ));
}

#[tokio::test]
async fn a_wallet_registered_after_sync_is_rechecked_when_its_scan_completes() {
    let (mut h, ids) = Harness::new(&[MNEMONIC_A]).await;
    let a = ids[0];
    h.filters_synced().await;
    h.tick().await;

    // A spend, signed by C, of a coin C's scan has not found yet, paying A.
    let to_a = next_unused_receive_address(&h.wallets, &a).await;
    let c = register(&h.wallets, MNEMONIC_C).await;
    let to_c = next_unused_receive_address(&h.wallets, &c).await;
    let funding = Transaction::dummy(&to_c, 11..12, &[COIN]);
    let spend = signed_spend(&h.wallets, &c, &to_c, &funding, &to_a).await;
    h.tick().await;
    assert!(h.announce(&spend).await);

    h.wallets
        .write()
        .await
        .check_transaction_in_all_wallets(&funding, in_block(950), true, true)
        .await;
    assert_eq!(h.total(&c).await, COIN);
    h.filters_synced().await;

    assert_eq!(h.total(&c).await, 0, "C's scan completing re-checks the held spend");
    assert_eq!(h.total(&a).await, PAYMENT);
}

/// A held spend the wallet swept because a conflicting spend confirmed is dropped, not
/// replayed, so its change is not credited again.
#[tokio::test]
async fn a_swept_held_spend_is_not_brought_back_by_a_replay() {
    let (mut h, ids) = Harness::new(&[MNEMONIC_A]).await;
    let a = ids[0];
    h.filters_synced().await;
    h.tick().await;

    let to_a = next_unused_receive_address(&h.wallets, &a).await;
    let funding = Transaction::dummy(&to_a, 13..14, &[COIN]);
    h.wallets
        .write()
        .await
        .check_transaction_in_all_wallets(&funding, in_block(960), true, true)
        .await;
    let change = next_unused_receive_address(&h.wallets, &a).await;
    let elsewhere = address_of_unregistered(MNEMONIC_B).await;
    let outputs = vec![
        TxOut {
            value: PAYMENT / 2,
            script_pubkey: elsewhere.script_pubkey(),
        },
        TxOut {
            value: PAYMENT / 2,
            script_pubkey: change.script_pubkey(),
        },
    ];
    let spend = signed_spend_to(&h.wallets, &a, &to_a, &funding, outputs).await;
    assert!(h.announce(&spend).await);
    assert!(h.manager.transactions.contains_key(&spend.txid()));

    // Another device spends the same coin, and that spend confirms.
    let winner = signed_spend(&h.wallets, &a, &to_a, &funding, &elsewhere).await;
    h.wallets
        .write()
        .await
        .check_transaction_in_all_wallets(&winner, in_block(961), true, true)
        .await;
    assert_eq!(h.total(&a).await, 0, "the precondition: the loser is swept");

    register(&h.wallets, MNEMONIC_C).await;
    h.tick().await;

    assert_eq!(h.total(&a).await, 0, "the swept spend's change is not credited again");
    assert!(!h.manager.transactions.contains_key(&spend.txid()));
}
