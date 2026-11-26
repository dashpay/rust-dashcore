use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use dash_spv::error::NetworkResult;
use dash_spv::network::{
    Inbound, MessageType, NetworkEvent, NetworkManager, PeerNetworkManager, RequestKey,
};
use dash_spv::test_utils::{test_socket_address, TestEventHandler};
use dash_spv::{DashSpvClient, SyncEvent};
use dashcore::consensus::deserialize;
use dashcore::hash_types::CycleHash;
use dashcore::network::message::NetworkMessage;
use dashcore::{Amount, InstantLock, Transaction};
use hex_conservative::decode_to_vec;
use key_wallet::transaction_checking::TransactionContext;
use key_wallet_manager::WalletEvent;
use serde_json::json;
use test_case::test_case;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::sync::{broadcast, Mutex};
use tokio::time::timeout;

use super::helpers::{wait_for_masternode_sync, wait_for_wallet_tx_status};
use super::setup::{
    create_mn_test_config, create_wallet_from_controller, receive_address,
    wait_for_controller_islock, TestContext, SYNC_TIMEOUT,
};

struct HeldInstantLocksNetwork {
    peer: Arc<PeerNetworkManager>,
    locks: Mutex<Option<UnboundedReceiver<Inbound>>>,
}

#[async_trait]
impl NetworkManager for HeldInstantLocksNetwork {
    async fn start(&self) {
        // Quorum data must stay unavailable until the test queues the locks.
    }
    async fn stop(&self) {
        self.peer.stop().await;
    }
    async fn enqueue(&self, height: u32, msg: NetworkMessage) {
        self.peer.enqueue(height, msg).await;
    }
    async fn send_to(&self, addr: SocketAddr, msg: NetworkMessage) -> bool {
        self.peer.send_to(addr, msg).await
    }
    async fn broadcast(&self, msg: NetworkMessage) -> NetworkResult<()> {
        self.peer.broadcast(msg).await
    }
    async fn dispatch_local(&self, msg: NetworkMessage) {
        self.peer.dispatch_local(msg).await;
    }
    async fn release_request(&self, key: RequestKey) {
        self.peer.release_request(key).await;
    }
    async fn subscribe(&self, kinds: &[MessageType]) -> UnboundedReceiver<Inbound> {
        if kinds.contains(&MessageType::IsDLock) {
            self.locks.lock().await.take().unwrap()
        } else {
            self.peer.subscribe(kinds).await
        }
    }
    fn events(&self) -> broadcast::Receiver<NetworkEvent> {
        self.peer.events()
    }
    async fn connected_count(&self) -> u32 {
        self.peer.connected_count().await
    }
    async fn ban_peer(&self, addr: SocketAddr) {
        self.peer.ban_peer(addr).await;
    }
}

#[test_case(false; "replayed")]
#[test_case(true; "received after quorum sync")]
#[tokio::test]
async fn deferred_lock_finalizes_only_after_real_quorum_sync(receive_after_sync: bool) {
    let Some(mut ctx) = TestContext::new(false).await else {
        return;
    };
    ctx.mn_ctx.mine_dkg_cycle().expect("a live signing quorum");
    let (wallet, wallet_id) = create_wallet_from_controller(&ctx.mn_ctx);
    let addr = receive_address(&wallet, &wallet_id).await;
    let txid = ctx.mn_ctx.controller.send_to_address(&addr, Amount::from_sat(50_000_000));
    wait_for_controller_islock(&mut ctx.mn_ctx, &txid, SYNC_TIMEOUT).await;
    let locks =
        ctx.mn_ctx.controller.try_rpc_call("getislocks", &[json!([txid.to_string()])]).unwrap();
    let genuine: InstantLock =
        deserialize(&decode_to_vec(locks[0]["hex"].as_str().unwrap()).unwrap()).unwrap();
    let raw = ctx
        .mn_ctx
        .controller
        .try_rpc_call("getrawtransaction", &[json!(txid.to_string())])
        .unwrap();
    let tx: Transaction = deserialize(&decode_to_vec(raw.as_str().unwrap()).unwrap()).unwrap();

    let config =
        create_mn_test_config(ctx.storage_path().to_path_buf(), ctx.mn_ctx.controller_addr);
    let peer = Arc::new(PeerNetworkManager::new(&config).await);
    let (lock_tx, lock_rx) = unbounded_channel();
    let network = HeldInstantLocksNetwork {
        peer: peer.clone(),
        locks: Mutex::new(Some(lock_rx)),
    };
    let handler = Arc::new(TestEventHandler::new());
    let mut progress = handler.subscribe_progress();
    let mut events = handler.subscribe_sync_events();
    let mut wallet_events = handler.subscribe_wallet_events();
    let client = DashSpvClient::new(config, network, wallet, vec![handler]).await.unwrap();
    client.run().await.unwrap();
    peer.dispatch_local(NetworkMessage::Tx(Box::new(tx))).await;
    wait_for_wallet_tx_status(
        &mut wallet_events,
        txid,
        |ctx| matches!(ctx, TransactionContext::Mempool),
        SYNC_TIMEOUT,
    )
    .await;

    let mut forged = genuine.clone();
    forged.inputs[0].vout += 1;
    let mut unknown_cycle = genuine.clone();
    unknown_cycle.cyclehash = CycleHash::from_byte_array([1; 32]);
    let mut queued = vec![unknown_cycle, forged];
    if !receive_after_sync {
        queued.push(genuine.clone());
    }
    let pending_count = queued.len();
    for lock in queued {
        lock_tx
            .send((test_socket_address(0), Arc::new(NetworkMessage::ISLock(lock).into())))
            .unwrap();
    }
    timeout(Duration::from_secs(SYNC_TIMEOUT), async {
        loop {
            if progress.borrow_and_update().instantsend().is_ok_and(|p| p.pending() == pending_count) {
                break;
            }
            tokio::select! {
                result = progress.changed() => result.unwrap(),
                event = events.recv() => {
                    assert!(!matches!(event.unwrap(), SyncEvent::InstantLockReceived { instant_lock, .. } if instant_lock.txid == txid), "a deferred lock emitted an event");
                }
                event = wallet_events.recv() => {
                    assert!(!matches!(event.unwrap(), WalletEvent::TransactionInstantLocked { txid: locked, .. } if locked == txid), "a deferred lock finalized the wallet");
                }
            }
        }
    }).await.expect("distinct locks remain pending");
    assert_eq!(progress.borrow().instantsend().unwrap().valid(), 0);

    // The controlled subscription excludes peer reannouncements.
    peer.start().await;
    if receive_after_sync {
        wait_for_masternode_sync(&mut progress, SYNC_TIMEOUT).await;
        lock_tx
            .send((
                test_socket_address(0),
                Arc::new(NetworkMessage::ISLock(genuine.clone()).into()),
            ))
            .unwrap();
    }
    let received = timeout(Duration::from_secs(SYNC_TIMEOUT), async {
        loop {
            if let SyncEvent::InstantLockReceived {
                instant_lock,
                validated,
            } = events.recv().await.unwrap()
            {
                if instant_lock.txid == txid {
                    assert!(validated);
                    break instant_lock;
                }
            }
        }
    })
    .await
    .expect("the deferred lock verifies after quorum sync");
    assert_eq!(received, genuine);
    let status = wait_for_wallet_tx_status(
        &mut wallet_events,
        txid,
        |ctx| matches!(ctx, TransactionContext::InstantSend(_)),
        SYNC_TIMEOUT,
    )
    .await;
    assert!(matches!(status, TransactionContext::InstantSend(lock) if lock == genuine));
    timeout(Duration::from_secs(SYNC_TIMEOUT), async {
        loop {
            if progress.borrow_and_update().instantsend().is_ok_and(|p| p.valid() == 1) {
                break;
            }
            progress.changed().await.unwrap();
        }
    })
    .await
    .expect("exactly one lock verified");
    assert_eq!(progress.borrow().instantsend().unwrap().pending(), 0);
    client.stop().await;
}
