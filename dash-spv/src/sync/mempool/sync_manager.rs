use super::manager::MEMPOOL_TX_EXPIRY;
use crate::error::SyncResult;
use crate::network::{Message, MessageType, NetworkEvent, RequestSender};
use crate::sync::{
    ManagerIdentifier, MempoolManager, SyncEvent, SyncManager, SyncManagerProgress, SyncState,
};
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use key_wallet_manager::WalletInterface;

#[async_trait]
impl<W: WalletInterface + 'static> SyncManager for MempoolManager<W> {
    fn identifier(&self) -> ManagerIdentifier {
        ManagerIdentifier::Mempool
    }

    fn state(&self) -> SyncState {
        self.progress.state()
    }

    fn set_state(&mut self, state: SyncState) {
        self.progress.set_state(state);
    }

    fn wanted_message_types(&self) -> &'static [MessageType] {
        &[MessageType::Inv, MessageType::Tx]
    }

    async fn start_sync(&mut self, requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
        // After a full disconnect, re-activate mempool on all connected peers
        self.activate_all_peers(requests).await?;
        let has_activated = self.peers.values().any(|v| v.is_some());
        if has_activated {
            self.set_state(SyncState::Synced);
            tracing::info!("Mempool manager re-activated after disconnect recovery");
        }
        // If no peers could be activated, stay in WaitingForConnections so the
        // next PeersUpdated event will retry activation.
        Ok(vec![])
    }

    fn on_disconnect(&mut self) {
        self.clear_pending();
    }

    async fn handle_message(
        &mut self,
        msg: Message,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        match msg.inner() {
            NetworkMessage::Inv(inv) => self.handle_inv(inv, msg.peer_address(), requests).await,
            NetworkMessage::Tx(tx) => self.handle_tx(tx.clone(), msg.peer_address()).await,
            _ => Ok(vec![]),
        }
    }

    async fn handle_sync_event(
        &mut self,
        event: &SyncEvent,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        match event {
            // Activate as soon as filter sync completes — the wallet's address
            // and UTXO set is fully populated at this point.
            SyncEvent::FiltersSyncComplete {
                ..
            } => {
                if self.state() != SyncState::Synced {
                    self.activate_all_peers(requests).await?;
                    let has_activated = self.peers.values().any(|v| v.is_some());
                    if has_activated {
                        self.set_state(SyncState::Synced);
                        tracing::info!("Mempool manager activated after filter sync");
                        return Ok(vec![]);
                    } else {
                        tracing::warn!(
                            "Filter sync complete but no peers available for mempool activation"
                        );
                    }
                }
                Ok(vec![])
            }
            SyncEvent::BlockProcessed {
                confirmed_txids,
                ..
            } => {
                // Remove confirmed transactions from mempool.
                // Bloom filter rebuild is handled by the tick's revision check.
                if !confirmed_txids.is_empty() {
                    self.remove_confirmed(confirmed_txids);
                }
                Ok(vec![])
            }
            SyncEvent::InstantLockReceived {
                instant_lock,
                ..
            } => {
                self.process_instant_send(instant_lock.clone()).await;
                Ok(vec![])
            }
            _ => Ok(vec![]),
        }
    }

    async fn tick(&mut self, requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
        if self.state() != SyncState::Synced {
            return Ok(vec![]);
        }

        // Prune expired transactions periodically
        self.prune_expired(MEMPOOL_TX_EXPIRY);

        // Prune pending requests that never received a response
        self.prune_pending_requests();

        // Send queued getdata requests now that slots may have freed up
        self.send_queued(requests).await?;

        // Rebroadcast unconfirmed self-sent transactions on a randomized interval
        self.rebroadcast_if_due(requests).await;

        // Rebuild bloom filter if the wallet's monitored set has changed.
        //
        // We poll the revision counter rather than using push-based wallet events
        // for simplicity: the revision lives on `ManagedCoreFundsAccount` and auto-bumps
        // on address generation and UTXO mutations, giving us a single source of
        // truth without needing event emission after every wallet operation.
        // Adding a push-based approach would require a new `select!` branch in the
        // shared `SyncManager::run` loop or a `WalletEvent` bridge — complexity
        // that isn't justified given the 100ms tick latency is negligible for bloom
        // filter rebuilds and the read lock is non-contending.
        let current_revision = self.wallet.read().await.monitor_revision();
        if current_revision != self.last_monitor_revision {
            tracing::info!("Wallet monitor revision changed, rebuilding bloom filter");
            self.rebuild_filter(requests).await?;
            self.last_monitor_revision = current_revision;
        }

        Ok(vec![])
    }

    async fn handle_network_event(
        &mut self,
        event: &NetworkEvent,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        match event {
            NetworkEvent::PeerConnected {
                address,
            } => {
                self.handle_peer_connected(*address);
                // If synced, activate the new peer immediately
                if self.state() == SyncState::Synced
                    && self.peers.get(address).is_some_and(|v| v.is_none())
                {
                    tracing::info!("Activating mempool on newly connected peer {}", address);
                    self.activate_peer(*address, requests).await?;
                }
            }
            NetworkEvent::PeerDisconnected {
                address,
            } => {
                self.handle_peer_disconnected(*address);
            }
            NetworkEvent::PeersUpdated {
                connected_count,
                best_height,
                ..
            } => {
                if let Some(best_height) = best_height {
                    self.update_target_height(*best_height);
                }
                if *connected_count == 0 {
                    self.stop_sync();
                } else if self.state() == SyncState::WaitingForConnections {
                    return self.start_sync(requests).await;
                }
            }
        }
        Ok(vec![])
    }

    fn progress(&self) -> SyncManagerProgress {
        SyncManagerProgress::Mempool(self.progress.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::config::MempoolStrategy;
    use crate::network::NetworkRequest;
    use crate::test_utils::test_socket_address;
    use dashcore::hashes::Hash;
    use key_wallet_manager::test_utils::MockWallet;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use tokio::sync::{mpsc, RwLock};

    fn create_test_manager(
    ) -> (MempoolManager<MockWallet>, RequestSender, mpsc::UnboundedReceiver<NetworkRequest>) {
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        let (tx, rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(tx);

        let manager = MempoolManager::new(wallet, MempoolStrategy::FetchAll, 1000, 0);

        (manager, requests, rx)
    }

    #[test]
    fn test_sync_manager_trait_basics() {
        let (mut manager, _, _rx) = create_test_manager();

        assert_eq!(manager.identifier(), ManagerIdentifier::Mempool);
        assert_eq!(manager.state(), SyncState::WaitForEvents);

        let types = manager.wanted_message_types();
        assert!(types.contains(&MessageType::Inv));
        assert!(types.contains(&MessageType::Tx));
        assert_eq!(types.len(), 2);

        manager.set_state(SyncState::Synced);
        assert_eq!(manager.state(), SyncState::Synced);

        assert!(matches!(manager.progress(), SyncManagerProgress::Mempool(_)));
    }

    #[tokio::test]
    async fn test_filters_sync_complete_activates() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = crate::test_utils::test_socket_address(1);
        manager.handle_peer_connected(peer);

        let event = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };

        let events = manager.handle_sync_event(&event, &requests).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::Synced);
        assert!(matches!(manager.peers.get(&peer), Some(Some(_))));
    }

    #[tokio::test]
    async fn test_filters_sync_complete_subsequent_is_noop() {
        let (mut manager, requests, _rx) = create_test_manager();
        manager.handle_peer_connected(crate::test_utils::test_socket_address(1));

        // Activate first
        let event0 = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&event0, &requests).await.unwrap();

        // Subsequent filter sync completions should not change state
        let event1 = SyncEvent::FiltersSyncComplete {
            tip_height: 1001,
        };
        let events = manager.handle_sync_event(&event1, &requests).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::Synced);
    }

    #[tokio::test]
    async fn test_reactivation_after_disconnect() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        // Initial activation
        let event = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        let events = manager.handle_sync_event(&event, &requests).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::Synced);

        // Simulate disconnect by resetting state
        manager.set_state(SyncState::WaitForEvents);

        // Re-sync should re-activate
        let event = SyncEvent::FiltersSyncComplete {
            tip_height: 1001,
        };
        let events = manager.handle_sync_event(&event, &requests).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::Synced);
    }

    #[tokio::test]
    async fn test_peer_connect_activates_when_synced() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer1 = test_socket_address(1);
        manager.handle_peer_connected(peer1);

        // Activate via SyncComplete
        let event = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&event, &requests).await.unwrap();
        assert!(matches!(manager.peers.get(&peer1), Some(Some(_))));

        // New peer connects while synced => should activate immediately
        let peer2 = test_socket_address(2);
        let connect = NetworkEvent::PeerConnected {
            address: peer2,
        };
        let events = manager.handle_network_event(&connect, &requests).await.unwrap();
        assert!(events.is_empty());
        assert!(matches!(manager.peers.get(&peer2), Some(Some(_))));
    }

    #[tokio::test]
    async fn test_network_event_peer_connect_disconnect() {
        let (mut manager, requests, _rx) = create_test_manager();

        let peer1 = test_socket_address(1);
        let peer2 = test_socket_address(2);

        // Connecting peers should return empty events (not synced yet)
        let connect1 = NetworkEvent::PeerConnected {
            address: peer1,
        };
        let events = manager.handle_network_event(&connect1, &requests).await.unwrap();
        assert!(events.is_empty());
        assert!(manager.peers.contains_key(&peer1));

        let connect2 = NetworkEvent::PeerConnected {
            address: peer2,
        };
        let events = manager.handle_network_event(&connect2, &requests).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.peers.len(), 2);

        let disconnect1 = NetworkEvent::PeerDisconnected {
            address: peer1,
        };
        let events = manager.handle_network_event(&disconnect1, &requests).await.unwrap();
        assert!(events.is_empty());

        // Still have peer2 available
        assert!(manager.peers.contains_key(&peer2));
        assert_eq!(manager.peers.len(), 1);

        // Disconnecting an already-disconnected peer should not error
        let events = manager.handle_network_event(&disconnect1, &requests).await.unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn test_block_processed_removes_confirmed_txids() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        // Activate
        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &requests).await.unwrap();

        // Add transactions to mempool
        let mut txids = Vec::new();
        for i in 0..2u32 {
            let tx = dashcore::Transaction {
                version: 1,
                lock_time: i,
                input: vec![],
                output: vec![],
                special_transaction_payload: None,
            };
            let txid = tx.txid();
            txids.push(txid);
            manager.transactions.insert(
                txid,
                crate::types::UnconfirmedTransaction::new(
                    tx,
                    dashcore::Amount::from_sat(0),
                    false,
                    false,
                    Vec::new(),
                    0,
                ),
            );
        }

        let event = SyncEvent::BlockProcessed {
            block_hash: dashcore::BlockHash::all_zeros(),
            height: 1001,
            wallets: BTreeSet::new(),
            new_addresses: BTreeMap::new(),
            confirmed_txids: txids.clone(),
        };
        let events = manager.handle_sync_event(&event, &requests).await.unwrap();
        assert!(events.is_empty());

        assert!(manager.transactions.is_empty());
    }

    #[tokio::test]
    async fn test_instant_lock_received_marks_transaction() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        // Activate
        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &requests).await.unwrap();

        // Add a transaction to mempool
        let tx = dashcore::Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        let txid = tx.txid();
        manager.transactions.insert(
            txid,
            crate::types::UnconfirmedTransaction::new(
                tx,
                dashcore::Amount::from_sat(0),
                false,
                false,
                Vec::new(),
                0,
            ),
        );

        // Fire InstantLockReceived with a lock whose txid matches
        let mut is_lock = dashcore::InstantLock::dummy(0..1);
        is_lock.txid = txid;

        let event = SyncEvent::InstantLockReceived {
            instant_lock: is_lock,
            validated: true,
        };
        let events = manager.handle_sync_event(&event, &requests).await.unwrap();
        assert!(events.is_empty());

        assert!(manager.transactions.get(&txid).unwrap().is_instant_send);
    }

    #[tokio::test]
    async fn test_peer_disconnect_removes_from_peers() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        // Activate
        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &requests).await.unwrap();

        // Disconnect the only peer
        let disconnect = NetworkEvent::PeerDisconnected {
            address: peer,
        };
        let events = manager.handle_network_event(&disconnect, &requests).await.unwrap();
        assert!(events.is_empty());
        assert!(manager.peers.is_empty());
    }

    #[tokio::test]
    async fn test_sync_complete_no_peers_stays_inactive() {
        let (mut manager, requests, _rx) = create_test_manager();

        let event = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        let events = manager.handle_sync_event(&event, &requests).await.unwrap();

        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::WaitForEvents);
        assert!(manager.peers.is_empty());
    }

    #[tokio::test]
    async fn test_start_sync_no_peers_stays_waiting() {
        let (mut manager, requests, _rx) = create_test_manager();

        // Simulate full disconnect setting state to WaitingForConnections
        manager.set_state(SyncState::WaitingForConnections);

        // start_sync with no peers should stay in WaitingForConnections
        let events = manager.start_sync(&requests).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::WaitingForConnections);
    }

    #[tokio::test]
    async fn test_disconnect_recovery_reactivates_on_reconnect() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        // Activate via SyncComplete
        let event = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&event, &requests).await.unwrap();
        assert_eq!(manager.state(), SyncState::Synced);

        // Disconnect peer
        let disconnect = NetworkEvent::PeerDisconnected {
            address: peer,
        };
        manager.handle_network_event(&disconnect, &requests).await.unwrap();

        // PeersUpdated with 0 triggers stop_sync
        let update = NetworkEvent::PeersUpdated {
            connected_count: 0,
            addresses: vec![],
            best_height: None,
        };
        manager.handle_network_event(&update, &requests).await.unwrap();
        assert_eq!(manager.state(), SyncState::WaitingForConnections);

        // PeersUpdated with 1 but no peers tracked yet: stays WaitingForConnections
        let update = NetworkEvent::PeersUpdated {
            connected_count: 1,
            addresses: vec![peer],
            best_height: Some(1000),
        };
        manager.handle_network_event(&update, &requests).await.unwrap();
        assert_eq!(manager.state(), SyncState::WaitingForConnections);

        // Peer reconnects and PeersUpdated fires again
        manager.handle_peer_connected(peer);
        let update = NetworkEvent::PeersUpdated {
            connected_count: 1,
            addresses: vec![peer],
            best_height: Some(1000),
        };
        manager.handle_network_event(&update, &requests).await.unwrap();
        assert_eq!(manager.state(), SyncState::Synced);
        assert!(matches!(manager.peers.get(&peer), Some(Some(_))));
    }

    #[tokio::test]
    async fn test_block_processed_confirmed_txids_does_not_eagerly_rebuild() {
        let mut mock = MockWallet::new();
        let script = dashcore::ScriptBuf::from_bytes(vec![
            0x76, 0xa9, 0x14, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x88, 0xac,
        ]);
        let addr = dashcore::Address::from_script(&script, dashcore::Network::Testnet).unwrap();
        mock.set_addresses(vec![addr]);
        let wallet = Arc::new(RwLock::new(mock));
        let (tx, mut rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(tx);

        let mut manager = MempoolManager::new(wallet, MempoolStrategy::BloomFilter, 1000, 0);

        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        // Activate
        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &requests).await.unwrap();

        // Drain activation messages
        while rx.try_recv().is_ok() {}

        // BlockProcessed does not eagerly rebuild — the tick handles it via
        // the revision check. Verify no FilterLoad is sent from the event handler.
        let event = SyncEvent::BlockProcessed {
            block_hash: dashcore::BlockHash::all_zeros(),
            height: 1001,
            wallets: BTreeSet::new(),
            new_addresses: BTreeMap::new(),
            confirmed_txids: vec![dashcore::Txid::all_zeros()],
        };
        manager.handle_sync_event(&event, &requests).await.unwrap();

        let has_filter_load = std::iter::from_fn(|| rx.try_recv().ok()).any(|req| {
            matches!(req, NetworkRequest::SendMessageToPeer(NetworkMessage::FilterLoad(_), _))
        });
        assert!(!has_filter_load, "BlockProcessed should not eagerly rebuild filter");
    }

    #[tokio::test]
    async fn test_block_processed_no_changes_no_rebuild_flag() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &requests).await.unwrap();

        // BlockProcessed with no confirmed txids and no new addresses
        let event = SyncEvent::BlockProcessed {
            block_hash: dashcore::BlockHash::all_zeros(),
            height: 1001,
            wallets: BTreeSet::new(),
            new_addresses: BTreeMap::new(),
            confirmed_txids: vec![],
        };
        manager.handle_sync_event(&event, &requests).await.unwrap();
    }

    #[tokio::test]
    async fn test_tick_rebuilds_filter_when_monitor_revision_changes() {
        let addr = {
            let script = dashcore::ScriptBuf::from_bytes(vec![
                0x76, 0xa9, 0x14, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x88, 0xac,
            ]);
            dashcore::Address::from_script(&script, dashcore::Network::Testnet).unwrap()
        };

        let mut mock = MockWallet::new();
        mock.set_addresses(vec![addr.clone()]);
        let initial_revision = mock.monitor_revision();
        let wallet = Arc::new(RwLock::new(mock));
        let (tx, mut rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(tx);

        let mut manager = MempoolManager::new(
            wallet.clone(),
            MempoolStrategy::BloomFilter,
            1000,
            initial_revision,
        );

        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        // Activate — this snapshots the monitor revision
        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &requests).await.unwrap();
        assert_eq!(manager.state(), SyncState::Synced);

        // Drain activation messages
        while rx.try_recv().is_ok() {}

        // tick with unchanged revision should not rebuild
        manager.tick(&requests).await.unwrap();
        assert!(rx.try_recv().is_err(), "no messages expected when revision unchanged");

        // Simulate wallet adding new addresses (bumps revision)
        {
            let mut w = wallet.write().await;
            let addr2 = dashcore::Address::from_script(
                &dashcore::ScriptBuf::from_bytes(vec![
                    0x76, 0xa9, 0x14, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0x88, 0xac,
                ]),
                dashcore::Network::Testnet,
            )
            .unwrap();
            w.set_addresses(vec![addr, addr2]);
        }

        // tick should detect stale filter and rebuild
        manager.tick(&requests).await.unwrap();

        let mut found_filter_load = false;
        while let Ok(msg) = rx.try_recv() {
            if matches!(msg, NetworkRequest::SendMessageToPeer(NetworkMessage::FilterLoad(_), _)) {
                found_filter_load = true;
            }
        }
        assert!(found_filter_load, "expected FilterLoad after monitor revision change");

        // Subsequent tick should not rebuild again (revision was snapshotted)
        manager.tick(&requests).await.unwrap();
        assert!(rx.try_recv().is_err(), "no messages expected after revision re-snapshot");
    }

    #[tokio::test]
    async fn test_tick_skips_rebuild_for_fetch_all_strategy() {
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        let (tx, mut rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(tx);

        let mut manager = MempoolManager::new(wallet.clone(), MempoolStrategy::FetchAll, 1000, 0);

        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &requests).await.unwrap();
        while rx.try_recv().is_ok() {}

        // Bump revision
        {
            let mut w = wallet.write().await;
            w.set_addresses(vec![dashcore::Address::dummy(dashcore::Network::Testnet, 0)]);
        }

        // tick should not send any filter messages for FetchAll
        manager.tick(&requests).await.unwrap();
        let mut found_filter = false;
        while let Ok(msg) = rx.try_recv() {
            if matches!(
                msg,
                NetworkRequest::SendMessageToPeer(NetworkMessage::FilterLoad(_), _)
                    | NetworkRequest::SendMessageToPeer(NetworkMessage::FilterClear, _)
            ) {
                found_filter = true;
            }
        }
        assert!(!found_filter, "FetchAll should not send filter messages on revision change");
    }

    #[tokio::test]
    async fn test_tick_rebuilds_filter_when_outpoints_change() {
        let addr = {
            let script = dashcore::ScriptBuf::from_bytes(vec![
                0x76, 0xa9, 0x14, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x88, 0xac,
            ]);
            dashcore::Address::from_script(&script, dashcore::Network::Testnet).unwrap()
        };

        let mut mock = MockWallet::new();
        mock.set_addresses(vec![addr]);
        let initial_revision = mock.monitor_revision();
        let wallet = Arc::new(RwLock::new(mock));
        let (tx, mut rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(tx);

        let mut manager = MempoolManager::new(
            wallet.clone(),
            MempoolStrategy::BloomFilter,
            1000,
            initial_revision,
        );

        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &requests).await.unwrap();
        while rx.try_recv().is_ok() {}

        // Simulate UTXO set change (new outpoint added)
        {
            let mut w = wallet.write().await;
            w.set_outpoints(vec![dashcore::OutPoint {
                txid: dashcore::Txid::from_byte_array([0xee; 32]),
                vout: 0,
            }]);
        }

        // tick should detect the revision change and rebuild
        manager.tick(&requests).await.unwrap();

        let found_filter_load = std::iter::from_fn(|| rx.try_recv().ok()).any(|msg| {
            matches!(msg, NetworkRequest::SendMessageToPeer(NetworkMessage::FilterLoad(_), _))
        });
        assert!(found_filter_load, "expected FilterLoad after outpoint change");
    }

    #[tokio::test]
    async fn test_handle_tx_does_not_eagerly_rebuild_filter() {
        let mut mock = MockWallet::new();
        mock.set_mempool_relevant(true);
        let script = dashcore::ScriptBuf::from_bytes(vec![
            0x76, 0xa9, 0x14, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x88, 0xac,
        ]);
        let addr = dashcore::Address::from_script(&script, dashcore::Network::Testnet).unwrap();
        mock.set_addresses(vec![addr]);
        let initial_revision = mock.monitor_revision();
        let wallet = Arc::new(RwLock::new(mock));
        let (tx_chan, mut rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(tx_chan);

        let mut manager = MempoolManager::new(
            wallet.clone(),
            MempoolStrategy::BloomFilter,
            1000,
            initial_revision,
        );

        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &requests).await.unwrap();
        while rx.try_recv().is_ok() {}

        // handle_tx with a relevant transaction should NOT eagerly rebuild
        let tx = dashcore::Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        manager.handle_tx(tx, test_socket_address(1)).await.unwrap();

        let has_filter_load = std::iter::from_fn(|| rx.try_recv().ok()).any(|msg| {
            matches!(msg, NetworkRequest::SendMessageToPeer(NetworkMessage::FilterLoad(_), _))
        });
        assert!(!has_filter_load, "handle_tx should not eagerly rebuild filter");

        // But the next tick should catch it if the wallet revision changed
        // (MockWallet bumps revision when set_mempool_relevant triggers processing)
        {
            let mut w = wallet.write().await;
            w.set_addresses(vec![dashcore::Address::dummy(dashcore::Network::Testnet, 0)]);
        }
        manager.tick(&requests).await.unwrap();

        let found_filter_load = std::iter::from_fn(|| rx.try_recv().ok()).any(|msg| {
            matches!(msg, NetworkRequest::SendMessageToPeer(NetworkMessage::FilterLoad(_), _))
        });
        assert!(found_filter_load, "tick should rebuild after revision change");
    }
}
