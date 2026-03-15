use super::manager::MEMPOOL_TX_EXPIRY;
use crate::error::SyncResult;
use crate::network::{Message, MessageType, NetworkEvent, RequestSender};
use crate::sync::{
    ManagerIdentifier, MempoolManager, SyncEvent, SyncManager, SyncManagerProgress, SyncState,
};
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use key_wallet_manager::wallet_interface::WalletInterface;

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

    fn clear_in_flight_state(&mut self) {
        self.clear_pending();
    }

    fn wanted_message_types(&self) -> &'static [MessageType] {
        &[MessageType::Inv, MessageType::Tx]
    }

    async fn handle_message(
        &mut self,
        msg: Message,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        match msg.inner() {
            NetworkMessage::Inv(inv) => self.handle_inv(inv, msg.peer_address(), requests).await,
            NetworkMessage::Tx(tx) => self.handle_tx(tx.clone(), requests).await,
            _ => Ok(vec![]),
        }
    }

    async fn handle_sync_event(
        &mut self,
        event: &SyncEvent,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        match event {
            SyncEvent::SyncComplete {
                ..
            } => {
                if self.state() != SyncState::Synced {
                    self.activate_all_peers(requests).await?;
                    let has_activated = self.peers.values().any(|v| v.is_some());
                    if has_activated {
                        self.set_state(SyncState::Synced);
                        tracing::info!("Mempool manager activated on all peers");
                        return Ok(vec![]);
                    } else {
                        tracing::warn!(
                            "Sync complete but no peers available for mempool activation"
                        );
                    }
                }
                Ok(vec![])
            }
            SyncEvent::BlockProcessed {
                new_addresses,
                confirmed_txids,
                ..
            } => {
                // Remove confirmed transactions from mempool
                if !confirmed_txids.is_empty() {
                    self.remove_confirmed(confirmed_txids).await;
                }
                if self.state() == SyncState::Synced
                    && (!confirmed_txids.is_empty() || !new_addresses.is_empty())
                {
                    // Confirmed transactions change the wallet's UTXO set and
                    // new addresses expand the monitored set. Both make the
                    // bloom filter stale, so rebuild immediately.
                    self.rebuild_filter(requests).await?;
                }
                Ok(vec![])
            }
            SyncEvent::InstantLockReceived {
                instant_lock,
                ..
            } => {
                self.mark_instant_send(&instant_lock.txid).await;
                Ok(vec![])
            }
            _ => Ok(vec![]),
        }
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

    async fn tick(&mut self, requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
        if self.state() != SyncState::Synced {
            return Ok(vec![]);
        }

        // Prune expired transactions periodically
        self.prune_expired(MEMPOOL_TX_EXPIRY).await;

        // Prune pending requests that never received a response
        self.prune_pending_requests();

        // Send queued getdata requests now that slots may have freed up
        self.send_queued(requests).await?;

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
    use crate::types::MempoolState;
    use dashcore::hashes::Hash;
    use key_wallet_manager::test_utils::MockWallet;
    use std::sync::Arc;
    use tokio::sync::{mpsc, RwLock};

    fn create_test_manager(
    ) -> (MempoolManager<MockWallet>, RequestSender, mpsc::UnboundedReceiver<NetworkRequest>) {
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let (tx, rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(tx);

        let manager = MempoolManager::new(wallet, mempool_state, MempoolStrategy::FetchAll, 1000);

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
    async fn test_handle_sync_complete_activates() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = crate::test_utils::test_socket_address(1);
        manager.handle_peer_connected(peer);

        let event = SyncEvent::SyncComplete {
            header_tip: 1000,
            cycle: 0,
        };

        let events = manager.handle_sync_event(&event, &requests).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::Synced);
        assert!(matches!(manager.peers.get(&peer), Some(Some(_))));
    }

    #[tokio::test]
    async fn test_handle_sync_complete_subsequent_cycles() {
        let (mut manager, requests, _rx) = create_test_manager();
        manager.handle_peer_connected(crate::test_utils::test_socket_address(1));

        // Activate first
        let event0 = SyncEvent::SyncComplete {
            header_tip: 1000,
            cycle: 0,
        };
        manager.handle_sync_event(&event0, &requests).await.unwrap();

        // Subsequent cycles should not change state
        let event1 = SyncEvent::SyncComplete {
            header_tip: 1001,
            cycle: 1,
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
        let event = SyncEvent::SyncComplete {
            header_tip: 1000,
            cycle: 0,
        };
        let events = manager.handle_sync_event(&event, &requests).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::Synced);

        // Simulate disconnect by resetting state
        manager.set_state(SyncState::WaitForEvents);

        // Re-sync should re-activate
        let event = SyncEvent::SyncComplete {
            header_tip: 1001,
            cycle: 1,
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
        let event = SyncEvent::SyncComplete {
            header_tip: 1000,
            cycle: 0,
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
        let sync = SyncEvent::SyncComplete {
            header_tip: 1000,
            cycle: 0,
        };
        manager.handle_sync_event(&sync, &requests).await.unwrap();

        // Add transactions to mempool state
        let mut txids = Vec::new();
        {
            let mut state = manager.mempool_state.write().await;
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
                state.add_transaction(crate::types::UnconfirmedTransaction::new(
                    tx,
                    dashcore::Amount::from_sat(0),
                    false,
                    false,
                    Vec::new(),
                    0,
                ));
            }
        }

        let event = SyncEvent::BlockProcessed {
            block_hash: dashcore::BlockHash::all_zeros(),
            height: 1001,
            new_addresses: vec![],
            confirmed_txids: txids.clone(),
        };
        let events = manager.handle_sync_event(&event, &requests).await.unwrap();
        assert!(events.is_empty());

        let state = manager.mempool_state.read().await;
        assert!(state.transactions.is_empty());
    }

    #[tokio::test]
    async fn test_instant_lock_received_marks_transaction() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        // Activate
        let sync = SyncEvent::SyncComplete {
            header_tip: 1000,
            cycle: 0,
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
        {
            let mut state = manager.mempool_state.write().await;
            state.add_transaction(crate::types::UnconfirmedTransaction::new(
                tx,
                dashcore::Amount::from_sat(0),
                false,
                false,
                Vec::new(),
                0,
            ));
        }

        // Fire InstantLockReceived with a lock whose txid matches
        let mut is_lock = dashcore::InstantLock::dummy(0..1);
        is_lock.txid = txid;

        let event = SyncEvent::InstantLockReceived {
            instant_lock: is_lock,
            validated: true,
        };
        let events = manager.handle_sync_event(&event, &requests).await.unwrap();
        assert!(events.is_empty());

        let state = manager.mempool_state.read().await;
        assert!(state.transactions.get(&txid).unwrap().is_instant_send);
    }

    #[tokio::test]
    async fn test_peer_disconnect_removes_from_peers() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        // Activate
        let sync = SyncEvent::SyncComplete {
            header_tip: 1000,
            cycle: 0,
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

        let event = SyncEvent::SyncComplete {
            header_tip: 1000,
            cycle: 0,
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
        let event = SyncEvent::SyncComplete {
            header_tip: 1000,
            cycle: 0,
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
    async fn test_block_processed_confirmed_txids_rebuilds_filter() {
        let mut mock = MockWallet::new();
        // Wallet needs at least one address for the bloom filter to be built
        let script = dashcore::ScriptBuf::from_bytes(vec![
            0x76, 0xa9, 0x14, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x88, 0xac,
        ]);
        let addr = dashcore::Address::from_script(&script, dashcore::Network::Testnet).unwrap();
        mock.set_addresses(vec![addr]);
        let wallet = Arc::new(RwLock::new(mock));
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));
        let (tx, mut rx) = mpsc::unbounded_channel::<NetworkRequest>();
        let requests = RequestSender::new(tx);

        let mut manager =
            MempoolManager::new(wallet, mempool_state, MempoolStrategy::BloomFilter, 1000);

        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        // Activate
        let sync = SyncEvent::SyncComplete {
            header_tip: 1000,
            cycle: 0,
        };
        manager.handle_sync_event(&sync, &requests).await.unwrap();

        // Drain activation messages
        while rx.try_recv().is_ok() {}

        // BlockProcessed with confirmed txids should rebuild immediately
        let event = SyncEvent::BlockProcessed {
            block_hash: dashcore::BlockHash::all_zeros(),
            height: 1001,
            new_addresses: vec![],
            confirmed_txids: vec![dashcore::Txid::all_zeros()],
        };
        manager.handle_sync_event(&event, &requests).await.unwrap();

        // Verify a FilterLoad was sent
        let mut found_filter_load = false;
        while let Ok(req) = rx.try_recv() {
            if matches!(req, NetworkRequest::SendMessageToPeer(NetworkMessage::FilterLoad(_), _)) {
                found_filter_load = true;
            }
        }
        assert!(found_filter_load, "expected FilterLoad after confirmed txids");
    }

    #[tokio::test]
    async fn test_block_processed_no_changes_no_rebuild_flag() {
        let (mut manager, requests, _rx) = create_test_manager();
        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        let sync = SyncEvent::SyncComplete {
            header_tip: 1000,
            cycle: 0,
        };
        manager.handle_sync_event(&sync, &requests).await.unwrap();

        // BlockProcessed with no confirmed txids and no new addresses
        let event = SyncEvent::BlockProcessed {
            block_hash: dashcore::BlockHash::all_zeros(),
            height: 1001,
            new_addresses: vec![],
            confirmed_txids: vec![],
        };
        manager.handle_sync_event(&event, &requests).await.unwrap();
    }
}
