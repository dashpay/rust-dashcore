use super::manager::MEMPOOL_TX_EXPIRY;
use crate::error::SyncResult;
use crate::network::{InboundMessage, MessageType, NetworkEvent, NetworkManager};
use crate::sync::{
    ManagerIdentifier, MempoolManager, SyncEvent, SyncManager, SyncManagerProgress, SyncState,
};
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use key_wallet_manager::WalletInterface;
use std::net::SocketAddr;
use std::sync::Arc;

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

    async fn start_sync(
        &mut self,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        // After a full disconnect, re-activate mempool on all connected peers
        self.activate_all_peers(network).await?;
        let has_activated = self.peers.values().any(|v| v.is_some());
        if has_activated {
            self.set_state(SyncState::Synced);
            tracing::info!("Mempool manager re-activated after disconnect recovery");
        }
        // If no peers could be activated, stay in WaitingForConnections so the
        // next PeersUpdated event will retry activation.
        Ok(vec![])
    }

    /// The only thing that seeds `self.peers`; it works only because the network manager
    /// connects in `start`, after the coordinator has subscribed us.
    async fn handle_network_event(
        &mut self,
        event: &NetworkEvent,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        match event {
            NetworkEvent::PeerConnected(addr) => {
                self.handle_peer_connected(*addr);
                // If synced, activate the new peer immediately; otherwise
                // `FiltersSyncComplete` (or `start_sync`) will.
                if self.state() == SyncState::Synced
                    && self.peers.get(addr).is_some_and(|v| v.is_none())
                {
                    tracing::info!("Activating mempool on newly connected peer {}", addr);
                    self.activate_peer(*addr, network).await?;
                }
                Ok(vec![])
            }
            NetworkEvent::PeerDisconnected(addr) => {
                // Hands this peer's queued txids to another activated peer.
                self.handle_peer_disconnected(*addr);
                Ok(vec![])
            }
            _ => {
                crate::sync::sync_manager::default_handle_network_event(self, event, network).await
            }
        }
    }

    fn on_disconnect(&mut self) {
        self.clear_pending();
    }

    async fn handle_message(
        &mut self,
        peer: SocketAddr,
        msg: InboundMessage,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        match msg.into_inner() {
            NetworkMessage::Tx(tx) => self.handle_tx(*tx, peer, network).await,
            NetworkMessage::Inv(inv) => self.handle_inv(&inv, peer, network).await,
            _ => Ok(vec![]),
        }
    }

    async fn handle_sync_event(
        &mut self,
        event: &SyncEvent,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        match event {
            // Activate as soon as filter sync completes — the wallet's address
            // and UTXO set is fully populated at this point.
            SyncEvent::FiltersSyncComplete {
                ..
            } => {
                if self.state() != SyncState::Synced {
                    self.activate_all_peers(network).await?;
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
                    return Ok(self.remove_confirmed(confirmed_txids));
                }
                Ok(vec![])
            }
            SyncEvent::InstantLockReceived {
                instant_lock,
                ..
            } => Ok(self.process_instant_send(instant_lock.clone()).await),
            _ => Ok(vec![]),
        }
    }

    async fn tick(&mut self, network: &Arc<dyn NetworkManager>) -> SyncResult<Vec<SyncEvent>> {
        // Broadcast bookkeeping runs regardless of sync state: broadcasts can
        // be initiated (and time out) before the mempool phase is synced.
        let events = self.expire_broadcasts();
        self.rebroadcast_if_due(network).await;

        if self.state() != SyncState::Synced {
            return Ok(events);
        }

        // Prune expired transactions periodically
        self.prune_expired(MEMPOOL_TX_EXPIRY);

        // Prune pending requests that never received a response
        self.prune_pending_requests();

        // Send queued getdata requests now that slots may have freed up
        self.send_queued(network).await?;

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
            self.rebuild_filter(network).await?;
            self.last_monitor_revision = current_revision;
        }

        Ok(events)
    }

    fn progress(&self) -> SyncManagerProgress {
        SyncManagerProgress::Mempool(self.progress.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::config::MempoolStrategy;
    use crate::sync::BroadcastConfig;
    use crate::test_utils::{test_socket_address, MockNetworkManager};
    use dashcore::hashes::Hash;
    use key_wallet_manager::test_utils::MockWallet;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn create_test_manager() -> (MempoolManager<MockWallet>, Arc<dyn NetworkManager>) {
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        let network: Arc<dyn NetworkManager> = Arc::new(MockNetworkManager::new());

        let manager = MempoolManager::new(
            wallet,
            MempoolStrategy::FetchAll,
            1000,
            0,
            BroadcastConfig::default(),
        );

        (manager, network)
    }

    #[test]
    fn test_sync_manager_trait_basics() {
        let (mut manager, _) = create_test_manager();

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
        let (mut manager, network) = create_test_manager();
        let peer = crate::test_utils::test_socket_address(1);
        manager.handle_peer_connected(peer);

        let event = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };

        let events = manager.handle_sync_event(&event, &network).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::Synced);
        assert!(matches!(manager.peers.get(&peer), Some(Some(_))));
    }

    #[tokio::test]
    async fn test_filters_sync_complete_subsequent_is_noop() {
        let (mut manager, network) = create_test_manager();
        manager.handle_peer_connected(crate::test_utils::test_socket_address(1));

        // Activate first
        let event0 = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&event0, &network).await.unwrap();

        // Subsequent filter sync completions should not change state
        let event1 = SyncEvent::FiltersSyncComplete {
            tip_height: 1001,
        };
        let events = manager.handle_sync_event(&event1, &network).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::Synced);
    }

    #[tokio::test]
    async fn test_reactivation_after_disconnect() {
        let (mut manager, network) = create_test_manager();
        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        // Initial activation
        let event = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        let events = manager.handle_sync_event(&event, &network).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::Synced);

        // Simulate disconnect by resetting state
        manager.set_state(SyncState::WaitForEvents);

        // Re-sync should re-activate
        let event = SyncEvent::FiltersSyncComplete {
            tip_height: 1001,
        };
        let events = manager.handle_sync_event(&event, &network).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::Synced);
    }

    #[tokio::test]
    async fn test_peer_connect_activates_when_synced() {
        let (mut manager, network) = create_test_manager();
        let peer1 = test_socket_address(1);
        manager.handle_peer_connected(peer1);

        // Activate via SyncComplete
        let event = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&event, &network).await.unwrap();
        assert!(matches!(manager.peers.get(&peer1), Some(Some(_))));

        // New peer connects while synced => should activate immediately
        let peer2 = test_socket_address(2);
        let connect = NetworkEvent::PeerConnected(peer2);
        let events = manager.handle_network_event(&connect, &network).await.unwrap();
        assert!(events.is_empty());
        assert!(matches!(manager.peers.get(&peer2), Some(Some(_))));
    }

    #[tokio::test]
    async fn test_network_event_peer_connect_disconnect() {
        let (mut manager, network) = create_test_manager();

        let peer1 = test_socket_address(1);
        let peer2 = test_socket_address(2);

        // Connecting peers should return empty events (not synced yet)
        let connect1 = NetworkEvent::PeerConnected(peer1);
        let events = manager.handle_network_event(&connect1, &network).await.unwrap();
        assert!(events.is_empty());
        assert!(manager.peers.contains_key(&peer1));

        let connect2 = NetworkEvent::PeerConnected(peer2);
        let events = manager.handle_network_event(&connect2, &network).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.peers.len(), 2);

        let disconnect1 = NetworkEvent::PeerDisconnected(peer1);
        let events = manager.handle_network_event(&disconnect1, &network).await.unwrap();
        assert!(events.is_empty());

        // Still have peer2 available
        assert!(manager.peers.contains_key(&peer2));
        assert_eq!(manager.peers.len(), 1);

        // Disconnecting an already-disconnected peer should not error
        let events = manager.handle_network_event(&disconnect1, &network).await.unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn test_block_processed_removes_confirmed_txids() {
        let (mut manager, network) = create_test_manager();
        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        // Activate
        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &network).await.unwrap();

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
            new_scripts: BTreeMap::new(),
            confirmed_txids: txids.clone(),
        };
        let events = manager.handle_sync_event(&event, &network).await.unwrap();
        assert!(events.is_empty());

        assert!(manager.transactions.is_empty());
    }

    #[tokio::test]
    async fn test_instant_lock_received_marks_transaction() {
        let (mut manager, network) = create_test_manager();
        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        // Activate
        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &network).await.unwrap();

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
        let events = manager.handle_sync_event(&event, &network).await.unwrap();
        assert!(events.is_empty());

        assert!(manager.transactions.get(&txid).unwrap().is_instant_send);

        use dashcore::{InstantLock, OutPoint, Transaction, TxOut};
        use key_wallet::account::StandardAccountType;
        use key_wallet::managed_account::managed_account_trait::ManagedAccountTrait;
        use key_wallet::managed_account::transaction_record::TransactionDirection;
        use key_wallet::test_utils::TestWalletContext;
        use key_wallet::transaction_checking::TransactionContext;
        use key_wallet::wallet::managed_wallet_info::managed_account_operations::ManagedAccountOperations;
        use key_wallet::wallet::ManagedWalletInfo;
        use key_wallet::AccountType;
        use key_wallet_manager::{WalletEvent, WalletManager};

        let mut ctx = TestWalletContext::new_random();
        let account_type = AccountType::Standard {
            index: 1,
            standard_account_type: StandardAccountType::BIP44Account,
        };
        ctx.wallet.add_account(account_type, None).unwrap();
        let mut preview =
            ManagedWalletInfo::from_wallet_with_name(&ctx.wallet, "preview".into(), 0);
        let address = preview
            .bip44_managed_account_at_index_mut(1)
            .unwrap()
            .next_receive_address(None, true)
            .unwrap();
        let mut funding = Transaction::dummy(&ctx.receive_address, 0..1, &[100_000]);
        funding.output.push(TxOut {
            value: 50_000,
            script_pubkey: address.script_pubkey(),
        });
        let mut spender = Transaction::dummy(&address, 1..2, &[40_000]);
        let outpoint = OutPoint::new(funding.txid(), 1);
        spender.input[0].previous_output = outpoint;

        let mut wallet = WalletManager::new(dashcore::Network::Testnet);
        let wallet_id = wallet.insert_wallet(ctx.wallet, ctx.managed_wallet).unwrap();
        let wallet = Arc::new(RwLock::new(wallet));
        let mut manager = MempoolManager::new(
            wallet.clone(),
            MempoolStrategy::FetchAll,
            1000,
            0,
            BroadcastConfig::default(),
        );
        manager
            .handle_message(peer, NetworkMessage::Tx(funding.clone().into()).into(), &network)
            .await
            .unwrap();
        {
            let mut wallet = wallet.write().await;
            let (inner, info) = wallet.get_wallet_and_info_mut(&wallet_id).unwrap();
            info.add_managed_account(inner, account_type).unwrap();
        }
        manager
            .handle_message(peer, NetworkMessage::Tx(spender.clone().into()).into(), &network)
            .await
            .unwrap();
        let mut rx = wallet.read().await.subscribe_events();
        let lock = InstantLock {
            txid: funding.txid(),
            ..InstantLock::default()
        };
        let event = SyncEvent::InstantLockReceived {
            instant_lock: lock,
            validated: true,
        };
        manager.handle_sync_event(&event, &network).await.unwrap();
        let mut corrections = Vec::new();
        let mut backfilled = 0;
        let mut locked = 0;
        while let Ok(event) = rx.try_recv() {
            match event {
                WalletEvent::TransactionDetected {
                    record,
                    ..
                } if record.txid == spender.txid() => {
                    corrections.push(record);
                }
                WalletEvent::TransactionDetected {
                    record,
                    ..
                } if record.txid == funding.txid() => {
                    assert_eq!(record.account_type, account_type);
                    backfilled += 1;
                }
                WalletEvent::TransactionInstantLocked {
                    txid,
                    ..
                } => {
                    assert_eq!(txid, funding.txid(), "funding lock must not lock the child");
                    locked += 1;
                }
                _ => {}
            }
        }
        assert_eq!(backfilled, 1);
        assert_eq!(locked, 1);
        assert_eq!(corrections.len(), 1);
        let corrected = &corrections[0];
        assert_eq!(corrected.net_amount, -10_000);
        assert_eq!(corrected.direction, TransactionDirection::Internal);
        assert_eq!(corrected.context, TransactionContext::Mempool);
        assert_eq!(corrected.input_details.len(), 1);
        {
            let wallet = wallet.read().await;
            let account = wallet
                .get_wallet_info(&wallet_id)
                .unwrap()
                .bip44_managed_account_at_index(1)
                .unwrap();
            assert_eq!(account.transactions()[&spender.txid()].net_amount, -10_000);
            assert!(!account.utxos.contains_key(&outpoint));
        }
        manager.handle_sync_event(&event, &network).await.unwrap();
        manager
            .handle_message(peer, NetworkMessage::Tx(funding.clone().into()).into(), &network)
            .await
            .unwrap();
        assert!(rx.try_recv().is_err(), "duplicate lock/transaction must not emit events");

        // Both accounts already know these transactions; block processing can precede mempool cleanup.
        for confirmed in [false, true] {
            let mut tx = Transaction::dummy(&address, 10 + u8::from(confirmed)..12, &[50_000]);
            tx.output = funding.output.clone();
            manager
                .handle_message(peer, NetworkMessage::Tx(tx.clone().into()).into(), &network)
                .await
                .unwrap();
            let block_context =
                TransactionContext::InBlock(key_wallet::transaction_checking::BlockInfo::new(
                    1001,
                    dashcore::BlockHash::from_byte_array([0xab; 32]),
                    1700000000,
                ));
            if confirmed {
                wallet
                    .write()
                    .await
                    .check_transaction_in_all_wallets(&tx, block_context.clone(), true, true)
                    .await;
            }
            while rx.try_recv().is_ok() {}
            let event = SyncEvent::InstantLockReceived {
                instant_lock: InstantLock {
                    txid: tx.txid(),
                    ..InstantLock::default()
                },
                validated: true,
            };
            manager.handle_sync_event(&event, &network).await.unwrap();
            let mut locks = 0;
            while let Ok(event) = rx.try_recv() {
                assert!(
                    matches!(event, WalletEvent::TransactionInstantLocked { txid, .. } if txid == tx.txid())
                );
                locks += 1;
            }
            assert_eq!(locks, 1, "one lock event per wallet, including after confirmation");
            {
                let wallet = wallet.read().await;
                for index in [0, 1] {
                    let account = wallet
                        .get_wallet_info(&wallet_id)
                        .unwrap()
                        .bip44_managed_account_at_index(index)
                        .unwrap();
                    let record = &account.transactions()[&tx.txid()];
                    if confirmed {
                        assert_eq!(record.context, block_context);
                    } else {
                        assert!(matches!(record.context, TransactionContext::InstantSend(_)));
                    }
                    assert!(account.utxos[&OutPoint::new(tx.txid(), index)].is_instantlocked);
                }
            }
            manager.handle_sync_event(&event, &network).await.unwrap();
            assert!(rx.try_recv().is_err());
        }

        let foreign = dashcore::Address::dummy(dashcore::Network::Testnet, 999);
        let mut outgoing = Transaction::dummy(&foreign, 20..21, &[99_000]);
        outgoing.input[0].previous_output = OutPoint::new(funding.txid(), 0);
        manager
            .handle_message(peer, NetworkMessage::Tx(outgoing.clone().into()).into(), &network)
            .await
            .unwrap();
        while rx.try_recv().is_ok() {}
        let event = SyncEvent::InstantLockReceived {
            instant_lock: InstantLock {
                txid: outgoing.txid(),
                ..InstantLock::default()
            },
            validated: true,
        };
        manager.handle_sync_event(&event, &network).await.unwrap();
        assert!(
            matches!(rx.try_recv().unwrap(), WalletEvent::TransactionInstantLocked { txid, .. } if txid == outgoing.txid())
        );
        assert!(rx.try_recv().is_err());
        let wallet = wallet.read().await;
        let account =
            wallet.get_wallet_info(&wallet_id).unwrap().first_bip44_managed_account().unwrap();
        assert!(matches!(
            account.transactions()[&outgoing.txid()].context,
            TransactionContext::InstantSend(_)
        ));
    }

    #[tokio::test]
    async fn test_peer_disconnect_removes_from_peers() {
        let (mut manager, network) = create_test_manager();
        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        // Activate
        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &network).await.unwrap();

        // Disconnect the only peer
        let disconnect = NetworkEvent::PeerDisconnected(peer);
        let events = manager.handle_network_event(&disconnect, &network).await.unwrap();
        assert!(events.is_empty());
        assert!(manager.peers.is_empty());
    }

    #[tokio::test]
    async fn test_sync_complete_no_peers_stays_inactive() {
        let (mut manager, network) = create_test_manager();

        let event = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        let events = manager.handle_sync_event(&event, &network).await.unwrap();

        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::WaitForEvents);
        assert!(manager.peers.is_empty());
    }

    #[tokio::test]
    async fn test_start_sync_no_peers_stays_waiting() {
        let (mut manager, network) = create_test_manager();

        // Simulate full disconnect setting state to WaitingForConnections
        manager.set_state(SyncState::WaitingForConnections);

        // start_sync with no peers should stay in WaitingForConnections
        let events = manager.start_sync(&network).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(manager.state(), SyncState::WaitingForConnections);
    }

    #[tokio::test]
    async fn test_disconnect_recovery_reactivates_on_reconnect() {
        let (mut manager, network) = create_test_manager();
        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        // Activate via SyncComplete
        let event = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&event, &network).await.unwrap();
        assert_eq!(manager.state(), SyncState::Synced);

        // Disconnect peer
        let disconnect = NetworkEvent::PeerDisconnected(peer);
        manager.handle_network_event(&disconnect, &network).await.unwrap();

        // Losing the last peer makes the coordinator reset the manager
        manager.on_disconnect();
        manager.set_state(SyncState::WaitingForConnections);

        // PeersUpdated with 1 but no peers tracked yet: stays WaitingForConnections
        let update = NetworkEvent::PeersUpdated {
            connected_count: 1,
            best_height: 1000,
        };
        manager.handle_network_event(&update, &network).await.unwrap();
        assert_eq!(manager.state(), SyncState::WaitingForConnections);

        // Peer reconnects and PeersUpdated fires again
        manager.handle_peer_connected(peer);
        let update = NetworkEvent::PeersUpdated {
            connected_count: 1,
            best_height: 1000,
        };
        manager.handle_network_event(&update, &network).await.unwrap();
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
        let network_mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = network_mock.clone();

        let mut manager = MempoolManager::new(
            wallet,
            MempoolStrategy::BloomFilter,
            1000,
            0,
            BroadcastConfig::default(),
        );

        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        // Activate
        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &network).await.unwrap();

        // Drain activation messages
        network_mock.clear_sent();

        // BlockProcessed does not eagerly rebuild — the tick handles it via
        // the revision check. Verify no FilterLoad is sent from the event handler.
        let event = SyncEvent::BlockProcessed {
            block_hash: dashcore::BlockHash::all_zeros(),
            height: 1001,
            wallets: BTreeSet::new(),
            new_scripts: BTreeMap::new(),
            confirmed_txids: vec![dashcore::Txid::all_zeros()],
        };
        manager.handle_sync_event(&event, &network).await.unwrap();

        let has_filter_load = network_mock
            .sent_to_messages()
            .into_iter()
            .any(|(_, req)| matches!(req, NetworkMessage::FilterLoad(_)));
        assert!(!has_filter_load, "BlockProcessed should not eagerly rebuild filter");
    }

    #[tokio::test]
    async fn test_block_processed_no_changes_no_rebuild_flag() {
        let (mut manager, network) = create_test_manager();
        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &network).await.unwrap();

        // BlockProcessed with no confirmed txids and no new addresses
        let event = SyncEvent::BlockProcessed {
            block_hash: dashcore::BlockHash::all_zeros(),
            height: 1001,
            wallets: BTreeSet::new(),
            new_scripts: BTreeMap::new(),
            confirmed_txids: vec![],
        };
        manager.handle_sync_event(&event, &network).await.unwrap();
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
        let network_mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = network_mock.clone();

        let mut manager = MempoolManager::new(
            wallet.clone(),
            MempoolStrategy::BloomFilter,
            1000,
            initial_revision,
            BroadcastConfig::default(),
        );

        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        // Activate — this snapshots the monitor revision
        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &network).await.unwrap();
        assert_eq!(manager.state(), SyncState::Synced);

        // Drain activation messages
        network_mock.clear_sent();

        // tick with unchanged revision should not rebuild
        manager.tick(&network).await.unwrap();
        assert!(
            network_mock.sent_to_messages().is_empty(),
            "no messages expected when revision unchanged"
        );

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
        manager.tick(&network).await.unwrap();

        let mut found_filter_load = false;
        for (_, msg) in network_mock.sent_to_messages() {
            if matches!(msg, NetworkMessage::FilterLoad(_)) {
                found_filter_load = true;
            }
        }
        assert!(found_filter_load, "expected FilterLoad after monitor revision change");

        // Subsequent tick should not rebuild again (revision was snapshotted)
        network_mock.clear_sent();
        manager.tick(&network).await.unwrap();
        assert!(
            network_mock.sent_to_messages().is_empty(),
            "no messages expected after revision re-snapshot"
        );
    }

    #[tokio::test]
    async fn test_tick_skips_rebuild_for_fetch_all_strategy() {
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        let network_mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = network_mock.clone();

        let mut manager = MempoolManager::new(
            wallet.clone(),
            MempoolStrategy::FetchAll,
            1000,
            0,
            BroadcastConfig::default(),
        );

        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &network).await.unwrap();
        network_mock.clear_sent();

        // Bump revision
        {
            let mut w = wallet.write().await;
            w.set_addresses(vec![dashcore::Address::dummy(dashcore::Network::Testnet, 0)]);
        }

        // tick should not send any filter messages for FetchAll
        manager.tick(&network).await.unwrap();
        let mut found_filter = false;
        for (_, msg) in network_mock.sent_to_messages() {
            if matches!(msg, NetworkMessage::FilterLoad(_) | NetworkMessage::FilterClear) {
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
        let network_mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = network_mock.clone();

        let mut manager = MempoolManager::new(
            wallet.clone(),
            MempoolStrategy::BloomFilter,
            1000,
            initial_revision,
            BroadcastConfig::default(),
        );

        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &network).await.unwrap();
        network_mock.clear_sent();

        // Simulate UTXO set change (new outpoint added)
        {
            let mut w = wallet.write().await;
            w.set_outpoints(vec![dashcore::OutPoint {
                txid: dashcore::Txid::from_byte_array([0xee; 32]),
                vout: 0,
            }]);
        }

        // tick should detect the revision change and rebuild
        manager.tick(&network).await.unwrap();

        let found_filter_load = network_mock
            .sent_to_messages()
            .into_iter()
            .any(|(_, msg)| matches!(msg, NetworkMessage::FilterLoad(_)));
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
        let network_mock = Arc::new(MockNetworkManager::new());
        let network: Arc<dyn NetworkManager> = network_mock.clone();

        let mut manager = MempoolManager::new(
            wallet.clone(),
            MempoolStrategy::BloomFilter,
            1000,
            initial_revision,
            BroadcastConfig::default(),
        );

        let peer = test_socket_address(1);
        manager.handle_peer_connected(peer);

        let sync = SyncEvent::FiltersSyncComplete {
            tip_height: 1000,
        };
        manager.handle_sync_event(&sync, &network).await.unwrap();
        network_mock.clear_sent();

        // handle_tx with a relevant transaction should NOT eagerly rebuild
        let tx = dashcore::Transaction {
            version: 1,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };
        manager.handle_tx(tx, test_socket_address(1), &network).await.unwrap();

        let has_filter_load = network_mock
            .sent_to_messages()
            .into_iter()
            .any(|(_, msg)| matches!(msg, NetworkMessage::FilterLoad(_)));
        assert!(!has_filter_load, "handle_tx should not eagerly rebuild filter");

        // But the next tick should catch it if the wallet revision changed
        // (MockWallet bumps revision when set_mempool_relevant triggers processing)
        {
            let mut w = wallet.write().await;
            w.set_addresses(vec![dashcore::Address::dummy(dashcore::Network::Testnet, 0)]);
        }
        manager.tick(&network).await.unwrap();

        let found_filter_load = network_mock
            .sent_to_messages()
            .into_iter()
            .any(|(_, msg)| matches!(msg, NetworkMessage::FilterLoad(_)));
        assert!(found_filter_load, "tick should rebuild after revision change");
    }
}
