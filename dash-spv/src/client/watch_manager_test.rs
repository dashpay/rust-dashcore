//! Unit tests for watch item management

#[cfg(test)]
mod tests {
    use crate::client::watch_manager::{WatchItemUpdateSender, WatchManager};
    use crate::error::SpvError;
    use crate::storage::memory::MemoryStorageManager;
    use crate::storage::StorageManager;
    use crate::types::WatchItem;
    use dashcore::{Address, Network, OutPoint, Script, ScriptBuf, Txid};
    use std::collections::HashSet;
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::sync::{mpsc, RwLock};

    // Mock wallet implementation for testing
    struct MockWallet {
        network: Network,
        watched_addresses: Arc<RwLock<HashSet<Address>>>,
    }

    impl MockWallet {
        fn new(network: Network) -> Self {
            Self {
                network,
                watched_addresses: Arc::new(RwLock::new(HashSet::new())),
            }
        }
    }

    #[async_trait::async_trait]
    impl key_wallet_manager::wallet_interface::WalletInterface for MockWallet {
        async fn process_block(
            &mut self,
            _block: &dashcore::Block,
            _height: u32,
            _network: dashcore::Network,
        ) -> Vec<dashcore::Txid> {
            Vec::new()
        }

        async fn process_mempool_transaction(
            &mut self,
            _tx: &dashcore::Transaction,
            _network: dashcore::Network,
        ) {
            // Not used in these tests
        }

        async fn handle_reorg(
            &mut self,
            _from_height: u32,
            _to_height: u32,
            _network: dashcore::Network,
        ) {
            // Not used in these tests
        }

        async fn check_compact_filter(
            &mut self,
            _filter: &dashcore::bip158::BlockFilter,
            _block_hash: &dashcore::BlockHash,
            _network: dashcore::Network,
        ) -> bool {
            false
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn test_address(network: Network) -> Address {
        Address::from_str("XjbaGWaGnvEtuQAUoBgDxJWe8ZNv45upG2")
            .unwrap()
            .require_network(network)
            .unwrap()
    }

    fn test_address2(network: Network) -> Address {
        Address::from_str("Xan9iCVe1q5jYRDZ4VSMCtBjq2VyQA3Dge")
            .unwrap()
            .require_network(network)
            .unwrap()
    }

    #[tokio::test]
    async fn test_add_watch_item() {
        let watch_items = Arc::new(RwLock::new(HashSet::new()));
        let (tx, _rx) = mpsc::unbounded_channel();
        let updater = Some(tx);
        let mut storage = MemoryStorageManager::new().await.unwrap();

        let addr = test_address(Network::Dash);
        let item = WatchItem::address(addr.clone());

        // Add watch item
        WatchManager::add_watch_item(&watch_items, &updater, item.clone(), &mut storage)
            .await
            .unwrap();

        // Verify it was added
        let items = watch_items.read().await;
        assert_eq!(items.len(), 1);
        assert!(items.contains(&item));
    }

    #[tokio::test]
    async fn test_remove_watch_item() {
        let watch_items = Arc::new(RwLock::new(HashSet::new()));
        let (tx, _rx) = mpsc::unbounded_channel();
        let updater = Some(tx);
        let mut storage = MemoryStorageManager::new().await.unwrap();

        let addr = test_address(Network::Dash);
        let item = WatchItem::address(addr.clone());

        // Add item first
        WatchManager::add_watch_item(&watch_items, &updater, item.clone(), &mut storage)
            .await
            .unwrap();

        // Remove item
        let removed = WatchManager::remove_watch_item(&watch_items, &updater, &item, &mut storage)
            .await
            .unwrap();

        assert!(removed);

        // Verify it was removed
        let items = watch_items.read().await;
        assert_eq!(items.len(), 0);
    }

    #[tokio::test]
    async fn test_duplicate_watch_item() {
        let watch_items = Arc::new(RwLock::new(HashSet::new()));
        let (tx, _rx) = mpsc::unbounded_channel();
        let updater = Some(tx);
        let mut storage = MemoryStorageManager::new().await.unwrap();

        let addr = test_address(Network::Dash);
        let item = WatchItem::address(addr.clone());

        // Add item first time
        WatchManager::add_watch_item(&watch_items, &updater, item.clone(), &mut storage)
            .await
            .unwrap();

        // Try to add same item again - should fail
        let result = WatchManager::add_watch_item(&watch_items, &updater, item, &mut storage).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SpvError::WatchItem(_)));

        // Should still only have one item
        let items = watch_items.read().await;
        assert_eq!(items.len(), 1);
    }

    #[tokio::test]
    async fn test_multiple_watch_items() {
        let watch_items = Arc::new(RwLock::new(HashSet::new()));
        let (tx, _rx) = mpsc::unbounded_channel();
        let updater = Some(tx);
        let mut storage = MemoryStorageManager::new().await.unwrap();

        let addr1 = test_address(Network::Dash);
        let addr2 = test_address2(Network::Dash);
        let script = addr1.script_pubkey();
        let outpoint = OutPoint {
            txid: Txid::from_str(
                "0101010101010101010101010101010101010101010101010101010101010101",
            )
            .unwrap(),
            vout: 0,
        };

        let item1 = WatchItem::address(addr1);
        let item2 = WatchItem::address(addr2);
        let item3 = WatchItem::Script(script);
        let item4 = WatchItem::Outpoint(outpoint);

        // Add all items
        WatchManager::add_watch_item(&watch_items, &updater, item1.clone(), &mut storage)
            .await
            .unwrap();
        WatchManager::add_watch_item(&watch_items, &updater, item2.clone(), &mut storage)
            .await
            .unwrap();
        WatchManager::add_watch_item(&watch_items, &updater, item3.clone(), &mut storage)
            .await
            .unwrap();
        WatchManager::add_watch_item(&watch_items, &updater, item4.clone(), &mut storage)
            .await
            .unwrap();

        // Verify all were added
        let items = watch_items.read().await;
        assert_eq!(items.len(), 4);
        assert!(items.contains(&item1));
        assert!(items.contains(&item2));
        assert!(items.contains(&item3));
        assert!(items.contains(&item4));
    }

    #[tokio::test]
    async fn test_load_watch_items() {
        let watch_items = Arc::new(RwLock::new(HashSet::new()));
        let (tx, _rx) = mpsc::unbounded_channel();
        let updater = Some(tx);
        let mut storage = MemoryStorageManager::new().await.unwrap();

        let addr = test_address(Network::Dash);
        let item = WatchItem::address(addr.clone());

        // Add and persist item
        WatchManager::add_watch_item(&watch_items, &updater, item.clone(), &mut storage)
            .await
            .unwrap();

        // Clear local watch items
        {
            let mut items = watch_items.write().await;
            items.clear();
        }

        // Load from storage
        WatchManager::load_watch_items(&watch_items, &storage).await.unwrap();

        // Verify it was loaded
        let items = watch_items.read().await;
        assert_eq!(items.len(), 1);
        assert!(items.contains(&item));
    }

    #[tokio::test]
    async fn test_watch_item_with_earliest_height() {
        let watch_items = Arc::new(RwLock::new(HashSet::new()));
        let (tx, _rx) = mpsc::unbounded_channel();
        let updater = Some(tx);
        let mut storage = MemoryStorageManager::new().await.unwrap();

        let addr = test_address(Network::Dash);
        let item = WatchItem::address_from_height(addr.clone(), 100000);

        // Add watch item with height
        WatchManager::add_watch_item(&watch_items, &updater, item.clone(), &mut storage)
            .await
            .unwrap();

        // Verify it was added with correct height
        let items = watch_items.read().await;
        assert_eq!(items.len(), 1);

        if let WatchItem::Address {
            address,
            earliest_height,
        } = items.iter().next().unwrap()
        {
            assert_eq!(*address, addr);
            assert_eq!(*earliest_height, Some(100000));
        } else {
            panic!("Expected Address watch item");
        }
    }

    #[tokio::test]
    async fn test_concurrent_watch_item_updates() {
        let watch_items = Arc::new(RwLock::new(HashSet::new()));
        let (tx, _rx) = mpsc::unbounded_channel();
        let updater = Some(tx);
        let storage = Arc::new(tokio::sync::Mutex::new(MemoryStorageManager::new().await.unwrap()));

        // Create multiple unique addresses
        let addresses: Vec<Address> =
            vec![test_address(Network::Dash), test_address2(Network::Dash)];

        // Add items concurrently
        let mut handles = vec![];
        for (i, addr) in addresses.iter().enumerate() {
            let watch_items = watch_items.clone();
            let updater = updater.clone();
            let storage = storage.clone();
            let item = WatchItem::address_from_height(addr.clone(), (i as u32) * 1000);

            let handle = tokio::spawn(async move {
                let mut storage = storage.lock().await;
                WatchManager::add_watch_item(&watch_items, &updater, item, &mut *storage).await
            });
            handles.push(handle);
        }

        // Wait for all to complete
        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }

        // Verify all items were added
        let items = watch_items.read().await;
        assert_eq!(items.len(), 2);
    }
}
