//! Unit tests for watch item management

#[cfg(test)]
mod tests {
    use crate::client::watch_manager::{WatchItemUpdateSender, WatchManager};
    use crate::error::SpvError;
    use crate::storage::memory::MemoryStorageManager;
    use crate::storage::StorageManager;
    use crate::types::WatchItem;
    use crate::wallet::Wallet;
    use dashcore::{Address, ScriptBuf};
    use std::collections::HashSet;
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::sync::{mpsc, RwLock};

    async fn setup_test_components() -> (
        Arc<RwLock<HashSet<WatchItem>>>,
        Arc<RwLock<Wallet>>,
        Option<WatchItemUpdateSender>,
        Box<dyn StorageManager>,
    ) {
        let watch_items = Arc::new(RwLock::new(HashSet::new()));
        let storage_arc = Arc::new(RwLock::new(MemoryStorageManager::new().await.unwrap()));
        let wallet = Arc::new(RwLock::new(Wallet::new(storage_arc.clone())));
        let (tx, _rx) = mpsc::unbounded_channel();
        let storage =
            Box::new(MemoryStorageManager::new().await.unwrap()) as Box<dyn StorageManager>;

        (watch_items, wallet, Some(tx), storage)
    }

    fn create_test_address() -> Address {
        // Create a dummy P2PKH address for testing
        use dashcore::hashes::Hash;
        let pubkey_hash = dashcore::PubkeyHash::from_byte_array([0u8; 20]);
        Address::new(
            dashcore::Network::Testnet,
            dashcore::address::Payload::PubkeyHash(pubkey_hash),
        )
    }

    #[tokio::test]
    async fn test_add_watch_item_address() {
        let (watch_items, wallet, updater, mut storage) = setup_test_components().await;
        let address = create_test_address();
        let item = WatchItem::address(address.clone());

        let result = WatchManager::add_watch_item(
            &watch_items,
            &wallet,
            &updater,
            item.clone(),
            &mut *storage,
        )
        .await;

        assert!(result.is_ok());

        // Verify item was added to watch_items
        let items = watch_items.read().await;
        assert_eq!(items.len(), 1);
        assert!(items.contains(&item));

        // Verify it was persisted to storage
        let stored_data = storage.load_metadata("watch_items").await.unwrap();
        assert!(stored_data.is_some());

        let stored_items: Vec<WatchItem> = serde_json::from_slice(&stored_data.unwrap()).unwrap();
        assert_eq!(stored_items.len(), 1);
        assert_eq!(stored_items[0], item);
    }

    #[tokio::test]
    async fn test_add_watch_item_script() {
        let (watch_items, wallet, updater, mut storage) = setup_test_components().await;
        let script = ScriptBuf::from(vec![0x00, 0x14]); // Dummy script
        let item = WatchItem::Script(script.clone());

        let result = WatchManager::add_watch_item(
            &watch_items,
            &wallet,
            &updater,
            item.clone(),
            &mut *storage,
        )
        .await;

        assert!(result.is_ok());

        // Verify item was added
        let items = watch_items.read().await;
        assert_eq!(items.len(), 1);
        assert!(items.contains(&item));
    }

    #[tokio::test]
    async fn test_add_duplicate_watch_item() {
        let (watch_items, wallet, updater, mut storage) = setup_test_components().await;
        let address = create_test_address();
        let item = WatchItem::address(address);

        // Add item first time
        let result1 = WatchManager::add_watch_item(
            &watch_items,
            &wallet,
            &updater,
            item.clone(),
            &mut *storage,
        )
        .await;
        assert!(result1.is_ok());

        // Try to add same item again
        let result2 = WatchManager::add_watch_item(
            &watch_items,
            &wallet,
            &updater,
            item.clone(),
            &mut *storage,
        )
        .await;
        assert!(result2.is_ok()); // Should succeed but not duplicate

        // Verify only one item exists
        let items = watch_items.read().await;
        assert_eq!(items.len(), 1);
    }

    #[tokio::test]
    async fn test_remove_watch_item() {
        let (watch_items, wallet, updater, mut storage) = setup_test_components().await;
        let address = create_test_address();
        let item = WatchItem::address(address);

        // Add item first
        WatchManager::add_watch_item(&watch_items, &wallet, &updater, item.clone(), &mut *storage)
            .await
            .unwrap();

        // Remove the item
        let result =
            WatchManager::remove_watch_item(&watch_items, &wallet, &updater, &item, &mut *storage)
                .await;

        assert!(result.is_ok());
        assert!(result.unwrap()); // Should return true for successful removal

        // Verify item was removed
        let items = watch_items.read().await;
        assert_eq!(items.len(), 0);

        // Verify storage was updated
        let stored_data = storage.load_metadata("watch_items").await.unwrap();
        assert!(stored_data.is_some());
        let stored_items: Vec<WatchItem> = serde_json::from_slice(&stored_data.unwrap()).unwrap();
        assert_eq!(stored_items.len(), 0);
    }

    #[tokio::test]
    async fn test_remove_nonexistent_watch_item() {
        let (watch_items, wallet, updater, mut storage) = setup_test_components().await;
        let address = create_test_address();
        let item = WatchItem::address(address);

        // Try to remove item that doesn't exist
        let result =
            WatchManager::remove_watch_item(&watch_items, &wallet, &updater, &item, &mut *storage)
                .await;

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should return false for item not found
    }

    #[tokio::test]
    async fn test_load_watch_items_empty() {
        let (watch_items, wallet, _, storage) = setup_test_components().await;

        let result = WatchManager::load_watch_items(&watch_items, &wallet, &*storage).await;

        assert!(result.is_ok());
        let items = watch_items.read().await;
        assert_eq!(items.len(), 0);
    }

    #[tokio::test]
    async fn test_load_watch_items_with_data() {
        let (watch_items, wallet, _, mut storage) = setup_test_components().await;

        // Create test data
        let address1 = create_test_address();
        let script = ScriptBuf::from(vec![0x00, 0x14]);
        let items_to_store = vec![WatchItem::address(address1), WatchItem::Script(script)];

        // Store the data
        let serialized = serde_json::to_vec(&items_to_store).unwrap();
        storage.store_metadata("watch_items", &serialized).await.unwrap();

        // Load the items
        let result = WatchManager::load_watch_items(&watch_items, &wallet, &*storage).await;

        assert!(result.is_ok());
        let items = watch_items.read().await;
        assert_eq!(items.len(), 2);
        for item in &items_to_store {
            assert!(items.contains(item));
        }
    }

    #[tokio::test]
    async fn test_watch_item_update_notification() {
        let watch_items = Arc::new(RwLock::new(HashSet::new()));
        let storage = Arc::new(RwLock::new(MemoryStorageManager::new().await.unwrap()));
        let wallet = Arc::new(RwLock::new(Wallet::new(storage.clone())));
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut storage =
            Box::new(MemoryStorageManager::new().await.unwrap()) as Box<dyn StorageManager>;

        let address = create_test_address();
        let item = WatchItem::address(address);

        // Add item with update sender
        let result = WatchManager::add_watch_item(
            &watch_items,
            &wallet,
            &Some(tx),
            item.clone(),
            &mut *storage,
        )
        .await;

        assert!(result.is_ok());

        // Check that update was sent
        let update = rx.recv().await;
        assert!(update.is_some());
        let updated_items = update.unwrap();
        assert_eq!(updated_items.len(), 1);
        assert_eq!(updated_items[0], item);
    }

    #[tokio::test]
    async fn test_multiple_watch_items() {
        let (watch_items, wallet, updater, mut storage) = setup_test_components().await;

        // Add multiple different items
        let address1 = create_test_address();
        let script1 = ScriptBuf::from(vec![0x00, 0x14]);
        let script2 = ScriptBuf::from(vec![0x00, 0x15]);

        let items = vec![
            WatchItem::address(address1),
            WatchItem::Script(script1),
            WatchItem::Script(script2),
        ];

        for item in &items {
            let result = WatchManager::add_watch_item(
                &watch_items,
                &wallet,
                &updater,
                item.clone(),
                &mut *storage,
            )
            .await;
            assert!(result.is_ok());
        }

        // Verify all items were added
        let stored_items = watch_items.read().await;
        assert_eq!(stored_items.len(), 3);
        for item in &items {
            assert!(stored_items.contains(item));
        }

        // Verify persistence
        let stored_data = storage.load_metadata("watch_items").await.unwrap().unwrap();
        let persisted_items: Vec<WatchItem> = serde_json::from_slice(&stored_data).unwrap();
        assert_eq!(persisted_items.len(), 3);
    }

    #[tokio::test]
    async fn test_error_handling_corrupt_storage_data() {
        let (watch_items, wallet, _, mut storage) = setup_test_components().await;

        // Store corrupt data
        let corrupt_data = b"not valid json";
        storage.store_metadata("watch_items", corrupt_data).await.unwrap();

        // Try to load
        let result = WatchManager::load_watch_items(&watch_items, &wallet, &*storage).await;

        // Should fail with deserialization error
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to deserialize"));
    }

    #[tokio::test]
    async fn test_watch_item_with_label() {
        let (watch_items, wallet, updater, mut storage) = setup_test_components().await;
        let address = create_test_address();
        let item = WatchItem::Address {
            address: address.clone(),
            earliest_height: None,
        };

        let result = WatchManager::add_watch_item(
            &watch_items,
            &wallet,
            &updater,
            item.clone(),
            &mut *storage,
        )
        .await;

        assert!(result.is_ok());

        // Verify label is preserved
        let items = watch_items.read().await;
        assert_eq!(items.len(), 1);
        let stored_item = items.iter().next().unwrap();
        if let WatchItem::Address {
            earliest_height,
            ..
        } = stored_item
        {
            assert_eq!(*earliest_height, None);
        } else {
            panic!("Expected Address watch item");
        }
    }

    #[tokio::test]
    async fn test_concurrent_add_operations() {
        let (watch_items, wallet, updater, storage) = setup_test_components().await;
        let storage = Arc::new(tokio::sync::Mutex::new(storage));

        // Create multiple different items
        let items: Vec<WatchItem> =
            (0..5).map(|i| WatchItem::Script(ScriptBuf::from(vec![0x00, i as u8]))).collect();

        // Add items concurrently
        let mut handles = vec![];
        for item in items {
            let watch_items = watch_items.clone();
            let wallet = wallet.clone();
            let updater = updater.clone();
            let storage = storage.clone();

            let handle = tokio::spawn(async move {
                let mut storage_guard = storage.lock().await;
                WatchManager::add_watch_item(
                    &watch_items,
                    &wallet,
                    &updater,
                    item,
                    &mut **storage_guard,
                )
                .await
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }

        // Verify all items were added
        let items = watch_items.read().await;
        assert_eq!(items.len(), 5);
    }
}
