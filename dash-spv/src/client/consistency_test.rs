//! Unit tests for wallet consistency validation and recovery

#[cfg(test)]
mod tests {
    use crate::client::consistency::{ConsistencyManager, ConsistencyRecovery, ConsistencyReport};
    use crate::storage::memory::MemoryStorageManager;
    use crate::storage::StorageManager;
    use crate::types::WatchItem;
    use crate::wallet::utxo::Utxo as SpvUtxo;
    use crate::wallet::Wallet;
    use dashcore::{Address, OutPoint, Txid};
    use dashcore_hashes::Hash;
    use std::collections::HashSet;
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn create_test_address() -> Address {
        Address::from_str("XeNTGz5bVjPNZVPpwTRz6SnLbZGxLqJUg4").unwrap().assume_checked()
    }

    fn create_test_utxo(index: u32) -> SpvUtxo {
        SpvUtxo {
            outpoint: OutPoint {
                txid: Txid::all_zeros(),
                vout: index,
            },
            txout: dashcore::TxOut {
                value: 1000 + (index as u64 * 100),
                script_pubkey: create_test_address().script_pubkey(),
            },
            address: create_test_address(),
            height: 100 + index,
            is_coinbase: false,
            is_confirmed: true,
            is_instantlocked: false,
        }
    }

    async fn setup_test_components(
    ) -> (Arc<RwLock<Wallet>>, Box<dyn StorageManager>, Arc<RwLock<HashSet<WatchItem>>>) {
        let wallet = Arc::new(RwLock::new(Wallet::new()));
        let storage =
            Box::new(MemoryStorageManager::new().await.unwrap()) as Box<dyn StorageManager>;
        let watch_items = Arc::new(RwLock::new(HashSet::new()));

        (wallet, storage, watch_items)
    }

    #[tokio::test]
    async fn test_validate_consistency_all_consistent() {
        let (wallet, mut storage, watch_items) = setup_test_components().await;

        // Add same UTXOs to both wallet and storage
        let utxo1 = create_test_utxo(0);
        let utxo2 = create_test_utxo(1);

        // Add to wallet
        {
            let mut wallet_guard = wallet.write().await;
            wallet_guard.add_utxo(utxo1.clone()).await.unwrap();
            wallet_guard.add_utxo(utxo2.clone()).await.unwrap();
        }

        // Add to storage
        storage.store_utxo(&utxo1).await.unwrap();
        storage.store_utxo(&utxo2).await.unwrap();

        // Add watched addresses
        let address = create_test_address();
        watch_items.write().await.insert(WatchItem::address(address.clone()));
        wallet.read().await.add_watched_address(address).await.unwrap();

        // Validate consistency
        let manager = ConsistencyManager::new(&wallet, &*storage, &watch_items);
        let report = manager.validate_wallet_consistency().await.unwrap();

        assert!(report.is_consistent);
        assert!(report.utxo_mismatches.is_empty());
        assert!(report.address_mismatches.is_empty());
        assert!(report.balance_mismatches.is_empty());
    }

    #[tokio::test]
    async fn test_validate_consistency_utxo_in_wallet_not_storage() {
        let (wallet, storage, watch_items) = setup_test_components().await;

        // Add UTXO only to wallet
        let utxo = create_test_utxo(0);
        {
            let mut wallet_guard = wallet.write().await;
            wallet_guard.add_utxo(utxo.clone()).await.unwrap();
        }

        // Validate consistency
        let manager = ConsistencyManager::new(&wallet, &*storage, &watch_items);
        let report = manager.validate_wallet_consistency().await.unwrap();

        assert!(!report.is_consistent);
        assert_eq!(report.utxo_mismatches.len(), 1);
        assert!(report.utxo_mismatches[0].contains("exists in wallet but not in storage"));
    }

    #[tokio::test]
    async fn test_validate_consistency_utxo_in_storage_not_wallet() {
        let (wallet, mut storage, watch_items) = setup_test_components().await;

        // Add UTXO only to storage
        let utxo = create_test_utxo(0);
        storage.store_utxo(&utxo).await.unwrap();

        // Validate consistency
        let manager = ConsistencyManager::new(&wallet, &*storage, &watch_items);
        let report = manager.validate_wallet_consistency().await.unwrap();

        assert!(!report.is_consistent);
        assert_eq!(report.utxo_mismatches.len(), 1);
        assert!(report.utxo_mismatches[0].contains("exists in storage but not in wallet"));
    }

    #[tokio::test]
    async fn test_validate_consistency_address_mismatch() {
        let (wallet, storage, watch_items) = setup_test_components().await;

        // Add address only to watch items
        let address = create_test_address();
        watch_items.write().await.insert(WatchItem::address(address.clone()));

        // Don't add to wallet - creates mismatch

        // Validate consistency
        let manager = ConsistencyManager::new(&wallet, &*storage, &watch_items);
        let report = manager.validate_wallet_consistency().await.unwrap();

        assert!(!report.is_consistent);
        assert_eq!(report.address_mismatches.len(), 1);
        assert!(report.address_mismatches[0].contains("in watch items but not in wallet"));
    }

    #[tokio::test]
    async fn test_validate_consistency_balance_calculation() {
        let (wallet, mut storage, watch_items) = setup_test_components().await;

        // Add UTXOs with specific values
        let utxo1 = create_test_utxo(0); // value: 1000
        let utxo2 = create_test_utxo(1); // value: 1100

        // Add to both wallet and storage
        {
            let mut wallet_guard = wallet.write().await;
            wallet_guard.add_utxo(utxo1.clone()).await.unwrap();
            wallet_guard.add_utxo(utxo2.clone()).await.unwrap();
        }
        storage.store_utxo(&utxo1).await.unwrap();
        storage.store_utxo(&utxo2).await.unwrap();

        // Validate consistency
        let manager = ConsistencyManager::new(&wallet, &*storage, &watch_items);
        let report = manager.validate_wallet_consistency().await.unwrap();

        // Should be consistent with correct balance
        assert!(report.is_consistent);

        // Verify balance calculation
        let wallet_balance = wallet.read().await.get_balance().await;
        assert_eq!(wallet_balance, 2100); // 1000 + 1100
    }

    #[tokio::test]
    async fn test_recover_consistency_sync_from_storage() {
        let (wallet, mut storage, watch_items) = setup_test_components().await;

        // Add UTXOs only to storage
        let utxo1 = create_test_utxo(0);
        let utxo2 = create_test_utxo(1);
        storage.store_utxo(&utxo1).await.unwrap();
        storage.store_utxo(&utxo2).await.unwrap();

        // Recover consistency
        let manager = ConsistencyManager::new(&wallet, &*storage, &watch_items);
        let recovery = manager.recover_wallet_consistency().await.unwrap();

        assert!(recovery.success);
        assert_eq!(recovery.utxos_synced, 2);
        assert_eq!(recovery.utxos_removed, 0);

        // Verify UTXOs were synced to wallet
        let wallet_utxos = wallet.read().await.get_utxos().await;
        assert_eq!(wallet_utxos.len(), 2);
    }

    #[tokio::test]
    async fn test_recover_consistency_remove_from_wallet() {
        let (wallet, storage, watch_items) = setup_test_components().await;

        // Add UTXOs only to wallet
        let utxo1 = create_test_utxo(0);
        let utxo2 = create_test_utxo(1);
        {
            let mut wallet_guard = wallet.write().await;
            wallet_guard.add_utxo(utxo1.clone()).await.unwrap();
            wallet_guard.add_utxo(utxo2.clone()).await.unwrap();
        }

        // Recover consistency
        let manager = ConsistencyManager::new(&wallet, &*storage, &watch_items);
        let recovery = manager.recover_wallet_consistency().await.unwrap();

        assert!(recovery.success);
        assert_eq!(recovery.utxos_synced, 0);
        assert_eq!(recovery.utxos_removed, 2);

        // Verify UTXOs were removed from wallet
        let wallet_utxos = wallet.read().await.get_utxos().await;
        assert_eq!(wallet_utxos.len(), 0);
    }

    #[tokio::test]
    async fn test_recover_consistency_sync_addresses() {
        let (wallet, storage, watch_items) = setup_test_components().await;

        // Add addresses to watch items
        let address1 = create_test_address();
        let address2 =
            Address::from_str("Xj4Ei2Sj9YAj7hMxx4XgZvGNqoqHkwqNgE").unwrap().assume_checked();

        watch_items.write().await.insert(WatchItem::address(address1.clone()));
        watch_items.write().await.insert(WatchItem::address(address2.clone()));

        // Recover consistency (should sync addresses to wallet)
        let manager = ConsistencyManager::new(&wallet, &*storage, &watch_items);
        let recovery = manager.recover_wallet_consistency().await.unwrap();

        assert!(recovery.success);
        assert_eq!(recovery.addresses_synced, 2);

        // Verify addresses were synced to wallet
        let wallet_guard = wallet.read().await;
        let watched_addresses = wallet_guard.get_watched_addresses().await;
        assert_eq!(watched_addresses.len(), 2);
    }

    #[tokio::test]
    async fn test_recover_consistency_mixed_operations() {
        let (wallet, mut storage, watch_items) = setup_test_components().await;

        // Setup mixed state:
        // - UTXO1: only in storage (should sync to wallet)
        // - UTXO2: only in wallet (should remove from wallet)
        // - UTXO3: in both (should remain)

        let utxo1 = create_test_utxo(0);
        let utxo2 = create_test_utxo(1);
        let utxo3 = create_test_utxo(2);

        storage.store_utxo(&utxo1).await.unwrap();
        storage.store_utxo(&utxo3).await.unwrap();

        {
            let mut wallet_guard = wallet.write().await;
            wallet_guard.add_utxo(utxo2.clone()).await.unwrap();
            wallet_guard.add_utxo(utxo3.clone()).await.unwrap();
        }

        // Add address to watch items
        let address = create_test_address();
        watch_items.write().await.insert(WatchItem::address(address));

        // Recover consistency
        let manager = ConsistencyManager::new(&wallet, &*storage, &watch_items);
        let recovery = manager.recover_wallet_consistency().await.unwrap();

        assert!(recovery.success);
        assert_eq!(recovery.utxos_synced, 1); // utxo1
        assert_eq!(recovery.utxos_removed, 1); // utxo2
        assert_eq!(recovery.addresses_synced, 1);

        // Verify final state
        let wallet_utxos = wallet.read().await.get_utxos().await;
        assert_eq!(wallet_utxos.len(), 2); // utxo1 and utxo3

        // Validate consistency after recovery
        let report = manager.validate_wallet_consistency().await.unwrap();
        assert!(report.is_consistent);
    }

    #[tokio::test]
    async fn test_consistency_with_labeled_watch_items() {
        let (wallet, storage, watch_items) = setup_test_components().await;

        // Add labeled watch item
        let address = create_test_address();
        let labeled_item = WatchItem::Address {
            address: address.clone(),
            label: Some("My Savings".to_string()),
        };

        watch_items.write().await.insert(labeled_item);
        wallet.read().await.add_watched_address(address).await.unwrap();

        // Validate consistency
        let manager = ConsistencyManager::new(&wallet, &*storage, &watch_items);
        let report = manager.validate_wallet_consistency().await.unwrap();

        assert!(report.is_consistent);
        assert!(report.address_mismatches.is_empty());
    }

    #[tokio::test]
    async fn test_consistency_report_formatting() {
        let (wallet, mut storage, watch_items) = setup_test_components().await;

        // Create various mismatches
        let utxo_wallet_only = create_test_utxo(0);
        let utxo_storage_only = create_test_utxo(1);

        wallet.write().await.add_utxo(utxo_wallet_only.clone()).await.unwrap();
        storage.store_utxo(&utxo_storage_only).await.unwrap();

        let address = create_test_address();
        watch_items.write().await.insert(WatchItem::address(address));

        // Validate consistency
        let manager = ConsistencyManager::new(&wallet, &*storage, &watch_items);
        let report = manager.validate_wallet_consistency().await.unwrap();

        assert!(!report.is_consistent);
        assert_eq!(report.utxo_mismatches.len(), 2);
        assert_eq!(report.address_mismatches.len(), 1);

        // Verify error messages are informative
        assert!(report.utxo_mismatches.iter().any(|msg| msg.contains("wallet but not in storage")));
        assert!(report.utxo_mismatches.iter().any(|msg| msg.contains("storage but not in wallet")));
        assert!(report.address_mismatches[0].contains("watch items but not in wallet"));
    }
}
