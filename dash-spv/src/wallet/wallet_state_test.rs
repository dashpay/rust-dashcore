//! Comprehensive unit tests for wallet state management
//!
//! This module tests state persistence, concurrent access, transaction tracking,
//! and rollback functionality.

#[cfg(test)]
mod tests {
    use super::super::wallet_state::*;
    use super::super::{TransactionStatus, UTXORollbackManager};
    use crate::storage::MemoryStorageManager;
    use dashcore::{BlockHash, Network, Transaction, TxIn, TxOut, Txid, Witness, OutPoint, ScriptBuf};
    use dashcore_hashes::Hash;
    use std::str::FromStr;

    // Helper functions

    fn create_test_txid(num: u8) -> Txid {
        Txid::from_slice(&[num; 32]).expect("Valid test txid")
    }

    fn create_test_block_hash(num: u8) -> BlockHash {
        BlockHash::from_slice(&[num; 32]).expect("Valid test block hash")
    }

    fn create_test_transaction(inputs: Vec<OutPoint>, outputs: Vec<(u64, ScriptBuf)>) -> Transaction {
        let tx_inputs = inputs
            .into_iter()
            .map(|outpoint| TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: u32::MAX,
                witness: Witness::new(),
            })
            .collect();

        let tx_outputs = outputs
            .into_iter()
            .map(|(value, script)| TxOut {
                value,
                script_pubkey: script,
            })
            .collect();

        Transaction {
            version: 1,
            lock_time: 0,
            input: tx_inputs,
            output: tx_outputs,
            special_transaction_payload: None,
        }
    }

    // Basic state management tests

    #[test]
    fn test_wallet_state_creation() {
        let state = WalletState::new(Network::Dash);
        assert!(!state.is_wallet_transaction(&create_test_txid(1)));
        assert_eq!(state.get_transaction_height(&create_test_txid(1)), None);
    }

    #[test]
    fn test_wallet_state_with_rollback() {
        let state = WalletState::with_rollback(Network::Dash, true);
        assert!(state.rollback_manager().is_some());
    }

    #[test]
    fn test_add_wallet_transaction() {
        let mut state = WalletState::new(Network::Dash);
        let txid = create_test_txid(1);
        
        assert!(!state.is_wallet_transaction(&txid));
        state.add_wallet_transaction(txid);
        assert!(state.is_wallet_transaction(&txid));
    }

    #[test]
    fn test_transaction_height_tracking() {
        let mut state = WalletState::new(Network::Dash);
        let txid = create_test_txid(1);
        
        // Initially no height
        assert_eq!(state.get_transaction_height(&txid), None);
        
        // Set confirmed height
        state.set_transaction_height(&txid, Some(100));
        assert_eq!(state.get_transaction_height(&txid), Some(100));
        
        // Update height
        state.set_transaction_height(&txid, Some(200));
        assert_eq!(state.get_transaction_height(&txid), Some(200));
        
        // Mark as unconfirmed
        state.set_transaction_height(&txid, None);
        assert_eq!(state.get_transaction_height(&txid), None);
    }

    #[test]
    fn test_mark_transaction_unconfirmed() {
        let mut state = WalletState::new(Network::Dash);
        let txid = create_test_txid(1);
        
        state.set_transaction_height(&txid, Some(100));
        assert_eq!(state.get_transaction_height(&txid), Some(100));
        
        state.mark_transaction_unconfirmed(&txid);
        assert_eq!(state.get_transaction_height(&txid), None);
    }

    // Transaction status tests

    #[test]
    fn test_get_transaction_status_without_rollback() {
        let mut state = WalletState::new(Network::Dash);
        let txid = create_test_txid(1);
        
        // Unconfirmed by default
        assert_eq!(state.get_transaction_status(&txid), TransactionStatus::Unconfirmed);
        
        // Confirmed
        state.set_transaction_height(&txid, Some(100));
        assert_eq!(state.get_transaction_status(&txid), TransactionStatus::Confirmed(100));
    }

    #[test]
    fn test_mark_transaction_conflicted() {
        let mut state = WalletState::with_rollback(Network::Dash, false);
        let txid = create_test_txid(1);
        
        state.set_transaction_height(&txid, Some(100));
        state.mark_transaction_conflicted(&txid);
        
        // Height should be removed
        assert_eq!(state.get_transaction_height(&txid), None);
    }

    // Multiple transaction tracking tests

    #[test]
    fn test_track_multiple_transactions() {
        let mut state = WalletState::new(Network::Dash);
        
        // Add multiple transactions
        for i in 1..=10 {
            let txid = create_test_txid(i);
            state.add_wallet_transaction(txid);
            state.set_transaction_height(&txid, Some(100 + i as u32));
        }
        
        // Verify all tracked
        for i in 1..=10 {
            let txid = create_test_txid(i);
            assert!(state.is_wallet_transaction(&txid));
            assert_eq!(state.get_transaction_height(&txid), Some(100 + i as u32));
        }
    }

    #[test]
    fn test_mixed_transaction_states() {
        let mut state = WalletState::new(Network::Dash);
        
        // Confirmed transaction
        let confirmed_txid = create_test_txid(1);
        state.add_wallet_transaction(confirmed_txid);
        state.set_transaction_height(&confirmed_txid, Some(100));
        
        // Unconfirmed transaction
        let unconfirmed_txid = create_test_txid(2);
        state.add_wallet_transaction(unconfirmed_txid);
        
        // Non-wallet transaction
        let other_txid = create_test_txid(3);
        
        assert!(state.is_wallet_transaction(&confirmed_txid));
        assert!(state.is_wallet_transaction(&unconfirmed_txid));
        assert!(!state.is_wallet_transaction(&other_txid));
        
        assert_eq!(state.get_transaction_height(&confirmed_txid), Some(100));
        assert_eq!(state.get_transaction_height(&unconfirmed_txid), None);
        assert_eq!(state.get_transaction_height(&other_txid), None);
    }

    // Rollback integration tests

    #[tokio::test]
    async fn test_init_rollback_from_storage() {
        let storage = MemoryStorageManager::new()
            .await
            .expect("Failed to create memory storage");
        
        let mut state = WalletState::new(Network::Dash);
        state.init_rollback_from_storage(&storage, true)
            .await
            .expect("Should initialize rollback from storage");
        
        assert!(state.rollback_manager().is_some());
    }

    #[tokio::test]
    async fn test_process_block_with_rollback() {
        let mut storage = MemoryStorageManager::new()
            .await
            .expect("Failed to create memory storage");
        
        let mut state = WalletState::with_rollback(Network::Dash, false);
        
        let block_hash = create_test_block_hash(1);
        let transactions = vec![
            create_test_transaction(vec![], vec![(100000, ScriptBuf::new())]),
            create_test_transaction(vec![], vec![(200000, ScriptBuf::new())]),
        ];
        
        state.process_block_with_rollback(100, block_hash, &transactions, &mut storage)
            .await
            .expect("Should process block");
        
        // Verify rollback manager has snapshot
        if let Some(manager) = state.rollback_manager() {
            let (count, oldest, newest) = manager.get_snapshot_info();
            assert_eq!(count, 1);
            assert_eq!(oldest, 100);
            assert_eq!(newest, 100);
        }
    }

    #[tokio::test]
    async fn test_rollback_to_height() {
        let mut storage = MemoryStorageManager::new()
            .await
            .expect("Failed to create memory storage");
        
        let mut state = WalletState::with_rollback(Network::Dash, false);
        
        // Process multiple blocks
        for height in 100..=105 {
            let block_hash = create_test_block_hash(height as u8);
            let transactions = vec![
                create_test_transaction(vec![], vec![(100000, ScriptBuf::new())]),
            ];
            
            state.process_block_with_rollback(height, block_hash, &transactions, &mut storage)
                .await
                .expect("Should process block");
        }
        
        // Rollback to height 102
        state.rollback_to_height(102, &mut storage)
            .await
            .expect("Should rollback");
        
        // Verify rollback occurred
        if let Some(manager) = state.rollback_manager() {
            let (count, oldest, newest) = manager.get_snapshot_info();
            assert_eq!(newest, 102);
        }
    }

    // Edge case tests

    #[test]
    fn test_transaction_height_overwrite() {
        let mut state = WalletState::new(Network::Dash);
        let txid = create_test_txid(1);
        
        // Set initial height
        state.set_transaction_height(&txid, Some(100));
        assert_eq!(state.get_transaction_height(&txid), Some(100));
        
        // Overwrite with different height
        state.set_transaction_height(&txid, Some(200));
        assert_eq!(state.get_transaction_height(&txid), Some(200));
        
        // Can still mark as unconfirmed
        state.mark_transaction_unconfirmed(&txid);
        assert_eq!(state.get_transaction_height(&txid), None);
    }

    #[test]
    fn test_non_existent_transaction_operations() {
        let mut state = WalletState::new(Network::Dash);
        let txid = create_test_txid(99);
        
        // Operations on non-existent transactions
        assert!(!state.is_wallet_transaction(&txid));
        assert_eq!(state.get_transaction_height(&txid), None);
        assert_eq!(state.get_transaction_status(&txid), TransactionStatus::Unconfirmed);
        
        // Can still set height for non-wallet transaction
        state.set_transaction_height(&txid, Some(100));
        assert_eq!(state.get_transaction_height(&txid), Some(100));
    }

    #[test]
    fn test_duplicate_add_wallet_transaction() {
        let mut state = WalletState::new(Network::Dash);
        let txid = create_test_txid(1);
        
        // Add same transaction multiple times
        state.add_wallet_transaction(txid);
        state.add_wallet_transaction(txid);
        state.add_wallet_transaction(txid);
        
        // Should still be tracked only once
        assert!(state.is_wallet_transaction(&txid));
    }

    // Rollback manager access tests

    #[test]
    fn test_rollback_manager_access() {
        let state = WalletState::new(Network::Dash);
        assert!(state.rollback_manager().is_none());
        
        let state_with_rollback = WalletState::with_rollback(Network::Dash, false);
        assert!(state_with_rollback.rollback_manager().is_some());
    }

    #[test]
    fn test_rollback_manager_mut_access() {
        let mut state = WalletState::with_rollback(Network::Dash, false);
        
        if let Some(_manager) = state.rollback_manager_mut() {
            // Can mutate the rollback manager
            // Note: set_max_snapshots and get_max_snapshots not exposed in public API
        }
    }

    // Complex scenarios

    #[test]
    fn test_reorg_scenario() {
        let mut state = WalletState::with_rollback(Network::Dash, false);
        
        // Add transactions at different heights
        let tx1 = create_test_txid(1);
        let tx2 = create_test_txid(2);
        let tx3 = create_test_txid(3);
        
        state.add_wallet_transaction(tx1);
        state.add_wallet_transaction(tx2);
        state.add_wallet_transaction(tx3);
        
        state.set_transaction_height(&tx1, Some(100));
        state.set_transaction_height(&tx2, Some(101));
        state.set_transaction_height(&tx3, Some(102));
        
        // Simulate reorg - tx3 becomes conflicted
        state.mark_transaction_conflicted(&tx3);
        assert_eq!(state.get_transaction_height(&tx3), None);
        assert_eq!(state.get_transaction_status(&tx3), TransactionStatus::Unconfirmed);
        
        // Other transactions remain confirmed
        assert_eq!(state.get_transaction_height(&tx1), Some(100));
        assert_eq!(state.get_transaction_height(&tx2), Some(101));
    }

    #[tokio::test]
    async fn test_concurrent_state_updates() {
        use tokio::sync::RwLock;
        use std::sync::Arc;
        
        let state = Arc::new(RwLock::new(WalletState::new(Network::Dash)));
        
        // Spawn multiple tasks updating state
        let mut handles = vec![];
        
        for i in 0..10 {
            let state_clone = state.clone();
            let handle = tokio::spawn(async move {
                let txid = create_test_txid(i);
                let mut state = state_clone.write().await;
                state.add_wallet_transaction(txid);
                state.set_transaction_height(&txid, Some(100 + i as u32));
            });
            handles.push(handle);
        }
        
        // Wait for all tasks
        for handle in handles {
            handle.await.expect("Task should complete");
        }
        
        // Verify all transactions were added
        let state = state.read().await;
        for i in 0..10 {
            let txid = create_test_txid(i);
            assert!(state.is_wallet_transaction(&txid));
            assert_eq!(state.get_transaction_height(&txid), Some(100 + i as u32));
        }
    }

    // Transaction status with rollback tests

    #[test]
    fn test_transaction_status_with_rollback_manager() {
        let mut state = WalletState::with_rollback(Network::Dash, false);
        let txid = create_test_txid(1);
        
        // Initially unconfirmed
        assert_eq!(state.get_transaction_status(&txid), TransactionStatus::Unconfirmed);
        
        // Mark as conflicted via rollback manager
        if let Some(manager) = state.rollback_manager_mut() {
            manager.mark_transaction_conflicted(&txid);
        }
        
        // Should return conflicted status from rollback manager
        assert_eq!(state.get_transaction_status(&txid), TransactionStatus::Conflicted);
    }
}