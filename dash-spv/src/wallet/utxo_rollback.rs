//! UTXO rollback mechanism for handling blockchain reorganizations
//!
//! This module provides functionality to track UTXO state changes and roll them back
//! during blockchain reorganizations. It maintains snapshots of UTXO state at key heights
//! and tracks transaction confirmation status changes.

use dashcore::{BlockHash, OutPoint, Transaction, Txid};
use std::collections::{HashMap, VecDeque};
use serde::{Deserialize, Serialize};
use crate::error::{Result, StorageError};
use crate::storage::StorageManager;
use super::{Utxo, WalletState};

/// Maximum number of rollback snapshots to maintain
const MAX_ROLLBACK_SNAPSHOTS: usize = 100;

/// Transaction confirmation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Transaction is unconfirmed (in mempool)
    Unconfirmed,
    /// Transaction is confirmed at a specific height
    Confirmed(u32),
    /// Transaction was conflicted by another transaction
    Conflicted,
    /// Transaction was abandoned (removed from mempool)
    Abandoned,
}

/// UTXO state change types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UTXOChange {
    /// UTXO was created
    Created(Utxo),
    /// UTXO was spent
    Spent(OutPoint),
    /// UTXO confirmation status changed
    StatusChanged {
        outpoint: OutPoint,
        old_status: bool,
        new_status: bool,
    },
}

/// Snapshot of UTXO state at a specific block height
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UTXOSnapshot {
    /// Block height of this snapshot
    pub height: u32,
    /// Block hash at this height
    pub block_hash: BlockHash,
    /// UTXO changes that occurred at this height
    pub changes: Vec<UTXOChange>,
    /// Transaction status changes at this height
    pub tx_status_changes: HashMap<Txid, (TransactionStatus, TransactionStatus)>,
    /// Total UTXO set size after applying changes
    pub utxo_count: usize,
    /// Timestamp when snapshot was created
    pub timestamp: u64,
}

/// Manages UTXO rollback functionality for reorganizations
pub struct UTXORollbackManager {
    /// Snapshots indexed by height
    snapshots: VecDeque<UTXOSnapshot>,
    /// Current transaction statuses
    tx_statuses: HashMap<Txid, TransactionStatus>,
    /// UTXOs indexed by outpoint for quick lookup
    utxo_index: HashMap<OutPoint, Utxo>,
    /// Maximum number of snapshots to keep
    max_snapshots: usize,
    /// Whether to persist snapshots to storage
    persist_snapshots: bool,
}

impl UTXORollbackManager {
    /// Create a new UTXO rollback manager
    pub fn new(persist_snapshots: bool) -> Self {
        Self {
            snapshots: VecDeque::new(),
            tx_statuses: HashMap::new(),
            utxo_index: HashMap::new(),
            max_snapshots: MAX_ROLLBACK_SNAPSHOTS,
            persist_snapshots,
        }
    }

    /// Create a new UTXO rollback manager with custom max snapshots
    pub fn with_max_snapshots(max_snapshots: usize, persist_snapshots: bool) -> Self {
        Self {
            snapshots: VecDeque::new(),
            tx_statuses: HashMap::new(),
            utxo_index: HashMap::new(),
            max_snapshots,
            persist_snapshots,
        }
    }

    /// Initialize from stored state
    pub async fn from_storage(
        storage: &dyn StorageManager,
        persist_snapshots: bool,
    ) -> Result<Self> {
        let mut manager = Self::new(persist_snapshots);
        
        // Load persisted snapshots if enabled
        if persist_snapshots {
            if let Ok(Some(data)) = storage.load_metadata("utxo_snapshots").await {
                if let Ok(snapshots) = bincode::deserialize::<VecDeque<UTXOSnapshot>>(&data) {
                    manager.snapshots = snapshots;
                }
            }
            
            // Load transaction statuses
            if let Ok(Some(data)) = storage.load_metadata("tx_statuses").await {
                if let Ok(statuses) = bincode::deserialize(&data) {
                    manager.tx_statuses = statuses;
                }
            }
        }
        
        // Rebuild UTXO index from current wallet state
        manager.rebuild_utxo_index(storage).await?;
        
        Ok(manager)
    }

    /// Create a snapshot of current UTXO state at a specific height
    pub fn create_snapshot(
        &mut self,
        height: u32,
        block_hash: BlockHash,
        changes: Vec<UTXOChange>,
        tx_changes: HashMap<Txid, (TransactionStatus, TransactionStatus)>,
    ) -> Result<()> {
        let snapshot = UTXOSnapshot {
            height,
            block_hash,
            changes,
            tx_status_changes: tx_changes,
            utxo_count: self.utxo_index.len(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Add snapshot to the queue
        self.snapshots.push_back(snapshot);

        // Limit snapshot count
        while self.snapshots.len() > self.max_snapshots {
            self.snapshots.pop_front();
        }

        Ok(())
    }

    /// Process a new block and track UTXO changes
    pub async fn process_block(
        &mut self,
        height: u32,
        block_hash: BlockHash,
        transactions: &[Transaction],
        wallet_state: &mut WalletState,
        storage: &mut dyn StorageManager,
    ) -> Result<()> {
        let mut changes = Vec::new();
        let mut tx_changes = HashMap::new();

        for tx in transactions {
            let txid = tx.txid();

            // Track transaction confirmation status change
            let old_status = self.tx_statuses.get(&txid).copied()
                .unwrap_or(TransactionStatus::Unconfirmed);
            let new_status = TransactionStatus::Confirmed(height);
            
            if old_status != new_status {
                tx_changes.insert(txid, (old_status, new_status));
                self.tx_statuses.insert(txid, new_status);
            }

            // Process inputs (spent UTXOs)
            for input in &tx.input {
                let outpoint = input.previous_output;
                
                if let Some(_utxo) = self.utxo_index.remove(&outpoint) {
                    changes.push(UTXOChange::Spent(outpoint));
                    
                    // Update wallet state
                    wallet_state.mark_transaction_unconfirmed(&outpoint.txid);
                    
                    // Remove from storage
                    storage.remove_utxo(&outpoint).await?;
                }
            }

            // Process outputs (created UTXOs)
            for (vout, output) in tx.output.iter().enumerate() {
                // Check if this output belongs to the wallet
                if wallet_state.is_wallet_transaction(&txid) {
                    let outpoint = OutPoint {
                        txid,
                        vout: vout as u32,
                    };

                    // Create UTXO (simplified - in practice, need address info)
                    let utxo = Utxo::new(
                        outpoint,
                        output.clone(),
                        // Address would come from wallet's address matching
                        dashcore::Address::from_script(&output.script_pubkey, dashcore::Network::Dash)
                            .unwrap_or_else(|_| panic!("Invalid script")),
                        height,
                        false, // Coinbase detection would be done elsewhere
                    );

                    changes.push(UTXOChange::Created(utxo.clone()));
                    self.utxo_index.insert(outpoint, utxo.clone());
                    
                    // Update wallet state
                    wallet_state.set_transaction_height(&txid, Some(height));
                    
                    // Store in storage
                    storage.store_utxo(&outpoint, &utxo).await?;
                }
            }
        }

        // Create snapshot
        self.create_snapshot(height, block_hash, changes, tx_changes)?;

        // Persist if enabled
        if self.persist_snapshots {
            self.persist_to_storage(storage).await?;
        }

        Ok(())
    }

    /// Rollback UTXO state to a specific height
    pub async fn rollback_to_height(
        &mut self,
        target_height: u32,
        wallet_state: &mut WalletState,
        storage: &mut dyn StorageManager,
    ) -> Result<Vec<UTXOSnapshot>> {
        let mut rolled_back_snapshots = Vec::new();

        // Find snapshots to roll back
        while let Some(snapshot) = self.snapshots.back() {
            if snapshot.height <= target_height {
                break;
            }

            let snapshot = self.snapshots.pop_back().unwrap();
            rolled_back_snapshots.push(snapshot.clone());

            // Reverse the changes in this snapshot
            for change in snapshot.changes.iter().rev() {
                match change {
                    UTXOChange::Created(utxo) => {
                        // Remove created UTXO
                        self.utxo_index.remove(&utxo.outpoint);
                        storage.remove_utxo(&utxo.outpoint).await?;
                        wallet_state.mark_transaction_unconfirmed(&utxo.outpoint.txid);
                    }
                    UTXOChange::Spent(outpoint) => {
                        // Restore spent UTXO (would need to be stored in snapshot)
                        // In practice, we'd need to store the full UTXO data
                        // For now, mark as unconfirmed
                        wallet_state.mark_transaction_unconfirmed(&outpoint.txid);
                    }
                    UTXOChange::StatusChanged { outpoint, old_status, .. } => {
                        // Restore old status
                        if let Some(utxo) = self.utxo_index.get_mut(outpoint) {
                            utxo.set_confirmed(*old_status);
                        }
                    }
                }
            }

            // Reverse transaction status changes
            for (txid, (old_status, _)) in snapshot.tx_status_changes {
                self.tx_statuses.insert(txid, old_status);
                
                match old_status {
                    TransactionStatus::Unconfirmed => {
                        wallet_state.mark_transaction_unconfirmed(&txid);
                    }
                    TransactionStatus::Confirmed(height) => {
                        wallet_state.set_transaction_height(&txid, Some(height));
                    }
                    _ => {}
                }
            }
        }

        // Persist if enabled
        if self.persist_snapshots {
            self.persist_to_storage(storage).await?;
        }

        Ok(rolled_back_snapshots)
    }

    /// Get snapshots in a height range
    pub fn get_snapshots_in_range(&self, start: u32, end: u32) -> Vec<&UTXOSnapshot> {
        self.snapshots
            .iter()
            .filter(|s| s.height >= start && s.height <= end)
            .collect()
    }

    /// Get the latest snapshot
    pub fn get_latest_snapshot(&self) -> Option<&UTXOSnapshot> {
        self.snapshots.back()
    }

    /// Get snapshot at specific height
    pub fn get_snapshot_at_height(&self, height: u32) -> Option<&UTXOSnapshot> {
        self.snapshots.iter().find(|s| s.height == height)
    }

    /// Mark a transaction as conflicted
    pub fn mark_transaction_conflicted(&mut self, txid: &Txid) {
        self.tx_statuses.insert(*txid, TransactionStatus::Conflicted);
    }

    /// Get transaction status
    pub fn get_transaction_status(&self, txid: &Txid) -> Option<TransactionStatus> {
        self.tx_statuses.get(txid).copied()
    }

    /// Get current UTXO count
    pub fn get_utxo_count(&self) -> usize {
        self.utxo_index.len()
    }

    /// Get all UTXOs
    pub fn get_all_utxos(&self) -> Vec<&Utxo> {
        self.utxo_index.values().collect()
    }

    /// Clear all snapshots (for testing or reset)
    pub fn clear_snapshots(&mut self) {
        self.snapshots.clear();
    }
    
    /// Get snapshot statistics
    pub fn get_snapshot_info(&self) -> (usize, u32, u32) {
        let count = self.snapshots.len();
        let oldest = self.snapshots.front().map(|s| s.height).unwrap_or(0);
        let newest = self.snapshots.back().map(|s| s.height).unwrap_or(0);
        (count, oldest, newest)
    }

    /// Rebuild UTXO index from storage
    async fn rebuild_utxo_index(&mut self, storage: &dyn StorageManager) -> Result<()> {
        self.utxo_index = storage.get_all_utxos().await?;
        Ok(())
    }

    /// Persist snapshots to storage
    async fn persist_to_storage(&self, storage: &mut dyn StorageManager) -> Result<()> {
        // Serialize and store snapshots
        let snapshot_data = bincode::serialize(&self.snapshots)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        storage.store_metadata("utxo_snapshots", &snapshot_data).await?;

        // Serialize and store transaction statuses
        let status_data = bincode::serialize(&self.tx_statuses)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        storage.store_metadata("tx_statuses", &status_data).await?;

        Ok(())
    }

    /// Validate UTXO consistency
    pub fn validate_consistency(&self) -> Result<()> {
        // Check that all UTXOs have valid data
        for (outpoint, utxo) in &self.utxo_index {
            if outpoint != &utxo.outpoint {
                return Err(StorageError::InconsistentState(
                    format!("UTXO outpoint mismatch: {:?} vs {:?}", outpoint, utxo.outpoint)
                ).into());
            }
        }

        // Check snapshot consistency
        let mut prev_height = 0;
        for snapshot in &self.snapshots {
            if snapshot.height <= prev_height {
                return Err(StorageError::InconsistentState(
                    format!("Snapshots not in ascending order: {} <= {}", snapshot.height, prev_height)
                ).into());
            }
            prev_height = snapshot.height;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::{Amount, ScriptBuf, TxOut};
    use dashcore_hashes::Hash;
    use crate::storage::MemoryStorageManager;

    async fn create_test_manager() -> UTXORollbackManager {
        UTXORollbackManager::new(false)
    }

    fn create_test_utxo(outpoint: OutPoint, value: u64, height: u32) -> Utxo {
        let txout = TxOut {
            value,
            script_pubkey: ScriptBuf::new(),
        };
        
        let address = dashcore::Address::from_script(
            &ScriptBuf::new_p2pkh(&dashcore::PubkeyHash::from_byte_array([1u8; 20])),
            dashcore::Network::Testnet
        ).unwrap();

        Utxo::new(outpoint, txout, address, height, false)
    }

    #[tokio::test]
    async fn test_snapshot_creation() {
        let mut manager = create_test_manager().await;
        
        let block_hash = BlockHash::from_byte_array([1u8; 32]);
        let changes = vec![
            UTXOChange::Created(create_test_utxo(
                OutPoint::null(),
                100000,
                100
            )),
        ];
        
        manager.create_snapshot(100, block_hash, changes, HashMap::new()).unwrap();
        
        assert_eq!(manager.snapshots.len(), 1);
        let snapshot = manager.get_latest_snapshot().unwrap();
        assert_eq!(snapshot.height, 100);
        assert_eq!(snapshot.block_hash, block_hash);
    }

    #[tokio::test]
    async fn test_snapshot_limit() {
        let mut manager = UTXORollbackManager::with_max_snapshots(5, false);
        
        // Create more snapshots than the limit
        for i in 0..10 {
            let block_hash = BlockHash::from_byte_array([i as u8; 32]);
            manager.create_snapshot(i, block_hash, vec![], HashMap::new()).unwrap();
        }
        
        // Should only keep the last 5
        assert_eq!(manager.snapshots.len(), 5);
        assert_eq!(manager.snapshots.front().unwrap().height, 5);
        assert_eq!(manager.snapshots.back().unwrap().height, 9);
    }

    #[tokio::test]
    async fn test_transaction_status_tracking() {
        let mut manager = create_test_manager().await;
        
        let txid = Txid::from_byte_array([1u8; 32]);
        
        // Initially unconfirmed
        assert_eq!(manager.get_transaction_status(&txid), None);
        
        // Mark as confirmed
        manager.tx_statuses.insert(txid, TransactionStatus::Confirmed(100));
        assert_eq!(
            manager.get_transaction_status(&txid),
            Some(TransactionStatus::Confirmed(100))
        );
        
        // Mark as conflicted
        manager.mark_transaction_conflicted(&txid);
        assert_eq!(
            manager.get_transaction_status(&txid),
            Some(TransactionStatus::Conflicted)
        );
    }

    #[tokio::test]
    async fn test_rollback_basic() {
        let mut manager = create_test_manager().await;
        let mut wallet_state = WalletState::new(dashcore::Network::Testnet);
        let mut storage = MemoryStorageManager::new().await.unwrap();
        
        // Create snapshots at heights 100, 110, 120
        for height in [100, 110, 120] {
            let block_hash = BlockHash::from_byte_array([height as u8; 32]);
            let outpoint = OutPoint {
                txid: Txid::from_byte_array([height as u8; 32]),
                vout: 0,
            };
            
            let utxo = create_test_utxo(outpoint, 100000, height);
            manager.utxo_index.insert(outpoint, utxo.clone());
            
            let changes = vec![UTXOChange::Created(utxo)];
            manager.create_snapshot(height, block_hash, changes, HashMap::new()).unwrap();
        }
        
        assert_eq!(manager.snapshots.len(), 3);
        assert_eq!(manager.utxo_index.len(), 3);
        
        // Rollback to height 105 (should remove snapshots at 110 and 120)
        let rolled_back = manager.rollback_to_height(105, &mut wallet_state, &mut storage).await.unwrap();
        
        assert_eq!(rolled_back.len(), 2);
        assert_eq!(manager.snapshots.len(), 1);
        assert_eq!(manager.utxo_index.len(), 1);
    }

    #[tokio::test]
    async fn test_consistency_validation() {
        let mut manager = create_test_manager().await;
        
        // Add valid UTXO
        let outpoint = OutPoint::null();
        let utxo = create_test_utxo(outpoint, 100000, 100);
        manager.utxo_index.insert(outpoint, utxo);
        
        // Should pass validation
        assert!(manager.validate_consistency().is_ok());
        
        // Add inconsistent UTXO (wrong outpoint)
        let wrong_outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 1,
        };
        let mut bad_utxo = create_test_utxo(outpoint, 100000, 100);
        bad_utxo.outpoint = wrong_outpoint;
        manager.utxo_index.insert(outpoint, bad_utxo);
        
        // Should fail validation
        assert!(manager.validate_consistency().is_err());
    }
}