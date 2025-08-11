//! Wallet state management for reorganizations

use super::{TransactionStatus, UTXORollbackManager};
use crate::error::Result;
use crate::storage::StorageManager;
use dashcore::{BlockHash, Network, Transaction, Txid};
use std::collections::HashMap;

/// Wallet state that tracks transaction confirmations
pub struct WalletState {
    network: Network,
    /// Transaction confirmation heights
    tx_heights: HashMap<Txid, Option<u32>>,
    /// Wallet transactions
    wallet_txs: HashMap<Txid, bool>,
    /// UTXO rollback manager
    rollback_manager: Option<UTXORollbackManager>,
}

impl WalletState {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            tx_heights: HashMap::new(),
            wallet_txs: HashMap::new(),
            rollback_manager: None,
        }
    }

    /// Create a new wallet state with rollback support
    pub fn with_rollback(network: Network, persist_snapshots: bool) -> Self {
        Self {
            network,
            tx_heights: HashMap::new(),
            wallet_txs: HashMap::new(),
            rollback_manager: Some(UTXORollbackManager::new(persist_snapshots)),
        }
    }

    /// Initialize rollback manager from storage
    pub async fn init_rollback_from_storage(
        &mut self,
        storage: &dyn StorageManager,
        persist_snapshots: bool,
    ) -> Result<()> {
        self.rollback_manager =
            Some(UTXORollbackManager::from_storage(storage, persist_snapshots).await?);
        Ok(())
    }

    /// Check if a transaction belongs to the wallet
    pub fn is_wallet_transaction(&self, txid: &Txid) -> bool {
        self.wallet_txs.contains_key(txid)
    }

    /// Mark a transaction as unconfirmed (for reorgs)
    pub fn mark_transaction_unconfirmed(&mut self, txid: &Txid) {
        self.tx_heights.insert(*txid, None);
    }

    /// Add a wallet transaction
    pub fn add_wallet_transaction(&mut self, txid: Txid) {
        self.wallet_txs.insert(txid, true);
    }

    /// Set transaction confirmation height
    pub fn set_transaction_height(&mut self, txid: &Txid, height: Option<u32>) {
        self.tx_heights.insert(*txid, height);
    }

    /// Get transaction confirmation height
    pub fn get_transaction_height(&self, txid: &Txid) -> Option<u32> {
        self.tx_heights.get(txid).and_then(|h| *h)
    }

    /// Process a block and track UTXO changes
    pub async fn process_block_with_rollback(
        &mut self,
        height: u32,
        block_hash: BlockHash,
        transactions: &[Transaction],
        storage: &mut dyn StorageManager,
    ) -> Result<()> {
        if let Some(mut rollback_mgr) = self.rollback_manager.take() {
            rollback_mgr.process_block(height, block_hash, transactions, self, storage).await?;
            self.rollback_manager = Some(rollback_mgr);
        }
        Ok(())
    }

    /// Rollback to a specific height
    pub async fn rollback_to_height(
        &mut self,
        target_height: u32,
        storage: &mut dyn StorageManager,
    ) -> Result<()> {
        if let Some(mut rollback_mgr) = self.rollback_manager.take() {
            rollback_mgr.rollback_to_height(target_height, self, storage).await?;
            self.rollback_manager = Some(rollback_mgr);
        }
        Ok(())
    }

    /// Get the rollback manager
    pub fn rollback_manager(&self) -> Option<&UTXORollbackManager> {
        self.rollback_manager.as_ref()
    }

    /// Get the mutable rollback manager
    pub fn rollback_manager_mut(&mut self) -> Option<&mut UTXORollbackManager> {
        self.rollback_manager.as_mut()
    }

    /// Mark a transaction as conflicted
    pub fn mark_transaction_conflicted(&mut self, txid: &Txid) {
        self.tx_heights.remove(txid);
        if let Some(ref mut rollback_mgr) = self.rollback_manager {
            rollback_mgr.mark_transaction_conflicted(txid);
        }
    }

    /// Get transaction status
    pub fn get_transaction_status(&self, txid: &Txid) -> TransactionStatus {
        if let Some(ref rollback_mgr) = self.rollback_manager {
            if let Some(status) = rollback_mgr.get_transaction_status(txid) {
                return status;
            }
        }

        // Fall back to height-based status
        if let Some(height) = self.get_transaction_height(txid) {
            TransactionStatus::Confirmed(height)
        } else {
            TransactionStatus::Unconfirmed
        }
    }
}
