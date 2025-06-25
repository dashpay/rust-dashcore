//! Wallet functionality for the Dash SPV client.
//!
//! This module provides wallet abstraction for monitoring addresses and tracking UTXOs.
//! It supports:
//! - Adding watched addresses
//! - Tracking unspent transaction outputs (UTXOs)
//! - Calculating balances
//! - Managing wallet state

pub mod transaction_processor;
pub mod utxo;
pub mod utxo_rollback;
pub mod wallet_state;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use dashcore::{Address, Amount, OutPoint};
use tokio::sync::RwLock;

use crate::bloom::{BloomFilterManager, BloomFilterConfig};
use crate::error::{SpvError, StorageError};
use crate::storage::StorageManager;
use crate::types::MempoolState;
pub use transaction_processor::{
    AddressStats, BlockResult, TransactionProcessor, TransactionResult,
};
pub use utxo::Utxo;
pub use utxo_rollback::{
    UTXORollbackManager, UTXOSnapshot, UTXOChange, TransactionStatus,
};
pub use wallet_state::WalletState;

/// Main wallet interface for monitoring addresses and tracking UTXOs.
#[derive(Clone)]
pub struct Wallet {
    /// Storage manager for persistence.
    storage: Arc<RwLock<dyn StorageManager>>,

    /// Set of addresses being watched.
    watched_addresses: Arc<RwLock<HashSet<Address>>>,

    /// Current UTXO set indexed by outpoint.
    utxo_set: Arc<RwLock<HashMap<OutPoint, Utxo>>>,
    
    /// UTXO rollback manager for reorg handling.
    rollback_manager: Arc<RwLock<Option<UTXORollbackManager>>>,
    
    /// Wallet state for tracking transactions.
    wallet_state: Arc<RwLock<WalletState>>,
    
    /// Bloom filter manager for SPV filtering.
    bloom_filter_manager: Option<Arc<BloomFilterManager>>,
}

/// Balance information for an address or the entire wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Balance {
    /// Confirmed balance (1+ confirmations or ChainLocked).
    pub confirmed: Amount,

    /// Pending balance (0 confirmations).
    pub pending: Amount,

    /// InstantLocked balance (InstantLocked but not ChainLocked).
    pub instantlocked: Amount,
    
    /// Mempool balance (unconfirmed transactions not yet in blocks).
    pub mempool: Amount,
    
    /// Mempool InstantLocked balance.
    pub mempool_instant: Amount,
}

impl Balance {
    /// Create a new empty balance.
    pub fn new() -> Self {
        Self {
            confirmed: Amount::ZERO,
            pending: Amount::ZERO,
            instantlocked: Amount::ZERO,
            mempool: Amount::ZERO,
            mempool_instant: Amount::ZERO,
        }
    }

    /// Get total balance (confirmed + pending + instantlocked + mempool).
    pub fn total(&self) -> Amount {
        self.confirmed + self.pending + self.instantlocked + self.mempool + self.mempool_instant
    }

    /// Add another balance to this one.
    pub fn add(&mut self, other: &Balance) {
        self.confirmed += other.confirmed;
        self.pending += other.pending;
        self.instantlocked += other.instantlocked;
        self.mempool += other.mempool;
        self.mempool_instant += other.mempool_instant;
    }
}

impl Default for Balance {
    fn default() -> Self {
        Self::new()
    }
}

impl Wallet {
    /// Create a new wallet with the given storage manager.
    pub fn new(storage: Arc<RwLock<dyn StorageManager>>) -> Self {
        Self {
            storage,
            watched_addresses: Arc::new(RwLock::new(HashSet::new())),
            utxo_set: Arc::new(RwLock::new(HashMap::new())),
            rollback_manager: Arc::new(RwLock::new(None)),
            wallet_state: Arc::new(RwLock::new(WalletState::new(dashcore::Network::Dash))),
            bloom_filter_manager: None,
        }
    }
    
    /// Get the network this wallet is operating on.
    pub fn network(&self) -> dashcore::Network {
        // Default to mainnet for now - in real implementation this should be configurable
        dashcore::Network::Dash
    }
    
    /// Check if we have a specific UTXO.
    pub fn has_utxo(&self, outpoint: &OutPoint) -> bool {
        // We need async access, but this method is sync, so we'll use try_read
        if let Ok(utxos) = self.utxo_set.try_read() {
            utxos.contains_key(outpoint)
        } else {
            false
        }
    }
    
    /// Calculate the net amount change for our wallet from a transaction.
    pub fn calculate_net_amount(&self, tx: &dashcore::Transaction) -> i64 {
        let mut net_amount: i64 = 0;
        
        // Check inputs (subtract if we're spending our UTXOs)
        if let Ok(utxos) = self.utxo_set.try_read() {
            for input in &tx.input {
                if let Some(utxo) = utxos.get(&input.previous_output) {
                    net_amount -= utxo.txout.value as i64;
                }
            }
        }
        
        // Check outputs (add if we're receiving)
        if let Ok(watched_addrs) = self.watched_addresses.try_read() {
            for output in &tx.output {
                if let Ok(address) = Address::from_script(&output.script_pubkey, self.network()) {
                    if watched_addrs.contains(&address) {
                        net_amount += output.value as i64;
                    }
                }
            }
        }
        
        net_amount
    }
    
    /// Calculate transaction fee for a given transaction.
    /// Returns the fee amount if we have all input UTXOs, otherwise returns None.
    pub fn calculate_transaction_fee(&self, tx: &dashcore::Transaction) -> Option<dashcore::Amount> {
        let mut total_input = 0u64;
        let mut have_all_inputs = true;
        
        // Get input values from our UTXO set
        if let Ok(utxos) = self.utxo_set.try_read() {
            for input in &tx.input {
                if let Some(utxo) = utxos.get(&input.previous_output) {
                    total_input += utxo.txout.value;
                } else {
                    // We don't have this UTXO, so we can't calculate the full fee
                    have_all_inputs = false;
                }
            }
        } else {
            return None; // Could not acquire lock
        }
        
        // If we don't have all inputs, we can't calculate the fee accurately
        if !have_all_inputs {
            return None;
        }
        
        // Sum output values
        let total_output: u64 = tx.output.iter().map(|out| out.value).sum();
        
        // Calculate fee (inputs - outputs)
        if total_input >= total_output {
            Some(dashcore::Amount::from_sat(total_input - total_output))
        } else {
            // This shouldn't happen for valid transactions
            None
        }
    }
    
    /// Check if a transaction is relevant to this wallet.
    pub fn is_transaction_relevant(&self, tx: &dashcore::Transaction) -> bool {
        // Check if any input spends our UTXOs
        if let Ok(utxos) = self.utxo_set.try_read() {
            for input in &tx.input {
                if utxos.contains_key(&input.previous_output) {
                    return true;
                }
            }
        }
        
        // Check if any output is to our watched addresses
        if let Ok(watched_addrs) = self.watched_addresses.try_read() {
            for output in &tx.output {
                if let Ok(address) = Address::from_script(&output.script_pubkey, self.network()) {
                    if watched_addrs.contains(&address) {
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    /// Create a new wallet with rollback support.
    pub fn new_with_rollback(storage: Arc<RwLock<dyn StorageManager>>, enable_rollback: bool) -> Self {
        let rollback_manager = if enable_rollback {
            Some(UTXORollbackManager::with_max_snapshots(100, true)) // 100 snapshots, persist to storage
        } else {
            None
        };
        
        let wallet_state = if enable_rollback {
            WalletState::with_rollback(dashcore::Network::Dash, true)
        } else {
            WalletState::new(dashcore::Network::Dash)
        };
        
        Self {
            storage,
            watched_addresses: Arc::new(RwLock::new(HashSet::new())),
            utxo_set: Arc::new(RwLock::new(HashMap::new())),
            rollback_manager: Arc::new(RwLock::new(rollback_manager)),
            wallet_state: Arc::new(RwLock::new(wallet_state)),
            bloom_filter_manager: None,
        }
    }

    /// Enable bloom filter support for this wallet.
    pub fn enable_bloom_filter(&mut self, config: BloomFilterConfig) {
        self.bloom_filter_manager = Some(Arc::new(BloomFilterManager::new(config)));
    }
    
    /// Get the bloom filter manager if enabled.
    pub fn bloom_filter_manager(&self) -> Option<&Arc<BloomFilterManager>> {
        self.bloom_filter_manager.as_ref()
    }

    /// Add an address to watch for transactions.
    pub async fn add_watched_address(&self, address: Address) -> Result<(), SpvError> {
        let mut watched = self.watched_addresses.write().await;
        watched.insert(address.clone());

        // Persist the updated watch list
        self.save_watched_addresses(&watched).await?;
        
        // Update bloom filter if enabled
        if let Some(ref bloom_manager) = self.bloom_filter_manager {
            bloom_manager.add_address(&address).await?;
        }

        Ok(())
    }

    /// Remove an address from the watch list.
    pub async fn remove_watched_address(&self, address: &Address) -> Result<bool, SpvError> {
        let mut watched = self.watched_addresses.write().await;
        let removed = watched.remove(address);

        if removed {
            // Persist the updated watch list
            self.save_watched_addresses(&watched).await?;
        }

        Ok(removed)
    }

    /// Get all watched addresses.
    pub async fn get_watched_addresses(&self) -> Vec<Address> {
        let watched = self.watched_addresses.read().await;
        watched.iter().cloned().collect()
    }

    /// Check if an address is being watched.
    pub async fn is_watching_address(&self, address: &Address) -> bool {
        let watched = self.watched_addresses.read().await;
        watched.contains(address)
    }

    /// Get the total balance across all watched addresses.
    pub async fn get_balance(&self) -> Result<Balance, SpvError> {
        self.calculate_balance(None).await
    }

    /// Get the balance for a specific address.
    pub async fn get_balance_for_address(&self, address: &Address) -> Result<Balance, SpvError> {
        self.calculate_balance(Some(address)).await
    }
    
    /// Get the balance including mempool transactions.
    pub async fn get_balance_with_mempool(
        &self,
        mempool_state: &MempoolState,
    ) -> Result<Balance, SpvError> {
        // Get regular balance
        let mut balance = self.get_balance().await?;
        
        // Add mempool balances
        if mempool_state.pending_balance != 0 {
            if mempool_state.pending_balance > 0 {
                balance.mempool = Amount::from_sat(mempool_state.pending_balance as u64);
            } else {
                // Handle negative balance (spending more than receiving)
                // This should be handled more carefully in production
                balance.mempool = Amount::ZERO;
            }
        }
        
        if mempool_state.pending_instant_balance != 0 {
            if mempool_state.pending_instant_balance > 0 {
                balance.mempool_instant = Amount::from_sat(mempool_state.pending_instant_balance as u64);
            } else {
                balance.mempool_instant = Amount::ZERO;
            }
        }
        
        Ok(balance)
    }
    
    /// Get the balance for a specific address including mempool.
    pub async fn get_balance_for_address_with_mempool(
        &self,
        address: &Address,
        mempool_state: &MempoolState,
    ) -> Result<Balance, SpvError> {
        // Get regular balance
        let mut balance = self.get_balance_for_address(address).await?;
        
        // Add mempool balance for this specific address
        for tx in mempool_state.transactions.values() {
            if tx.addresses.contains(address) {
                let amount = Amount::from_sat(tx.net_amount.abs() as u64);
                if tx.is_instant_send {
                    balance.mempool_instant += amount;
                } else {
                    balance.mempool += amount;
                }
            }
        }
        
        Ok(balance)
    }

    /// Get all UTXOs for the wallet.
    pub async fn get_utxos(&self) -> Vec<Utxo> {
        let utxos = self.utxo_set.read().await;
        utxos.values().cloned().collect()
    }
    
    /// Get all unspent outputs (alias for get_utxos).
    pub async fn get_unspent_outputs(&self) -> Result<Vec<Utxo>, SpvError> {
        Ok(self.get_utxos().await)
    }
    
    /// Get all addresses (alias for get_watched_addresses).
    pub async fn get_all_addresses(&self) -> Result<Vec<Address>, SpvError> {
        Ok(self.get_watched_addresses().await)
    }

    /// Get UTXOs for a specific address.
    pub async fn get_utxos_for_address(&self, address: &Address) -> Vec<Utxo> {
        let utxos = self.utxo_set.read().await;
        utxos.values().filter(|utxo| &utxo.address == address).cloned().collect()
    }

    /// Add a UTXO to the wallet.
    pub(crate) async fn add_utxo(&self, utxo: Utxo) -> Result<(), SpvError> {
        tracing::info!(
            "Adding UTXO: {} for address {} at height {} (is_confirmed={})",
            utxo.outpoint,
            utxo.address,
            utxo.height,
            utxo.is_confirmed
        );
        
        let mut utxos = self.utxo_set.write().await;
        utxos.insert(utxo.outpoint, utxo.clone());

        // Persist the UTXO
        let mut storage = self.storage.write().await;
        storage.store_utxo(&utxo.outpoint, &utxo).await?;
        
        // Track in rollback manager if enabled
        if let Some(ref _rollback_mgr) = *self.rollback_manager.read().await {
            let _change = UTXOChange::Created(utxo.clone());
            // Note: This requires block height which isn't available here
            // The rollback tracking should be done at the block processing level
        }

        Ok(())
    }

    /// Remove a UTXO from the wallet (when it's spent).
    pub(crate) async fn remove_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, SpvError> {
        let mut utxos = self.utxo_set.write().await;
        let removed = utxos.remove(outpoint);

        if removed.is_some() {
            // Remove from storage
            let mut storage = self.storage.write().await;
            storage.remove_utxo(outpoint).await?;
        }

        Ok(removed)
    }

    /// Load wallet state from storage.
    pub async fn load_from_storage(&self) -> Result<(), SpvError> {
        // Load watched addresses
        let storage = self.storage.read().await;
        if let Some(data) = storage.load_metadata("watched_addresses").await? {
            let address_strings: Vec<String> = bincode::deserialize(&data).map_err(|e| {
                SpvError::Storage(StorageError::Serialization(format!(
                    "Failed to deserialize watched addresses: {}",
                    e
                )))
            })?;

            let mut addresses = HashSet::new();
            for addr_str in address_strings {
                let address = addr_str
                    .parse::<dashcore::Address<dashcore::address::NetworkUnchecked>>()
                    .map_err(|e| {
                        SpvError::Storage(StorageError::Serialization(format!(
                            "Invalid address: {}",
                            e
                        )))
                    })?
                    .assume_checked();
                addresses.insert(address);
            }

            let mut watched = self.watched_addresses.write().await;
            *watched = addresses;
        }

        // Load UTXOs
        let utxos = storage.get_all_utxos().await?;
        let mut utxo_set = self.utxo_set.write().await;
        *utxo_set = utxos;

        Ok(())
    }

    /// Calculate balance with proper confirmation logic.
    async fn calculate_balance(
        &self,
        address_filter: Option<&Address>,
    ) -> Result<Balance, SpvError> {
        let utxos = self.utxo_set.read().await;
        let mut balance = Balance::new();
        
        tracing::debug!(
            "Calculating balance for address filter: {:?}, total UTXOs: {}", 
            address_filter, 
            utxos.len()
        );

        // TODO: Get current tip height for confirmation calculation
        // For now, use a placeholder - in a real implementation, this would come from the sync manager
        let current_height = self.get_current_tip_height().await.unwrap_or(1000000);

        for utxo in utxos.values() {
            // Filter by address if specified
            if let Some(filter_addr) = address_filter {
                if &utxo.address != filter_addr {
                    continue;
                }
            }

            let amount = Amount::from_sat(utxo.txout.value);
            
            tracing::debug!(
                "UTXO {}: amount={}, height={}, is_confirmed={}, is_instantlocked={}",
                utxo.outpoint,
                amount,
                utxo.height,
                utxo.is_confirmed,
                utxo.is_instantlocked
            );

            // Categorize UTXO based on confirmation and lock status
            if utxo.is_confirmed || self.is_chainlocked(utxo).await {
                // Confirmed: marked as confirmed OR ChainLocked
                balance.confirmed += amount;
                tracing::debug!("  -> Added to confirmed balance");
            } else if utxo.is_instantlocked {
                // InstantLocked but not ChainLocked
                balance.instantlocked += amount;
            } else {
                // Check if we have enough confirmations (6+)
                let confirmations = if current_height >= utxo.height {
                    current_height - utxo.height + 1
                } else {
                    0
                };

                tracing::debug!("  -> Confirmations: {}", confirmations);
                if confirmations >= 1 {
                    balance.confirmed += amount;
                    tracing::debug!("  -> Added to confirmed balance (1+ confirmations)");
                } else {
                    balance.pending += amount;
                    tracing::debug!("  -> Added to pending balance (0 confirmations)");
                }
            }
        }
        
        tracing::debug!(
            "Final balance: confirmed={}, pending={}, instantlocked={}, total={}",
            balance.confirmed,
            balance.pending,
            balance.instantlocked,
            balance.total()
        );

        Ok(balance)
    }

    /// Get the current blockchain tip height.
    async fn get_current_tip_height(&self) -> Option<u32> {
        let storage = self.storage.read().await;
        match storage.get_tip_height().await {
            Ok(height) => height,
            Err(e) => {
                tracing::warn!("Failed to get tip height from storage: {}", e);
                None
            }
        }
    }

    /// Get the height for a specific block hash.
    /// This is a public method that allows external components to query block heights.
    pub async fn get_block_height(&self, block_hash: &dashcore::BlockHash) -> Option<u32> {
        let storage = self.storage.read().await;
        match storage.get_header_height_by_hash(block_hash).await {
            Ok(height) => height,
            Err(e) => {
                tracing::warn!("Failed to get height for block {}: {}", block_hash, e);
                None
            }
        }
    }

    /// Check if a UTXO is ChainLocked.
    /// TODO: This should check against actual ChainLock data.
    async fn is_chainlocked(&self, _utxo: &Utxo) -> bool {
        // Placeholder implementation - in the future this would check ChainLock status
        false
    }

    /// Update UTXO confirmation status based on current blockchain state.
    pub async fn update_confirmation_status(&self) -> Result<(), SpvError> {
        let current_height = self.get_current_tip_height().await.unwrap_or(1000000);
        let mut utxos = self.utxo_set.write().await;

        for utxo in utxos.values_mut() {
            let confirmations = if current_height >= utxo.height {
                current_height - utxo.height + 1
            } else {
                0
            };

            // Update confirmation status (1+ confirmations or ChainLocked)
            let was_confirmed = utxo.is_confirmed;
            utxo.is_confirmed = confirmations >= 1 || self.is_chainlocked(utxo).await;

            // If confirmation status changed, persist the update
            if was_confirmed != utxo.is_confirmed {
                let mut storage = self.storage.write().await;
                storage.store_utxo(&utxo.outpoint, utxo).await?;
            }
        }

        Ok(())
    }

    /// Save watched addresses to storage.
    async fn save_watched_addresses(&self, addresses: &HashSet<Address>) -> Result<(), SpvError> {
        // Convert addresses to strings for serialization
        let address_strings: Vec<String> = addresses.iter().map(|addr| addr.to_string()).collect();
        let data = bincode::serialize(&address_strings).map_err(|e| {
            SpvError::Storage(StorageError::Serialization(format!(
                "Failed to serialize watched addresses: {}",
                e
            )))
        })?;

        let mut storage = self.storage.write().await;
        storage.store_metadata("watched_addresses", &data).await?;

        Ok(())
    }
    
    /// Handle a transaction being confirmed in a block (moved from mempool).
    pub async fn handle_transaction_confirmed(
        &self,
        txid: &dashcore::Txid,
        block_height: u32,
        block_hash: &dashcore::BlockHash,
        mempool_state: &mut MempoolState,
    ) -> Result<(), SpvError> {
        // Remove from mempool
        if let Some(tx) = mempool_state.remove_transaction(txid) {
            tracing::info!(
                "Transaction {} confirmed at height {} (was in mempool for {:?})",
                txid,
                block_height,
                tx.first_seen.elapsed()
            );
        }
        
        Ok(())
    }
    
    /// Process a new block - track UTXO changes for rollback support.
    pub async fn process_block(
        &self,
        block_height: u32,
        block_hash: dashcore::BlockHash,
        transactions: &[dashcore::Transaction],
    ) -> Result<(), SpvError> {
        // Create snapshot if rollback is enabled
        let mut rollback_mgr_guard = self.rollback_manager.write().await;
        if let Some(ref mut rollback_mgr) = *rollback_mgr_guard {
            let mut wallet_state = self.wallet_state.write().await;
            let mut storage = self.storage.write().await;
            
            rollback_mgr.process_block(
                block_height,
                block_hash,
                transactions,
                &mut *wallet_state,
                &mut *storage,
            ).await.map_err(|e| SpvError::Storage(StorageError::ReadFailed(e.to_string())))?;
        }
        
        Ok(())
    }
    
    /// Rollback wallet state to a specific height.
    pub async fn rollback_to_height(&self, target_height: u32) -> Result<(), SpvError> {
        let mut rollback_mgr_guard = self.rollback_manager.write().await;
        if let Some(ref mut rollback_mgr) = *rollback_mgr_guard {
            let mut wallet_state = self.wallet_state.write().await;
            let mut storage = self.storage.write().await;
            
            // Rollback and get the snapshots that were rolled back
            let rolled_back_snapshots = rollback_mgr.rollback_to_height(
                target_height,
                &mut *wallet_state,
                &mut *storage,
            ).await.map_err(|e| SpvError::Storage(StorageError::ReadFailed(e.to_string())))?;
            
            // Apply changes to wallet's UTXO set
            let mut utxos = self.utxo_set.write().await;
            
            for snapshot in rolled_back_snapshots {
                for change in snapshot.changes {
                    match change {
                        UTXOChange::Created(utxo) => {
                            // Remove UTXO that was created after target height
                            utxos.remove(&utxo.outpoint);
                        }
                        UTXOChange::Spent(outpoint) => {
                            // For spent UTXOs, we need to restore them but we don't have the full UTXO data
                            // This is a limitation - we would need to store the full UTXO in the Spent variant
                            tracing::warn!("Cannot restore spent UTXO {} - full data not available", outpoint);
                        }
                        UTXOChange::StatusChanged { outpoint, old_status, .. } => {
                            // Restore old status
                            if let Some(utxo) = utxos.get_mut(&outpoint) {
                                // Set confirmation status based on old_status boolean
                                utxo.set_confirmed(old_status);
                            }
                        }
                    }
                }
            }
            
            tracing::info!("Wallet rolled back to height {}", target_height);
        } else {
            return Err(SpvError::Config("Rollback not enabled for this wallet".to_string()));
        }
        
        Ok(())
    }
    
    /// Check if rollback is enabled.
    pub async fn is_rollback_enabled(&self) -> bool {
        self.rollback_manager.read().await.is_some()
    }
    
    /// Get rollback manager statistics.
    pub async fn get_rollback_stats(&self) -> Option<(usize, u32, u32)> {
        if let Some(ref mgr) = *self.rollback_manager.read().await {
            let (snapshot_count, oldest, newest) = mgr.get_snapshot_info();
            Some((snapshot_count, oldest, newest))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorageManager;
    use dashcore::{Address, Network};

    async fn create_test_wallet() -> Wallet {
        let storage = Arc::new(RwLock::new(MemoryStorageManager::new().await.unwrap()));
        Wallet::new(storage)
    }

    fn create_test_address() -> Address {
        // Create a simple P2PKH address for testing
        use dashcore::{Address, PubkeyHash, ScriptBuf};
        use dashcore_hashes::Hash;
        let pubkey_hash = PubkeyHash::from_slice(&[1u8; 20]).unwrap();
        let script = ScriptBuf::new_p2pkh(&pubkey_hash);
        Address::from_script(&script, Network::Testnet).unwrap()
    }

    #[tokio::test]
    async fn test_wallet_creation() {
        let wallet = create_test_wallet().await;

        // Wallet should start with no watched addresses
        let addresses = wallet.get_watched_addresses().await;
        assert!(addresses.is_empty());

        // Balance should be zero
        let balance = wallet.get_balance().await.unwrap();
        assert_eq!(balance.total(), Amount::ZERO);
    }

    #[tokio::test]
    async fn test_add_watched_address() {
        let wallet = create_test_wallet().await;
        let address = create_test_address();

        // Add address
        wallet.add_watched_address(address.clone()).await.unwrap();

        // Check it was added
        let addresses = wallet.get_watched_addresses().await;
        assert_eq!(addresses.len(), 1);
        assert!(addresses.contains(&address));

        // Check is_watching_address
        assert!(wallet.is_watching_address(&address).await);
    }

    #[tokio::test]
    async fn test_remove_watched_address() {
        let wallet = create_test_wallet().await;
        let address = create_test_address();

        // Add address
        wallet.add_watched_address(address.clone()).await.unwrap();

        // Remove address
        let removed = wallet.remove_watched_address(&address).await.unwrap();
        assert!(removed);

        // Check it was removed
        let addresses = wallet.get_watched_addresses().await;
        assert!(addresses.is_empty());
        assert!(!wallet.is_watching_address(&address).await);

        // Try to remove again (should return false)
        let removed = wallet.remove_watched_address(&address).await.unwrap();
        assert!(!removed);
    }

    #[tokio::test]
    async fn test_balance_new() {
        let balance = Balance::new();
        assert_eq!(balance.confirmed, Amount::ZERO);
        assert_eq!(balance.pending, Amount::ZERO);
        assert_eq!(balance.instantlocked, Amount::ZERO);
        assert_eq!(balance.total(), Amount::ZERO);
    }

    #[tokio::test]
    async fn test_balance_add() {
        let mut balance1 = Balance {
            confirmed: Amount::from_sat(1000),
            pending: Amount::from_sat(500),
            instantlocked: Amount::from_sat(200),
        };

        let balance2 = Balance {
            confirmed: Amount::from_sat(2000),
            pending: Amount::from_sat(300),
            instantlocked: Amount::from_sat(100),
        };

        balance1.add(&balance2);

        assert_eq!(balance1.confirmed, Amount::from_sat(3000));
        assert_eq!(balance1.pending, Amount::from_sat(800));
        assert_eq!(balance1.instantlocked, Amount::from_sat(300));
        assert_eq!(balance1.total(), Amount::from_sat(4100));
    }

    #[tokio::test]
    async fn test_utxo_storage_operations() {
        let wallet = create_test_wallet().await;
        let address = create_test_address();

        // Create a test UTXO
        use dashcore::{OutPoint, TxOut, Txid};
        use std::str::FromStr;

        let outpoint = OutPoint {
            txid: Txid::from_str(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
            vout: 0,
        };

        let txout = TxOut {
            value: 50000,
            script_pubkey: dashcore::ScriptBuf::new(),
        };

        let utxo = crate::wallet::Utxo::new(outpoint, txout, address.clone(), 100, false);

        // Add UTXO
        wallet.add_utxo(utxo.clone()).await.unwrap();

        // Check it was added
        let all_utxos = wallet.get_utxos().await;
        assert_eq!(all_utxos.len(), 1);
        assert_eq!(all_utxos[0], utxo);

        // Check balance
        let balance = wallet.get_balance().await.unwrap();
        assert_eq!(balance.confirmed, Amount::from_sat(50000));

        // Remove UTXO
        let removed = wallet.remove_utxo(&outpoint).await.unwrap();
        assert!(removed.is_some());
        assert_eq!(removed.unwrap(), utxo);

        // Check it was removed
        let all_utxos = wallet.get_utxos().await;
        assert!(all_utxos.is_empty());

        // Check balance is zero
        let balance = wallet.get_balance().await.unwrap();
        assert_eq!(balance.total(), Amount::ZERO);
    }

    #[tokio::test]
    async fn test_calculate_balance_single_utxo() {
        let wallet = create_test_wallet().await;
        let address = create_test_address();

        // Add the address to watch
        wallet.add_watched_address(address.clone()).await.unwrap();

        use dashcore::{OutPoint, TxOut, Txid};
        use std::str::FromStr;

        let outpoint = OutPoint {
            txid: Txid::from_str(
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
            vout: 0,
        };

        let txout = TxOut {
            value: 1000000, // 0.01 DASH
            script_pubkey: address.script_pubkey(),
        };

        // Create UTXO at height 100
        let utxo = crate::wallet::Utxo::new(outpoint, txout, address.clone(), 100, false);

        // Add UTXO to wallet
        wallet.add_utxo(utxo).await.unwrap();

        // Check balance (should be pending since we use a high default current height)
        let balance = wallet.get_balance().await.unwrap();
        assert_eq!(balance.confirmed, Amount::from_sat(1000000)); // Will be confirmed due to high current height
        assert_eq!(balance.pending, Amount::ZERO);
        assert_eq!(balance.instantlocked, Amount::ZERO);
        assert_eq!(balance.total(), Amount::from_sat(1000000));

        // Check balance for specific address
        let addr_balance = wallet.get_balance_for_address(&address).await.unwrap();
        assert_eq!(addr_balance, balance);
    }

    #[tokio::test]
    async fn test_calculate_balance_multiple_utxos() {
        let wallet = create_test_wallet().await;
        let address1 = create_test_address();
        let address2 = {
            use dashcore::{Address, PubkeyHash, ScriptBuf};
            use dashcore_hashes::Hash;
            let pubkey_hash = PubkeyHash::from_slice(&[2u8; 20]).unwrap();
            let script = ScriptBuf::new_p2pkh(&pubkey_hash);
            Address::from_script(&script, dashcore::Network::Testnet).unwrap()
        };

        // Add addresses to watch
        wallet.add_watched_address(address1.clone()).await.unwrap();
        wallet.add_watched_address(address2.clone()).await.unwrap();

        use dashcore::{OutPoint, TxOut, Txid};
        use std::str::FromStr;

        // Create multiple UTXOs
        let utxo1 = crate::wallet::Utxo::new(
            OutPoint {
                txid: Txid::from_str(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
                vout: 0,
            },
            TxOut {
                value: 1000000,
                script_pubkey: address1.script_pubkey(),
            },
            address1.clone(),
            100,
            false,
        );

        let utxo2 = crate::wallet::Utxo::new(
            OutPoint {
                txid: Txid::from_str(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .unwrap(),
                vout: 0,
            },
            TxOut {
                value: 2000000,
                script_pubkey: address1.script_pubkey(),
            },
            address1.clone(),
            200,
            false,
        );

        let utxo3 = crate::wallet::Utxo::new(
            OutPoint {
                txid: Txid::from_str(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                )
                .unwrap(),
                vout: 0,
            },
            TxOut {
                value: 500000,
                script_pubkey: address2.script_pubkey(),
            },
            address2.clone(),
            150,
            false,
        );

        // Add UTXOs to wallet
        wallet.add_utxo(utxo1).await.unwrap();
        wallet.add_utxo(utxo2).await.unwrap();
        wallet.add_utxo(utxo3).await.unwrap();

        // Check total balance
        let total_balance = wallet.get_balance().await.unwrap();
        assert_eq!(total_balance.total(), Amount::from_sat(3500000));

        // Check balance for address1 (should have utxo1 + utxo2)
        let addr1_balance = wallet.get_balance_for_address(&address1).await.unwrap();
        assert_eq!(addr1_balance.total(), Amount::from_sat(3000000));

        // Check balance for address2 (should have utxo3)
        let addr2_balance = wallet.get_balance_for_address(&address2).await.unwrap();
        assert_eq!(addr2_balance.total(), Amount::from_sat(500000));
    }

    #[tokio::test]
    async fn test_balance_with_different_confirmation_states() {
        let wallet = create_test_wallet().await;
        let address = create_test_address();

        wallet.add_watched_address(address.clone()).await.unwrap();

        use dashcore::{OutPoint, TxOut, Txid};
        use std::str::FromStr;

        // Create UTXOs with different confirmation states
        let mut confirmed_utxo = crate::wallet::Utxo::new(
            OutPoint {
                txid: Txid::from_str(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
                vout: 0,
            },
            TxOut {
                value: 1000000,
                script_pubkey: address.script_pubkey(),
            },
            address.clone(),
            100,
            false,
        );
        confirmed_utxo.set_confirmed(true);

        let mut instantlocked_utxo = crate::wallet::Utxo::new(
            OutPoint {
                txid: Txid::from_str(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .unwrap(),
                vout: 0,
            },
            TxOut {
                value: 500000,
                script_pubkey: address.script_pubkey(),
            },
            address.clone(),
            200,
            false,
        );
        instantlocked_utxo.set_instantlocked(true);

        // Create a pending UTXO by manually overriding the default height behavior
        let pending_utxo = crate::wallet::Utxo::new(
            OutPoint {
                txid: Txid::from_str(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                )
                .unwrap(),
                vout: 0,
            },
            TxOut {
                value: 300000,
                script_pubkey: address.script_pubkey(),
            },
            address.clone(),
            999998, // High height to ensure it's pending with our mock current height
            false,
        );

        // Add UTXOs to wallet
        wallet.add_utxo(confirmed_utxo).await.unwrap();
        wallet.add_utxo(instantlocked_utxo).await.unwrap();
        wallet.add_utxo(pending_utxo).await.unwrap();

        // Check balance breakdown
        let balance = wallet.get_balance().await.unwrap();
        assert_eq!(balance.confirmed, Amount::from_sat(1000000)); // Manually confirmed UTXO
        assert_eq!(balance.instantlocked, Amount::from_sat(500000)); // InstantLocked UTXO
        assert_eq!(balance.pending, Amount::from_sat(300000)); // Pending UTXO
        assert_eq!(balance.total(), Amount::from_sat(1800000));
    }

    #[tokio::test]
    async fn test_balance_after_spending() {
        let wallet = create_test_wallet().await;
        let address = create_test_address();

        wallet.add_watched_address(address.clone()).await.unwrap();

        use dashcore::{OutPoint, TxOut, Txid};
        use std::str::FromStr;

        let outpoint1 = OutPoint {
            txid: Txid::from_str(
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
            vout: 0,
        };

        let outpoint2 = OutPoint {
            txid: Txid::from_str(
                "2222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap(),
            vout: 0,
        };

        let utxo1 = crate::wallet::Utxo::new(
            outpoint1,
            TxOut {
                value: 1000000,
                script_pubkey: address.script_pubkey(),
            },
            address.clone(),
            100,
            false,
        );

        let utxo2 = crate::wallet::Utxo::new(
            outpoint2,
            TxOut {
                value: 500000,
                script_pubkey: address.script_pubkey(),
            },
            address.clone(),
            200,
            false,
        );

        // Add UTXOs to wallet
        wallet.add_utxo(utxo1).await.unwrap();
        wallet.add_utxo(utxo2).await.unwrap();

        // Check initial balance
        let initial_balance = wallet.get_balance().await.unwrap();
        assert_eq!(initial_balance.total(), Amount::from_sat(1500000));

        // Spend one UTXO
        let removed = wallet.remove_utxo(&outpoint1).await.unwrap();
        assert!(removed.is_some());

        // Check balance after spending
        let new_balance = wallet.get_balance().await.unwrap();
        assert_eq!(new_balance.total(), Amount::from_sat(500000));

        // Verify specific UTXO is gone
        let utxos = wallet.get_utxos().await;
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].outpoint, outpoint2);
    }

    #[tokio::test]
    async fn test_update_confirmation_status() {
        let wallet = create_test_wallet().await;
        let address = create_test_address();

        wallet.add_watched_address(address.clone()).await.unwrap();

        use dashcore::{OutPoint, TxOut, Txid};
        use std::str::FromStr;

        let utxo = crate::wallet::Utxo::new(
            OutPoint {
                txid: Txid::from_str(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
                vout: 0,
            },
            TxOut {
                value: 1000000,
                script_pubkey: address.script_pubkey(),
            },
            address.clone(),
            100,
            false,
        );

        // Add UTXO (should start as unconfirmed)
        wallet.add_utxo(utxo.clone()).await.unwrap();

        // Verify initial state
        let utxos = wallet.get_utxos().await;
        assert!(!utxos[0].is_confirmed);

        // Update confirmation status
        wallet.update_confirmation_status().await.unwrap();

        // Check that UTXO is now confirmed (due to high mock current height)
        let updated_utxos = wallet.get_utxos().await;
        assert!(updated_utxos[0].is_confirmed);
    }
}
