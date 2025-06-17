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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use dashcore::{Address, Amount, OutPoint};
use tokio::sync::RwLock;

use crate::error::{SpvError, StorageError};
use crate::storage::StorageManager;
pub use transaction_processor::{
    AddressStats, BlockResult, TransactionProcessor, TransactionResult,
};
pub use utxo::Utxo;

/// Main wallet interface for monitoring addresses and tracking UTXOs.
#[derive(Clone)]
pub struct Wallet {
    /// Storage manager for persistence.
    storage: Arc<RwLock<dyn StorageManager>>,

    /// Set of addresses being watched.
    watched_addresses: Arc<RwLock<HashSet<Address>>>,

    /// Current UTXO set indexed by outpoint.
    utxo_set: Arc<RwLock<HashMap<OutPoint, Utxo>>>,
}

/// Balance information for an address or the entire wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Balance {
    /// Confirmed balance (6+ confirmations or ChainLocked).
    pub confirmed: Amount,

    /// Pending balance (< 6 confirmations).
    pub pending: Amount,

    /// InstantLocked balance (InstantLocked but not ChainLocked).
    pub instantlocked: Amount,
}

impl Balance {
    /// Create a new empty balance.
    pub fn new() -> Self {
        Self {
            confirmed: Amount::ZERO,
            pending: Amount::ZERO,
            instantlocked: Amount::ZERO,
        }
    }

    /// Get total balance (confirmed + pending + instantlocked).
    pub fn total(&self) -> Amount {
        self.confirmed + self.pending + self.instantlocked
    }

    /// Add another balance to this one.
    pub fn add(&mut self, other: &Balance) {
        self.confirmed += other.confirmed;
        self.pending += other.pending;
        self.instantlocked += other.instantlocked;
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
        }
    }

    /// Add an address to watch for transactions.
    pub async fn add_watched_address(&self, address: Address) -> Result<(), SpvError> {
        let mut watched = self.watched_addresses.write().await;
        watched.insert(address);

        // Persist the updated watch list
        self.save_watched_addresses(&watched).await?;

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

    /// Get all UTXOs for the wallet.
    pub async fn get_utxos(&self) -> Vec<Utxo> {
        let utxos = self.utxo_set.read().await;
        utxos.values().cloned().collect()
    }

    /// Get UTXOs for a specific address.
    pub async fn get_utxos_for_address(&self, address: &Address) -> Vec<Utxo> {
        let utxos = self.utxo_set.read().await;
        utxos.values().filter(|utxo| &utxo.address == address).cloned().collect()
    }

    /// Add a UTXO to the wallet.
    pub(crate) async fn add_utxo(&self, utxo: Utxo) -> Result<(), SpvError> {
        let mut utxos = self.utxo_set.write().await;
        utxos.insert(utxo.outpoint, utxo.clone());

        // Persist the UTXO
        let mut storage = self.storage.write().await;
        storage.store_utxo(&utxo.outpoint, &utxo).await?;

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

            // Categorize UTXO based on confirmation and lock status
            if utxo.is_confirmed || self.is_chainlocked(utxo).await {
                // Confirmed: 6+ confirmations OR ChainLocked
                balance.confirmed += amount;
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

                if confirmations >= 6 {
                    balance.confirmed += amount;
                } else {
                    balance.pending += amount;
                }
            }
        }

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

            // Update confirmation status (6+ confirmations or ChainLocked)
            let was_confirmed = utxo.is_confirmed;
            utxo.is_confirmed = confirmations >= 6 || self.is_chainlocked(utxo).await;

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
