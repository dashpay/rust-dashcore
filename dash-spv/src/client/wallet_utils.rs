//! Wallet utility functions and helper methods for the Dash SPV client.

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{Result, SpvError};
use crate::wallet::{Balance, Wallet};

/// Summary of wallet statistics.
#[derive(Debug, Clone)]
pub struct WalletSummary {
    /// Number of watched addresses.
    pub watched_addresses_count: usize,
    /// Number of UTXOs in the wallet.
    pub utxo_count: usize,
    /// Total balance across all addresses.
    pub total_balance: Balance,
}

/// Wallet utilities for safe operations with comprehensive error handling.
pub struct WalletUtils {
    wallet: Arc<RwLock<Wallet>>,
}

impl WalletUtils {
    /// Create a new wallet utilities instance.
    pub fn new(wallet: Arc<RwLock<Wallet>>) -> Self {
        Self {
            wallet,
        }
    }

    /// Safely add a UTXO to the wallet with comprehensive error handling.
    pub async fn safe_add_utxo(&self, utxo: crate::wallet::Utxo) -> Result<()> {
        let wallet = self.wallet.write().await;

        match wallet.add_utxo(utxo.clone()).await {
            Ok(_) => {
                tracing::debug!(
                    "Successfully added UTXO {}:{} for address {}",
                    utxo.outpoint.txid,
                    utxo.outpoint.vout,
                    utxo.address
                );
                Ok(())
            }
            Err(e) => {
                tracing::error!(
                    "Failed to add UTXO {}:{} for address {}: {}",
                    utxo.outpoint.txid,
                    utxo.outpoint.vout,
                    utxo.address,
                    e
                );

                // Try to continue with degraded functionality
                tracing::warn!(
                    "Continuing with degraded wallet functionality due to UTXO storage failure"
                );

                Err(SpvError::Storage(crate::error::StorageError::WriteFailed(format!(
                    "Failed to store UTXO {}: {}",
                    utxo.outpoint, e
                ))))
            }
        }
    }

    /// Safely remove a UTXO from the wallet with comprehensive error handling.
    pub async fn safe_remove_utxo(
        &self,
        outpoint: &dashcore::OutPoint,
    ) -> Result<Option<crate::wallet::Utxo>> {
        let wallet = self.wallet.write().await;

        match wallet.remove_utxo(outpoint).await {
            Ok(removed_utxo) => {
                if let Some(ref utxo) = removed_utxo {
                    tracing::debug!(
                        "Successfully removed UTXO {} for address {}",
                        outpoint,
                        utxo.address
                    );
                } else {
                    tracing::debug!(
                        "UTXO {} was not found in wallet (already spent or never existed)",
                        outpoint
                    );
                }
                Ok(removed_utxo)
            }
            Err(e) => {
                tracing::error!("Failed to remove UTXO {}: {}", outpoint, e);

                // This is less critical than adding - we can continue
                tracing::warn!(
                    "Continuing despite UTXO removal failure - wallet may show incorrect balance"
                );

                Err(SpvError::Storage(crate::error::StorageError::WriteFailed(format!(
                    "Failed to remove UTXO {}: {}",
                    outpoint, e
                ))))
            }
        }
    }

    /// Safely get wallet balance with error handling and fallback.
    pub async fn safe_get_wallet_balance(&self) -> Result<Balance> {
        let wallet = self.wallet.read().await;

        match wallet.get_balance().await {
            Ok(balance) => Ok(balance),
            Err(e) => {
                tracing::error!("Failed to calculate wallet balance: {}", e);

                // Return zero balance as fallback
                tracing::warn!("Returning zero balance as fallback due to calculation failure");
                Ok(Balance::new())
            }
        }
    }

    /// Get the total wallet balance.
    pub async fn get_wallet_balance(&self) -> Result<Balance> {
        let wallet = self.wallet.read().await;
        wallet.get_balance().await.map_err(|e| {
            SpvError::Storage(crate::error::StorageError::ReadFailed(format!(
                "Wallet error: {}",
                e
            )))
        })
    }

    /// Get balance for a specific address.
    pub async fn get_wallet_address_balance(&self, address: &dashcore::Address) -> Result<Balance> {
        let wallet = self.wallet.read().await;
        wallet.get_balance_for_address(address).await.map_err(|e| {
            SpvError::Storage(crate::error::StorageError::ReadFailed(format!(
                "Wallet error: {}",
                e
            )))
        })
    }

    /// Get all watched addresses from the wallet.
    pub async fn get_watched_addresses(&self) -> Vec<dashcore::Address> {
        let wallet = self.wallet.read().await;
        wallet.get_watched_addresses().await
    }

    /// Get a summary of wallet statistics.
    pub async fn get_wallet_summary(&self) -> Result<WalletSummary> {
        let wallet = self.wallet.read().await;
        let addresses = wallet.get_watched_addresses().await;
        let utxos = wallet.get_utxos().await;
        let balance = wallet.get_balance().await.map_err(|e| {
            SpvError::Storage(crate::error::StorageError::ReadFailed(format!(
                "Wallet error: {}",
                e
            )))
        })?;

        Ok(WalletSummary {
            watched_addresses_count: addresses.len(),
            utxo_count: utxos.len(),
            total_balance: balance,
        })
    }

    /// Update wallet UTXO confirmation statuses based on current blockchain height.
    pub async fn update_wallet_confirmations(&self) -> Result<()> {
        let wallet = self.wallet.write().await;
        wallet.update_confirmation_status().await.map_err(|e| {
            SpvError::Storage(crate::error::StorageError::ReadFailed(format!(
                "Wallet error: {}",
                e
            )))
        })
    }

    /// Synchronize all current watch items with the wallet.
    /// This ensures that address watch items are properly tracked by the wallet.
    pub async fn sync_watch_items_with_wallet(
        &self,
        watch_items: &std::collections::HashSet<crate::types::WatchItem>,
    ) -> Result<usize> {
        let mut synced_count = 0;

        for item in watch_items.iter() {
            if let crate::types::WatchItem::Address {
                address,
                ..
            } = item
            {
                let wallet = self.wallet.write().await;
                if let Err(e) = wallet.add_watched_address(address.clone()).await {
                    tracing::warn!("Failed to sync address {} with wallet: {}", address, e);
                } else {
                    synced_count += 1;
                }
            }
        }

        tracing::info!("Synced {} address watch items with wallet", synced_count);
        Ok(synced_count)
    }
}
