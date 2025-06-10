//! Wallet consistency validation and recovery functionality.

use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashSet;

use crate::error::{Result, SpvError};
use crate::types::WatchItem;
use crate::wallet::Wallet;
use crate::storage::StorageManager;

/// Report of wallet consistency validation.
#[derive(Debug, Clone)]
pub struct ConsistencyReport {
    /// UTXO mismatches between wallet and storage.
    pub utxo_mismatches: Vec<String>,
    /// Address mismatches between watch items and wallet.
    pub address_mismatches: Vec<String>,
    /// Balance calculation mismatches.
    pub balance_mismatches: Vec<String>,
    /// Whether the wallet and storage are consistent.
    pub is_consistent: bool,
}

/// Result of wallet consistency recovery attempt.
#[derive(Debug, Clone)]
pub struct ConsistencyRecovery {
    /// Number of UTXOs synced from storage to wallet.
    pub utxos_synced: usize,
    /// Number of addresses synced between watch items and wallet.
    pub addresses_synced: usize,
    /// Number of UTXOs removed from wallet (not in storage).
    pub utxos_removed: usize,
    /// Whether the recovery was successful.
    pub success: bool,
}

/// Wallet consistency manager.
pub struct ConsistencyManager<'a> {
    wallet: &'a Arc<RwLock<Wallet>>,
    storage: &'a dyn StorageManager,
    watch_items: &'a Arc<RwLock<HashSet<WatchItem>>>,
}

impl<'a> ConsistencyManager<'a> {
    /// Create a new consistency manager.
    pub fn new(
        wallet: &'a Arc<RwLock<Wallet>>,
        storage: &'a dyn StorageManager,
        watch_items: &'a Arc<RwLock<HashSet<WatchItem>>>,
    ) -> Self {
        Self {
            wallet,
            storage,
            watch_items,
        }
    }
    
    /// Validate wallet and storage consistency.
    pub async fn validate_wallet_consistency(&self) -> Result<ConsistencyReport> {
        tracing::info!("Validating wallet and storage consistency...");
        
        let mut report = ConsistencyReport {
            utxo_mismatches: Vec::new(),
            address_mismatches: Vec::new(),
            balance_mismatches: Vec::new(),
            is_consistent: true,
        };
        
        // Validate UTXO consistency between wallet and storage
        let wallet = self.wallet.read().await;
        let wallet_utxos = wallet.get_utxos().await;
        let storage_utxos = self.storage.get_all_utxos().await
            .map_err(|e| SpvError::Storage(e))?;
        
        // Check for UTXOs in wallet but not in storage
        for wallet_utxo in &wallet_utxos {
            if !storage_utxos.contains_key(&wallet_utxo.outpoint) {
                report.utxo_mismatches.push(format!(
                    "UTXO {} exists in wallet but not in storage", 
                    wallet_utxo.outpoint
                ));
                report.is_consistent = false;
            }
        }
        
        // Check for UTXOs in storage but not in wallet
        for (outpoint, storage_utxo) in &storage_utxos {
            if !wallet_utxos.iter().any(|wu| &wu.outpoint == outpoint) {
                report.utxo_mismatches.push(format!(
                    "UTXO {} exists in storage but not in wallet (address: {})", 
                    outpoint, storage_utxo.address
                ));
                report.is_consistent = false;
            }
        }
        
        // Validate address consistency between WatchItems and wallet
        let watch_items = self.watch_items.read().await;
        let wallet_addresses = wallet.get_watched_addresses().await;
        
        // Collect addresses from watch items
        let watch_addresses: std::collections::HashSet<_> = watch_items.iter()
            .filter_map(|item| {
                if let WatchItem::Address { address, .. } = item {
                    Some(address.clone())
                } else {
                    None
                }
            })
            .collect();
        
        let wallet_address_set: std::collections::HashSet<_> = wallet_addresses.iter().cloned().collect();
        
        // Check for addresses in watch items but not in wallet
        for address in &watch_addresses {
            if !wallet_address_set.contains(address) {
                report.address_mismatches.push(format!(
                    "Address {} in watch items but not in wallet", 
                    address
                ));
                report.is_consistent = false;
            }
        }
        
        // Check for addresses in wallet but not in watch items
        for address in &wallet_addresses {
            if !watch_addresses.contains(address) {
                report.address_mismatches.push(format!(
                    "Address {} in wallet but not in watch items", 
                    address
                ));
                report.is_consistent = false;
            }
        }
        
        if report.is_consistent {
            tracing::info!("✅ Wallet consistency validation passed");
        } else {
            tracing::warn!("❌ Wallet consistency issues detected: {} UTXO mismatches, {} address mismatches", 
                          report.utxo_mismatches.len(), report.address_mismatches.len());
        }
        
        Ok(report)
    }
    
    /// Attempt to recover from wallet consistency issues.
    pub async fn recover_wallet_consistency(&self) -> Result<ConsistencyRecovery> {
        tracing::info!("Attempting wallet consistency recovery...");
        
        let mut recovery = ConsistencyRecovery {
            utxos_synced: 0,
            addresses_synced: 0,
            utxos_removed: 0,
            success: true,
        };
        
        // First, validate to see what needs fixing
        let report = self.validate_wallet_consistency().await?;
        
        if report.is_consistent {
            tracing::info!("No recovery needed - wallet is already consistent");
            return Ok(recovery);
        }
        
        let wallet = self.wallet.read().await;
        
        // Sync UTXOs from storage to wallet
        let storage_utxos = self.storage.get_all_utxos().await
            .map_err(|e| SpvError::Storage(e))?;
        let wallet_utxos = wallet.get_utxos().await;
        
        // Add missing UTXOs to wallet
        for (outpoint, storage_utxo) in &storage_utxos {
            if !wallet_utxos.iter().any(|wu| &wu.outpoint == outpoint) {
                if let Err(e) = wallet.add_utxo(storage_utxo.clone()).await {
                    tracing::error!("Failed to sync UTXO {} to wallet: {}", outpoint, e);
                    recovery.success = false;
                } else {
                    recovery.utxos_synced += 1;
                }
            }
        }
        
        // Remove UTXOs from wallet that aren't in storage
        for wallet_utxo in &wallet_utxos {
            if !storage_utxos.contains_key(&wallet_utxo.outpoint) {
                if let Err(e) = wallet.remove_utxo(&wallet_utxo.outpoint).await {
                    tracing::error!("Failed to remove UTXO {} from wallet: {}", wallet_utxo.outpoint, e);
                    recovery.success = false;
                } else {
                    recovery.utxos_removed += 1;
                }
            }
        }
        
        if recovery.success {
            tracing::info!("✅ Wallet consistency recovery completed: {} UTXOs synced, {} UTXOs removed, {} addresses synced", 
                          recovery.utxos_synced, recovery.utxos_removed, recovery.addresses_synced);
        } else {
            tracing::error!("❌ Wallet consistency recovery partially failed");
        }
        
        Ok(recovery)
    }
    
    /// Ensure wallet consistency by validating and recovering if necessary.
    pub async fn ensure_wallet_consistency(&self) -> Result<()> {
        // First validate consistency
        let report = self.validate_wallet_consistency().await?;
        
        if !report.is_consistent {
            tracing::warn!("Wallet inconsistencies detected, attempting recovery...");
            
            // Attempt recovery
            let recovery = self.recover_wallet_consistency().await?;
            
            if !recovery.success {
                return Err(SpvError::Config(
                    "Wallet consistency recovery failed - some issues remain".to_string()
                ));
            }
            
            // Validate again after recovery
            let post_recovery_report = self.validate_wallet_consistency().await?;
            if !post_recovery_report.is_consistent {
                return Err(SpvError::Config(
                    "Wallet consistency recovery incomplete - issues remain after recovery".to_string()
                ));
            }
            
            tracing::info!("✅ Wallet consistency fully recovered");
        }
        
        Ok(())
    }
}