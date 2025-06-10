//! Watch item management for the Dash SPV client.

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{Result, SpvError};
use crate::types::WatchItem;
use crate::storage::StorageManager;
use crate::wallet::Wallet;
use crate::sync::filters::FilterNotificationSender;

/// Type for sending watch item updates to the filter processor.
pub type WatchItemUpdateSender = tokio::sync::mpsc::UnboundedSender<Vec<WatchItem>>;

/// Watch item manager for adding, removing, and synchronizing watch items.
pub struct WatchManager<'a> {
    watch_items: &'a Arc<RwLock<HashSet<WatchItem>>>,
    storage: &'a mut dyn StorageManager,
    wallet: &'a Arc<RwLock<Wallet>>,
    filter_processor: &'a Option<FilterNotificationSender>,
    watch_item_updater: &'a Option<WatchItemUpdateSender>,
}

impl<'a> WatchManager<'a> {
    /// Create a new watch manager.
    pub fn new(
        watch_items: &'a Arc<RwLock<HashSet<WatchItem>>>,
        storage: &'a mut dyn StorageManager,
        wallet: &'a Arc<RwLock<Wallet>>,
        filter_processor: &'a Option<FilterNotificationSender>,
        watch_item_updater: &'a Option<WatchItemUpdateSender>,
    ) -> Self {
        Self {
            watch_items,
            storage,
            wallet,
            filter_processor,
            watch_item_updater,
        }
    }

    /// Add a watch item.
    pub async fn add_watch_item(&mut self, item: WatchItem) -> Result<()> {
        let mut watch_items = self.watch_items.write().await;
        let is_new = watch_items.insert(item.clone());
        
        if is_new {
            tracing::info!("Added watch item: {:?}", item);
            
            // If the watch item is an address, add it to the wallet as well
            if let WatchItem::Address { address, .. } = &item {
                let wallet = self.wallet.read().await;
                if let Err(e) = wallet.add_watched_address(address.clone()).await {
                    tracing::warn!("Failed to add address to wallet: {}", e);
                    // Continue anyway - the WatchItem is still valid for filter processing
                }
            }
            
            // Store in persistent storage
            let watch_list: Vec<WatchItem> = watch_items.iter().cloned().collect();
            let serialized = serde_json::to_vec(&watch_list)
                .map_err(|e| SpvError::Config(format!("Failed to serialize watch items: {}", e)))?;
            
            self.storage.store_metadata("watch_items", &serialized).await
                .map_err(|e| SpvError::Storage(e))?;
            
            // Send updated watch items to filter processor if it exists
            if let Some(updater) = self.watch_item_updater {
                if let Err(e) = updater.send(watch_list.clone()) {
                    tracing::error!("Failed to send watch item update to filter processor: {}", e);
                }
            }
        }
        
        Ok(())
    }
    
    /// Remove a watch item.
    pub async fn remove_watch_item(&mut self, item: &WatchItem) -> Result<bool> {
        let mut watch_items = self.watch_items.write().await;
        let removed = watch_items.remove(item);
        
        if removed {
            tracing::info!("Removed watch item: {:?}", item);
            
            // If the watch item is an address, remove it from the wallet as well
            if let WatchItem::Address { address, .. } = item {
                let wallet = self.wallet.read().await;
                if let Err(e) = wallet.remove_watched_address(address).await {
                    tracing::warn!("Failed to remove address from wallet: {}", e);
                    // Continue anyway - the WatchItem removal is still valid
                }
            }
            
            // Update persistent storage
            let watch_list: Vec<WatchItem> = watch_items.iter().cloned().collect();
            let serialized = serde_json::to_vec(&watch_list)
                .map_err(|e| SpvError::Config(format!("Failed to serialize watch items: {}", e)))?;
            
            self.storage.store_metadata("watch_items", &serialized).await
                .map_err(|e| SpvError::Storage(e))?;
            
            // Send updated watch items to filter processor if it exists
            if let Some(updater) = self.watch_item_updater {
                if let Err(e) = updater.send(watch_list.clone()) {
                    tracing::error!("Failed to send watch item update to filter processor: {}", e);
                }
            }
        }
        
        Ok(removed)
    }
    
    /// Get all watch items.
    pub async fn get_watch_items(&self) -> Vec<WatchItem> {
        let watch_items = self.watch_items.read().await;
        watch_items.iter().cloned().collect()
    }
    
    /// Load watch items from storage.
    pub async fn load_watch_items(&mut self) -> Result<()> {
        if let Some(data) = self.storage.load_metadata("watch_items").await
            .map_err(|e| SpvError::Storage(e))? {
            
            let watch_list: Vec<WatchItem> = serde_json::from_slice(&data)
                .map_err(|e| SpvError::Config(format!("Failed to deserialize watch items: {}", e)))?;
            
            let mut watch_items = self.watch_items.write().await;
            let mut addresses_synced = 0;
            
            for item in watch_list {
                // Sync address watch items with the wallet
                if let WatchItem::Address { address, .. } = &item {
                    let wallet = self.wallet.read().await;
                    if let Err(e) = wallet.add_watched_address(address.clone()).await {
                        tracing::warn!("Failed to sync address {} with wallet during load: {}", address, e);
                    } else {
                        addresses_synced += 1;
                    }
                }
                
                watch_items.insert(item);
            }
            
            tracing::info!("Loaded {} watch items from storage ({} addresses synced with wallet)", 
                          watch_items.len(), addresses_synced);
        }
        
        Ok(())
    }
}