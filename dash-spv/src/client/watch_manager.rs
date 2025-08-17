//! Watch item management for the Dash SPV client.

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{Result, SpvError};
use crate::storage::StorageManager;
use crate::types::WatchItem;

/// Type for sending watch item updates to the filter processor.
pub type WatchItemUpdateSender = tokio::sync::mpsc::UnboundedSender<Vec<WatchItem>>;

/// Watch item manager for adding, removing, and synchronizing watch items.
pub struct WatchManager;

impl WatchManager {
    /// Add a watch item.
    pub async fn add_watch_item<S: StorageManager>(
        watch_items: &Arc<RwLock<HashSet<WatchItem>>>,
        watch_item_updater: &Option<WatchItemUpdateSender>,
        item: WatchItem,
        storage: &mut S,
    ) -> Result<()> {
        // Check if the item is new and collect the watch list in a limited scope
        let (is_new, watch_list) = {
            let mut watch_items_guard = watch_items.write().await;
            let is_new = watch_items_guard.insert(item.clone());
            let watch_list = if is_new {
                Some(watch_items_guard.iter().cloned().collect::<Vec<_>>())
            } else {
                None
            };
            (is_new, watch_list)
        };

        if is_new {
            tracing::info!("Added watch item: {:?}", item);

            // Wallet now handles addresses internally via WalletInterface

            // Store in persistent storage
            let watch_list = watch_list.ok_or_else(|| {
                SpvError::General(
                    "Internal error: watch_list should be Some when is_new is true".to_string(),
                )
            })?;
            let serialized = serde_json::to_vec(&watch_list)
                .map_err(|e| SpvError::Config(format!("Failed to serialize watch items: {}", e)))?;

            storage
                .store_metadata("watch_items", &serialized)
                .await
                .map_err(|e| SpvError::Storage(e))?;

            // Send updated watch items to filter processor if it exists
            if let Some(updater) = watch_item_updater {
                if let Err(e) = updater.send(watch_list.clone()) {
                    tracing::error!("Failed to send watch item update to filter processor: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Remove a watch item.
    pub async fn remove_watch_item<S: StorageManager>(
        watch_items: &Arc<RwLock<HashSet<WatchItem>>>,
        watch_item_updater: &Option<WatchItemUpdateSender>,
        item: &WatchItem,
        storage: &mut S,
    ) -> Result<bool> {
        // Remove the item and collect the watch list in a limited scope
        let (removed, watch_list) = {
            let mut watch_items_guard = watch_items.write().await;
            let removed = watch_items_guard.remove(item);
            let watch_list = if removed {
                Some(watch_items_guard.iter().cloned().collect::<Vec<_>>())
            } else {
                None
            };
            (removed, watch_list)
        };

        if removed {
            tracing::info!("Removed watch item: {:?}", item);

            // Wallet now handles addresses internally via WalletInterface

            // Update persistent storage
            let watch_list = watch_list.ok_or_else(|| {
                SpvError::General(
                    "Internal error: watch_list should be Some when removed is true".to_string(),
                )
            })?;
            let serialized = serde_json::to_vec(&watch_list)
                .map_err(|e| SpvError::Config(format!("Failed to serialize watch items: {}", e)))?;

            storage
                .store_metadata("watch_items", &serialized)
                .await
                .map_err(|e| SpvError::Storage(e))?;

            // Send updated watch items to filter processor if it exists
            if let Some(updater) = watch_item_updater {
                if let Err(e) = updater.send(watch_list.clone()) {
                    tracing::error!("Failed to send watch item update to filter processor: {}", e);
                }
            }
        }

        Ok(removed)
    }

    /// Load watch items from storage.
    pub async fn load_watch_items<S: StorageManager>(
        watch_items: &Arc<RwLock<HashSet<WatchItem>>>,
        storage: &S,
    ) -> Result<()> {
        if let Some(data) =
            storage.load_metadata("watch_items").await.map_err(|e| SpvError::Storage(e))?
        {
            let watch_list: Vec<WatchItem> = serde_json::from_slice(&data).map_err(|e| {
                SpvError::Config(format!("Failed to deserialize watch items: {}", e))
            })?;

            // Wallet now handles addresses internally via WalletInterface

            // Now insert all items into the watch_items set
            {
                let mut watch_items_guard = watch_items.write().await;
                for item in watch_list {
                    watch_items_guard.insert(item);
                }

                tracing::info!("Loaded {} watch items from storage", watch_items_guard.len());
            }
        }

        Ok(())
    }
}
