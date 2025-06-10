//! Filter synchronization and management for the Dash SPV client.

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{Result, SpvError};
use crate::types::{WatchItem, FilterMatch};
use crate::sync::SyncManager;
use crate::storage::StorageManager;
use crate::network::NetworkManager;
use crate::types::SpvStats;

/// Filter synchronization manager for coordinating filter downloads and checking.
pub struct FilterSyncCoordinator<'a> {
    sync_manager: &'a mut SyncManager,
    storage: &'a mut dyn StorageManager,
    network: &'a mut dyn NetworkManager,
    watch_items: &'a Arc<RwLock<std::collections::HashSet<WatchItem>>>,
    stats: &'a Arc<RwLock<SpvStats>>,
    running: &'a Arc<RwLock<bool>>,
}

impl<'a> FilterSyncCoordinator<'a> {
    /// Create a new filter sync coordinator.
    pub fn new(
        sync_manager: &'a mut SyncManager,
        storage: &'a mut dyn StorageManager,
        network: &'a mut dyn NetworkManager,
        watch_items: &'a Arc<RwLock<std::collections::HashSet<WatchItem>>>,
        stats: &'a Arc<RwLock<SpvStats>>,
        running: &'a Arc<RwLock<bool>>,
    ) -> Self {
        Self {
            sync_manager,
            storage,
            network,
            watch_items,
            stats,
            running,
        }
    }

    /// Sync compact filters for recent blocks and check for matches.
    /// Sync and check filters with internal monitoring loop management.
    /// This method automatically handles the monitoring loop required for CFilter message processing.
    pub async fn sync_and_check_filters_with_monitoring(&mut self, num_blocks: Option<u32>) -> Result<Vec<FilterMatch>> {
        // Just delegate to the regular method for now - the real fix is in sync_filters_coordinated
        self.sync_and_check_filters(num_blocks).await
    }

    pub async fn sync_and_check_filters(&mut self, num_blocks: Option<u32>) -> Result<Vec<FilterMatch>> {
        let running = self.running.read().await;
        if !*running {
            return Err(SpvError::Config("Client not running".to_string()));
        }
        drop(running);
        
        // Get current tip height to determine range
        let tip_height = self.storage.get_tip_height().await
            .map_err(|e| SpvError::Storage(e))?
            .unwrap_or(0);
        
        // Get current watch items to determine earliest height needed
        let watch_items = self.get_watch_items().await;
        
        if watch_items.is_empty() {
            tracing::info!("No watch items configured, skipping filter sync");
            return Ok(Vec::new());
        }
        
        // Find the earliest height among all watch items
        let earliest_height = watch_items.iter()
            .filter_map(|item| item.earliest_height())
            .min()
            .unwrap_or(tip_height.saturating_sub(99)); // Default to last 100 blocks if no earliest_height set
        
        let num_blocks = num_blocks.unwrap_or(100);
        let default_start = tip_height.saturating_sub(num_blocks - 1);
        let start_height = earliest_height.min(default_start); // Go back to the earliest required height
        let actual_count = tip_height - start_height + 1; // Actual number of blocks available
        
        tracing::info!("Requesting filters from height {} to {} ({} blocks)", 
                      start_height, tip_height, actual_count);
        tracing::info!("Filter processing and matching will happen automatically in background thread as CFilter messages arrive");
        
        // Send filter requests - processing will happen automatically in the background
        self.sync_filters_coordinated(start_height, actual_count).await?;
        
        // Return empty vector since matching happens asynchronously in the filter processor thread
        // Actual matches will be processed and blocks requested automatically when CFilter messages arrive
        Ok(Vec::new())
    }
    
    /// Sync filters in coordination with the monitoring loop using simplified processing
    async fn sync_filters_coordinated(&mut self, start_height: u32, count: u32) -> Result<()> {
        let end_height = start_height + count - 1;
        
        tracing::info!("Starting coordinated filter sync from height {} to {} ({} filters expected)", 
                      start_height, end_height, count);
        
        // Use batch processing to send filter requests
        let batch_size = 100;
        let mut current_height = start_height;
        let mut batches_sent = 0;
        
        // Send all filter requests in batches
        while current_height <= end_height {
            let batch_end = (current_height + batch_size - 1).min(end_height);
            
            tracing::debug!("Sending batch {}: heights {} to {}", batches_sent + 1, current_height, batch_end);
            
            // Get stop hash for this batch
            let stop_hash = self.storage.get_header(batch_end).await
                .map_err(|e| SpvError::Storage(e))?
                .ok_or_else(|| SpvError::Config("Stop header not found".to_string()))?
                .block_hash();
            
            // Send the request - monitoring loop will handle the responses via filter processor
            self.sync_manager.filter_sync_mut().request_filters(&mut *self.network, current_height, stop_hash).await
                .map_err(|e| SpvError::Sync(e))?;
            
            current_height = batch_end + 1;
            batches_sent += 1;
        }
        
        tracing::info!("✅ All filter requests sent ({} batches), processing via filter processor thread", batches_sent);
        
        Ok(())
    }
    
    /// Get all watch items.
    async fn get_watch_items(&self) -> Vec<WatchItem> {
        let watch_items = self.watch_items.read().await;
        watch_items.iter().cloned().collect()
    }
    
    /// Report a filter match to the user.
    pub async fn report_filter_match(&self, block_hash: dashcore::BlockHash) -> Result<()> {
        // Get block height for better reporting by scanning headers
        let height = self.find_height_for_block_hash(block_hash).await
            .unwrap_or(0);
        
        tracing::info!("🚨 FILTER MATCH DETECTED! Block {} at height {} contains transactions affecting watched addresses/scripts", 
                      block_hash, height);
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.filters_matched += 1;
        }
        
        // TODO: Additional actions could be taken here:
        // - Store the match in a database
        // - Send notifications  
        // - Update wallet balance (now happens in process_new_block when the full block arrives)
        
        Ok(())
    }
    
    /// Helper method to find height for a block hash.
    async fn find_height_for_block_hash(&self, block_hash: dashcore::BlockHash) -> Option<u32> {
        // Use the efficient reverse index
        self.storage.get_header_height_by_hash(&block_hash).await.ok().flatten()
    }
    
    /// Process and check a compact filter for matches.
    pub async fn process_and_check_filter(&mut self, cfilter: dashcore::network::message_filter::CFilter) -> Result<()> {
        tracing::debug!("Processing compact filter for block {}", cfilter.block_hash);
        
        // Get watch items to check against
        let watch_items: Vec<_> = self.watch_items.read().await.iter().cloned().collect();
        
        if watch_items.is_empty() {
            tracing::debug!("No watch items configured, skipping filter check");
            return Ok(());
        }
        
        // Use FilterSyncManager to check for matches
        let has_matches = self.sync_manager.filter_sync().check_filter_for_matches(
            &cfilter.filter,
            &cfilter.block_hash,
            &watch_items,
            &*self.storage
        ).await.map_err(|e| SpvError::Sync(e))?;
        
        if has_matches {
            tracing::info!("🎯 Filter match found for block {}!", cfilter.block_hash);
            
            // Get block height for the FilterMatch
            let height = self.find_height_for_block_hash(cfilter.block_hash).await
                .unwrap_or(0);
            
            // Create FilterMatch object
            let filter_match = FilterMatch {
                block_hash: cfilter.block_hash,
                height,
                block_requested: false,
            };
            
            // Request the full block download
            self.sync_manager.filter_sync_mut()
                .request_block_download(filter_match, &mut *self.network)
                .await
                .map_err(|e| SpvError::Sync(e))?;
            
            self.report_filter_match(cfilter.block_hash).await?;
        } else {
            tracing::debug!("No filter matches for block {}", cfilter.block_hash);
        }
        
        Ok(())
    }
}