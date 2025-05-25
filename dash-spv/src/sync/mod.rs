//! Synchronization management for the Dash SPV client.

pub mod headers;
pub mod filters;
pub mod masternodes;
pub mod state;

use crate::client::ClientConfig;
use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::types::SyncProgress;

pub use headers::HeaderSyncManager;
pub use filters::FilterSyncManager;
pub use masternodes::MasternodeSyncManager;
pub use state::SyncState;

/// Coordinates all synchronization activities.
pub struct SyncManager {
    header_sync: HeaderSyncManager,
    filter_sync: FilterSyncManager,
    masternode_sync: MasternodeSyncManager,
    state: SyncState,
    config: ClientConfig,
}

impl SyncManager {
    /// Create a new sync manager.
    pub fn new(config: &ClientConfig) -> Self {
        Self {
            header_sync: HeaderSyncManager::new(config),
            filter_sync: FilterSyncManager::new(config),
            masternode_sync: MasternodeSyncManager::new(config),
            state: SyncState::new(),
            config: config.clone(),
        }
    }
    
    /// Synchronize all components to the tip.
    pub async fn sync_all(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<SyncProgress> {
        let mut progress = SyncProgress::default();
        
        // Step 1: Sync headers first
        if self.config.validation_mode != crate::types::ValidationMode::None {
            progress = self.sync_headers(network, storage).await?;
        }
        
        // Step 2: Sync filter headers if enabled
        if self.config.enable_filters {
            progress = self.sync_filter_headers(network, storage).await?;
        }
        
        // Step 3: Sync masternode list if enabled
        if self.config.enable_masternodes {
            progress = self.sync_masternodes(network, storage).await?;
        }
        
        progress.last_update = std::time::SystemTime::now();
        Ok(progress)
    }
    
    /// Synchronize headers.
    pub async fn sync_headers(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<SyncProgress> {
        if self.state.is_syncing(SyncComponent::Headers) {
            return Err(SyncError::SyncInProgress);
        }
        
        self.state.start_sync(SyncComponent::Headers);
        
        let result = self.header_sync.sync(network, storage).await;
        
        self.state.finish_sync(SyncComponent::Headers);
        
        let progress = result?;
        Ok(progress)
    }
    
    /// Synchronize filter headers.
    pub async fn sync_filter_headers(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<SyncProgress> {
        if self.state.is_syncing(SyncComponent::FilterHeaders) {
            return Err(SyncError::SyncInProgress);
        }
        
        self.state.start_sync(SyncComponent::FilterHeaders);
        
        let result = self.filter_sync.sync_headers(network, storage).await;
        
        self.state.finish_sync(SyncComponent::FilterHeaders);
        
        let progress = result?;
        Ok(progress)
    }
    
    /// Synchronize masternode list.
    pub async fn sync_masternodes(
        &mut self,
        network: &mut dyn NetworkManager,
        storage: &mut dyn StorageManager,
    ) -> SyncResult<SyncProgress> {
        if self.state.is_syncing(SyncComponent::Masternodes) {
            return Err(SyncError::SyncInProgress);
        }
        
        self.state.start_sync(SyncComponent::Masternodes);
        
        let result = self.masternode_sync.sync(network, storage).await;
        
        self.state.finish_sync(SyncComponent::Masternodes);
        
        let progress = result?;
        Ok(progress)
    }
    
    /// Get current sync state.
    pub fn sync_state(&self) -> &SyncState {
        &self.state
    }
    
    /// Check if any sync is in progress.
    pub fn is_syncing(&self) -> bool {
        self.state.is_any_syncing()
    }
}

/// Sync component types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncComponent {
    Headers,
    FilterHeaders,
    Filters,
    Masternodes,
}