//! Builder pattern for creating DashSpvClient with different storage backends
//!
//! This module provides a flexible way to create SPV clients with either
//! the traditional storage manager or the new event-driven storage service.

use super::{ClientConfig, DashSpvClient};
use crate::{
    chain::ChainLockManager,
    error::{Result, SpvError},
    network::{multi_peer::MultiPeerNetworkManager, NetworkManager},
    storage::{
        compat::StorageManagerCompat,
        disk_backend::DiskStorageBackend,
        memory_backend::MemoryStorageBackend,
        service::{StorageClient, StorageService},
        DiskStorageManager, MemoryStorageManager, StorageManager,
    },
    sync::sequential::SequentialSyncManager,
    types::{ChainState, MempoolState, SpvStats, SyncProgress},
    validation::ValidationManager,
    wallet::Wallet,
};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Builder for creating a DashSpvClient with customizable components
pub struct DashSpvClientBuilder {
    config: ClientConfig,
    use_storage_service: bool,
    storage_path: Option<PathBuf>,
}

impl DashSpvClientBuilder {
    /// Create a new builder with the given configuration
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            use_storage_service: false,
            storage_path: None,
        }
    }

    /// Use the new event-driven storage service (recommended)
    pub fn with_storage_service(mut self) -> Self {
        self.use_storage_service = true;
        self
    }

    /// Set a custom storage path (only used with storage service)
    pub fn with_storage_path(mut self, path: PathBuf) -> Self {
        self.storage_path = Some(path);
        self
    }

    /// Build the DashSpvClient
    pub async fn build(self) -> Result<DashSpvClient> {
        // Validate configuration
        self.config.validate().map_err(|e| SpvError::Config(e))?;

        // Initialize stats
        let stats = Arc::new(RwLock::new(SpvStats::default()));

        // Create storage manager first so we can load chain state
        let mut storage: Box<dyn StorageManager> = if self.use_storage_service {
            // Use the new storage service architecture
            let (service, client) = if self.config.enable_persistence {
                if let Some(path) = self.storage_path.or(self.config.storage_path.clone()) {
                    let backend = Box::new(DiskStorageBackend::new(path).await?);
                    StorageService::new(backend)
                } else {
                    let backend = Box::new(MemoryStorageBackend::new());
                    StorageService::new(backend)
                }
            } else {
                let backend = Box::new(MemoryStorageBackend::new());
                StorageService::new(backend)
            };

            // Spawn the storage service
            tokio::spawn(async move {
                service.run().await;
            });

            // Wrap the client in the compatibility layer
            Box::new(StorageManagerCompat::new(client))
        } else {
            // Use the traditional storage manager
            if self.config.enable_persistence {
                if let Some(path) = &self.config.storage_path {
                    Box::new(
                        DiskStorageManager::new(path.clone())
                            .await
                            .map_err(|e| SpvError::Storage(e))?,
                    )
                } else {
                    Box::new(MemoryStorageManager::new().await.map_err(|e| SpvError::Storage(e))?)
                }
            } else {
                Box::new(MemoryStorageManager::new().await.map_err(|e| SpvError::Storage(e))?)
            }
        };

        // Load or create chain state
        let state = match storage.load_chain_state().await {
            Ok(Some(loaded_state)) => {
                tracing::info!(
                    "📥 Loaded existing chain state - tip_height: {}, headers_count: {}, sync_base: {}",
                    loaded_state.tip_height(),
                    loaded_state.headers.len(),
                    loaded_state.sync_base_height
                );
                Arc::new(RwLock::new(loaded_state))
            }
            Ok(None) => {
                tracing::info!(
                    "🆕 No existing chain state found, creating new state for network: {:?}",
                    self.config.network
                );
                Arc::new(RwLock::new(ChainState::new_for_network(self.config.network)))
            }
            Err(e) => {
                tracing::warn!("⚠️ Failed to load chain state: {}, creating new state", e);
                Arc::new(RwLock::new(ChainState::new_for_network(self.config.network)))
            }
        };

        // Create network manager
        let network: Box<dyn NetworkManager> =
            Box::new(MultiPeerNetworkManager::new(&self.config).await?);

        // Create wallet
        let wallet_storage = Arc::new(RwLock::new(
            MemoryStorageManager::new().await.map_err(|e| SpvError::Storage(e))?,
        ));
        let wallet = Arc::new(RwLock::new(Wallet::new(wallet_storage)));

        // Create managers
        let validation = ValidationManager::new(self.config.validation_mode);
        let chainlock_manager = Arc::new(ChainLockManager::new(true));

        // Create sequential sync manager
        let received_filter_heights = stats.read().await.received_filter_heights.clone();
        let sync_manager = SequentialSyncManager::new(&self.config, received_filter_heights)
            .map_err(|e| SpvError::Sync(e))?;

        // Create channels for block processing
        let (block_processor_tx, block_processor_rx) = mpsc::unbounded_channel();

        // Create channels for progress updates
        let (progress_tx, progress_rx) = mpsc::unbounded_channel();

        // Create channels for events
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        // Create mempool state
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));

        // Create the client
        let client = DashSpvClient {
            config: self.config,
            state,
            stats: stats.clone(),
            network,
            storage,
            wallet,
            sync_manager,
            validation,
            chainlock_manager,
            running: Arc::new(RwLock::new(false)),
            watch_items: Arc::new(RwLock::new(HashSet::new())),
            event_queue: Arc::new(RwLock::new(Vec::new())),
            terminal_ui: None,
            filter_processor: None,
            watch_item_updater: None,
            block_processor_tx,
            progress_sender: Some(progress_tx),
            progress_receiver: Some(progress_rx),
            event_tx,
            event_rx: Some(event_rx),
            mempool_state: mempool_state.clone(),
            mempool_filter: None,
            last_sync_state_save: Arc::new(RwLock::new(0)),
            cached_sync_progress: Arc::new(RwLock::new((
                SyncProgress::default(),
                std::time::Instant::now()
                    .checked_sub(std::time::Duration::from_secs(60))
                    .unwrap_or_else(std::time::Instant::now),
            ))),
            cached_stats: Arc::new(RwLock::new((
                SpvStats::default(),
                std::time::Instant::now()
                    .checked_sub(std::time::Duration::from_secs(60))
                    .unwrap_or_else(std::time::Instant::now),
            ))),
        };

        // Spawn the block processor
        let block_processor = crate::client::block_processor::BlockProcessor::new(
            block_processor_rx,
            client.wallet.clone(),
            client.watch_items.clone(),
            stats,
            client.event_tx.clone(),
        );

        tokio::spawn(async move {
            tracing::info!("🏭 Starting block processor worker task");
            block_processor.run().await;
            tracing::info!("🏭 Block processor worker task completed");
        });

        Ok(client)
    }
}

impl DashSpvClient {
    /// Create a new SPV client using the storage service (recommended)
    ///
    /// This creates a client that uses the new event-driven storage architecture
    /// which prevents deadlocks and improves concurrency.
    pub async fn new_with_storage_service(config: ClientConfig) -> Result<Self> {
        DashSpvClientBuilder::new(config).with_storage_service().build().await
    }
}
