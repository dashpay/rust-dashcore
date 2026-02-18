//! Client lifecycle management.
//!
//! This module contains:
//! - Constructor (`new`)
//! - Startup logic (`start`)
//! - Shutdown logic (`stop`, `shutdown`)
//! - Sync initiation (`start_sync`)
//! - Genesis block initialization
//! - Wallet data loading

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use super::{ClientConfig, DashSpvClient};
use crate::chain::checkpoints::{mainnet_checkpoints, testnet_checkpoints, CheckpointManager};
use crate::error::{Result, SpvError};
use crate::mempool_filter::MempoolFilter;
use crate::network::NetworkManager;
use crate::storage::{
    PersistentBlockHeaderStorage, PersistentBlockStorage, PersistentFilterHeaderStorage,
    PersistentFilterStorage, PersistentMetadataStorage, StorageManager,
};
use crate::sync::{
    BlockHeadersManager, BlocksManager, ChainLockManager, FilterHeadersManager, FiltersManager,
    InstantSendManager, Managers, MasternodesManager, SyncCoordinator,
};
use crate::types::MempoolState;
use dashcore::network::constants::NetworkExt;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore_hashes::Hash;
use key_wallet_manager::wallet_interface::WalletInterface;

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    /// Create a new SPV client with the given configuration, network, storage, and wallet.
    pub async fn new(
        config: ClientConfig,
        network: N,
        storage: S,
        wallet: Arc<RwLock<W>>,
    ) -> Result<Self> {
        // Validate configuration
        config.validate().map_err(SpvError::Config)?;

        let masternode_engine = {
            if config.enable_masternodes {
                Some(Arc::new(RwLock::new(MasternodeListEngine::default_for_network(
                    config.network,
                ))))
            } else {
                None
            }
        };

        let mut managers: Managers<
            PersistentBlockHeaderStorage,
            PersistentFilterHeaderStorage,
            PersistentFilterStorage,
            PersistentBlockStorage,
            PersistentMetadataStorage,
            W,
        > = Managers::default();

        let checkpoints = match config.network {
            dashcore::Network::Dash => mainnet_checkpoints(),
            dashcore::Network::Testnet => testnet_checkpoints(),
            _ => Vec::new(),
        };
        let checkpoint_manager = Arc::new(CheckpointManager::new(checkpoints));
        managers.block_headers =
            Some(BlockHeadersManager::new(storage.block_headers(), checkpoint_manager));

        if config.enable_filters {
            managers.filter_headers =
                Some(FilterHeadersManager::new(storage.block_headers(), storage.filter_headers()));
            managers.filters = Some(FiltersManager::new(
                wallet.clone(),
                storage.block_headers(),
                storage.filter_headers(),
                storage.filters(),
            ));
            managers.blocks =
                Some(BlocksManager::new(wallet.clone(), storage.block_headers(), storage.blocks()));
        }

        // Build masternode manager if enabled
        if config.enable_masternodes {
            let masternode_list_engine = masternode_engine
                .clone()
                .expect("Masternode list engine must exist if masternodes are enabled");
            managers.masternode = Some(MasternodesManager::new(
                storage.block_headers(),
                masternode_list_engine.clone(),
                config.network,
            ));
            managers.chainlock = Some(ChainLockManager::new(
                storage.block_headers(),
                storage.metadata(),
                masternode_list_engine.clone(),
            ));
            managers.instantsend = Some(InstantSendManager::new(masternode_list_engine.clone()));
        }

        // Create sync coordinator (managers are passed to start() later)
        let sync_coordinator = SyncCoordinator::new(managers);

        // Create mempool state
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));

        // Wrap storage in Arc<Mutex>
        let storage = Arc::new(Mutex::new(storage));

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            network: Arc::new(Mutex::new(network)),
            storage,
            wallet,
            masternode_engine,
            sync_coordinator: Arc::new(Mutex::new(sync_coordinator)),
            running: Arc::new(RwLock::new(false)),
            mempool_state,
            mempool_filter: Arc::new(RwLock::new(None)),
        })
    }

    /// Start the SPV client.
    pub async fn start(&self) -> Result<()> {
        {
            let running = self.running.read().await;
            if *running {
                return Err(SpvError::Config("Client already running".to_string()));
            }
        }

        // Load wallet data from storage
        self.load_wallet_data().await?;

        let config = self.config.read().await;

        // Initialize mempool filter if mempool tracking is enabled
        if config.enable_mempool_tracking {
            // TODO: Get monitored addresses from wallet
            let filter = Arc::new(MempoolFilter::new(
                config.mempool_strategy,
                config.max_mempool_transactions,
                self.mempool_state.clone(),
                HashSet::new(), // Will be populated from wallet's monitored addresses
                config.network,
            ));

            *self.mempool_filter.write().await = Some(filter);

            // Load mempool state from storage if persistence is enabled
            if config.persist_mempool {
                if let Some(state) = self
                    .storage
                    .lock()
                    .await
                    .load_mempool_state()
                    .await
                    .map_err(SpvError::Storage)?
                {
                    *self.mempool_state.write().await = state;
                }
            }
        }

        // Drop config before calling methods that also read it
        drop(config);

        // Initialize genesis block if not already present
        self.initialize_genesis_block().await?;

        // Start all sync tasks before connecting to the network to make sure initial connection
        // events are handled correctly in the sync coordinator.
        if let Err(e) =
            self.sync_coordinator.lock().await.start(&mut *self.network.lock().await).await
        {
            tracing::error!("Failed to start sync coordinator: {}", e);
            return Err(SpvError::Sync(e));
        }

        // Connect to network
        self.network.lock().await.connect().await?;

        // Only mark as running after all startup operations succeed
        {
            let mut running = self.running.write().await;
            *running = true;
        }

        Ok(())
    }

    /// Stop the SPV client.
    pub async fn stop(&self) -> Result<()> {
        // Check if already stopped
        {
            let running = self.running.read().await;
            if !*running {
                return Ok(());
            }
        }

        // Shut down sync coordinator: signals cancellation and waits for manager
        // tasks to drain before we tear down the network and storage layers.
        if let Err(e) = self.sync_coordinator.lock().await.shutdown().await {
            log::warn!("Error shutting down sync coordinator: {}", e);
        }

        // Disconnect from network
        self.network.lock().await.disconnect().await?;

        // Shutdown storage to ensure all data is persisted
        {
            let mut storage = self.storage.lock().await;
            storage.shutdown().await;
            tracing::info!("Storage shutdown completed - all data persisted");
        }

        // Mark as stopped
        let mut running = self.running.write().await;
        *running = false;

        Ok(())
    }

    /// Shutdown the SPV client (alias for stop).
    pub async fn shutdown(&self) -> Result<()> {
        self.stop().await
    }

    /// Initialize genesis block or checkpoint.
    pub(super) async fn initialize_genesis_block(&self) -> Result<()> {
        let config = self.config.read().await;

        // Check if we already have any headers in storage
        let current_tip = {
            let storage = self.storage.lock().await;
            storage.get_tip_height().await
        };

        if current_tip.is_some() {
            // We already have headers, genesis block should be at height 0
            tracing::debug!("Headers already exist in storage, skipping genesis initialization");
            return Ok(());
        }

        // Check if we should use a checkpoint instead of genesis
        if let Some(start_height) = config.start_from_height {
            // Get checkpoints for this network
            let checkpoints = match config.network {
                dashcore::Network::Dash => crate::chain::checkpoints::mainnet_checkpoints(),
                dashcore::Network::Testnet => crate::chain::checkpoints::testnet_checkpoints(),
                _ => vec![],
            };

            // Create checkpoint manager
            let checkpoint_manager = crate::chain::checkpoints::CheckpointManager::new(checkpoints);

            // Find the best checkpoint at or before the requested height
            if let Some(checkpoint) = checkpoint_manager.last_checkpoint_before_height(start_height)
            {
                if checkpoint.height > 0 {
                    tracing::info!(
                        "🚀 Starting sync from checkpoint at height {} instead of genesis (requested start height: {})",
                        checkpoint.height,
                        start_height
                    );

                    // Build header from checkpoint
                    use dashcore::{
                        block::{Header as BlockHeader, Version},
                        pow::CompactTarget,
                    };

                    let checkpoint_header = BlockHeader {
                        version: Version::from_consensus(536870912), // Version 0x20000000 is common for modern blocks
                        prev_blockhash: checkpoint.prev_blockhash,
                        merkle_root: checkpoint
                            .merkle_root
                            .map(|h| dashcore::TxMerkleNode::from_byte_array(*h.as_byte_array()))
                            .unwrap_or_else(dashcore::TxMerkleNode::all_zeros),
                        time: checkpoint.timestamp,
                        bits: CompactTarget::from_consensus(
                            checkpoint.target.to_compact_lossy().to_consensus(),
                        ),
                        nonce: checkpoint.nonce,
                    };

                    // Verify hash matches
                    let calculated_hash = checkpoint_header.block_hash();
                    if calculated_hash != checkpoint.block_hash {
                        tracing::warn!(
                            "Checkpoint header hash mismatch at height {}: expected {}, calculated {}",
                            checkpoint.height,
                            checkpoint.block_hash,
                            calculated_hash
                        );
                    } else {
                        {
                            let mut storage = self.storage.lock().await;
                            storage
                                .store_headers_at_height(&[checkpoint_header], checkpoint.height)
                                .await?;
                        }

                        tracing::info!(
                            "✅ Initialized from checkpoint at height {}, skipping {} headers",
                            checkpoint.height,
                            checkpoint.height
                        );

                        return Ok(());
                    }
                }
            }
        }

        // Get the genesis block hash for this network
        let genesis_hash = config
            .network
            .known_genesis_block_hash()
            .ok_or_else(|| SpvError::Config("No known genesis hash for network".to_string()))?;

        tracing::info!(
            "Initializing genesis block for network {:?}: {}",
            config.network,
            genesis_hash
        );

        let genesis_header = dashcore::blockdata::constants::genesis_block(config.network).header;

        // Verify the header produces the expected genesis hash
        let calculated_hash = genesis_header.block_hash();
        if calculated_hash != genesis_hash {
            return Err(SpvError::Config(format!(
                "Genesis header hash mismatch! Expected: {}, Calculated: {}",
                genesis_hash, calculated_hash
            )));
        }

        tracing::debug!("Using genesis block header with hash: {}", calculated_hash);

        // Store the genesis header at height 0
        let genesis_headers = vec![genesis_header];
        {
            let mut storage = self.storage.lock().await;
            storage.store_headers(&genesis_headers).await.map_err(SpvError::Storage)?;
        }

        // Verify it was stored correctly
        let stored_height = {
            let storage = self.storage.lock().await;
            storage.get_tip_height().await
        };
        tracing::info!(
            "✅ Genesis block initialized at height 0, storage reports tip height: {:?}",
            stored_height
        );

        Ok(())
    }

    /// Load wallet data from storage.
    pub(super) async fn load_wallet_data(&self) -> Result<()> {
        tracing::info!("Loading wallet data from storage...");

        let _wallet = self.wallet.read().await;

        // The wallet implementation is responsible for managing its own persistent state
        // The SPV client will notify it of new blocks/transactions through the WalletInterface
        tracing::info!("Wallet data loading is handled by the wallet implementation");

        Ok(())
    }
}
