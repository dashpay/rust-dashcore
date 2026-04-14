//! Client lifecycle management.
//!
//! This module contains:
//! - Constructor (`new`)
//! - Startup logic (`start`)
//! - Shutdown logic (`stop`, `shutdown`)
//! - Sync initiation (`start_sync`)
//! - Genesis block initialization
//! - Wallet data loading

use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use super::{ClientConfig, DashSpvClient, EventHandler};
use crate::chain::checkpoints::{mainnet_checkpoints, testnet_checkpoints, CheckpointManager};
use crate::error::{Result, SpvError};
use crate::network::NetworkManager;
use crate::storage::{
    PersistentBlockHeaderStorage, PersistentBlockStorage, PersistentFilterHeaderStorage,
    PersistentFilterStorage, PersistentMetadataStorage, StorageManager,
};
use crate::sync::{
    BlockHeadersManager, BlocksManager, ChainLockManager, FilterHeadersManager, FiltersManager,
    InstantSendManager, Managers, MasternodesManager, MempoolManager, SyncCoordinator,
};
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore_hashes::Hash;
use key_wallet_manager::WalletInterface;

impl<W: WalletInterface, N: NetworkManager, S: StorageManager, H: EventHandler>
    DashSpvClient<W, N, S, H>
{
    /// Create a new SPV client with the given configuration, network, storage, and wallet.
    pub async fn new(
        config: ClientConfig,
        network: N,
        mut storage: S,
        wallet: Arc<RwLock<W>>,
        event_handler: Arc<H>,
    ) -> Result<Self> {
        // Validate configuration
        config.validate().map_err(SpvError::Config)?;

        // Initialize genesis block or checkpoint before creating managers,
        // so they can read the tip from storage during construction.
        Self::initialize_genesis_block(&config, &mut storage).await?;

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
            dashcore::Network::Mainnet => mainnet_checkpoints(),
            dashcore::Network::Testnet => testnet_checkpoints(),
            _ => Vec::new(),
        };
        let checkpoint_manager = Arc::new(CheckpointManager::new(checkpoints));
        managers.block_headers = Some(
            BlockHeadersManager::new(
                storage.block_headers(),
                storage.metadata(),
                checkpoint_manager,
            )
            .await?,
        );

        if config.enable_filters {
            managers.filter_headers = Some(
                FilterHeadersManager::new(storage.block_headers(), storage.filter_headers())
                    .await?,
            );
            managers.filters = Some(
                FiltersManager::new(
                    wallet.clone(),
                    storage.block_headers(),
                    storage.filter_headers(),
                    storage.filters(),
                )
                .await,
            );
            managers.blocks = Some(
                BlocksManager::new(wallet.clone(), storage.block_headers(), storage.blocks()).await,
            );
        }

        // Build masternode manager if enabled
        if config.enable_masternodes {
            let masternode_list_engine = masternode_engine
                .clone()
                .expect("Masternode list engine must exist if masternodes are enabled");
            managers.masternode = Some(
                MasternodesManager::new(
                    storage.block_headers(),
                    masternode_list_engine.clone(),
                    config.network,
                )
                .await,
            );
            managers.chainlock = Some(
                ChainLockManager::new(
                    storage.block_headers(),
                    storage.metadata(),
                    masternode_list_engine.clone(),
                )
                .await,
            );
            managers.instantsend = Some(InstantSendManager::new(masternode_list_engine.clone()));
        }

        // Build mempool manager if tracking is enabled
        if config.enable_mempool_tracking {
            let initial_revision = wallet.read().await.monitor_revision();
            managers.mempool = Some(MempoolManager::new(
                wallet.clone(),
                config.mempool_strategy,
                config.max_mempool_transactions,
                initial_revision,
            ));
        }

        let sync_coordinator = SyncCoordinator::new(managers).await;

        // Wrap storage in Arc<Mutex>
        let storage = Arc::new(Mutex::new(storage));

        let client = Self {
            config: Arc::new(RwLock::new(config)),
            network: Arc::new(Mutex::new(network)),
            storage,
            wallet,
            masternode_engine,
            sync_coordinator: Arc::new(Mutex::new(sync_coordinator)),
            running: Arc::new(RwLock::new(false)),
            event_handler,
        };

        // Load wallet data from storage
        client.load_wallet_data().await?;

        // Emit initial progress so callers get immediate feedback
        let initial_progress = client.sync_coordinator.lock().await.progress().clone();
        client.event_handler.on_progress(&initial_progress);

        Ok(client)
    }

    /// Start the SPV client: spawn sync tasks and connect to the network.
    pub(super) async fn start(&self) -> Result<()> {
        {
            let running = self.running.read().await;
            if *running {
                return Err(SpvError::Config("Client already running".to_string()));
            }
        }

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
            tracing::warn!("Error shutting down sync coordinator: {}", e);
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

    /// Initialize genesis block or checkpoint in storage.
    ///
    /// Called before creating managers so they can read the tip during construction.
    async fn initialize_genesis_block(config: &ClientConfig, storage: &mut S) -> Result<()> {
        // Check if we already have any headers in storage
        let current_tip = storage.get_tip_height().await;

        if current_tip.is_some() {
            // We already have headers, genesis block should be at height 0
            tracing::debug!("Headers already exist in storage, skipping genesis initialization");
            return Ok(());
        }

        // Check if we should use a checkpoint instead of genesis
        if let Some(start_height) = config.start_from_height {
            // Get checkpoints for this network
            let checkpoints = match config.network {
                dashcore::Network::Mainnet => crate::chain::checkpoints::mainnet_checkpoints(),
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
                        storage
                            .store_headers_at_height(&[checkpoint_header], checkpoint.height)
                            .await?;

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
        storage.store_headers(&[genesis_header]).await.map_err(SpvError::Storage)?;

        // Verify it was stored correctly
        let stored_height = storage.get_tip_height().await;
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
