//! Client lifecycle management.
//!
//! This module contains:
//! - Constructor (`new`)
//! - Shutdown logic (`stop`)
//! - Sync initiation (`start_sync`)
//! - Genesis block initialization
//! - Wallet data loading

use super::core::SyncLoop;
use super::core::SyncManagers;
use super::{ClientConfig, DashSpvClient, EventHandler};
use crate::chain::checkpoints::CheckpointManager;
use crate::error::{Result, SpvError};
use crate::network::NetworkManager;
use crate::sml_engine::MasternodeListEngine;
use crate::storage::{
    BlockHeaderStorage, BlockStorage, FilterHeaderStorage, FilterStorage,
    PersistentBlockHeaderStorage, StorageManager,
};
use crate::sync::{
    BlockHeadersManager, BlocksManager, ChainLockManager, FilterHeadersManager, FiltersManager,
    InstantSendManager, Managers, MasternodesManager, MempoolManager, SyncCoordinator,
};
use crate::types::HashedBlockHeader;
use dashcore::block::{Header as BlockHeader, Version};
use dashcore::network::constants::NetworkExt;
use dashcore::pow::CompactTarget;
use dashcore::TxMerkleNode;
use dashcore_hashes::Hash;
use key_wallet_manager::WalletInterface;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

impl<W: WalletInterface, N: NetworkManager, S: StorageManager> DashSpvClient<W, N, S> {
    /// Create a new SPV client with the given configuration, network, storage, and wallet.
    pub async fn new(
        config: ClientConfig,
        network: N,
        mut storage: S,
        wallet: Arc<RwLock<W>>,
        event_handlers: Vec<Arc<dyn EventHandler>>,
    ) -> Result<Self> {
        tracing::info!("{}", crate::version_info());

        // Validate configuration
        config.validate().map_err(SpvError::Config)?;
        config.apply_global_overrides().map_err(SpvError::Config)?;

        let start_from_height = Self::resolve_start_height(&config, &wallet).await;

        // Initialize genesis block or checkpoint before creating managers,
        // so they can read the tip from storage during construction.
        Self::initialize_genesis_block(&config, start_from_height, &mut storage).await?;

        let masternode_engine = {
            if config.enable_masternodes {
                let engine = storage.masternodes().read().await.load_engine().await;
                Some(Arc::new(RwLock::new(engine)))
            } else {
                None
            }
        };

        // Report the progress of the data already in storage before the first run.
        let initial_progress =
            Self::build_managers(&config, &storage, &wallet, masternode_engine.as_ref())
                .await?
                .progress();

        // Wrap storage in Arc<Mutex>
        let storage = Arc::new(Mutex::new(storage));

        let client = Self {
            config: Arc::new(RwLock::new(config)),
            network: Arc::new(Mutex::new(network)),
            storage,
            wallet,
            masternode_engine,
            sync_coordinator: Arc::new(Mutex::new(SyncCoordinator::new(initial_progress.clone()))),
            sync_loop: Arc::new(Mutex::new(None)),
            event_handlers: Arc::new(event_handlers),
        };

        // Load wallet data from storage
        client.load_wallet_data().await?;

        // Emit initial progress so callers get immediate feedback
        for event_handler in client.event_handlers.iter() {
            event_handler.on_progress(&initial_progress);
        }

        Ok(client)
    }

    /// Resolve where to anchor the chain.
    ///
    /// An explicit `start_from_height` always wins. Otherwise fall back to the wallet
    /// birth height so we don't sync headers and filter headers from genesis when the
    /// wallet only cares about recent blocks. The wallet-derived height is floored at
    /// the network minimum: no HD/BIP39 wallet can predate mainnet's activation height,
    /// so a low or zero birth height must never drag mainnet sync below it.
    async fn resolve_start_height(config: &ClientConfig, wallet: &RwLock<W>) -> Option<u32> {
        match config.start_from_height {
            Some(height) => Some(height),
            None => {
                let birth_height = wallet.read().await.earliest_required_height().await;
                let start = birth_height.max(config.network.hd_wallet_sync_floor());
                (start > 0).then_some(start)
            }
        }
    }

    /// Build the sync managers enabled by `config` on top of `storage`.
    async fn build_managers(
        config: &ClientConfig,
        storage: &S,
        wallet: &Arc<RwLock<W>>,
        masternode_engine: Option<&Arc<RwLock<MasternodeListEngine<PersistentBlockHeaderStorage>>>>,
    ) -> Result<SyncManagers<W>> {
        let mut managers: SyncManagers<W> = Managers::default();

        let checkpoint_manager = Arc::new(CheckpointManager::for_network(config.network));
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
        if let Some(masternode_list_engine) =
            masternode_engine.filter(|_| config.enable_masternodes)
        {
            managers.masternode = Some(
                MasternodesManager::new(
                    storage.block_headers(),
                    masternode_list_engine.clone(),
                    config.network,
                    Some(storage.masternodes()),
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
                config.broadcast_config(),
            ));
        }

        Ok(managers)
    }

    /// Build the sync managers, resuming from wherever storage left off.
    async fn build_sync_managers(&self) -> Result<SyncManagers<W>> {
        let config = self.config.read().await.clone();
        let mut storage = self.storage.lock().await;
        let start_from_height = Self::resolve_start_height(&config, &self.wallet).await;
        Self::initialize_genesis_block(&config, start_from_height, &mut storage).await?;

        Self::build_managers(&config, &storage, &self.wallet, self.masternode_engine.as_ref()).await
    }

    /// Start the sync managers, the network and the storage worker.
    pub(super) async fn start_sync(&self) -> Result<()> {
        let managers = self.build_sync_managers().await?;

        // Start all sync tasks before connecting to the network to make sure initial connection
        // events are handled correctly in the sync coordinator.
        if let Err(e) = self
            .sync_coordinator
            .lock()
            .await
            .start(managers, &mut *self.network.lock().await)
            .await
        {
            tracing::error!("Failed to start sync coordinator: {}", e);
            return Err(SpvError::Sync(e));
        }

        // Start the network
        if let Err(e) = self.network.lock().await.start().await {
            if let Err(e) = self.sync_coordinator.lock().await.shutdown().await {
                tracing::warn!("Error shutting down sync coordinator: {}", e);
            }
            return Err(e.into());
        }

        // Start persisting last, so a failed start leaves nothing to stop.
        self.storage.lock().await.start().await;

        Ok(())
    }

    /// Stop the SPV client.
    pub async fn stop(&self) {
        let mut sync_loop = self.sync_loop.lock().await;
        if let Some(running) = sync_loop.take() {
            self.stop_locked(running).await;
        }
    }

    /// Stop the client if its sync loop failed. A loop that was stopped or
    /// replaced by a later `run` in the meantime is left alone.
    pub(super) async fn stop_failed(&self) {
        let mut sync_loop = self.sync_loop.lock().await;
        if let Some(failed) = sync_loop.take_if(|running| running.shutdown.is_cancelled()) {
            self.stop_locked(failed).await;
        }
    }

    /// Recover from a fork at `fork_height`: stop the client, drop the stored
    /// chain and what the wallets recorded above the fork, and run again, so
    /// the client syncs onto the branch the network follows. A loop that was
    /// stopped or replaced in the meantime is left alone.
    ///
    /// Boxed because the client it runs again can recover from a fork too.
    pub(super) fn handle_fork(
        &self,
        fork_height: u32,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            let mut sync_loop = self.sync_loop.lock().await;
            let Some(forked) = sync_loop.take_if(|running| running.shutdown.is_cancelled()) else {
                return Ok(());
            };
            self.stop_locked(forked).await;

            tracing::warn!("Fork at height {}, dropping the stored chain above it", fork_height);
            // The wallets go first: a wallet refusing the fork leaves storage as
            // it is, and storage failing after them keeps the fork unstored, so
            // it is detected and retried.
            let truncated = async {
                self.wallet.write().await.truncate_above(fork_height)?;
                let mut storage = self.storage.lock().await;
                BlockHeaderStorage::truncate_above(&mut *storage, fork_height).await?;
                FilterHeaderStorage::truncate_above(&mut *storage, fork_height).await?;
                FilterStorage::truncate_above(&mut *storage, fork_height).await?;
                BlockStorage::truncate_above(&mut *storage, fork_height).await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            }
            .await;

            if let Err(e) = truncated {
                tracing::warn!("Fork at height {} not followed: {}", fork_height, e);
            }

            self.run_locked(&mut sync_loop).await
        })
    }

    /// Stop `sync_loop` and everything it drives. The caller holds the lock.
    pub(super) async fn stop_locked(
        &self,
        SyncLoop {
            task,
            shutdown,
        }: SyncLoop,
    ) {
        // Stop the sync loop before tearing anything down so it cannot lock the
        // sync coordinator again. This prevents a tick from racing against the
        // shutdown below.
        shutdown.cancel();
        if let Err(e) = task.await {
            tracing::warn!("Sync loop task failed: {}", e);
        }

        // Shut down sync coordinator: signals cancellation and waits for manager
        // tasks to drain before we tear down the network and storage layers.
        if let Err(e) = self.sync_coordinator.lock().await.shutdown().await {
            tracing::warn!("Error shutting down sync coordinator: {}", e);
        }

        // Stop the network
        self.network.lock().await.stop().await;

        // Stop storage to ensure all data is persisted
        {
            let mut storage = self.storage.lock().await;
            storage.stop().await;
            tracing::info!("Storage stopped - all data persisted");
        }
    }

    /// Initialize genesis block or checkpoint in storage.
    ///
    /// Called before creating managers so they can read the tip during construction.
    async fn initialize_genesis_block(
        config: &ClientConfig,
        start_from_height: Option<u32>,
        storage: &mut S,
    ) -> Result<()> {
        // Check if we already have any headers in storage
        let current_tip = storage.get_tip_height().await;

        if current_tip.is_some() {
            // We already have headers, genesis block should be at height 0
            tracing::debug!("Headers already exist in storage, skipping genesis initialization");
            return Ok(());
        }

        // Check if we should use a checkpoint instead of genesis
        if let Some(start_height) = start_from_height {
            let checkpoint_manager = CheckpointManager::for_network(config.network);

            // Find the best checkpoint at or before the requested height
            if let Some(checkpoint) = checkpoint_manager.last_checkpoint_before_height(start_height)
            {
                if checkpoint.height > 0 {
                    tracing::info!(
                        "🚀 Starting sync from checkpoint at height {} instead of genesis (requested start height: {})",
                        checkpoint.height,
                        start_height
                    );

                    // The checkpoint stores the trusted block hash but not the block version,
                    // so a reconstructed header cannot be hashed back to that value. Anchor on
                    // the trusted hash directly: chain linkage compares against the stored hash,
                    // and `time`/`bits` (used for difficulty checks of later headers) come from
                    // the checkpoint. The version is irrelevant since the hash is never recomputed.
                    let checkpoint_header = BlockHeader {
                        version: Version::from_consensus(0),
                        prev_blockhash: checkpoint.prev_blockhash,
                        merkle_root: checkpoint
                            .merkle_root
                            .map(|h| TxMerkleNode::from_byte_array(*h.as_byte_array()))
                            .unwrap_or_else(TxMerkleNode::all_zeros),
                        time: checkpoint.timestamp,
                        bits: CompactTarget::from_consensus(
                            checkpoint.target.to_compact_lossy().to_consensus(),
                        ),
                        nonce: checkpoint.nonce,
                    };
                    let anchor = HashedBlockHeader::with_trusted_hash(
                        checkpoint_header,
                        checkpoint.block_hash,
                    );
                    storage.store_headers_at_height(&[anchor], checkpoint.height).await?;

                    tracing::info!(
                        "✅ Initialized from checkpoint at height {}, skipping {} headers",
                        checkpoint.height,
                        checkpoint.height
                    );

                    return Ok(());
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
        storage
            .store_headers(&[crate::types::HashedBlockHeader::from(genesis_header)])
            .await
            .map_err(SpvError::Storage)?;

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
