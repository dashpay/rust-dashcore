//! Client lifecycle management.
//!
//! This module contains:
//! - Constructor (`new`)
//! - Startup logic (`start`)
//! - Shutdown logic (`stop`, `shutdown`)
//! - Sync initiation (`start_sync`)
//! - Genesis block initialization
//! - Wallet data loading

use super::{ClientConfig, DashSpvClient, EventHandler};
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
use crate::types::HashedBlockHeader;
use dashcore::block::{Header as BlockHeader, Version};
use dashcore::network::constants::NetworkExt;
use dashcore::pow::CompactTarget;
use dashcore::sml::masternode_list_engine::MasternodeListEngine;
use dashcore::TxMerkleNode;
use dashcore_hashes::Hash;
use key_wallet_manager::WalletInterface;
use std::sync::Arc;
use tokio::sync::{watch, Mutex, RwLock};

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

        // Masternodes and chainlocks share one list engine; create it up front so the
        // handle stored on the client and the one handed to the managers stay the same.
        let masternode_engine = if config.enable_masternodes {
            Some(Arc::new(RwLock::new(MasternodeListEngine::default_for_network(config.network))))
        } else {
            None
        };

        // Resolve the anchor height, initialize the genesis/checkpoint header, and build
        // all sync managers against storage.
        let managers =
            Self::build_managers(&config, &mut storage, &wallet, &masternode_engine).await?;
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
            running: Arc::new(watch::Sender::new(false)),
            event_handlers: Arc::new(event_handlers),
        };

        // Load wallet data from storage
        client.load_wallet_data().await?;

        // Emit initial progress so callers get immediate feedback
        let initial_progress = client.sync_coordinator.lock().await.progress().clone();
        for event_handler in client.event_handlers.iter() {
            event_handler.on_progress(&initial_progress);
        }

        Ok(client)
    }

    /// Resolve the anchor height, initialize the genesis or checkpoint header in storage,
    /// and construct every sync manager against storage.
    ///
    /// The caller owns `storage`. When it has just been cleared this re-anchors from scratch,
    /// otherwise `initialize_genesis_block` sees the existing tip and leaves the chain in place.
    async fn build_managers(
        config: &ClientConfig,
        storage: &mut S,
        wallet: &Arc<RwLock<W>>,
        masternode_engine: &Option<Arc<RwLock<MasternodeListEngine>>>,
    ) -> Result<
        Managers<
            PersistentBlockHeaderStorage,
            PersistentFilterHeaderStorage,
            PersistentFilterStorage,
            PersistentBlockStorage,
            PersistentMetadataStorage,
            W,
        >,
    > {
        // An explicit `start_from_height` always wins. Otherwise fall back to the wallet
        // birth height so we don't sync headers and filter headers from genesis when the
        // wallet only cares about recent blocks. The wallet-derived height is floored at
        // the network minimum: no HD/BIP39 wallet can predate mainnet's activation height,
        // so a low or zero birth height must never drag mainnet sync below it.
        let start_from_height = match config.start_from_height {
            Some(height) => Some(height),
            None => {
                let birth_height = wallet.read().await.earliest_required_height().await;
                let start = birth_height.max(config.network.hd_wallet_sync_floor());
                (start > 0).then_some(start)
            }
        };

        // Initialize genesis block or checkpoint before creating managers,
        // so they can read the tip from storage during construction.
        Self::initialize_genesis_block(config, start_from_height, storage).await?;

        let mut managers: Managers<
            PersistentBlockHeaderStorage,
            PersistentFilterHeaderStorage,
            PersistentFilterStorage,
            PersistentBlockStorage,
            PersistentMetadataStorage,
            W,
        > = Managers::default();

        let checkpoint_manager = Arc::new(config.checkpoint_manager());
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

        Ok(managers)
    }

    /// Whether the current wallet set needs a resync: some wallet's birth height is below
    /// the anchored header start, so its earlier history cannot be scanned without
    /// re-anchoring lower. Returns false when nothing is anchored yet or every wallet is
    /// already within the synced range.
    pub async fn resync_needed(&self) -> bool {
        let required = self.wallet.read().await.earliest_required_height().await;
        if required == 0 {
            return false;
        }

        match self.storage.lock().await.get_start_height().await {
            Some(header_start) => required < header_start,
            None => false,
        }
    }

    /// Force a full resync from the checkpoint at or below the current minimum wallet birth
    /// height. Tears down sync, wipes all chain storage, and rebuilds the sync managers so the
    /// next sync re-anchors from scratch.
    ///
    /// Wallet state (per-wallet synced heights and discovered outputs) lives outside chain
    /// storage and is preserved, so only chain data is refetched: an added wallet with a
    /// lower birth height drags the anchor down and gets its range scanned, while wallets
    /// that were already ahead keep their progress and are not rescanned below it.
    ///
    /// Restores the running state it was called in. A running client keeps running across the
    /// resync. A stopped client stays stopped with its managers rebuilt against the cleared
    /// storage.
    ///
    /// The teardown and restart are done directly on the coordinator and network rather than
    /// through `stop`/`start`, and the coordinator is reset in place rather than replaced. This
    /// keeps the `running` flag set and the coordinator's event and progress senders alive, so
    /// the `run` monitoring loop and every progress and event subscriber stay connected across
    /// the resync instead of tearing down. Flipping `running` would make `run` exit and never
    /// come back, silently freezing all outward progress.
    pub async fn force_resync(&self) -> Result<()> {
        let was_running = self.is_running();

        // Tear down the running sync without touching `running`, so the `run` loop keeps
        // monitoring. Drain the coordinator's manager tasks and drop the network connection.
        if was_running {
            self.sync_coordinator.lock().await.shutdown().await.map_err(SpvError::Sync)?;
            self.network.lock().await.disconnect().await?;
        }

        // Masternode lists are chain-derived and wiped below, so reset the shared engine so it
        // doesn't retain state from before the resync.
        if let Some(engine) = &self.masternode_engine {
            let network = self.config.read().await.network;
            *engine.write().await = MasternodeListEngine::default_for_network(network);
        }

        // Rebuild the managers while holding only the storage and config locks, then reset the
        // coordinator with them, so we never hold the storage lock and the coordinator lock at
        // once.
        let managers = {
            let mut storage = self.storage.lock().await;
            storage.clear().await.map_err(SpvError::Storage)?;
            let config = self.config.read().await;
            Self::build_managers(&config, &mut storage, &self.wallet, &self.masternode_engine)
                .await?
        };
        self.sync_coordinator.lock().await.reset(managers);

        if was_running {
            // Respawn the coordinator's tasks and reconnect, mirroring `start` but without
            // flipping `running`. `connect` re-arms the network for a fresh start on its own,
            // so the rebuilt managers pick up a working request path.
            let mut network = self.network.lock().await;
            self.sync_coordinator
                .lock()
                .await
                .start(&mut *network)
                .await
                .map_err(SpvError::Sync)?;
            network.connect().await?;
        }

        Ok(())
    }

    /// Resync only if a wallet now sits below the anchored header start, collapsing the
    /// `resync_needed` check and the `force_resync` action into one call. Returns whether a
    /// resync actually ran, so a caller that just added wallets can do the whole "rescan the
    /// older history if I need to" step without polling `resync_needed` itself.
    pub async fn resync_if_needed(&self) -> Result<bool> {
        if self.resync_needed().await {
            self.force_resync().await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Start the SPV client: spawn sync tasks and connect to the network.
    pub(super) async fn start(&self) -> Result<()> {
        if self.is_running() {
            return Err(SpvError::Config("Client already running".to_string()));
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

        // Only mark as running after all startup operations succeed.
        // `send_replace` always stores the value regardless of receiver count,
        // so this is correct even when `run()` has not subscribed yet.
        self.running.send_replace(true);

        Ok(())
    }

    /// Stop the SPV client.
    pub async fn stop(&self) -> Result<()> {
        // Check if already stopped
        if !*self.running.borrow() {
            return Ok(());
        }

        // Flip the running state before tearing anything down so a concurrent
        // `run()` loop wakes immediately and breaks out before it can lock the
        // sync coordinator again. This prevents a tick from racing against the
        // shutdown below.
        self.running.send_replace(false);

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

        Ok(())
    }

    /// Shutdown the SPV client (alias for stop).
    pub async fn shutdown(&self) -> Result<()> {
        self.stop().await
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
            let checkpoint_manager = config.checkpoint_manager();

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
