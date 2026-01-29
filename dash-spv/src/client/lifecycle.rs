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
use tokio::sync::{mpsc, Mutex, RwLock};

use crate::chain::ChainLockManager;
use crate::error::{Result, SpvError};
use crate::mempool_filter::MempoolFilter;
use crate::network::NetworkManager;
use crate::storage::StorageManager;
use crate::sync::legacy::SyncManager;
use crate::types::{ChainState, MempoolState, SpvStats};
use dashcore::network::constants::NetworkExt;
use dashcore_hashes::Hash;
use key_wallet_manager::wallet_interface::WalletInterface;

use super::{ClientConfig, DashSpvClient};

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

        // Initialize state for the network
        let state = Arc::new(RwLock::new(ChainState::new()));
        let stats = Arc::new(RwLock::new(SpvStats::default()));

        // Wrap storage in Arc<Mutex>
        let storage = Arc::new(Mutex::new(storage));

        // Create sync manager
        let received_filter_heights = stats.read().await.received_filter_heights.clone();
        tracing::info!("Creating sequential sync manager");
        let sync_manager = SyncManager::new(
            &config,
            received_filter_heights,
            wallet.clone(),
            state.clone(),
            stats.clone(),
        )
        .map_err(SpvError::Sync)?;

        // Create ChainLock manager
        let chainlock_manager = Arc::new(ChainLockManager::new(true));

        // Create progress channels
        let (progress_sender, progress_receiver) = mpsc::unbounded_channel();

        // Create event channels
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        // Create mempool state
        let mempool_state = Arc::new(RwLock::new(MempoolState::default()));

        Ok(Self {
            config,
            state,
            stats,
            network,
            storage,
            wallet,
            sync_manager,
            chainlock_manager,
            running: Arc::new(RwLock::new(false)),
            #[cfg(feature = "terminal-ui")]
            terminal_ui: None,
            filter_processor: None,
            progress_sender: Some(progress_sender),
            progress_receiver: Some(progress_receiver),
            event_tx,
            event_rx: Some(event_rx),
            mempool_state,
            mempool_filter: None,
        })
    }

    /// Start the SPV client.
    pub async fn start(&mut self) -> Result<()> {
        {
            let running = self.running.read().await;
            if *running {
                return Err(SpvError::Config("Client already running".to_string()));
            }
        }

        // Load wallet data from storage
        self.load_wallet_data().await?;

        // Initialize mempool filter if mempool tracking is enabled
        if self.config.enable_mempool_tracking {
            // TODO: Get monitored addresses from wallet
            self.mempool_filter = Some(Arc::new(MempoolFilter::new(
                self.config.mempool_strategy,
                self.config.max_mempool_transactions,
                self.mempool_state.clone(),
                HashSet::new(), // Will be populated from wallet's monitored addresses
                self.config.network,
            )));

            // Load mempool state from storage if persistence is enabled
            if self.config.persist_mempool {
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

        // For sequential sync, filter processor is handled internally
        if self.config.enable_filters && self.filter_processor.is_none() {
            tracing::info!("📊 Sequential sync mode: filter processing handled internally");
        }

        // Initialize genesis block if not already present
        self.initialize_genesis_block().await?;

        // Load headers from storage if they exist
        // This ensures the ChainState has headers loaded for both checkpoint and normal sync
        let tip_height = {
            let storage = self.storage.lock().await;
            storage.get_tip_height().await.unwrap_or(0)
        };
        if tip_height > 0 {
            tracing::info!("Found {} headers in storage, loading into sync manager...", tip_height);
            let storage = self.storage.lock().await;
            self.sync_manager.load_headers_from_storage(&storage).await
        }

        // Connect to network
        self.network.connect().await?;

        {
            let mut running = self.running.write().await;
            *running = true;
        }

        // Update terminal UI after connection with initial data
        #[cfg(feature = "terminal-ui")]
        if let Some(ui) = &self.terminal_ui {
            // Get initial header count from storage
            let (header_height, filter_height) = {
                let storage = self.storage.lock().await;
                let h_height = storage.get_tip_height().await.unwrap_or(0);
                let f_height =
                    storage.get_filter_tip_height().await.map_err(SpvError::Storage)?.unwrap_or(0);
                (h_height, f_height)
            };

            let _ = ui
                .update_status(|status| {
                    status.peer_count = 1; // Connected to one peer
                    status.headers = header_height;
                    status.filter_headers = filter_height;
                })
                .await;
        }

        Ok(())
    }

    /// Stop the SPV client.
    pub async fn stop(&mut self) -> Result<()> {
        // Check if already stopped
        {
            let running = self.running.read().await;
            if !*running {
                return Ok(());
            }
        }

        // Disconnect from network
        self.network.disconnect().await?;

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
    pub async fn shutdown(&mut self) -> Result<()> {
        self.stop().await
    }

    /// Initialize genesis block or checkpoint.
    pub(super) async fn initialize_genesis_block(&mut self) -> Result<()> {
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
        if let Some(start_height) = self.config.start_from_height {
            // Get checkpoints for this network
            let checkpoints = match self.config.network {
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

                    // Initialize chain state with checkpoint
                    let mut chain_state = self.state.write().await;

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
                        // Initialize chain state from checkpoint
                        chain_state.init_from_checkpoint(checkpoint.height);

                        // Clone the chain state for storage
                        let chain_state_for_storage = (*chain_state).clone();
                        drop(chain_state);

                        // Update storage with chain state including sync_base_height
                        {
                            let mut storage = self.storage.lock().await;
                            storage
                                .store_headers_at_height(&[checkpoint_header], checkpoint.height)
                                .await?;
                            storage
                                .store_chain_state(&chain_state_for_storage)
                                .await
                                .map_err(SpvError::Storage)?;
                        }

                        // Don't store the checkpoint header itself - we'll request headers from peers
                        // starting from this checkpoint

                        tracing::info!(
                            "✅ Initialized from checkpoint at height {}, skipping {} headers",
                            checkpoint.height,
                            checkpoint.height
                        );

                        // Update the sync manager's cached flags from the checkpoint-initialized state
                        self.sync_manager.update_chain_state_cache(checkpoint.height);
                        tracing::info!(
                            "Updated sync manager with checkpoint-initialized chain state"
                        );

                        return Ok(());
                    }
                }
            }
        }

        // Get the genesis block hash for this network
        let genesis_hash = self
            .config
            .network
            .known_genesis_block_hash()
            .ok_or_else(|| SpvError::Config("No known genesis hash for network".to_string()))?;

        tracing::info!(
            "Initializing genesis block for network {:?}: {}",
            self.config.network,
            genesis_hash
        );

        let genesis_header =
            dashcore::blockdata::constants::genesis_block(self.config.network).header;

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
