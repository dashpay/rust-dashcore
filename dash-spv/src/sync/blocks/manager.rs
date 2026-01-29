//! Blocks manager for parallel sync.
//!
//! Downloads blocks that matched wallet filters and processes them in height order.
//! Subscribes to BlockNeeded events and emits BlockProcessed events.

use std::sync::Arc;

use tokio::sync::RwLock;

use super::pipeline::BlocksPipeline;
use crate::error::SyncResult;
use crate::network::RequestSender;
use crate::storage::{BlockHeaderStorage, BlockStorage};
use crate::sync::{BlocksProgress, SyncEvent, SyncManager, SyncState};
use key_wallet_manager::wallet_interface::WalletInterface;

/// Blocks manager for downloading and processing matching blocks.
///
/// This manager:
/// - Subscribes to BlockNeeded events from FiltersManager
/// - Downloads blocks using pipelined requests
/// - Processes blocks through wallet in height order
/// - Emits BlockProcessed events
///
/// Generic over:
/// - `H: BlockHeaderStorage` for height lookups
/// - `B: BlockStorage` for storing and loading blocks
/// - `W: WalletInterface` for wallet operations
pub struct BlocksManager<H: BlockHeaderStorage, B: BlockStorage, W: WalletInterface> {
    /// Current progress of the manager.
    pub(super) progress: BlocksProgress,
    /// Block header storage (for height lookups).
    pub(super) header_storage: Arc<RwLock<H>>,
    /// Block storage (for storing and loading blocks).
    pub(super) block_storage: Arc<RwLock<B>>,
    /// Wallet for processing blocks.
    pub(super) wallet: Arc<RwLock<W>>,
    /// Pipeline for downloading blocks (handles buffering and height ordering).
    pub(super) pipeline: BlocksPipeline,
    /// Whether FiltersSyncComplete has been received.
    pub(super) filters_sync_complete: bool,
}

impl<H: BlockHeaderStorage, B: BlockStorage, W: WalletInterface> BlocksManager<H, B, W> {
    /// Create a new blocks manager with the given storage references.
    pub fn new(
        wallet: Arc<RwLock<W>>,
        header_storage: Arc<RwLock<H>>,
        block_storage: Arc<RwLock<B>>,
    ) -> Self {
        Self {
            progress: BlocksProgress::default(),
            header_storage,
            block_storage,
            wallet,
            pipeline: BlocksPipeline::new(),
            filters_sync_complete: false,
        }
    }

    pub(super) async fn send_pending(&mut self, requests: &RequestSender) -> SyncResult<()> {
        let sent = self.pipeline.send_pending(requests).await?;
        if sent > 0 {
            self.progress.add_requested(sent as u32);
        }
        Ok(())
    }

    /// Process buffered blocks in height order.
    ///
    /// Uses the pipeline's height-ordering logic to ensure blocks are processed
    /// in the correct sequence.
    pub(super) async fn process_buffered_blocks(&mut self) -> SyncResult<Vec<SyncEvent>> {
        let mut events = Vec::new();

        // Process blocks in height order using pipeline's ordering logic
        while let Some((block, height)) = self.pipeline.take_next_ordered_block() {
            let hash = block.block_hash();

            // Process block through wallet
            let mut wallet = self.wallet.write().await;
            let result = wallet.process_block(&block, height).await;
            drop(wallet);

            let total_relevant = result.relevant_tx_count();
            if total_relevant > 0 {
                tracing::info!(
                    "Found {} relevant transactions ({} new, {} existing) {} at height {}, new addresses: {}",
                    total_relevant,
                    result.new_txids.len(),
                    result.existing_txids.len(),
                    hash,
                    height,
                    result.new_addresses.len()
                );
            }

            // Collect new addresses for gap limit rescanning
            let new_addresses: Vec<_> = result.new_addresses.into_iter().collect();
            if !new_addresses.is_empty() {
                tracing::debug!(
                    "Block {} generated {} new addresses for gap limit maintenance",
                    height,
                    new_addresses.len()
                );
            }

            self.progress.add_processed(1);
            if total_relevant > 0 {
                self.progress.add_relevant(1);
            }
            // Only count new transactions to avoid double-counting during rescans
            self.progress.add_transactions(result.new_txids.len() as u32);
            self.progress.update_last_processed(height);

            events.push(SyncEvent::BlockProcessed {
                block_hash: hash,
                height,
                new_addresses,
            });
        }

        // Check if pipeline is empty
        if self.pipeline.is_complete() && self.state() == SyncState::Syncing {
            if self.filters_sync_complete {
                // Filters are done and pipeline is empty - we're fully synced
                self.progress.set_state(SyncState::Synced);
                tracing::info!(
                    "Block sync complete, processed {} blocks",
                    self.progress.processed()
                );
            } else {
                // Pipeline empty but filters still syncing - wait for more blocks
                self.progress.set_state(SyncState::WaitForEvents);
            }
        }

        Ok(events)
    }
}

impl<H: BlockHeaderStorage, B: BlockStorage, W: WalletInterface> std::fmt::Debug
    for BlocksManager<H, B, W>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlocksManager")
            .field("progress", &self.progress)
            .field("pipeline", &self.pipeline)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{MessageType, NetworkManager};
    use crate::storage::{
        DiskStorageManager, PersistentBlockHeaderStorage, PersistentBlockStorage,
    };
    use crate::sync::{ManagerIdentifier, SyncEvent, SyncManagerProgress};
    use crate::test_utils::MockNetworkManager;
    use key_wallet_manager::test_utils::MockWallet;
    use key_wallet_manager::wallet_manager::FilterMatchKey;
    use std::collections::BTreeSet;

    type TestBlocksManager =
        BlocksManager<PersistentBlockHeaderStorage, PersistentBlockStorage, MockWallet>;
    type TestSyncManager = dyn SyncManager;

    async fn create_test_manager() -> TestBlocksManager {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        BlocksManager::new(wallet, storage.header_storage(), storage.block_storage())
    }

    #[tokio::test]
    async fn test_blocks_manager_new() {
        let manager = create_test_manager().await;
        assert_eq!(manager.identifier(), ManagerIdentifier::Block);
        assert_eq!(manager.state(), SyncState::Initializing);
        assert_eq!(manager.wanted_message_types(), vec![MessageType::Block]);
    }

    #[tokio::test]
    async fn test_blocks_manager_progress() {
        let mut manager = create_test_manager().await;
        manager.progress.update_last_processed(500);
        manager.progress.add_processed(10);

        let manager_ref: &TestSyncManager = &manager;
        let progress = manager_ref.progress();
        if let SyncManagerProgress::Blocks(blocks_progress) = progress {
            assert_eq!(blocks_progress.last_processed(), 500);
            assert_eq!(blocks_progress.processed(), 10);
        } else {
            panic!("Expected SyncManagerProgress::Blocks");
        }
    }

    #[tokio::test]
    async fn test_blocks_manager_handle_blocks_needed_event() {
        let mut manager = create_test_manager().await;
        manager.progress.set_state(SyncState::Synced);

        let network = MockNetworkManager::new();
        let requests = network.request_sender();

        let block_hash = dashcore::BlockHash::dummy(0);
        let mut blocks = BTreeSet::new();
        blocks.insert(FilterMatchKey::new(100, block_hash));
        let event = SyncEvent::BlocksNeeded {
            blocks,
        };

        let events = manager.handle_sync_event(&event, &requests).await.unwrap();

        // Should queue the block
        assert_eq!(manager.state(), SyncState::Syncing);
        assert!(events.is_empty());
    }
}
