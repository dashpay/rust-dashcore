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
use key_wallet_manager::WalletInterface;

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
    pub async fn new(
        wallet: Arc<RwLock<W>>,
        header_storage: Arc<RwLock<H>>,
        block_storage: Arc<RwLock<B>>,
    ) -> Self {
        let last_processed_height = wallet.read().await.last_processed_height();

        let mut initial_progress = BlocksProgress::default();
        initial_progress.update_last_processed(last_processed_height);

        Self {
            progress: initial_progress,
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
        while let Some((block, height, interested)) = self.pipeline.take_next_ordered_block() {
            let hash = block.block_hash();

            // Process the block only for the wallets whose filter matched it.
            // Already-synced wallets that did not match are not touched.
            let mut wallet = self.wallet.write().await;
            let result = wallet.process_block_for_wallets(&block, height, &interested).await;
            drop(wallet);

            let total_relevant = result.relevant_tx_count();
            let new_scripts_total: usize = result.new_scripts.values().map(|v| v.len()).sum();
            if total_relevant > 0 {
                tracing::info!(
                    "Found {} relevant transactions ({} new, {} existing) {} at height {}, new scripts: {}",
                    total_relevant,
                    result.new_txids.len(),
                    result.existing_txids.len(),
                    hash,
                    height,
                    new_scripts_total
                );
            }

            // Collect confirmed txids before moving new_scripts out of result
            let confirmed_txids: Vec<_> = result.relevant_txids().cloned().collect();

            // Collect new scripts for gap limit rescanning
            let new_scripts = result.new_scripts;
            if new_scripts_total > 0 {
                tracing::debug!(
                    "Block {} generated {} new scripts for gap limit maintenance across {} wallets",
                    height,
                    new_scripts_total,
                    new_scripts.len()
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
                wallets: interested,
                new_scripts,
                confirmed_txids,
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
        DiskStorageManager, PersistentBlockHeaderStorage, PersistentBlockStorage, StorageManager,
    };
    use crate::sync::{ManagerIdentifier, SyncEvent, SyncManagerProgress};
    use crate::test_utils::MockNetworkManager;
    use key_wallet_manager::test_utils::{MockWallet, MOCK_WALLET_ID};
    use key_wallet_manager::FilterMatchKey;
    use std::collections::{BTreeMap, BTreeSet};

    type TestBlocksManager =
        BlocksManager<PersistentBlockHeaderStorage, PersistentBlockStorage, MockWallet>;
    type TestSyncManager = dyn SyncManager;

    async fn create_test_manager() -> TestBlocksManager {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let wallet = Arc::new(RwLock::new(MockWallet::new()));
        BlocksManager::new(wallet, storage.block_headers(), storage.blocks()).await
    }

    #[tokio::test]
    async fn test_blocks_manager_new() {
        let manager = create_test_manager().await;
        assert_eq!(manager.identifier(), ManagerIdentifier::Block);
        assert_eq!(manager.state(), SyncState::WaitForEvents);
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
        let mut blocks = BTreeMap::new();
        blocks.insert(FilterMatchKey::new(100, block_hash), BTreeSet::from([MOCK_WALLET_ID]));
        let event = SyncEvent::BlocksNeeded {
            blocks,
        };

        let events = manager.handle_sync_event(&event, &requests).await.unwrap();

        // Should queue the block
        assert_eq!(manager.state(), SyncState::Syncing);
        assert!(events.is_empty());
    }

    /// `process_buffered_blocks` must call `process_block_for_wallets` with
    /// the exact wallet set carried in the pipeline so already-synced
    /// wallets are not touched by routing logic.
    #[tokio::test]
    async fn test_process_buffered_blocks_routes_wallet_set() {
        use dashcore::block::Header;
        use dashcore::{Block, TxMerkleNode};
        use dashcore_hashes::Hash;

        let mut manager = create_test_manager().await;
        manager.progress.set_state(SyncState::Syncing);

        let header = Header {
            version: dashcore::blockdata::block::Version::from_consensus(1),
            prev_blockhash: dashcore::BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: dashcore::CompactTarget::from_consensus(0),
            nonce: 0,
        };
        let block = Block {
            header,
            txdata: vec![],
        };
        manager.pipeline.add_from_storage(block.clone(), 100, BTreeSet::from([MOCK_WALLET_ID]));

        let events = manager.process_buffered_blocks().await.unwrap();
        assert!(matches!(events.first(), Some(SyncEvent::BlockProcessed { .. })));

        // MOCK_WALLET_ID was in the routed set, so MockWallet recorded the
        // block. (MockWallet::process_block_for_wallets returns early when
        // its id is absent.)
        let processed = manager.wallet.read().await.processed_blocks();
        let processed = processed.lock().await;
        assert_eq!(processed.len(), 1);
        assert_eq!(processed[0].1, 100);
    }

    /// A wallet that is NOT in the pipeline's interested set must not be
    /// routed the block. Two wallets are registered, but only `wallet_in`
    /// appears in the routed set; the other wallet's processed log must
    /// stay empty for that block.
    #[tokio::test]
    async fn test_process_buffered_blocks_excludes_uninterested_wallet() {
        use dashcore::block::Header;
        use dashcore::{Block, TxMerkleNode};
        use dashcore_hashes::Hash;
        use key_wallet_manager::test_utils::{MockWalletState, MultiMockWallet};
        use key_wallet_manager::WalletId;

        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let multi = MultiMockWallet::new();
        let wallet_in: WalletId = [0xAA; 32];
        let wallet_out: WalletId = [0xBB; 32];
        let multi = Arc::new(RwLock::new(multi));
        {
            let mut w = multi.write().await;
            w.insert_wallet(wallet_in, MockWalletState::default());
            w.insert_wallet(wallet_out, MockWalletState::default());
        }
        let mut manager: BlocksManager<
            PersistentBlockHeaderStorage,
            PersistentBlockStorage,
            MultiMockWallet,
        > = BlocksManager::new(multi.clone(), storage.block_headers(), storage.blocks()).await;
        manager.progress.set_state(SyncState::Syncing);

        let header = Header {
            version: dashcore::blockdata::block::Version::from_consensus(1),
            prev_blockhash: dashcore::BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: dashcore::CompactTarget::from_consensus(0),
            nonce: 0,
        };
        let block = Block {
            header,
            txdata: vec![],
        };
        // Only wallet_in is in the routed set.
        manager.pipeline.add_from_storage(block.clone(), 100, BTreeSet::from([wallet_in]));

        let _ = manager.process_buffered_blocks().await.unwrap();

        let processed = multi.read().await.processed();
        let processed = processed.lock().await;
        // Exactly one entry, for wallet_in only.
        assert_eq!(processed.len(), 1);
        assert_eq!(processed[0].0, wallet_in);
        assert_eq!(processed[0].2, 100);
        assert!(
            !processed.iter().any(|(id, _, _)| *id == wallet_out),
            "wallet_out was not in the routed set, must not be processed"
        );
    }

    /// `on_disconnect` for `BlocksManager` keeps the downloaded buffer, the
    /// per-block wallet routing, and the `filters_sync_complete` flag, and
    /// moves any in-flight `getdata`s back to pending so the next
    /// `send_pending` reissues them. Without this preservation, blocks waiting
    /// in `downloaded` for height ordering would be dropped, leaving
    /// `FiltersManager.tracker` entries that never get decremented.
    #[tokio::test]
    async fn test_on_disconnect_preserves_pipeline_work() {
        use dashcore::block::Header;
        use dashcore::{Block, TxMerkleNode};
        use dashcore_hashes::Hash;

        let mut manager = create_test_manager().await;
        manager.filters_sync_complete = true;

        let header = Header {
            version: dashcore::blockdata::block::Version::from_consensus(1),
            prev_blockhash: dashcore::BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: dashcore::CompactTarget::from_consensus(0),
            nonce: 0,
        };
        let block = Block {
            header,
            txdata: vec![],
        };

        // Already-downloaded block sitting in the pipeline.
        manager.pipeline.add_from_storage(block.clone(), 200, BTreeSet::from([MOCK_WALLET_ID]));

        manager.on_disconnect();

        assert!(!manager.pipeline.is_complete(), "downloaded buffer must survive on_disconnect");
        assert!(manager.filters_sync_complete);
    }
}
