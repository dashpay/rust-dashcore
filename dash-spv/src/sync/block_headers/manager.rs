//! Headers manager for parallel sync.
//!
//! Downloads and validates block headers from peers. Handles both initial sync
//! and post-sync header updates. Emits BlockHeadersStored events for other managers.
//!
//! Uses HeadersPipeline for parallel downloads across checkpoint-defined segments
//! during initial sync. The same pipeline is reused for post-sync updates.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::chain::CheckpointManager;
use crate::error::{SyncError, SyncResult};
use crate::network::RequestSender;
use crate::storage::{BlockHeaderStorage, BlockHeaderTip};
use crate::sync::block_headers::HeadersPipeline;
use crate::sync::{BlockHeadersProgress, SyncEvent, SyncManager, SyncState};
use crate::types::HashedBlockHeader;
use crate::validation::{BlockHeaderValidator, Validator};
use dashcore::block::Header;
use dashcore::network::message_blockdata::Inventory;
use dashcore::BlockHash;
use tokio::sync::RwLock;

/// Headers manager for downloading and validating block headers.
///
/// This manager handles:
/// - Initial header sync using parallel pipeline (checkpoint-based segments)
/// - Post-sync header updates via inventory announcements
///
/// Generic over `H: BlockHeaderStorage` to allow different storage implementations.
pub struct BlockHeadersManager<H: BlockHeaderStorage> {
    /// Current progress of the manager.
    pub(super) progress: BlockHeadersProgress,
    /// Block header storage.
    pub(super) header_storage: Arc<RwLock<H>>,
    /// Pipeline for parallel header downloads (used for both initial sync and post-sync).
    pub(super) pipeline: HeadersPipeline,
    /// Pending block announcements waiting for headers message (post-sync).
    pub(super) pending_announcements: HashMap<BlockHash, Instant>,
}

impl<H: BlockHeaderStorage> std::fmt::Debug for BlockHeadersManager<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockHeadersManager")
            .field("progress", &self.progress)
            .field("pipeline", &self.pipeline)
            .finish_non_exhaustive()
    }
}

impl<H: BlockHeaderStorage> BlockHeadersManager<H> {
    /// Create a new headers manager with the given storage and checkpoint manager.
    pub fn new(header_storage: Arc<RwLock<H>>, checkpoint_manager: Arc<CheckpointManager>) -> Self {
        Self {
            progress: BlockHeadersProgress::default(),
            header_storage,
            pipeline: HeadersPipeline::new(checkpoint_manager.clone()),
            pending_announcements: HashMap::new(),
        }
    }

    pub(super) async fn tip(&self) -> SyncResult<BlockHeaderTip> {
        self.header_storage
            .read()
            .await
            .get_tip()
            .await
            .ok_or_else(|| SyncError::MissingDependency("storage not initialized".to_string()))
    }

    /// Validate and store headers batch.
    async fn store_headers(&mut self, headers: &[HashedBlockHeader]) -> SyncResult<BlockHeaderTip> {
        debug_assert!(!headers.is_empty());

        // Validate batch for internal continuity and PoW
        BlockHeaderValidator::new().validate(headers)?;

        // Store headers
        self.header_storage.write().await.store_hashed_headers(headers).await?;

        let tip = self.tip().await?;

        // Update state
        self.progress.update_current_height(tip.height());
        self.progress.add_processed(headers.len() as u32);

        Ok(tip)
    }

    /// Handle incoming headers message (used for both initial sync and post-sync).
    pub(super) async fn handle_headers_pipeline(
        &mut self,
        headers: &[Header],
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        if !self.pipeline.is_initialized() {
            // Pipeline not initialized (shouldn't happen in normal flow)
            tracing::warn!("Received headers but pipeline not initialized");
            return Ok(vec![]);
        }

        let was_syncing = self.state() == SyncState::Syncing;

        // Route headers to the pipeline
        let matched = self.pipeline.receive_headers(headers);

        if matched.is_none() && !headers.is_empty() {
            tracing::debug!(
                "Headers not matched by pipeline (prev_hash: {}), may be post-sync update",
                headers[0].prev_blockhash
            );
        }

        // Send more requests if capacity available
        let sent = self.pipeline.send_pending(requests)?;
        if sent > 0 {
            tracing::debug!("Pipeline sent {} more requests", sent);
        }

        // Process ready-to-store segments
        let mut events = Vec::new();
        let ready_batches = self.pipeline.take_ready_to_store();

        for (_start_height, batch_headers) in ready_batches {
            if !batch_headers.is_empty() {
                // Validate chain continuity with current tip
                let tip = self.tip().await?;
                if batch_headers[0].header().prev_blockhash != *tip.hash() {
                    return Err(SyncError::Validation(format!(
                        "Segment chain break: expected prev {}, got {}",
                        tip.hash(),
                        batch_headers[0].header().prev_blockhash
                    )));
                }

                // Clear any pending announcements for headers we're storing
                for header in &batch_headers {
                    self.pending_announcements.remove(header.hash());
                }

                let new_tip = self.store_headers(&batch_headers).await?;
                // Update target if we've exceeded it (post-sync case)
                if new_tip.height() > self.progress.target_height() {
                    self.progress.update_target_height(new_tip.height());
                }
                events.push(SyncEvent::BlockHeadersStored {
                    tip_height: new_tip.height(),
                });
            }
        }

        if was_syncing && self.pipeline.is_complete() {
            // If blocks were announced during sync, request them before finalizing the sync
            if !self.pending_announcements.is_empty() {
                tracing::info!(
                    "Pipeline complete but {} blocks announced during sync, requesting headers",
                    self.pending_announcements.len()
                );
                self.pipeline.reset_tip_segment();
                self.pipeline.send_pending(requests)?;
            } else {
                // Synced to the tip and no pending announcements, finalize and emit event
                let tip = self.tip().await?;
                self.progress.update_target_height(tip.height());
                self.progress.set_state(SyncState::Synced);
                tracing::info!("Headers sync complete at height {}", tip.height());
                events.push(SyncEvent::BlockHeaderSyncComplete {
                    tip_height: tip.height(),
                });
            }
        }

        self.progress.bump_last_activity();
        Ok(events)
    }

    /// Handle inventory announcements for new blocks.
    ///
    /// During initial sync, Dash Core sends inv (not headers2) because it doesn't
    /// think we have the parent block. We track these announcements so we can
    /// request headers after sync completes.
    ///
    /// When synced, we expect unsolicited headers2 announcements. The tick handler
    /// uses a timeout to send fallback GetHeaders if headers don't arrive.
    pub(super) async fn handle_inventory(
        &mut self,
        inv: &[Inventory],
        _requests: &RequestSender,
    ) -> SyncResult<()> {
        for inv_item in inv {
            if let Inventory::Block(block_hash) = inv_item {
                // Check if already pending
                if self.pending_announcements.contains_key(block_hash) {
                    continue;
                }

                // Check if we already have this block
                if let Ok(Some(_)) =
                    self.header_storage.read().await.get_header_height_by_hash(block_hash).await
                {
                    continue;
                }

                tracing::info!("New block announced via inv: {}", block_hash);
                self.pending_announcements.insert(*block_hash, Instant::now());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::checkpoints::testnet_checkpoints;
    use crate::network::MessageType;
    use crate::storage::{DiskStorageManager, PersistentBlockHeaderStorage};
    use crate::sync::{ManagerIdentifier, SyncManagerProgress};

    type TestBlockHeadersManager = BlockHeadersManager<PersistentBlockHeaderStorage>;

    fn create_test_checkpoint_manager() -> Arc<CheckpointManager> {
        Arc::new(CheckpointManager::new(testnet_checkpoints()))
    }

    async fn create_test_manager() -> TestBlockHeadersManager {
        let storage = DiskStorageManager::with_temp_dir().await.unwrap();
        let checkpoint_manager = create_test_checkpoint_manager();
        BlockHeadersManager::new(storage.header_storage(), checkpoint_manager)
    }

    #[tokio::test]
    async fn test_block_headers_manager_new() {
        let manager = create_test_manager().await;
        assert_eq!(manager.identifier(), ManagerIdentifier::BlockHeader);
        assert_eq!(manager.state(), SyncState::Initializing);
        assert_eq!(manager.wanted_message_types(), vec![MessageType::Headers, MessageType::Inv]);
    }

    #[tokio::test]
    async fn test_headers_manager_progress() {
        let mut manager = create_test_manager().await;
        manager.progress.update_current_height(100);
        manager.progress.update_target_height(200);
        manager.progress.add_processed(50);

        let progress = manager.progress();
        if let SyncManagerProgress::BlockHeaders(progress) = progress {
            assert_eq!(progress.state(), SyncState::Initializing);
            assert_eq!(progress.current_height(), 100);
            assert_eq!(progress.target_height(), 200);
            assert_eq!(progress.processed(), 50);
            assert!(progress.last_activity().elapsed().as_secs() < 1);
        } else {
            panic!("Expected SyncManagerProgress::BlockHeaders");
        }
    }

    #[tokio::test]
    async fn test_headers_manager_has_pipeline() {
        let manager = create_test_manager().await;
        assert!(!manager.pipeline.is_initialized());
        assert_eq!(manager.pipeline.segment_count(), 0);
    }
}
