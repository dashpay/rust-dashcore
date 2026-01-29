use crate::error::SyncResult;
use crate::network::{Message, MessageType, RequestSender};
use crate::storage::{BlockHeaderStorage, BlockStorage};
use crate::sync::{
    BlocksManager, ManagerIdentifier, SyncEvent, SyncManager, SyncManagerProgress, SyncState,
};
use crate::types::HashedBlock;
use crate::SyncError;
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use key_wallet_manager::wallet_interface::WalletInterface;

#[async_trait]
impl<H: BlockHeaderStorage, B: BlockStorage, W: WalletInterface + 'static> SyncManager
    for BlocksManager<H, B, W>
{
    fn identifier(&self) -> ManagerIdentifier {
        ManagerIdentifier::Block
    }

    fn state(&self) -> SyncState {
        self.progress.state()
    }

    fn set_state(&mut self, state: SyncState) {
        self.progress.set_state(state);
    }

    fn wanted_message_types(&self) -> &'static [MessageType] {
        &[MessageType::Block]
    }

    async fn initialize(&mut self) -> SyncResult<()> {
        // Get wallet state
        let wallet = self.wallet.read().await;
        let synced_height = wallet.synced_height();
        drop(wallet);

        self.progress.update_last_processed(synced_height);
        self.progress.set_state(SyncState::WaitingForConnections);

        tracing::info!("BlocksManager initialized at height {}", self.progress.last_processed());

        Ok(())
    }

    async fn start_sync(&mut self, _requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
        // Check if filters already completed (event received before start_sync)
        if self.filters_sync_complete && self.pipeline.is_complete() {
            self.progress.set_state(SyncState::Synced);
            tracing::info!("BlocksManager: already synced (filters complete, no blocks needed)");
            return Ok(vec![]);
        }

        // Otherwise wait for BlocksNeeded or FiltersSyncComplete events
        self.set_state(SyncState::WaitForEvents);
        Ok(vec![])
    }

    fn stop_sync(&mut self) {
        self.progress.set_state(SyncState::WaitingForConnections);
        self.filters_sync_complete = false;
    }

    async fn handle_message(
        &mut self,
        msg: Message,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        let NetworkMessage::Block(block) = msg.inner() else {
            return Ok(vec![]);
        };

        let hash = block.block_hash();

        // Check if this is a block we requested (pipeline handles buffering with height)
        if !self.pipeline.receive_block(block) {
            tracing::debug!("Received unrequested block {}", hash);
            return Ok(vec![]);
        }

        // Look up height for storage
        let height =
            self.header_storage.read().await.get_header_height_by_hash(&hash).await?.ok_or_else(
                || {
                    SyncError::InvalidState(format!(
                        "Block {} has no stored header - cannot determine height",
                        hash
                    ))
                },
            )?;

        tracing::debug!("Received block {} at height {}", hash, height);

        // Persist blocks to speed-up wallet rescans
        self.block_storage
            .write()
            .await
            .store_block(height, HashedBlock::new(hash, block.clone()))
            .await?;

        self.progress.add_downloaded(1);

        // Process buffered blocks
        let events = self.process_buffered_blocks().await?;

        if self.pipeline.has_pending_requests() {
            self.send_pending(requests).await?;
        }

        Ok(events)
    }

    async fn handle_sync_event(
        &mut self,
        event: &SyncEvent,
        requests: &RequestSender,
    ) -> SyncResult<Vec<SyncEvent>> {
        // React to BlocksNeeded events
        if let SyncEvent::BlocksNeeded {
            blocks,
        } = event
        {
            if blocks.is_empty() {
                return Ok(vec![]);
            }

            tracing::debug!("Blocks needed: {} blocks", blocks.len());

            let mut to_download = Vec::new();

            let block_storage = self.block_storage.read().await;
            for key in blocks {
                // Check if block is already stored (from previous sync)
                if let Ok(Some(hashed_block)) = block_storage.load_block(key.height()).await {
                    if hashed_block.hash() != key.hash() {
                        tracing::warn!(
                            "Stored block hash mismatch at height {}. expected: {}, got: {} ",
                            key.height(),
                            key.hash(),
                            hashed_block.hash(),
                        );
                        return Err(SyncError::Validation(format!(
                            "Stored block hash mismatch. expected: {:?}, got {}",
                            key,
                            hashed_block.hash()
                        )));
                    }
                    // Block loaded from storage, add to pipeline for processing
                    self.pipeline.add_from_storage(hashed_block.block().clone(), key.height());
                    self.progress.add_from_storage(1);
                    continue;
                }

                // Block not in storage, queue for download with height
                to_download.push(key.clone());
            }
            drop(block_storage);

            // Queue all blocks that need downloading
            self.pipeline.queue(to_download);

            self.progress.set_state(SyncState::Syncing);

            // Send batched request for blocks not in storage
            if self.pipeline.has_pending_requests() {
                self.send_pending(requests).await?;
            }

            // Process any blocks we loaded from storage
            return self.process_buffered_blocks().await;
        }

        // React to FiltersSyncComplete - filters are done, no more BlocksNeeded events coming
        if let SyncEvent::FiltersSyncComplete {
            ..
        } = event
        {
            self.filters_sync_complete = true;

            // If pipeline is already empty, transition to Synced now
            if self.pipeline.is_complete()
                && matches!(self.state(), SyncState::Syncing | SyncState::WaitForEvents)
            {
                self.progress.set_state(SyncState::Synced);
                tracing::info!(
                    "Block sync complete, processed {} blocks",
                    self.progress.processed()
                );
            }
        }

        Ok(vec![])
    }

    async fn tick(&mut self, requests: &RequestSender) -> SyncResult<Vec<SyncEvent>> {
        // Handle timeouts
        let timed_out = self.pipeline.handle_timeouts();
        if !timed_out.is_empty() {
            tracing::debug!("Re-queued {} timed out block downloads", timed_out.len());
        }

        self.send_pending(requests).await?;

        // Try to process any buffered blocks
        self.process_buffered_blocks().await
    }

    fn progress(&self) -> SyncManagerProgress {
        SyncManagerProgress::Blocks(self.progress.clone())
    }
}
