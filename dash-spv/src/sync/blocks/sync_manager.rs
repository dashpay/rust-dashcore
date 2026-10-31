use crate::error::SyncResult;
use crate::network::{InboundMessage, MessageType, NetworkManager, RequestKey};
use crate::storage::{BlockHeaderStorage, BlockStorage};
use crate::sync::sync_manager::ensure_not_started;
use crate::sync::{
    BlocksManager, ManagerIdentifier, SyncEvent, SyncManager, SyncManagerProgress, SyncState,
};
use crate::types::HashedBlock;
use crate::validation::{BlockValidator, Validator};
use crate::SyncError;
use async_trait::async_trait;
use dashcore::network::message::NetworkMessage;
use key_wallet_manager::{FilterMatchKey, WalletId, WalletInterface};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

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

    async fn start_sync(
        &mut self,
        _network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        ensure_not_started(self.state(), self.identifier())?;
        // Check if filters already completed (event received before start_sync)
        if self.filters_sync_complete && self.pipeline.is_complete() {
            self.progress.set_state(SyncState::Synced);
            tracing::info!("BlocksManager: already synced (filters complete, no blocks needed)");
            return Ok(vec![]);
        }

        // If in-progress block work survived a disconnect, resume in Syncing so
        // `process_buffered_blocks` can transition to Synced once the pipeline
        // drains. Otherwise wait for BlocksNeeded / FiltersSyncComplete events.
        if !self.pipeline.is_complete() {
            self.set_state(SyncState::Syncing);
        } else {
            self.set_state(SyncState::WaitForEvents);
        }
        Ok(vec![])
    }

    /// Keep the whole pipeline across a disconnect: dropping it would make
    /// `FiltersManager` re-track the same blocks and leak `pending_blocks` counters.
    fn on_disconnect(&mut self) {}

    async fn handle_message(
        &mut self,
        peer: SocketAddr,
        msg: InboundMessage,
        network: &Arc<dyn NetworkManager>,
    ) -> SyncResult<Vec<SyncEvent>> {
        let NetworkMessage::Block(block) = &*msg else {
            return Ok(vec![]);
        };

        let hashed_block = HashedBlock::from(block);

        if let Err(e) = BlockValidator::new().validate(&hashed_block) {
            network.ban_peer(peer).await;
            self.pipeline.send_pending(network).await?;
            return Err(e.into());
        }

        // Check if this is a block we requested (pipeline handles buffering with height)
        if !self.pipeline.receive_block(&hashed_block) {
            tracing::debug!("Received unrequested block {}", hashed_block.hash());
            return Ok(vec![]);
        }

        network.release_request(RequestKey::Block(*hashed_block.hash())).await;

        // Look up height for storage
        let height = self
            .header_storage
            .read()
            .await
            .get_header_height_by_hash(hashed_block.hash())
            .await?
            .ok_or_else(|| {
                SyncError::InvalidState(format!(
                    "Block {} has no stored header - cannot determine height",
                    hashed_block.hash()
                ))
            })?;

        tracing::debug!("Received block {} at height {}", hashed_block.hash(), height);

        // Persist blocks to speed-up wallet rescans
        self.block_storage.write().await.store_block(height, hashed_block).await?;

        self.progress.add_downloaded(1);

        // No `send_pending` here: the wanted blocks are already declared and the
        // broker paces them out as capacity frees.
        self.process_buffered_blocks().await
    }

    async fn handle_sync_event(
        &mut self,
        event: &SyncEvent,
        network: &Arc<dyn NetworkManager>,
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

            let mut to_download: Vec<(FilterMatchKey, BTreeSet<WalletId>)> = Vec::new();

            let block_storage = self.block_storage.read().await;
            for (key, wallets) in blocks {
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
                    self.pipeline.add_from_storage(hashed_block, key.height(), wallets.clone());
                    self.progress.add_from_storage(1);
                    continue;
                }

                // Block not in storage, queue for download with height + wallets
                to_download.push((key.clone(), wallets.clone()));
            }
            drop(block_storage);

            // Queue all blocks that need downloading
            let newly_wanted = self.pipeline.queue(to_download);
            self.progress.add_requested(newly_wanted as u32);

            self.progress.set_state(SyncState::Syncing);

            if self.pipeline.has_pending_requests() {
                self.send_pending(network).await?;
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

    async fn tick(&mut self, _network: &Arc<dyn NetworkManager>) -> SyncResult<Vec<SyncEvent>> {
        self.process_buffered_blocks().await
    }

    fn progress(&self) -> SyncManagerProgress {
        SyncManagerProgress::Blocks(self.progress.clone())
    }
}
