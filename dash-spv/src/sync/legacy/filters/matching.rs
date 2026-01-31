//! Filter matching and block download logic.
//!
//! This module handles matching compact block filters against watched scripts/addresses
//! and coordinating block downloads for matched filters.
//!
//! ## Key Features
//!
//! - Efficient filter matching using BIP158 algorithms
//! - Block download coordination for matches

use dashcore::{
    bip158::{BlockFilterReader, Error as Bip158Error},
    network::message::NetworkMessage,
    network::message_blockdata::Inventory,
    BlockHash, ScriptBuf,
};

use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::storage::StorageManager;

impl<S: StorageManager, N: NetworkManager> super::manager::FilterSyncManager<S, N> {
    /// Check if filter matches any of the provided scripts using BIP158 GCS filter.
    #[allow(dead_code)]
    fn filter_matches_scripts(
        &self,
        filter_data: &[u8],
        block_hash: &BlockHash,
        scripts: &[ScriptBuf],
    ) -> SyncResult<bool> {
        if scripts.is_empty() {
            return Ok(false);
        }

        if filter_data.is_empty() {
            tracing::debug!("Empty filter data, no matches possible");
            return Ok(false);
        }

        // Create a BlockFilterReader with the block hash for proper key derivation
        let filter_reader = BlockFilterReader::new(block_hash);

        // Convert scripts to byte slices for matching without heap allocation
        let mut script_bytes = Vec::with_capacity(scripts.len());
        for script in scripts {
            script_bytes.push(script.as_bytes());
        }

        // tracing::debug!("Checking filter against {} watch scripts using BIP158 GCS", scripts.len());

        // Use the BIP158 filter to check if any scripts match
        let mut filter_slice = filter_data;
        match filter_reader.match_any(&mut filter_slice, script_bytes.into_iter()) {
            Ok(matches) => {
                if matches {
                    tracing::info!(
                        "BIP158 filter match found! Block {} contains watched scripts",
                        block_hash
                    );
                } else {
                    tracing::trace!("No BIP158 filter matches found for block {}", block_hash);
                }
                Ok(matches)
            }
            Err(Bip158Error::Io(e)) => {
                Err(SyncError::Storage(format!("BIP158 filter IO error: {}", e)))
            }
            Err(Bip158Error::UtxoMissing(outpoint)) => {
                Err(SyncError::Validation(format!("BIP158 filter UTXO missing: {}", outpoint)))
            }
            Err(_) => Err(SyncError::Validation("BIP158 filter error".to_string())),
        }
    }

    /// Store filter headers from a CFHeaders message.
    /// This method is used when filter headers are received outside of the normal sync process,
    pub async fn process_filter_matches_and_download(
        &mut self,
        filter_matches: Vec<crate::types::FilterMatch>,
        network: &mut N,
    ) -> SyncResult<Vec<crate::types::FilterMatch>> {
        if filter_matches.is_empty() {
            return Ok(filter_matches);
        }

        tracing::info!("Processing {} filter matches for block downloads", filter_matches.len());

        // Filter out blocks already being downloaded or queued
        let mut new_downloads = Vec::new();
        let mut inventory_items = Vec::new();

        for filter_match in filter_matches {
            // Check if already downloading or queued
            if self.downloading_blocks.contains_key(&filter_match.block_hash) {
                tracing::debug!("Block {} already being downloaded", filter_match.block_hash);
                continue;
            }

            if self.pending_block_downloads.iter().any(|m| m.block_hash == filter_match.block_hash)
            {
                tracing::debug!("Block {} already queued for download", filter_match.block_hash);
                continue;
            }

            tracing::info!(
                "📦 Queuing block download for {} at height {}",
                filter_match.block_hash,
                filter_match.height
            );

            // Add to inventory for bulk request
            inventory_items.push(Inventory::Block(filter_match.block_hash));

            // Mark as downloading and add to queue
            self.downloading_blocks.insert(filter_match.block_hash, filter_match.height);
            self.pending_block_downloads.push_back(filter_match.clone());
            new_downloads.push(filter_match);
        }

        // Send single bundled GetData request for all blocks
        if !inventory_items.is_empty() {
            tracing::info!(
                "📦 Requesting {} blocks in single GetData message",
                inventory_items.len()
            );

            let getdata = NetworkMessage::GetData(inventory_items);
            network.send_message(getdata).await.map_err(|e| {
                SyncError::Network(format!("Failed to send bundled GetData for blocks: {}", e))
            })?;

            tracing::debug!(
                "Added {} blocks to download queue (total queue size: {})",
                new_downloads.len(),
                self.pending_block_downloads.len()
            );
        }

        Ok(new_downloads)
    }

    pub async fn request_block_download(
        &mut self,
        filter_match: crate::types::FilterMatch,
        network: &mut N,
    ) -> SyncResult<()> {
        // Check if already downloading or queued
        if self.downloading_blocks.contains_key(&filter_match.block_hash) {
            tracing::debug!("Block {} already being downloaded", filter_match.block_hash);
            return Ok(());
        }

        if self.pending_block_downloads.iter().any(|m| m.block_hash == filter_match.block_hash) {
            tracing::debug!("Block {} already queued for download", filter_match.block_hash);
            return Ok(());
        }

        tracing::info!(
            "📦 Requesting block download for {} at height {}",
            filter_match.block_hash,
            filter_match.height
        );

        // Create GetData message for the block
        let inv = Inventory::Block(filter_match.block_hash);

        let getdata = vec![inv];

        // Send the request
        network
            .send_message(NetworkMessage::GetData(getdata))
            .await
            .map_err(|e| SyncError::Network(format!("Failed to send GetData for block: {}", e)))?;

        // Mark as downloading and add to queue
        self.downloading_blocks.insert(filter_match.block_hash, filter_match.height);
        let block_hash = filter_match.block_hash;
        self.pending_block_downloads.push_back(filter_match);

        tracing::debug!(
            "Added block {} to download queue (queue size: {})",
            block_hash,
            self.pending_block_downloads.len()
        );

        Ok(())
    }

    pub async fn handle_downloaded_block(
        &mut self,
        block: &dashcore::block::Block,
    ) -> SyncResult<Option<crate::types::FilterMatch>> {
        let block_hash = block.block_hash();

        // Check if this block was requested by the sync manager
        if let Some(height) = self.downloading_blocks.remove(&block_hash) {
            tracing::info!("📦 Received expected block {} at height {}", block_hash, height);

            // Find and remove from pending queue
            if let Some(pos) =
                self.pending_block_downloads.iter().position(|m| m.block_hash == block_hash)
            {
                let mut filter_match =
                    self.pending_block_downloads.remove(pos).ok_or_else(|| {
                        SyncError::InvalidState("filter match should exist at position".to_string())
                    })?;
                filter_match.block_requested = true;

                tracing::debug!(
                    "Removed block {} from download queue (remaining: {})",
                    block_hash,
                    self.pending_block_downloads.len()
                );

                return Ok(Some(filter_match));
            }
        }

        // Check if this block was requested by the filter processing thread
        {
            let mut processing_requests = self.processing_thread_requests.lock().await;
            if processing_requests.remove(&block_hash) {
                tracing::info!(
                    "📦 Received block {} requested by filter processing thread",
                    block_hash
                );

                // We don't have height information for processing thread requests,
                // so we'll need to look it up
                // Create a minimal FilterMatch to indicate this was a processing thread request
                let filter_match = crate::types::FilterMatch {
                    block_hash,
                    height: 0, // Height unknown for processing thread requests
                    block_requested: true,
                };

                return Ok(Some(filter_match));
            }
        }

        tracing::warn!("Received unexpected block: {}", block_hash);
        Ok(None)
    }
}
