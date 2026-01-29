//! Headers pipeline for parallel downloads across checkpoint-defined segments.
//!
//! Uses checkpoints to create independent download segments that can be
//! downloaded in parallel from multiple peers. Each segment tracks its own
//! progress and buffers headers until ready for ordered storage.

use std::sync::Arc;

use dashcore::block::Header;
use dashcore::BlockHash;

use crate::chain::CheckpointManager;
use crate::error::SyncResult;
use crate::network::RequestSender;
use crate::sync::block_headers::segment_state::SegmentState;
use crate::types::HashedBlockHeader;

/// Pipeline for parallel header downloads across checkpoint-defined segments.
///
/// Divides the blockchain into segments based on checkpoints and downloads
/// them in parallel. Headers are buffered and stored in order to maintain
/// chain consistency.
pub struct HeadersPipeline {
    /// Download segments (ordered by height).
    segments: Vec<SegmentState>,
    /// Index of the next segment to store (all previous must be complete).
    next_to_store: usize,
    /// Checkpoint manager reference.
    checkpoint_manager: Arc<CheckpointManager>,
    /// Whether the pipeline has been initialized.
    initialized: bool,
}

impl std::fmt::Debug for HeadersPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeadersPipeline")
            .field("segments", &self.segments)
            .field("next_to_store", &self.next_to_store)
            .field("initialized", &self.initialized)
            .finish_non_exhaustive()
    }
}

impl HeadersPipeline {
    /// Create a new headers pipeline with the given checkpoint manager.
    pub fn new(checkpoint_manager: Arc<CheckpointManager>) -> Self {
        Self {
            segments: Vec::new(),
            next_to_store: 0,
            checkpoint_manager,
            initialized: false,
        }
    }

    /// Initialize the pipeline for downloading from current_height to target_height.
    pub fn init(&mut self, current_height: u32, current_hash: BlockHash, target_height: u32) {
        self.segments.clear();
        self.next_to_store = 0;
        self.initialized = true;

        // Get checkpoint heights and find which ones are relevant
        let checkpoint_heights = self.checkpoint_manager.checkpoint_heights();

        // Find checkpoints between current_height and target_height
        let mut boundaries: Vec<(u32, BlockHash)> = Vec::new();

        // Start from current position
        boundaries.push((current_height, current_hash));

        // Add checkpoints that are above current_height
        for &height in checkpoint_heights {
            if height > current_height && height <= target_height {
                if let Some(cp) = self.checkpoint_manager.get_checkpoint(height) {
                    boundaries.push((height, cp.block_hash));
                }
            }
        }

        // Sort by height
        boundaries.sort_by_key(|(h, _)| *h);

        // Create segments between consecutive boundaries
        for i in 0..boundaries.len() {
            let (start_height, start_hash) = boundaries[i];
            let (target_height, target_hash) = if i + 1 < boundaries.len() {
                let (h, hash) = boundaries[i + 1];
                (Some(h), Some(hash))
            } else {
                // Last segment goes to tip (unknown target)
                (None, None)
            };

            let segment =
                SegmentState::new(i, start_height, start_hash, target_height, target_hash);

            tracing::info!(
                "Created segment {}: {} -> {:?} (start_hash: {})",
                i,
                start_height,
                target_height,
                start_hash
            );

            self.segments.push(segment);
        }

        tracing::info!(
            "HeadersPipeline initialized with {} segments for heights {} to {}",
            self.segments.len(),
            current_height,
            target_height
        );
    }

    /// Get the number of segments in the pipeline.
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Send pending requests for active segments.
    /// Returns the number of requests sent.
    pub fn send_pending(&mut self, requests: &RequestSender) -> SyncResult<usize> {
        let mut sent = 0;
        for segment in &mut self.segments {
            // Skip completed segments
            if segment.complete {
                continue;
            }
            while segment.can_send() {
                segment.send_request(requests)?;
                sent += 1;
            }
        }
        Ok(sent)
    }

    /// Try to match incoming headers to the correct segment.
    /// Returns the segment index if matched, or None if headers don't belong to any segment.
    pub fn receive_headers(&mut self, headers: &[Header]) -> Option<usize> {
        if headers.is_empty() {
            // Empty response means the peer has no more headers after our locator.
            // Route to the tip segment (target_height is None) if it has in-flight requests.
            // Middle segments complete via checkpoint validation, not empty responses.
            for segment in &mut self.segments {
                if !segment.complete
                    && segment.target_height.is_none()
                    && segment.coordinator.active_count() > 0
                {
                    tracing::debug!(
                        "Routing empty response to tip segment {} at height {}",
                        segment.segment_id,
                        segment.current_height
                    );
                    segment.receive_headers(headers);
                    return Some(segment.segment_id);
                }
            }
            return None;
        }

        let prev_hash = headers[0].prev_blockhash;

        // Find the segment that matches
        for (idx, segment) in self.segments.iter_mut().enumerate() {
            if segment.matches(&prev_hash) {
                // If tip segment was completed but receives new headers (post-sync),
                // reset it so take_ready_to_store() can process the new headers
                if segment.complete && segment.target_height.is_none() {
                    segment.complete = false;
                    self.next_to_store = idx;
                    tracing::debug!(
                        "Tip segment {} receiving post-sync headers, reset for continued processing",
                        segment.segment_id
                    );
                }
                let _processed = segment.receive_headers(headers);
                return Some(segment.segment_id);
            }
        }

        tracing::warn!(
            "Received {} headers with prev_hash {} but no segment matched",
            headers.len(),
            prev_hash
        );
        None
    }

    /// Get segments that are ready to store (complete and in order).
    /// Returns tuples of (start_height, headers).
    pub fn take_ready_to_store(&mut self) -> Vec<(u32, Vec<HashedBlockHeader>)> {
        let mut ready = Vec::new();

        while self.next_to_store < self.segments.len() {
            // Check if segment has buffered headers
            if self.segments[self.next_to_store].buffered_headers.is_empty() {
                break;
            }

            // For non-first segments, check if previous segment completed
            if self.next_to_store > 0 {
                let prev_complete = self.segments[self.next_to_store - 1].complete;
                let prev_empty = self.segments[self.next_to_store - 1].buffered_headers.is_empty();
                if !prev_complete || !prev_empty {
                    break;
                }
            }

            let segment = &mut self.segments[self.next_to_store];
            let start_height = segment.start_height + 1; // +1 because we store headers after start
            let segment_id = segment.segment_id;
            let headers = segment.take_buffered();
            let is_complete = segment.complete;
            let is_empty = segment.buffered_headers.is_empty();

            if !headers.is_empty() {
                tracing::info!(
                    "Segment {}: {} headers ready to store from height {}",
                    segment_id,
                    headers.len(),
                    start_height
                );
                ready.push((start_height, headers));
            }

            // If this segment is complete and drained, move to next
            if is_complete && is_empty {
                self.next_to_store += 1;
            } else {
                break;
            }
        }

        ready
    }

    /// Check if all segments are complete.
    pub fn is_complete(&self) -> bool {
        self.segments.iter().all(|s| s.complete && s.buffered_headers.is_empty())
    }

    /// Get the total number of buffered headers across all segments.
    pub fn total_buffered(&self) -> u32 {
        self.segments.iter().map(|s| s.buffered_headers.len() as u32).sum()
    }

    /// Check for timeouts in all segments.
    pub fn handle_timeouts(&mut self) {
        for segment in &mut self.segments {
            segment.handle_timeouts();
        }
    }

    /// Check if pipeline is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Reset the tip segment for continued syncing after initial sync completes.
    /// This allows the pipeline to be reused for post-sync header updates.
    /// Returns true if the tip segment was reset, false if not found or not complete.
    pub fn reset_tip_segment(&mut self) -> bool {
        // Find the tip segment (target_height is None)
        for (idx, segment) in self.segments.iter_mut().enumerate() {
            if segment.target_height.is_none() && segment.complete {
                segment.complete = false;
                // Reset next_to_store so buffered headers can be processed
                self.next_to_store = idx;
                tracing::debug!(
                    "Reset tip segment {} at height {} for continued syncing",
                    segment.segment_id,
                    segment.current_height
                );
                return true;
            }
        }
        false
    }

    /// Check if the tip segment has active requests in flight.
    pub fn tip_segment_has_pending_request(&self) -> bool {
        self.segments
            .iter()
            .find(|s| s.target_height.is_none())
            .is_some_and(|s| !s.complete && s.coordinator.active_count() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::checkpoints::{mainnet_checkpoints, testnet_checkpoints};
    use tokio::sync::mpsc::unbounded_channel;

    use crate::network::{NetworkRequest, RequestSender};

    fn create_test_checkpoint_manager(is_testnet: bool) -> Arc<CheckpointManager> {
        let checkpoints = if is_testnet {
            testnet_checkpoints()
        } else {
            mainnet_checkpoints()
        };
        Arc::new(CheckpointManager::new(checkpoints))
    }

    fn create_test_request_sender(
    ) -> (RequestSender, tokio::sync::mpsc::UnboundedReceiver<NetworkRequest>) {
        let (tx, rx) = unbounded_channel();
        (RequestSender::new(tx), rx)
    }

    #[test]
    fn test_pipeline_new() {
        let cm = create_test_checkpoint_manager(true);
        let pipeline = HeadersPipeline::new(cm);

        assert!(!pipeline.is_initialized());
        assert_eq!(pipeline.segment_count(), 0);
    }

    #[test]
    fn test_pipeline_init_testnet() {
        let cm = create_test_checkpoint_manager(true);
        let mut pipeline = HeadersPipeline::new(cm.clone());

        // Get genesis hash for testnet
        let genesis = cm.get_checkpoint(0).unwrap();
        pipeline.init(0, genesis.block_hash, 1_200_000);

        assert!(pipeline.is_initialized());
        // Should have segments: 0->500k, 500k->800k, 800k->1.1M, 1.1M->tip
        assert!(pipeline.segment_count() >= 3);
    }

    #[test]
    fn test_pipeline_init_from_middle() {
        let cm = create_test_checkpoint_manager(true);
        let mut pipeline = HeadersPipeline::new(cm.clone());

        // Start from checkpoint 500k
        let cp_500k = cm.get_checkpoint(500_000).unwrap();
        pipeline.init(500_000, cp_500k.block_hash, 1_200_000);

        // Should have fewer segments since we're starting from 500k
        assert!(pipeline.is_initialized());
        // Segments: 500k->800k, 800k->1.1M, 1.1M->tip
        assert!(pipeline.segment_count() >= 2);
    }

    #[test]
    fn test_pipeline_send_pending() {
        let cm = create_test_checkpoint_manager(true);
        let mut pipeline = HeadersPipeline::new(cm.clone());

        let genesis = cm.get_checkpoint(0).unwrap();
        pipeline.init(0, genesis.block_hash, 1_200_000);

        let (sender, mut rx) = create_test_request_sender();

        let sent = pipeline.send_pending(&sender).unwrap();

        // Should send at least one request per segment
        assert!(sent >= pipeline.segment_count());

        // Verify messages were queued
        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, sent);
    }

    #[test]
    fn test_pipeline_is_complete_initially() {
        let cm = create_test_checkpoint_manager(true);
        let mut pipeline = HeadersPipeline::new(cm.clone());

        let genesis = cm.get_checkpoint(0).unwrap();
        pipeline.init(0, genesis.block_hash, 1_200_000);

        assert!(!pipeline.is_complete());
    }

    #[test]
    fn test_take_ready_to_store_empty() {
        let cm = create_test_checkpoint_manager(true);
        let mut pipeline = HeadersPipeline::new(cm.clone());

        let genesis = cm.get_checkpoint(0).unwrap();
        pipeline.init(0, genesis.block_hash, 1_200_000);

        let ready = pipeline.take_ready_to_store();
        assert!(ready.is_empty());
    }
}
