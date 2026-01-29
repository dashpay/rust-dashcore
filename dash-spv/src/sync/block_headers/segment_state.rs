use crate::error::SyncResult;
use crate::network::RequestSender;
use crate::sync::download_coordinator::{DownloadConfig, DownloadCoordinator};
use crate::types::HashedBlockHeader;
use dashcore::{BlockHash, Header};
use std::time::Duration;

/// Timeout for header requests.
const HEADERS_TIMEOUT: Duration = Duration::from_secs(30);

/// State for a single download segment between two checkpoints.
#[derive(Debug)]
pub(super) struct SegmentState {
    /// Unique segment identifier (index in segments array).
    pub(super) segment_id: usize,
    /// Starting height of this segment.
    pub(super) start_height: u32,
    /// Target height (None for tip segment).
    pub(super) target_height: Option<u32>,
    /// Target hash (next checkpoint hash for validation).
    target_hash: Option<BlockHash>,
    /// Current tip hash for GetHeaders locator.
    current_tip_hash: BlockHash,
    /// Current height reached in this segment.
    pub(super) current_height: u32,
    /// Download coordinator for tracking in-flight requests.
    pub(super) coordinator: DownloadCoordinator<BlockHash>,
    /// Buffered headers waiting to be stored.
    pub(super) buffered_headers: Vec<HashedBlockHeader>,
    /// Whether this segment has completed downloading.
    pub(super) complete: bool,
}

impl SegmentState {
    /// Create a new segment state.
    pub(super) fn new(
        segment_id: usize,
        start_height: u32,
        start_hash: BlockHash,
        target_height: Option<u32>,
        target_hash: Option<BlockHash>,
    ) -> Self {
        Self {
            segment_id,
            start_height,
            target_height,
            target_hash,
            current_tip_hash: start_hash,
            current_height: start_height,
            coordinator: DownloadCoordinator::new(
                DownloadConfig::default()
                    .with_max_concurrent(1) // Only 1 request at a time (sequential getheaders)
                    .with_timeout(HEADERS_TIMEOUT)
                    .with_max_retries(3),
            ),
            buffered_headers: Vec::new(),
            complete: false,
        }
    }

    /// Check if the segment can send more requests.
    /// Only one getheaders request can be in-flight at a time (sequential protocol).
    pub(super) fn can_send(&self) -> bool {
        !self.complete && !self.coordinator.is_in_flight(&self.current_tip_hash)
    }

    /// Send a GetHeaders request for this segment.
    pub(super) fn send_request(&mut self, requests: &RequestSender) -> SyncResult<()> {
        requests.request_block_headers(self.current_tip_hash)?;
        self.coordinator.mark_sent(&[self.current_tip_hash]);
        tracing::debug!(
            "Segment {}: sent GetHeaders from height {} hash {}",
            self.segment_id,
            self.current_height,
            self.current_tip_hash
        );
        Ok(())
    }

    /// Try to match incoming headers to this segment.
    /// Returns true if the headers belong to this segment.
    pub(super) fn matches(&self, prev_blockhash: &BlockHash) -> bool {
        // Match if prev_blockhash equals our current tip hash
        &self.current_tip_hash == prev_blockhash
    }

    /// Process received headers for this segment.
    /// Returns the number of headers processed.
    pub(super) fn receive_headers(&mut self, headers: &[Header]) -> usize {
        if headers.is_empty() {
            // Empty response means we've reached the peer's tip for this segment
            self.complete = true;
            // Clear in-flight tracking for the current tip hash
            self.coordinator.receive(&self.current_tip_hash);
            tracing::info!(
                "Segment {}: complete (empty response at height {})",
                self.segment_id,
                self.current_height
            );
            return 0;
        }

        // Mark the request as received
        let prev_hash = headers[0].prev_blockhash;
        self.coordinator.receive(&prev_hash);

        // Process headers
        let mut processed = 0;
        for header in headers {
            let hashed = HashedBlockHeader::from(*header);
            let hash = *hashed.hash();
            let height = self.current_height + processed as u32 + 1;

            // Check if we've reached the target (next checkpoint)
            if let (Some(target_height), Some(target_hash)) = (self.target_height, self.target_hash)
            {
                if height == target_height {
                    if hash == target_hash {
                        tracing::info!(
                            "Segment {}: reached target checkpoint at height {}",
                            self.segment_id,
                            target_height
                        );
                        self.buffered_headers.push(hashed);
                        processed += 1;
                        self.complete = true;
                        break;
                    } else {
                        tracing::error!(
                            "Segment {}: checkpoint mismatch at height {}! expected {}, got {}",
                            self.segment_id,
                            target_height,
                            target_hash,
                            hash
                        );
                        // Continue anyway but log the error
                    }
                }
            }

            self.buffered_headers.push(hashed);
            processed += 1;
        }

        // Update current tip for next request
        if let Some(last) = headers.last() {
            self.current_tip_hash = last.block_hash();
            self.current_height += processed as u32;
        }

        tracing::debug!(
            "Segment {}: received {} headers, now at height {}, buffered {}",
            self.segment_id,
            processed,
            self.current_height,
            self.buffered_headers.len()
        );

        processed
    }

    /// Take buffered headers from this segment.
    pub(super) fn take_buffered(&mut self) -> Vec<HashedBlockHeader> {
        std::mem::take(&mut self.buffered_headers)
    }

    /// Check for timed out requests and handle retries.
    pub(super) fn handle_timeouts(&mut self) {
        let timed_out = self.coordinator.check_timeouts();
        for hash in timed_out {
            tracing::warn!(
                "Segment {}: request timed out for hash {}, will retry",
                self.segment_id,
                hash
            );
            // Re-enqueue for retry
            self.coordinator.enqueue_retry(hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sync::block_headers::segment_state::SegmentState;
    use dashcore::{BlockHash, Header};

    #[test]
    fn test_segment_state_new() {
        let hash = BlockHash::dummy(0);
        let segment = SegmentState::new(0, 0, hash, Some(500_000), None);

        assert_eq!(segment.segment_id, 0);
        assert_eq!(segment.start_height, 0);
        assert_eq!(segment.current_height, 0);
        assert!(!segment.complete);
        assert!(segment.buffered_headers.is_empty());
    }

    #[test]
    fn test_segment_can_send() {
        let hash = BlockHash::dummy(0);
        let segment = SegmentState::new(0, 0, hash, Some(1000), None);

        assert!(segment.can_send());
    }

    #[test]
    fn test_segment_matches() {
        let hash = BlockHash::dummy(0);
        let segment = SegmentState::new(0, 0, hash, Some(1000), None);

        assert!(segment.matches(&hash));
        assert!(!segment.matches(&BlockHash::dummy(1)));
    }

    #[test]
    fn test_segment_receive_empty() {
        let hash = BlockHash::dummy(1);
        let mut segment = SegmentState::new(0, 0, hash, Some(1000), None);

        let processed = segment.receive_headers(&[]);

        assert_eq!(processed, 0);
        assert!(segment.complete);
    }

    #[test]
    fn test_segment_receive_headers() {
        let hash = BlockHash::dummy(1);
        let mut segment = SegmentState::new(0, 0, hash, None, None);
        segment.coordinator.mark_sent(&[hash]);

        // Create dummy headers that chain from all-zeros
        let headers: Vec<Header> = (1..=10).map(Header::dummy).collect();

        // Manually fix the prev_blockhash of first header
        let mut first = headers[0];
        first.prev_blockhash = hash;

        let processed = segment.receive_headers(&[first]);

        assert_eq!(processed, 1);
        assert_eq!(segment.buffered_headers.len(), 1);
        assert_eq!(segment.current_height, 1);
        assert!(!segment.complete);
    }
}
