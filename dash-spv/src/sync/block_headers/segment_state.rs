use crate::error::{SyncError, SyncResult};
use crate::network::NetworkManager;
use crate::types::HashedBlockHeader;
use dashcore::network::message::NetworkMessage;
use dashcore::network::message_blockdata::GetHeadersMessage;
use dashcore::BlockHash;
use dashcore_hashes::Hash;
use std::sync::Arc;

/// State for a single download segment between two checkpoints.
///
/// The segment declares the single `getheaders` it wants (a locator from its
/// `current_tip_hash`) to the network manager, which de-duplicates, paces, times
/// out and retries it. The segment keeps no in-flight bookkeeping of its own: it
/// simply wants `current_tip_hash` for as long as it is not `complete`.
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
    pub(super) current_tip_hash: BlockHash,
    /// Current height reached in this segment.
    pub(super) current_height: u32,
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
            buffered_headers: Vec::new(),
            complete: false,
        }
    }

    /// Check if the segment still wants a `getheaders`.
    ///
    /// A segment wants its `current_tip_hash` locator declared for as long as it
    /// is not complete. The network manager de-duplicates re-declarations, so the
    /// pipeline can (re-)declare each tick without tracking what is on the wire.
    pub(super) fn can_send(&self) -> bool {
        !self.complete
    }

    /// Declare this segment's `getheaders` to the network manager.
    ///
    /// The broker de-duplicates by `RequestKey::Headers(current_tip_hash)`, paces
    /// the request across peers and retries it on timeout, so this may be a no-op
    /// if the request is already in play.
    pub(super) async fn send_request(&mut self, network: &Arc<dyn NetworkManager>) {
        network
            .send(NetworkMessage::GetHeaders(GetHeadersMessage::new(
                vec![self.current_tip_hash],
                BlockHash::all_zeros(),
            )))
            .await;
        tracing::debug!(
            "Segment {}: declared GetHeaders from height {} hash {}",
            self.segment_id,
            self.current_height,
            self.current_tip_hash
        );
    }

    /// Try to match incoming headers to this segment.
    /// Returns true if the headers belong to this segment.
    pub(super) fn matches(&self, prev_blockhash: &BlockHash) -> bool {
        // Match if prev_blockhash equals our current tip hash
        &self.current_tip_hash == prev_blockhash
    }

    /// Process received headers for this segment.
    /// Returns the number of headers processed, or an error if checkpoint validation fails.
    pub(super) fn receive_headers(&mut self, headers: &[HashedBlockHeader]) -> SyncResult<usize> {
        if headers.is_empty() {
            // Empty response means we've reached the peer's tip for this segment
            self.complete = true;
            tracing::info!(
                "Segment {}: complete (empty response at height {})",
                self.segment_id,
                self.current_height
            );
            return Ok(0);
        }

        // Reject headers on a segment that already reached its checkpoint
        if self.complete {
            return Err(SyncError::InvalidState(format!(
                "Segment {}: received {} headers on completed segment (height {})",
                self.segment_id,
                headers.len(),
                self.current_height
            )));
        }

        // Process headers
        let mut processed = 0;
        for hashed in headers {
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
                        self.buffered_headers.push(hashed.clone());
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
                        return Err(SyncError::Validation(format!(
                            "Block at height {} does not match checkpoint: expected {}, got {}",
                            target_height, target_hash, hash
                        )));
                    }
                }
            }

            self.buffered_headers.push(hashed.clone());
            processed += 1;
        }

        // Update current tip for next request
        if processed > 0 {
            self.current_tip_hash = *headers[processed - 1].hash();
            self.current_height += processed as u32;
        }

        tracing::debug!(
            "Segment {}: received {} headers, now at height {}, buffered {}",
            self.segment_id,
            processed,
            self.current_height,
            self.buffered_headers.len()
        );

        Ok(processed)
    }

    /// Take buffered headers from this segment.
    pub(super) fn take_buffered(&mut self) -> Vec<HashedBlockHeader> {
        std::mem::take(&mut self.buffered_headers)
    }
}

#[cfg(test)]
mod tests {
    use crate::error::SyncError;
    use crate::sync::block_headers::segment_state::SegmentState;
    use crate::types::HashedBlockHeader;
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

        // A fresh, incomplete segment wants its locator declared.
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

        let processed = segment.receive_headers(&[]).unwrap();

        assert_eq!(processed, 0);
        assert!(segment.complete);
        // An empty response no longer allows sending — the segment is done.
        assert!(!segment.can_send());
    }

    #[test]
    fn test_segment_receive_headers() {
        let hash = BlockHash::dummy(1);
        let mut segment = SegmentState::new(0, 0, hash, None, None);

        let first = Header::dummy_chain(1, hash).remove(0);

        let processed = segment.receive_headers(&[first.into()]).unwrap();

        assert_eq!(processed, 1);
        assert_eq!(segment.buffered_headers.len(), 1);
        assert_eq!(segment.current_height, 1);
        assert!(!segment.complete);
        // The tip advanced to the received header's hash for the next locator.
        assert_eq!(segment.current_tip_hash, first.block_hash());
    }

    #[test]
    fn test_segment_checkpoint_mismatch_returns_error() {
        let start_hash = BlockHash::dummy(0);
        // Segment with checkpoint at height 1 expecting a specific hash
        let expected_checkpoint_hash = BlockHash::dummy(99);
        let mut segment =
            SegmentState::new(0, 0, start_hash, Some(1), Some(expected_checkpoint_hash));

        // A valid header at height 1 whose hash is not the expected checkpoint.
        let header = Header::dummy_chain(1, start_hash).remove(0);

        // The header's hash won't match the expected checkpoint hash
        let hashed = HashedBlockHeader::from(header);
        let actual_hash = hashed.hash();
        assert_ne!(*actual_hash, expected_checkpoint_hash);

        // Receiving this header should fail with a validation error
        let result = segment.receive_headers(&[header.into()]);
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            SyncError::Validation(msg) => {
                assert!(msg.contains("does not match checkpoint"));
                assert!(msg.contains("height 1"));
            }
            _ => panic!("Expected SyncError::Validation, got {:?}", err),
        }

        // Segment should not be complete and no headers should be buffered
        assert!(!segment.complete);
        assert!(segment.buffered_headers.is_empty());
    }

    #[test]
    fn test_segment_checkpoint_match_completes_segment() {
        let start_hash = BlockHash::dummy(0);
        // Create a header first to get its hash for the checkpoint
        let header = Header::dummy_chain(1, start_hash).remove(0);
        let hashed = HashedBlockHeader::from(header);
        let header_hash = *hashed.hash();

        // Create segment with checkpoint matching the header's hash
        let mut segment = SegmentState::new(0, 0, start_hash, Some(1), Some(header_hash));

        // Receiving this header should succeed and complete the segment
        let result = segment.receive_headers(&[header.into()]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);

        // Segment should be complete with the header buffered
        assert!(segment.complete);
        assert_eq!(segment.buffered_headers.len(), 1);
    }

    #[test]
    fn test_completed_segment_rejects_new_headers() {
        let start_hash = BlockHash::dummy(0);
        let mut segment = SegmentState::new(0, 0, start_hash, Some(100), None);

        // Mark segment as complete (simulating checkpoint reached)
        segment.complete = true;
        segment.current_height = 100;

        // Create a header that would match
        let mut header = Header::dummy(1);
        header.prev_blockhash = start_hash;

        // Completed segment should return an invalid state error
        let result = segment.receive_headers(&[header.into()]);
        assert!(result.is_err());
        match result.unwrap_err() {
            SyncError::InvalidState(msg) => {
                assert!(msg.contains("completed segment"));
            }
            other => panic!("Expected SyncError::InvalidState, got {:?}", other),
        }
        assert!(segment.buffered_headers.is_empty());
    }
}
