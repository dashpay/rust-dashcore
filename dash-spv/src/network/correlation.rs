//! Request/response correlation for QRInfo messages.
//!
//! This module provides correlation between QRInfo requests and responses
//! to support concurrent request tracking and proper response routing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashcore::network::message_qrinfo::QRInfo;
use dashcore::BlockHash;
use dashcore_hashes::Hash;
use tokio::sync::oneshot;

/// Correlates QRInfo requests with responses for parallel processing.
pub struct QRInfoCorrelationManager {
    /// Pending requests waiting for responses.
    pending_requests: HashMap<RequestId, PendingQRInfoRequest>,
    /// Next request ID.
    next_request_id: AtomicU64,
}

impl QRInfoCorrelationManager {
    /// Create a new correlation manager.
    pub fn new() -> Self {
        Self {
            pending_requests: HashMap::new(),
            next_request_id: AtomicU64::new(1),
        }
    }

    /// Register a QRInfo request and get a channel to wait for the response.
    pub fn register_request(
        &mut self,
        base_hash: BlockHash,
        tip_hash: BlockHash,
    ) -> (RequestId, oneshot::Receiver<Result<QRInfo, CorrelationError>>) {
        let request_id = RequestId(self.next_request_id.fetch_add(1, Ordering::Relaxed));
        let (response_tx, response_rx) = oneshot::channel();

        let pending = PendingQRInfoRequest {
            base_hash,
            tip_hash,
            response_sender: response_tx,
            timestamp: Instant::now(),
        };

        self.pending_requests.insert(request_id, pending);

        tracing::debug!(
            "Registered QRInfo request {} for range {:x} to {:x}",
            request_id.0,
            base_hash,
            tip_hash
        );

        (request_id, response_rx)
    }

    /// Handle incoming QRInfo response and match it to pending request.
    pub fn handle_qr_info_response(&mut self, qr_info: QRInfo) -> Result<(), CorrelationError> {
        // Find matching request based on QRInfo content
        let matching_request_id = self.find_matching_request(&qr_info)?;

        if let Some(pending) = self.pending_requests.remove(&matching_request_id) {
            if pending.response_sender.send(Ok(qr_info)).is_err() {
                tracing::warn!(
                    "Failed to send QRInfo response for request {} - receiver dropped",
                    matching_request_id.0
                );
            } else {
                tracing::debug!(
                    "Successfully correlated QRInfo response to request {}",
                    matching_request_id.0
                );
            }

            Ok(())
        } else {
            Err(CorrelationError::RequestNotFound(matching_request_id))
        }
    }

    /// Clean up expired requests (requests that have been waiting too long).
    pub fn cleanup_expired_requests(&mut self, timeout: Duration) {
        let now = Instant::now();
        let expired_ids: Vec<RequestId> = self
            .pending_requests
            .iter()
            .filter(|(_, pending)| now.duration_since(pending.timestamp) > timeout)
            .map(|(id, _)| *id)
            .collect();

        for request_id in expired_ids {
            if let Some(pending) = self.pending_requests.remove(&request_id) {
                let _ = pending
                    .response_sender
                    .send(Err(CorrelationError::Timeout));
                tracing::warn!("Cleaned up expired QRInfo request {}", request_id.0);
            }
        }
    }

    /// Find the pending request that matches this QRInfo response.
    fn find_matching_request(&self, qr_info: &QRInfo) -> Result<RequestId, CorrelationError> {
        // Strategy: Match based on the block hashes in the QRInfo diffs
        // For now, use the last diff in the list as it should correspond to the tip
        if let Some(last_diff) = qr_info.mn_list_diff_list.last() {
            let tip_hash = last_diff.block_hash;
            
            for (request_id, pending) in &self.pending_requests {
                if pending.tip_hash == tip_hash {
                    return Ok(*request_id);
                }
            }
        }
        
        // If no matching request found, check all diffs for any matching hash
        for diff in &qr_info.mn_list_diff_list {
            for (request_id, pending) in &self.pending_requests {
                if pending.tip_hash == diff.block_hash {
                    return Ok(*request_id);
                }
            }
        }

        // Fallback: Try to match based on height ranges if we can derive them
        self.find_matching_request_by_content(qr_info)
    }

    fn find_matching_request_by_content(&self, qr_info: &QRInfo) -> Result<RequestId, CorrelationError> {
        // More sophisticated matching based on analyzing all diffs in QRInfo
        for (request_id, pending) in &self.pending_requests {
            // Check if any of the diffs in QRInfo match our expected range
            let diffs = [
                &qr_info.mn_list_diff_tip,
                &qr_info.mn_list_diff_h,
                &qr_info.mn_list_diff_at_h_minus_c,
                &qr_info.mn_list_diff_at_h_minus_2c,
                &qr_info.mn_list_diff_at_h_minus_3c,
            ];

            for diff in diffs {
                if diff.base_block_hash == pending.base_hash || diff.block_hash == pending.tip_hash {
                    return Ok(*request_id);
                }
            }

            // Check additional diffs if present
            for diff in &qr_info.mn_list_diff_list {
                if diff.base_block_hash == pending.base_hash || diff.block_hash == pending.tip_hash {
                    return Ok(*request_id);
                }
            }
        }

        Err(CorrelationError::NoMatchFound)
    }

    /// Get the number of pending requests.
    pub fn pending_count(&self) -> usize {
        self.pending_requests.len()
    }

    /// Check if a specific request ID is still pending.
    pub fn is_pending(&self, request_id: RequestId) -> bool {
        self.pending_requests.contains_key(&request_id)
    }

    /// Cancel a pending request.
    pub fn cancel_request(&mut self, request_id: RequestId) -> Result<(), CorrelationError> {
        if let Some(pending) = self.pending_requests.remove(&request_id) {
            let _ = pending
                .response_sender
                .send(Err(CorrelationError::Cancelled));
            Ok(())
        } else {
            Err(CorrelationError::RequestNotFound(request_id))
        }
    }
}

impl Default for QRInfoCorrelationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for a QRInfo request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId(pub u64);

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RequestId({})", self.0)
    }
}

#[derive(Debug)]
struct PendingQRInfoRequest {
    base_hash: BlockHash,
    tip_hash: BlockHash,
    response_sender: oneshot::Sender<Result<QRInfo, CorrelationError>>,
    timestamp: Instant,
}

/// Errors that can occur during correlation.
#[derive(Debug, thiserror::Error, Clone)]
pub enum CorrelationError {
    #[error("Request {0} not found")]
    RequestNotFound(RequestId),
    #[error("No matching request found for QRInfo response")]
    NoMatchFound,
    #[error("Request timed out")]
    Timeout,
    #[error("Request was cancelled")]
    Cancelled,
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::network::message_sml::MnListDiff;

    fn test_block_hash(height: u32) -> BlockHash {
        BlockHash::from_byte_array([height as u8; 32])
    }

    fn create_test_qr_info(base_hash: BlockHash, tip_hash: BlockHash) -> QRInfo {
        QRInfo::default()
    }

    #[tokio::test]
    async fn test_request_response_correlation() {
        let mut correlator = QRInfoCorrelationManager::new();

        let base_hash = test_block_hash(1000);
        let tip_hash = test_block_hash(1100);

        let (_request_id, response_rx) = correlator.register_request(base_hash, tip_hash);

        // Create matching QRInfo response
        let qr_info = create_test_qr_info(base_hash, tip_hash);

        // Handle the response
        let result = correlator.handle_qr_info_response(qr_info.clone());
        assert!(result.is_ok());

        // Should receive the response
        let received_qr_info = response_rx.await.unwrap().unwrap();
        assert_eq!(received_qr_info.mn_list_diff_tip.block_hash, tip_hash);
    }

    #[tokio::test]
    async fn test_multiple_concurrent_requests() {
        let mut correlator = QRInfoCorrelationManager::new();

        let mut request_receivers = Vec::new();
        let mut expected_responses = Vec::new();

        // Register multiple requests
        for i in 0..5 {
            let base_hash = test_block_hash(i * 100);
            let tip_hash = test_block_hash(i * 100 + 50);

            let (_, response_rx) = correlator.register_request(base_hash, tip_hash);
            request_receivers.push(response_rx);

            let qr_info = create_test_qr_info(base_hash, tip_hash);
            expected_responses.push(qr_info);
        }

        // Send responses in different order
        let response_order = [2, 0, 4, 1, 3];
        for &index in &response_order {
            let result = correlator.handle_qr_info_response(expected_responses[index].clone());
            assert!(result.is_ok(), "Failed to handle response {}", index);
        }

        // All requests should receive their responses
        for (i, response_rx) in request_receivers.into_iter().enumerate() {
            let received = response_rx.await.unwrap().unwrap();
            assert_eq!(
                received.mn_list_diff_tip.block_hash,
                expected_responses[i].mn_list_diff_tip.block_hash
            );
        }

        assert_eq!(correlator.pending_count(), 0);
    }

    #[tokio::test]
    async fn test_expired_request_cleanup() {
        let mut correlator = QRInfoCorrelationManager::new();

        let (_request_id, response_rx) = correlator.register_request(
            test_block_hash(1000),
            test_block_hash(1100),
        );

        assert_eq!(correlator.pending_count(), 1);

        // Clean up with very short timeout
        correlator.cleanup_expired_requests(Duration::from_millis(1));

        // Wait a bit to ensure expiration
        tokio::time::sleep(Duration::from_millis(10)).await;
        correlator.cleanup_expired_requests(Duration::from_millis(1));

        assert_eq!(correlator.pending_count(), 0);

        // Should receive timeout error
        let result = response_rx.await.unwrap();
        assert!(matches!(result, Err(CorrelationError::Timeout)));
    }

    #[tokio::test]
    async fn test_no_match_found() {
        let mut correlator = QRInfoCorrelationManager::new();

        // Register a request
        correlator.register_request(test_block_hash(1000), test_block_hash(1100));

        // Send a response that doesn't match any request
        let unmatched_qr_info = create_test_qr_info(test_block_hash(2000), test_block_hash(2100));

        let result = correlator.handle_qr_info_response(unmatched_qr_info);
        assert!(matches!(result, Err(CorrelationError::NoMatchFound)));
    }

    #[tokio::test]
    async fn test_cancel_request() {
        let mut correlator = QRInfoCorrelationManager::new();

        let (request_id, response_rx) = correlator.register_request(
            test_block_hash(1000),
            test_block_hash(1100),
        );

        // Cancel the request
        let result = correlator.cancel_request(request_id);
        assert!(result.is_ok());

        // Should receive cancelled error
        let result = response_rx.await.unwrap();
        assert!(matches!(result, Err(CorrelationError::Cancelled)));

        // Cancelling again should fail
        let result = correlator.cancel_request(request_id);
        assert!(matches!(result, Err(CorrelationError::RequestNotFound(_))));
    }
}