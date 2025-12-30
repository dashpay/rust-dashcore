//! Types and constants for filter synchronization.

use dashcore::network::message_filter::CFHeaders;
use dashcore::BlockHash;
use std::time::Instant;
use tokio::sync::mpsc;

// ============================================================================
// Constants
// ============================================================================

/// Maximum size of a single CFHeaders request batch.
/// Stay under Dash Core's 2000 limit. Using 1999 helps reduce accidental overlaps.
pub const FILTER_BATCH_SIZE: u32 = 1999;

/// Timeout for overall filter sync operations (seconds).
pub const SYNC_TIMEOUT_SECONDS: u64 = 5;

/// Default range for filter synchronization.
pub const DEFAULT_FILTER_SYNC_RANGE: u32 = 100;

/// Batch size for compact filter requests (CFilters).
pub const FILTER_REQUEST_BATCH_SIZE: u32 = 1000;

/// Maximum concurrent filter batches allowed.
pub const MAX_CONCURRENT_FILTER_REQUESTS: usize = 50;

/// Delay before retrying filter requests (milliseconds).
pub const FILTER_RETRY_DELAY_MS: u64 = 100;

/// Timeout for individual filter requests (seconds).
pub const REQUEST_TIMEOUT_SECONDS: u64 = 30;

// ============================================================================
// Type Aliases
// ============================================================================

/// Handle for sending CFilter messages to the processing thread.
pub type FilterNotificationSender =
    mpsc::UnboundedSender<dashcore::network::message_filter::CFilter>;

// ============================================================================
// Request Types
// ============================================================================

/// Represents a filter request to be sent or queued.
#[derive(Debug, Clone)]
pub struct FilterRequest {
    pub start_height: u32,
    pub end_height: u32,
    pub stop_hash: BlockHash,
    pub is_retry: bool,
}

/// Represents an active filter request that has been sent and is awaiting response.
#[derive(Debug)]
pub struct ActiveRequest {
    pub sent_time: Instant,
}

/// Represents a CFHeaders request to be sent or queued.
#[derive(Debug, Clone)]
pub struct CFHeaderRequest {
    pub start_height: u32,
    pub stop_hash: BlockHash,
    #[allow(dead_code)]
    pub is_retry: bool,
}

/// Represents an active CFHeaders request that has been sent and is awaiting response.
#[derive(Debug)]
pub struct ActiveCFHeaderRequest {
    pub sent_time: Instant,
    pub stop_hash: BlockHash,
}

/// Represents a received CFHeaders batch waiting for sequential processing.
#[derive(Debug)]
pub struct ReceivedCFHeaderBatch {
    pub cfheaders: CFHeaders,
    #[allow(dead_code)]
    pub received_at: Instant,
}
