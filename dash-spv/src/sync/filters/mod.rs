//! BIP157 Compact Block Filter synchronization.
//!
//! This module was refactored from a single 4,000+ line file into organized sub-modules.
//!
//! ## Module Organization
//!
//! - `types` - Type definitions and constants
//! - `manager` - Main FilterSyncManager coordination
//! - `headers` - CFHeaders synchronization
//! - `download` - CFilter download logic
//! - `matching` - Filter matching against wallet
//! - `retry` - Retry and timeout logic
//! - `stats` - Statistics and progress tracking
//! - `requests` - Request queue management
//!
//! ## Thread Safety
//!
//! Lock acquisition order (to prevent deadlocks):
//! 1. pending_requests
//! 2. active_requests
//! 3. received_heights

pub mod download;
pub mod headers;
pub mod manager;
pub mod matching;
pub mod requests;
pub mod retry;
pub mod stats;
pub mod types;

// Re-export main types
pub use manager::FilterSyncManager;
pub use types::{
    ActiveCFHeaderRequest, ActiveRequest, CFHeaderRequest, FilterNotificationSender, FilterRequest,
    ReceivedCFHeaderBatch,
};
pub use types::{
    DEFAULT_FILTER_SYNC_RANGE, FILTER_BATCH_SIZE, FILTER_REQUEST_BATCH_SIZE, FILTER_RETRY_DELAY_MS,
    MAX_CONCURRENT_FILTER_REQUESTS, REQUEST_TIMEOUT_SECONDS, SYNC_TIMEOUT_SECONDS,
};
