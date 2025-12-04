//! Header synchronization with fork detection and reorganization handling.

mod manager;
pub mod validation;

pub use manager::{HeaderSyncManager, ReorgConfig};
pub use validation::validate_headers;
