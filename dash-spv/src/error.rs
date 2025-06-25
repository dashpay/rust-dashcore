//! Error types for the Dash SPV client.

use std::io;
use thiserror::Error;

/// Main error type for the Dash SPV client.
#[derive(Debug, Error)]
pub enum SpvError {
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("Sync error: {0}")]
    Sync(#[from] SyncError),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("General error: {0}")]
    General(String),
}

/// Network-related errors.
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Timeout occurred")]
    Timeout,

    #[error("Peer disconnected")]
    PeerDisconnected,

    #[error("Message serialization error: {0}")]
    Serialization(#[from] dashcore::consensus::encode::Error),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

/// Storage-related errors.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Corruption detected: {0}")]
    Corruption(String),

    #[error("Data not found: {0}")]
    NotFound(String),

    #[error("Write failed: {0}")]
    WriteFailed(String),

    #[error("Read failed: {0}")]
    ReadFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Inconsistent state: {0}")]
    InconsistentState(String),
    
    #[error("Lock poisoned: {0}")]
    LockPoisoned(String),
}

/// Validation-related errors.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid proof of work")]
    InvalidProofOfWork,

    #[error("Invalid header chain: {0}")]
    InvalidHeaderChain(String),

    #[error("Invalid ChainLock: {0}")]
    InvalidChainLock(String),

    #[error("Invalid InstantLock: {0}")]
    InvalidInstantLock(String),

    #[error("Invalid filter header chain: {0}")]
    InvalidFilterHeaderChain(String),

    #[error("Consensus error: {0}")]
    Consensus(String),

    #[error("Masternode verification failed: {0}")]
    MasternodeVerification(String),

    #[error("Storage error: {0}")]
    StorageError(#[from] StorageError),
}

/// Synchronization-related errors.
#[derive(Debug, Error)]
pub enum SyncError {
    #[error("Sync already in progress")]
    SyncInProgress,

    #[error("Sync timeout")]
    SyncTimeout,

    #[error("Sync failed: {0}")]
    SyncFailed(String),

    #[error("Invalid sync state: {0}")]
    InvalidState(String),

    #[error("Missing dependency: {0}")]
    MissingDependency(String),
    
    // Explicit error category variants
    #[error("Timeout error: {0}")]
    Timeout(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Storage error: {0}")]
    Storage(String),
}

impl SyncError {
    /// Returns a static string representing the error category based on the variant
    pub fn category(&self) -> &'static str {
        match self {
            SyncError::SyncInProgress => "state",
            SyncError::SyncTimeout | SyncError::Timeout(_) => "timeout",
            SyncError::InvalidState(_) | SyncError::Validation(_) => "validation",
            SyncError::MissingDependency(_) => "dependency",
            SyncError::Network(_) => "network",
            SyncError::Storage(_) => "storage",
            SyncError::SyncFailed(msg) => {
                // Fallback to string matching for legacy SyncFailed errors
                if msg.contains("timeout") || msg.contains("timed out") {
                    "timeout"
                } else if msg.contains("network") || msg.contains("connection") {
                    "network"
                } else if msg.contains("validation") || msg.contains("invalid") {
                    "validation"
                } else if msg.contains("storage") || msg.contains("disk") {
                    "storage"
                } else {
                    "unknown"
                }
            }
        }
    }
}

/// Type alias for Result with SpvError.
pub type Result<T> = std::result::Result<T, SpvError>;

/// Type alias for network operation results.
pub type NetworkResult<T> = std::result::Result<T, NetworkError>;

/// Type alias for storage operation results.
pub type StorageResult<T> = std::result::Result<T, StorageError>;

/// Type alias for validation operation results.
pub type ValidationResult<T> = std::result::Result<T, ValidationError>;

/// Type alias for sync operation results.
pub type SyncResult<T> = std::result::Result<T, SyncError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_error_category() {
        // Test explicit variant categories
        assert_eq!(SyncError::Timeout("test".to_string()).category(), "timeout");
        assert_eq!(SyncError::Network("test".to_string()).category(), "network");
        assert_eq!(SyncError::Validation("test".to_string()).category(), "validation");
        assert_eq!(SyncError::Storage("test".to_string()).category(), "storage");
        
        // Test existing variant categories
        assert_eq!(SyncError::SyncInProgress.category(), "state");
        assert_eq!(SyncError::SyncTimeout.category(), "timeout");
        assert_eq!(SyncError::InvalidState("test".to_string()).category(), "validation");
        assert_eq!(SyncError::MissingDependency("test".to_string()).category(), "dependency");
        
        // Test SyncFailed fallback categorization
        assert_eq!(SyncError::SyncFailed("connection timeout".to_string()).category(), "timeout");
        assert_eq!(SyncError::SyncFailed("network error".to_string()).category(), "network");
        assert_eq!(SyncError::SyncFailed("validation failed".to_string()).category(), "validation");
        assert_eq!(SyncError::SyncFailed("disk full".to_string()).category(), "storage");
        assert_eq!(SyncError::SyncFailed("something else".to_string()).category(), "unknown");
    }
}
