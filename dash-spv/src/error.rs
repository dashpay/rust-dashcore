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
