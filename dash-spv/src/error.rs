//! Error types for the Dash SPV client.

use std::io;
use thiserror::Error;

/// Main error type for the Dash SPV client.
#[derive(Debug, Error)]
pub enum SpvError {
    #[error("Channel failure for: {0} - Failure: {1}")]
    ChannelFailure(String, String),

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

    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),

    #[error("Logging error: {0}")]
    Logging(#[from] LoggingError),

    #[error("Wallet error: {0}")]
    Wallet(#[from] WalletError),

    #[error("Quorum lookup error: {0}")]
    QuorumLookupError(String),
}

/// Parse-related errors.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Invalid network address: {0}")]
    InvalidAddress(String),

    #[error("Invalid network name: {0}")]
    InvalidNetwork(String),

    #[error("Missing required argument: {0}")]
    MissingArgument(String),

    #[error("Invalid argument value for {0}: {1}")]
    InvalidArgument(String, String),
}

/// Logging-related errors.
#[derive(Debug, Error)]
pub enum LoggingError {
    #[error("Failed to create log directory: {0}")]
    DirectoryCreation(#[from] std::io::Error),

    #[error("Subscriber initialization failed: {0}")]
    SubscriberInit(String),

    #[error("Log rotation failed: {0}")]
    RotationFailed(String),
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

    #[error("Not connected")]
    NotConnected,

    #[error("Message serialization error: {0}")]
    Serialization(#[from] dashcore::consensus::encode::Error),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Address parse error: {0}")]
    AddressParse(String),

    #[error("System time error: {0}")]
    SystemTime(String),
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

    #[error("Data directory locked: {0}")]
    DirectoryLocked(String),
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

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

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
    /// Indicates that a sync operation is already in progress
    #[error("Sync already in progress")]
    SyncInProgress,

    /// Deprecated: Use specific error variants instead
    #[deprecated(note = "Use Network, Storage, Validation, or Timeout variants instead")]
    #[error("Sync failed: {0}")]
    SyncFailed(String),

    /// Indicates an invalid state in the sync process (e.g., unexpected phase transitions)
    /// Use this for sync state machine errors, not validation errors
    #[error("Invalid sync state: {0}")]
    InvalidState(String),

    /// Indicates a missing dependency required for sync (e.g., missing previous block)
    #[error("Missing dependency: {0}")]
    MissingDependency(String),

    // Explicit error category variants
    /// Timeout errors during sync operations (e.g., peer response timeout)
    #[error("Timeout error: {0}")]
    Timeout(String),

    /// Network-related errors (e.g., connection failures, protocol errors)
    #[error("Network error: {0}")]
    Network(String),

    /// Validation errors for data received during sync (e.g., invalid headers, invalid proofs)
    /// Use this for data validation errors, not state errors
    #[error("Validation error: {0}")]
    Validation(String),

    /// Storage-related errors (e.g., database failures)
    #[error("Storage error: {0}")]
    Storage(String),

    /// Headers2 decompression failed - can trigger fallback to regular headers
    #[error("Headers2 decompression failed: {0}")]
    Headers2DecompressionFailed(String),
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

/// Type alias for logging operation results.
pub type LoggingResult<T> = std::result::Result<T, LoggingError>;

/// Wallet-related errors.
#[derive(Debug, Error)]
pub enum WalletError {
    #[error("Balance calculation overflow")]
    BalanceOverflow,

    #[error("Unsupported address type: {0}")]
    UnsupportedAddressType(String),

    #[error("UTXO not found: {0}")]
    UtxoNotFound(dashcore::OutPoint),

    #[error("Invalid script pubkey")]
    InvalidScriptPubkey,

    #[error("Wallet not initialized")]
    NotInitialized,

    #[error("Transaction validation failed: {0}")]
    TransactionValidation(String),

    #[error("Invalid transaction output at index {0}")]
    InvalidOutput(usize),

    #[error("Address error: {0}")]
    AddressError(String),

    #[error("Script error: {0}")]
    ScriptError(String),
}

/// Type alias for wallet operation results.
pub type WalletResult<T> = std::result::Result<T, WalletError>;
