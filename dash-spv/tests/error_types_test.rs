//! Unit tests for error types, conversions, and formatting
//!
//! This test suite focuses on:
//! - Error type conversions and From implementations
//! - Error message formatting and context preservation
//! - Error category classification
//! - Nested error handling

use dashcore::{OutPoint, Txid};
use dashcore_hashes::Hash;
use std::io;

use dash_spv::error::*;

#[test]
fn test_network_error_from_io_error() {
    let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "Connection refused");
    let net_err: NetworkError = io_err.into();

    match net_err {
        NetworkError::Io(_) => {
            assert!(net_err.to_string().contains("Connection refused"));
        }
        _ => panic!("Expected NetworkError::Io variant"),
    }
}

#[test]
fn test_storage_error_from_io_error() {
    let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "Permission denied");
    let storage_err: StorageError = io_err.into();

    match storage_err {
        StorageError::Io(_) => {
            assert!(storage_err.to_string().contains("Permission denied"));
        }
        _ => panic!("Expected StorageError::Io variant"),
    }
}

#[test]
fn test_spv_error_from_network_error() {
    let net_err = NetworkError::Timeout;
    let spv_err: SpvError = net_err.into();

    match spv_err {
        SpvError::Network(NetworkError::Timeout) => {
            assert_eq!(spv_err.to_string(), "Network error: Timeout occurred");
        }
        _ => panic!("Expected SpvError::Network variant"),
    }
}

#[test]
fn test_spv_error_from_storage_error() {
    let storage_err = StorageError::Corruption("Header checksum mismatch".to_string());
    let spv_err: SpvError = storage_err.into();

    match &spv_err {
        SpvError::Storage(StorageError::Corruption(msg)) => {
            assert_eq!(msg, "Header checksum mismatch");
            assert!(spv_err.to_string().contains("Header checksum mismatch"));
        }
        _ => panic!("Expected SpvError::Storage variant"),
    }
}

#[test]
fn test_spv_error_from_validation_error() {
    let val_err = ValidationError::InvalidProofOfWork;
    let spv_err: SpvError = val_err.into();

    match spv_err {
        SpvError::Validation(ValidationError::InvalidProofOfWork) => {
            assert_eq!(spv_err.to_string(), "Validation error: Invalid proof of work");
        }
        _ => panic!("Expected SpvError::Validation variant"),
    }
}

#[test]
fn test_spv_error_from_sync_error() {
    let sync_err = SyncError::SyncInProgress;
    let spv_err: SpvError = sync_err.into();

    match spv_err {
        SpvError::Sync(SyncError::SyncInProgress) => {
            assert_eq!(spv_err.to_string(), "Sync error: Sync already in progress");
        }
        _ => panic!("Expected SpvError::Sync variant"),
    }
}

#[test]
fn test_spv_error_from_io_error() {
    let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "Unexpected end of file");
    let spv_err: SpvError = io_err.into();

    match spv_err {
        SpvError::Io(_) => {
            assert!(spv_err.to_string().contains("Unexpected end of file"));
        }
        _ => panic!("Expected SpvError::Io variant"),
    }
}

#[test]
fn test_validation_error_from_storage_error() {
    let storage_err = StorageError::NotFound("Block header at height 12345".to_string());
    let val_err: ValidationError = storage_err.into();

    match val_err {
        ValidationError::StorageError(StorageError::NotFound(msg)) => {
            assert_eq!(msg, "Block header at height 12345");
        }
        _ => panic!("Expected ValidationError::StorageError variant"),
    }
}

#[test]
fn test_network_error_variants() {
    let errors = vec![
        (
            NetworkError::ConnectionFailed("127.0.0.1:9999 refused connection".to_string()),
            "Connection failed: 127.0.0.1:9999 refused connection",
        ),
        (
            NetworkError::HandshakeFailed("Version mismatch".to_string()),
            "Handshake failed: Version mismatch",
        ),
        (
            NetworkError::ProtocolError("Invalid message format".to_string()),
            "Protocol error: Invalid message format",
        ),
        (NetworkError::Timeout, "Timeout occurred"),
        (NetworkError::PeerDisconnected, "Peer disconnected"),
        (NetworkError::NotConnected, "Not connected"),
        (
            NetworkError::AddressParse("Invalid IP address".to_string()),
            "Address parse error: Invalid IP address",
        ),
        (
            NetworkError::SystemTime("Clock drift detected".to_string()),
            "System time error: Clock drift detected",
        ),
    ];

    for (error, expected_msg) in errors {
        assert_eq!(error.to_string(), expected_msg);
    }
}

#[test]
fn test_storage_error_variants() {
    let errors = vec![
        (
            StorageError::Corruption("Invalid segment header".to_string()),
            "Corruption detected: Invalid segment header",
        ),
        (
            StorageError::NotFound("Header at height 1000".to_string()),
            "Data not found: Header at height 1000",
        ),
        (
            StorageError::WriteFailed("/tmp/headers.dat: Permission denied".to_string()),
            "Write failed: /tmp/headers.dat: Permission denied",
        ),
        (
            StorageError::ReadFailed("Segment file truncated".to_string()),
            "Read failed: Segment file truncated",
        ),
        (
            StorageError::Serialization("Invalid encoding".to_string()),
            "Serialization error: Invalid encoding",
        ),
        (
            StorageError::InconsistentState("Height mismatch".to_string()),
            "Inconsistent state: Height mismatch",
        ),
        (
            StorageError::LockPoisoned("Mutex poisoned by panic".to_string()),
            "Lock poisoned: Mutex poisoned by panic",
        ),
    ];

    for (error, expected_msg) in errors {
        assert_eq!(error.to_string(), expected_msg);
    }
}

#[test]
fn test_validation_error_variants() {
    let errors = vec![
        (ValidationError::InvalidProofOfWork, "Invalid proof of work"),
        (
            ValidationError::InvalidHeaderChain("Height 5000: timestamp regression".to_string()),
            "Invalid header chain: Height 5000: timestamp regression",
        ),
        (
            ValidationError::InvalidChainLock("Signature verification failed".to_string()),
            "Invalid ChainLock: Signature verification failed",
        ),
        (
            ValidationError::InvalidInstantLock("Quorum not found".to_string()),
            "Invalid InstantLock: Quorum not found",
        ),
        (
            ValidationError::InvalidFilterHeaderChain("Hash mismatch at height 3000".to_string()),
            "Invalid filter header chain: Hash mismatch at height 3000",
        ),
        (
            ValidationError::Consensus("Block size exceeds limit".to_string()),
            "Consensus error: Block size exceeds limit",
        ),
        (
            ValidationError::MasternodeVerification("Invalid ProRegTx".to_string()),
            "Masternode verification failed: Invalid ProRegTx",
        ),
    ];

    for (error, expected_msg) in errors {
        assert_eq!(error.to_string(), expected_msg);
    }
}

#[test]
fn test_sync_error_variants_and_categories() {
    let test_cases = vec![
        (SyncError::SyncInProgress, "state", "Sync already in progress"),
        (
            SyncError::InvalidState("Unexpected phase transition".to_string()),
            "state",
            "Invalid sync state: Unexpected phase transition",
        ),
        (
            SyncError::MissingDependency("Previous block not found".to_string()),
            "dependency",
            "Missing dependency: Previous block not found",
        ),
        (
            SyncError::Timeout("Peer response timeout".to_string()),
            "timeout",
            "Timeout error: Peer response timeout",
        ),
        (
            SyncError::Network("Connection lost".to_string()),
            "network",
            "Network error: Connection lost",
        ),
        (
            SyncError::Validation("Invalid block header".to_string()),
            "validation",
            "Validation error: Invalid block header",
        ),
        (
            SyncError::Storage("Database locked".to_string()),
            "storage",
            "Storage error: Database locked",
        ),
        (
            SyncError::Headers2DecompressionFailed("Invalid zstd stream".to_string()),
            "headers2",
            "Headers2 decompression failed: Invalid zstd stream",
        ),
    ];

    for (error, expected_category, expected_msg) in test_cases {
        assert_eq!(error.category(), expected_category);
        assert_eq!(error.to_string(), expected_msg);
    }
}

#[test]
fn test_wallet_error_variants() {
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([0xAB; 32]),
        vout: 5,
    };

    let errors = vec![
        (WalletError::BalanceOverflow, "Balance calculation overflow"),
        (
            WalletError::UnsupportedAddressType("P2WSH".to_string()),
            "Unsupported address type: P2WSH",
        ),
        (WalletError::InvalidScriptPubkey, "Invalid script pubkey"),
        (WalletError::NotInitialized, "Wallet not initialized"),
        (
            WalletError::TransactionValidation("Invalid signature".to_string()),
            "Transaction validation failed: Invalid signature",
        ),
        (WalletError::InvalidOutput(3), "Invalid transaction output at index 3"),
        (
            WalletError::AddressError("Invalid network byte".to_string()),
            "Address error: Invalid network byte",
        ),
        (
            WalletError::ScriptError("Script execution failed".to_string()),
            "Script error: Script execution failed",
        ),
    ];

    for (error, expected_msg) in errors {
        assert_eq!(error.to_string(), expected_msg);
    }

    // Special case for UTXO not found (contains hex)
    let utxo_error = WalletError::UtxoNotFound(outpoint);
    assert!(utxo_error.to_string().contains("UTXO not found"));
    assert!(utxo_error.to_string().contains("abab")); // Partial hex from txid
}

#[test]
fn test_parse_error_variants() {
    let errors = vec![
        (ParseError::InvalidAddress("xyz123".to_string()), "Invalid network address: xyz123"),
        (ParseError::InvalidNetwork("mainnet2".to_string()), "Invalid network name: mainnet2"),
        (
            ParseError::MissingArgument("--storage-path".to_string()),
            "Missing required argument: --storage-path",
        ),
        (
            ParseError::InvalidArgument("port".to_string(), "abc".to_string()),
            "Invalid argument value for port: abc",
        ),
    ];

    for (error, expected_msg) in errors {
        assert_eq!(error.to_string(), expected_msg);
    }
}

#[test]
fn test_error_context_preservation() {
    // Create a chain of errors to test context preservation
    let io_err = io::Error::other("Disk failure");
    let storage_err: StorageError = io_err.into();
    let val_err: ValidationError = storage_err.into();
    let spv_err: SpvError = val_err.into();

    // The final error should still contain the original context
    let error_string = spv_err.to_string();
    assert!(error_string.contains("Validation error"));
    assert!(error_string.contains("Storage error"));
    assert!(error_string.contains("Disk failure"));
}

#[test]
fn test_result_type_aliases() {
    // Test that type aliases work correctly
    fn network_operation() -> NetworkResult<u32> {
        Err(NetworkError::Timeout)
    }

    fn storage_operation() -> StorageResult<String> {
        Err(StorageError::NotFound("test".to_string()))
    }

    fn validation_operation() -> ValidationResult<bool> {
        Err(ValidationError::InvalidProofOfWork)
    }

    fn sync_operation() -> SyncResult<()> {
        Err(SyncError::SyncInProgress)
    }

    fn wallet_operation() -> WalletResult<u64> {
        Err(WalletError::BalanceOverflow)
    }

    assert!(network_operation().is_err());
    assert!(storage_operation().is_err());
    assert!(validation_operation().is_err());
    assert!(sync_operation().is_err());
    assert!(wallet_operation().is_err());
}

#[test]
#[ignore]
fn test_error_display_formatting() {
    // Test that errors format nicely for user display
    let errors: Vec<Box<dyn std::error::Error>> = vec![
        Box::new(NetworkError::ConnectionFailed(
            "peer1.example.com:9999 - Connection timed out after 30s".to_string(),
        )),
        Box::new(StorageError::WriteFailed(
            "Cannot write to /var/lib/dash-spv/headers.dat: No space left on device (28)"
                .to_string(),
        )),
        Box::new(ValidationError::InvalidHeaderChain(
            "Block 523412: Previous block hash mismatch. Expected: 0x1234..., Got: 0x5678..."
                .to_string(),
        )),
        Box::new(SyncError::Timeout(
            "No response from peer after 60 seconds during header download".to_string(),
        )),
        Box::new(WalletError::TransactionValidation(
            "Transaction abc123... has invalid signature in input 0".to_string(),
        )),
    ];

    for error in errors {
        let formatted = format!("{}", error);
        assert!(!formatted.is_empty());
        assert!(formatted.len() > 10); // Should have meaningful content

        // Test that error chain formatting works
        let debug_formatted = format!("{:?}", error);
        assert!(debug_formatted.len() > formatted.len()); // Debug format should be more verbose
    }
}

#[test]
fn test_sync_error_deprecated_variant() {
    // Test that deprecated SyncFailed variant still works but is marked deprecated
    #[allow(deprecated)]
    let error = SyncError::SyncFailed("This should not be used".to_string());

    assert_eq!(error.category(), "unknown");
    assert!(error.to_string().contains("This should not be used"));
}

#[test]
fn test_error_source_chain() {
    // Test std::error::Error source() implementation
    let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "Access denied");
    let storage_err = StorageError::Io(io_err);
    let spv_err = SpvError::Storage(storage_err);

    // Should be able to walk the error chain
    let mut error_messages = vec![];
    let mut current_error: &dyn std::error::Error = &spv_err;

    loop {
        error_messages.push(current_error.to_string());
        match current_error.source() {
            Some(source) => current_error = source,
            None => break,
        }
    }

    assert!(error_messages.len() >= 2);
    assert!(error_messages[0].contains("Storage error"));
    assert!(error_messages.iter().any(|m| m.contains("Access denied")));
}
