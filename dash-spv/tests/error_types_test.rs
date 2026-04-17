//! Unit tests for error types, conversions, and formatting
//!
//! This test suite focuses on:
//! - Error type conversions and From implementations
//! - Error message formatting and context preservation
//! - Error category classification
//! - Nested error handling

use std::io;

use dash_spv::error::*;
use dash_spv::sync::ManagerIdentifier;

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
fn test_spv_error_from_sync_error() {
    let sync_err = SyncError::SyncInProgress(ManagerIdentifier::BlockHeader);
    let spv_err: SpvError = sync_err.into();

    match spv_err {
        SpvError::Sync(SyncError::SyncInProgress(_)) => {
            assert_eq!(spv_err.to_string(), "Sync error: BlockHeader already started");
        }
        _ => panic!("Expected SpvError::Sync variant"),
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
            ValidationError::InvalidInstantLock("Quorum not found".to_string()),
            "Invalid InstantLock: Quorum not found",
        ),
        (
            ValidationError::InvalidFilterHeaderChain("Hash mismatch at height 3000".to_string()),
            "Invalid filter header chain: Hash mismatch at height 3000",
        ),
    ];

    for (error, expected_msg) in errors {
        assert_eq!(error.to_string(), expected_msg);
    }
}

#[test]
fn test_sync_error_variants_and_categories() {
    let test_cases = vec![
        (SyncError::SyncInProgress(ManagerIdentifier::BlockHeader), "BlockHeader already started"),
        (
            SyncError::InvalidState("Unexpected phase transition".to_string()),
            "Invalid sync state: Unexpected phase transition",
        ),
        (
            SyncError::MissingDependency("Previous block not found".to_string()),
            "Missing dependency: Previous block not found",
        ),
        (SyncError::Network("Connection lost".to_string()), "Network error: Connection lost"),
        (
            SyncError::Validation("Invalid block header".to_string()),
            "Validation error: Invalid block header",
        ),
    ];

    for (error, expected_msg) in test_cases {
        assert_eq!(error.to_string(), expected_msg);
    }
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
        Err(SyncError::SyncInProgress(ManagerIdentifier::BlockHeader))
    }

    assert!(network_operation().is_err());
    assert!(storage_operation().is_err());
    assert!(validation_operation().is_err());
    assert!(sync_operation().is_err());
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
