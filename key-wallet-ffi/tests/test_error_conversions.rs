//! Tests for error conversions between different crates

use key_wallet_ffi::error::{FFIError, FFIErrorCode};

/// Helper to test an FFIError conversion and clean up the message
fn assert_ffi_error_code(mut ffi_err: FFIError, expected: FFIErrorCode) {
    assert_eq!(ffi_err.code, expected);
    unsafe { ffi_err.free_message() };
}

#[test]
fn test_key_wallet_error_to_ffi_error() {
    use key_wallet::Error as KeyWalletError;

    // Test InvalidMnemonic conversion
    let err = KeyWalletError::InvalidMnemonic("bad mnemonic".to_string());
    assert_ffi_error_code(err.into(), FFIErrorCode::InvalidMnemonic);

    // Test InvalidNetwork conversion
    let err = KeyWalletError::InvalidNetwork;
    assert_ffi_error_code(err.into(), FFIErrorCode::InvalidNetwork);

    // Test InvalidAddress conversion
    let err = KeyWalletError::InvalidAddress("bad address".to_string());
    assert_ffi_error_code(err.into(), FFIErrorCode::InvalidAddress);

    // Test InvalidDerivationPath conversion
    let err = KeyWalletError::InvalidDerivationPath("bad path".to_string());
    assert_ffi_error_code(err.into(), FFIErrorCode::InvalidDerivationPath);

    // Test InvalidParameter conversion
    let err = KeyWalletError::InvalidParameter("bad param".to_string());
    assert_ffi_error_code(err.into(), FFIErrorCode::InvalidInput);

    // Test Serialization conversion
    let err = KeyWalletError::Serialization("serialization failed".to_string());
    assert_ffi_error_code(err.into(), FFIErrorCode::SerializationError);

    // Test WatchOnly conversion
    let err = KeyWalletError::WatchOnly;
    assert_ffi_error_code(err.into(), FFIErrorCode::InvalidState);

    // Test CoinJoinNotEnabled conversion
    let err = KeyWalletError::CoinJoinNotEnabled;
    assert_ffi_error_code(err.into(), FFIErrorCode::InvalidState);

    // Test KeyError conversion (should map to WalletError)
    let err = KeyWalletError::KeyError("key error".to_string());
    assert_ffi_error_code(err.into(), FFIErrorCode::WalletError);

    // Test Base58 conversion (should map to WalletError)
    let err = KeyWalletError::Base58;
    assert_ffi_error_code(err.into(), FFIErrorCode::WalletError);
}

#[test]
fn test_wallet_manager_error_to_ffi_error() {
    use key_wallet_manager::wallet_manager::WalletError;

    // Test WalletNotFound conversion
    let wallet_id = [0u8; 32];
    let err = WalletError::WalletNotFound(wallet_id);
    assert_ffi_error_code(err.into(), FFIErrorCode::NotFound);

    // Test InvalidMnemonic conversion
    let err = WalletError::InvalidMnemonic("bad mnemonic".to_string());
    assert_ffi_error_code(err.into(), FFIErrorCode::InvalidMnemonic);

    // Test InvalidNetwork conversion
    let err = WalletError::InvalidNetwork;
    assert_ffi_error_code(err.into(), FFIErrorCode::InvalidNetwork);

    // Test AccountNotFound conversion
    let err = WalletError::AccountNotFound(0);
    assert_ffi_error_code(err.into(), FFIErrorCode::NotFound);

    // Test AddressGeneration conversion
    let err = WalletError::AddressGeneration("failed to generate".to_string());
    assert_ffi_error_code(err.into(), FFIErrorCode::InvalidAddress);

    // Test InvalidParameter conversion
    let err = WalletError::InvalidParameter("bad param".to_string());
    assert_ffi_error_code(err.into(), FFIErrorCode::InvalidInput);

    // Test TransactionBuild conversion
    let err = WalletError::TransactionBuild("tx build failed".to_string());
    assert_ffi_error_code(err.into(), FFIErrorCode::InvalidTransaction);

    // Test InsufficientFunds conversion
    let err = WalletError::InsufficientFunds;
    assert_ffi_error_code(err.into(), FFIErrorCode::InvalidState);

    // Test WalletCreation conversion
    let err = WalletError::WalletCreation("creation failed".to_string());
    assert_ffi_error_code(err.into(), FFIErrorCode::WalletError);

    // Test WalletExists conversion
    let err = WalletError::WalletExists(wallet_id);
    assert_ffi_error_code(err.into(), FFIErrorCode::InvalidState);

    // Test AccountCreation conversion
    let err = WalletError::AccountCreation("account creation failed".to_string());
    assert_ffi_error_code(err.into(), FFIErrorCode::WalletError);
}

#[test]
fn test_key_wallet_error_to_wallet_manager_error() {
    use key_wallet::Error as KeyWalletError;
    use key_wallet_manager::wallet_manager::WalletError;

    // Test InvalidMnemonic conversion
    let err = KeyWalletError::InvalidMnemonic("bad mnemonic".to_string());
    let wallet_err: WalletError = err.into();
    match wallet_err {
        WalletError::InvalidMnemonic(msg) => assert_eq!(msg, "bad mnemonic"),
        _ => panic!("Wrong error type"),
    }

    // Test InvalidNetwork conversion
    let err = KeyWalletError::InvalidNetwork;
    let wallet_err: WalletError = err.into();
    assert!(matches!(wallet_err, WalletError::InvalidNetwork));

    // Test InvalidAddress conversion
    let err = KeyWalletError::InvalidAddress("bad address".to_string());
    let wallet_err: WalletError = err.into();
    match wallet_err {
        WalletError::AddressGeneration(msg) => assert!(msg.contains("bad address")),
        _ => panic!("Wrong error type"),
    }

    // Test InvalidParameter conversion
    let err = KeyWalletError::InvalidParameter("bad param".to_string());
    let wallet_err: WalletError = err.into();
    match wallet_err {
        WalletError::InvalidParameter(msg) => assert_eq!(msg, "bad param"),
        _ => panic!("Wrong error type"),
    }

    // Test WatchOnly conversion
    let err = KeyWalletError::WatchOnly;
    let wallet_err: WalletError = err.into();
    match wallet_err {
        WalletError::InvalidParameter(msg) => assert!(msg.contains("watch-only")),
        _ => panic!("Wrong error type"),
    }

    // Test CoinJoinNotEnabled conversion
    let err = KeyWalletError::CoinJoinNotEnabled;
    let wallet_err: WalletError = err.into();
    match wallet_err {
        WalletError::InvalidParameter(msg) => assert!(msg.contains("CoinJoin")),
        _ => panic!("Wrong error type"),
    }

    // Test KeyError conversion
    let err = KeyWalletError::KeyError("key issue".to_string());
    let wallet_err: WalletError = err.into();
    match wallet_err {
        WalletError::AccountCreation(msg) => assert!(msg.contains("key issue")),
        _ => panic!("Wrong error type"),
    }

    // Test Serialization conversion
    let err = KeyWalletError::Serialization("serialize failed".to_string());
    let wallet_err: WalletError = err.into();
    match wallet_err {
        WalletError::InvalidParameter(msg) => assert!(msg.contains("serialize failed")),
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_error_message_consistency() {
    use key_wallet::Error as KeyWalletError;
    use key_wallet_manager::wallet_manager::WalletError;

    // Test that error messages are preserved through conversions
    let original_msg = "This is a test error message";
    let key_err = KeyWalletError::InvalidMnemonic(original_msg.to_string());

    // Convert to WalletError
    let wallet_err: WalletError = key_err.clone().into();
    let wallet_msg = wallet_err.to_string();
    assert!(wallet_msg.contains(original_msg));

    // Convert to FFIError
    let ffi_err: FFIError = key_err.into();
    assert_ffi_error_code(ffi_err, FFIErrorCode::InvalidMnemonic);
}

#[test]
fn test_ffi_error_success() {
    // Test creating a success FFIError
    let err = FFIError::success();
    assert_eq!(err.code, FFIErrorCode::Success);
    assert!(err.message.is_null());
}

#[test]
fn test_ffi_error_with_message() {
    // Test creating an error with a message
    let err = FFIError::error(FFIErrorCode::InvalidInput, "Test error".to_string());
    assert_eq!(err.code, FFIErrorCode::InvalidInput);
    assert!(!err.message.is_null());

    // Clean up the allocated message
    unsafe {
        if !err.message.is_null() {
            let _ = std::ffi::CString::from_raw(err.message);
        }
    }
}
