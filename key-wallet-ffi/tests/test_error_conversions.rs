//! Tests for error conversions between different crates

use key_wallet_ffi::error::{FFIError, FFIErrorCode};

#[test]
fn test_key_wallet_error_to_ffi_error() {
    use key_wallet::Error as KeyWalletError;

    // Test InvalidMnemonic conversion
    let err = KeyWalletError::InvalidMnemonic("bad mnemonic".to_string());
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::InvalidMnemonic);

    // Test InvalidNetwork conversion
    let err = KeyWalletError::InvalidNetwork;
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::InvalidNetwork);

    // Test InvalidAddress conversion
    let err = KeyWalletError::InvalidAddress("bad address".to_string());
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::InvalidAddress);

    // Test InvalidDerivationPath conversion
    let err = KeyWalletError::InvalidDerivationPath("bad path".to_string());
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::InvalidDerivationPath);

    // Test InvalidParameter conversion
    let err = KeyWalletError::InvalidParameter("bad param".to_string());
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::InvalidInput);

    // Test Serialization conversion
    let err = KeyWalletError::Serialization("serialization failed".to_string());
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::SerializationError);

    // Test WatchOnly conversion
    let err = KeyWalletError::WatchOnly;
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::InvalidState);

    // Test CoinJoinNotEnabled conversion
    let err = KeyWalletError::CoinJoinNotEnabled;
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::InvalidState);

    // Test KeyError conversion (should map to WalletError)
    let err = KeyWalletError::KeyError("key error".to_string());
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::WalletError);

    // Test Base58 conversion (should map to WalletError)
    let err = KeyWalletError::Base58;
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::WalletError);
}

#[test]
fn test_wallet_manager_error_to_ffi_error() {
    use key_wallet_manager::wallet_manager::WalletError;

    // Test WalletNotFound conversion
    let wallet_id = [0u8; 32];
    let err = WalletError::WalletNotFound(wallet_id);
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::NotFound);

    // Test InvalidMnemonic conversion
    let err = WalletError::InvalidMnemonic("bad mnemonic".to_string());
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::InvalidMnemonic);

    // Test InvalidNetwork conversion
    let err = WalletError::InvalidNetwork;
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::InvalidNetwork);

    // Test AccountNotFound conversion
    let err = WalletError::AccountNotFound(0);
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::NotFound);

    // Test AddressGeneration conversion
    let err = WalletError::AddressGeneration("failed to generate".to_string());
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::InvalidAddress);

    // Test InvalidParameter conversion
    let err = WalletError::InvalidParameter("bad param".to_string());
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::InvalidInput);

    // Test TransactionBuild conversion
    let err = WalletError::TransactionBuild("tx build failed".to_string());
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::InvalidTransaction);

    // Test InsufficientFunds conversion
    let err = WalletError::InsufficientFunds;
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::InvalidState);

    // Test WalletCreation conversion
    let err = WalletError::WalletCreation("creation failed".to_string());
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::WalletError);

    // Test WalletExists conversion
    let err = WalletError::WalletExists(wallet_id);
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::InvalidState);

    // Test AccountCreation conversion
    let err = WalletError::AccountCreation("account creation failed".to_string());
    let ffi_err: FFIError = err.into();
    assert_eq!(ffi_err.code, FFIErrorCode::WalletError);
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
    // Note: We can't easily check the message in FFIError since it's a raw pointer
    // but we know it should contain the original message
    assert_eq!(ffi_err.code, FFIErrorCode::InvalidMnemonic);
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
