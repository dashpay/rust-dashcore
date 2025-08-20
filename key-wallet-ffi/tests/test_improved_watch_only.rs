#[test]
fn test_improved_watch_only_wallet_creation() {
    use key_wallet_ffi::error::{FFIError, FFIErrorCode};
    use key_wallet_ffi::types::FFINetwork;
    use std::ffi::CStr;

    let mut error = FFIError::success();
    let error = &mut error as *mut FFIError;

    // 1. Create a regular wallet to get an xpub
    let seed = vec![0x01u8; 64];
    let source_wallet = key_wallet_ffi::wallet::wallet_create_from_seed(
        seed.as_ptr(),
        seed.len(),
        FFINetwork::Testnet,
        error,
    );
    assert!(!source_wallet.is_null());

    // 2. Get xpub from the regular wallet
    let xpub =
        key_wallet_ffi::wallet::wallet_get_xpub(source_wallet, FFINetwork::Testnet, 0, error);
    assert!(!xpub.is_null());

    // 3. Create a watch-only wallet using the improved implementation
    // This now properly creates an AccountCollection with account 0
    let watch_wallet =
        key_wallet_ffi::wallet::wallet_create_from_xpub(xpub, FFINetwork::Testnet, error);
    assert!(!watch_wallet.is_null());
    assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

    // 4. Verify the watch-only wallet has account 0 and can derive addresses
    let addr = key_wallet_ffi::address::wallet_derive_receive_address(
        watch_wallet,
        FFINetwork::Testnet,
        0, // account 0
        0, // address index 0
        error,
    );
    assert!(!addr.is_null());
    assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

    // 5. Verify both wallets derive the same address
    let source_addr = key_wallet_ffi::address::wallet_derive_receive_address(
        source_wallet,
        FFINetwork::Testnet,
        0,
        0,
        error,
    );
    assert!(!source_addr.is_null());

    let watch_addr_str = unsafe { CStr::from_ptr(addr).to_str().unwrap() };
    let source_addr_str = unsafe { CStr::from_ptr(source_addr).to_str().unwrap() };
    assert_eq!(watch_addr_str, source_addr_str);

    println!("✅ Watch-only wallet properly created with AccountCollection!");
    println!("   Both wallets derive the same address: {}", watch_addr_str);

    // Clean up
    key_wallet_ffi::address::address_free(addr);
    key_wallet_ffi::address::address_free(source_addr);
    key_wallet_ffi::wallet::wallet_free(source_wallet);
    key_wallet_ffi::wallet::wallet_free(watch_wallet);
    key_wallet_ffi::utils::string_free(xpub);
}
