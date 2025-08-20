#[test]
fn test_address_simple() {
    use key_wallet_ffi::error::{FFIError, FFIErrorCode};
    use key_wallet_ffi::types::FFINetwork;
    use std::ffi::CStr;

    let mut error = FFIError::success();
    let error = &mut error as *mut FFIError;

    // Create a wallet to get a valid address
    let seed = vec![0x42u8; 64];
    let wallet = unsafe {
        key_wallet_ffi::wallet::wallet_create_from_seed(
            seed.as_ptr(),
            seed.len(),
            FFINetwork::Testnet,
            error,
        )
    };
    assert!(!wallet.is_null());

    // Get an address from the wallet
    let addr = unsafe {
        key_wallet_ffi::address::wallet_derive_receive_address(
            wallet,
            FFINetwork::Testnet,
            0,
            0,
            error,
        )
    };
    assert!(!addr.is_null());

    // Convert to string and verify
    let addr_str = unsafe { CStr::from_ptr(addr).to_str().unwrap() };
    println!("Generated address: {}", addr_str);

    // Basic validation - should start with 'y' for testnet
    assert!(addr_str.starts_with('y'));
    assert!(addr_str.len() > 20);

    // Clean up
    unsafe {
        key_wallet_ffi::address::address_free(addr);
        key_wallet_ffi::wallet::wallet_free(wallet);
    }

    println!("Test passed!");
}
