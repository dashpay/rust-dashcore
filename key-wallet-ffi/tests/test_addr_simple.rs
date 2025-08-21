#[test]
fn test_address_simple() {
    use key_wallet_ffi::error::FFIError;
    use key_wallet_ffi::types::FFINetwork;

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

    // Since we can't derive addresses directly from wallets anymore,
    // we'll test wallet creation and basic properties
    let is_watch_only = unsafe { key_wallet_ffi::wallet::wallet_is_watch_only(wallet, error) };
    assert!(!is_watch_only);

    // Get wallet ID to verify it was created
    let mut wallet_id = [0u8; 32];
    let success =
        unsafe { key_wallet_ffi::wallet::wallet_get_id(wallet, wallet_id.as_mut_ptr(), error) };
    assert!(success);
    assert_ne!(wallet_id, [0u8; 32]);

    println!("Generated wallet with ID: {:?}", &wallet_id[..8]);

    // Clean up
    unsafe {
        key_wallet_ffi::wallet::wallet_free(wallet);
    }

    println!("Test passed!");
}
