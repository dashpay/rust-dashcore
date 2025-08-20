#[test]
fn test_debug_wallet_add() {
    use key_wallet_ffi::error::FFIError;
    use key_wallet_ffi::types::FFINetwork;
    use key_wallet_ffi::wallet_manager;
    use std::ffi::CString;

    let mut error = FFIError::success();
    let error = &mut error as *mut FFIError;

    let manager = wallet_manager::wallet_manager_create(error);
    assert!(!manager.is_null());
    println!("Manager created successfully");

    let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    let passphrase = CString::new("pass1").unwrap();

    println!("Adding wallet with passphrase 'pass1'");
    let success = wallet_manager::wallet_manager_add_wallet_from_mnemonic(
        manager,
        mnemonic.as_ptr(),
        passphrase.as_ptr(),
        FFINetwork::Testnet,
        error,
    );

    if !success {
        unsafe {
            println!("Failed to add wallet! Error code: {:?}", (*error).code);
            if !(*error).message.is_null() {
                let msg = std::ffi::CStr::from_ptr((*error).message);
                println!("Error message: {:?}", msg);
            }
        }
    } else {
        println!("Successfully added wallet with passphrase");
    }

    assert!(success);

    // Clean up
    wallet_manager::wallet_manager_free(manager);
}
