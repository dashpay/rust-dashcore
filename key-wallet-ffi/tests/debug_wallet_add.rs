use dash_network::ffi::FFINetwork;

#[test]
fn test_debug_wallet_add() {
    use key_wallet_ffi::error::FFIError;
    use key_wallet_ffi::wallet_manager;
    use std::ffi::CString;

    let mut error = FFIError::default();
    let error = &mut error as *mut FFIError;

    let manager = unsafe { wallet_manager::wallet_manager_create(FFINetwork::Testnet, error) };
    assert!(!manager.is_null());
    println!("Manager created successfully");

    let mnemonic = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();

    println!("Adding wallet from mnemonic");
    let success = unsafe {
        wallet_manager::wallet_manager_add_wallet_from_mnemonic(manager, mnemonic.as_ptr(), error)
    };

    if !success {
        unsafe {
            println!("Failed to add wallet! Error code: {:?}", (*error).code);
            if !(*error).message.is_null() {
                let msg = std::ffi::CStr::from_ptr((*error).message);
                println!("Error message: {:?}", msg);
            }
        }
    } else {
        println!("Successfully added wallet from mnemonic");
    }

    assert!(success);

    // Clean up
    unsafe {
        wallet_manager::wallet_manager_free(manager);
    }
}
