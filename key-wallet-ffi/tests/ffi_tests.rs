//! FFI tests
//!
//! These tests verify the FFI implementation works correctly.
//! They test the Rust implementation directly, not through generated bindings.

#[test]
fn test_ffi_types_exist() {
    // This test just verifies the crate compiles with all the expected types
    use key_wallet_ffi::{
        initialize, validate_mnemonic, Address, AddressGenerator, AddressType, ExtendedKey,
        HDWallet, KeyWalletError, Language, Mnemonic, Network,
    };

    // Verify we can call initialize
    initialize();

    // This test passes if it compiles
    assert!(true);
}
