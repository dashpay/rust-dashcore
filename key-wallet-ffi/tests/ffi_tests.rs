//! FFI tests
//!
//! These tests verify the FFI implementation works correctly.
//! They test the Rust implementation directly, not through generated bindings.

#[test]
fn test_ffi_types_exist() {
    // This test just verifies the crate compiles with all the expected types
    use key_wallet_ffi::key_wallet_ffi_initialize;

    // Verify we can call initialize
    assert!(key_wallet_ffi_initialize());
}
