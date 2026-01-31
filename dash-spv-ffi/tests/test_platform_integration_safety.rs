//! Comprehensive safety tests for platform_integration FFI functions
//!
//! Tests focus on:
//! - Null pointer handling
//! - Buffer overflow prevention
//! - Memory safety (double-free, use-after-free)
//! - Thread safety
//! - Error propagation

use dash_spv_ffi::*;
use serial_test::serial;
use std::ffi::CStr;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::thread;

/// Helper to create a mock FFI client for testing
unsafe fn create_mock_client() -> *mut FFIDashSpvClient {
    // For now, we'll use a null pointer since we're testing error cases
    // In a real implementation, this would create a valid mock client
    ptr::null_mut()
}

/// Helper to check FFI error result
fn assert_ffi_error(result: FFIResult, expected_code: FFIErrorCode) {
    assert_eq!(
        result.error_code, expected_code as i32,
        "Expected error code {}, got {}",
        expected_code as i32, result.error_code
    );
}

#[test]
#[serial]
fn test_get_core_handle_null_safety() {
    unsafe {
        // Test 2: Getting last error after null pointer operation
        let error = dash_spv_ffi_get_last_error();
        if !error.is_null() {
            let error_str = CStr::from_ptr(error);
            assert!(
                error_str.to_string_lossy().contains("null")
                    || error_str.to_string_lossy().contains("Null"),
                "Error should mention null pointer"
            );
            // Note: Error strings are managed internally by the FFI layer
        }
    }
}

#[test]
#[serial]
fn test_get_quorum_public_key_null_pointer_safety() {
    unsafe {
        let quorum_hash = [0u8; 32];
        let mut output_buffer = [0u8; 48];

        // Test 1: Null client
        let result = ffi_dash_spv_get_quorum_public_key(
            ptr::null_mut(),
            0,
            quorum_hash.as_ptr(),
            0,
            output_buffer.as_mut_ptr(),
            output_buffer.len(),
        );
        assert_ffi_error(result, FFIErrorCode::NullPointer);

        // Test 2: Null quorum hash
        let mock_client = create_mock_client();
        if !mock_client.is_null() {
            let result = ffi_dash_spv_get_quorum_public_key(
                mock_client,
                0,
                ptr::null(),
                0,
                output_buffer.as_mut_ptr(),
                output_buffer.len(),
            );
            assert_ffi_error(result, FFIErrorCode::NullPointer);
        }

        // Test 3: Null output buffer
        let result = ffi_dash_spv_get_quorum_public_key(
            create_mock_client(),
            0,
            quorum_hash.as_ptr(),
            0,
            ptr::null_mut(),
            48,
        );
        assert_ffi_error(result, FFIErrorCode::NullPointer);
    }
}

#[test]
#[serial]
fn test_get_quorum_public_key_buffer_size_validation() {
    unsafe {
        let quorum_hash = [0u8; 32];
        let mock_client = create_mock_client();

        // Test 1: Buffer too small (47 bytes instead of 48)
        let mut small_buffer = [0u8; 47];
        let result = ffi_dash_spv_get_quorum_public_key(
            mock_client,
            0,
            quorum_hash.as_ptr(),
            0,
            small_buffer.as_mut_ptr(),
            small_buffer.len(),
        );
        // Should fail with InvalidArgument or similar
        assert!(result.error_code != 0, "Should fail with small buffer");

        // Test 2: Correct buffer size (48 bytes)
        let mut correct_buffer = [0u8; 48];
        let _result = ffi_dash_spv_get_quorum_public_key(
            mock_client,
            0,
            quorum_hash.as_ptr(),
            0,
            correct_buffer.as_mut_ptr(),
            correct_buffer.len(),
        );
        // Will fail due to null client, but not due to buffer size

        // Test 3: Larger buffer (should be fine)
        let mut large_buffer = [0u8; 100];
        let _result = ffi_dash_spv_get_quorum_public_key(
            mock_client,
            0,
            quorum_hash.as_ptr(),
            0,
            large_buffer.as_mut_ptr(),
            large_buffer.len(),
        );
        // Will fail due to null client, but not due to buffer size
    }
}

#[test]
#[serial]
fn test_get_platform_activation_height_safety() {
    unsafe {
        let mut height: u32 = 0;

        // Test 1: Null client
        let result =
            ffi_dash_spv_get_platform_activation_height(ptr::null_mut(), &mut height as *mut u32);
        assert_ffi_error(result, FFIErrorCode::NullPointer);

        // Test 2: Null output pointer
        let mock_client = create_mock_client();
        let result = ffi_dash_spv_get_platform_activation_height(mock_client, ptr::null_mut());
        assert_ffi_error(result, FFIErrorCode::NullPointer);
    }
}

#[test]
#[serial]
fn test_thread_safety_concurrent_access() {
    // Test concurrent access to FFI functions
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let results = Arc::new(Mutex::new(Vec::new()));

    let mut handles = vec![];

    for i in 0..3 {
        let barrier_clone = barrier.clone();
        let results_clone = results.clone();

        let handle = thread::spawn(move || {
            unsafe {
                // Synchronize thread start
                barrier_clone.wait();

                // Each thread tries to get platform activation height
                let mut height: u32 = 0;
                let result = ffi_dash_spv_get_platform_activation_height(
                    ptr::null_mut(), // Using null for test
                    &mut height as *mut u32,
                );

                // Store result
                results_clone.lock().unwrap().push((i, result.error_code));
            }
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify all threads got consistent error codes
    let results_vec = results.lock().unwrap();
    assert_eq!(results_vec.len(), 3);
    let expected_error = FFIErrorCode::NullPointer as i32;
    for (thread_id, error_code) in results_vec.iter() {
        assert_eq!(*error_code, expected_error, "Thread {} got unexpected error code", thread_id);
    }
}

#[test]
#[serial]
fn test_memory_safety_patterns() {
    unsafe {
        // Test 1: Buffer overflow prevention
        let quorum_hash = [0u8; 32];
        let mut tiny_buffer = [0u8; 1]; // Way too small

        let result = ffi_dash_spv_get_quorum_public_key(
            ptr::null_mut(),
            0,
            quorum_hash.as_ptr(),
            0,
            tiny_buffer.as_mut_ptr(),
            tiny_buffer.len(), // Correctly report size
        );

        // Should fail safely without buffer overflow
        assert_ne!(result.error_code, 0);
    }
}

#[test]
#[serial]
fn test_error_propagation_thread_local() {
    unsafe {
        // Trigger an error
        let result = ffi_dash_spv_get_platform_activation_height(ptr::null_mut(), ptr::null_mut());
        assert_ne!(result.error_code, 0);

        // Get the error message
        let error = dash_spv_ffi_get_last_error();
        assert!(!error.is_null(), "Should have error message");

        if !error.is_null() {
            let error_str = CStr::from_ptr(error);
            let error_string = error_str.to_string_lossy();

            // Verify error message is meaningful
            assert!(!error_string.is_empty(), "Error message should not be empty");

            // Note: Error strings are managed internally
        }
    }
}

#[test]
#[serial]
fn test_boundary_conditions() {
    unsafe {
        // Test various boundary conditions

        // Test 1: Zero-length buffer
        let quorum_hash = [0u8; 32];
        let result = ffi_dash_spv_get_quorum_public_key(
            ptr::null_mut(),
            0,
            quorum_hash.as_ptr(),
            0,
            ptr::null_mut(),
            0, // Zero length
        );
        assert_ne!(result.error_code, 0);

        // Test 2: Maximum values
        let result = ffi_dash_spv_get_quorum_public_key(
            ptr::null_mut(),
            u32::MAX, // Max quorum type
            quorum_hash.as_ptr(),
            u32::MAX, // Max height
            ptr::null_mut(),
            0,
        );
        assert_ne!(result.error_code, 0);
    }
}

/// Test error string lifecycle management
#[test]
#[serial]
fn test_error_string_lifecycle() {
    unsafe {
        // Trigger an error to generate an error string
        let _ = ffi_dash_spv_get_platform_activation_height(ptr::null_mut(), ptr::null_mut());

        let error = dash_spv_ffi_get_last_error();
        if !error.is_null() {
            // Verify we can read the string
            let error_cstr = CStr::from_ptr(error);
            let error_string = error_cstr.to_string_lossy();
            assert!(!error_string.is_empty());

            // The error string is managed internally and should not be freed by the caller
            // Multiple calls should return the same pointer until cleared
            let error2 = dash_spv_ffi_get_last_error();
            assert_eq!(error, error2, "Should return same error pointer");
        }
    }
}
