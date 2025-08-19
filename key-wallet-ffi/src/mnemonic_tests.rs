//! Unit tests for mnemonic FFI module

#[cfg(test)]
mod tests {
    use crate::error::{FFIError, FFIErrorCode};
    use crate::mnemonic;
    use std::ffi::CString;
    use std::os::raw::c_char;
    use std::ptr;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const TEST_MNEMONIC_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn test_mnemonic_validation() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test valid 12-word mnemonic
        let valid_mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let is_valid = unsafe { mnemonic::mnemonic_validate(valid_mnemonic.as_ptr(), error) };
        assert!(is_valid);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        // Test valid 24-word mnemonic
        let valid_mnemonic_24 = CString::new(TEST_MNEMONIC_24).unwrap();
        let is_valid = unsafe { mnemonic::mnemonic_validate(valid_mnemonic_24.as_ptr(), error) };
        assert!(is_valid);

        // Test invalid mnemonic
        let invalid_mnemonic = CString::new("invalid mnemonic phrase here").unwrap();
        let is_valid = unsafe { mnemonic::mnemonic_validate(invalid_mnemonic.as_ptr(), error) };
        assert!(!is_valid);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidMnemonic);

        // Test null mnemonic
        let is_valid = unsafe { mnemonic::mnemonic_validate(ptr::null(), error) };
        assert!(!is_valid);
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_mnemonic_generation() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test 12-word generation
        let mnemonic_12 = unsafe { mnemonic::mnemonic_generate(12, error) };
        assert!(!mnemonic_12.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

        let mnemonic_str = unsafe { std::ffi::CStr::from_ptr(mnemonic_12).to_str().unwrap() };
        let word_count = mnemonic_str.split_whitespace().count();
        assert_eq!(word_count, 12);

        // Validate the generated mnemonic
        let is_valid = unsafe { mnemonic::mnemonic_validate(mnemonic_12, error) };
        assert!(is_valid);

        unsafe {
            mnemonic::mnemonic_free(mnemonic_12);
        }

        // Test 24-word generation
        let mnemonic_24 = unsafe { mnemonic::mnemonic_generate(24, error) };
        assert!(!mnemonic_24.is_null());

        let mnemonic_str = unsafe { std::ffi::CStr::from_ptr(mnemonic_24).to_str().unwrap() };
        let word_count = mnemonic_str.split_whitespace().count();
        assert_eq!(word_count, 24);

        unsafe {
            mnemonic::mnemonic_free(mnemonic_24);
        }

        // Test invalid word count
        let invalid = unsafe { mnemonic::mnemonic_generate(13, error) };
        assert!(invalid.is_null());
        assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_mnemonic_to_seed() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let passphrase = CString::new("").unwrap();

        let mut seed = [0u8; 64];
        let mut seed_len: usize = 0;

        let success = unsafe {
            mnemonic::mnemonic_to_seed(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                seed.as_mut_ptr(),
                &mut seed_len,
                error,
            )
        };

        assert!(success);
        assert_eq!(seed_len, 64);
        assert_ne!(seed, [0u8; 64]); // Seed should not be all zeros

        // Test with passphrase
        let passphrase = CString::new("test passphrase").unwrap();
        let mut seed_with_pass = [0u8; 64];

        let success = unsafe {
            mnemonic::mnemonic_to_seed(
                mnemonic.as_ptr(),
                passphrase.as_ptr(),
                seed_with_pass.as_mut_ptr(),
                &mut seed_len,
                error,
            )
        };

        assert!(success);
        assert_ne!(seed, seed_with_pass); // Different passphrase should produce different seed
    }

    #[test]
    fn test_mnemonic_word_counts() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test all valid word counts
        let valid_counts = [12, 15, 18, 21, 24];

        for count in valid_counts.iter() {
            let mnemonic = unsafe { mnemonic::mnemonic_generate(*count, error) };
            assert!(!mnemonic.is_null());

            let mnemonic_str = unsafe { std::ffi::CStr::from_ptr(mnemonic).to_str().unwrap() };
            let word_count = mnemonic_str.split_whitespace().count();
            assert_eq!(word_count, *count as usize);

            unsafe {
                mnemonic::mnemonic_free(mnemonic);
            }
        }
    }

    #[test]
    fn test_mnemonic_invalid_word_count() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test invalid word counts
        let invalid_counts = [0, 1, 11, 13, 14, 16, 17, 19, 20, 22, 23, 25, 100];

        for count in invalid_counts.iter() {
            let mnemonic = unsafe { mnemonic::mnemonic_generate(*count, error) };
            assert!(mnemonic.is_null());
            assert_eq!(unsafe { (*error).code }, FFIErrorCode::InvalidInput);
        }
    }

    #[test]
    fn test_mnemonic_edge_cases() {
        let mut error = FFIError::success();
        let error = &mut error as *mut FFIError;

        // Test with null mnemonic
        let success = unsafe { mnemonic::mnemonic_validate(ptr::null(), error) };
        assert!(!success);

        // Test with empty mnemonic
        let empty = CString::new("").unwrap();
        let success = unsafe { mnemonic::mnemonic_validate(empty.as_ptr(), error) };
        assert!(!success);

        // Test with wrong word count
        let wrong_count = CString::new("abandon abandon abandon").unwrap();
        let success = unsafe { mnemonic::mnemonic_validate(wrong_count.as_ptr(), error) };
        assert!(!success);

        // Test mnemonic to seed with null passphrase
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let mut seed = [0u8; 64];
        let mut seed_len: usize = 0;

        let success = unsafe {
            mnemonic::mnemonic_to_seed(
                mnemonic.as_ptr(),
                ptr::null(), // null passphrase
                seed.as_mut_ptr(),
                &mut seed_len,
                error,
            )
        };
        assert!(success);
        assert_eq!(seed_len, 64);
    }
}
