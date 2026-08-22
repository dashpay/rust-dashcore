//! Unit tests for mnemonic FFI module

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::error::{FFIError, FFIErrorCode};
    use crate::mnemonic;
    use std::ffi::CString;

    use std::ptr;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const TEST_MNEMONIC_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn test_mnemonic_validation() {
        let mut error = FFIError::default();
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
        let mut error = FFIError::default();
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
        let mut error = FFIError::default();
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
        let mut error = FFIError::default();
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
        let mut error = FFIError::default();
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
        let mut error = FFIError::default();
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

    #[test]
    fn test_mnemonic_generate_with_language() {
        let mut error = FFIError::default();

        // Test generating with different languages
        let languages = [
            mnemonic::FFILanguage::English,
            mnemonic::FFILanguage::Spanish,
            mnemonic::FFILanguage::French,
            mnemonic::FFILanguage::Italian,
            mnemonic::FFILanguage::Japanese,
            mnemonic::FFILanguage::Korean,
            mnemonic::FFILanguage::ChineseSimplified,
            mnemonic::FFILanguage::ChineseTraditional,
            mnemonic::FFILanguage::Czech,
            mnemonic::FFILanguage::Portuguese,
        ];

        unsafe {
            for lang in languages.iter() {
                let mnemonic_ptr = mnemonic::mnemonic_generate_with_language(12, *lang, &mut error);

                assert!(!mnemonic_ptr.is_null());
                assert_eq!(error.code, FFIErrorCode::Success);

                // Verify it's valid
                let is_valid = mnemonic::mnemonic_validate(mnemonic_ptr, &mut error);
                assert!(is_valid);

                // Clean up
                mnemonic::mnemonic_free(mnemonic_ptr);
            }
        }
    }

    #[test]
    fn test_mnemonic_czech_portuguese_languages() {
        let mut error = FFIError::default();

        // Test Czech language specifically
        unsafe {
            let czech_mnemonic = mnemonic::mnemonic_generate_with_language(
                12,
                mnemonic::FFILanguage::Czech,
                &mut error,
            );
            assert!(!czech_mnemonic.is_null());
            assert_eq!(error.code, FFIErrorCode::Success);

            // Verify it's valid
            let is_valid = mnemonic::mnemonic_validate(czech_mnemonic, &mut error);
            assert!(is_valid);

            mnemonic::mnemonic_free(czech_mnemonic);
        }

        // Test Portuguese language specifically
        unsafe {
            let portuguese_mnemonic = mnemonic::mnemonic_generate_with_language(
                24,
                mnemonic::FFILanguage::Portuguese,
                &mut error,
            );
            assert!(!portuguese_mnemonic.is_null());
            assert_eq!(error.code, FFIErrorCode::Success);

            // Verify it's valid
            let is_valid = mnemonic::mnemonic_validate(portuguese_mnemonic, &mut error);
            assert!(is_valid);

            mnemonic::mnemonic_free(portuguese_mnemonic);
        }
    }

    #[test]
    fn test_mnemonic_generate_and_validate_languages() {
        let mut error = FFIError::default();

        // Generate a mnemonic with a specific language
        let mnemonic_ptr = unsafe {
            mnemonic::mnemonic_generate_with_language(
                12,
                mnemonic::FFILanguage::Spanish,
                &mut error,
            )
        };
        assert!(!mnemonic_ptr.is_null());

        // Validate it (validation doesn't need language since it checks all word lists)
        let is_valid = unsafe { mnemonic::mnemonic_validate(mnemonic_ptr, &mut error) };
        assert!(is_valid);

        // Clean up
        unsafe {
            mnemonic::mnemonic_free(mnemonic_ptr);
        }
    }

    #[test]
    fn test_mnemonic_free_null() {
        // Should handle null gracefully
        unsafe {
            mnemonic::mnemonic_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_seed_from_mnemonic_with_different_passphrases() {
        let mut error = FFIError::default();
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();

        // Test with empty passphrase
        let empty_pass = CString::new("").unwrap();
        let mut seed1 = [0u8; 64];
        let mut seed_len = 64usize;

        let success = unsafe {
            mnemonic::mnemonic_to_seed(
                mnemonic.as_ptr(),
                empty_pass.as_ptr(),
                seed1.as_mut_ptr(),
                &mut seed_len,
                &mut error,
            )
        };
        assert!(success);

        // Test with non-empty passphrase
        let pass = CString::new("TREZOR").unwrap();
        let mut seed2 = [0u8; 64];
        seed_len = 64;

        let success = unsafe {
            mnemonic::mnemonic_to_seed(
                mnemonic.as_ptr(),
                pass.as_ptr(),
                seed2.as_mut_ptr(),
                &mut seed_len,
                &mut error,
            )
        };
        assert!(success);

        // Seeds should be different
        assert_ne!(seed1, seed2);
    }

    #[test]
    fn test_mnemonic_word_count_function() {
        let mut error = FFIError::default();

        // Test different mnemonics
        let test_cases = [
            ("word", 1),
            ("two words", 2),
            ("three word mnemonic", 3),
            (TEST_MNEMONIC, 12),
            (TEST_MNEMONIC_24, 24),
        ];

        unsafe {
            for (mnemonic_str, expected_count) in test_cases {
                let mnemonic = CString::new(mnemonic_str).unwrap();
                let count = mnemonic::mnemonic_word_count(mnemonic.as_ptr(), &mut error);

                assert_eq!(count, expected_count);
                assert_eq!(error.code, FFIErrorCode::Success);
            }
        }
    }

    #[test]
    fn test_mnemonic_word_count_null_input() {
        let mut error = FFIError::default();

        let count = unsafe { mnemonic::mnemonic_word_count(ptr::null(), &mut error) };

        assert_eq!(count, 0);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_mnemonic_word_count_utf8_error() {
        let mut error = FFIError::default();

        // Create invalid UTF-8 string
        let invalid_utf8 = [0xFF, 0xFE, 0xFD, 0x00];
        let count = unsafe {
            mnemonic::mnemonic_word_count(
                invalid_utf8.as_ptr() as *const std::os::raw::c_char,
                &mut error,
            )
        };

        assert_eq!(count, 0);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_mnemonic_to_seed_null_inputs() {
        let mut error = FFIError::default();
        let mut seed = [0u8; 64];
        let mut seed_len = 0usize;

        // Test null mnemonic
        let success = unsafe {
            mnemonic::mnemonic_to_seed(
                ptr::null(),
                ptr::null(),
                seed.as_mut_ptr(),
                &mut seed_len,
                &mut error,
            )
        };
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test null seed_out
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let success = unsafe {
            mnemonic::mnemonic_to_seed(
                mnemonic.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                &mut seed_len,
                &mut error,
            )
        };
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test null seed_len
        let success = unsafe {
            mnemonic::mnemonic_to_seed(
                mnemonic.as_ptr(),
                ptr::null(),
                seed.as_mut_ptr(),
                ptr::null_mut(),
                &mut error,
            )
        };
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_mnemonic_to_seed_invalid_mnemonic() {
        let mut error = FFIError::default();
        let mut seed = [0u8; 64];
        let mut seed_len = 0usize;

        let invalid_mnemonic = CString::new("invalid mnemonic phrase").unwrap();
        let success = unsafe {
            mnemonic::mnemonic_to_seed(
                invalid_mnemonic.as_ptr(),
                ptr::null(),
                seed.as_mut_ptr(),
                &mut seed_len,
                &mut error,
            )
        };

        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidMnemonic);
    }

    #[test]
    fn test_mnemonic_to_seed_utf8_errors() {
        let mut error = FFIError::default();
        let mut seed = [0u8; 64];
        let mut seed_len = 0usize;

        // Test invalid UTF-8 in mnemonic
        let invalid_utf8 = [0xFF, 0xFE, 0xFD, 0x00];
        let success = unsafe {
            mnemonic::mnemonic_to_seed(
                invalid_utf8.as_ptr() as *const std::os::raw::c_char,
                ptr::null(),
                seed.as_mut_ptr(),
                &mut seed_len,
                &mut error,
            )
        };
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);

        // Test invalid UTF-8 in passphrase
        let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
        let success = unsafe {
            mnemonic::mnemonic_to_seed(
                mnemonic.as_ptr(),
                invalid_utf8.as_ptr() as *const std::os::raw::c_char,
                seed.as_mut_ptr(),
                &mut seed_len,
                &mut error,
            )
        };
        assert!(!success);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_mnemonic_validate_utf8_error() {
        let mut error = FFIError::default();

        // Create invalid UTF-8 string
        let invalid_utf8 = [0xFF, 0xFE, 0xFD, 0x00];
        let is_valid = unsafe {
            mnemonic::mnemonic_validate(
                invalid_utf8.as_ptr() as *const std::os::raw::c_char,
                &mut error,
            )
        };

        assert!(!is_valid);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_mnemonic_generate_with_language_invalid_word_count() {
        let mut error = FFIError::default();

        // Test invalid word count with language
        let mnemonic = unsafe {
            mnemonic::mnemonic_generate_with_language(
                13,
                mnemonic::FFILanguage::English,
                &mut error,
            )
        };

        assert!(mnemonic.is_null());
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
    }

    #[test]
    fn test_mnemonic_generate_with_language_all_word_counts() {
        let mut error = FFIError::default();

        // Test all valid word counts with language
        let valid_counts = [12, 15, 18, 21, 24];

        for word_count in valid_counts {
            let mnemonic = unsafe {
                mnemonic::mnemonic_generate_with_language(
                    word_count,
                    mnemonic::FFILanguage::English,
                    &mut error,
                )
            };

            assert!(!mnemonic.is_null());
            assert_eq!(error.code, FFIErrorCode::Success);

            let mnemonic_str = unsafe { std::ffi::CStr::from_ptr(mnemonic).to_str().unwrap() };
            assert_eq!(mnemonic_str.split_whitespace().count(), word_count as usize);

            unsafe {
                mnemonic::mnemonic_free(mnemonic);
            }
        }
    }

    #[test]
    fn test_mnemonic_generate_different_languages() {
        let mut error = FFIError::default();

        // Test generating with all supported languages
        let languages = [
            mnemonic::FFILanguage::English,
            mnemonic::FFILanguage::ChineseSimplified,
            mnemonic::FFILanguage::ChineseTraditional,
            mnemonic::FFILanguage::French,
            mnemonic::FFILanguage::Italian,
            mnemonic::FFILanguage::Japanese,
            mnemonic::FFILanguage::Korean,
            mnemonic::FFILanguage::Spanish,
        ];

        for lang in languages {
            let mnemonic_ptr =
                unsafe { mnemonic::mnemonic_generate_with_language(12, lang, &mut error) };

            // Some languages might not be fully supported by the underlying library
            unsafe {
                if !mnemonic_ptr.is_null() {
                    assert_eq!(error.code, FFIErrorCode::Success);

                    let mnemonic_str = std::ffi::CStr::from_ptr(mnemonic_ptr).to_str().unwrap();
                    assert_eq!(mnemonic_str.split_whitespace().count(), 12);

                    // Verify it validates
                    let is_valid = mnemonic::mnemonic_validate(mnemonic_ptr, &mut error);
                    assert!(is_valid);

                    mnemonic::mnemonic_free(mnemonic_ptr);
                }
            }
        }
    }

    #[test]
    fn test_generated_mnemonic_deterministic_seed() {
        let mut error = FFIError::default();

        // Generate mnemonic
        let mnemonic = unsafe { mnemonic::mnemonic_generate(12, &mut error) };
        assert!(!mnemonic.is_null());

        let passphrase = CString::new("").unwrap();

        // Generate seed twice with same passphrase - should be identical
        let mut seed1 = [0u8; 64];
        let mut seed_len1 = 0usize;
        let mut seed2 = [0u8; 64];
        let mut seed_len2 = 0usize;

        let success1 = unsafe {
            mnemonic::mnemonic_to_seed(
                mnemonic,
                passphrase.as_ptr(),
                seed1.as_mut_ptr(),
                &mut seed_len1,
                &mut error,
            )
        };

        let success2 = unsafe {
            mnemonic::mnemonic_to_seed(
                mnemonic,
                passphrase.as_ptr(),
                seed2.as_mut_ptr(),
                &mut seed_len2,
                &mut error,
            )
        };

        assert!(success1);
        assert!(success2);
        assert_eq!(seed_len1, 64);
        assert_eq!(seed_len2, 64);
        assert_eq!(seed1, seed2); // Should be identical

        unsafe {
            mnemonic::mnemonic_free(mnemonic);
        }
    }

    #[test]
    fn test_mnemonic_comprehensive_workflow() {
        let mut error = FFIError::default();

        // Generate -> Validate -> Get word count -> Convert to seed -> Free
        let mnemonic = unsafe { mnemonic::mnemonic_generate(15, &mut error) };
        assert!(!mnemonic.is_null());
        assert_eq!(error.code, FFIErrorCode::Success);

        let passphrase = CString::new("").unwrap();

        // Validate
        let is_valid = unsafe { mnemonic::mnemonic_validate(mnemonic, &mut error) };
        assert!(is_valid);
        assert_eq!(error.code, FFIErrorCode::Success);

        // Check word count
        let word_count = unsafe { mnemonic::mnemonic_word_count(mnemonic, &mut error) };
        assert_eq!(word_count, 15);
        assert_eq!(error.code, FFIErrorCode::Success);

        // Convert to seed
        let mut seed = [0u8; 64];
        let mut seed_len = 0usize;

        let success = unsafe {
            mnemonic::mnemonic_to_seed(
                mnemonic,
                passphrase.as_ptr(),
                seed.as_mut_ptr(),
                &mut seed_len,
                &mut error,
            )
        };

        assert!(success);
        assert_eq!(seed_len, 64);
        assert_ne!(seed, [0u8; 64]);
        assert_eq!(error.code, FFIErrorCode::Success);

        // Free
        unsafe {
            mnemonic::mnemonic_free(mnemonic);
        }
    }

    /// Entropy whose French encoding contains non-ASCII (accented) words;
    /// shared by the multi-language tests below.
    const ANY_LANGUAGE_TEST_ENTROPY: [u8; 16] = [
        0x0c, 0x1e, 0x24, 0xe5, 0x91, 0x77, 0x79, 0xd2, 0x97, 0xe1, 0x4d, 0x45, 0xf1, 0x4e, 0x1a,
        0x1a,
    ];

    /// French phrase for `ANY_LANGUAGE_TEST_ENTROPY`, with its BIP-39 seed
    /// computed independently of this codebase (python
    /// `hashlib.pbkdf2_hmac('sha512', NFKD(phrase), b"mnemonic", 2048)`).
    const FRENCH_REFERENCE_PHRASE: &str = "amour troupeau couteau brèche gustatif tenaille exécuter capuche dicter lagune jaune cogner";
    const FRENCH_REFERENCE_SEED_HEX: &str = "895debca7a86928a0c4cb5712aefd6d4cf4c7cfd23448ccd5418932e4f00c940089a3501f4f33eaf115f1a689d6c1e54b6bb6d5f40e4791234cb2ac87d62df68";

    /// The invariant that regressed in Dash Wallet iOS 9.0.0: whatever
    /// `mnemonic_validate` accepts, `mnemonic_to_seed` and
    /// `wallet_create_from_mnemonic` must accept too — in every supported
    /// language, not just English.
    #[test]
    fn test_validate_parse_symmetry_all_languages() {
        use dash_network::ffi::FFINetwork;
        use key_wallet::mnemonic::{Language, Mnemonic};

        for lang in Language::ALL {
            let phrase = Mnemonic::from_entropy(&ANY_LANGUAGE_TEST_ENTROPY, lang).unwrap().phrase();
            let c_phrase = CString::new(phrase).unwrap();

            let mut error = FFIError::default();
            let error = &mut error as *mut FFIError;

            let is_valid = unsafe { mnemonic::mnemonic_validate(c_phrase.as_ptr(), error) };
            assert!(is_valid, "{lang:?}: validate must accept");
            assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

            let mut seed = [0u8; 64];
            let mut seed_len: usize = 64;
            let ok = unsafe {
                mnemonic::mnemonic_to_seed(
                    c_phrase.as_ptr(),
                    ptr::null(),
                    seed.as_mut_ptr(),
                    &mut seed_len,
                    error,
                )
            };
            assert!(ok, "{lang:?}: to_seed must accept a validated phrase");
            assert_eq!(seed_len, 64);
            assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);

            let wallet = unsafe {
                crate::wallet::wallet_create_from_mnemonic(
                    c_phrase.as_ptr(),
                    FFINetwork::Testnet,
                    error,
                )
            };
            assert!(!wallet.is_null(), "{lang:?}: wallet creation must accept a validated phrase");
            assert_eq!(unsafe { (*error).code }, FFIErrorCode::Success);
            unsafe { crate::wallet::wallet_free(wallet) };
        }
    }

    /// Seed derivation for a non-English phrase must match the BIP-39 spec
    /// (PBKDF2-HMAC-SHA512 over the NFKD phrase), not merely succeed —
    /// pinned against an independently computed reference vector.
    #[test]
    fn test_mnemonic_to_seed_french_reference_vector() {
        let c_phrase = CString::new(FRENCH_REFERENCE_PHRASE).unwrap();
        let mut error = FFIError::default();
        let error = &mut error as *mut FFIError;

        let mut seed = [0u8; 64];
        let mut seed_len: usize = 64;
        let ok = unsafe {
            mnemonic::mnemonic_to_seed(
                c_phrase.as_ptr(),
                ptr::null(),
                seed.as_mut_ptr(),
                &mut seed_len,
                error,
            )
        };
        assert!(ok, "French phrase must derive a seed");
        assert_eq!(seed_len, 64);
        assert_eq!(hex::encode(seed), FRENCH_REFERENCE_SEED_HEX);
    }
}
