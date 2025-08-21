//! Mnemonic generation and handling

#[cfg(test)]
#[path = "mnemonic_tests.rs"]
mod tests;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};
use std::ptr;

use key_wallet::Mnemonic;

use crate::error::{FFIError, FFIErrorCode};

/// Language enumeration for mnemonic generation
///
/// This enum must be kept in sync with key_wallet::mnemonic::Language.
/// When adding new languages to the key_wallet crate, remember to update
/// this FFI enum and both From implementations below.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum FFILanguage {
    English = 0,
    ChineseSimplified = 1,
    ChineseTraditional = 2,
    Czech = 3,
    French = 4,
    Italian = 5,
    Japanese = 6,
    Korean = 7,
    Portuguese = 8,
    Spanish = 9,
}

impl From<FFILanguage> for key_wallet::mnemonic::Language {
    fn from(l: FFILanguage) -> Self {
        use key_wallet::mnemonic::Language;
        match l {
            FFILanguage::English => Language::English,
            FFILanguage::ChineseSimplified => Language::ChineseSimplified,
            FFILanguage::ChineseTraditional => Language::ChineseTraditional,
            FFILanguage::Czech => Language::Czech,
            FFILanguage::French => Language::French,
            FFILanguage::Italian => Language::Italian,
            FFILanguage::Japanese => Language::Japanese,
            FFILanguage::Korean => Language::Korean,
            FFILanguage::Portuguese => Language::Portuguese,
            FFILanguage::Spanish => Language::Spanish,
        }
    }
}

impl From<key_wallet::mnemonic::Language> for FFILanguage {
    fn from(l: key_wallet::mnemonic::Language) -> Self {
        use key_wallet::mnemonic::Language;
        match l {
            Language::English => FFILanguage::English,
            Language::ChineseSimplified => FFILanguage::ChineseSimplified,
            Language::ChineseTraditional => FFILanguage::ChineseTraditional,
            Language::Czech => FFILanguage::Czech,
            Language::French => FFILanguage::French,
            Language::Italian => FFILanguage::Italian,
            Language::Japanese => FFILanguage::Japanese,
            Language::Korean => FFILanguage::Korean,
            Language::Portuguese => FFILanguage::Portuguese,
            Language::Spanish => FFILanguage::Spanish,
        }
    }
}

/// Generate a new mnemonic with specified word count (12, 15, 18, 21, or 24)
#[no_mangle]
pub extern "C" fn mnemonic_generate(word_count: c_uint, error: *mut FFIError) -> *mut c_char {
    let entropy_bits = match word_count {
        12 => 128,
        15 => 160,
        18 => 192,
        21 => 224,
        24 => 256,
        _ => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                format!("Invalid word count: {}. Must be 12, 15, 18, 21, or 24", word_count),
            );
            return ptr::null_mut();
        }
    };

    use key_wallet::mnemonic::Language;
    let word_count = match entropy_bits {
        128 => 12,
        160 => 15,
        192 => 18,
        224 => 21,
        256 => 24,
        _ => 12,
    };
    match Mnemonic::generate(word_count, Language::English) {
        Ok(mnemonic) => {
            FFIError::set_success(error);
            match CString::new(mnemonic.to_string()) {
                Ok(c_str) => c_str.into_raw(),
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::AllocationFailed,
                        "Failed to allocate string".to_string(),
                    );
                    ptr::null_mut()
                }
            }
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidMnemonic,
                format!("Failed to generate mnemonic: {}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Generate a new mnemonic with specified language and word count
#[no_mangle]
pub extern "C" fn mnemonic_generate_with_language(
    word_count: c_uint,
    language: FFILanguage,
    error: *mut FFIError,
) -> *mut c_char {
    let entropy_bits = match word_count {
        12 => 128,
        15 => 160,
        18 => 192,
        21 => 224,
        24 => 256,
        _ => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                format!("Invalid word count: {}. Must be 12, 15, 18, 21, or 24", word_count),
            );
            return ptr::null_mut();
        }
    };

    // Convert FFILanguage to key_wallet Language
    use key_wallet::mnemonic::Language;
    let lang: Language = language.into();
    let word_count = match entropy_bits {
        128 => 12,
        160 => 15,
        192 => 18,
        224 => 21,
        256 => 24,
        _ => 12,
    };
    match Mnemonic::generate(word_count, lang) {
        Ok(mnemonic) => {
            FFIError::set_success(error);
            match CString::new(mnemonic.to_string()) {
                Ok(c_str) => c_str.into_raw(),
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::AllocationFailed,
                        "Failed to allocate string".to_string(),
                    );
                    ptr::null_mut()
                }
            }
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidMnemonic,
                format!("Failed to generate mnemonic: {}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Validate a mnemonic phrase
///
/// # Safety
///
/// - `mnemonic` must be a valid null-terminated C string or null
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn mnemonic_validate(mnemonic: *const c_char, error: *mut FFIError) -> bool {
    if mnemonic.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Mnemonic is null".to_string());
        return false;
    }

    let mnemonic_str = unsafe {
        match CStr::from_ptr(mnemonic).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in mnemonic".to_string(),
                );
                return false;
            }
        }
    };

    use key_wallet::mnemonic::Language;

    // Try validation against all supported languages
    let languages = [
        Language::English,
        Language::ChineseSimplified,
        Language::ChineseTraditional,
        Language::Czech,
        Language::French,
        Language::Italian,
        Language::Japanese,
        Language::Korean,
        Language::Portuguese,
        Language::Spanish,
    ];

    for language in languages.iter() {
        if Mnemonic::validate(mnemonic_str, *language) {
            FFIError::set_success(error);
            return true;
        }
    }

    // If no language validates, return error
    FFIError::set_error(
        error,
        FFIErrorCode::InvalidMnemonic,
        "Invalid mnemonic: does not match any supported language".to_string(),
    );
    false
}

/// Convert mnemonic to seed with optional passphrase
///
/// # Safety
///
/// - `mnemonic` must be a valid null-terminated C string
/// - `passphrase` must be a valid null-terminated C string or null
/// - `seed_out` must be a valid pointer to a buffer of at least 64 bytes
/// - `seed_len` must be a valid pointer to store the seed length
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn mnemonic_to_seed(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    seed_out: *mut u8,
    seed_len: *mut usize,
    error: *mut FFIError,
) -> bool {
    if mnemonic.is_null() || seed_out.is_null() || seed_len.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let mnemonic_str = unsafe {
        match CStr::from_ptr(mnemonic).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in mnemonic".to_string(),
                );
                return false;
            }
        }
    };

    let passphrase_str = if passphrase.is_null() {
        ""
    } else {
        unsafe {
            match CStr::from_ptr(passphrase).to_str() {
                Ok(s) => s,
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::InvalidInput,
                        "Invalid UTF-8 in passphrase".to_string(),
                    );
                    return false;
                }
            }
        }
    };

    use key_wallet::mnemonic::Language;
    match Mnemonic::from_phrase(mnemonic_str, Language::English) {
        Ok(m) => {
            let seed = m.to_seed(passphrase_str);
            let seed_bytes: &[u8] = seed.as_ref();

            unsafe {
                *seed_len = seed_bytes.len();
                if *seed_len > 64 {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::InvalidState,
                        "Seed too large".to_string(),
                    );
                    return false;
                }

                std::ptr::copy_nonoverlapping(seed_bytes.as_ptr(), seed_out, seed_bytes.len());
            }

            FFIError::set_success(error);
            true
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidMnemonic,
                format!("Invalid mnemonic: {}", e),
            );
            false
        }
    }
}

/// Get word count from mnemonic
///
/// # Safety
///
/// - `mnemonic` must be a valid null-terminated C string or null
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn mnemonic_word_count(
    mnemonic: *const c_char,
    error: *mut FFIError,
) -> c_uint {
    if mnemonic.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Mnemonic is null".to_string());
        return 0;
    }

    let mnemonic_str = unsafe {
        match CStr::from_ptr(mnemonic).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in mnemonic".to_string(),
                );
                return 0;
            }
        }
    };

    let word_count = mnemonic_str.split_whitespace().count() as c_uint;
    FFIError::set_success(error);
    word_count
}

/// Free a mnemonic string
///
/// # Safety
///
/// - `mnemonic` must be a valid pointer created by mnemonic generation functions or null
/// - After calling this function, the pointer becomes invalid
#[no_mangle]
pub unsafe extern "C" fn mnemonic_free(mnemonic: *mut c_char) {
    if !mnemonic.is_null() {
        unsafe {
            let _ = CString::from_raw(mnemonic);
        }
    }
}
