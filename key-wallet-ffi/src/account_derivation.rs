//! Account-level derivation functions exposed over FFI

use crate::account::FFIAccount;
#[cfg(feature = "bls")]
use crate::account::FFIBLSAccount;
#[cfg(feature = "eddsa")]
use crate::account::FFIEdDSAAccount;
use crate::error::{FFIError, FFIErrorCode};
use crate::keys::{FFIExtendedPrivateKey, FFIPrivateKey};
use key_wallet::account::derivation::AccountDerivation;
use key_wallet::account::AccountTrait;
use std::ffi::CString;
use std::os::raw::{c_char, c_uint};
use std::ptr;

// No extra FFI enum for chain selection; account semantics decide path.

/// Derive an extended private key from an account at a given index, using the provided master xpriv.
///
/// Returns an opaque FFIExtendedPrivateKey pointer that must be freed with `extended_private_key_free`.
///
/// Notes:
/// - This is chain-agnostic. For accounts with internal/external chains, this returns an error.
/// - For hardened-only account types (e.g., EdDSA), a hardened index is used.
///
/// # Safety
/// - `account` and `master_xpriv` must be valid, non-null pointers allocated by this library.
/// - `error` must be a valid pointer to an FFIError or null.
/// - The caller must free the returned pointer with `extended_private_key_free`.
#[no_mangle]
pub unsafe extern "C" fn account_derive_extended_private_key_at(
    account: *const FFIAccount,
    master_xpriv: *const FFIExtendedPrivateKey,
    index: c_uint,
    error: *mut FFIError,
) -> *mut FFIExtendedPrivateKey {
    if account.is_null() || master_xpriv.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let account = &*account;
    let master_xpriv = &*master_xpriv;

    if account.inner().is_watch_only() {
        FFIError::set_error(
            error,
            FFIErrorCode::WalletError,
            "Account is watch-only; private derivation not allowed".to_string(),
        );
        return ptr::null_mut();
    }

    match account.inner().derive_from_master_xpriv_extended_xpriv_at(master_xpriv.inner(), index) {
        Ok(derived) => {
            FFIError::set_success(error);
            Box::into_raw(Box::new(FFIExtendedPrivateKey::from_inner(derived)))
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to derive extended private key: {:?}", e),
            );
            ptr::null_mut()
        }
    }
}

// ========================= BLS (feature = "bls") =========================
/// Derive a BLS private key from a raw seed buffer at the given index.
///
/// Returns a newly allocated hex string of the 32-byte private key. The caller must free
/// it with `string_free`.
///
/// Notes:
/// - Uses the account's network for master key creation.
/// - Chain-agnostic; may return an error for accounts with internal/external chains.
///
/// # Safety
/// - `account` must be a valid, non-null pointer to an `FFIBLSAccount` (only when `bls` feature is enabled).
/// - `seed` must point to a readable buffer of length `seed_len` (1..=64 bytes expected).
/// - `error` must be a valid pointer to an FFIError or null.
/// - Returned string must be freed with `string_free`.
#[cfg(feature = "bls")]
#[no_mangle]
pub unsafe extern "C" fn bls_account_derive_private_key_from_seed(
    account: *const FFIBLSAccount,
    seed: *const u8,
    seed_len: usize,
    index: c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    if account.is_null() || seed.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }
    let account = &*account;
    if seed_len == 0 || seed_len > 64 {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Seed length must be between 1 and 64 bytes".to_string(),
        );
        return ptr::null_mut();
    }
    let seed_slice = std::slice::from_raw_parts(seed, seed_len);
    match account.inner().derive_from_seed_private_key_at(seed_slice, index) {
        Ok(sk) => {
            // Return private key bytes as hex
            let hex = hex::encode(sk.to_be_bytes());
            match CString::new(hex) {
                Ok(s) => {
                    FFIError::set_success(error);
                    s.into_raw()
                }
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::AllocationFailed,
                        "Allocation failed".into(),
                    );
                    ptr::null_mut()
                }
            }
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to derive BLS private key from seed: {:?}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Derive a BLS private key from a mnemonic + optional passphrase at the given index.
///
/// Returns a newly allocated hex string of the 32-byte private key. The caller must free
/// it with `string_free`.
///
/// Notes:
/// - Uses the English wordlist for parsing the mnemonic.
/// - Chain-agnostic; may return an error for accounts with internal/external chains.
///
/// # Safety
/// - `account` must be a valid, non-null pointer to an `FFIBLSAccount` (only when `bls` feature is enabled).
/// - `mnemonic` must be a valid, null-terminated UTF-8 C string.
/// - `passphrase` may be null; if not null, must be a valid UTF-8 C string.
/// - `error` must be a valid pointer to an FFIError or null.
/// - Returned string must be freed with `string_free`.
#[cfg(feature = "bls")]
#[no_mangle]
pub unsafe extern "C" fn bls_account_derive_private_key_from_mnemonic(
    account: *const FFIBLSAccount,
    mnemonic: *const c_char,
    passphrase: *const c_char,
    index: c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    if account.is_null() || mnemonic.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }
    let account = &*account;
    let mnemonic_str = match std::ffi::CStr::from_ptr(mnemonic).to_str() {
        Ok(s) => s,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Invalid mnemonic string".into(),
            );
            return ptr::null_mut();
        }
    };
    let passphrase_str = if passphrase.is_null() {
        None
    } else {
        match std::ffi::CStr::from_ptr(passphrase).to_str() {
            Ok(s) => Some(s),
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid passphrase string".into(),
                );
                return ptr::null_mut();
            }
        }
    };
    match account.inner().derive_from_mnemonic_private_key_at(
        mnemonic_str,
        passphrase_str,
        key_wallet::mnemonic::Language::English,
        index,
    ) {
        Ok(sk) => {
            let hex = hex::encode(sk.to_be_bytes());
            match CString::new(hex) {
                Ok(s) => {
                    FFIError::set_success(error);
                    s.into_raw()
                }
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::AllocationFailed,
                        "Allocation failed".into(),
                    );
                    ptr::null_mut()
                }
            }
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to derive BLS private key from mnemonic: {:?}", e),
            );
            ptr::null_mut()
        }
    }
}

// ========================= EdDSA (feature = "eddsa") =========================
/// Derive an EdDSA (ed25519) private key from a raw seed buffer at the given index.
///
/// Returns a newly allocated hex string of the 32-byte private key. The caller must free
/// it with `string_free`.
///
/// Notes:
/// - EdDSA only supports hardened derivation; the index will be used accordingly.
/// - Chain-agnostic; EdDSA accounts typically do not have internal/external split.
///
/// # Safety
/// - `account` must be a valid, non-null pointer to an `FFIEdDSAAccount` (only when `eddsa` feature is enabled).
/// - `seed` must point to a readable buffer of length `seed_len` (1..=64 bytes expected).
/// - `error` must be a valid pointer to an FFIError or null.
/// - Returned string must be freed with `string_free`.
#[cfg(feature = "eddsa")]
#[no_mangle]
pub unsafe extern "C" fn eddsa_account_derive_private_key_from_seed(
    account: *const FFIEdDSAAccount,
    seed: *const u8,
    seed_len: usize,
    index: c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    if account.is_null() || seed.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }
    let account = &*account;
    let seed_slice = std::slice::from_raw_parts(seed, seed_len);
    match account.inner().derive_from_seed_private_key_at(seed_slice, index) {
        Ok(sk) => {
            // Return 32-byte ed25519 seed/private key as hex
            let hex = hex::encode(sk.to_bytes());
            match CString::new(hex) {
                Ok(s) => {
                    FFIError::set_success(error);
                    s.into_raw()
                }
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::AllocationFailed,
                        "Allocation failed".into(),
                    );
                    ptr::null_mut()
                }
            }
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to derive EdDSA private key from seed: {:?}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Derive an EdDSA (ed25519) private key from a mnemonic + optional passphrase at the given index.
///
/// Returns a newly allocated hex string of the 32-byte private key. The caller must free
/// it with `string_free`.
///
/// Notes:
/// - Uses the English wordlist for parsing the mnemonic.
///
/// # Safety
/// - `account` must be a valid, non-null pointer to an `FFIEdDSAAccount` (only when `eddsa` feature is enabled).
/// - `mnemonic` must be a valid, null-terminated UTF-8 C string.
/// - `passphrase` may be null; if not null, must be a valid UTF-8 C string.
/// - `error` must be a valid pointer to an FFIError or null.
/// - Returned string must be freed with `string_free`.
#[cfg(feature = "eddsa")]
#[no_mangle]
pub unsafe extern "C" fn eddsa_account_derive_private_key_from_mnemonic(
    account: *const FFIEdDSAAccount,
    mnemonic: *const c_char,
    passphrase: *const c_char,
    index: c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    if account.is_null() || mnemonic.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }
    let account = &*account;
    let mnemonic_str = match std::ffi::CStr::from_ptr(mnemonic).to_str() {
        Ok(s) => s,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Invalid mnemonic string".into(),
            );
            return ptr::null_mut();
        }
    };
    let passphrase_str = if passphrase.is_null() {
        None
    } else {
        match std::ffi::CStr::from_ptr(passphrase).to_str() {
            Ok(s) => Some(s),
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid passphrase string".into(),
                );
                return ptr::null_mut();
            }
        }
    };
    match account.inner().derive_from_mnemonic_private_key_at(
        mnemonic_str,
        passphrase_str,
        key_wallet::mnemonic::Language::English,
        index,
    ) {
        Ok(sk) => {
            let hex = hex::encode(sk.to_bytes());
            match CString::new(hex) {
                Ok(s) => {
                    FFIError::set_success(error);
                    s.into_raw()
                }
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::AllocationFailed,
                        "Allocation failed".into(),
                    );
                    ptr::null_mut()
                }
            }
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to derive EdDSA private key from mnemonic: {:?}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Derive a private key (secp256k1) from an account at a given chain/index, using the provided master xpriv.
/// Returns an opaque FFIPrivateKey pointer that must be freed with `private_key_free`.
///
/// # Safety
/// - `account` and `master_xpriv` must be valid pointers allocated by this library
/// - `error` must be a valid pointer to an FFIError or null
#[no_mangle]
pub unsafe extern "C" fn account_derive_private_key_at(
    account: *const FFIAccount,
    master_xpriv: *const FFIExtendedPrivateKey,
    index: c_uint,
    error: *mut FFIError,
) -> *mut FFIPrivateKey {
    if account.is_null() || master_xpriv.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let account = &*account;
    let master_xpriv = &*master_xpriv;

    if account.inner().is_watch_only() {
        FFIError::set_error(
            error,
            FFIErrorCode::WalletError,
            "Account is watch-only; private derivation not allowed".to_string(),
        );
        return ptr::null_mut();
    }

    match account.inner().derive_from_master_xpriv_extended_xpriv_at(master_xpriv.inner(), index) {
        Ok(derived) => {
            FFIError::set_success(error);
            Box::into_raw(Box::new(FFIPrivateKey::from_secret(derived.private_key)))
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to derive private key: {:?}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Derive a private key from an account at a given chain/index and return as WIF string.
/// Caller must free the returned string with `string_free`.
///
/// # Safety
/// - `account` and `master_xpriv` must be valid pointers allocated by this library
/// - `error` must be a valid pointer to an FFIError or null
#[no_mangle]
pub unsafe extern "C" fn account_derive_private_key_as_wif_at(
    account: *const FFIAccount,
    master_xpriv: *const FFIExtendedPrivateKey,
    index: c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    if account.is_null() || master_xpriv.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let account = &*account;
    let master_xpriv = &*master_xpriv;

    if account.inner().is_watch_only() {
        FFIError::set_error(
            error,
            FFIErrorCode::WalletError,
            "Account is watch-only; private derivation not allowed".to_string(),
        );
        return ptr::null_mut();
    }

    match account.inner().derive_from_master_xpriv_extended_xpriv_at(master_xpriv.inner(), index) {
        Ok(derived) => {
            // Wrap into dashcore::PrivateKey to WIF encode
            let dash_priv = dashcore::PrivateKey {
                compressed: true,
                network: account.inner().network(),
                inner: derived.private_key,
            };
            match CString::new(dash_priv.to_wif()) {
                Ok(c_str) => {
                    FFIError::set_success(error);
                    c_str.into_raw()
                }
                Err(_) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::AllocationFailed,
                        "Failed to allocate WIF string".to_string(),
                    );
                    ptr::null_mut()
                }
            }
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to derive private key: {:?}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Derive an extended private key from a raw seed buffer at the given index.
/// Returns an opaque FFIExtendedPrivateKey pointer that must be freed with `extended_private_key_free`.
///
/// # Safety
/// - `account` must be a valid pointer to an FFIAccount
/// - `seed` must point to a valid buffer of length `seed_len`
/// - `error` must be a valid pointer to an FFIError or null
#[no_mangle]
pub unsafe extern "C" fn account_derive_extended_private_key_from_seed(
    account: *const FFIAccount,
    seed: *const u8,
    seed_len: usize,
    index: c_uint,
    error: *mut FFIError,
) -> *mut FFIExtendedPrivateKey {
    if account.is_null() || seed.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let account = &*account;
    let seed_slice = std::slice::from_raw_parts(seed, seed_len);

    match account.inner().derive_from_seed_extended_xpriv_at(seed_slice, index) {
        Ok(derived) => {
            FFIError::set_success(error);
            Box::into_raw(Box::new(FFIExtendedPrivateKey::from_inner(derived)))
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to derive extended private key from seed: {:?}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Derive a private key from a raw seed buffer at the given index.
/// Returns an opaque FFIPrivateKey pointer that must be freed with `private_key_free`.
///
/// # Safety
/// - `account` must be a valid pointer to an FFIAccount
/// - `seed` must point to a valid buffer of length `seed_len`
/// - `error` must be a valid pointer to an FFIError or null
#[no_mangle]
pub unsafe extern "C" fn account_derive_private_key_from_seed(
    account: *const FFIAccount,
    seed: *const u8,
    seed_len: usize,
    index: c_uint,
    error: *mut FFIError,
) -> *mut FFIPrivateKey {
    if account.is_null() || seed.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let account = &*account;
    let seed_slice = std::slice::from_raw_parts(seed, seed_len);

    match account.inner().derive_from_seed_extended_xpriv_at(seed_slice, index) {
        Ok(derived) => {
            FFIError::set_success(error);
            Box::into_raw(Box::new(FFIPrivateKey::from_secret(derived.private_key)))
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to derive private key from seed: {:?}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Derive an extended private key from a mnemonic + optional passphrase at the given index.
/// Returns an opaque FFIExtendedPrivateKey pointer that must be freed with `extended_private_key_free`.
///
/// # Safety
/// - `account` must be a valid pointer to an FFIAccount
/// - `mnemonic` must be a valid, null-terminated C string
/// - `passphrase` may be null; if not null, must be a valid C string
/// - `error` must be a valid pointer to an FFIError or null
#[no_mangle]
pub unsafe extern "C" fn account_derive_extended_private_key_from_mnemonic(
    account: *const FFIAccount,
    mnemonic: *const c_char,
    passphrase: *const c_char,
    index: c_uint,
    error: *mut FFIError,
) -> *mut FFIExtendedPrivateKey {
    if account.is_null() || mnemonic.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let account = &*account;
    let mnemonic_str = match std::ffi::CStr::from_ptr(mnemonic).to_str() {
        Ok(s) => s,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Invalid mnemonic string".to_string(),
            );
            return ptr::null_mut();
        }
    };
    let passphrase_str = if passphrase.is_null() {
        None
    } else {
        match std::ffi::CStr::from_ptr(passphrase).to_str() {
            Ok(s) => Some(s),
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid passphrase string".to_string(),
                );
                return ptr::null_mut();
            }
        }
    };

    match account.inner().derive_from_mnemonic_extended_xpriv_at(
        mnemonic_str,
        passphrase_str,
        key_wallet::mnemonic::Language::English,
        index,
    ) {
        Ok(derived) => {
            FFIError::set_success(error);
            Box::into_raw(Box::new(FFIExtendedPrivateKey::from_inner(derived)))
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to derive extended private key from mnemonic: {:?}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Derive a private key from a mnemonic + optional passphrase at the given index.
/// Returns an opaque FFIPrivateKey pointer that must be freed with `private_key_free`.
///
/// # Safety
/// - `account` must be a valid pointer to an FFIAccount
/// - `mnemonic` must be a valid, null-terminated C string
/// - `passphrase` may be null; if not null, must be a valid C string
/// - `error` must be a valid pointer to an FFIError or null
#[no_mangle]
pub unsafe extern "C" fn account_derive_private_key_from_mnemonic(
    account: *const FFIAccount,
    mnemonic: *const c_char,
    passphrase: *const c_char,
    index: c_uint,
    error: *mut FFIError,
) -> *mut FFIPrivateKey {
    if account.is_null() || mnemonic.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let account = &*account;
    let mnemonic_str = match std::ffi::CStr::from_ptr(mnemonic).to_str() {
        Ok(s) => s,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Invalid mnemonic string".to_string(),
            );
            return ptr::null_mut();
        }
    };
    let passphrase_str = if passphrase.is_null() {
        None
    } else {
        match std::ffi::CStr::from_ptr(passphrase).to_str() {
            Ok(s) => Some(s),
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid passphrase string".to_string(),
                );
                return ptr::null_mut();
            }
        }
    };

    match account.inner().derive_from_mnemonic_extended_xpriv_at(
        mnemonic_str,
        passphrase_str,
        key_wallet::mnemonic::Language::English,
        index,
    ) {
        Ok(derived) => {
            FFIError::set_success(error);
            Box::into_raw(Box::new(FFIPrivateKey::from_secret(derived.private_key)))
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to derive private key from mnemonic: {:?}", e),
            );
            ptr::null_mut()
        }
    }
}
