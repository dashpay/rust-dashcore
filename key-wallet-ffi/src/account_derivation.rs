//! Account-level derivation functions exposed over FFI

use crate::account::FFIAccount;
#[cfg(feature = "bls")]
use crate::account::FFIBLSAccount;
#[cfg(feature = "eddsa")]
use crate::account::FFIEdDSAAccount;
use crate::error::{FFIError, FFIErrorCode};
use crate::keys::{FFIExtendedPrivKey, FFIPrivateKey};
use crate::{check_ptr, deref_ptr, unwrap_or_return};
use key_wallet::account::derivation::AccountDerivation;
use key_wallet::account::AccountTrait;
use std::ffi::CString;
use std::os::raw::{c_char, c_uint};
use std::ptr;

// No extra FFI enum for chain selection; account semantics decide path.

/// Derive an extended private key from an account at a given index, using the provided master xpriv.
///
/// Returns an opaque FFIExtendedPrivKey pointer that must be freed with `extended_private_key_free`.
///
/// Notes:
/// - This is chain-agnostic. For accounts with internal/external chains, this returns an error.
/// - For hardened-only account types (e.g., EdDSA), a hardened index is used.
///
/// # Safety
/// - `account` and `master_xpriv` must be valid, non-null pointers allocated by this library.
/// - `error` must be a valid pointer to an FFIError.
/// - The caller must free the returned pointer with `extended_private_key_free`.
#[no_mangle]
pub unsafe extern "C" fn account_derive_extended_private_key_at(
    account: *const FFIAccount,
    master_xpriv: *const FFIExtendedPrivKey,
    index: c_uint,
    error: *mut FFIError,
) -> *mut FFIExtendedPrivKey {
    let account = deref_ptr!(account, error);
    let master_xpriv = deref_ptr!(master_xpriv, error);

    if account.inner().is_watch_only() {
        (*error).set(
            FFIErrorCode::WalletError,
            "Account is watch-only; private derivation not allowed",
        );
        return ptr::null_mut();
    }

    let derived = unwrap_or_return!(
        account.inner().derive_from_master_xpriv_extended_xpriv_at(master_xpriv.inner(), index),
        error
    );
    Box::into_raw(Box::new(FFIExtendedPrivKey::from_inner(derived)))
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
/// - `error` must be a valid pointer to an FFIError.
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
    let account = deref_ptr!(account, error);
    check_ptr!(seed, error);
    if seed_len == 0 || seed_len > 64 {
        (*error).set(FFIErrorCode::InvalidInput, "Seed length must be between 1 and 64 bytes");
        return ptr::null_mut();
    }
    let seed_slice = std::slice::from_raw_parts(seed, seed_len);
    let sk = unwrap_or_return!(
        account.inner().derive_from_seed_private_key_at(seed_slice, index),
        error
    );
    unwrap_or_return!(CString::new(hex::encode(sk.to_be_bytes())), error).into_raw()
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
/// - `error` must be a valid pointer to an FFIError.
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
    let account = deref_ptr!(account, error);
    let mnemonic = deref_ptr!(mnemonic, error);
    let mnemonic_str = unwrap_or_return!(std::ffi::CStr::from_ptr(mnemonic).to_str(), error);
    let passphrase_str = if passphrase.is_null() {
        None
    } else {
        Some(unwrap_or_return!(std::ffi::CStr::from_ptr(passphrase).to_str(), error))
    };
    let sk = unwrap_or_return!(
        account.inner().derive_from_mnemonic_private_key_at(
            mnemonic_str,
            passphrase_str,
            key_wallet::mnemonic::Language::English,
            index,
        ),
        error
    );
    unwrap_or_return!(CString::new(hex::encode(sk.to_be_bytes())), error).into_raw()
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
/// - `error` must be a valid pointer to an FFIError.
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
    let account = deref_ptr!(account, error);
    check_ptr!(seed, error);
    let seed_slice = std::slice::from_raw_parts(seed, seed_len);
    let sk = unwrap_or_return!(
        account.inner().derive_from_seed_private_key_at(seed_slice, index),
        error
    );
    unwrap_or_return!(CString::new(hex::encode(sk.to_bytes())), error).into_raw()
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
/// - `error` must be a valid pointer to an FFIError.
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
    let account = deref_ptr!(account, error);
    let mnemonic = deref_ptr!(mnemonic, error);
    let mnemonic_str = unwrap_or_return!(std::ffi::CStr::from_ptr(mnemonic).to_str(), error);
    let passphrase_str = if passphrase.is_null() {
        None
    } else {
        Some(unwrap_or_return!(std::ffi::CStr::from_ptr(passphrase).to_str(), error))
    };
    let sk = unwrap_or_return!(
        account.inner().derive_from_mnemonic_private_key_at(
            mnemonic_str,
            passphrase_str,
            key_wallet::mnemonic::Language::English,
            index,
        ),
        error
    );
    unwrap_or_return!(CString::new(hex::encode(sk.to_bytes())), error).into_raw()
}

/// Derive a private key (secp256k1) from an account at a given chain/index, using the provided master xpriv.
/// Returns an opaque FFIPrivateKey pointer that must be freed with `private_key_free`.
///
/// # Safety
/// - `account` and `master_xpriv` must be valid pointers allocated by this library
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn account_derive_private_key_at(
    account: *const FFIAccount,
    master_xpriv: *const FFIExtendedPrivKey,
    index: c_uint,
    error: *mut FFIError,
) -> *mut FFIPrivateKey {
    let account = deref_ptr!(account, error);
    let master_xpriv = deref_ptr!(master_xpriv, error);

    if account.inner().is_watch_only() {
        (*error).set(
            FFIErrorCode::WalletError,
            "Account is watch-only; private derivation not allowed",
        );
        return ptr::null_mut();
    }

    let derived = unwrap_or_return!(
        account.inner().derive_from_master_xpriv_extended_xpriv_at(master_xpriv.inner(), index),
        error
    );
    Box::into_raw(Box::new(FFIPrivateKey::from_secret(derived.private_key)))
}

/// Derive a private key from an account at a given chain/index and return as WIF string.
/// Caller must free the returned string with `string_free`.
///
/// # Safety
/// - `account` and `master_xpriv` must be valid pointers allocated by this library
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn account_derive_private_key_as_wif_at(
    account: *const FFIAccount,
    master_xpriv: *const FFIExtendedPrivKey,
    index: c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    let account = deref_ptr!(account, error);
    let master_xpriv = deref_ptr!(master_xpriv, error);

    if account.inner().is_watch_only() {
        (*error).set(
            FFIErrorCode::WalletError,
            "Account is watch-only; private derivation not allowed",
        );
        return ptr::null_mut();
    }

    let derived = unwrap_or_return!(
        account.inner().derive_from_master_xpriv_extended_xpriv_at(master_xpriv.inner(), index),
        error
    );
    let dash_priv = dashcore::PrivateKey {
        compressed: true,
        network: account.inner().network(),
        inner: derived.private_key,
    };
    unwrap_or_return!(CString::new(dash_priv.to_wif()), error).into_raw()
}

/// Derive an extended private key from a raw seed buffer at the given index.
/// Returns an opaque FFIExtendedPrivKey pointer that must be freed with `extended_private_key_free`.
///
/// # Safety
/// - `account` must be a valid pointer to an FFIAccount
/// - `seed` must point to a valid buffer of length `seed_len`
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn account_derive_extended_private_key_from_seed(
    account: *const FFIAccount,
    seed: *const u8,
    seed_len: usize,
    index: c_uint,
    error: *mut FFIError,
) -> *mut FFIExtendedPrivKey {
    let account = deref_ptr!(account, error);
    check_ptr!(seed, error);
    let seed_slice = std::slice::from_raw_parts(seed, seed_len);
    let derived = unwrap_or_return!(
        account.inner().derive_from_seed_extended_xpriv_at(seed_slice, index),
        error
    );
    Box::into_raw(Box::new(FFIExtendedPrivKey::from_inner(derived)))
}

/// Derive a private key from a raw seed buffer at the given index.
/// Returns an opaque FFIPrivateKey pointer that must be freed with `private_key_free`.
///
/// # Safety
/// - `account` must be a valid pointer to an FFIAccount
/// - `seed` must point to a valid buffer of length `seed_len`
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn account_derive_private_key_from_seed(
    account: *const FFIAccount,
    seed: *const u8,
    seed_len: usize,
    index: c_uint,
    error: *mut FFIError,
) -> *mut FFIPrivateKey {
    let account = deref_ptr!(account, error);
    check_ptr!(seed, error);
    let seed_slice = std::slice::from_raw_parts(seed, seed_len);
    let derived = unwrap_or_return!(
        account.inner().derive_from_seed_extended_xpriv_at(seed_slice, index),
        error
    );
    Box::into_raw(Box::new(FFIPrivateKey::from_secret(derived.private_key)))
}

/// Derive an extended private key from a mnemonic + optional passphrase at the given index.
/// Returns an opaque FFIExtendedPrivKey pointer that must be freed with `extended_private_key_free`.
///
/// # Safety
/// - `account` must be a valid pointer to an FFIAccount
/// - `mnemonic` must be a valid, null-terminated C string
/// - `passphrase` may be null; if not null, must be a valid C string
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn account_derive_extended_private_key_from_mnemonic(
    account: *const FFIAccount,
    mnemonic: *const c_char,
    passphrase: *const c_char,
    index: c_uint,
    error: *mut FFIError,
) -> *mut FFIExtendedPrivKey {
    let account = deref_ptr!(account, error);
    let mnemonic = deref_ptr!(mnemonic, error);
    let mnemonic_str = unwrap_or_return!(std::ffi::CStr::from_ptr(mnemonic).to_str(), error);
    let passphrase_str = if passphrase.is_null() {
        None
    } else {
        Some(unwrap_or_return!(std::ffi::CStr::from_ptr(passphrase).to_str(), error))
    };
    let derived = unwrap_or_return!(
        account.inner().derive_from_mnemonic_extended_xpriv_at(
            mnemonic_str,
            passphrase_str,
            key_wallet::mnemonic::Language::English,
            index,
        ),
        error
    );
    Box::into_raw(Box::new(FFIExtendedPrivKey::from_inner(derived)))
}

/// Derive a private key from a mnemonic + optional passphrase at the given index.
/// Returns an opaque FFIPrivateKey pointer that must be freed with `private_key_free`.
///
/// # Safety
/// - `account` must be a valid pointer to an FFIAccount
/// - `mnemonic` must be a valid, null-terminated C string
/// - `passphrase` may be null; if not null, must be a valid C string
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn account_derive_private_key_from_mnemonic(
    account: *const FFIAccount,
    mnemonic: *const c_char,
    passphrase: *const c_char,
    index: c_uint,
    error: *mut FFIError,
) -> *mut FFIPrivateKey {
    let account = deref_ptr!(account, error);
    let mnemonic = deref_ptr!(mnemonic, error);
    let mnemonic_str = unwrap_or_return!(std::ffi::CStr::from_ptr(mnemonic).to_str(), error);
    let passphrase_str = if passphrase.is_null() {
        None
    } else {
        Some(unwrap_or_return!(std::ffi::CStr::from_ptr(passphrase).to_str(), error))
    };
    let derived = unwrap_or_return!(
        account.inner().derive_from_mnemonic_extended_xpriv_at(
            mnemonic_str,
            passphrase_str,
            key_wallet::mnemonic::Language::English,
            index,
        ),
        error
    );
    Box::into_raw(Box::new(FFIPrivateKey::from_secret(derived.private_key)))
}

#[cfg(test)]
#[path = "account_derivation_tests.rs"]
mod account_derivation_tests;
