//! BIP32 and DIP9 derivation path functions

use crate::error::{FFIError, FFIErrorCode};
use crate::keys::FFIExtendedPrivKey;
use crate::keys::FFIExtendedPubKey;
use crate::{check_ptr, deref_ptr, unwrap_or_return};
use dashcore::ffi::FFINetwork;
use dashcore::Network;
use key_wallet::{ExtendedPrivKey, ExtendedPubKey};
use secp256k1::Secp256k1;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};
use std::ptr;
use std::slice;

/// Derivation path type for DIP9
#[repr(C)]
#[derive(Clone, Copy)]
pub enum FFIDerivationPathType {
    PathUnknown = 0,
    PathBIP32 = 1,
    PathBIP44 = 2,
    PathBlockchainIdentities = 3,
    PathProviderFunds = 4,
    PathProviderVotingKeys = 5,
    PathProviderOperatorKeys = 6,
    PathProviderOwnerKeys = 7,
    PathContactBasedFunds = 8,
    PathContactBasedFundsRoot = 9,
    PathContactBasedFundsExternal = 10,
    PathBlockchainIdentityCreditRegistrationFunding = 11,
    PathBlockchainIdentityCreditTopupFunding = 12,
    PathBlockchainIdentityCreditInvitationFunding = 13,
    PathProviderPlatformNodeKeys = 14,
    PathCoinJoin = 15,
    PathRoot = 255,
}

/// Create a new master extended private key from seed
///
/// # Safety
///
/// - `seed` must be a valid pointer to a byte array of `seed_len` length
/// - `error` must be a valid pointer to an FFIError structure
/// - The caller must ensure the seed pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn derivation_new_master_key(
    seed: *const u8,
    seed_len: usize,
    network: FFINetwork,
    error: *mut FFIError,
) -> *mut FFIExtendedPrivKey {
    check_ptr!(seed, error);
    let seed_slice = slice::from_raw_parts(seed, seed_len);
    let network_rust: key_wallet::Network = network.into();
    let xpriv = unwrap_or_return!(
        key_wallet::bip32::ExtendedPrivKey::new_master(network_rust, seed_slice),
        error
    );
    Box::into_raw(Box::new(FFIExtendedPrivKey::from_inner(xpriv)))
}

/// Derive a BIP44 account path (m/44'/5'/account')
///
/// # Safety
///
/// `path_out` must point to a writable buffer of at least `path_max_len` bytes
/// and `error` must be a valid pointer to an `FFIError`.
#[no_mangle]
pub unsafe extern "C" fn derivation_bip44_account_path(
    network: FFINetwork,
    account_index: c_uint,
    path_out: *mut c_char,
    path_max_len: usize,
    error: *mut FFIError,
) -> bool {
    check_ptr!(path_out, error);

    let network_rust: key_wallet::Network = network.into();

    use key_wallet::bip32::DerivationPath;
    let derivation = DerivationPath::bip_44_account(network_rust, account_index);

    let path_str = format!("{}", derivation);

    let c_string = unwrap_or_return!(CString::new(path_str), error);

    let bytes = c_string.as_bytes_with_nul();
    if bytes.len() > path_max_len {
        (*error).set(
            FFIErrorCode::InvalidInput,
            &format!("Path too long: {} > {}", bytes.len(), path_max_len),
        );
        return false;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), path_out.cast::<u8>(), bytes.len());
    }
    true
}

/// Derive a BIP44 payment path (m/44'/5'/account'/change/index)
///
/// # Safety
///
/// `path_out` must point to a writable buffer of at least `path_max_len` bytes
/// and `error` must be a valid pointer to an `FFIError`.
#[no_mangle]
pub unsafe extern "C" fn derivation_bip44_payment_path(
    network: FFINetwork,
    account_index: c_uint,
    is_change: bool,
    address_index: c_uint,
    path_out: *mut c_char,
    path_max_len: usize,
    error: *mut FFIError,
) -> bool {
    check_ptr!(path_out, error);

    let network_rust: key_wallet::Network = network.into();

    use key_wallet::bip32::DerivationPath;
    let derivation =
        DerivationPath::bip_44_payment_path(network_rust, account_index, is_change, address_index);

    let path_str = format!("{}", derivation);

    let c_string = unwrap_or_return!(CString::new(path_str), error);

    let bytes = c_string.as_bytes_with_nul();
    if bytes.len() > path_max_len {
        (*error).set(
            FFIErrorCode::InvalidInput,
            &format!("Path too long: {} > {}", bytes.len(), path_max_len),
        );
        return false;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), path_out.cast::<u8>(), bytes.len());
    }
    true
}

/// Derive CoinJoin path (m/9'/5'/4'/account')
///
/// # Safety
///
/// `path_out` must point to a writable buffer of at least `path_max_len` bytes
/// and `error` must be a valid pointer to an `FFIError`.
#[no_mangle]
pub unsafe extern "C" fn derivation_coinjoin_path(
    network: FFINetwork,
    account_index: c_uint,
    path_out: *mut c_char,
    path_max_len: usize,
    error: *mut FFIError,
) -> bool {
    check_ptr!(path_out, error);

    let network_rust: key_wallet::Network = network.into();

    use key_wallet::bip32::DerivationPath;
    let derivation = DerivationPath::coinjoin_path(network_rust, account_index);

    let path_str = format!("{}", derivation);

    let c_string = unwrap_or_return!(CString::new(path_str), error);

    let bytes = c_string.as_bytes_with_nul();
    if bytes.len() > path_max_len {
        (*error).set(
            FFIErrorCode::InvalidInput,
            &format!("Path too long: {} > {}", bytes.len(), path_max_len),
        );
        return false;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), path_out.cast::<u8>(), bytes.len());
    }
    true
}

/// Derive identity registration path (m/9'/5'/5'/1'/index')
///
/// # Safety
///
/// `path_out` must point to a writable buffer of at least `path_max_len` bytes
/// and `error` must be a valid pointer to an `FFIError`.
#[no_mangle]
pub unsafe extern "C" fn derivation_identity_registration_path(
    network: FFINetwork,
    identity_index: c_uint,
    path_out: *mut c_char,
    path_max_len: usize,
    error: *mut FFIError,
) -> bool {
    check_ptr!(path_out, error);

    let network_rust: key_wallet::Network = network.into();

    use key_wallet::bip32::DerivationPath;
    let derivation = DerivationPath::identity_registration_path(network_rust, identity_index);

    let path_str = format!("{}", derivation);

    let c_string = unwrap_or_return!(CString::new(path_str), error);

    let bytes = c_string.as_bytes_with_nul();
    if bytes.len() > path_max_len {
        (*error).set(
            FFIErrorCode::InvalidInput,
            &format!("Path too long: {} > {}", bytes.len(), path_max_len),
        );
        return false;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), path_out.cast::<u8>(), bytes.len());
    }
    true
}

/// Derive identity top-up path (m/9'/5'/5'/2'/identity_index'/top_up_index')
///
/// # Safety
///
/// `path_out` must point to a writable buffer of at least `path_max_len` bytes
/// and `error` must be a valid pointer to an `FFIError`.
#[no_mangle]
pub unsafe extern "C" fn derivation_identity_topup_path(
    network: FFINetwork,
    identity_index: c_uint,
    topup_index: c_uint,
    path_out: *mut c_char,
    path_max_len: usize,
    error: *mut FFIError,
) -> bool {
    check_ptr!(path_out, error);

    let network_rust: key_wallet::Network = network.into();

    use key_wallet::bip32::DerivationPath;
    let derivation =
        DerivationPath::identity_top_up_path(network_rust, identity_index, topup_index);

    let path_str = format!("{}", derivation);

    let c_string = unwrap_or_return!(CString::new(path_str), error);

    let bytes = c_string.as_bytes_with_nul();
    if bytes.len() > path_max_len {
        (*error).set(
            FFIErrorCode::InvalidInput,
            &format!("Path too long: {} > {}", bytes.len(), path_max_len),
        );
        return false;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), path_out.cast::<u8>(), bytes.len());
    }
    true
}

/// Derive identity authentication path (m/9'/5'/5'/0'/identity_index'/key_index')
///
/// # Safety
///
/// `path_out` must point to a writable buffer of at least `path_max_len` bytes
/// and `error` must be a valid pointer to an `FFIError`.
#[no_mangle]
pub unsafe extern "C" fn derivation_identity_authentication_path(
    network: FFINetwork,
    identity_index: c_uint,
    key_index: c_uint,
    path_out: *mut c_char,
    path_max_len: usize,
    error: *mut FFIError,
) -> bool {
    check_ptr!(path_out, error);

    let network_rust: key_wallet::Network = network.into();

    use key_wallet::bip32::{DerivationPath, KeyDerivationType};
    let derivation = DerivationPath::identity_authentication_path(
        network_rust,
        KeyDerivationType::ECDSA, // Using ECDSA for authentication keys
        identity_index,
        key_index,
    );

    let path_str = format!("{}", derivation);

    let c_string = unwrap_or_return!(CString::new(path_str), error);

    let bytes = c_string.as_bytes_with_nul();
    if bytes.len() > path_max_len {
        (*error).set(
            FFIErrorCode::InvalidInput,
            &format!("Path too long: {} > {}", bytes.len(), path_max_len),
        );
        return false;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), path_out.cast::<u8>(), bytes.len());
    }
    true
}

/// Derive private key for a specific path from seed
///
/// # Safety
///
/// - `seed` must be a valid pointer to a byte array of `seed_len` length
/// - `path` must be a valid pointer to a null-terminated C string
/// - `error` must be a valid pointer to an FFIError structure
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn derivation_derive_private_key_from_seed(
    seed: *const u8,
    seed_len: usize,
    path: *const c_char,
    network: FFINetwork,
    error: *mut FFIError,
) -> *mut FFIExtendedPrivKey {
    use key_wallet::bip32::{DerivationPath, ExtendedPrivKey};
    use std::str::FromStr;

    check_ptr!(seed, error);
    let path = deref_ptr!(path, error);

    let seed_slice = slice::from_raw_parts(seed, seed_len);
    let network_rust: Network = network.into();
    let path_str = unwrap_or_return!(CStr::from_ptr(path).to_str(), error);
    let derivation_path = unwrap_or_return!(DerivationPath::from_str(path_str), error);

    let secp = Secp256k1::new();
    let master = unwrap_or_return!(ExtendedPrivKey::new_master(network_rust, seed_slice), error);
    let xpriv = unwrap_or_return!(master.derive_priv(&secp, &derivation_path), error);
    Box::into_raw(Box::new(FFIExtendedPrivKey::from_inner(xpriv)))
}

/// Derive public key from extended private key
///
/// # Safety
///
/// - `xpriv` must be a valid pointer to an FFIExtendedPrivKey
/// - `error` must be a valid pointer to an FFIError
/// - The returned pointer must be freed with `extended_public_key_free`
#[no_mangle]
pub unsafe extern "C" fn derivation_xpriv_to_xpub(
    xpriv: *const FFIExtendedPrivKey,
    error: *mut FFIError,
) -> *mut FFIExtendedPubKey {
    use key_wallet::bip32::ExtendedPubKey;
    let xpriv = deref_ptr!(xpriv, error);
    let secp = Secp256k1::new();
    let xpub = ExtendedPubKey::from_priv(&secp, xpriv.inner());
    Box::into_raw(Box::new(FFIExtendedPubKey::from_inner(xpub)))
}

/// Get extended private key as string
///
/// # Safety
///
/// - `xpriv` must be a valid pointer to an FFIExtendedPrivKey
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed with `string_free`
#[no_mangle]
pub unsafe extern "C" fn derivation_xpriv_to_string(
    xpriv: *const FFIExtendedPrivKey,
    error: *mut FFIError,
) -> *mut c_char {
    let xpriv = deref_ptr!(xpriv, error);
    unwrap_or_return!(CString::new(xpriv.inner().to_string()), error).into_raw()
}

/// Get extended public key as string
///
/// # Safety
///
/// - `xpub` must be a valid pointer to an FFIExtendedPubKey
/// - `error` must be a valid pointer to an FFIError
/// - The returned string must be freed with `string_free`
#[no_mangle]
pub unsafe extern "C" fn derivation_xpub_to_string(
    xpub: *const FFIExtendedPubKey,
    error: *mut FFIError,
) -> *mut c_char {
    let xpub = deref_ptr!(xpub, error);
    unwrap_or_return!(CString::new(xpub.inner().to_string()), error).into_raw()
}

/// Get fingerprint from extended public key (4 bytes)
///
/// # Safety
///
/// - `xpub` must be a valid pointer to an FFIExtendedPubKey
/// - `fingerprint_out` must be a valid pointer to a buffer of at least 4 bytes
/// - `error` must be a valid pointer to an FFIError
#[no_mangle]
pub unsafe extern "C" fn derivation_xpub_fingerprint(
    xpub: *const FFIExtendedPubKey,
    fingerprint_out: *mut u8,
    error: *mut FFIError,
) -> bool {
    let xpub = deref_ptr!(xpub, error);
    check_ptr!(fingerprint_out, error);
    let fingerprint = xpub.inner().fingerprint();
    let bytes = fingerprint.to_bytes();
    ptr::copy_nonoverlapping(bytes.as_ptr(), fingerprint_out, 4);
    true
}

/// Free extended private key
///
/// # Safety
///
/// - `xpriv` must be a valid pointer to an FFIExtendedPrivKey that was allocated by this library
/// - The pointer must not be used after calling this function
/// - This function must only be called once per allocation
#[no_mangle]
pub unsafe extern "C" fn derivation_xpriv_free(xpriv: *mut FFIExtendedPrivKey) {
    if !xpriv.is_null() {
        let _ = Box::from_raw(xpriv);
    }
}

/// Free extended public key
///
/// # Safety
///
/// - `xpub` must be a valid pointer to an FFIExtendedPubKey that was allocated by this library
/// - The pointer must not be used after calling this function
/// - This function must only be called once per allocation
#[no_mangle]
pub unsafe extern "C" fn derivation_xpub_free(xpub: *mut FFIExtendedPubKey) {
    if !xpub.is_null() {
        let _ = Box::from_raw(xpub);
    }
}

/// Free derivation path string
///
/// # Safety
///
/// - `s` must be a valid pointer to a C string that was allocated by this library
/// - The pointer must not be used after calling this function
/// - This function must only be called once per allocation
#[no_mangle]
pub unsafe extern "C" fn derivation_string_free(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}

// MARK: - Simplified Derivation Functions

/// Derive an address from a private key
///
/// # Safety
/// - `private_key` must be a valid pointer to 32 bytes
/// - `network` is the network for the address
///
/// # Returns
/// - Pointer to C string with address (caller must free)
/// - NULL on error
#[no_mangle]
pub unsafe extern "C" fn key_wallet_derive_address_from_key(
    private_key: *const u8,
    network: FFINetwork,
) -> *mut c_char {
    if private_key.is_null() {
        return ptr::null_mut();
    }

    let key_slice = slice::from_raw_parts(private_key, 32);

    // Create a secp256k1 private key
    let secp = Secp256k1::new();
    let secret_key = match secp256k1::SecretKey::from_slice(key_slice) {
        Ok(sk) => sk,
        Err(_) => return ptr::null_mut(),
    };

    // Get public key
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

    // Convert to dashcore PublicKey
    let dash_pubkey = dashcore::PublicKey::new(public_key);

    // Convert to Dash address
    let dash_network: key_wallet::Network = network.into();
    let address = key_wallet::Address::p2pkh(&dash_pubkey, dash_network);

    match CString::new(address.to_string()) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Derive an address from a seed at a specific derivation path
///
/// # Safety
/// - `seed` must be a valid pointer to 64 bytes
/// - `network` is the network for the address
/// - `path` must be a valid null-terminated C string (e.g., "m/44'/5'/0'/0/0")
///
/// # Returns
/// - Pointer to C string with address (caller must free)
/// - NULL on error
#[no_mangle]
pub unsafe extern "C" fn key_wallet_derive_address_from_seed(
    seed: *const u8,
    network: FFINetwork,
    path: *const c_char,
) -> *mut c_char {
    if seed.is_null() || path.is_null() {
        return ptr::null_mut();
    }

    let seed_slice = slice::from_raw_parts(seed, 64);
    let dash_network: key_wallet::Network = network.into();

    // Parse derivation path
    let path_str = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    use std::str::FromStr;
    let derivation_path = match key_wallet::DerivationPath::from_str(path_str) {
        Ok(dp) => dp,
        Err(_) => return ptr::null_mut(),
    };

    // Create master key from seed
    let master_key = match ExtendedPrivKey::new_master(dash_network, seed_slice) {
        Ok(xprv) => xprv,
        Err(_) => return ptr::null_mut(),
    };

    // Derive at path
    let secp = Secp256k1::new();
    let derived_key = match master_key.derive_priv(&secp, &derivation_path) {
        Ok(xprv) => xprv,
        Err(_) => return ptr::null_mut(),
    };

    // Get public key
    let extended_pubkey = ExtendedPubKey::from_priv(&secp, &derived_key);

    // Convert secp256k1::PublicKey to dashcore::PublicKey
    let dash_pubkey = dashcore::PublicKey::new(extended_pubkey.public_key);

    // Convert to address
    let address = key_wallet::Address::p2pkh(&dash_pubkey, dash_network);

    match CString::new(address.to_string()) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Derive a private key from a seed at a specific derivation path
///
/// # Safety
/// - `seed` must be a valid pointer to 64 bytes
/// - `path` must be a valid null-terminated C string (e.g., "m/44'/5'/0'/0/0")
/// - `key_out` must be a valid pointer to a buffer of at least 32 bytes
///
/// # Returns
/// - 0 on success
/// - -1 on error
#[no_mangle]
pub unsafe extern "C" fn key_wallet_derive_private_key_from_seed(
    seed: *const u8,
    path: *const c_char,
    key_out: *mut u8,
) -> i32 {
    if seed.is_null() || path.is_null() || key_out.is_null() {
        return -1;
    }

    let seed_slice = slice::from_raw_parts(seed, 64);

    // Parse derivation path
    let path_str = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    use std::str::FromStr;
    let derivation_path = match key_wallet::DerivationPath::from_str(path_str) {
        Ok(dp) => dp,
        Err(_) => return -1,
    };

    // Create master key from seed (use testnet as default, doesn't affect key derivation)
    let master_key = match ExtendedPrivKey::new_master(key_wallet::Network::Testnet, seed_slice) {
        Ok(xprv) => xprv,
        Err(_) => return -1,
    };

    // Derive at path
    let secp = Secp256k1::new();
    let derived_key = match master_key.derive_priv(&secp, &derivation_path) {
        Ok(xprv) => xprv,
        Err(_) => return -1,
    };

    // Copy private key bytes
    let key_bytes = derived_key.private_key.secret_bytes();
    ptr::copy_nonoverlapping(key_bytes.as_ptr(), key_out, 32);

    0
}

#[cfg(test)]
#[path = "derivation_tests.rs"]
mod tests;
