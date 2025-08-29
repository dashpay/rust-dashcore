//! BIP32 and DIP9 derivation path functions

use crate::error::{FFIError, FFIErrorCode};
use crate::types::FFINetworks;
use dash_network::Network;
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

/// Extended private key structure
pub struct FFIExtendedPrivKey {
    inner: key_wallet::bip32::ExtendedPrivKey,
}

/// Extended public key structure
pub struct FFIExtendedPubKey {
    inner: key_wallet::bip32::ExtendedPubKey,
}

/// Create a new master extended private key from seed
///
/// # Safety
///
/// - `seed` must be a valid pointer to a byte array of `seed_len` length
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure the seed pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn derivation_new_master_key(
    seed: *const u8,
    seed_len: usize,
    network: FFINetworks,
    error: *mut FFIError,
) -> *mut FFIExtendedPrivKey {
    if seed.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Seed is null".to_string());
        return ptr::null_mut();
    }

    let seed_slice = slice::from_raw_parts(seed, seed_len);
    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
            return ptr::null_mut();
        }
    };

    match key_wallet::bip32::ExtendedPrivKey::new_master(network_rust, seed_slice) {
        Ok(xpriv) => {
            FFIError::set_success(error);
            Box::into_raw(Box::new(FFIExtendedPrivKey {
                inner: xpriv,
            }))
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to create master key: {:?}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Derive a BIP44 account path (m/44'/5'/account')
#[no_mangle]
pub extern "C" fn derivation_bip44_account_path(
    network: FFINetworks,
    account_index: c_uint,
    path_out: *mut c_char,
    path_max_len: usize,
    error: *mut FFIError,
) -> bool {
    if path_out.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Path output buffer is null".to_string(),
        );
        return false;
    }

    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
            return false;
        }
    };

    use key_wallet::bip32::DerivationPath;
    let derivation = DerivationPath::bip_44_account(network_rust, account_index);

    let path_str = format!("{}", derivation);

    let c_string = match CString::new(path_str) {
        Ok(s) => s,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::AllocationFailed,
                "Failed to create C string".to_string(),
            );
            return false;
        }
    };

    let bytes = c_string.as_bytes_with_nul();
    if bytes.len() > path_max_len {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            format!("Path too long: {} > {}", bytes.len(), path_max_len),
        );
        return false;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), path_out as *mut u8, bytes.len());
    }

    FFIError::set_success(error);
    true
}

/// Derive a BIP44 payment path (m/44'/5'/account'/change/index)
#[no_mangle]
pub extern "C" fn derivation_bip44_payment_path(
    network: FFINetworks,
    account_index: c_uint,
    is_change: bool,
    address_index: c_uint,
    path_out: *mut c_char,
    path_max_len: usize,
    error: *mut FFIError,
) -> bool {
    if path_out.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Path output buffer is null".to_string(),
        );
        return false;
    }

    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
            return false;
        }
    };

    use key_wallet::bip32::DerivationPath;
    let derivation =
        DerivationPath::bip_44_payment_path(network_rust, account_index, is_change, address_index);

    let path_str = format!("{}", derivation);

    let c_string = match CString::new(path_str) {
        Ok(s) => s,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::AllocationFailed,
                "Failed to create C string".to_string(),
            );
            return false;
        }
    };

    let bytes = c_string.as_bytes_with_nul();
    if bytes.len() > path_max_len {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            format!("Path too long: {} > {}", bytes.len(), path_max_len),
        );
        return false;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), path_out as *mut u8, bytes.len());
    }

    FFIError::set_success(error);
    true
}

/// Derive CoinJoin path (m/9'/5'/4'/account')
#[no_mangle]
pub extern "C" fn derivation_coinjoin_path(
    network: FFINetworks,
    account_index: c_uint,
    path_out: *mut c_char,
    path_max_len: usize,
    error: *mut FFIError,
) -> bool {
    if path_out.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Path output buffer is null".to_string(),
        );
        return false;
    }

    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
            return false;
        }
    };

    use key_wallet::bip32::DerivationPath;
    let derivation = DerivationPath::coinjoin_path(network_rust, account_index);

    let path_str = format!("{}", derivation);

    let c_string = match CString::new(path_str) {
        Ok(s) => s,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::AllocationFailed,
                "Failed to create C string".to_string(),
            );
            return false;
        }
    };

    let bytes = c_string.as_bytes_with_nul();
    if bytes.len() > path_max_len {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            format!("Path too long: {} > {}", bytes.len(), path_max_len),
        );
        return false;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), path_out as *mut u8, bytes.len());
    }

    FFIError::set_success(error);
    true
}

/// Derive identity registration path (m/9'/5'/5'/1'/index')
#[no_mangle]
pub extern "C" fn derivation_identity_registration_path(
    network: FFINetworks,
    identity_index: c_uint,
    path_out: *mut c_char,
    path_max_len: usize,
    error: *mut FFIError,
) -> bool {
    if path_out.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Path output buffer is null".to_string(),
        );
        return false;
    }

    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
            return false;
        }
    };

    use key_wallet::bip32::DerivationPath;
    let derivation = DerivationPath::identity_registration_path(network_rust, identity_index);

    let path_str = format!("{}", derivation);

    let c_string = match CString::new(path_str) {
        Ok(s) => s,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::AllocationFailed,
                "Failed to create C string".to_string(),
            );
            return false;
        }
    };

    let bytes = c_string.as_bytes_with_nul();
    if bytes.len() > path_max_len {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            format!("Path too long: {} > {}", bytes.len(), path_max_len),
        );
        return false;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), path_out as *mut u8, bytes.len());
    }

    FFIError::set_success(error);
    true
}

/// Derive identity top-up path (m/9'/5'/5'/2'/identity_index'/top_up_index')
#[no_mangle]
pub extern "C" fn derivation_identity_topup_path(
    network: FFINetworks,
    identity_index: c_uint,
    topup_index: c_uint,
    path_out: *mut c_char,
    path_max_len: usize,
    error: *mut FFIError,
) -> bool {
    if path_out.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Path output buffer is null".to_string(),
        );
        return false;
    }

    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
            return false;
        }
    };

    use key_wallet::bip32::DerivationPath;
    let derivation =
        DerivationPath::identity_top_up_path(network_rust, identity_index, topup_index);

    let path_str = format!("{}", derivation);

    let c_string = match CString::new(path_str) {
        Ok(s) => s,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::AllocationFailed,
                "Failed to create C string".to_string(),
            );
            return false;
        }
    };

    let bytes = c_string.as_bytes_with_nul();
    if bytes.len() > path_max_len {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            format!("Path too long: {} > {}", bytes.len(), path_max_len),
        );
        return false;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), path_out as *mut u8, bytes.len());
    }

    FFIError::set_success(error);
    true
}

/// Derive identity authentication path (m/9'/5'/5'/0'/identity_index'/key_index')
#[no_mangle]
pub extern "C" fn derivation_identity_authentication_path(
    network: FFINetworks,
    identity_index: c_uint,
    key_index: c_uint,
    path_out: *mut c_char,
    path_max_len: usize,
    error: *mut FFIError,
) -> bool {
    if path_out.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Path output buffer is null".to_string(),
        );
        return false;
    }

    let network_rust: key_wallet::Network = match network.try_into() {
        Ok(n) => n,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Must specify exactly one network".to_string(),
            );
            return false;
        }
    };

    use key_wallet::bip32::{DerivationPath, KeyDerivationType};
    let derivation = DerivationPath::identity_authentication_path(
        network_rust,
        KeyDerivationType::ECDSA, // Using ECDSA for authentication keys
        identity_index,
        key_index,
    );

    let path_str = format!("{}", derivation);

    let c_string = match CString::new(path_str) {
        Ok(s) => s,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::AllocationFailed,
                "Failed to create C string".to_string(),
            );
            return false;
        }
    };

    let bytes = c_string.as_bytes_with_nul();
    if bytes.len() > path_max_len {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            format!("Path too long: {} > {}", bytes.len(), path_max_len),
        );
        return false;
    }

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), path_out as *mut u8, bytes.len());
    }

    FFIError::set_success(error);
    true
}

/// Derive private key for a specific path from seed
///
/// # Safety
///
/// - `seed` must be a valid pointer to a byte array of `seed_len` length
/// - `path` must be a valid pointer to a null-terminated C string
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure all pointers remain valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn derivation_derive_private_key_from_seed(
    seed: *const u8,
    seed_len: usize,
    path: *const c_char,
    network: FFINetworks,
    error: *mut FFIError,
) -> *mut FFIExtendedPrivKey {
    if seed.is_null() || path.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let seed_slice = slice::from_raw_parts(seed, seed_len);
    let network_rust: Network = network.try_into().unwrap_or(Network::Dash);

    let path_str = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Invalid UTF-8 in path".to_string(),
            );
            return ptr::null_mut();
        }
    };

    use key_wallet::bip32::{DerivationPath, ExtendedPrivKey};
    use secp256k1::Secp256k1;
    use std::str::FromStr;

    let derivation_path = match DerivationPath::from_str(path_str) {
        Ok(p) => p,
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidDerivationPath,
                format!("Invalid derivation path: {:?}", e),
            );
            return ptr::null_mut();
        }
    };

    let secp = Secp256k1::new();
    let master = match ExtendedPrivKey::new_master(network_rust, seed_slice) {
        Ok(m) => m,
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to create master key: {:?}", e),
            );
            return ptr::null_mut();
        }
    };

    match master.derive_priv(&secp, &derivation_path) {
        Ok(xpriv) => {
            FFIError::set_success(error);
            Box::into_raw(Box::new(FFIExtendedPrivKey {
                inner: xpriv,
            }))
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
    if xpriv.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Extended private key is null".to_string(),
        );
        return ptr::null_mut();
    }

    unsafe {
        let xpriv = &*xpriv;
        use key_wallet::bip32::ExtendedPubKey;
        use secp256k1::Secp256k1;

        let secp = Secp256k1::new();
        let xpub = ExtendedPubKey::from_priv(&secp, &xpriv.inner);

        FFIError::set_success(error);
        Box::into_raw(Box::new(FFIExtendedPubKey {
            inner: xpub,
        }))
    }
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
    if xpriv.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Extended private key is null".to_string(),
        );
        return ptr::null_mut();
    }

    unsafe {
        let xpriv = &*xpriv;
        let xpriv_str = xpriv.inner.to_string();

        match CString::new(xpriv_str) {
            Ok(c_str) => {
                FFIError::set_success(error);
                c_str.into_raw()
            }
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
    if xpub.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Extended public key is null".to_string(),
        );
        return ptr::null_mut();
    }

    unsafe {
        let xpub = &*xpub;
        let xpub_str = xpub.inner.to_string();

        match CString::new(xpub_str) {
            Ok(c_str) => {
                FFIError::set_success(error);
                c_str.into_raw()
            }
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
    if xpub.is_null() || fingerprint_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    unsafe {
        let xpub = &*xpub;
        let fingerprint = xpub.inner.fingerprint();
        let bytes = fingerprint.to_bytes();

        ptr::copy_nonoverlapping(bytes.as_ptr(), fingerprint_out, 4);

        FFIError::set_success(error);
        true
    }
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

/// Derive key using DIP9 path constants for identity
///
/// # Safety
///
/// - `seed` must be a valid pointer to a byte array of `seed_len` length
/// - `error` must be a valid pointer to an FFIError structure or null
/// - The caller must ensure the seed pointer remains valid for the duration of this call
#[no_mangle]
pub unsafe extern "C" fn dip9_derive_identity_key(
    seed: *const u8,
    seed_len: usize,
    network: FFINetworks,
    identity_index: c_uint,
    key_index: c_uint,
    key_type: FFIDerivationPathType,
    error: *mut FFIError,
) -> *mut FFIExtendedPrivKey {
    if seed.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Seed is null".to_string());
        return ptr::null_mut();
    }

    let seed_slice = slice::from_raw_parts(seed, seed_len);
    let network_rust: Network = network.try_into().unwrap_or(Network::Dash);

    use key_wallet::bip32::{ChildNumber, DerivationPath};
    use key_wallet::dip9::{
        IDENTITY_AUTHENTICATION_PATH_MAINNET, IDENTITY_AUTHENTICATION_PATH_TESTNET,
        IDENTITY_REGISTRATION_PATH_MAINNET, IDENTITY_REGISTRATION_PATH_TESTNET,
        IDENTITY_TOPUP_PATH_MAINNET, IDENTITY_TOPUP_PATH_TESTNET,
    };

    let base_path = match (network_rust, key_type) {
        (key_wallet::Network::Dash, FFIDerivationPathType::PathBlockchainIdentities) => {
            IDENTITY_AUTHENTICATION_PATH_MAINNET
        }
        (
            key_wallet::Network::Testnet
            | key_wallet::Network::Devnet
            | key_wallet::Network::Regtest,
            FFIDerivationPathType::PathBlockchainIdentities,
        ) => IDENTITY_AUTHENTICATION_PATH_TESTNET,
        (
            key_wallet::Network::Dash,
            FFIDerivationPathType::PathBlockchainIdentityCreditRegistrationFunding,
        ) => IDENTITY_REGISTRATION_PATH_MAINNET,
        (
            key_wallet::Network::Testnet
            | key_wallet::Network::Devnet
            | key_wallet::Network::Regtest,
            FFIDerivationPathType::PathBlockchainIdentityCreditRegistrationFunding,
        ) => IDENTITY_REGISTRATION_PATH_TESTNET,
        (
            key_wallet::Network::Dash,
            FFIDerivationPathType::PathBlockchainIdentityCreditTopupFunding,
        ) => IDENTITY_TOPUP_PATH_MAINNET,
        (
            key_wallet::Network::Testnet
            | key_wallet::Network::Devnet
            | key_wallet::Network::Regtest,
            FFIDerivationPathType::PathBlockchainIdentityCreditTopupFunding,
        ) => IDENTITY_TOPUP_PATH_TESTNET,
        _ => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                "Invalid key type for identity derivation".to_string(),
            );
            return ptr::null_mut();
        }
    };

    // Build additional path based on key type
    let additional_path = match key_type {
        FFIDerivationPathType::PathBlockchainIdentities => {
            // Authentication: identity_index'/key_index'
            let cn1 = match ChildNumber::from_hardened_idx(identity_index) {
                Ok(v) => v,
                Err(e) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::InvalidDerivationPath,
                        format!("Invalid identity_index: {}", e),
                    );
                    return ptr::null_mut();
                }
            };
            let cn2 = match ChildNumber::from_hardened_idx(key_index) {
                Ok(v) => v,
                Err(e) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::InvalidDerivationPath,
                        format!("Invalid key_index: {}", e),
                    );
                    return ptr::null_mut();
                }
            };
            DerivationPath::from(vec![cn1, cn2])
        }
        FFIDerivationPathType::PathBlockchainIdentityCreditRegistrationFunding => {
            // Registration: index'
            let cn = match ChildNumber::from_hardened_idx(identity_index) {
                Ok(v) => v,
                Err(e) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::InvalidDerivationPath,
                        format!("Invalid identity_index: {}", e),
                    );
                    return ptr::null_mut();
                }
            };
            DerivationPath::from(vec![cn])
        }
        FFIDerivationPathType::PathBlockchainIdentityCreditTopupFunding => {
            // Top-up: identity_index'/topup_index'
            let cn1 = match ChildNumber::from_hardened_idx(identity_index) {
                Ok(v) => v,
                Err(e) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::InvalidDerivationPath,
                        format!("Invalid identity_index: {}", e),
                    );
                    return ptr::null_mut();
                }
            };
            let cn2 = match ChildNumber::from_hardened_idx(key_index) {
                Ok(v) => v,
                Err(e) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::InvalidDerivationPath,
                        format!("Invalid topup_index: {}", e),
                    );
                    return ptr::null_mut();
                }
            };
            DerivationPath::from(vec![cn1, cn2])
        }
        _ => {
            FFIError::set_error(error, FFIErrorCode::InvalidInput, "Invalid key type".to_string());
            return ptr::null_mut();
        }
    };

    match base_path.derive_priv_ecdsa_for_master_seed(seed_slice, additional_path, network_rust) {
        Ok(xpriv) => {
            FFIError::set_success(error);
            Box::into_raw(Box::new(FFIExtendedPrivKey {
                inner: xpriv,
            }))
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to derive identity key: {:?}", e),
            );
            ptr::null_mut()
        }
    }
}

#[cfg(test)]
#[path = "derivation_tests.rs"]
mod tests;
