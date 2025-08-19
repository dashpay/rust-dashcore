//! BIP32 and DIP9 derivation path functions

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};
use std::ptr;
use std::slice;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::FFINetwork;

/// Derivation path type for DIP9
#[repr(C)]
#[derive(Clone, Copy)]
pub enum FFIDerivationPathType {
    Unknown = 0,
    BIP32 = 1,
    BIP44 = 2,
    BlockchainIdentities = 3,
    ProviderFunds = 4,
    ProviderVotingKeys = 5,
    ProviderOperatorKeys = 6,
    ProviderOwnerKeys = 7,
    ContactBasedFunds = 8,
    ContactBasedFundsRoot = 9,
    ContactBasedFundsExternal = 10,
    BlockchainIdentityCreditRegistrationFunding = 11,
    BlockchainIdentityCreditTopupFunding = 12,
    BlockchainIdentityCreditInvitationFunding = 13,
    ProviderPlatformNodeKeys = 14,
    CoinJoin = 15,
    Root = 255,
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
#[no_mangle]
pub extern "C" fn derivation_new_master_key(
    seed: *const u8,
    seed_len: usize,
    network: FFINetwork,
    error: *mut FFIError,
) -> *mut FFIExtendedPrivKey {
    if seed.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Seed is null".to_string());
        return ptr::null_mut();
    }

    let seed_slice = unsafe { slice::from_raw_parts(seed, seed_len) };
    let network_rust: key_wallet::Network = network.into();

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
    network: FFINetwork,
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

    let network_rust: key_wallet::Network = network.into();

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
    network: FFINetwork,
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

    let network_rust: key_wallet::Network = network.into();

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
    network: FFINetwork,
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

    let network_rust: key_wallet::Network = network.into();

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
    network: FFINetwork,
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

    let network_rust: key_wallet::Network = network.into();

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
    network: FFINetwork,
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

    let network_rust: key_wallet::Network = network.into();

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
    network: FFINetwork,
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

    let network_rust: key_wallet::Network = network.into();

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
#[no_mangle]
pub extern "C" fn derivation_derive_private_key_from_seed(
    seed: *const u8,
    seed_len: usize,
    path: *const c_char,
    network: FFINetwork,
    error: *mut FFIError,
) -> *mut FFIExtendedPrivKey {
    if seed.is_null() || path.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return ptr::null_mut();
    }

    let seed_slice = unsafe { slice::from_raw_parts(seed, seed_len) };
    let network_rust: key_wallet::Network = network.into();

    let path_str = unsafe {
        match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in path".to_string(),
                );
                return ptr::null_mut();
            }
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
#[no_mangle]
pub extern "C" fn derivation_xpriv_to_xpub(
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
#[no_mangle]
pub extern "C" fn derivation_xpriv_to_string(
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
#[no_mangle]
pub extern "C" fn derivation_xpub_to_string(
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
#[no_mangle]
pub extern "C" fn derivation_xpub_fingerprint(
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
#[no_mangle]
pub extern "C" fn derivation_xpriv_free(xpriv: *mut FFIExtendedPrivKey) {
    if !xpriv.is_null() {
        unsafe {
            let _ = Box::from_raw(xpriv);
        }
    }
}

/// Free extended public key
#[no_mangle]
pub extern "C" fn derivation_xpub_free(xpub: *mut FFIExtendedPubKey) {
    if !xpub.is_null() {
        unsafe {
            let _ = Box::from_raw(xpub);
        }
    }
}

/// Free derivation path string
#[no_mangle]
pub extern "C" fn derivation_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

/// Derive key using DIP9 path constants for identity
#[no_mangle]
pub extern "C" fn dip9_derive_identity_key(
    seed: *const u8,
    seed_len: usize,
    network: FFINetwork,
    identity_index: c_uint,
    key_index: c_uint,
    key_type: FFIDerivationPathType,
    error: *mut FFIError,
) -> *mut FFIExtendedPrivKey {
    if seed.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Seed is null".to_string());
        return ptr::null_mut();
    }

    let seed_slice = unsafe { slice::from_raw_parts(seed, seed_len) };
    let network_rust: key_wallet::Network = network.into();

    use key_wallet::bip32::{ChildNumber, DerivationPath};
    use key_wallet::dip9::{
        IDENTITY_AUTHENTICATION_PATH_MAINNET, IDENTITY_AUTHENTICATION_PATH_TESTNET,
        IDENTITY_REGISTRATION_PATH_MAINNET, IDENTITY_REGISTRATION_PATH_TESTNET,
        IDENTITY_TOPUP_PATH_MAINNET, IDENTITY_TOPUP_PATH_TESTNET,
    };

    let base_path = match (network_rust, key_type) {
        (key_wallet::Network::Dash, FFIDerivationPathType::BlockchainIdentities) => {
            IDENTITY_AUTHENTICATION_PATH_MAINNET
        }
        (
            key_wallet::Network::Testnet
            | key_wallet::Network::Devnet
            | key_wallet::Network::Regtest,
            FFIDerivationPathType::BlockchainIdentities,
        ) => IDENTITY_AUTHENTICATION_PATH_TESTNET,
        (
            key_wallet::Network::Dash,
            FFIDerivationPathType::BlockchainIdentityCreditRegistrationFunding,
        ) => IDENTITY_REGISTRATION_PATH_MAINNET,
        (
            key_wallet::Network::Testnet
            | key_wallet::Network::Devnet
            | key_wallet::Network::Regtest,
            FFIDerivationPathType::BlockchainIdentityCreditRegistrationFunding,
        ) => IDENTITY_REGISTRATION_PATH_TESTNET,
        (
            key_wallet::Network::Dash,
            FFIDerivationPathType::BlockchainIdentityCreditTopupFunding,
        ) => IDENTITY_TOPUP_PATH_MAINNET,
        (
            key_wallet::Network::Testnet
            | key_wallet::Network::Devnet
            | key_wallet::Network::Regtest,
            FFIDerivationPathType::BlockchainIdentityCreditTopupFunding,
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
        FFIDerivationPathType::BlockchainIdentities => {
            // Authentication: identity_index'/key_index'
            DerivationPath::from(vec![
                ChildNumber::from_hardened_idx(identity_index).unwrap(),
                ChildNumber::from_hardened_idx(key_index).unwrap(),
            ])
        }
        FFIDerivationPathType::BlockchainIdentityCreditRegistrationFunding => {
            // Registration: index'
            DerivationPath::from(vec![ChildNumber::from_hardened_idx(identity_index).unwrap()])
        }
        FFIDerivationPathType::BlockchainIdentityCreditTopupFunding => {
            // Top-up: identity_index'/topup_index'
            DerivationPath::from(vec![
                ChildNumber::from_hardened_idx(identity_index).unwrap(),
                ChildNumber::from_hardened_idx(key_index).unwrap(), // key_index used as topup_index
            ])
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
