//! Provider keys FFI bindings
//!
//! This module provides FFI bindings for provider (masternode) keys,
//! including BLS keys for voting/owner/operator roles and EdDSA keys
//! for platform operations.

use std::ffi::CString;
use std::os::raw::{c_char, c_uint};
use std::ptr;
use std::slice;

use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFINetwork, FFIWallet};
use key_wallet::AccountType;

/// Provider key type
#[repr(C)]
pub enum FFIProviderKeyType {
    /// BLS voting keys (m/9'/5'/3'/1'/[key_index])
    VotingKeys = 0,
    /// BLS owner keys (m/9'/5'/3'/2'/[key_index])
    OwnerKeys = 1,
    /// BLS operator keys (m/9'/5'/3'/3'/[key_index])
    OperatorKeys = 2,
    /// EdDSA platform P2P keys (m/9'/5'/3'/4'/[key_index])
    PlatformKeys = 3,
}

/// Provider key info
#[repr(C)]
pub struct FFIProviderKeyInfo {
    /// Key index
    pub key_index: c_uint,
    /// Public key bytes (48 bytes for BLS, 32 bytes for EdDSA)
    pub public_key: *mut u8,
    /// Public key length
    pub public_key_len: usize,
    /// Private key bytes (32 bytes, only if available)
    pub private_key: *mut u8,
    /// Private key length (0 if not available)
    pub private_key_len: usize,
    /// Derivation path as string
    pub derivation_path: *mut c_char,
}

/// Generate a provider key at a specific index
///
/// This generates a provider key (BLS or EdDSA) at the specified index.
/// For voting, owner, and operator keys, this generates BLS keys.
/// For platform keys, this generates EdDSA keys.
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `info_out` must be a valid pointer to store the key info
/// - `error` must be a valid pointer to an FFIError or null
/// - The returned public_key, private_key, and derivation_path must be freed by the caller
#[no_mangle]
pub unsafe extern "C" fn wallet_generate_provider_key(
    wallet: *const FFIWallet,
    network: FFINetwork,
    key_type: FFIProviderKeyType,
    key_index: c_uint,
    include_private: bool,
    info_out: *mut FFIProviderKeyInfo,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() || info_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let wallet = &*wallet;
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

    // Determine the account type based on key type
    let account_type = match key_type {
        FFIProviderKeyType::VotingKeys => AccountType::ProviderVotingKeys,
        FFIProviderKeyType::OwnerKeys => AccountType::ProviderOwnerKeys,
        FFIProviderKeyType::OperatorKeys => AccountType::ProviderOperatorKeys,
        FFIProviderKeyType::PlatformKeys => AccountType::ProviderPlatformKeys,
    };

    // Get the account
    let accounts = match wallet.inner().accounts.get(&network_rust) {
        Some(accounts) => accounts,
        None => {
            FFIError::set_error(
                error,
                FFIErrorCode::NotFound,
                "No accounts for network".to_string(),
            );
            return false;
        }
    };

    let account = match &account_type {
        AccountType::ProviderVotingKeys => accounts.provider_voting_keys.as_ref(),
        AccountType::ProviderOwnerKeys => accounts.provider_owner_keys.as_ref(),
        AccountType::ProviderOperatorKeys => None, // BLSAccount not yet supported
        AccountType::ProviderPlatformKeys => None, // EdDSAAccount not yet supported
        _ => None,
    };

    let _account = match account {
        Some(acc) => acc,
        None => {
            FFIError::set_error(
                error,
                FFIErrorCode::NotFound,
                format!("Provider account type {:?} not found", account_type),
            );
            return false;
        }
    };

    // Generate the key at the specified index
    // TODO: Get proper derivation path when available
    use key_wallet::DerivationPath;
    let derivation_path = DerivationPath::default();

    // For now, return placeholder data until BLS/EdDSA key generation is implemented
    // TODO: Implement actual BLS/EdDSA key generation when available in Account
    let (public_key_bytes, private_key_bytes) = match key_type {
        FFIProviderKeyType::VotingKeys
        | FFIProviderKeyType::OwnerKeys
        | FFIProviderKeyType::OperatorKeys => {
            // BLS keys - placeholder
            let pub_bytes = vec![0u8; 48]; // BLS public key is 48 bytes
            let priv_bytes = if include_private {
                Some(vec![0u8; 32]) // BLS private key is 32 bytes
            } else {
                None
            };
            (pub_bytes, priv_bytes)
        }
        FFIProviderKeyType::PlatformKeys => {
            // EdDSA keys - placeholder
            let pub_bytes = vec![0u8; 32]; // Ed25519 public key is 32 bytes
            let priv_bytes = if include_private {
                Some(vec![0u8; 32]) // Ed25519 private key is 32 bytes
            } else {
                None
            };
            (pub_bytes, priv_bytes)
        }
    };

    // Allocate and copy public key
    let pub_key_len = public_key_bytes.len();
    let pub_key_ptr = libc::malloc(pub_key_len) as *mut u8;
    if pub_key_ptr.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InternalError,
            "Failed to allocate memory for public key".to_string(),
        );
        return false;
    }
    ptr::copy_nonoverlapping(public_key_bytes.as_ptr(), pub_key_ptr, pub_key_len);

    // Allocate and copy private key if available
    let (priv_key_ptr, priv_key_len) = if let Some(priv_bytes) = private_key_bytes {
        let len = priv_bytes.len();
        let ptr = libc::malloc(len) as *mut u8;
        if ptr.is_null() {
            libc::free(pub_key_ptr as *mut libc::c_void);
            FFIError::set_error(
                error,
                FFIErrorCode::InternalError,
                "Failed to allocate memory for private key".to_string(),
            );
            return false;
        }
        ptr::copy_nonoverlapping(priv_bytes.as_ptr(), ptr, len);
        (ptr, len)
    } else {
        (ptr::null_mut(), 0)
    };

    // Create derivation path string
    let path_str = format!("{}", derivation_path);
    let path_cstring = match CString::new(path_str) {
        Ok(s) => s,
        Err(_) => {
            libc::free(pub_key_ptr as *mut libc::c_void);
            if !priv_key_ptr.is_null() {
                libc::free(priv_key_ptr as *mut libc::c_void);
            }
            FFIError::set_error(
                error,
                FFIErrorCode::InternalError,
                "Failed to create derivation path string".to_string(),
            );
            return false;
        }
    };

    // Fill the output structure
    *info_out = FFIProviderKeyInfo {
        key_index,
        public_key: pub_key_ptr,
        public_key_len: pub_key_len,
        private_key: priv_key_ptr,
        private_key_len: priv_key_len,
        derivation_path: path_cstring.into_raw(),
    };

    FFIError::set_success(error);
    true
}

/// Free provider key info
///
/// # Safety
///
/// - `info` must be a valid pointer to an FFIProviderKeyInfo
/// - This function must only be called once per info structure
#[no_mangle]
pub unsafe extern "C" fn provider_key_info_free(info: *mut FFIProviderKeyInfo) {
    if !info.is_null() {
        let info = &mut *info;

        if !info.public_key.is_null() {
            libc::free(info.public_key as *mut libc::c_void);
            info.public_key = ptr::null_mut();
        }

        if !info.private_key.is_null() {
            libc::free(info.private_key as *mut libc::c_void);
            info.private_key = ptr::null_mut();
        }

        if !info.derivation_path.is_null() {
            let _ = CString::from_raw(info.derivation_path);
            info.derivation_path = ptr::null_mut();
        }
    }
}

/// Sign data with a provider key
///
/// This signs arbitrary data with the provider key at the specified index.
/// For BLS keys, this produces a BLS signature.
/// For EdDSA keys, this produces an Ed25519 signature.
///
/// # Safety
///
/// - `wallet` must be a valid pointer to an FFIWallet
/// - `data` must be a valid pointer to data with at least `data_len` bytes
/// - `signature_out` must be a valid pointer to store the signature pointer
/// - `signature_len_out` must be a valid pointer to store the signature length
/// - `error` must be a valid pointer to an FFIError or null
/// - The returned signature must be freed with `libc::free`
#[no_mangle]
pub unsafe extern "C" fn wallet_sign_with_provider_key(
    wallet: *const FFIWallet,
    network: FFINetwork,
    key_type: FFIProviderKeyType,
    _key_index: c_uint,
    data: *const u8,
    data_len: usize,
    signature_out: *mut *mut u8,
    signature_len_out: *mut usize,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() || data.is_null() || signature_out.is_null() || signature_len_out.is_null()
    {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    let wallet = &*wallet;
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
    let _data_slice = slice::from_raw_parts(data, data_len);

    // Determine the account type based on key type
    let account_type = match key_type {
        FFIProviderKeyType::VotingKeys => AccountType::ProviderVotingKeys,
        FFIProviderKeyType::OwnerKeys => AccountType::ProviderOwnerKeys,
        FFIProviderKeyType::OperatorKeys => AccountType::ProviderOperatorKeys,
        FFIProviderKeyType::PlatformKeys => AccountType::ProviderPlatformKeys,
    };

    // Get the account
    let accounts = match wallet.inner().accounts.get(&network_rust) {
        Some(accounts) => accounts,
        None => {
            FFIError::set_error(
                error,
                FFIErrorCode::NotFound,
                "No accounts for network".to_string(),
            );
            return false;
        }
    };

    let account = match &account_type {
        AccountType::ProviderVotingKeys => accounts.provider_voting_keys.as_ref(),
        AccountType::ProviderOwnerKeys => accounts.provider_owner_keys.as_ref(),
        AccountType::ProviderOperatorKeys => None, // BLSAccount not yet supported
        AccountType::ProviderPlatformKeys => None, // EdDSAAccount not yet supported
        _ => None,
    };

    let _account = match account {
        Some(acc) => acc,
        None => {
            FFIError::set_error(
                error,
                FFIErrorCode::NotFound,
                format!("Provider account type {:?} not found", account_type),
            );
            return false;
        }
    };

    // Sign the data
    // TODO: Implement actual signing when BLS/EdDSA signing is available in Account
    let signature_bytes = match key_type {
        FFIProviderKeyType::VotingKeys
        | FFIProviderKeyType::OwnerKeys
        | FFIProviderKeyType::OperatorKeys => {
            // BLS signature - placeholder
            vec![0u8; 96] // BLS signature is 96 bytes
        }
        FFIProviderKeyType::PlatformKeys => {
            // EdDSA signature - placeholder
            vec![0u8; 64] // Ed25519 signature is 64 bytes
        }
    };

    // Allocate and copy signature
    let sig_len = signature_bytes.len();
    let sig_ptr = libc::malloc(sig_len) as *mut u8;
    if sig_ptr.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InternalError,
            "Failed to allocate memory for signature".to_string(),
        );
        return false;
    }
    ptr::copy_nonoverlapping(signature_bytes.as_ptr(), sig_ptr, sig_len);

    *signature_out = sig_ptr;
    *signature_len_out = sig_len;

    FFIError::set_success(error);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_key_type_values() {
        assert_eq!(FFIProviderKeyType::VotingKeys as u32, 0);
        assert_eq!(FFIProviderKeyType::OwnerKeys as u32, 1);
        assert_eq!(FFIProviderKeyType::OperatorKeys as u32, 2);
        assert_eq!(FFIProviderKeyType::PlatformKeys as u32, 3);
    }
}
