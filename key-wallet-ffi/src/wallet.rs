//! Wallet creation and management

#[cfg(test)]
#[path = "wallet_tests.rs"]
mod tests;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};
use std::ptr;
use std::slice;

use key_wallet::wallet::initialization::WalletAccountCreationOptions;
use key_wallet::{Mnemonic, Network, Seed, Wallet, WalletConfig};

use crate::error::{FFIError, FFIErrorCode};
use crate::types::{FFINetwork, FFIWallet, FFIWalletAccountCreationOptions};

/// Create a new wallet from mnemonic with options
#[no_mangle]
pub extern "C" fn wallet_create_from_mnemonic_with_options(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    network: FFINetwork,
    account_options: *const FFIWalletAccountCreationOptions,
    error: *mut FFIError,
) -> *mut FFIWallet {
    if mnemonic.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Mnemonic is null".to_string());
        return ptr::null_mut();
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
                return ptr::null_mut();
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
                    return ptr::null_mut();
                }
            }
        }
    };

    use key_wallet::mnemonic::Language;
    let mnemonic = match Mnemonic::from_phrase(mnemonic_str, Language::English) {
        Ok(m) => m,
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidMnemonic,
                format!("Invalid mnemonic: {}", e),
            );
            return ptr::null_mut();
        }
    };

    let network_rust: key_wallet::Network = network.into();
    let config = WalletConfig::default();

    // Convert account creation options
    let creation_options = if account_options.is_null() {
        WalletAccountCreationOptions::Default
    } else {
        unsafe { (*account_options).to_wallet_options() }
    };

    let wallet = if passphrase_str.is_empty() {
        match Wallet::from_mnemonic(mnemonic, config, network_rust, creation_options) {
            Ok(w) => w,
            Err(e) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::WalletError,
                    format!("Failed to create wallet: {}", e),
                );
                return ptr::null_mut();
            }
        }
    } else {
        // For wallets with passphrase, we need to handle account creation differently
        // First create the wallet without accounts
        match Wallet::from_mnemonic_with_passphrase(
            mnemonic,
            passphrase_str.to_string(),
            config,
            network_rust,
            creation_options,
        ) {
            Ok(w) => w,
            Err(e) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::WalletError,
                    format!("Failed to create wallet with passphrase: {}", e),
                );
                return ptr::null_mut();
            }
        }
    };

    FFIError::set_success(error);
    Box::into_raw(Box::new(FFIWallet::new(wallet)))
}

/// Create a new wallet from mnemonic (backward compatibility)
#[no_mangle]
pub extern "C" fn wallet_create_from_mnemonic(
    mnemonic: *const c_char,
    passphrase: *const c_char,
    network: FFINetwork,
    error: *mut FFIError,
) -> *mut FFIWallet {
    wallet_create_from_mnemonic_with_options(
        mnemonic,
        passphrase,
        network,
        ptr::null(), // Use default options
        error,
    )
}

/// Create a new wallet from seed with options
#[no_mangle]
pub extern "C" fn wallet_create_from_seed_with_options(
    seed: *const u8,
    seed_len: usize,
    network: FFINetwork,
    account_options: *const FFIWalletAccountCreationOptions,
    error: *mut FFIError,
) -> *mut FFIWallet {
    if seed.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Seed is null".to_string());
        return ptr::null_mut();
    }

    if seed_len != 64 {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            format!("Invalid seed length: {}, expected 64", seed_len),
        );
        return ptr::null_mut();
    }

    let seed_bytes = unsafe { slice::from_raw_parts(seed, seed_len) };
    let mut seed_array = [0u8; 64];
    seed_array.copy_from_slice(seed_bytes);
    let seed = Seed::new(seed_array);
    let network_rust: key_wallet::Network = network.into();
    let config = WalletConfig::default();

    // Convert account creation options
    let creation_options = if account_options.is_null() {
        WalletAccountCreationOptions::Default
    } else {
        unsafe { (*account_options).to_wallet_options() }
    };

    match Wallet::from_seed(seed, config, network_rust, creation_options) {
        Ok(wallet) => {
            FFIError::set_success(error);
            Box::into_raw(Box::new(FFIWallet::new(wallet)))
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to create wallet from seed: {}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Create a new wallet from seed (backward compatibility)
#[no_mangle]
pub extern "C" fn wallet_create_from_seed(
    seed: *const u8,
    seed_len: usize,
    network: FFINetwork,
    error: *mut FFIError,
) -> *mut FFIWallet {
    wallet_create_from_seed_with_options(
        seed,
        seed_len,
        network,
        ptr::null(), // Use default options
        error,
    )
}

/// Create a new wallet from seed bytes
#[no_mangle]
pub extern "C" fn wallet_create_from_seed_bytes(
    seed_bytes: *const u8,
    seed_len: usize,
    network: FFINetwork,
    error: *mut FFIError,
) -> *mut FFIWallet {
    if seed_bytes.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Seed bytes are null".to_string());
        return ptr::null_mut();
    }

    let seed_slice = unsafe { slice::from_raw_parts(seed_bytes, seed_len) };
    let network_rust: key_wallet::Network = network.into();
    let config = WalletConfig::default();

    // from_seed_bytes expects specific length
    if seed_len != 64 {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            format!("Invalid seed length: {}, expected 64", seed_len),
        );
        return ptr::null_mut();
    }

    let mut seed_array = [0u8; 64];
    seed_array.copy_from_slice(seed_slice);

    match Wallet::from_seed(
        Seed::new(seed_array),
        config,
        network_rust,
        WalletAccountCreationOptions::Default,
    ) {
        Ok(wallet) => {
            FFIError::set_success(error);
            Box::into_raw(Box::new(FFIWallet::new(wallet)))
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to create wallet from seed bytes: {}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Create a watch-only wallet from extended public key
#[no_mangle]
pub extern "C" fn wallet_create_from_xpub(
    xpub: *const c_char,
    network: FFINetwork,
    error: *mut FFIError,
) -> *mut FFIWallet {
    if xpub.is_null() {
        FFIError::set_error(
            error,
            FFIErrorCode::InvalidInput,
            "Extended public key is null".to_string(),
        );
        return ptr::null_mut();
    }

    let xpub_str = unsafe {
        match CStr::from_ptr(xpub).to_str() {
            Ok(s) => s,
            Err(_) => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    "Invalid UTF-8 in extended public key".to_string(),
                );
                return ptr::null_mut();
            }
        }
    };

    let network_rust: key_wallet::Network = network.into();
    let config = WalletConfig::default();

    use key_wallet::ExtendedPubKey;
    use std::str::FromStr;

    let xpub = match ExtendedPubKey::from_str(xpub_str) {
        Ok(xpub) => xpub,
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::InvalidInput,
                format!("Invalid extended public key: {}", e),
            );
            return ptr::null_mut();
        }
    };

    // Create a watch-only wallet with the given xpub as account 0
    use key_wallet::account::StandardAccountType;
    use key_wallet::{Account, AccountCollection, AccountType};

    let account_type = AccountType::Standard {
        index: 0,
        standard_account_type: StandardAccountType::BIP44Account,
    };

    // Create account 0 with the provided xpub
    match Account::new(None, account_type, xpub, network_rust) {
        Ok(account) => {
            // Create an AccountCollection and add the account
            let mut account_collection = AccountCollection::new();
            account_collection.insert(account);

            // Create the accounts map
            let mut accounts = std::collections::BTreeMap::new();
            accounts.insert(network_rust, account_collection);

            // Create the watch-only wallet
            match Wallet::from_xpub(xpub, Some(config), accounts) {
                Ok(wallet) => {
                    FFIError::set_success(error);
                    Box::into_raw(Box::new(FFIWallet::new(wallet)))
                }
                Err(e) => {
                    FFIError::set_error(
                        error,
                        FFIErrorCode::WalletError,
                        format!("Failed to create watch-only wallet: {}", e),
                    );
                    ptr::null_mut()
                }
            }
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to create account: {}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Create a new random wallet with options
#[no_mangle]
pub extern "C" fn wallet_create_random_with_options(
    network: FFINetwork,
    account_options: *const FFIWalletAccountCreationOptions,
    error: *mut FFIError,
) -> *mut FFIWallet {
    let network_rust: key_wallet::Network = network.into();
    let config = WalletConfig::default();

    // Convert account creation options
    let creation_options = if account_options.is_null() {
        WalletAccountCreationOptions::Default
    } else {
        unsafe { (*account_options).to_wallet_options() }
    };

    match Wallet::new_random(config, network_rust, creation_options) {
        Ok(wallet) => {
            FFIError::set_success(error);
            Box::into_raw(Box::new(FFIWallet::new(wallet)))
        }
        Err(e) => {
            FFIError::set_error(
                error,
                FFIErrorCode::WalletError,
                format!("Failed to create random wallet: {}", e),
            );
            ptr::null_mut()
        }
    }
}

/// Create a new random wallet (backward compatibility)
#[no_mangle]
pub extern "C" fn wallet_create_random(
    network: FFINetwork,
    error: *mut FFIError,
) -> *mut FFIWallet {
    wallet_create_random_with_options(
        network,
        ptr::null(), // Use default options
        error,
    )
}

/// Get wallet ID (32-byte hash)
#[no_mangle]
pub extern "C" fn wallet_get_id(
    wallet: *const FFIWallet,
    id_out: *mut u8,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() || id_out.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Null pointer provided".to_string());
        return false;
    }

    unsafe {
        let wallet = &*wallet;
        let wallet_id = wallet.inner().wallet_id;

        std::ptr::copy_nonoverlapping(wallet_id.as_ptr(), id_out, 32);
        FFIError::set_success(error);
        true
    }
}

/// Check if wallet has mnemonic
#[no_mangle]
pub extern "C" fn wallet_has_mnemonic(wallet: *const FFIWallet, error: *mut FFIError) -> bool {
    if wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Wallet is null".to_string());
        return false;
    }

    unsafe {
        let wallet = &*wallet;
        FFIError::set_success(error);
        wallet.inner().has_mnemonic()
    }
}

/// Check if wallet is watch-only
#[no_mangle]
pub extern "C" fn wallet_is_watch_only(wallet: *const FFIWallet, error: *mut FFIError) -> bool {
    if wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Wallet is null".to_string());
        return false;
    }

    unsafe {
        let wallet = &*wallet;
        FFIError::set_success(error);
        wallet.inner().is_watch_only()
    }
}

/// Get extended public key for account
#[no_mangle]
pub extern "C" fn wallet_get_xpub(
    wallet: *const FFIWallet,
    network: FFINetwork,
    account_index: c_uint,
    error: *mut FFIError,
) -> *mut c_char {
    if wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Wallet is null".to_string());
        return ptr::null_mut();
    }

    unsafe {
        let wallet = &*wallet;
        let network_rust: Network = network.into();

        match wallet.inner().get_bip44_account(network_rust, account_index) {
            Some(account) => {
                let xpub = account.extended_public_key();
                FFIError::set_success(error);
                match CString::new(xpub.to_string()) {
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
            None => {
                FFIError::set_error(error, FFIErrorCode::NotFound, "Account not found".to_string());
                ptr::null_mut()
            }
        }
    }
}

/// Free a wallet
#[no_mangle]
pub extern "C" fn wallet_free(wallet: *mut FFIWallet) {
    if !wallet.is_null() {
        unsafe {
            let _ = Box::from_raw(wallet);
        }
    }
}

/// Add an account to the wallet
#[no_mangle]
pub extern "C" fn wallet_add_account(
    wallet: *mut FFIWallet,
    network: FFINetwork,
    account_type: c_uint,
    account_index: c_uint,
    error: *mut FFIError,
) -> bool {
    if wallet.is_null() {
        FFIError::set_error(error, FFIErrorCode::InvalidInput, "Wallet is null".to_string());
        return false;
    }

    unsafe {
        let wallet = &mut *wallet;
        let network_rust: key_wallet::Network = network.into();

        use crate::types::FFIAccountType;
        use key_wallet::account::types::{AccountType, StandardAccountType};

        let account_type_enum = match account_type {
            0 => FFIAccountType::Standard,
            1 => FFIAccountType::CoinJoin,
            2 => FFIAccountType::Identity,
            _ => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidInput,
                    format!("Invalid account type: {}", account_type),
                );
                return false;
            }
        };

        let account_type = account_type_enum.to_account_type(account_index);

        match wallet.inner_mut() {
            Some(w) => {
                // Get or create the account collection for this network
                let accounts = w.accounts.entry(network_rust).or_insert_with(|| {
                    // Create empty account collection
                    Default::default()
                });

                // Create the account (this would need proper implementation based on account type)
                // For now, we'll return success if the account already exists
                match account_type {
                    AccountType::Standard {
                        index,
                        ..
                    } => {
                        if accounts.standard_bip44_accounts.contains_key(&index) {
                            FFIError::set_success(error);
                            true
                        } else {
                            // Would need to create the account here
                            FFIError::set_error(
                                error,
                                FFIErrorCode::WalletError,
                                "Account creation not yet fully implemented".to_string(),
                            );
                            false
                        }
                    }
                    _ => {
                        FFIError::set_error(
                            error,
                            FFIErrorCode::WalletError,
                            "Only standard accounts supported for now".to_string(),
                        );
                        false
                    }
                }
            }
            None => {
                FFIError::set_error(
                    error,
                    FFIErrorCode::InvalidState,
                    "Cannot modify wallet".to_string(),
                );
                false
            }
        }
    }
}
