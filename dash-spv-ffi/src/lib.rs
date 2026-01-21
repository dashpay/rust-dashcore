pub mod callbacks;
pub mod checkpoints;
pub mod client;
pub mod config;
pub mod error;
pub mod platform_integration;
pub mod types;
pub mod utils;

pub use callbacks::*;
pub use checkpoints::*;
pub use client::*;
pub use config::*;
pub use error::*;
pub use platform_integration::*;
pub use types::*;
pub use utils::*;

// Re-export key-wallet-ffi modules for unified access
// This allows consumers to link just dash-spv-ffi to get wallet functionality too
//
// Note: We re-export modules rather than using glob (*) to avoid conflicts with
// SpvFFIErrorCode which is defined differently in both crates.
pub use key_wallet_ffi::account;
pub use key_wallet_ffi::account_collection;
pub use key_wallet_ffi::account_derivation;
pub use key_wallet_ffi::address;
pub use key_wallet_ffi::address_pool;
pub use key_wallet_ffi::derivation;
pub use key_wallet_ffi::keys;
pub use key_wallet_ffi::managed_account;
pub use key_wallet_ffi::managed_account_collection;
pub use key_wallet_ffi::managed_wallet;
pub use key_wallet_ffi::mnemonic;
pub use key_wallet_ffi::transaction;
pub use key_wallet_ffi::transaction_checking;
pub use key_wallet_ffi::types as wallet_types;
pub use key_wallet_ffi::utils as wallet_utils;
pub use key_wallet_ffi::utxo;
pub use key_wallet_ffi::wallet;
pub use key_wallet_ffi::wallet_manager;

// Re-export key types directly at this level (excluding SpvFFIErrorCode to avoid conflict)
pub use key_wallet_ffi::FFIWalletManager;
pub use key_wallet_ffi::FFINetwork;
pub use key_wallet_ffi::FFIWallet;
pub use key_wallet_ffi::key_wallet_ffi_initialize;
pub use key_wallet_ffi::key_wallet_ffi_version;

// FFINetwork is now defined in types.rs for cbindgen compatibility
// It must match the definition in key_wallet_ffi

#[cfg(test)]
#[path = "../tests/unit/test_type_conversions.rs"]
mod test_type_conversions;

#[cfg(test)]
#[path = "../tests/unit/test_error_handling.rs"]
mod test_error_handling;

#[cfg(test)]
#[path = "../tests/unit/test_configuration.rs"]
mod test_configuration;

#[cfg(test)]
#[path = "../tests/unit/test_client_lifecycle.rs"]
mod test_client_lifecycle;

#[cfg(test)]
#[path = "../tests/unit/test_async_operations.rs"]
mod test_async_operations;

mod broadcast;
#[cfg(test)]
#[path = "../tests/unit/test_memory_management.rs"]
mod test_memory_management;
