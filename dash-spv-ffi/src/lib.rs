pub mod callbacks;
pub mod client;
pub mod config;
pub mod error;
pub mod platform_integration;
pub mod types;
pub mod utils;

pub use callbacks::*;
pub use client::*;
pub use config::*;
pub use error::*;
pub use platform_integration::*;
pub use types::*;
pub use utils::*;

// Re-export wallet-FFI types used by `FFIWalletEventCallbacks` so consumers
// can refer to them via `dash_spv_ffi::*` without importing `key_wallet_ffi`
// directly.
pub use key_wallet_ffi::managed_account::{FFIAccountType, FFITransactionRecord};
pub use key_wallet_ffi::types::FFIAccountKind;

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

#[cfg(test)]
#[path = "../tests/unit/test_memory_management.rs"]
mod test_memory_management;
