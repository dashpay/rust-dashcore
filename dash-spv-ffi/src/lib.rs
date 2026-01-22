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
