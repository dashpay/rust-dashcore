pub mod callbacks;
pub mod client;
pub mod config;
pub mod error;
pub mod types;
pub mod utils;
pub mod wallet;

pub use callbacks::*;
pub use client::*;
pub use config::*;
pub use error::*;
pub use types::*;
pub use utils::*;
pub use wallet::*;

// Re-export commonly used types
pub use types::FFINetwork;

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
#[path = "../tests/unit/test_wallet_operations.rs"]
mod test_wallet_operations;

#[cfg(test)]
#[path = "../tests/unit/test_memory_management.rs"]
mod test_memory_management;
