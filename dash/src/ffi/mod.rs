//! C-compatible FFI surface of `dashcore`.
//!
//! `FFINetwork` now lives in the `dash-network` crate; it is re-exported here
//! so that `dashcore::ffi::FFINetwork` remains the stable public path.

pub use dash_network::ffi::{FFINetwork, dashcore_network_get_name};
