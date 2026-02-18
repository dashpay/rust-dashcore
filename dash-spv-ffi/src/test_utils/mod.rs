//! Shared test infrastructure for FFI integration tests.
//!
//! Provides reusable context, callbacks, and helpers that FFI integration tests share.
//! Gated behind the `test-utils` feature so integration tests can import via
//! `dash_spv_ffi::test_utils`.

pub mod callbacks;
pub mod context;

pub use callbacks::*;
pub use context::*;
