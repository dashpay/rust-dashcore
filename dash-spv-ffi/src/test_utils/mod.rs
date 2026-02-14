//! Shared test infrastructure for FFI integration tests.
//!
//! Provides reusable context, callbacks, and helpers that FFI integration tests share.
//! Gated behind the `test-utils` feature so integration tests can import via
//! `dash_spv_ffi::test_utils`.

pub mod callbacks;
pub mod context;

pub use callbacks::*;
pub use context::*;

/// Initialize logging for FFI tests.
///
/// Console output is controlled by the `DASHD_TEST_LOG` environment variable,
/// matching the behavior of the Rust integration tests. Without the env var,
/// logs are silenced to keep test output clean.
///
/// Only the first call takes effect (logging uses a global OnceLock).
pub fn init_test_logging() {
    let console = std::env::var("DASHD_TEST_LOG").is_ok();
    unsafe {
        crate::dash_spv_ffi_init_logging(c"info".as_ptr(), console, std::ptr::null(), 0);
    }
}
