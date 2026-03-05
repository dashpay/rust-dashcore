//! FFI sync tests using dashd.
//!
//! These tests mirror Rust SPV sync tests but use FFI bindings
//! with the event-based API (dash_spv_ffi_client_run + event callbacks).

mod callbacks;
mod context;
mod tests_basic;
mod tests_callback;
mod tests_restart;
mod tests_transaction;
