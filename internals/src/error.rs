// Written by the Rust Bitcoin developers.
// SPDX-License-Identifier: CC0-1.0

//! # Error
//!
//! Error handling macros and helpers.
//!

/// Formats error.
#[macro_export]
macro_rules! write_err {
    ($writer:expr, $string:literal $(, $args:expr)*; $source:expr) => {
        {
            let _ = &$source;   // Prevents clippy warnings.
            write!($writer, $string $(, $args)*)
        }
    }
}
