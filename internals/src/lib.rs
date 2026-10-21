// Written by the Rust Dash developers.
// SPDX-License-Identifier: CC0-1.0

//! # Rust DashCore Internal
//!
//! This crate is only meant to be used internally by crates in the
//! [rust-dash](https://github.com/rust-dashcore) ecosystem.
//!

// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Coding conventions
#![warn(missing_docs)]

pub mod error;
pub mod hex;
pub mod macros;
