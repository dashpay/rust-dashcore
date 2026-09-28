// Rust Bitcoin Library - Written by the rust-dash developers.
// SPDX-License-Identifier: CC0-1.0

//! Cryptography
//!
//! Cryptography related functionality: keys and signatures.
//!

pub mod ecdsa {
    pub use dashcore_crypto::ecdsa::{Error, SerializedSignature, Signature};
}
pub mod key;
pub mod sighash;
pub mod taproot {
    pub use dashcore_crypto::taproot::{Error, Signature};
}
