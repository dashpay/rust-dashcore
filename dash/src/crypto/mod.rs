// Rust Bitcoin Library - Written by the rust-dash developers.
// SPDX-License-Identifier: CC0-1.0

//! Cryptography
//!
//! Cryptography related functionality: keys and signatures.
//!

pub mod ecdsa {
    #[cfg(feature = "rand")]
    pub use dashcore_crypto::ecdsa::generate;
    pub use dashcore_crypto::ecdsa::{
        DecodeError, ParseSignatureError, SerializedSignature, Signature,
    };
}
pub mod key;
pub mod sighash;
pub mod taproot {
    pub use dashcore_crypto::taproot::{Error, Signature};
}
