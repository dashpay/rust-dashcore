// Rust Bitcoin Library - Written by the rust-dash developers.
// SPDX-License-Identifier: CC0-1.0

//! Cryptography
//!
//! Cryptography related functionality: keys and signatures.
//!

pub mod ecdsa {
    pub use dashcore_crypto::ecdsa::{
        DecodeError, ECDSA_PK_LEN, ECDSA_PK_UNCOMPRESSED_LEN, ECDSA_SIG_LEN, ECDSA_SK_LEN,
        EcdsaError, EcdsaPublicKey, EcdsaRecSignature, EcdsaSecretKey, EcdsaSignature,
        ParseSignatureError, SerializedSignature, Signature,
    };
}
pub mod key;
pub mod sighash;
pub mod taproot {
    pub use dashcore_crypto::taproot::{Error, Signature};
}
