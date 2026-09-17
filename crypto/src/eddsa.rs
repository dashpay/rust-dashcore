//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! Ed25519 keys for Platform node identity.

use dash_types::{make_bytes, make_sbytes};
#[cfg(feature = "eddsa")]
use ed25519_dalek::{SigningKey, VerifyingKey};
use thiserror::Error as ThisError;

/// Raw Ed25519 public key length.
pub const EDDSA_PK_LEN: usize = 32;

/// Raw Ed25519 secret key (seed) length.
pub const EDDSA_SK_LEN: usize = 32;

/// Errors produced by Ed25519 operations.
#[cfg(feature = "eddsa")]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, ThisError)]
pub enum EddsaError {
    /// Public key bytes are not a usable curve point.
    #[error("Invalid Ed25519 public key: {0}")]
    InvalidPublicKey(String),
}

make_bytes! {
    /// Ed25519 public key (32 bytes, unvalidated).
    EddsaPkBytes, EDDSA_PK_LEN
}

#[cfg(feature = "eddsa")]
impl EddsaPkBytes {
    /// Checks these bytes are a usable curve point.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPublicKey` when the bytes are not on the curve.
    pub fn validate(&self) -> Result<(), EddsaError> {
        VerifyingKey::from_bytes(self.as_bytes())
            .map(|_| ())
            .map_err(|e| EddsaError::InvalidPublicKey(e.to_string()))
    }
}

make_sbytes! {
    /// Ed25519 secret key seed (32 bytes).
    EddsaSkBytes, EDDSA_SK_LEN
}

#[cfg(feature = "eddsa")]
impl EddsaSkBytes {
    /// Derives the corresponding public key.
    pub fn public_key(&self) -> EddsaPkBytes {
        EddsaPkBytes::from_bytes(SigningKey::from_bytes(self.as_bytes()).verifying_key().to_bytes())
    }
}
