// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin taproot keys.
//!
//! This module provides taproot keys used in Bitcoin (including reexporting secp256k1 keys).
//!

use core::fmt;

use internals::write_err;
pub use secp256k1::{self};

use crate::prelude::*;
use crate::sighash::TapSighashType;

/// A BIP340-341 serialized taproot signature with the corresponding hash type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signature {
    /// The underlying schnorr signature
    pub sig: secp256k1::schnorr::Signature,
    /// The corresponding hash type
    pub hash_ty: TapSighashType,
}

impl Signature {
    /// Deserialize from slice
    pub fn from_slice(sl: &[u8]) -> Result<Self, Error> {
        let Some((sig, hash_ty)) =
            sl.split_first_chunk::<{ secp256k1::constants::SCHNORR_SIGNATURE_SIZE }>()
        else {
            return Err(Error::InvalidSignatureSize(sl.len()));
        };
        let hash_ty = match hash_ty {
            // Default sighash type is implied by the absence of a trailing byte.
            [] => TapSighashType::Default,
            [hash_ty] => TapSighashType::from_consensus_u8(*hash_ty)
                .map_err(|_| Error::InvalidSighashType(*hash_ty))?,
            _ => return Err(Error::InvalidSignatureSize(sl.len())),
        };
        Ok(Signature {
            sig: secp256k1::schnorr::Signature::from_byte_array(*sig),
            hash_ty,
        })
    }

    /// Serialize Signature
    pub fn to_vec(self) -> Vec<u8> {
        // TODO: add support to serialize to a writer to SerializedSig
        let mut ser_sig = self.sig.as_ref().to_vec();
        if self.hash_ty == TapSighashType::Default {
            // default sighash type, don't add extra sighash byte
        } else {
            ser_sig.push(self.hash_ty as u8);
        }
        ser_sig
    }
}

/// A taproot sig related error.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Base58 encoding error
    InvalidSighashType(u8),
    /// Signature has valid size but does not parse correctly
    Secp256k1(secp256k1::Error),
    /// Invalid taproot signature size
    InvalidSignatureSize(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidSighashType(hash_ty) => {
                write!(f, "invalid signature hash type {}", hash_ty)
            }
            Error::Secp256k1(ref e) => {
                write_err!(f, "taproot signature has correct len but is malformed"; e)
            }
            Error::InvalidSignatureSize(sz) => write!(f, "invalid taproot signature size: {}", sz),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            Secp256k1(e) => Some(e),
            InvalidSighashType(_) | InvalidSignatureSize(_) => None,
        }
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Secp256k1(e)
    }
}
