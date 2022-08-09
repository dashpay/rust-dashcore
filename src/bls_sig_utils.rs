// Rust Dash Library
// Written by
//   The Rust Dash developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Dash BLS elements
//! Convenience wrappers around fixed size arrays of 48 and 96 bytes representing the public key
//! and signature.
//!

use core::{fmt};

/// A BLS Public key is 48 bytes in the scheme used for Dash Core
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BLSPublicKey([u8;48]);

impl_array_newtype!(BLSPublicKey, u8, 48);
impl_bytes_newtype!(BLSPublicKey, 48);

/// A BLS Signature is 96 bytes in the scheme used for Dash Core
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BLSSignature([u8;96]);

impl_array_newtype!(BLSSignature, u8, 96);
impl_bytes_newtype!(BLSSignature, 96);

macro_rules! impl_elementencode {
    ($element:ident, $len:expr) => {
        impl $crate::consensus::Encodable for $element {
            fn consensus_encode<S: $crate::io::Write>(&self, mut s: S) -> Result<usize, $crate::io::Error> {
                s.write(self.0.as_slice())
            }
        }

        impl $crate::consensus::Decodable for $element {
            fn consensus_decode<D: $crate::io::Read>(mut d: D) -> Result<Self, $crate::consensus::encode::Error> {
                let mut data :[u8;$len] = [0u8; $len];
                d.read_exact(&mut data)?;
                Ok($element(data))
            }
        }
    }
}

impl_elementencode!(BLSPublicKey, 48);
impl_elementencode!(BLSSignature, 96);
