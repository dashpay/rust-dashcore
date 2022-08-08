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

use std::io::{Read, Write};
use consensus::{Decodable, Encodable};
use consensus::encode::Error;
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

impl Encodable for BLSPublicKey {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, std::io::Error> {
        s.write(self.0.as_slice())?;
        Ok(48)
    }
}

impl Decodable for BLSPublicKey {
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, Error> {
        let mut data :[u8;48] = [0u8; 48];
        d.read_exact(&mut data)?;
        Ok(BLSPublicKey(data))
    }
}

impl Encodable for BLSSignature {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, std::io::Error> {
        s.write(self.0.as_slice())?;
        Ok(96)
    }
}

impl Decodable for BLSSignature {
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, Error> {
        let mut data :[u8;96] = [0u8; 96];
        d.read_exact(&mut data)?;
        Ok(BLSSignature(data))
    }
}

// macro_rules! impl_elementencode {
//     ($element:ident) => {
//         impl $crate::consensus::Encodable for $element {
//             fn consensus_encode<S: $crate::io::Write>(&self, s: S) -> Result<usize, $crate::io::Error> {
//                 s.write(self.0.as_slice())?;
//             }
//         }
//
//         impl $crate::consensus::Decodable for $element {
//             fn consensus_decode<D: $crate::io::Read>(d: D) -> Result<Self, $crate::consensus::encode::Error> {
//                 let mut data :[u8;96] = [0u8; 96];
//                 d.read_exact(&mut data)?;
//                 Ok(BLSSignature(data))
//             }
//         }
//     }
// }
//
// impl_elementencode!(BLSPublicKey);
// impl_elementencode!(BLSSignature);
