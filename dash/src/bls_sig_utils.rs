//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! BLS12-381 public key and signatures.

pub use dashcore_crypto::bls::*;

macro_rules! impl_elementencode {
    ($element:ident, $len:expr) => {
        impl $crate::consensus::Encodable for $element {
            fn consensus_encode<W: $crate::io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> Result<usize, $crate::io::Error> {
                self.as_bytes().consensus_encode(w)
            }
        }

        impl $crate::consensus::Decodable for $element {
            fn consensus_decode<R: $crate::io::Read + ?Sized>(
                r: &mut R,
            ) -> Result<Self, $crate::consensus::encode::Error> {
                let mut data: [u8; $len] = [0u8; $len];
                r.read_exact(&mut data)?;
                Ok($element::from_bytes(data))
            }
        }
    };
}

impl_elementencode!(BLSPublicKey, 48);
impl_elementencode!(BLSSignature, 96);
