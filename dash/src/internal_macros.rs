// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Internal macros.
//!
//! Macros meant to be used inside the Rust Bitcoin library.
//!

macro_rules! impl_consensus_encoding {
    ($thing:ident, $($field:ident),+) => (
        impl $crate::consensus::Encodable for $thing {
            #[inline]
            fn consensus_encode<R: $crate::io::Write + ?Sized>(
                &self,
                r: &mut R,
            ) -> Result<usize, $crate::io::Error> {
                let mut len = 0;
                $(len += self.$field.consensus_encode(r)?;)+
                Ok(len)
            }
        }

        impl $crate::consensus::Decodable for $thing {

            #[inline]
            fn consensus_decode_from_finite_reader<R: $crate::io::Read + ?Sized>(
                r: &mut R,
            ) -> Result<$thing, $crate::consensus::encode::Error> {
                Ok($thing {
                    $($field: $crate::consensus::Decodable::consensus_decode_from_finite_reader(r)?),+
                })
            }

            #[inline]
            fn consensus_decode<R: $crate::io::Read + ?Sized>(
                r: &mut R,
            ) -> Result<$thing, $crate::consensus::encode::Error> {
                use crate::io::Read as _;
                let mut r = r.take($crate::consensus::encode::MAX_VEC_SIZE as u64);
                Ok($thing {
                    $($field: $crate::consensus::Decodable::consensus_decode(r.by_ref())?),+
                })
            }
        }
    );
}
pub(crate) use impl_consensus_encoding;
// We use test_macros module to keep things organised, re-export everything for ease of use.
#[cfg(test)]
pub(crate) use test_macros::*;

#[cfg(test)]
mod test_macros {

    macro_rules! hex (($hex:expr) => (hex_conservative::decode_to_vec($hex).unwrap()));
    pub(crate) use hex;
}
