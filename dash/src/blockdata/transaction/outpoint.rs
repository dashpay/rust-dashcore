// Rust Dash Library
// Originally written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//     For Bitcoin
// Refactored for Dash in 2022 by
//     The Dash Core Developers
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

//! Dash Outpoints.
//!
//! An outpoint is a reference to one of the indexed destinations of a transaction.
//!

use core::fmt;
use std::error;

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use hashes::{self, Hash};

use crate::consensus::{Decodable, Encodable, deserialize, encode};
use crate::hash_types::Txid;
use crate::io;

/// A reference to a transaction output.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct OutPoint {
    /// The referenced transaction's txid.
    pub txid: Txid,
    /// The index of the referenced output in its transaction's vout.
    pub vout: u32,
}
#[cfg(feature = "serde")]
crate::serde_utils::serde_struct_human_string_impl!(OutPoint, "an OutPoint", txid, vout);

impl From<[u8; 36]> for OutPoint {
    fn from(buffer: [u8; 36]) -> Self {
        let (left, right) = buffer.split_at(32);
        let index: [u8; 4] = right.try_into().expect("OutPoint vout is not 4 bytes");
        Self {
            txid: deserialize(left).expect("OutPoint txid is not 32 bytes"),
            vout: u32::from_le_bytes(index),
        }
    }
}

impl From<OutPoint> for [u8; 36] {
    fn from(value: OutPoint) -> Self {
        let mut bytes = [0u8; 36];
        // Serialize the txid
        let txid_bytes: [u8; 32] = value.txid.to_raw_hash().into(); // Assuming to_raw_hash() returns the hash as sha256d::Hash, which can be converted into [u8; 32]
        bytes[..32].copy_from_slice(&txid_bytes);
        // Serialize the vout
        let vout_bytes = value.vout.to_le_bytes();
        bytes[32..].copy_from_slice(&vout_bytes);
        bytes
    }
}

impl OutPoint {
    /// Creates a new [`OutPoint`].
    #[inline]
    pub fn new(txid: Txid, vout: u32) -> OutPoint {
        OutPoint {
            txid,
            vout,
        }
    }

    /// Creates a "null" `OutPoint`.
    ///
    /// This value is used for coinbase transactions because they don't have any previous outputs.
    #[inline]
    pub fn null() -> OutPoint {
        OutPoint {
            txid: Hash::all_zeros(),
            vout: u32::MAX,
        }
    }

    /// Checks if an `OutPoint` is "null".
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dashcore::blockdata::constants::genesis_block;
    /// use dashcore::Network;
    ///
    /// let block = genesis_block(Network::Mainnet);
    /// let tx = &block.txdata[0];
    ///
    /// // Coinbase transactions don't have any previous output.
    /// assert!(tx.input[0].previous_output.is_null());
    /// ```
    #[inline]
    pub fn is_null(&self) -> bool {
        *self == OutPoint::null()
    }
}

impl Default for OutPoint {
    fn default() -> Self {
        OutPoint::null()
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

impl Encodable for OutPoint {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let len = self.txid.consensus_encode(w)?;
        Ok(len + self.vout.consensus_encode(w)?)
    }
}

impl Decodable for OutPoint {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(OutPoint {
            txid: Decodable::consensus_decode(r)?,
            vout: Decodable::consensus_decode(r)?,
        })
    }
}
impl TryInto<Vec<u8>> for OutPoint {
    type Error = io::Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut buffer = Vec::new();

        self.consensus_encode(&mut buffer)?;

        Ok(buffer)
    }
}

/// An error in parsing an OutPoint.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ParseOutPointError {
    /// Error in TXID part.
    Txid(hashes::hex::Error),
    /// Error in vout part.
    Vout(crate::error::ParseIntError),
    /// Error in general format.
    Format,
    /// Size exceeds max.
    TooLong,
    /// Vout part is not strictly numeric without leading zeroes.
    VoutNotCanonical,
}

impl core::str::FromStr for OutPoint {
    type Err = ParseOutPointError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 75 {
            // 64 + 1 + 10
            return Err(ParseOutPointError::TooLong);
        }
        let find = s.find(':');
        if find.is_none() || find != s.rfind(':') {
            return Err(ParseOutPointError::Format);
        }
        let colon = find.unwrap();
        if colon == 0 || colon == s.len() - 1 {
            return Err(ParseOutPointError::Format);
        }
        Ok(OutPoint {
            txid: s[..colon].parse().map_err(ParseOutPointError::Txid)?,
            vout: parse_vout(&s[colon + 1..])?,
        })
    }
}

impl fmt::Display for ParseOutPointError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseOutPointError::Txid(ref e) => write!(f, "error parsing TXID: {}", e),
            ParseOutPointError::Vout(ref e) => write!(f, "error parsing vout: {}", e),
            ParseOutPointError::Format => write!(f, "OutPoint not in <txid>:<vout> format"),
            ParseOutPointError::TooLong => write!(f, "vout should be at most 10 digits"),
            ParseOutPointError::VoutNotCanonical => {
                write!(f, "no leading zeroes or + allowed in vout part")
            }
        }
    }
}

impl error::Error for ParseOutPointError {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            ParseOutPointError::Txid(ref e) => Some(e),
            ParseOutPointError::Vout(ref e) => Some(e),
            _ => None,
        }
    }
}

/// Parses a string-encoded transaction index (vout).
/// Does not permit leading zeroes or non-digit characters.
fn parse_vout(s: &str) -> Result<u32, ParseOutPointError> {
    if s.len() > 1 {
        let first = s.chars().next().unwrap();
        if first == '0' || first == '+' {
            return Err(ParseOutPointError::VoutNotCanonical);
        }
    }
    crate::parse::int(s).map_err(ParseOutPointError::Vout)
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;
    use crate::Transaction;
    use crate::internal_macros::hex;

    #[test]
    fn test_outpoint() {
        assert_eq!(OutPoint::from_str("i don't care"), Err(ParseOutPointError::Format));
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:1:1"
            ),
            Err(ParseOutPointError::Format)
        );
        assert_eq!(
            OutPoint::from_str("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:"),
            Err(ParseOutPointError::Format)
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:11111111111"
            ),
            Err(ParseOutPointError::TooLong)
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:01"
            ),
            Err(ParseOutPointError::VoutNotCanonical)
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:+42"
            ),
            Err(ParseOutPointError::VoutNotCanonical)
        );
        assert_eq!(
            OutPoint::from_str("i don't care:1"),
            Err(ParseOutPointError::Txid("i don't care".parse::<Txid>().unwrap_err()))
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c945X:1"
            ),
            Err(ParseOutPointError::Txid(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c945X"
                    .parse::<Txid>()
                    .unwrap_err()
            ))
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:lol"
            ),
            Err(ParseOutPointError::Vout(crate::parse::int::<u32, _>("lol").unwrap_err()))
        );

        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:42"
            ),
            Ok(OutPoint {
                txid: "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
                    .parse()
                    .unwrap(),
                vout: 42,
            })
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:0"
            ),
            Ok(OutPoint {
                txid: "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
                    .parse()
                    .unwrap(),
                vout: 0,
            })
        );
    }

    #[test]
    fn out_point_buffer() {
        let mut tx = Transaction {
            version: 0,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };

        let pk_data = hex!("b8e2d839dd21088b78bebfea3e3e632181197982");

        let mut pk_array: [u8; 20] = [0; 20];
        for (index, kek) in pk_array.iter_mut().enumerate() {
            *kek = *pk_data.get(index).unwrap();
        }

        tx.add_burn_output(10000, &pk_array);

        let mut expected_buf = tx.txid().as_byte_array().to_vec();
        let mut expected_index = vec![0, 0, 0, 0];
        // 0 serialized as 32 bits
        expected_buf.append(&mut expected_index);

        let out_point_buffer = tx.out_point_buffer(0).unwrap();

        assert_eq!(out_point_buffer.to_vec(), expected_buf);

        assert!(tx.out_point_buffer(1).is_none());
    }

    /// Regression test for the bug where `OutPoint::deserialize` errored with
    /// "invalid type: map, expected an OutPoint" when an OutPoint-bearing
    /// struct was wrapped by an internally-tagged enum and round-tripped
    /// through serde's intermediate `ContentDeserializer`. `ContentDeserializer`
    /// always reports `is_human_readable() == true`, so a value originally
    /// produced by a non-human-readable encoder ends up replayed into the HR
    /// branch as a map — which the previous string-only HR visitor rejected.
    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_through_internally_tagged_enum() {
        use serde_derive::{Deserialize, Serialize};

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct WithOutPoint {
            out_point: OutPoint,
        }

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        #[serde(tag = "type")]
        enum Tagged {
            A(WithOutPoint),
        }

        let original = Tagged::A(WithOutPoint {
            out_point: OutPoint {
                txid: "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
                    .parse()
                    .unwrap(),
                vout: 7,
            },
        });

        // Round-trip through serde_json::Value forces serde to buffer the value
        // into a Content tree, then replay it through ContentDeserializer when
        // resolving the internally-tagged enum variant. The canonical HR form
        // serializes the OutPoint as a string, so this exercises the visit_str
        // path through ContentDeserializer.
        let value = serde_json::to_value(&original).unwrap();
        let restored: Tagged = serde_json::from_value(value).unwrap();
        assert_eq!(original, restored);

        // Hand-build the struct/map form of the OutPoint inside the tagged
        // enum and deserialize from it. This is the exact shape that triggered
        // the original bug downstream (`platform_value::Value` produces struct
        // shapes for OutPoint because it is non-human-readable, and the tagged
        // enum then replays those through `ContentDeserializer` with
        // `is_human_readable() == true`). Before the fix this failed with
        // `invalid type: map, expected an OutPoint`.
        let map_form = serde_json::json!({
            "type": "A",
            "out_point": {
                "txid": "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
                "vout": 7,
            },
        });
        let from_map: Tagged = serde_json::from_value(map_form).unwrap();
        assert_eq!(original, from_map);

        // The canonical HR string form must still deserialize, so existing
        // JSON producers do not break.
        let from_string: OutPoint = serde_json::from_str(
            "\"5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:7\"",
        )
        .unwrap();
        assert_eq!(
            from_string,
            OutPoint {
                txid: "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
                    .parse()
                    .unwrap(),
                vout: 7,
            },
        );

        // Plain bincode (non-human-readable) round-trip of an `OutPoint`
        // must still succeed via the struct-shape branch — guards against
        // breaking the `visit_seq` path. (Note: a bincode round-trip of the
        // tagged enum above is *not* possible in serde at all — internally-
        // tagged enum dispatch requires `deserialize_any` on the upstream
        // deserializer, and bincode is not self-describing. That's a serde
        // limitation orthogonal to this bug.)
        let raw = OutPoint {
            txid: "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
                .parse()
                .unwrap(),
            vout: 7,
        };
        let cfg = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(raw, cfg).unwrap();
        let (decoded, _): (OutPoint, _) = bincode::serde::decode_from_slice(&bytes, cfg).unwrap();
        assert_eq!(raw, decoded);

        // Duplicate field in the map form must error with `duplicate field`,
        // not silently keep the last value. Parse from a JSON string (rather
        // than `serde_json::json!`) because `Value::Object` deduplicates keys
        // on construction — the duplicate must reach the visitor as separate
        // map entries, which only happens during streaming parse.
        let err = serde_json::from_str::<OutPoint>(
            r#"{"txid":"5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456","txid":"0000000000000000000000000000000000000000000000000000000000000000","vout":7}"#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("duplicate field"),
            "expected duplicate-field error, got: {err}",
        );
    }

    // #[test]
    // fn out_point_parse() {
    //     let mut tx = Transaction {
    //         version: 0,
    //         lock_time: 0,
    //         input: vec![],
    //         output: vec![],
    //         special_transaction_payload: None,
    //     };
    //
    //     let pk_data = hex!("b8e2d839dd21088b78bebfea3e3e632181197982");
    //
    //     let mut pk_array: [u8; 20] = [0; 20];
    //     for (index, kek) in pk_array.iter_mut().enumerate() {
    //         *kek = *pk_data.get(index).unwrap();
    //     }
    //
    //     tx.add_burn_output(10000, &pk_array);
    //
    //     let mut expected_buf = tx.txid().as_byte_array().to_vec();
    //     let mut expected_index = vec![0, 0, 0, 0];
    //     // 0 serialized as 32 bits
    //     expected_buf.append(&mut expected_index);
    //
    //     let out_point_buffer = tx.out_point_buffer(0).unwrap();
    //
    //     let out_point = OutPoint::from(out_point_buffer);
    //
    //     assert_eq!(out_point.vout, 0);
    //     assert_eq!(out_point.txid, tx.txid());
    // }
}
