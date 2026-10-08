// Rust Dash Library
// Written for Dash in 2022 by
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

//! Dash Coinbase Special Transaction.
//!
//! Each time a block is mined it includes a coinbase special transaction.
//! It is defined in DIP4 [dip-0004](https://github.com/dashpay/dips/blob/master/dip-0004.md).
//!

use hashes::Hash;

use crate::bls_sig_utils::BLSSignature;
use crate::consensus::encode::{compact_size_len, read_compact_size, write_compact_size};
use crate::consensus::{Decodable, Encodable, encode};
use crate::hash_types::{MerkleRootAssetUnlocks, MerkleRootMasternodeList, MerkleRootQuorums};
use crate::io;
use crate::io::{Error, ErrorKind};

/// A Coinbase payload. This is contained as the payload of a coinbase special transaction.
/// The Coinbase payload is described in DIP4.
///
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct CoinbasePayload {
    pub version: u16,
    pub height: u32,
    pub merkle_root_masternode_list: MerkleRootMasternodeList,
    pub merkle_root_quorums: MerkleRootQuorums,
    pub best_cl_height: Option<u32>,
    pub best_cl_signature: Option<BLSSignature>,
    pub asset_locked_amount: Option<u64>,
    /// Merkle root over the instance hashes of the block's version 2 asset unlocks, all-zero
    /// when there are none. Present from version 4.
    pub merkle_root_asset_unlocks: Option<MerkleRootAssetUnlocks>,
}

// Same shape as the earlier derived impl, with `merkle_root_asset_unlocks` only from version 4,
// so payloads persisted through binary serde before the field existed keep decoding.
#[cfg(feature = "serde")]
impl serde::Serialize for CoinbasePayload {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        let has_asset_unlocks_root = self.version >= 4;
        let len = if has_asset_unlocks_root {
            8
        } else {
            7
        };
        let mut state = serializer.serialize_struct("CoinbasePayload", len)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("height", &self.height)?;
        state.serialize_field("merkle_root_masternode_list", &self.merkle_root_masternode_list)?;
        state.serialize_field("merkle_root_quorums", &self.merkle_root_quorums)?;
        state.serialize_field("best_cl_height", &self.best_cl_height)?;
        state.serialize_field("best_cl_signature", &self.best_cl_signature)?;
        state.serialize_field("asset_locked_amount", &self.asset_locked_amount)?;
        if has_asset_unlocks_root {
            state.serialize_field("merkle_root_asset_unlocks", &self.merkle_root_asset_unlocks)?;
        }
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CoinbasePayload {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use core::fmt;

        use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};

        const FIELDS: &[&str] = &[
            "version",
            "height",
            "merkle_root_masternode_list",
            "merkle_root_quorums",
            "best_cl_height",
            "best_cl_signature",
            "asset_locked_amount",
            "merkle_root_asset_unlocks",
        ];

        struct CoinbasePayloadVisitor;

        impl<'de> Visitor<'de> for CoinbasePayloadVisitor {
            type Value = CoinbasePayload;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a coinbase payload")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                macro_rules! next {
                    ($index:expr) => {
                        seq.next_element()?
                            .ok_or_else(|| de::Error::invalid_length($index, &self))?
                    };
                }
                let version: u16 = next!(0);
                Ok(CoinbasePayload {
                    version,
                    height: next!(1),
                    merkle_root_masternode_list: next!(2),
                    merkle_root_quorums: next!(3),
                    best_cl_height: next!(4),
                    best_cl_signature: next!(5),
                    asset_locked_amount: next!(6),
                    // Read only from version 4: earlier payloads were written without it.
                    merkle_root_asset_unlocks: if version >= 4 {
                        next!(7)
                    } else {
                        None
                    },
                })
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut version = None;
                let mut height = None;
                let mut merkle_root_masternode_list = None;
                let mut merkle_root_quorums = None;
                let mut best_cl_height = None;
                let mut best_cl_signature = None;
                let mut asset_locked_amount = None;
                let mut merkle_root_asset_unlocks = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "version" => version = Some(map.next_value()?),
                        "height" => height = Some(map.next_value()?),
                        "merkle_root_masternode_list" => {
                            merkle_root_masternode_list = Some(map.next_value()?)
                        }
                        "merkle_root_quorums" => merkle_root_quorums = Some(map.next_value()?),
                        "best_cl_height" => best_cl_height = map.next_value()?,
                        "best_cl_signature" => best_cl_signature = map.next_value()?,
                        "asset_locked_amount" => asset_locked_amount = map.next_value()?,
                        "merkle_root_asset_unlocks" => {
                            merkle_root_asset_unlocks = map.next_value()?
                        }
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                // `merkle_root_asset_unlocks` only exists from version 4, as in `visit_seq`;
                // reject it rather than drop it silently on the next encode.
                let version: u16 = version.ok_or_else(|| de::Error::missing_field("version"))?;
                if version < 4 && merkle_root_asset_unlocks.is_some() {
                    return Err(de::Error::custom(
                        "merkle_root_asset_unlocks only exists from version 4",
                    ));
                }
                Ok(CoinbasePayload {
                    version,
                    height: height.ok_or_else(|| de::Error::missing_field("height"))?,
                    merkle_root_masternode_list: merkle_root_masternode_list
                        .ok_or_else(|| de::Error::missing_field("merkle_root_masternode_list"))?,
                    merkle_root_quorums: merkle_root_quorums
                        .ok_or_else(|| de::Error::missing_field("merkle_root_quorums"))?,
                    best_cl_height,
                    best_cl_signature,
                    asset_locked_amount,
                    merkle_root_asset_unlocks,
                })
            }
        }

        deserializer.deserialize_struct("CoinbasePayload", FIELDS, CoinbasePayloadVisitor)
    }
}

impl CoinbasePayload {
    /// Latest spec version of the Coinbase payload.
    pub const CURRENT_VERSION: u16 = 3;

    /// Create a new Coinbase payload at [`Self::CURRENT_VERSION`].
    pub fn new(
        height: u32,
        merkle_root_masternode_list: MerkleRootMasternodeList,
        merkle_root_quorums: MerkleRootQuorums,
        best_cl_height: Option<u32>,
        best_cl_signature: Option<BLSSignature>,
        asset_locked_amount: Option<u64>,
    ) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            height,
            merkle_root_masternode_list,
            merkle_root_quorums,
            best_cl_height,
            best_cl_signature,
            asset_locked_amount,
            merkle_root_asset_unlocks: None,
        }
    }

    /// The size of the payload in bytes.
    /// version(2) + height(4) + merkle_root_masternode_list(32) + merkle_root_quorums(32)
    /// in addition to the above, if version >= 3: asset_locked_amount(8) + best_cl_height(compact_size) +
    /// best_cl_signature(96)
    /// in addition to the above, if version >= 4: merkle_root_asset_unlocks(32)
    pub fn size(&self) -> usize {
        let mut size: usize = 2 + 4 + 32;
        if self.version >= 2 {
            size += 32; // merkle_root_quorums
        }
        if self.version >= 3 {
            size += 96;
            if let Some(best_cl_height) = self.best_cl_height {
                size += compact_size_len(best_cl_height);
            }
            size += 8;
        }
        if self.version >= 4 {
            size += 32;
        }
        size
    }
}

// Same layout as a derived impl, with `merkle_root_asset_unlocks` only from version 4, so
// payloads persisted before the field existed keep decoding.
#[cfg(feature = "bincode")]
impl bincode::Encode for CoinbasePayload {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.version.encode(encoder)?;
        self.height.encode(encoder)?;
        self.merkle_root_masternode_list.encode(encoder)?;
        self.merkle_root_quorums.encode(encoder)?;
        self.best_cl_height.encode(encoder)?;
        self.best_cl_signature.encode(encoder)?;
        self.asset_locked_amount.encode(encoder)?;
        if self.version >= 4 {
            self.merkle_root_asset_unlocks.encode(encoder)?;
        }
        Ok(())
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for CoinbasePayload {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        use bincode::Decode;

        let version = u16::decode(decoder)?;
        Ok(CoinbasePayload {
            version,
            height: Decode::decode(decoder)?,
            merkle_root_masternode_list: Decode::decode(decoder)?,
            merkle_root_quorums: Decode::decode(decoder)?,
            best_cl_height: Decode::decode(decoder)?,
            best_cl_signature: Decode::decode(decoder)?,
            asset_locked_amount: Decode::decode(decoder)?,
            merkle_root_asset_unlocks: if version >= 4 {
                Decode::decode(decoder)?
            } else {
                None
            },
        })
    }
}

#[cfg(feature = "bincode")]
bincode::impl_borrow_decode!(CoinbasePayload);

impl Encodable for CoinbasePayload {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(w)?;
        len += self.height.consensus_encode(w)?;
        len += self.merkle_root_masternode_list.consensus_encode(w)?;
        if self.version >= 2 {
            len += self.merkle_root_quorums.consensus_encode(w)?;
        }
        if self.version >= 3 {
            if let Some(best_cl_height) = self.best_cl_height {
                len += write_compact_size(w, best_cl_height)?;
            } else {
                return Err(Error::new(ErrorKind::InvalidInput, "best_cl_height is not set"));
            }

            if let Some(ref best_cl_signature) = self.best_cl_signature {
                len += best_cl_signature.consensus_encode(w)?;
            } else {
                return Err(Error::new(ErrorKind::InvalidInput, "best_cl_signature is not set"));
            }

            if let Some(asset_locked_amount) = self.asset_locked_amount {
                len += asset_locked_amount.consensus_encode(w)?;
            } else {
                return Err(Error::new(ErrorKind::InvalidInput, "asset_locked_amount is not set"));
            }
        }
        if self.version >= 4 {
            if let Some(merkle_root_asset_unlocks) = self.merkle_root_asset_unlocks {
                len += merkle_root_asset_unlocks.consensus_encode(w)?;
            } else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "merkle_root_asset_unlocks is not set",
                ));
            }
        }
        Ok(len)
    }
}

impl Decodable for CoinbasePayload {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(r)?;
        let height = u32::consensus_decode(r)?;
        let merkle_root_masternode_list = MerkleRootMasternodeList::consensus_decode(r)?;
        let merkle_root_quorums = if version >= 2 {
            MerkleRootQuorums::consensus_decode(r)?
        } else {
            MerkleRootQuorums::all_zeros()
        };
        let best_cl_height = if version >= 3 {
            Some(read_compact_size(r)?)
        } else {
            None
        };
        let best_cl_signature = if version >= 3 {
            Some(BLSSignature::consensus_decode(r)?)
        } else {
            None
        };
        let asset_locked_amount = if version >= 3 {
            Some(u64::consensus_decode(r)?)
        } else {
            None
        };
        let merkle_root_asset_unlocks = if version >= 4 {
            Some(MerkleRootAssetUnlocks::consensus_decode(r)?)
        } else {
            None
        };
        Ok(CoinbasePayload {
            version,
            height,
            merkle_root_masternode_list,
            merkle_root_quorums,
            best_cl_height,
            best_cl_signature,
            asset_locked_amount,
            merkle_root_asset_unlocks,
        })
    }
}

#[cfg(test)]
mod tests {
    use hashes::Hash;

    use crate::bls_sig_utils::BLSSignature;
    use crate::consensus::{Decodable, Encodable};
    use crate::hash_types::{MerkleRootAssetUnlocks, MerkleRootMasternodeList, MerkleRootQuorums};
    use crate::transaction::special_transaction::coinbase::CoinbasePayload;

    #[test]
    fn size() {
        let test_cases: &[(usize, u16)] = &[(38, 1), (70, 2), (177, 3), (209, 4)];
        for (want, version) in test_cases.iter() {
            let payload = CoinbasePayload {
                height: 1000,
                version: *version,
                merkle_root_masternode_list: MerkleRootMasternodeList::all_zeros(),
                merkle_root_quorums: MerkleRootQuorums::all_zeros(),
                best_cl_height: Some(900),
                best_cl_signature: Some(BLSSignature::from([0; 96])),
                asset_locked_amount: Some(10000),
                merkle_root_asset_unlocks: Some(MerkleRootAssetUnlocks::all_zeros()),
            };
            assert_eq!(payload.size(), *want);
            let actual = payload.consensus_encode(&mut Vec::new()).unwrap();
            assert_eq!(actual, *want);
        }
    }

    #[test]
    fn regression_test_version_1_payload_decode() {
        // Regression test for coinbase payload version 1 over-reading bug
        // This is the exact payload from block 1028171 that was causing the issue
        let payload_hex =
            "01004bb00f002176daba0c98fecfa0903fa527d118fbb704c497ee6ab817945e68ba9ba8743b";
        let payload_bytes = hex_decode(payload_hex).unwrap();

        // Verify payload is 38 bytes (version 1 should be: 2+4+32 = 38 bytes)
        assert_eq!(payload_bytes.len(), 38);

        let mut cursor = std::io::Cursor::new(&payload_bytes);
        let coinbase_payload = CoinbasePayload::consensus_decode(&mut cursor).unwrap();

        // Verify the payload was decoded correctly
        assert_eq!(coinbase_payload.version, 1);
        assert_eq!(coinbase_payload.height, 1028171); // 0x0fb04b in little endian

        // Most importantly: verify we consumed exactly the payload length (no over-reading)
        assert_eq!(
            cursor.position() as usize,
            payload_bytes.len(),
            "Decoder over-read the payload! This indicates the version 1 fix is not working"
        );

        // Verify the size calculation matches
        assert_eq!(coinbase_payload.size(), 38);

        // Verify encoding produces the same length
        let encoded_len = coinbase_payload.consensus_encode(&mut Vec::new()).unwrap();
        assert_eq!(encoded_len, 38);
    }

    #[test]
    fn test_version_conditional_fields() {
        // Test that merkle_root_quorums is only included for version >= 2

        // Version 1: should NOT include merkle_root_quorums
        let payload_v1 = CoinbasePayload {
            version: 1,
            height: 1000,
            merkle_root_masternode_list: MerkleRootMasternodeList::all_zeros(),
            merkle_root_quorums: MerkleRootQuorums::all_zeros(),
            best_cl_height: None,
            best_cl_signature: None,
            asset_locked_amount: None,
            merkle_root_asset_unlocks: None,
        };
        assert_eq!(payload_v1.size(), 38); // 2 + 4 + 32 = 38 (no quorum root)

        // Version 2: should include merkle_root_quorums
        let payload_v2 = CoinbasePayload {
            version: 2,
            height: 1000,
            merkle_root_masternode_list: MerkleRootMasternodeList::all_zeros(),
            merkle_root_quorums: MerkleRootQuorums::all_zeros(),
            best_cl_height: None,
            best_cl_signature: None,
            asset_locked_amount: None,
            merkle_root_asset_unlocks: None,
        };
        assert_eq!(payload_v2.size(), 70); // 2 + 4 + 32 + 32 = 70 (includes quorum root)

        // Test round-trip encoding/decoding for both versions
        let mut encoded_v1 = Vec::new();
        let len_v1 = payload_v1.consensus_encode(&mut encoded_v1).unwrap();
        assert_eq!(len_v1, 38);
        assert_eq!(encoded_v1.len(), 38);

        let mut encoded_v2 = Vec::new();
        let len_v2 = payload_v2.consensus_encode(&mut encoded_v2).unwrap();
        assert_eq!(len_v2, 70);
        assert_eq!(encoded_v2.len(), 70);

        // Decode and verify
        let decoded_v1 =
            CoinbasePayload::consensus_decode(&mut std::io::Cursor::new(&encoded_v1)).unwrap();
        assert_eq!(decoded_v1.version, 1);
        assert_eq!(decoded_v1.height, 1000);

        let decoded_v2 =
            CoinbasePayload::consensus_decode(&mut std::io::Cursor::new(&encoded_v2)).unwrap();
        assert_eq!(decoded_v2.version, 2);
        assert_eq!(decoded_v2.height, 1000);
    }

    #[test]
    fn version_4_round_trips_the_asset_unlocks_root() {
        let root = MerkleRootAssetUnlocks::from_byte_array([0xab; 32]);
        let payload = CoinbasePayload {
            version: 4,
            height: 1000,
            merkle_root_masternode_list: MerkleRootMasternodeList::all_zeros(),
            merkle_root_quorums: MerkleRootQuorums::all_zeros(),
            best_cl_height: Some(900),
            best_cl_signature: Some(BLSSignature::from([0; 96])),
            asset_locked_amount: Some(10000),
            merkle_root_asset_unlocks: Some(root),
        };

        let mut encoded = Vec::new();
        payload.consensus_encode(&mut encoded).unwrap();
        // The root follows `asset_locked_amount` at the end of the payload.
        assert_eq!(&encoded[encoded.len() - 32..], &[0xab; 32]);

        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = CoinbasePayload::consensus_decode(&mut cursor).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(cursor.position() as usize, encoded.len());
    }

    #[cfg(feature = "bincode")]
    #[test]
    fn version_4_bincode_round_trips_the_asset_unlocks_root() {
        let payload = CoinbasePayload {
            version: 4,
            height: 1000,
            merkle_root_masternode_list: MerkleRootMasternodeList::all_zeros(),
            merkle_root_quorums: MerkleRootQuorums::all_zeros(),
            best_cl_height: Some(900),
            best_cl_signature: Some(BLSSignature::from([0; 96])),
            asset_locked_amount: Some(10000),
            merkle_root_asset_unlocks: Some(MerkleRootAssetUnlocks::from_byte_array([0xab; 32])),
        };
        let bytes = bincode::encode_to_vec(&payload, bincode::config::standard()).unwrap();
        let (decoded, read): (CoinbasePayload, usize) =
            bincode::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(read, bytes.len());
    }

    #[test]
    fn version_4_without_asset_unlocks_root_fails_to_encode() {
        let payload = CoinbasePayload {
            version: 4,
            height: 1000,
            merkle_root_masternode_list: MerkleRootMasternodeList::all_zeros(),
            merkle_root_quorums: MerkleRootQuorums::all_zeros(),
            best_cl_height: Some(900),
            best_cl_signature: Some(BLSSignature::from([0; 96])),
            asset_locked_amount: Some(10000),
            merkle_root_asset_unlocks: None,
        };
        assert!(payload.consensus_encode(&mut Vec::new()).is_err());
    }

    /// The shape `CoinbasePayload` had with derived serde before version 4 existed.
    #[cfg(feature = "serde")]
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct PreV4CoinbasePayload {
        version: u16,
        height: u32,
        merkle_root_masternode_list: MerkleRootMasternodeList,
        merkle_root_quorums: MerkleRootQuorums,
        best_cl_height: Option<u32>,
        best_cl_signature: Option<BLSSignature>,
        asset_locked_amount: Option<u64>,
    }

    #[cfg(feature = "serde")]
    fn v3_payloads() -> (CoinbasePayload, PreV4CoinbasePayload) {
        let payload = CoinbasePayload {
            version: 3,
            height: 1000,
            merkle_root_masternode_list: MerkleRootMasternodeList::from_byte_array([1; 32]),
            merkle_root_quorums: MerkleRootQuorums::from_byte_array([2; 32]),
            best_cl_height: Some(900),
            best_cl_signature: Some(BLSSignature::from([3; 96])),
            asset_locked_amount: Some(10000),
            merkle_root_asset_unlocks: None,
        };
        let pre_v4 = PreV4CoinbasePayload {
            version: 3,
            height: 1000,
            merkle_root_masternode_list: payload.merkle_root_masternode_list,
            merkle_root_quorums: payload.merkle_root_quorums,
            best_cl_height: Some(900),
            best_cl_signature: Some(BLSSignature::from([3; 96])),
            asset_locked_amount: Some(10000),
        };
        (payload, pre_v4)
    }

    #[cfg(all(feature = "serde", feature = "bincode"))]
    #[test]
    fn binary_serde_keeps_the_pre_v4_shape_before_version_4() {
        let (payload, pre_v4) = v3_payloads();
        let config = bincode::config::standard();
        let old_bytes = bincode::serde::encode_to_vec(&pre_v4, config).unwrap();
        assert_eq!(bincode::serde::encode_to_vec(&payload, config).unwrap(), old_bytes);
        let (decoded, read): (CoinbasePayload, usize) =
            bincode::serde::decode_from_slice(&old_bytes, config).unwrap();
        assert_eq!((decoded, read), (payload, old_bytes.len()));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn json_keeps_the_pre_v4_shape_before_version_4() {
        let (payload, pre_v4) = v3_payloads();
        let old_json = serde_json::to_value(&pre_v4).unwrap();
        assert_eq!(serde_json::to_value(&payload).unwrap(), old_json);
        assert_eq!(serde_json::from_value::<CoinbasePayload>(old_json).unwrap(), payload);
    }

    #[cfg(all(feature = "serde", feature = "bincode"))]
    #[test]
    fn serde_round_trips_the_asset_unlocks_root_at_version_4() {
        let payload = CoinbasePayload {
            version: 4,
            merkle_root_asset_unlocks: Some(MerkleRootAssetUnlocks::from_byte_array([0xab; 32])),
            ..v3_payloads().0
        };
        let config = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(&payload, config).unwrap();
        let (decoded, read): (CoinbasePayload, usize) =
            bincode::serde::decode_from_slice(&bytes, config).unwrap();
        assert_eq!((decoded, read), (payload.clone(), bytes.len()));

        let json = serde_json::to_value(&payload).unwrap();
        assert!(json.get("merkle_root_asset_unlocks").is_some());
        assert_eq!(serde_json::from_value::<CoinbasePayload>(json).unwrap(), payload);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn json_rejects_the_asset_unlocks_root_before_version_4() {
        let payload = CoinbasePayload {
            version: 4,
            merkle_root_asset_unlocks: Some(MerkleRootAssetUnlocks::from_byte_array([0xab; 32])),
            ..v3_payloads().0
        };
        let mut json = serde_json::to_value(&payload).unwrap();
        json["version"] = 3.into();
        assert!(serde_json::from_value::<CoinbasePayload>(json).is_err());
    }

    fn hex_decode(s: &str) -> Result<Vec<u8>, &'static str> {
        if !s.len().is_multiple_of(2) {
            return Err("Hex string has odd length");
        }

        let mut bytes = Vec::with_capacity(s.len() / 2);
        for chunk in s.as_bytes().chunks(2) {
            let high = hex_digit(chunk[0])?;
            let low = hex_digit(chunk[1])?;
            bytes.push((high << 4) | low);
        }
        Ok(bytes)
    }

    fn hex_digit(digit: u8) -> Result<u8, &'static str> {
        match digit {
            b'0'..=b'9' => Ok(digit - b'0'),
            b'a'..=b'f' => Ok(digit - b'a' + 10),
            b'A'..=b'F' => Ok(digit - b'A' + 10),
            _ => Err("Invalid hex digit"),
        }
    }
}
