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

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};

use hashes::Hash;

use crate::bls_sig_utils::BLSSignature;
use crate::consensus::encode::{compact_size_len, read_compact_size, write_compact_size};
use crate::consensus::{Decodable, Encodable, encode};
use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
use crate::io;
use crate::io::{Error, ErrorKind};

/// A Coinbase payload. This is contained as the payload of a coinbase special transaction.
/// The Coinbase payload is described in DIP4.
///
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct CoinbasePayload {
    pub version: u16,
    pub height: u32,
    pub merkle_root_masternode_list: MerkleRootMasternodeList,
    pub merkle_root_quorums: MerkleRootQuorums,
    pub best_cl_height: Option<u32>,
    pub best_cl_signature: Option<BLSSignature>,
    pub asset_locked_amount: Option<u64>,
}

impl CoinbasePayload {
    /// The size of the payload in bytes.
    /// version(2) + height(4) + merkle_root_masternode_list(32) + merkle_root_quorums(32)
    /// in addition to the above, if version >= 3: asset_locked_amount(8) + best_cl_height(compact_size) +
    /// best_cl_signature(96)
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
        size
    }
}

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
        Ok(CoinbasePayload {
            version,
            height,
            merkle_root_masternode_list,
            merkle_root_quorums,
            best_cl_height,
            best_cl_signature,
            asset_locked_amount,
        })
    }
}

#[cfg(test)]
mod tests {
    use hashes::Hash;

    use crate::bls_sig_utils::BLSSignature;
    use crate::consensus::{Decodable, Encodable};
    use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
    use crate::transaction::special_transaction::coinbase::CoinbasePayload;

    #[test]
    fn size() {
        let test_cases: &[(usize, u16)] = &[(38, 1), (70, 2), (177, 3)];
        for (want, version) in test_cases.iter() {
            let payload = CoinbasePayload {
                height: 1000,
                version: *version,
                merkle_root_masternode_list: MerkleRootMasternodeList::all_zeros(),
                merkle_root_quorums: MerkleRootQuorums::all_zeros(),
                best_cl_height: Some(900),
                best_cl_signature: Some(BLSSignature::from([0; 96])),
                asset_locked_amount: Some(10000),
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
        let payload_hex = "01004bb00f002176daba0c98fecfa0903fa527d118fbb704c497ee6ab817945e68ba9ba8743b";
        let payload_bytes = hex_decode(payload_hex).unwrap();
        
        // Verify payload is 38 bytes (version 1 should be: 2+4+32 = 38 bytes)
        assert_eq!(payload_bytes.len(), 38);
        
        let mut cursor = std::io::Cursor::new(&payload_bytes);
        let coinbase_payload = CoinbasePayload::consensus_decode(&mut cursor).unwrap();
        
        // Verify the payload was decoded correctly
        assert_eq!(coinbase_payload.version, 1);
        assert_eq!(coinbase_payload.height, 1028171); // 0x0fb04b in little endian
        
        // Most importantly: verify we consumed exactly the payload length (no over-reading)
        assert_eq!(cursor.position() as usize, payload_bytes.len(),
                   "Decoder over-read the payload! This indicates the version 1 fix is not working");
        
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
        let decoded_v1 = CoinbasePayload::consensus_decode(&mut std::io::Cursor::new(&encoded_v1)).unwrap();
        assert_eq!(decoded_v1.version, 1);
        assert_eq!(decoded_v1.height, 1000);
        
        let decoded_v2 = CoinbasePayload::consensus_decode(&mut std::io::Cursor::new(&encoded_v2)).unwrap();
        assert_eq!(decoded_v2.version, 2);
        assert_eq!(decoded_v2.height, 1000);
    }

    fn hex_decode(s: &str) -> Result<Vec<u8>, &'static str> {
        if s.len() % 2 != 0 {
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
