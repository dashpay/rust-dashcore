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

use crate::bls_sig_utils::BLSSignature;
use crate::consensus::encode::{compact_size_len, read_compact_size, write_compact_size};
use crate::consensus::{encode, Decodable, Encodable};
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
        let mut size: usize = 2 + 4 + 32 + 32;
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
        len += self.merkle_root_quorums.consensus_encode(w)?;
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
        let merkle_root_quorums = MerkleRootQuorums::consensus_decode(r)?;
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
    use crate::consensus::Encodable;
    use crate::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};
    use crate::transaction::special_transaction::coinbase::CoinbasePayload;

    #[test]
    fn size() {
        let test_cases: &[(usize, u16)] = &[(70, 2), (177, 3)];
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
}
