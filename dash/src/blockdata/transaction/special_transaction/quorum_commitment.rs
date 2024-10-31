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

//! Dash Quorum Commitment Special Transaction.
//!
//! It is defined in DIP6 [dip-0006.md](https://github.com/dashpay/dips/blob/master/dip-0006.md).
//!

use std::io::{Read, Write};
use crate::bls_sig_utils::{BLSPublicKey, BLSSignature};
use crate::consensus::{Decodable, Encodable, encode};
use crate::hash_types::{QuorumHash, QuorumVVecHash};
use crate::prelude::*;
use crate::{VarInt, io};

/// A Quorum Finalization Commitment. It is described in the finalization section of DIP6:
/// [dip-0006.md#6-finalization-phase](https://github.com/dashpay/dips/blob/master/dip-0006.md#6-finalization-phase)
///
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct QuorumFinalizationCommitment {
    pub version: u16,
    pub llmq_type: u8,
    pub quorum_hash: QuorumHash,
    pub quorum_index: Option<i16>,
    pub signers: Vec<u8>,
    pub valid_members: Vec<u8>,
    pub quorum_public_key: BLSPublicKey,
    pub quorum_vvec_hash: QuorumVVecHash,
    pub quorum_sig: BLSSignature,
    pub sig: BLSSignature,
}

impl QuorumFinalizationCommitment {
    /// The size of the payload in bytes.
    pub fn size(&self) -> usize {
        let mut size = 2 + 1 + 32 + 48 + 32 + 96 + 96;
        size += VarInt(self.signers.len() as u64).len() + self.signers.len();
        size += VarInt(self.valid_members.len() as u64).len() + self.valid_members.len();
        if self.version == 2 || self.version == 4 {
            size += 16;
        }
        size
    }
}

impl Encodable for QuorumFinalizationCommitment {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(w)?;
        len += self.llmq_type.consensus_encode(w)?;
        len += self.quorum_hash.consensus_encode(w)?;
        if self.version == 2 || self.version == 4 {
            len += self.quorum_index.unwrap().consensus_encode(w)?;
        }
        len += self.signers.consensus_encode(w)?;
        len += self.valid_members.consensus_encode(w)?;
        len += self.quorum_public_key.consensus_encode(w)?;
        len += self.quorum_vvec_hash.consensus_encode(w)?;
        len += self.quorum_sig.consensus_encode(w)?;
        len += self.sig.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for QuorumFinalizationCommitment {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(r)?;
        let llmq_type = u8::consensus_decode(r)?;
        let quorum_hash = QuorumHash::consensus_decode(r)?;
        let quorum_index = if version == 2 || version == 4 { Some(i16::consensus_decode(r)?) } else { None };
        let signers_count = read_compact_size(r)?;
        let signers = read_fixed_bitset(r, signers_count as usize)?;
        let valid_members_count = read_compact_size(r)?;
        let valid_members = read_fixed_bitset(r, valid_members_count as usize)?;
        let quorum_public_key = BLSPublicKey::consensus_decode(r)?;
        let quorum_vvec_hash = QuorumVVecHash::consensus_decode(r)?;
        let quorum_sig = BLSSignature::consensus_decode(r)?;
        let sig = BLSSignature::consensus_decode(r)?;
        Ok(QuorumFinalizationCommitment {
            version,
            llmq_type,
            quorum_hash,
            quorum_index,
            signers: signers.iter().map(|&b| b as u8).collect(),
            valid_members: valid_members.iter().map(|&b| b as u8).collect(),
            quorum_public_key,
            quorum_vvec_hash,
            quorum_sig,
            sig,
        })
    }
}

/// A Quorum Commitment Payload used in a Quorum Commitment Special Transaction.
/// This is used in the mining phase as described in DIP 6:
/// [dip-0006.md#7-mining-phase](https://github.com/dashpay/dips/blob/master/dip-0006.md#7-mining-phase).
///
/// Miners take the best final commitment for a DKG session and mine it into a block.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct QuorumCommitmentPayload {
    version: u16,
    height: u32,
    finalization_commitment: QuorumFinalizationCommitment,
}

impl QuorumCommitmentPayload {
    /// The size of the payload in bytes.
    pub fn size(&self) -> usize { 2 + 4 + self.finalization_commitment.size() }
}

impl Encodable for QuorumCommitmentPayload {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(w)?;
        len += self.height.consensus_encode(w)?;
        len += self.finalization_commitment.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for QuorumCommitmentPayload {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(r)?;
        let height = u32::consensus_decode(r)?;
        let finalization_commitment = QuorumFinalizationCommitment::consensus_decode(r)?;
        Ok(QuorumCommitmentPayload { version, height, finalization_commitment })
    }
}

fn read_compact_size<R: Read + ?Sized>(r: &mut R) -> io::Result<u64> {
    let mut marker = [0u8; 1];
    r.read_exact(&mut marker)?;
    match marker[0] {
        0xFD => {
            // Read the next 2 bytes as a little-endian u16
            let mut buf = [0u8; 2];
            r.read_exact(&mut buf)?;
            Ok(u16::from_le_bytes(buf) as u64)
        }
        0xFE => {
            // Read the next 4 bytes as a little-endian u32
            let mut buf = [0u8; 4];
            r.read_exact(&mut buf)?;
            Ok(u32::from_le_bytes(buf) as u64)
        }
        0xFF => {
            // Read the next 8 bytes as a little-endian u64
            let mut buf = [0u8; 8];
            r.read_exact(&mut buf)?;
            Ok(u64::from_le_bytes(buf))
        }
        value => {
            // For values less than 253, the value is stored directly in the marker byte
            Ok(value as u64)
        }
    }
}

fn read_fixed_bitset<R: Read + ?Sized>(r: &mut R, size: usize) -> std::io::Result<Vec<bool>> {
    // Calculate the number of bytes needed
    let num_bytes = (size + 7) / 8;
    let mut bytes = vec![0u8; num_bytes];

    // Read bytes from the reader
    r.read_exact(&mut bytes)?;

    // Unpack bits into a vector of bools
    let mut bits = Vec::with_capacity(size);
    for p in 0..size {
        let byte = bytes[p / 8];
        let bit = (byte >> (p % 8)) & 1;
        bits.push(bit != 0);
    }

    Ok(bits)
}

#[cfg(test)]
mod tests {
    use hashes::Hash;

    use crate::bls_sig_utils::{BLSPublicKey, BLSSignature};
    use crate::consensus::Encodable;
    use crate::hash_types::{QuorumHash, QuorumVVecHash};
    use crate::transaction::special_transaction::quorum_commitment::{
        QuorumCommitmentPayload, QuorumFinalizationCommitment,
    };

    #[test]
    fn size() {
        let want = 325;
        let payload = QuorumCommitmentPayload {
            version: 0,
            height: 0,
            finalization_commitment: QuorumFinalizationCommitment {
                version: 0,
                llmq_type: 0,
                quorum_hash: QuorumHash::all_zeros(),
                quorum_index: None,
                signers: vec![1, 2, 3, 4, 5],
                valid_members: vec![6, 7, 8, 9, 0],
                quorum_public_key: BLSPublicKey::from([0; 48]),
                quorum_vvec_hash: QuorumVVecHash::all_zeros(),
                quorum_sig: BLSSignature::from([0; 96]),
                sig: BLSSignature::from([0; 96]),
            },
        };
        let actual = payload.consensus_encode(&mut Vec::new()).unwrap();
        assert_eq!(payload.size(), want);
        assert_eq!(actual, want);
    }
}
