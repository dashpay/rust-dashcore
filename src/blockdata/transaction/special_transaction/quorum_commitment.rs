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
//! It is defined in DIP6 https://github.com/dashpay/dips/blob/master/dip-0006.md.
//!

use std::io;
use ::{OutPoint, Script};
use ::{QuorumHash, VarInt};
use bls_sig_utils::{BLSPublicKey, BLSSignature};
use consensus::{Decodable, encode};
use QuorumVVecHash;

#[derive(Clone)]
pub struct QuorumFinalizationCommitment {
    version: u16,
    llmq_type: u8,
    quorum_hash: QuorumHash,
    signers: Vec<u8>,
    valid_members: Vec<u8>,
    quorum_public_key: BLSPublicKey,
    quorum_vvec_hash: QuorumVVecHash,
    quorum_sig: BLSSignature,
    sig: BLSSignature,
}

impl Decodable for QuorumFinalizationCommitment {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(&mut d)?;
        let llmq_type = u8::consensus_decode(&mut d)?;
        let quorum_hash = QuorumHash::consensus_decode(&mut d)?;
        let signers = Vec::<u8>::consensus_decode(&mut d)?;
        let valid_members = Vec::<u8>::consensus_decode(&mut d)?;
        let quorum_public_key = BLSPublicKey::consensus_decode(&mut d)?;
        let quorum_vvec_hash = QuorumVVecHash::consensus_decode(&mut d)?;
        let quorum_sig = BLSSignature::consensus_decode(&mut d)?;
        let sig = BLSSignature::consensus_decode(d)?;
        Ok(QuorumFinalizationCommitment {
            version,
            llmq_type,
            quorum_hash,
            signers,
            valid_members,
            quorum_public_key,
            quorum_vvec_hash,
            quorum_sig,
            sig
        })
    }
}


#[derive(Clone)]
pub struct QuorumCommitmentPayload {
    version: u16,
    height: u32,
    commitment: QuorumFinalizationCommitment,
}

impl Decodable for QuorumCommitmentPayload {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(&mut d)?;
        let height = u32::consensus_decode(&mut d)?;
        let commitment = QuorumFinalizationCommitment::consensus_decode(d)?;
        Ok(QuorumCommitmentPayload {
            version,
            height,
            commitment
        })
    }
}


#[cfg(test)]
mod tests {

}