use std::io;
use std::io::{Error, Write};
use bls_sig_utils::BLSSignature;
use consensus::{Decodable, Encodable, encode};
use QuorumHash;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct CreditWithdrawalPayload {
    version: u8,
    index: u64,
    fee: u32,
    request_height: u32,
    quorum_hash: QuorumHash,
    quorum_sig: BLSSignature,
}

impl Encodable for CreditWithdrawalPayload {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.index.consensus_encode(&mut s)?;
        len += self.fee.consensus_encode(&mut s)?;
        len += self.request_height.consensus_encode(&mut s)?;
        len += self.quorum_hash.consensus_encode(&mut s)?;
        len += self.quorum_sig.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for CreditWithdrawalPayload {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let version = u8::consensus_decode(&mut d)?;
        let index = u64::consensus_decode(&mut d)?;
        let fee = u32::consensus_decode(&mut d)?;
        let request_height = u32::consensus_decode(&mut d)?;
        let quorum_hash = QuorumHash::consensus_decode(&mut d)?;
        let quorum_sig = BLSSignature::consensus_decode(&mut d)?;
        Ok(CreditWithdrawalPayload {
            version,
            index,
            fee,
            request_height,
            quorum_hash,
            quorum_sig
        })
    }
}