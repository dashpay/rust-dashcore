use std::io;
use std::io::{Error, Write};
use consensus::{Decodable, Encodable, encode};
use TxOut;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct AssetLockPayload {
    version: u8,
    count: u8,
    credit_outputs: Vec<TxOut>,
}

impl Encodable for AssetLockPayload {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.count.consensus_encode(&mut s)?;
        len += self.credit_outputs.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for AssetLockPayload {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let version = u8::consensus_decode(&mut d)?;
        let count = u8::consensus_decode(&mut d)?;
        let credit_outputs = Vec::<TxOut>::consensus_decode(&mut d)?;
        Ok(AssetLockPayload {
            version,
            count,
            credit_outputs,
        })
    }
}