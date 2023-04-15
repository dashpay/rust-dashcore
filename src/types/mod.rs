use std::convert::{TryFrom, TryInto};
use hashes::hex::FromHex;
use consensus::encode;
use crate::Error;

pub type ProTxHash = CryptoHash;

pub type QuorumHash = CryptoHash;

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Ord, PartialOrd)]
pub struct CryptoHash(#[serde(with = "hex")] pub [u8; 32]);

impl TryFrom<&str> for CryptoHash {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let vec = Vec::from_hex(value).map_err(Error::Hex)?;
        Ok(CryptoHash(vec.try_into().map_err(|_| encode::Error::InvalidVectorSize { expected: 32, actual: vec.len() })?))
    }
}
