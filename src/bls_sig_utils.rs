use std::convert::TryFrom;
use std::io::{Read, Write};
use consensus::{Decodable, Encodable};
use consensus::encode::Error;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct BLSPublicKey([u8;48]);

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct BLSSignature([u8;96]);

impl Encodable for BLSPublicKey {
    fn consensus_encode<S: Write>(&self, s: S) -> Result<usize, std::io::Error> {
        Ok(hex::encode(s)?)
    }
}

impl Decodable for BLSPublicKey {
    fn consensus_decode<D: Read>(d: D) -> Result<Self, Error> {
        Ok(BLSPublicKey::try_from(hex::decode(d))?)
    }
}

impl Encodable for BLSSignature {
    fn consensus_encode<S: Write>(&self, s: S) -> Result<usize, std::io::Error> {
        Ok(hex::encode(s)?)
    }
}

impl Decodable for BLSSignature {
    fn consensus_decode<D: Read>(d: D) -> Result<Self, Error> {
        Ok(BLSSignature::try_from(hex::decode(d))?)
    }
}

// macro_rules! impl_elementencode {
//     ($element:ident) => {
//         impl $crate::consensus::Encodable for $element {
//             fn consensus_encode<S: $crate::io::Write>(&self, s: S) -> Result<usize, $crate::io::Error> {
//                 self.0.consensus_encode(s)
//             }
//         }
//
//         impl $crate::consensus::Decodable for $element {
//             fn consensus_decode<D: $crate::io::Read>(d: D) -> Result<Self, $crate::consensus::encode::Error> {
//                 Ok(Self::from_inner($element::hex::FromHex::consensus_decode(d)?))
//             }
//         }
//     }
// }
//
// impl_elementencode!(BLSPublicKey);
// impl_elementencode!(BLSSignature);