use std::io::{Read, Write};
use consensus::{Decodable, Encodable};
use consensus::encode::Error;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct BLSPublicKey([u8;48]);

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct BLSSignature([u8;96]);

impl Encodable for BLSPublicKey {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, std::io::Error> {
        s.write(self.0.as_slice())?;
        Ok(48)
    }
}

impl Decodable for BLSPublicKey {
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, Error> {
        let mut data :[u8;48] = [0u8; 48];
        d.read_exact(&mut data)?;
        Ok(BLSPublicKey(data))
    }
}

impl Encodable for BLSSignature {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, std::io::Error> {
        s.write(self.0.as_slice())?;
        Ok(96)
    }
}

impl Decodable for BLSSignature {
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, Error> {
        let mut data :[u8;96] = [0u8; 96];
        d.read_exact(&mut data)?;
        Ok(BLSSignature(data))
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