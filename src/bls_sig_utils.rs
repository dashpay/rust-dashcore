use std::io::Read;
use consensus::Decodable;
use consensus::encode::Error;

#[derive(Clone)]
pub struct BLSPublicKey([u8;48]);

#[derive(Clone)]
pub struct BLSSignature([u8;96]);

impl Decodable for BLSPublicKey {
    fn consensus_decode<D: Read>(d: D) -> Result<Self, Error> {
        Ok(hashes::hex::FromHex(d)?)
        // Ok(Self::from_inner($element::hex::FromHex::consensus_decode(d)?))
    }
}

impl Decodable for BLSSignature {
    fn consensus_decode<D: Read>(d: D) -> Result<Self, Error> {
        Ok(hashes::hex::FromHex(d)?)
        // Ok(Self::from_inner($element::hex::FromHex::consensus_decode(d)?))
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