//! Dash MNHF Signal Special Transaction.
//!
//! The MNHF (Masternode Hard Fork) Signal special transaction is used by masternodes to collectively 
//! signal when a network hard fork should activate. It's a voting mechanism where masternode quorums 
//! can indicate consensus for protocol upgrades.
//!
//! The transaction has no inputs/outputs and pays no fees - it's purely for governance signaling 
//! to coordinate network upgrades in a decentralized way.
//!
//! The special transaction type used for MNHFTx Transactions is 7.

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use hashes::Hash;

use crate::bls_sig_utils::BLSSignature;
use crate::consensus::{Decodable, Encodable, encode};
use crate::hash_types::QuorumHash;
use crate::io;

/// A MNHF Signal Payload used in a MNHF Signal Special Transaction.
/// This is used by masternodes to signal consensus for hard fork activations.
/// 
/// The payload contains an nVersion field and a nested MNHFTx signal structure.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct MnhfSignalPayload {
    /// Version of the MNHF signal payload (nVersion in C++)
    pub version: u8,
    /// The version bit being signaled for (versionBit in MNHFTx)
    pub version_bit: u8,
    /// Hash of the quorum that created this signal (quorumHash in MNHFTx)
    pub quorum_hash: QuorumHash,
    /// BLS signature from the quorum (sig in MNHFTx)
    pub sig: BLSSignature,
}

impl MnhfSignalPayload {
    /// The size of the payload in bytes.
    /// version(1) + version_bit(1) + quorum_hash(32) + sig(96) = 130 bytes
    pub fn size(&self) -> usize {
        130
    }
}

impl Encodable for MnhfSignalPayload {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(w)?;
        len += self.version_bit.consensus_encode(w)?;
        len += self.quorum_hash.consensus_encode(w)?;
        len += self.sig.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for MnhfSignalPayload {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let version = u8::consensus_decode(r)?;
        let version_bit = u8::consensus_decode(r)?;
        let quorum_hash = QuorumHash::consensus_decode(r)?;
        let sig = BLSSignature::consensus_decode(r)?;
        
        Ok(MnhfSignalPayload {
            version,
            version_bit,
            quorum_hash,
            sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{Decodable, Encodable};

    #[test]
    fn test_mnhf_signal_payload_size() {
        let payload = MnhfSignalPayload {
            version: 1,
            version_bit: 11,
            quorum_hash: QuorumHash::all_zeros(),
            sig: BLSSignature::from([0; 96]),
        };
        
        assert_eq!(payload.size(), 130);
        
        // Test that encoding produces the expected size
        let encoded_len = payload.consensus_encode(&mut Vec::new()).unwrap();
        assert_eq!(encoded_len, 130);
    }

    #[test]
    fn test_mnhf_signal_payload_roundtrip() {
        let original = MnhfSignalPayload {
            version: 1,
            version_bit: 11,
            quorum_hash: QuorumHash::all_zeros(),
            sig: BLSSignature::from([42; 96]),
        };
        
        // Encode
        let mut encoded = Vec::new();
        let encoded_len = original.consensus_encode(&mut encoded).unwrap();
        assert_eq!(encoded_len, 130);
        assert_eq!(encoded.len(), 130);
        
        // Decode
        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = MnhfSignalPayload::consensus_decode(&mut cursor).unwrap();
        
        // Verify round-trip
        assert_eq!(original, decoded);
        assert_eq!(cursor.position() as usize, encoded.len());
    }

    #[test]
    fn test_failing_transaction_payload() {
        // Test the actual failing payload from the error message
        // extraPayload: "010bdd1ec5c4a8db99beced78f2c16565d31458bbf4771a55f552900000000000000afc931a000054238f952286289448847d86e25c20b6d357bf2845ed286ecdee426ca53a0f06de790c5b3a8c13913c1ad10da511122f9de8cd98c4af693acda58379fe572c2a8b41e7a860b85653306a6a2c1a6e8e3ba47560f17c1d5bf1a4889"
        let payload_hex = "010bdd1ec5c4a8db99beced78f2c16565d31458bbf4771a55f552900000000000000afc931a000054238f952286289448847d86e25c20b6d357bf2845ed286ecdee426ca53a0f06de790c5b3a8c13913c1ad10da511122f9de8cd98c4af693acda58379fe572c2a8b41e7a860b85653306a6a2c1a6e8e3ba47560f17c1d5bf1a4889";
        let payload_bytes = hex_decode(payload_hex).unwrap();
        
        // Verify payload is 130 bytes
        assert_eq!(payload_bytes.len(), 130);
        
        let mut cursor = std::io::Cursor::new(&payload_bytes);
        let payload = MnhfSignalPayload::consensus_decode(&mut cursor).unwrap();
        
        // Verify the payload was decoded correctly
        assert_eq!(payload.version, 1);
        assert_eq!(payload.version_bit, 11);
        
        // Verify we consumed exactly the payload length (no over-reading)
        assert_eq!(cursor.position() as usize, payload_bytes.len(),
                   "Decoder over-read the payload!");
        
        // Verify the size calculation matches
        assert_eq!(payload.size(), 130);
        
        // Verify encoding produces the same length
        let encoded_len = payload.consensus_encode(&mut Vec::new()).unwrap();
        assert_eq!(encoded_len, 130);
        
        // Verify round-trip encoding matches original bytes
        let mut encoded = Vec::new();
        payload.consensus_encode(&mut encoded).unwrap();
        assert_eq!(encoded, payload_bytes);
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