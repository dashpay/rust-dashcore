// SPDX-License-Identifier: CC0-1.0

//! PSBT serialization.
//!
//! Traits to serialize PSBT values to and from raw bytes
//! according to the BIP-174 specification.
//!

use core::convert::TryInto;

use dashcore_hashes::{hash160, ripemd160, sha256, sha256d, Hash};

use super::map::{Input, Map, Output, PsbtSighashType};
use super::Psbt;
use crate::bip32::KeySource;
use crate::bip32::{ChildNumber, Fingerprint};
use crate::psbt::{Error, PartiallySignedTransaction};
use alloc::string::String;
use alloc::vec::Vec;
use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::txout::TxOut;
use dashcore::blockdata::transaction::Transaction;
use dashcore::consensus::encode::{self, serialize, Decodable};
use dashcore::crypto::ecdsa;
use dashcore::crypto::key::PublicKey;
use dashcore::io;
/// A trait for serializing a value as raw data for insertion into PSBT
/// key-value maps.
pub trait Serialize {
    /// Serialize a value as raw data.
    fn serialize(&self) -> Vec<u8>;
}

/// A trait for deserializing a value from raw data in PSBT key-value maps.
pub trait Deserialize: Sized {
    /// Deserialize a value from raw data.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
}

impl PartiallySignedTransaction {
    /// Serialize a value as bytes in hex.
    pub fn serialize_hex(&self) -> String {
        use dashcore::prelude::DisplayHex;
        format!("{:x}", self.serialize().as_hex())
    }

    /// Serialize as raw binary data
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        //  <magic>
        buf.extend_from_slice(b"psbt");

        buf.push(0xff_u8);

        buf.extend(self.serialize_map());

        for i in &self.inputs {
            buf.extend(i.serialize_map());
        }

        for i in &self.outputs {
            buf.extend(i.serialize_map());
        }

        buf
    }

    /// Deserialize a value from raw binary data.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        const MAGIC_BYTES: &[u8] = b"psbt";
        if bytes.get(0..MAGIC_BYTES.len()) != Some(MAGIC_BYTES) {
            return Err(Error::InvalidMagic);
        }

        const PSBT_SEPARATOR: u8 = 0xff_u8;
        if bytes.get(MAGIC_BYTES.len()) != Some(&PSBT_SEPARATOR) {
            return Err(Error::InvalidSeparator);
        }

        let mut d = bytes.get(5..).ok_or(Error::NoMorePairs)?;

        let mut global = Psbt::decode_global(&mut d)?;
        global.unsigned_tx_checks()?;

        let inputs: Vec<Input> = {
            let inputs_len: usize = global.unsigned_tx.input.len();

            let mut inputs: Vec<Input> = Vec::with_capacity(inputs_len);

            for _ in 0..inputs_len {
                inputs.push(Input::decode(&mut d)?);
            }

            inputs
        };

        let outputs: Vec<Output> = {
            let outputs_len: usize = global.unsigned_tx.output.len();

            let mut outputs: Vec<Output> = Vec::with_capacity(outputs_len);

            for _ in 0..outputs_len {
                outputs.push(Output::decode(&mut d)?);
            }

            outputs
        };

        global.inputs = inputs;
        global.outputs = outputs;
        Ok(global)
    }
}
impl_psbt_de_serialize!(Transaction);
impl_psbt_de_serialize!(TxOut);
impl_psbt_hash_de_serialize!(ripemd160::Hash);
impl_psbt_hash_de_serialize!(sha256::Hash);
impl_psbt_hash_de_serialize!(hash160::Hash);
impl_psbt_hash_de_serialize!(sha256d::Hash);

impl Serialize for ScriptBuf {
    fn serialize(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl Deserialize for ScriptBuf {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from(bytes.to_vec()))
    }
}

impl Serialize for PublicKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf).expect("vecs don't error");
        buf
    }
}

impl Deserialize for PublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        PublicKey::from_slice(bytes).map_err(Error::InvalidPublicKey)
    }
}

impl Serialize for secp256k1::PublicKey {
    fn serialize(&self) -> Vec<u8> {
        secp256k1::PublicKey::serialize(self).to_vec()
    }
}

impl Deserialize for secp256k1::PublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        secp256k1::PublicKey::from_slice(bytes).map_err(Error::InvalidSecp256k1PublicKey)
    }
}

impl Serialize for ecdsa::Signature {
    fn serialize(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl Deserialize for ecdsa::Signature {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        // NB: Since BIP-174 says "the signature as would be pushed to the stack from
        // a scriptSig we should ideally use a consensus deserialization and do
        // not error on a non-standard values. However,
        //
        // 1) the current implementation of from_u32_consensus(`flag`) does not preserve
        // the sighash byte `flag` mapping all unknown values to EcdsaSighashType::All or
        // EcdsaSighashType::AllPlusAnyOneCanPay. Therefore, break the invariant
        // EcdsaSig::from_slice(&sl[..]).to_vec = sl.
        //
        // 2) This would cause to have invalid signatures because the sighash message
        // also has a field sighash_u32 (See BIP141). For example, when signing with non-standard
        // 0x05, the sighash message would have the last field as 0x05u32 while, the verification
        // would use check the signature assuming sighash_u32 as `0x01`.
        ecdsa::Signature::from_slice(bytes).map_err(|e| match e {
            ecdsa::Error::EmptySignature => Error::InvalidEcdsaSignature(e),
            ecdsa::Error::NonStandardSighashType(flag) => Error::NonStandardSighashType(flag),
            ecdsa::Error::Secp256k1(..) => Error::InvalidEcdsaSignature(e),
            ecdsa::Error::HexEncoding(..) => {
                unreachable!("Decoding from slice, not hex")
            }
            _ => Error::InvalidEcdsaSignature(e),
        })
    }
}

impl Serialize for KeySource {
    fn serialize(&self) -> Vec<u8> {
        let mut rv: Vec<u8> = Vec::with_capacity(key_source_len(self));

        rv.append(&mut self.0.to_bytes().to_vec());

        for cnum in self.1.into_iter() {
            rv.append(&mut serialize(&u32::from(*cnum)))
        }

        rv
    }
}

impl Deserialize for KeySource {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }

        let fprint: Fingerprint = bytes[0..4].try_into().expect("4 is the fingerprint length");
        let mut dpath: Vec<ChildNumber> = Default::default();

        let mut d = &bytes[4..];
        while !d.is_empty() {
            match u32::consensus_decode(&mut d) {
                Ok(index) => dpath.push(index.into()),
                Err(e) => return Err(e)?,
            }
        }

        Ok((fprint, dpath.into()))
    }
}

// partial sigs
impl Serialize for Vec<u8> {
    fn serialize(&self) -> Vec<u8> {
        self.clone()
    }
}

impl Deserialize for Vec<u8> {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Ok(bytes.to_vec())
    }
}

impl Serialize for PsbtSighashType {
    fn serialize(&self) -> Vec<u8> {
        serialize(&self.to_u32())
    }
}

impl Deserialize for PsbtSighashType {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let raw: u32 = encode::deserialize(bytes)?;
        Ok(PsbtSighashType {
            inner: raw,
        })
    }
}

// Helper function to compute key source len
fn key_source_len(key_source: &KeySource) -> usize {
    4 + 4 * key_source.1.as_ref().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_deserialize_non_standard_psbt_sighash_type() {
        let non_standard_sighash = [222u8, 0u8, 0u8, 0u8]; // 32 byte value.
        let sighash = PsbtSighashType::deserialize(&non_standard_sighash);
        assert!(sighash.is_ok())
    }

    #[test]
    #[should_panic(expected = "InvalidMagic")]
    fn invalid_vector_1() {
        let hex_psbt = b"0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300";
        PartiallySignedTransaction::deserialize(hex_psbt).unwrap();
    }
}
