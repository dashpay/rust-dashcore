// SPDX-License-Identifier: CC0-1.0

//! Signature hash implementation (used in transaction signing).
//!
//! Efficient implementation of the algorithm to compute the message to be signed.
//! Computing signature hashes is required to sign a transaction and this module is designed to
//! handle its complexity efficiently. Computing these hashes is as simple as creating
//! [`SighashCache`] and calling its methods.

use core::borrow::Borrow;
use core::fmt;

use hashes::Hash;

pub use dashcore_crypto::sighash::SplitAnyoneCanPay;
pub use dashcore_crypto::sighash::{
    EcdsaSighashType, InvalidSighashTypeError, LegacySighash, NonStandardSighashType,
    NonStandardSighashTypeError, SighashTypeParseError,
};

use crate::blockdata::opcodes::all::OP_CODESEPARATOR;
use crate::blockdata::transaction::txout::TxOut;
use crate::blockdata::transaction::{EncodeSigningDataResult, Transaction};
use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::io;
use crate::prelude::*;
use crate::script::{Script, ScriptBuf};

/// Used for signature hash for invalid use of SIGHASH_SINGLE.
#[rustfmt::skip]
pub(crate) const UINT256_ONE: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
];

/// Efficiently calculates signature hash message.
#[derive(Debug)]
pub struct SighashCache<T: Borrow<Transaction>> {
    /// Access to transaction required for transaction introspection.
    tx: T,
}

/// Possible errors in computing the signature message.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Could happen only by using `*_encode_signing_*` methods with custom writers, engines writers
    /// like the ones used in methods `*_signature_hash` do not error.
    Io(io::ErrorKind),

    /// Requested index is greater or equal than the number of inputs in the transaction.
    IndexOutOfInputsBounds {
        /// Requested index.
        index: usize,
        /// Number of transaction inputs.
        inputs_size: usize,
    },

    /// Using `SIGHASH_SINGLE` without a "corresponding output" (an output with the same index as
    /// the input being verified) is a validation failure.
    SingleWithoutCorrespondingOutput {
        /// Requested index.
        index: usize,
        /// Number of transaction outputs.
        outputs_size: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;

        match self {
            Io(error_kind) => write!(f, "writer errored: {:?}", error_kind),
            IndexOutOfInputsBounds {
                index,
                inputs_size,
            } => write!(
                f,
                "Requested index ({}) is greater or equal than the number of transaction inputs ({})",
                index, inputs_size
            ),
            SingleWithoutCorrespondingOutput {
                index,
                outputs_size,
            } => write!(
                f,
                "SIGHASH_SINGLE for input ({}) haven't a corresponding output (#outputs:{})",
                index, outputs_size
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match self {
            Io(_)
            | IndexOutOfInputsBounds {
                ..
            }
            | SingleWithoutCorrespondingOutput {
                ..
            } => None,
        }
    }
}

impl<R: Borrow<Transaction>> SighashCache<R> {
    /// Constructs a new `SighashCache` from an unsigned transaction.
    ///
    /// For the generated sighashes to be valid, no fields in the transaction may change except
    /// for script_sig.
    pub fn new(tx: R) -> Self {
        SighashCache {
            tx,
        }
    }

    /// Returns the reference to the cached transaction.
    pub fn transaction(&self) -> &Transaction {
        self.tx.borrow()
    }

    /// Destroys the cache and recovers the stored transaction.
    pub fn into_transaction(self) -> R {
        self.tx
    }

    /// Encodes the legacy signing data from which a signature hash for a given input index with a
    /// given sighash flag can be computed.
    ///
    /// To actually produce a scriptSig, this hash needs to be run through an ECDSA signer, the
    /// [`EcdsaSighashType`] appended to the resulting sig, and a script written around this, but
    /// this is the general (and hard) part.
    ///
    /// The `sighash_type` supports an arbitrary `u32` value, instead of just [`EcdsaSighashType`],
    /// because internally 4 bytes are being hashed, even though only the lowest byte is appended to
    /// signature in a transaction.
    ///
    /// # Warning
    ///
    /// - `script_pubkey` is the script code. As in Dash Core, every OP_CODESEPARATOR opcode in it
    ///   is left out of the signing data. Passing only the part of the script after the last
    ///   executed OP_CODESEPARATOR is up to the caller, since choosing it needs script evaluation.
    /// - Does NOT handle the sighash single bug (see "Return type" section)
    ///
    /// # Returns
    ///
    /// This function can't handle the SIGHASH_SINGLE bug internally, so it returns [`EncodeSigningDataResult`]
    /// that must be handled by the caller (see [`EncodeSigningDataResult::is_sighash_single_bug`]).
    pub fn legacy_encode_signing_data_to<Write: io::Write, U: Into<u32>>(
        &self,
        writer: Write,
        input_index: usize,
        script_pubkey: &Script,
        sighash_type: U,
    ) -> EncodeSigningDataResult<Error> {
        if input_index >= self.tx.borrow().input.len() {
            return EncodeSigningDataResult::WriteResult(Err(Error::IndexOutOfInputsBounds {
                index: input_index,
                inputs_size: self.tx.borrow().input.len(),
            }));
        }
        let sighash_type: u32 = sighash_type.into();

        if is_invalid_use_of_sighash_single(
            sighash_type,
            input_index,
            self.tx.borrow().output.len(),
        ) {
            // We cannot correctly handle the SIGHASH_SINGLE bug here because usage of this function
            // will result in the data written to the writer being hashed, however the correct
            // handling of the SIGHASH_SINGLE bug is to return the 'one array' - either implement
            // this behaviour manually or use `signature_hash()`.
            return EncodeSigningDataResult::SighashSingleBug;
        }

        fn encode_signing_data_to_inner<Write: io::Write>(
            self_: &Transaction,
            mut writer: Write,
            input_index: usize,
            script_pubkey: &Script,
            sighash_type: u32,
        ) -> Result<(), io::Error> {
            let (sighash, anyone_can_pay) =
                EcdsaSighashType::from_consensus(sighash_type).split_anyonecanpay_flag();

            // Serialize like Dash Core's `CTransactionSignatureSerializer`
            // (src/script/interpreter.cpp).
            let single_or_none =
                sighash == EcdsaSighashType::Single || sighash == EcdsaSighashType::None;
            self_.consensus_encode_version_and_type(&mut writer)?;
            // Only the input being signed with ANYONECANPAY, else all of them; the signed one
            // carries the script code and the others an empty script.
            let inputs = if anyone_can_pay {
                input_index..input_index + 1
            } else {
                0..self_.input.len()
            };
            VarInt(inputs.len() as u64).consensus_encode(&mut writer)?;
            for n in inputs {
                let input = &self_.input[n];
                input.previous_output.consensus_encode(&mut writer)?;
                if n == input_index {
                    encode_script_code(&mut writer, script_pubkey.as_bytes())?;
                } else {
                    ScriptBuf::new().consensus_encode(&mut writer)?;
                }
                let sequence = if n != input_index && single_or_none {
                    0
                } else {
                    input.sequence
                };
                sequence.consensus_encode(&mut writer)?;
            }
            // SINGLE signs the outputs up to and including this one, with the others blanked
            match sighash {
                EcdsaSighashType::All => self_.output.consensus_encode(&mut writer)?,
                EcdsaSighashType::Single => {
                    VarInt((input_index + 1) as u64).consensus_encode(&mut writer)?;
                    // `input_index < output.len()` here: the SIGHASH_SINGLE bug case returned above
                    for (n, out) in self_.output[..=input_index].iter().enumerate() {
                        if n == input_index {
                            out.consensus_encode(&mut writer)?;
                        } else {
                            TxOut::default().consensus_encode(&mut writer)?;
                        }
                    }
                    0
                }
                EcdsaSighashType::None => VarInt(0).consensus_encode(&mut writer)?,
                _ => unreachable!(),
            };
            self_.lock_time.consensus_encode(&mut writer)?;
            self_.encode_special_payload(&mut writer)?;
            sighash_type.to_le_bytes().consensus_encode(&mut writer)?;
            Ok(())
        }

        EncodeSigningDataResult::WriteResult(
            encode_signing_data_to_inner(
                self.tx.borrow(),
                writer,
                input_index,
                script_pubkey,
                sighash_type,
            )
            .map_err(|e| Error::Io(e.kind())),
        )
    }

    /// Computes a legacy signature hash for a given input index with a given sighash flag.
    ///
    /// To actually produce a scriptSig, this hash needs to be run through an ECDSA signer, the
    /// [`EcdsaSighashType`] appended to the resulting sig, and a script written around this, but
    /// this is the general (and hard) part.
    ///
    /// The `sighash_type` supports an arbitrary `u32` value, instead of just [`EcdsaSighashType`],
    /// because internally 4 bytes are being hashed, even though only the lowest byte is appended to
    /// signature in a transaction.
    ///
    /// This function correctly handles the sighash single bug by returning the 'one array'. The
    /// sighash single bug becomes exploitable when one tries to sign a transaction with
    /// `SIGHASH_SINGLE` and there is not a corresponding output with the same index as the input.
    ///
    /// # Warning
    ///
    /// `script_pubkey` is the script code. As in Dash Core, every OP_CODESEPARATOR opcode in it is
    /// left out of the signing data. Passing only the part of the script after the last executed
    /// OP_CODESEPARATOR is up to the caller, since choosing it needs script evaluation.
    pub fn legacy_signature_hash(
        &self,
        input_index: usize,
        script_pubkey: &Script,
        sighash_type: u32,
    ) -> Result<LegacySighash, Error> {
        let mut enc = LegacySighash::engine();
        if self
            .legacy_encode_signing_data_to(&mut enc, input_index, script_pubkey, sighash_type)
            .is_sighash_single_bug()?
        {
            Ok(LegacySighash::from_byte_array(UINT256_ONE))
        } else {
            Ok(LegacySighash::from_engine(enc))
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e.kind())
    }
}

/// Writes `script_code` the way Dash Core's `CTransactionSignatureSerializer::SerializeScriptCode`
/// (src/script/interpreter.cpp) does: every `OP_CODESEPARATOR` opcode is left out, and the length
/// prefix is the script's length minus those opcodes. Like Core, the opcodes are read with
/// `GetScriptOp` (src/script/script.cpp), so a `0xab` byte inside push data is kept. When a push
/// runs past the end of the script, its opcode is written, and so is its length field when that
/// field is complete; everything after that is dropped. This matches `GetScriptOp` advancing past
/// them before it fails, and `SerializeScriptCode` writing up to that point. The length prefix still
/// counts the whole script minus the separators.
fn encode_script_code<W: io::Write + ?Sized>(writer: &mut W, script_code: &[u8]) -> io::Result<()> {
    let mut separators = Vec::new();
    let mut pc = 0;
    let parsed_end = loop {
        let Some(&opcode) = script_code.get(pc) else {
            break pc;
        };
        pc += 1;
        // Push opcodes are 0x00..=0x4b (push that many bytes) and OP_PUSHDATA1/2/4 (0x4c..=0x4e,
        // followed by a 1, 2 or 4 byte little-endian length)
        let push_len = match opcode {
            0x00..=0x4b => usize::from(opcode),
            0x4c..=0x4e => {
                let width = match opcode {
                    0x4c => 1,
                    0x4d => 2,
                    _ => 4,
                };
                let Some(bytes) = script_code.get(pc..pc + width) else {
                    break pc;
                };
                pc += width;
                bytes.iter().rev().fold(0usize, |len, &b| len << 8 | usize::from(b))
            }
            _ => {
                if opcode == OP_CODESEPARATOR.to_u8() {
                    separators.push(pc - 1);
                }
                0
            }
        };
        if script_code.len() - pc < push_len {
            break pc;
        }
        pc += push_len;
    };
    VarInt((script_code.len() - separators.len()) as u64).consensus_encode(writer)?;
    let mut start = 0;
    for separator in separators {
        writer.write_all(&script_code[start..separator])?;
        start = separator + 1;
    }
    writer.write_all(&script_code[start..parsed_end])
}

fn is_invalid_use_of_sighash_single(sighash: u32, input_index: usize, output_len: usize) -> bool {
    // Core checks `(nHashType & 0x1f) == SIGHASH_SINGLE`, so ANYONECANPAY
    // counts as well.
    EcdsaSighashType::from_consensus(sighash).is_single() && input_index >= output_len
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use test_case::test_case;

    use super::*;
    use crate::blockdata::script::Instruction;
    use crate::blockdata::transaction::txin::TxIn;
    use crate::consensus::deserialize;
    use crate::crypto::ecdsa::{EcdsaPublicKey, EcdsaSignature};
    use crate::internal_macros::hex;

    #[test]
    fn sighash_single_bug() {
        // We need a tx with more inputs than outputs.
        let tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![TxIn::default(), TxIn::default()],
            output: vec![TxOut::default()],
            special_transaction_payload: None,
        };
        let script = ScriptBuf::new();
        let cache = SighashCache::new(&tx);

        let one = LegacySighash::from_slice(&UINT256_ONE).unwrap();

        // Low five bits say SINGLE, with or without ANYONECANPAY.
        for flag in [0x03, 0x23, 0x83, 0xa3] {
            let got = cache.legacy_signature_hash(1, &script, flag).expect("sighash");
            assert_eq!(got, one, "{flag:#x}");
        }
        let got = cache.legacy_signature_hash(1, &script, 0x01).expect("sighash");
        assert_ne!(got, one);
    }

    // Dash Core signed both spends with `signrawtransactionwithkey`. Core returns the negative
    // version one with `0080ffff` in place of the wire bytes `00803412` restored here.
    #[test_case("00803412011111111111111111111111111111111111111111111111111111111111111111000000006a47304402203000e9aee375bc3acc126f0619679f822e46ad6c22f86b08ea56a4d05049f30102206931600834541a32024eab87425f66fea7acb042ad93505c4fc735378275a541012103badbb484572c23cc321f6346b3e455d7fcf3052b27003e579be971e2fc1ef609ffffffff01e8030000000000001976a914d6f4120a643b5acea9e8cf6dae4ef1341f66552b88ac00000000"; "version 0x8000 with type bytes")]
    #[test_case("01002a00011111111111111111111111111111111111111111111111111111111111111111000000006a473044022058115bbc7dc1ec8a2ab489234ace74bd9f7e1f97bd64730a6bfc9fa995debcc40220646a89d37ba477a3346ab2ff0d5a5175d660bf1be3b76e7714c44d2796e3425f012103badbb484572c23cc321f6346b3e455d7fcf3052b27003e579be971e2fc1ef609ffffffff01e8030000000000001976a914d6f4120a643b5acea9e8cf6dae4ef1341f66552b88ac00000000"; "version 1 with type bytes")]
    fn legacy_sighash_matches_core_signature(tx_hex: &str) {
        let tx: Transaction = deserialize(&hex!(tx_hex)).unwrap();
        let script_pubkey =
            ScriptBuf::from(hex!("76a914d6f4120a643b5acea9e8cf6dae4ef1341f66552b88ac"));
        let pushes: Vec<&[u8]> = tx.input[0]
            .script_sig
            .instructions()
            .map(|ins| match ins.unwrap() {
                Instruction::PushBytes(bytes) => bytes.as_bytes(),
                Instruction::Op(op) => panic!("unexpected {op} in the scriptSig"),
            })
            .collect();
        let (der, sighash_type) = pushes[0].split_at(pushes[0].len() - 1);

        let sighash = SighashCache::new(&tx)
            .legacy_signature_hash(0, &script_pubkey, u32::from(sighash_type[0]))
            .unwrap();
        let signature = EcdsaSignature::from_der(der).unwrap();
        EcdsaPublicKey::from_bytes(pushes[1])
            .unwrap()
            .verify(&sighash.to_byte_array(), signature)
            .expect("Core's signature must verify against our legacy sighash");
    }

    #[test]
    fn script_code_leaves_out_code_separators() {
        fn encoded(script_code: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            encode_script_code(&mut out, script_code).unwrap();
            out
        }
        // OP_1 OP_CODESEPARATOR OP_2 OP_CODESEPARATOR
        assert_eq!(encoded(&[0x51, 0xab, 0x52, 0xab]), [0x02, 0x51, 0x52]);
        // A pushed 0xab byte is data, not an opcode
        assert_eq!(encoded(&[0x01, 0xab, 0xab]), [0x02, 0x01, 0xab]);
        // A push that runs past the end: its opcode and its complete length field are written,
        // the data after them is dropped, and the length prefix still counts the whole script
        // minus the separator before it
        assert_eq!(encoded(&[0xab, 0x51, 0x4c, 0x05, 0x00]), [0x04, 0x51, 0x4c, 0x05]);
        // A direct push that runs past the end: only its opcode is written
        assert_eq!(encoded(&[0x51, 0x05, 0x00]), [0x03, 0x51, 0x05]);
        // OP_PUSHDATA2 with an incomplete length field: only the opcode is written
        assert_eq!(encoded(&[0x51, 0x4d, 0x01]), [0x03, 0x51, 0x4d]);
        // No separators: written as is
        assert_eq!(encoded(&[0x76, 0xa9]), [0x02, 0x76, 0xa9]);
    }

    /// Dash Core's `src/test/data/sighash.json` (MIT), all 500 vectors; 169 of them have
    /// OP_CODESEPARATOR in the script code.
    #[test]
    fn legacy_sighash_dash_core_vectors() {
        let data = include_str!("../../tests/data/legacy_sighash_dash_core.json");
        let vectors = serde_json::from_str::<Value>(data).unwrap();
        let vectors = vectors.as_array().unwrap();
        assert_eq!(vectors.len(), 501);
        for (i, t) in vectors.iter().skip(1).enumerate() {
            let tx: Transaction =
                deserialize(&hex!(t[0].as_str().unwrap())).expect("Dash Core vector tx");
            let script = ScriptBuf::from(hex!(t[1].as_str().unwrap()));
            let input_index = t[2].as_u64().unwrap() as usize;
            let hash_type = t[3].as_i64().unwrap() as u32;
            let mut expected = hex!(t[4].as_str().unwrap());
            expected.reverse();
            let got = SighashCache::new(&tx)
                .legacy_signature_hash(input_index, &script, hash_type)
                .unwrap();
            assert_eq!(got, LegacySighash::from_slice(&expected).unwrap(), "vector {i}");
        }
    }

    #[test]
    fn test_sighash_errors() {
        let dumb_tx = Transaction {
            version: 0,
            lock_time: 0,
            input: vec![TxIn::default()],
            output: vec![],
            special_transaction_payload: None,
        };
        let c = SighashCache::new(&dumb_tx);

        assert_eq!(
            c.legacy_signature_hash(10, Script::empty(), 0u32),
            Err(Error::IndexOutOfInputsBounds {
                index: 10,
                inputs_size: 1,
            })
        );
    }
}
