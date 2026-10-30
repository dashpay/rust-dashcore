// SPDX-License-Identifier: CC0-1.0

//! Signature hash implementation (used in transaction signing).
//!
//! Efficient implementation of the algorithm to compute the message to be signed according to
//! [Bip143](https://github.com/bitcoin/bips/blob/99701f68a88ce33b2d0838eb84e115cef505b4c2/bip-0143.mediawiki)
//! and legacy (before Bip143).
//!
//! Computing signature hashes is required to sign a transaction and this module is designed to
//! handle its complexity efficiently. Computing these hashes is as simple as creating
//! [`SighashCache`] and calling its methods.

use core::borrow::{Borrow, BorrowMut};
use core::fmt;

use hashes::{Hash, sha256, sha256d};

pub use dashcore_crypto::sighash::SplitAnyoneCanPay;
pub use dashcore_crypto::sighash::{
    EcdsaSighashType, InvalidSighashTypeError, LegacySighash, NonStandardSighashType,
    NonStandardSighashTypeError, SegwitV0Sighash, SighashTypeParseError,
};

use crate::blockdata::transaction::txin::TxIn;
use crate::blockdata::transaction::txout::TxOut;
use crate::blockdata::transaction::{EncodeSigningDataResult, Transaction};
use crate::blockdata::witness::Witness;
use crate::consensus::Encodable;
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

/// Efficiently calculates signature hash message for legacy and segwit inputs.
#[derive(Debug)]
pub struct SighashCache<T: Borrow<Transaction>> {
    /// Access to transaction required for transaction introspection. Moreover, type
    /// `T: Borrow<Transaction>` allows us to use borrowed and mutable borrowed types,
    /// the latter in particular is necessary for [`SighashCache::witness_mut`].
    tx: T,

    /// Common cache for segwit inputs, `None` for legacy inputs.
    common_cache: Option<CommonCache>,

    /// Cache for segwit v0 inputs (the result of another round of sha256 on `common_cache`).
    segwit_cache: Option<SegwitCache>,
}

/// Common values cached for segwit inputs.
#[derive(Debug)]
struct CommonCache {
    prevouts: sha256::Hash,
    sequences: sha256::Hash,

    /// In theory `outputs` could be an `Option` since `SIGHASH_NONE` and `SIGHASH_SINGLE` do not
    /// need it, but since `SIGHASH_ALL` is by far the most used variant we don't bother.
    outputs: sha256::Hash,
}

/// Values cached for segwit inputs, equivalent to [`CommonCache`] plus another round of `sha256`.
#[derive(Debug)]
struct SegwitCache {
    prevouts: sha256d::Hash,
    sequences: sha256d::Hash,
    outputs: sha256d::Hash,
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
    /// The sighash components are computed in a lazy manner when required. For the generated
    /// sighashes to be valid, no fields in the transaction may change except for script_sig and
    /// witness.
    pub fn new(tx: R) -> Self {
        SighashCache {
            tx,
            common_cache: None,
            segwit_cache: None,
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

    /// Encodes the BIP143 signing data for any flag type into a given object implementing a
    /// [`std::io::Write`] trait.
    pub fn segwit_encode_signing_data_to<Write: io::Write>(
        &mut self,
        mut writer: Write,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: EcdsaSighashType,
    ) -> Result<(), Error> {
        let zero_hash = sha256d::Hash::all_zeros();

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        self.tx.borrow().version.consensus_encode(&mut writer)?;

        if !anyone_can_pay {
            self.segwit_cache().prevouts.consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        if !anyone_can_pay
            && sighash != EcdsaSighashType::Single
            && sighash != EcdsaSighashType::None
        {
            self.segwit_cache().sequences.consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        {
            let txin =
                &self.tx.borrow().input.get(input_index).ok_or(Error::IndexOutOfInputsBounds {
                    index: input_index,
                    inputs_size: self.tx.borrow().input.len(),
                })?;

            txin.previous_output.consensus_encode(&mut writer)?;
            script_code.consensus_encode(&mut writer)?;
            value.consensus_encode(&mut writer)?;
            txin.sequence.consensus_encode(&mut writer)?;
        }

        if sighash != EcdsaSighashType::Single && sighash != EcdsaSighashType::None {
            self.segwit_cache().outputs.consensus_encode(&mut writer)?;
        } else if sighash == EcdsaSighashType::Single && input_index < self.tx.borrow().output.len()
        {
            let mut single_enc = LegacySighash::engine();
            self.tx.borrow().output[input_index].consensus_encode(&mut single_enc)?;
            let hash = LegacySighash::from_engine(single_enc);
            writer.write_all(&hash[..])?;
        } else {
            writer.write_all(&zero_hash[..])?;
        }

        self.tx.borrow().lock_time.consensus_encode(&mut writer)?;
        sighash_type.to_u32().consensus_encode(&mut writer)?;
        Ok(())
    }

    /// Computes the BIP143 sighash for any flag type.
    pub fn segwit_signature_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: EcdsaSighashType,
    ) -> Result<SegwitV0Sighash, Error> {
        let mut enc = SegwitV0Sighash::engine();
        self.segwit_encode_signing_data_to(
            &mut enc,
            input_index,
            script_code,
            value,
            sighash_type,
        )?;
        Ok(SegwitV0Sighash::from_engine(enc))
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
    /// - Does NOT attempt to support OP_CODESEPARATOR. In general this would require evaluating
    ///   `script_pubkey` to determine which separators get evaluated and which don't, which we don't
    ///   have the information to determine.
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

            // Build tx to sign
            let mut tx = Transaction {
                version: self_.version,
                lock_time: self_.lock_time,
                input: vec![],
                output: vec![],
                special_transaction_payload: self_.special_transaction_payload.clone(),
            };
            // Add all inputs necessary..
            if anyone_can_pay {
                tx.input = vec![TxIn {
                    previous_output: self_.input[input_index].previous_output,
                    script_sig: script_pubkey.to_owned(),
                    sequence: self_.input[input_index].sequence,
                    witness: Witness::default(),
                }];
            } else {
                tx.input = Vec::with_capacity(self_.input.len());
                for (n, input) in self_.input.iter().enumerate() {
                    tx.input.push(TxIn {
                        previous_output: input.previous_output,
                        script_sig: if n == input_index {
                            script_pubkey.to_owned()
                        } else {
                            ScriptBuf::new()
                        },
                        sequence: if n != input_index
                            && (sighash == EcdsaSighashType::Single
                                || sighash == EcdsaSighashType::None)
                        {
                            0
                        } else {
                            input.sequence
                        },
                        witness: Witness::default(),
                    });
                }
            }
            // ..then all outputs
            tx.output = match sighash {
                EcdsaSighashType::All => self_.output.clone(),
                EcdsaSighashType::Single => {
                    let output_iter = self_
                        .output
                        .iter()
                        .take(input_index + 1) // sign all outputs up to and including this one, but erase
                        .enumerate() // all of them except for this one
                        .map(|(n, out)| {
                            if n == input_index {
                                out.clone()
                            } else {
                                TxOut::default()
                            }
                        });
                    output_iter.collect()
                }
                EcdsaSighashType::None => vec![],
                _ => unreachable!(),
            };
            // hash the result
            tx.consensus_encode(&mut writer)?;
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
    /// Does NOT attempt to support OP_CODESEPARATOR. In general this would require evaluating
    /// `script_pubkey` to determine which separators get evaluated and which don't, which we don't
    /// have the information to determine.
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

    fn common_cache_minimal_borrow<'a>(
        common_cache: &'a mut Option<CommonCache>,
        tx: &Transaction,
    ) -> &'a CommonCache {
        common_cache.get_or_insert_with(|| {
            let mut enc_prevouts = sha256::Hash::engine();
            let mut enc_sequences = sha256::Hash::engine();
            for txin in tx.input.iter() {
                txin.previous_output.consensus_encode(&mut enc_prevouts).unwrap();
                txin.sequence.consensus_encode(&mut enc_sequences).unwrap();
            }
            CommonCache {
                prevouts: sha256::Hash::from_engine(enc_prevouts),
                sequences: sha256::Hash::from_engine(enc_sequences),
                outputs: {
                    let mut enc = sha256::Hash::engine();
                    for txout in tx.output.iter() {
                        txout.consensus_encode(&mut enc).unwrap();
                    }
                    sha256::Hash::from_engine(enc)
                },
            }
        })
    }

    fn segwit_cache(&mut self) -> &SegwitCache {
        let common_cache = &mut self.common_cache;
        let tx = self.tx.borrow();
        self.segwit_cache.get_or_insert_with(|| {
            let common_cache = Self::common_cache_minimal_borrow(common_cache, tx);
            SegwitCache {
                prevouts: common_cache.prevouts.hash_again(),
                sequences: common_cache.sequences.hash_again(),
                outputs: common_cache.outputs.hash_again(),
            }
        })
    }
}

impl<R: BorrowMut<Transaction>> SighashCache<R> {
    /// When the `SighashCache` is initialized with a mutable reference to a transaction instead of
    /// a regular reference, this method is available to allow modification to the witnesses.
    ///
    /// This allows in-line signing such as
    /// ```
    /// use dashcore::{absolute, Transaction, Script};
    /// use dashcore::sighash::{EcdsaSighashType, SighashCache};
    ///
    /// let mut tx_to_sign = Transaction { version: 2, lock_time: 0, input: Vec::new(), output: Vec::new(), special_transaction_payload: None};
    /// let input_count = tx_to_sign.input.len();
    ///
    /// let mut sig_hasher = SighashCache::new(&mut tx_to_sign);
    /// for inp in 0..input_count {
    ///     let prevout_script = Script::empty();
    ///     let _sighash = sig_hasher.segwit_signature_hash(inp, prevout_script, 42, EcdsaSighashType::All);
    ///     // ... sign the sighash
    ///     sig_hasher.witness_mut(inp).unwrap().push(&Vec::new());
    /// }
    /// ```
    pub fn witness_mut(&mut self, input_index: usize) -> Option<&mut Witness> {
        self.tx.borrow_mut().input.get_mut(input_index).map(|i| &mut i.witness)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e.kind())
    }
}

fn is_invalid_use_of_sighash_single(sighash: u32, input_index: usize, output_len: usize) -> bool {
    // Core checks `(nHashType & 0x1f) == SIGHASH_SINGLE`, so ANYONECANPAY
    // counts as well.
    EcdsaSighashType::from_consensus(sighash).is_single() && input_index >= output_len
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::Network;
    use crate::address::Address;
    use crate::consensus::deserialize;
    use crate::crypto::key::PublicKey;
    use crate::crypto::sighash::LegacySighash;
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

    #[ignore]
    #[test]
    #[cfg(feature = "serde")]
    fn legacy_sighash() {
        use serde_json::Value;

        use crate::sighash::SighashCache;

        fn run_test_sighash(
            tx: &str,
            script: &str,
            input_index: usize,
            hash_type: i64,
            expected_result: &str,
        ) {
            let tx_bytes = hex!(tx);
            let tx: Transaction = deserialize(tx_bytes.as_slice()).unwrap();
            let script = ScriptBuf::from(hex!(script));
            let mut raw_expected = hex!(expected_result);
            raw_expected.reverse();
            let want = LegacySighash::from_slice(&raw_expected[..]).unwrap();

            let cache = SighashCache::new(&tx);
            let got = cache.legacy_signature_hash(input_index, &script, hash_type as u32).unwrap();

            assert_eq!(got, want);
        }

        // These test vectors were stolen from libbtc, which is Copyright 2014 Jonas Schnelli MIT
        // They were transformed by replacing {...} with run_test_sighash(...), then the ones containing
        // OP_CODESEPARATOR in their pubkeys were removed
        let data = include_str!("../../tests/data/legacy_sighash.json");

        let testdata = serde_json::from_str::<Value>(data).unwrap().as_array().unwrap().clone();
        for t in testdata.iter().skip(1) {
            let tx = t.get(0).unwrap().as_str().unwrap();
            let script = t.get(1).unwrap().as_str().unwrap_or("");
            let input_index = t.get(2).unwrap().as_u64().unwrap();
            let hash_type = t.get(3).unwrap().as_i64().unwrap();
            let expected_sighash = t.get(4).unwrap().as_str().unwrap();
            run_test_sighash(tx, script, input_index as usize, hash_type, expected_sighash);
        }
    }

    fn p2pkh_hex(pk: &str) -> ScriptBuf {
        let pk: PublicKey = PublicKey::from_str(pk).unwrap();
        Address::p2pkh(&pk, Network::Mainnet).script_pubkey()
    }

    #[test]
    fn bip143_p2wpkh() {
        let tx = deserialize::<Transaction>(
            &hex!(
                "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f000000\
                0000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000\
                00ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093\
                510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
            ),
        ).unwrap();

        let witness_script =
            p2pkh_hex("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357");
        let value = 600_000_000;

        let mut cache = SighashCache::new(&tx);
        assert_eq!(
            cache.segwit_signature_hash(1, &witness_script, value, EcdsaSighashType::All).unwrap(),
            "313ca7f8ba3ad9da3eb040a61e2768eceb7126d610c13dbd440fdc3e1f1d07e0"
                .parse::<SegwitV0Sighash>()
                .unwrap(),
        );

        let cache = cache.segwit_cache();
        // Parse hex into Vec because BIP143 test vector displays forwards but our sha256d::Hash displays backwards.
        assert_eq!(
            cache.prevouts.as_byte_array(),
            hex!("96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37").as_slice(),
        );
        assert_eq!(
            cache.sequences.as_byte_array(),
            hex!("52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b").as_slice(),
        );
        assert_eq!(
            cache.outputs.as_byte_array(),
            hex!("863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5").as_slice(),
        );
    }

    #[test]
    fn bip143_p2wpkh_nested_in_p2sh() {
        let tx = deserialize::<Transaction>(
            &hex!(
                "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000\
                0000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac00\
                08af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"
            ),
        ).unwrap();

        let witness_script =
            p2pkh_hex("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873");
        let value = 1_000_000_000;

        let mut cache = SighashCache::new(&tx);
        assert_eq!(
            cache.segwit_signature_hash(0, &witness_script, value, EcdsaSighashType::All).unwrap(),
            "1c9c7380e80e8b12f62b896cb2a2f994c5f5d86ebb8b803bfdeab385ffd3a7a9"
                .parse::<SegwitV0Sighash>()
                .unwrap(),
        );

        let cache = cache.segwit_cache();
        // Parse hex into Vec because BIP143 test vector displays forwards but our sha256d::Hash displays backwards.
        assert_eq!(
            cache.prevouts.as_byte_array(),
            hex!("b0287b4a252ac05af83d2dcef00ba313af78a3e9c329afa216eb3aa2a7b4613a").as_slice(),
        );
        assert_eq!(
            cache.sequences.as_byte_array(),
            hex!("18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198").as_slice(),
        );
        assert_eq!(
            cache.outputs.as_byte_array(),
            hex!("de984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c83").as_slice(),
        );
    }

    #[test]
    fn bip143_p2wsh_nested_in_p2sh() {
        let tx = deserialize::<Transaction>(&hex!(
            "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000\
             ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f\
             05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000"
        ))
        .unwrap();

        let witness_script = ScriptBuf::from_hex(
            "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28\
             bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b\
             9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58\
             c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b1486\
             2c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b\
             56ae",
        )
        .unwrap();
        let value = 987654321;

        let mut cache = SighashCache::new(&tx);
        assert_eq!(
            cache.segwit_signature_hash(0, &witness_script, value, EcdsaSighashType::All).unwrap(),
            "3a892568a19aee7bb185d5b4f7359e3e20d09db39ea38fdaf73eb719394fde69"
                .parse::<SegwitV0Sighash>()
                .unwrap(),
        );

        let cache = cache.segwit_cache();
        // Parse hex into Vec because BIP143 test vector displays forwards but our sha256d::Hash displays backwards.
        assert_eq!(
            cache.prevouts.as_byte_array(),
            hex!("74afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0").as_slice(),
        );
        assert_eq!(
            cache.sequences.as_byte_array(),
            hex!("3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044").as_slice(),
        );
        assert_eq!(
            cache.outputs.as_byte_array(),
            hex!("bc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc").as_slice(),
        );
    }
}
