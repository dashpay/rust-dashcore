// Rust Dash Library
// Originally written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//     For Bitcoin
// Updated for Dash in 2022 by
//     The Dash Core Developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Dash transactions.
//!
//! A transaction describes a transfer of money. It consumes previously-unspent
//! transaction outputs and produces new ones, satisfying the condition to spend
//! the old outputs (typically a digital signature with a specific key must be
//! provided) and defining the condition to spend the new ones. The use of digital
//! signatures ensures that coins cannot be spent by unauthorized parties.
//!
//! This module provides the structures and functions needed to support transactions.
//!

pub mod hash_type;
pub mod outpoint;
pub mod special_transaction;
pub mod txin;
pub mod txout;

use core::default::Default;

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use hashes::{Hash, sha256d};

use crate::blockdata::constants::WITNESS_SCALE_FACTOR;
#[cfg(feature = "bitcoinconsensus")]
use crate::blockdata::script;
use crate::blockdata::script::Script;
use crate::blockdata::transaction::hash_type::EcdsaSighashType;
use crate::blockdata::transaction::special_transaction::{TransactionPayload, TransactionType};
use crate::blockdata::transaction::txin::TxIn;
use crate::blockdata::transaction::txout::TxOut;
use crate::blockdata::witness::Witness;
use crate::consensus::encode::VarInt;
use crate::consensus::{Decodable, Encodable, encode};
use crate::hash_types::{InputsHash, Txid, Wtxid};
use crate::prelude::*;
use crate::sighash::LegacySighash;
pub use crate::transaction::outpoint::*;
use crate::{ScriptBuf, Weight, io};

/// Used for signature hash for invalid use of SIGHASH_SINGLE.
const UINT256_ONE: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Result of [`Transaction::encode_signing_data_to`].
///
/// This type forces the caller to handle SIGHASH_SINGLE bug case.
///
/// This corner case can't be expressed using standard `Result`,
/// in a way that is both convenient and not-prone to accidental
/// mistakes (like calling `.expect("writer never fails")`).
#[must_use]
pub enum EncodeSigningDataResult<E> {
    /// Input data is an instance of `SIGHASH_SINGLE` bug
    SighashSingleBug,
    /// Operation performed normally.
    WriteResult(Result<(), E>),
}

impl<E> EncodeSigningDataResult<E> {
    /// Checks for SIGHASH_SINGLE bug returning error if the writer failed.
    ///
    /// This method is provided for easy and correct handling of the result because
    /// SIGHASH_SINGLE bug is a special case that must not be ignored nor cause panicking.
    /// Since the data is usually written directly into a hasher which never fails,
    /// the recommended pattern to handle this is:
    ///
    /// ```rust
    /// # use dashcore::consensus::deserialize;
    /// # use dashcore::hashes::{Hash, hex::FromHex};
    /// # use dashcore::sighash::{LegacySighash, SighashCache};
    /// # use dashcore::Transaction;
    /// # let mut writer = LegacySighash::engine();
    /// # let input_index = 0;
    /// # let script_pubkey = dashcore::ScriptBuf::new();
    /// # let sighash_u32 = 0u32;
    /// # const SOME_TX: &'static str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";
    /// # let raw_tx = Vec::from_hex(SOME_TX).unwrap();
    /// # let tx: Transaction = deserialize(&raw_tx).unwrap();
    /// let cache = SighashCache::new(&tx);
    /// if cache.legacy_encode_signing_data_to(&mut writer, input_index, &script_pubkey, sighash_u32)
    ///         .is_sighash_single_bug()
    ///         .expect("writer can't fail") {
    ///     // use a hash value of "1", instead of computing the actual hash due to SIGHASH_SINGLE bug
    /// }
    /// ```
    #[allow(clippy::wrong_self_convention)] // E is not Copy so we consume self.
    pub fn is_sighash_single_bug(self) -> Result<bool, E> {
        match self {
            EncodeSigningDataResult::SighashSingleBug => Ok(true),
            EncodeSigningDataResult::WriteResult(Ok(())) => Ok(false),
            EncodeSigningDataResult::WriteResult(Err(e)) => Err(e),
        }
    }

    /// Maps a `Result<T, E>` to `Result<T, F>` by applying a function to a
    /// contained [`Err`] value, leaving an [`Ok`] value untouched.
    ///
    /// Like [`Result::map_err`].
    pub fn map_err<E2, F>(self, f: F) -> EncodeSigningDataResult<E2>
    where
        F: FnOnce(E) -> E2,
    {
        match self {
            EncodeSigningDataResult::SighashSingleBug => EncodeSigningDataResult::SighashSingleBug,
            EncodeSigningDataResult::WriteResult(Err(e)) => {
                EncodeSigningDataResult::WriteResult(Err(f(e)))
            }
            EncodeSigningDataResult::WriteResult(Ok(o)) => {
                EncodeSigningDataResult::WriteResult(Ok(o))
            }
        }
    }
}

/// A Dash transaction, which describes an authenticated movement of coins.
///
/// If any inputs have nonempty witnesses, the entire transaction is serialized
/// in the post-BIP141 Segwit format which includes a list of witnesses. If all
/// inputs have empty witnesses, the transaction is serialized in the pre-BIP141
/// format.
///
/// There is one major exception to this: to avoid deserialization ambiguity,
/// if the transaction has no inputs, it is serialized in the BIP141 style. Be
/// aware that this differs from the transaction format in PSBT, which _never_
/// uses BIP141. (Ordinarily there is no conflict, since in PSBT transactions
/// are always unsigned and therefore their inputs have empty witnesses.)
///
/// The specific ambiguity is that Segwit uses the flag bytes `0001` where an old
/// serializer would read the number of transaction inputs. The old serializer
/// would interpret this as "no inputs, one output", which means the transaction
/// is invalid, and simply reject it. Segwit further specifies that this encoding
/// should *only* be used when some input has a nonempty witness; that is,
/// witness-less transactions should be encoded in the traditional format.
///
/// However, in protocols where transactions may legitimately have 0 inputs, e.g.
/// when parties are cooperatively funding a transaction, the "00 means Segwit"
/// heuristic does not work. Since Segwit requires such a transaction be encoded
/// in the original transaction format (since it has no inputs and therefore
/// no input witnesses), a traditionally encoded transaction may have the `0001`
/// Segwit flag in it, which confuses most Segwit parsers including the one in
/// Bitcoin Core.
///
/// We therefore deviate from the spec by always using the Segwit witness encoding
/// for 0-input transactions, which results in unambiguously parseable transactions.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Transaction {
    /// The protocol version, is currently expected to be 1 or 2 (BIP 68).
    pub version: u16,
    /// Block number before which this transaction is valid, or 0 for valid immediately.
    pub lock_time: u32,
    /// List of transaction inputs.
    pub input: Vec<TxIn>,
    /// List of transaction outputs.
    pub output: Vec<TxOut>,
    /// Special Transaction Payload
    pub special_transaction_payload: Option<TransactionPayload>,
}

impl Transaction {
    /// Computes a "normalized TXID" which does not include any signatures.
    /// This gives a way to identify a transaction that is "the same" as
    /// another in the sense of having same inputs and outputs.
    pub fn ntxid(&self) -> sha256d::Hash {
        let cloned_tx = Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: self
                .input
                .iter()
                .map(|txin| TxIn {
                    script_sig: ScriptBuf::new(),
                    witness: Witness::default(),
                    ..*txin
                })
                .collect(),
            output: self.output.clone(),
            special_transaction_payload: self.special_transaction_payload.clone(),
        };
        cloned_tx.txid().into()
    }

    /// Computes the txid. For non-segwit transactions this will be identical
    /// to the output of `wtxid()`, but for segwit transactions,
    /// this will give the correct txid (not including witnesses) while `wtxid`
    /// will also hash witnesses.
    pub fn txid(&self) -> Txid {
        let mut enc = Txid::engine();
        self.version.consensus_encode(&mut enc).expect("engines don't error");
        (self.tx_type() as u16).consensus_encode(&mut enc).expect("engines don't error");
        self.input.consensus_encode(&mut enc).expect("engines don't error");
        self.output.consensus_encode(&mut enc).expect("engines don't error");
        self.lock_time.consensus_encode(&mut enc).expect("engines don't error");
        if let Some(payload) = &self.special_transaction_payload {
            let mut buf = Vec::new();
            payload.consensus_encode(&mut buf).expect("engines don't error");
            // this is so we get the size of the payload
            buf.consensus_encode(&mut enc).expect("engines don't error");
        }

        Txid::from_engine(enc)
    }

    /// Get the transaction type. If a classical transaction this would be 0.
    /// Otherwise it is gotten by association from the payload type.
    pub fn tx_type(&self) -> TransactionType {
        TransactionType::from_optional_payload(&self.special_transaction_payload)
    }

    /// Computes SegWit-version of the transaction id (wtxid). For transaction with the witness
    /// data this hash includes witness, for pre-witness transaction it is equal to the normal
    /// value returned by txid() function.
    pub fn wtxid(&self) -> Wtxid {
        let mut enc = Wtxid::engine();
        self.consensus_encode(&mut enc).expect("engines don't error");
        Wtxid::from_engine(enc)
    }

    /// Encodes the signing data from which a signature hash for a given input index with a given
    /// sighash flag can be computed.
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
    /// `script_pubkey` to determine which separators get evaluated and which don't, which we don't
    /// have the information to determine.
    /// - Does NOT handle the sighash single bug, you should either handle that manually or use
    /// [`Self::signature_hash()`] instead.
    ///
    /// # Panics
    ///
    /// If `input_index` is out of bounds (greater than or equal to `self.input.len()`).
    /// Encodes the signing data from which a signature hash for a given input index with a given
    /// sighash flag can be computed.
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
    /// `script_pubkey` to determine which separators get evaluated and which don't, which we don't
    /// have the information to determine.
    /// - Does NOT handle the sighash single bug (see "Returns" section)
    ///
    /// # Returns
    ///
    /// This function can't handle the SIGHASH_SINGLE bug internally, so it returns [`EncodeSigningDataResult`]
    /// that must be handled by the caller (see [`EncodeSigningDataResult::is_sighash_single_bug`]).
    ///
    /// # Panics
    ///
    /// If `input_index` is out of bounds (greater than or equal to `self.input.len()`).
    #[deprecated(
        since = "0.30.0",
        note = "Use SighashCache::legacy_encode_signing_data_to instead"
    )]
    pub fn encode_signing_data_to<Write: io::Write, U: Into<u32>>(
        &self,
        writer: Write,
        input_index: usize,
        script_pubkey: &Script,
        sighash_type: U,
    ) -> EncodeSigningDataResult<io::Error> {
        use EncodeSigningDataResult::*;

        use crate::sighash::{self, SighashCache};

        assert!(input_index < self.input.len()); // Panic on OOB

        let cache = SighashCache::new(self);
        match cache.legacy_encode_signing_data_to(writer, input_index, script_pubkey, sighash_type)
        {
            SighashSingleBug => SighashSingleBug,
            WriteResult(res) => match res {
                Ok(()) => WriteResult(Ok(())),
                Err(e) => match e {
                    sighash::Error::Io(e) => WriteResult(Err(e.into())),
                    _ => unreachable!("we check input_index above"),
                },
            },
        }
    }

    /// Computes a signature hash for a given input index with a given sighash flag.
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
    ///
    /// # Panics
    ///
    /// If `input_index` is out of bounds (greater than or equal to `self.input.len()`).
    pub fn signature_hash(
        &self,
        input_index: usize,
        script_pubkey: &Script,
        sighash_u32: u32,
    ) -> LegacySighash {
        if self.is_invalid_use_of_sighash_single(sighash_u32, input_index) {
            return LegacySighash::from_slice(&UINT256_ONE).expect("const-size array");
        }

        let mut engine = LegacySighash::engine();
        let _ = self.encode_signing_data_to(&mut engine, input_index, script_pubkey, sighash_u32);
        LegacySighash::from_engine(engine)
    }

    /// This will hash all input outpoints
    pub fn hash_inputs(&self) -> InputsHash {
        let mut enc = InputsHash::engine();
        for input in self.input.iter() {
            input.previous_output.consensus_encode(&mut enc).expect("engines don't error");
        }
        InputsHash::from_engine(enc)
    }

    // fn legacy_sign_pubkey_hash_inputs_with_private_keys(&mut self, keys: HashMap<PubkeyHash, PrivateKey>) -> Result<(), sighash::Error> {
    //     let cache = SighashCache::new(self);
    //
    //     for (index, input) in self.input.iter_mut().enumerate() {
    //         let mut hash_inner = [0u8; 20];
    //         hash_inner.copy_from_slice(&input.script_sig.as_bytes()[3..23]);
    //         let pubkey_hash = PubkeyHash::from_inner(hash_inner);
    //
    //         let private_key = keys.get(pubkey_hash);
    //         if let Some(key) = key {
    //             let hash = cache.legacy_signature_hash(index,,EcdsaSighashType)?;
    //             let signature = sign_hash(hash, private_key).map_err();
    //             input.script_sig = Script::is_p2pkh()
    //         } else {
    //             return Err()
    //         }
    //     }
    // }

    fn is_invalid_use_of_sighash_single(&self, sighash: u32, input_index: usize) -> bool {
        let ty = EcdsaSighashType::from_consensus(sighash);
        ty == EcdsaSighashType::Single && input_index >= self.output.len()
    }

    /// Returns the "weight" of this transaction, as defined by BIP141.
    ///
    /// For transactions with an empty witness, this is simply the consensus-serialized size times
    /// four. For transactions with a witness, this is the non-witness consensus-serialized size
    /// multiplied by three plus the with-witness consensus-serialized size.
    ///
    /// For transactions with no inputs, this function will return a value 2 less than the actual
    /// weight of the serialized transaction. The reason is that zero-input transactions, post-segwit,
    /// cannot be unambiguously serialized; we make a choice that adds two extra bytes. For more
    /// details see [BIP 141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
    /// which uses a "input count" of `0x00` as a `marker` for a Segwit-encoded transaction.
    ///
    /// If you need to use 0-input transactions, we strongly recommend you do so using the PSBT
    /// API. The unsigned transaction encoded within PSBT is always a non-segwit transaction
    /// and can therefore avoid this ambiguity.
    #[inline]
    pub fn weight(&self) -> Weight {
        Weight::from_wu(self.scaled_size(WITNESS_SCALE_FACTOR) as u64)
    }
    /// Returns the regular byte-wise consensus-serialized size of this transaction.
    #[inline]
    #[deprecated(since = "0.28.0", note = "Please use `transaction::size` instead.")]
    pub fn get_size(&self) -> usize {
        self.size()
    }

    /// Returns the regular byte-wise consensus-serialized size of this transaction.
    #[inline]
    pub fn size(&self) -> usize {
        self.scaled_size(1)
    }

    /// Returns the "virtual size" (vsize) of this transaction.
    #[inline]
    #[deprecated(since = "0.28.0", note = "Please use `transaction::vsize` instead.")]
    pub fn get_vsize(&self) -> usize {
        self.vsize()
    }

    /// Returns the "virtual size" (vsize) of this transaction.
    ///
    /// Will be `ceil(weight / 4.0)`. Note this implements the virtual size as per [`BIP141`], which
    /// is different to what is implemented in Bitcoin Core. The computation should be the same for
    /// any remotely sane transaction, and a standardness-rule-correct version is available in the
    /// [`policy`] module.
    ///
    /// [`BIP141`]: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
    /// [`policy`]: ../policy/mod.rs.html
    #[inline]
    pub fn vsize(&self) -> usize {
        // No overflow because it's computed from data in memory
        self.weight().to_vbytes_ceil() as usize
    }

    /// Returns the size of this transaction excluding the witness data.
    #[deprecated(since = "0.28.0", note = "Please use `transaction::strippedsize` instead.")]
    pub fn get_strippedsize(&self) -> usize {
        self.strippedsize()
    }

    /// Returns the size of this transaction excluding the witness data.
    pub fn strippedsize(&self) -> usize {
        let mut input_size = 0;
        for input in &self.input {
            input_size += 32 + 4 + 4 + // outpoint (32+4) + nSequence
                VarInt(input.script_sig.len() as u64).len() +
                input.script_sig.len();
        }
        let mut output_size = 0;
        for output in &self.output {
            output_size += 8 + // value
                VarInt(output.script_pubkey.len() as u64).len() +
                output.script_pubkey.len();
        }
        let special_tx_len = self.special_transaction_len();
        let non_input_size =
            // version:
            4 +
                // count varints:
                VarInt(self.input.len() as u64).len() +
                VarInt(self.output.len() as u64).len() +
                output_size +
                // lock_time
                4 +
                special_tx_len;
        non_input_size + input_size
    }

    /// Internal utility function for size/weight functions.
    fn scaled_size(&self, scale_factor: usize) -> usize {
        let mut input_weight = 0;
        let mut inputs_with_witnesses = 0;
        for input in &self.input {
            input_weight += scale_factor
                * (32 + 4 + 4 + // outpoint (32+4) + nSequence
                VarInt(input.script_sig.len() as u64).len() +
                input.script_sig.len());
            if !input.witness.is_empty() {
                inputs_with_witnesses += 1;
                input_weight += input.witness.serialized_len();
            }
        }
        let mut output_size = 0;
        for output in &self.output {
            output_size += 8 + // value
                VarInt(output.script_pubkey.len() as u64).len() +
                output.script_pubkey.len();
        }
        let special_tx_len = self.special_transaction_len();
        let non_input_size =
            // version:
            4 +
                // count varints:
                VarInt(self.input.len() as u64).len() +
                VarInt(self.output.len() as u64).len() +
                output_size +
                // lock_time
                4 +
                special_tx_len;
        if inputs_with_witnesses == 0 {
            non_input_size * scale_factor + input_weight
        } else {
            non_input_size * scale_factor + input_weight + self.input.len() - inputs_with_witnesses
                + 2
        }
    }

    /// Returns the length of the special transaction payload, if any.
    pub fn special_transaction_len(&self) -> usize {
        match self.special_transaction_payload.as_ref() {
            Some(payload) => payload.len(),
            None => 0,
        }
    }

    /// Shorthand for [`Self::verify_with_flags`] with flag [`bitcoinconsensus::VERIFY_ALL`].
    #[cfg(feature = "bitcoinconsensus")]
    pub fn verify<S>(&self, spent: S) -> Result<(), script::Error>
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
    {
        self.verify_with_flags(spent, ::bitcoinconsensus::VERIFY_ALL)
    }

    /// Verify that this transaction is able to spend its inputs.
    /// The `spent` closure should not return the same [`TxOut`] twice!
    #[cfg(feature = "bitcoinconsensus")]
    pub fn verify_with_flags<S, F>(&self, mut spent: S, flags: F) -> Result<(), script::Error>
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
        F: Into<u32>,
    {
        let tx = encode::serialize(&*self);
        let flags: u32 = flags.into();
        for (idx, input) in self.input.iter().enumerate() {
            if let Some(output) = spent(&input.previous_output) {
                output.script_pubkey.verify_with_flags(
                    idx,
                    crate::Amount::from_sat(output.value),
                    tx.as_slice(),
                    flags,
                )?;
            } else {
                return Err(script::Error::UnknownSpentOutput(input.previous_output.clone()));
            }
        }
        Ok(())
    }

    /// Is this a coin base transaction?
    pub fn is_coin_base(&self) -> bool {
        self.input.len() == 1 && self.input[0].previous_output.is_null()
    }

    /// Returns `true` if the transaction itself opted in to be BIP-125-replaceable (RBF). This
    /// **does not** cover the case where a transaction becomes replaceable due to ancestors being
    /// RBF.
    pub fn is_explicitly_rbf(&self) -> bool {
        self.input.iter().any(|input| input.sequence < (0xffffffff - 1))
    }

    /// Adds an output that burns Dash. Used to top up a Dash Identity;
    /// accepts hash of the public key to prove ownership of the burnt
    /// dash on Dash Platform.
    pub fn add_burn_output(&mut self, satoshis_to_burn: u64, data: &[u8; 20]) {
        let burn_script = ScriptBuf::new_op_return(data);
        let output = TxOut {
            value: satoshis_to_burn,
            script_pubkey: burn_script,
        };
        self.output.push(output)
    }

    /// Gives an OutPoint buffer for the output at a given index
    pub fn out_point_buffer(&self, output_index: usize) -> Option<[u8; 36]> {
        self.output.get(output_index).map(|_a| {
            let mut result: [u8; 36] = [0; 36];
            let hash = self.txid();

            let (one, two) = result.split_at_mut(32);
            one.copy_from_slice(hash.as_raw_hash().as_byte_array().as_slice());
            let output_index_bytes: [u8; 4] = (output_index as u32).to_le_bytes();
            two.copy_from_slice(&output_index_bytes);
            result
        })
    }

    /// Computes the weight and checks that it matches the output of `predict_weight`.
    #[cfg(test)]
    fn check_weight(&self) -> Weight {
        let weight1 = self.weight();
        let inputs = self.input.iter().map(|txin| {
            InputWeightPrediction::new(
                txin.script_sig.len(),
                txin.witness.iter().map(|elem| elem.len()),
            )
        });
        let outputs = self.output.iter().map(|txout| txout.script_pubkey.len());
        let weight2 = predict_weight(inputs, outputs);
        assert_eq!(weight1, weight2);
        weight1
    }
}

impl Encodable for Transaction {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(w)?;
        len += (self.tx_type() as u16).consensus_encode(w)?;
        // To avoid serialization ambiguity, no inputs means we use BIP141 serialization (see
        // `Transaction` docs for full explanation).
        let mut have_witness = self.input.is_empty();
        for input in &self.input {
            if !input.witness.is_empty() {
                have_witness = true;
                break;
            }
        }
        // Forcing have_witness to false for AssetUnlock, as currently Core doesn't support BIP141 SegWit.
        if self.tx_type() == TransactionType::AssetUnlock {
            have_witness = false;
        }
        if !have_witness {
            len += self.input.consensus_encode(w)?;
            len += self.output.consensus_encode(w)?;
        } else {
            len += 0u8.consensus_encode(w)?;
            len += 1u8.consensus_encode(w)?;
            len += self.input.consensus_encode(w)?;
            len += self.output.consensus_encode(w)?;
            for input in &self.input {
                len += input.witness.consensus_encode(w)?;
            }
        }
        len += self.lock_time.consensus_encode(w)?;
        if let Some(payload) = &self.special_transaction_payload {
            let mut buf = Vec::new();
            payload.consensus_encode(&mut buf)?;
            // this is so we get the size of the payload
            len += buf.consensus_encode(w)?;
        }
        Ok(len)
    }
}

impl Decodable for Transaction {
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode_from_finite_reader(r)?;
        let special_transaction_type_u16 = u16::consensus_decode(r)?;
        let special_transaction_type = TransactionType::try_from(special_transaction_type_u16)
            .map_err(|_| {
                encode::Error::UnknownSpecialTransactionType(special_transaction_type_u16)
            })?;
        let input = Vec::<TxIn>::consensus_decode_from_finite_reader(r)?;
        // segwit
        let mut segwit = input.is_empty();
        // Forcing segwit to false for AssetUnlock, as currently Core doesn't support BIP141 SegWit.
        if special_transaction_type == TransactionType::AssetUnlock {
            segwit = false;
        }
        if special_transaction_type == TransactionType::QuorumCommitment {
            segwit = false;
        }
        if segwit {
            let segwit_flag = u8::consensus_decode_from_finite_reader(r)?;
            match segwit_flag {
                // BIP144 input witnesses
                1 => {
                    let mut input = Vec::<TxIn>::consensus_decode_from_finite_reader(r)?;
                    let output = Vec::<TxOut>::consensus_decode_from_finite_reader(r)?;
                    for txin in input.iter_mut() {
                        txin.witness = Decodable::consensus_decode_from_finite_reader(r)?;
                    }
                    if !input.is_empty() && input.iter().all(|input| input.witness.is_empty()) {
                        Err(encode::Error::ParseFailed("witness flag set but no witnesses present"))
                    } else {
                        Ok(Transaction {
                            version,
                            input,
                            output,
                            lock_time: Decodable::consensus_decode_from_finite_reader(r)?,
                            special_transaction_payload: special_transaction_type
                                .consensus_decode(r)?,
                        })
                    }
                }
                // We don't support anything else
                x => Err(encode::Error::UnsupportedSegwitFlag(x)),
            }
            // non-segwit
        } else {
            Ok(Transaction {
                version,
                input,
                output: Decodable::consensus_decode_from_finite_reader(r)?,
                lock_time: Decodable::consensus_decode_from_finite_reader(r)?,
                special_transaction_payload: special_transaction_type.consensus_decode(r)?,
            })
        }
    }
}

/// Weight prediction of an individual input.
///
/// This helper type collects information about an input to be used in [`predict_weight`] function.
/// It can only be created using the [`new`](InputWeightPrediction::new) function.
#[derive(Copy, Clone, Debug)]
pub struct InputWeightPrediction {
    script_size: usize,
    witness_size: usize,
}

impl InputWeightPrediction {
    /// Input weight prediction corresponding to spending of P2WPKH output with the largest possible
    /// DER-encoded signature.
    ///
    /// If the input in your transaction uses P2WPKH you can use this instead of
    /// [`InputWeightPrediction::new`].
    ///
    /// This is useful when you **do not** use [signature grinding] and want to ensure you are not
    /// under-paying. See [`ground_p2wpkh`](Self::ground_p2wpkh) if you do use signature grinding.
    ///
    /// [signature grinding]: https://bitcoin.stackexchange.com/questions/111660/what-is-signature-grinding
    pub const P2WPKH_MAX: Self = InputWeightPrediction {
        script_size: 0,
        witness_size: 1 + 1 + 73 + 1 + 33,
    };

    /// Input weight prediction corresponding to spending of taproot output using the key and
    /// default sighash.
    ///
    /// If the input in your transaction uses Taproot key spend you can use this instead of
    /// [`InputWeightPrediction::new`].
    pub const P2TR_KEY_DEFAULT_SIGHASH: Self = InputWeightPrediction {
        script_size: 0,
        witness_size: 1 + 1 + 64,
    };

    /// Input weight prediction corresponding to spending of taproot output using the key and
    /// **non**-default sighash.
    ///
    /// If the input in your transaction uses Taproot key spend you can use this instead of
    /// [`InputWeightPrediction::new`].
    pub const P2TR_KEY_NON_DEFAULT_SIGHASH: Self = InputWeightPrediction {
        script_size: 0,
        witness_size: 1 + 1 + 65,
    };

    /// Input weight prediction corresponding to spending of P2WPKH output using [signature
    /// grinding].
    ///
    /// If the input in your transaction uses P2WPKH and you use signature grinding you can use this
    /// instead of [`InputWeightPrediction::new`]. See [`P2WPKH_MAX`](Self::P2WPKH_MAX) if you don't
    /// use signature grinding.
    ///
    /// Note: `bytes_to_grind` is usually `1` because of exponential cost of higher values.
    ///
    /// # Panics
    ///
    /// The funcion panics in const context and debug builds if `bytes_to_grind` is higher than 62.
    ///
    /// [signature grinding]: https://bitcoin.stackexchange.com/questions/111660/what-is-signature-grinding
    pub const fn ground_p2wpkh(bytes_to_grind: usize) -> Self {
        // Written to trigger const/debug panic for unreasonably high values.
        let der_signature_size = 10 + (62 - bytes_to_grind);
        let witness_size = 1 // length of element count varint
            + 1 // length of element size varint (max signature length is 73B)
            + der_signature_size
            + 1 // sighash flag
            + 1 // length of element size varint
            + 33; // length of (always-compressed) public key
        InputWeightPrediction {
            script_size: 0,
            witness_size,
        }
    }

    /// Computes the prediction for a single input.
    pub fn new<T>(input_script_len: usize, witness_element_lengths: T) -> Self
    where
        T: IntoIterator,
        T::Item: Borrow<usize>,
    {
        let (count, total_size) =
            witness_element_lengths.into_iter().fold((0, 0), |(count, total_size), elem_len| {
                let elem_len = *elem_len.borrow();
                let elem_size = elem_len + VarInt(elem_len as u64).len();
                (count + 1, total_size + elem_size)
            });
        let witness_size = if count > 0 {
            total_size + VarInt(count as u64).len()
        } else {
            0
        };
        let script_size = input_script_len + VarInt(input_script_len as u64).len();

        InputWeightPrediction {
            script_size,
            witness_size,
        }
    }

    /// Computes the prediction for a single input in `const` context.
    ///
    /// *Important: only available in Rust 1.46+*
    ///
    /// This is a `const` version of [`new`](Self::new) which only allows slices due to current Rust
    /// limitations around `const fn`. Because of these limitations it may be less efficient than
    /// `new` and thus is intended to be only used in `const` context.
    pub const fn from_slice(input_script_len: usize, witness_element_lengths: &[usize]) -> Self {
        let mut i = 0;
        let mut total_size = 0;
        // for loops not supported in const fn
        while i < witness_element_lengths.len() {
            let elem_len = witness_element_lengths[i];
            let elem_size = elem_len + VarInt(elem_len as u64).len();
            total_size += elem_size;
            i += 1;
        }
        let witness_size = if !witness_element_lengths.is_empty() {
            total_size + VarInt(witness_element_lengths.len() as u64).len()
        } else {
            0
        };
        let script_size = input_script_len + VarInt(input_script_len as u64).len();

        InputWeightPrediction {
            script_size,
            witness_size,
        }
    }
}

/// Predicts the weight of a to-be-constructed transaction.
///
/// This function computes the weight of a transaction which is not fully known. All that is needed
/// is the lengths of scripts and witness elements.
///
/// # Arguments
///
/// * `inputs` - an iterator which returns `InputWeightPrediction` for each input of the
///   to-be-constructed transaction.
/// * `output_script_lens` - an iterator which returns the length of `script_pubkey` of each output
///   of the to-be-constructed transaction.
///
/// Note that lengths of the scripts and witness elements must be non-serialized, IOW *without* the
/// preceding compact size. The lenght of preceding compact size is computed and added inside the
/// function for convenience.
///
/// # Usage
///
/// When signing a transaction one doesn't know the signature before knowing the transaction fee and
/// the transaction fee is not known before knowing the transaction size which is not known before
/// knowing the signature. This apparent dependency cycle can be broken by knowing the length of the
/// signature without knowing the contents of the signature e.g., we know all Schnorr signatures
/// are 64 bytes long.
///
/// Additionally, some protocols may require calculating the amounts before knowing various parts
/// of the transaction (assuming their length is known).
///
/// # Notes on integer overflow
///
/// Overflows are intentionally not checked because one of the following holds:
///
/// * The transaction is valid (obeys the block size limit) and the code feeds correct values to
///   this function - no overflow can happen.
/// * The transaction will be so large it doesn't fit in the memory - overflow will happen but
///   then the transaction will fail to construct and even if one serialized it on disk directly
///   it'd be invalid anyway so overflow doesn't matter.
/// * The values fed into this function are inconsistent with the actual lengths the transaction
///   will have - the code is already broken and checking overflows doesn't help. Unfortunately
///   this probably cannot be avoided.
pub fn predict_weight<I, O>(inputs: I, output_script_lens: O) -> Weight
where
    I: IntoIterator<Item = InputWeightPrediction>,
    O: IntoIterator<Item = usize>,
{
    let (input_count, partial_input_weight, inputs_with_witnesses) = inputs.into_iter().fold(
        (0, 0, 0),
        |(count, partial_input_weight, inputs_with_witnesses), prediction| {
            (
                count + 1,
                partial_input_weight + prediction.script_size * 4 + prediction.witness_size,
                inputs_with_witnesses + (prediction.witness_size > 0) as usize,
            )
        },
    );
    let (output_count, output_scripts_size) = output_script_lens.into_iter().fold(
        (0, 0),
        |(output_count, total_scripts_size), script_len| {
            let script_size = script_len + VarInt(script_len as u64).len();
            (output_count + 1, total_scripts_size + script_size)
        },
    );
    predict_weight_internal(
        input_count,
        partial_input_weight,
        inputs_with_witnesses,
        output_count,
        output_scripts_size,
    )
}

const fn predict_weight_internal(
    input_count: usize,
    partial_input_weight: usize,
    inputs_with_witnesses: usize,
    output_count: usize,
    output_scripts_size: usize,
) -> Weight {
    let input_weight = partial_input_weight + input_count * 4 * (32 + 4 + 4);
    let output_size = 8 * output_count + output_scripts_size;
    let non_input_size =
        // version:
        4 +
            // count varints:
            VarInt(input_count as u64).len() +
            VarInt(output_count as u64).len() +
            output_size +
            // lock_time
            4;
    let weight = if inputs_with_witnesses == 0 {
        non_input_size * 4 + input_weight
    } else {
        non_input_size * 4 + input_weight + input_count - inputs_with_witnesses + 2
    };
    Weight::from_wu(weight as u64)
}

#[cfg(test)]
mod tests {
    use hashes::hex::FromHex;

    use super::*;
    use crate::blockdata::constants::WITNESS_SCALE_FACTOR;
    use crate::consensus::encode::{deserialize, serialize};
    use crate::internal_macros::hex;
    use crate::network::message::{NetworkMessage, RawNetworkMessage};

    #[test]
    fn test_is_coinbase() {
        use crate::blockdata::constants;
        use crate::network::constants::Network;

        let genesis = constants::genesis_block(Network::Dash);
        assert!(genesis.txdata[0].is_coin_base());
        let tx_bytes = Vec::from_hex("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();
        assert!(!tx.is_coin_base());
    }

    #[test]
    fn test_nonsegwit_transaction() {
        let tx_bytes = hex!(
            "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000"
        );
        let tx: Result<Transaction, _> = deserialize(&tx_bytes);
        assert!(tx.is_ok());
        let realtx = tx.unwrap();
        // All these tests aren't really needed because if they fail, the hash check at the end
        // will also fail. But these will show you where the failure is so I'll leave them in.
        assert_eq!(realtx.version, 1);
        assert_eq!(realtx.input.len(), 1);
        // In particular this one is easy to get backward -- in dash hashes are encoded
        // as little-endian 256-bit numbers rather than as data strings.
        assert_eq!(
            format!("{:x}", realtx.input[0].previous_output.txid),
            "ce9ea9f6f5e422c6a9dbcddb3b9a14d1c78fab9ab520cb281aa2a74a09575da1".to_string()
        );
        assert_eq!(realtx.input[0].previous_output.vout, 1);
        assert_eq!(realtx.output.len(), 1);
        assert_eq!(realtx.lock_time, 0);

        assert_eq!(
            format!("{:x}", realtx.txid()),
            "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7".to_string()
        );
        assert_eq!(
            format!("{:x}", realtx.wtxid()),
            "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7".to_string()
        );
        assert_eq!(realtx.check_weight().to_wu() as usize, tx_bytes.len() * WITNESS_SCALE_FACTOR);
        assert_eq!(realtx.size(), tx_bytes.len());
        assert_eq!(realtx.vsize(), tx_bytes.len());
        assert_eq!(realtx.strippedsize(), tx_bytes.len());
    }

    #[test]
    fn test_segwit_transaction() {
        let tx_bytes = hex!(
            "02000000000101595895ea20179de87052b4046dfe6fd515860505d6511a9004cf12a1f93cac7c01000000\
            00ffffffff01deb807000000000017a9140f3444e271620c736808aa7b33e370bd87cb5a078702483045022\
            100fb60dad8df4af2841adc0346638c16d0b8035f5e3f3753b88db122e70c79f9370220756e6633b17fd271\
            0e626347d28d60b0a2d6cbb41de51740644b9fb3ba7751040121028fa937ca8cba2197a37c007176ed89410\
            55d3bcb8627d085e94553e62f057dcc00000000"
        );
        let tx: Result<Transaction, _> = deserialize(&tx_bytes);
        assert!(tx.is_ok());
        let realtx = tx.unwrap();
        // All these tests aren't really needed because if they fail, the hash check at the end
        // will also fail. But these will show you where the failure is so I'll leave them in.
        assert_eq!(realtx.version, 2);
        assert_eq!(realtx.input.len(), 1);
        // In particular this one is easy to get backward -- in dash hashes are encoded
        // as little-endian 256-bit numbers rather than as data strings.
        assert_eq!(
            format!("{:x}", realtx.input[0].previous_output.txid),
            "7cac3cf9a112cf04901a51d605058615d56ffe6d04b45270e89d1720ea955859".to_string()
        );
        assert_eq!(realtx.input[0].previous_output.vout, 1);
        assert_eq!(realtx.output.len(), 1);
        assert_eq!(realtx.lock_time, 0);

        assert_eq!(
            format!("{:x}", realtx.txid()),
            "f5864806e3565c34d1b41e716f72609d00b55ea5eac5b924c9719a842ef42206".to_string()
        );
        assert_eq!(
            format!("{:x}", realtx.wtxid()),
            "80b7d8a82d5d5bf92905b06f2014dd699e03837ca172e3a59d51426ebbe3e7f5".to_string()
        );
        const EXPECTED_WEIGHT: Weight = Weight::from_wu(442);
        assert_eq!(realtx.check_weight(), EXPECTED_WEIGHT);
        assert_eq!(realtx.size(), tx_bytes.len());
        assert_eq!(realtx.vsize(), 111);
        // Since
        //     size   =                        stripped_size + witness_size
        //     weight = WITNESS_SCALE_FACTOR * stripped_size + witness_size
        // then,
        //     stripped_size = (weight - size) / (WITNESS_SCALE_FACTOR - 1)
        let expected_strippedsize =
            (EXPECTED_WEIGHT.to_wu() as usize - tx_bytes.len()) / (WITNESS_SCALE_FACTOR - 1);
        assert_eq!(realtx.strippedsize(), expected_strippedsize);
        // Construct a transaction without the witness data.
        let mut tx_without_witness = realtx;
        tx_without_witness.input.iter_mut().for_each(|input| input.witness.clear());
        assert_eq!(
            tx_without_witness.check_weight().to_wu() as usize,
            expected_strippedsize * WITNESS_SCALE_FACTOR
        );
        assert_eq!(tx_without_witness.size(), expected_strippedsize);
        assert_eq!(tx_without_witness.vsize(), expected_strippedsize);
        assert_eq!(tx_without_witness.strippedsize(), expected_strippedsize);
    }

    #[test]
    fn test_transaction_version() {
        let tx_bytes = Vec::from_hex("ffff00000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000").unwrap();
        let tx: Result<Transaction, _> = deserialize(&tx_bytes);
        assert!(tx.is_ok());
        let realtx = tx.unwrap();
        assert_eq!(realtx.version, 65535);

        let tx2_bytes = Vec::from_hex("000000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000").unwrap();
        let tx2: Result<Transaction, _> = deserialize(&tx2_bytes);
        assert!(tx2.is_ok());
        let realtx2 = tx2.unwrap();
        assert_eq!(realtx2.version, 0);
    }

    #[test]
    fn tx_no_input_deserialization() {
        let tx_bytes = Vec::from_hex(
            "010000000001000100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000"
        ).unwrap();
        let tx: Transaction = deserialize(&tx_bytes).expect("deserialize tx");

        assert_eq!(tx.input.len(), 0);
        assert_eq!(tx.output.len(), 1);

        let reser = serialize(&tx);
        assert_eq!(tx_bytes, reser);
    }

    #[test]
    fn test_ntxid() {
        let tx_bytes = Vec::from_hex("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap();
        let mut tx: Transaction = deserialize(&tx_bytes).unwrap();

        let old_ntxid = tx.ntxid();
        assert_eq!(
            format!("{:x}", old_ntxid),
            "c3573dbea28ce24425c59a189391937e00d255150fa973d59d61caf3a06b601d"
        );
        // changing sigs does not affect it
        tx.input[0].script_sig = ScriptBuf::new();
        assert_eq!(old_ntxid, tx.ntxid());
        // changing pks does
        tx.output[0].script_pubkey = ScriptBuf::new();
        assert!(old_ntxid != tx.ntxid());
    }

    #[test]
    fn test_txid() {
        // segwit tx from Liquid integration tests, txid/hash from Core decoderawtransaction
        let tx_bytes = hex!(
            "01000000000102ff34f95a672bb6a4f6ff4a7e90fa8c7b3be7e70ffc39bc99be3bda67942e836c00000000\
             23220020cde476664d3fa347b8d54ef3aee33dcb686a65ced2b5207cbf4ec5eda6b9b46e4f414d4c934ad8\
             1d330314e888888e3bd22c7dde8aac2ca9227b30d7c40093248af7812201000000232200200af6f6a071a6\
             9d5417e592ed99d256ddfd8b3b2238ac73f5da1b06fc0b2e79d54f414d4c0ba0c8f505000000001976a914\
             dcb5898d9036afad9209e6ff0086772795b1441088ac033c0f000000000017a914889f8c10ff2bd4bb9dab\
             b68c5c0d700a46925e6c87033c0f000000000017a914889f8c10ff2bd4bb9dabb68c5c0d700a46925e6c87\
             033c0f000000000017a914889f8c10ff2bd4bb9dabb68c5c0d700a46925e6c87033c0f000000000017a914\
             889f8c10ff2bd4bb9dabb68c5c0d700a46925e6c87033c0f000000000017a914889f8c10ff2bd4bb9dabb6\
             8c5c0d700a46925e6c87033c0f000000000017a914889f8c10ff2bd4bb9dabb68c5c0d700a46925e6c8703\
             3c0f000000000017a914889f8c10ff2bd4bb9dabb68c5c0d700a46925e6c87033c0f000000000017a91488\
             9f8c10ff2bd4bb9dabb68c5c0d700a46925e6c87033c0f000000000017a914889f8c10ff2bd4bb9dabb68c\
             5c0d700a46925e6c87033c0f000000000017a914889f8c10ff2bd4bb9dabb68c5c0d700a46925e6c870500\
             47304402200380b8663e727d7e8d773530ef85d5f82c0b067c97ae927800a0876a1f01d8e2022021ee611e\
             f6507dfd217add2cd60a8aea3cbcfec034da0bebf3312d19577b8c290147304402207bd9943ce1c2c5547b\
             120683fd05d78d23d73be1a5b5a2074ff586b9c853ed4202202881dcf435088d663c9af7b23efb3c03b9db\
             c0c899b247aa94a74d9b4b3c84f501483045022100ba12bba745af3f18f6e56be70f8382ca8e107d1ed5ce\
             aa3e8c360d5ecf78886f022069b38ebaac8fe6a6b97b497cbbb115f3176f7213540bef08f9292e5a72de52\
             de01695321023c9cd9c6950ffee24772be948a45dc5ef1986271e46b686cb52007bac214395a2102756e27\
             cb004af05a6e9faed81fd68ff69959e3c64ac8c9f6cd0e08fd0ad0e75d2103fa40da236bd82202a985a910\
             4e851080b5940812685769202a3b43e4a8b13e6a53ae050048304502210098b9687b81d725a7970d1eee91\
             ff6b89bc9832c2e0e3fb0d10eec143930b006f02206f77ce19dc58ecbfef9221f81daad90bb4f468df3912\
             12abc4f084fe2cc9bdef01483045022100e5479f81a3ad564103da5e2ec8e12f61f3ac8d312ab68763c1dd\
             d7bae94c20610220789b81b7220b27b681b1b2e87198897376ba9d033bc387f084c8b8310c8539c2014830\
             45022100aa1cc48a2d256c0e556616444cc08ae4959d464e5ffff2ae09e3550bdab6ce9f02207192d5e332\
             9a56ba7b1ead724634d104f1c3f8749fe6081e6233aee3e855817a016953210260de9cc68658c61af984e3\
             ab0281d17cfca1cc035966d335f474932d5e6c5422210355fbb768ce3ce39360277345dbb5f376e706459e\
             5a2b5e0e09a535e61690647021023222ceec58b94bd25925dd9743dae6b928737491bd940fc5dd7c6f5d5f\
             2adc1e53ae00000000"
        );
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        assert_eq!(
            format!("{:x}", tx.wtxid()),
            "d6ac4a5e61657c4c604dcde855a1db74ec6b3e54f32695d72c5e11c7761ea1b4"
        );
        assert_eq!(
            format!("{:x}", tx.txid()),
            "9652aa62b0e748caeec40c4cb7bc17c6792435cc3dfe447dd1ca24f912a1c6ec"
        );
        assert_eq!(tx.check_weight(), Weight::from_wu(2718));

        // non-segwit tx from my mempool
        let tx_bytes = hex!(
            "01000000010c7196428403d8b0c88fcb3ee8d64f56f55c8973c9ab7dd106bb4f3527f5888d000000006a47\
             30440220503a696f55f2c00eee2ac5e65b17767cd88ed04866b5637d3c1d5d996a70656d02202c9aff698f\
             343abb6d176704beda63fcdec503133ea4f6a5216b7f925fa9910c0121024d89b5a13d6521388969209df2\
             7a8469bd565aff10e8d42cef931fad5121bfb8ffffffff02b825b404000000001976a914ef79e7ee9fff98\
             bcfd08473d2b76b02a48f8c69088ac0000000000000000296a273236303039343836393731373233313237\
             3633313032313332353630353838373931323132373000000000"
        );
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        assert_eq!(
            format!("{:x}", tx.wtxid()),
            "971ed48a62c143bbd9c87f4bafa2ef213cfa106c6e140f111931d0be307468dd"
        );
        assert_eq!(
            format!("{:x}", tx.txid()),
            "971ed48a62c143bbd9c87f4bafa2ef213cfa106c6e140f111931d0be307468dd"
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_txn_encode_decode() {
        let tx_bytes = Vec::from_hex("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();
        serde_round_trip!(tx);
    }

    // Test decoding transaction `4be105f158ea44aec57bf12c5817d073a712ab131df6f37786872cfc70734188`
    // from testnet, which is the first BIP144-encoded transaction I encountered.
    #[test]
    #[cfg(feature = "serde")]
    fn test_segwit_tx_decode() {
        let tx_bytes = Vec::from_hex("010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff3603da1b0e00045503bd5704c7dd8a0d0ced13bb5785010800000000000a636b706f6f6c122f4e696e6a61506f6f6c2f5345475749542fffffffff02b4e5a212000000001976a914876fbb82ec05caa6af7a3b5e5a983aae6c6cc6d688ac0000000000000000266a24aa21a9edf91c46b49eb8a29089980f02ee6b57e7d63d33b18b4fddac2bcd7db2a39837040120000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();
        assert_eq!(tx.weight(), Weight::from_wu(780));
        serde_round_trip!(tx);

        let consensus_encoded = serialize(&tx);
        assert_eq!(consensus_encoded, tx_bytes);
    }

    #[test]
    #[cfg(feature = "bitcoinconsensus")]
    fn test_transaction_verify() {
        use std::collections::HashMap;

        use hashes::hex::FromHex;

        use crate::blockdata::script;
        use crate::blockdata::witness::Witness;

        // a random recent segwit transaction from blockchain using both old and segwit inputs
        let mut spending: Transaction = deserialize(Vec::from_hex("020000000001031cfbc8f54fbfa4a33a30068841371f80dbfe166211242213188428f437445c91000000006a47304402206fbcec8d2d2e740d824d3d36cc345b37d9f65d665a99f5bd5c9e8d42270a03a8022013959632492332200c2908459547bf8dbf97c65ab1a28dec377d6f1d41d3d63e012103d7279dfb90ce17fe139ba60a7c41ddf605b25e1c07a4ddcb9dfef4e7d6710f48feffffff476222484f5e35b3f0e43f65fc76e21d8be7818dd6a989c160b1e5039b7835fc00000000171600140914414d3c94af70ac7e25407b0689e0baa10c77feffffffa83d954a62568bbc99cc644c62eb7383d7c2a2563041a0aeb891a6a4055895570000000017160014795d04cc2d4f31480d9a3710993fbd80d04301dffeffffff06fef72f000000000017a91476fd7035cd26f1a32a5ab979e056713aac25796887a5000f00000000001976a914b8332d502a529571c6af4be66399cd33379071c588ac3fda0500000000001976a914fc1d692f8de10ae33295f090bea5fe49527d975c88ac522e1b00000000001976a914808406b54d1044c429ac54c0e189b0d8061667e088ac6eb68501000000001976a914dfab6085f3a8fb3e6710206a5a959313c5618f4d88acbba20000000000001976a914eb3026552d7e3f3073457d0bee5d4757de48160d88ac0002483045022100bee24b63212939d33d513e767bc79300051f7a0d433c3fcf1e0e3bf03b9eb1d70220588dc45a9ce3a939103b4459ce47500b64e23ab118dfc03c9caa7d6bfc32b9c601210354fd80328da0f9ae6eef2b3a81f74f9a6f66761fadf96f1d1d22b1fd6845876402483045022100e29c7e3a5efc10da6269e5fc20b6a1cb8beb92130cc52c67e46ef40aaa5cac5f0220644dd1b049727d991aece98a105563416e10a5ac4221abac7d16931842d5c322012103960b87412d6e169f30e12106bdf70122aabb9eb61f455518322a18b920a4dfa887d30700")
            .unwrap().as_slice()).unwrap();
        let spent1: Transaction = deserialize(Vec::from_hex("020000000001040aacd2c49f5f3c0968cfa8caf9d5761436d95385252e3abb4de8f5dcf8a582f20000000017160014bcadb2baea98af0d9a902e53a7e9adff43b191e9feffffff96cd3c93cac3db114aafe753122bd7d1afa5aa4155ae04b3256344ecca69d72001000000171600141d9984579ceb5c67ebfbfb47124f056662fe7adbfeffffffc878dd74d3a44072eae6178bb94b9253177db1a5aaa6d068eb0e4db7631762e20000000017160014df2a48cdc53dae1aba7aa71cb1f9de089d75aac3feffffffe49f99275bc8363f5f593f4eec371c51f62c34ff11cc6d8d778787d340d6896c0100000017160014229b3b297a0587e03375ab4174ef56eeb0968735feffffff03360d0f00000000001976a9149f44b06f6ee92ddbc4686f71afe528c09727a5c788ac24281b00000000001976a9140277b4f68ff20307a2a9f9b4487a38b501eb955888ac227c0000000000001976a9148020cd422f55eef8747a9d418f5441030f7c9c7788ac0247304402204aa3bd9682f9a8e101505f6358aacd1749ecf53a62b8370b97d59243b3d6984f02200384ad449870b0e6e89c92505880411285ecd41cf11e7439b973f13bad97e53901210205b392ffcb83124b1c7ce6dd594688198ef600d34500a7f3552d67947bbe392802473044022033dfd8d190a4ae36b9f60999b217c775b96eb10dee3a1ff50fb6a75325719106022005872e4e36d194e49ced2ebcf8bb9d843d842e7b7e0eb042f4028396088d292f012103c9d7cbf369410b090480de2aa15c6c73d91b9ffa7d88b90724614b70be41e98e0247304402207d952de9e59e4684efed069797e3e2d993e9f98ec8a9ccd599de43005fe3f713022076d190cc93d9513fc061b1ba565afac574e02027c9efbfa1d7b71ab8dbb21e0501210313ad44bc030cc6cb111798c2bf3d2139418d751c1e79ec4e837ce360cc03b97a024730440220029e75edb5e9413eb98d684d62a077b17fa5b7cc19349c1e8cc6c4733b7b7452022048d4b9cae594f03741029ff841e35996ef233701c1ea9aa55c301362ea2e2f68012103590657108a72feb8dc1dec022cf6a230bb23dc7aaa52f4032384853b9f8388baf9d20700")
            .unwrap().as_slice()).unwrap();
        let spent2: Transaction = deserialize(Vec::from_hex("0200000000010166c3d39490dc827a2594c7b17b7d37445e1f4b372179649cd2ce4475e3641bbb0100000017160014e69aa750e9bff1aca1e32e57328b641b611fc817fdffffff01e87c5d010000000017a914f3890da1b99e44cd3d52f7bcea6a1351658ea7be87024830450221009eb97597953dc288de30060ba02d4e91b2bde1af2ecf679c7f5ab5989549aa8002202a98f8c3bd1a5a31c0d72950dd6e2e3870c6c5819a6c3db740e91ebbbc5ef4800121023f3d3b8e74b807e32217dea2c75c8d0bd46b8665b3a2d9b3cb310959de52a09bc9d20700")
            .unwrap().as_slice()).unwrap();
        let spent3: Transaction = deserialize(Vec::from_hex("01000000027a1120a30cef95422638e8dab9dedf720ec614b1b21e451a4957a5969afb869d000000006a47304402200ecc318a829a6cad4aa9db152adbf09b0cd2de36f47b53f5dade3bc7ef086ca702205722cda7404edd6012eedd79b2d6f24c0a0c657df1a442d0a2166614fb164a4701210372f4b97b34e9c408741cd1fc97bcc7ffdda6941213ccfde1cb4075c0f17aab06ffffffffc23b43e5a18e5a66087c0d5e64d58e8e21fcf83ce3f5e4f7ecb902b0e80a7fb6010000006b483045022100f10076a0ea4b4cf8816ed27a1065883efca230933bf2ff81d5db6258691ff75202206b001ef87624e76244377f57f0c84bc5127d0dd3f6e0ef28b276f176badb223a01210309a3a61776afd39de4ed29b622cd399d99ecd942909c36a8696cfd22fc5b5a1affffffff0200127a000000000017a914f895e1dd9b29cb228e9b06a15204e3b57feaf7cc8769311d09000000001976a9144d00da12aaa51849d2583ae64525d4a06cd70fde88ac00000000")
            .unwrap().as_slice()).unwrap();

        let mut spent = HashMap::new();
        spent.insert(spent1.txid(), spent1);
        spent.insert(spent2.txid(), spent2);
        spent.insert(spent3.txid(), spent3);
        let mut spent2 = spent.clone();
        let mut spent3 = spent.clone();

        spending
            .verify(|point: &OutPoint| {
                if let Some(tx) = spent.remove(&point.txid) {
                    return tx.output.get(point.vout as usize).cloned();
                }
                None
            })
            .unwrap();

        // test that we fail with repeated use of same input
        let mut double_spending = spending.clone();
        let re_use = double_spending.input[0].clone();
        double_spending.input.push(re_use);

        assert!(
            double_spending
                .verify(|point: &OutPoint| {
                    if let Some(tx) = spent2.remove(&point.txid) {
                        return tx.output.get(point.vout as usize).cloned();
                    }
                    None
                })
                .is_err()
        );

        // test that we get a failure if we corrupt a signature
        let mut witness: Vec<_> = spending.input[1].witness.to_vec();
        witness[0][10] = 42;
        spending.input[1].witness = Witness::from_slice(witness.as_slice());
        match spending
            .verify(|point: &OutPoint| {
                if let Some(tx) = spent3.remove(&point.txid) {
                    return tx.output.get(point.vout as usize).cloned();
                }
                None
            })
            .err()
            .unwrap()
        {
            script::Error::BitcoinConsensus(_) => {}
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn add_burn_output() {
        let mut tx = Transaction {
            version: 0,
            lock_time: 0,
            input: vec![],
            output: vec![],
            special_transaction_payload: None,
        };

        let pk_data = Vec::from_hex("b8e2d839dd21088b78bebfea3e3e632181197982").unwrap();

        let mut pk_array: [u8; 20] = [0; 20];
        for (index, kek) in pk_array.iter_mut().enumerate() {
            *kek = *pk_data.get(index).unwrap();
        }

        tx.add_burn_output(10000, &pk_array);

        let output = tx.output.first().unwrap();

        assert_eq!(output.value, 10000);
        assert!(output.script_pubkey.is_op_return());

        let data = &output.script_pubkey.as_bytes()[2..];

        assert_eq!(data.len(), 20);
        assert_eq!(&data, &pk_data.as_slice());
    }

    #[test]
    fn deserialize_serialize_coinbase_transaction_in_dml() {
        let block_hex = include_str!("../../../tests/data/test_DML_diffs/DML_0_2221605.hex");
        let data = hex::decode(block_hex).expect("decode hex");
        let mn_list_diff: RawNetworkMessage = deserialize(&data).expect("deserialize MnListDiff");
        if let NetworkMessage::MnListDiff(diff) = mn_list_diff.payload {
            let serialized = serialize(&diff.coinbase_tx);
            let deserialized: Transaction =
                deserialize(serialized.as_slice()).expect("expected to deserialize");
        }
    }
}

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use EmptyWrite;
    use consensus::{Encodable, deserialize};
    use hashes::hex::FromHex;
    use test::{Bencher, black_box};

    use super::Transaction;

    const SOME_TX: &'static str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";

    #[bench]
    pub fn bench_transaction_size(bh: &mut Bencher) {
        let raw_tx = Vec::from_hex(SOME_TX).unwrap();

        let mut tx: Transaction = deserialize(&raw_tx).unwrap();

        bh.iter(|| {
            black_box(black_box(&mut tx).size());
        });
    }

    #[bench]
    pub fn bench_transaction_serialize(bh: &mut Bencher) {
        let raw_tx = Vec::from_hex(SOME_TX).unwrap();
        let tx: Transaction = deserialize(&raw_tx).unwrap();

        let mut data = Vec::with_capacity(raw_tx.len());

        bh.iter(|| {
            let result = tx.consensus_encode(&mut data);
            black_box(&result);
            data.clear();
        });
    }

    #[bench]
    pub fn bench_transaction_serialize_logic(bh: &mut Bencher) {
        let raw_tx = Vec::from_hex(SOME_TX).unwrap();
        let tx: Transaction = deserialize(&raw_tx).unwrap();

        bh.iter(|| {
            let size = tx.consensus_encode(&mut EmptyWrite);
            black_box(&size);
        });
    }

    #[bench]
    pub fn bench_transaction_deserialize(bh: &mut Bencher) {
        let raw_tx = Vec::from_hex(SOME_TX).unwrap();

        bh.iter(|| {
            let tx: Transaction = deserialize(&raw_tx).unwrap();
            black_box(&tx);
        });
    }
}
