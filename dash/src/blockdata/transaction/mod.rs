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

pub mod outpoint;
pub mod special_transaction;
pub mod txin;
pub mod txout;

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use hashes::{Hash, sha256d};

#[cfg(feature = "bitcoinconsensus")]
use crate::blockdata::script;
use crate::blockdata::script::Script;
pub use crate::blockdata::transaction::special_transaction::{TransactionPayload, TransactionType};
use crate::blockdata::transaction::txin::TxIn;
use crate::blockdata::transaction::txout::TxOut;
use crate::consensus::encode::VarInt;
use crate::consensus::{Decodable, Encodable, encode};
use crate::hash_types::{InputsHash, Txid};
use crate::prelude::*;
pub use crate::transaction::outpoint::*;
use crate::{ScriptBuf, Weight, io};

/// Result of `SighashCache::legacy_encode_signing_data_to`.
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
/// Dash transactions use a format with a 2-byte version followed by a 2-byte
/// transaction type. Standard transactions have type 0, while special transactions
/// (masternode registration, quorum commitments, etc.) have non-zero types and
/// include additional payload data.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
                    ..*txin
                })
                .collect(),
            output: self.output.clone(),
            special_transaction_payload: self.special_transaction_payload.clone(),
        };
        cloned_tx.txid().into()
    }

    /// Computes the transaction ID (txid) by double-SHA256 hashing the serialized transaction.
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

    /// Encodes the signing data from which a signature hash for a given input index with a given
    /// sighash flag can be computed.
    ///
    /// To actually produce a scriptSig, this hash needs to be run through an ECDSA signer, the
    /// `EcdsaSighashType` appended to the resulting sig, and a script written around this, but
    /// this is the general (and hard) part.
    ///
    /// The `sighash_type` supports an arbitrary `u32` value, instead of just `EcdsaSighashType`,
    /// because internally 4 bytes are being hashed, even though only the lowest byte is appended to
    /// signature in a transaction.
    ///
    /// # Warning
    ///
    /// - Does NOT attempt to support OP_CODESEPARATOR. In general this would require evaluating
    ///   `script_pubkey` to determine which separators get evaluated and which don't, which we don't
    ///   have the information to determine.
    /// - Does NOT handle the sighash single bug, you should either handle that manually or use
    ///   `Self::signature_hash()` instead.
    ///
    /// # Panics
    ///
    /// If `input_index` is out of bounds (greater than or equal to `self.input.len()`).
    /// Encodes the signing data from which a signature hash for a given input index with a given
    /// sighash flag can be computed.
    ///
    /// To actually produce a scriptSig, this hash needs to be run through an ECDSA signer, the
    /// `EcdsaSighashType` appended to the resulting sig, and a script written around this, but
    /// this is the general (and hard) part.
    ///
    /// The `sighash_type` supports an arbitrary `u32` value, instead of just `EcdsaSighashType`,
    /// because internally 4 bytes are being hashed, even though only the lowest byte is appended to
    /// signature in a transaction.
    ///
    /// # Warning
    ///
    /// - Does NOT attempt to support OP_CODESEPARATOR. In general this would require evaluating
    ///   `script_pubkey` to determine which separators get evaluated and which don't, which we don't
    ///   have the information to determine.
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

    /// This will hash all input outpoints
    pub fn hash_inputs(&self) -> InputsHash {
        let mut enc = InputsHash::engine();
        for input in self.input.iter() {
            input.previous_output.consensus_encode(&mut enc).expect("engines don't error");
        }
        InputsHash::from_engine(enc)
    }

    /// Returns the "weight" of this transaction (size * 4).
    #[inline]
    pub fn weight(&self) -> Weight {
        Weight::from_wu((self.size() * 4) as u64)
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
        self.calculate_size()
    }

    /// Returns the "virtual size" (vsize) of this transaction.
    #[inline]
    #[deprecated(since = "0.28.0", note = "Please use `transaction::vsize` instead.")]
    pub fn get_vsize(&self) -> usize {
        self.vsize()
    }

    /// Returns the "virtual size" (vsize) of this transaction.
    ///
    /// This equals the serialized size.
    #[inline]
    pub fn vsize(&self) -> usize {
        // No overflow because it's computed from data in memory
        self.weight().to_vbytes_ceil() as usize
    }

    /// Returns the size of this transaction.
    #[deprecated(since = "0.28.0", note = "Please use `transaction::strippedsize` instead.")]
    pub fn get_strippedsize(&self) -> usize {
        self.strippedsize()
    }

    /// Returns the size of this transaction.
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

    /// Internal utility function for size calculations.
    fn calculate_size(&self) -> usize {
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
        // version (2) + tx_type (2) + input count varint + output count varint + lock_time (4)
        4 + VarInt(self.input.len() as u64).len()
            + VarInt(self.output.len() as u64).len()
            + input_size
            + output_size
            + 4
            + special_tx_len
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
        let tx = encode::serialize(self);
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
                return Err(script::Error::UnknownSpentOutput(input.previous_output));
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
        let inputs =
            self.input.iter().map(|txin| InputWeightPrediction::new(txin.script_sig.len()));
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
        len += self.input.consensus_encode(w)?;
        len += self.output.consensus_encode(w)?;
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
        let output = Vec::<TxOut>::consensus_decode_from_finite_reader(r)?;
        let lock_time = Decodable::consensus_decode_from_finite_reader(r)?;
        let special_transaction_payload = special_transaction_type.consensus_decode(r)?;

        Ok(Transaction {
            version,
            input,
            output,
            lock_time,
            special_transaction_payload,
        })
    }
}

/// Weight prediction of an individual input.
///
/// This helper type collects information about an input to be used in [`predict_weight`] function.
#[derive(Copy, Clone, Debug)]
pub struct InputWeightPrediction {
    script_size: usize,
}

impl InputWeightPrediction {
    /// Computes the prediction for a single input.
    pub fn new(input_script_len: usize) -> Self {
        let script_size = input_script_len + VarInt(input_script_len as u64).len();
        InputWeightPrediction {
            script_size,
        }
    }
}

/// Predicts the weight of a to-be-constructed transaction.
///
/// This function computes the weight of a transaction which is not fully known. All that is needed
/// is the lengths of scripts.
///
/// # Arguments
///
/// * `inputs` - an iterator which returns `InputWeightPrediction` for each input of the
///   to-be-constructed transaction.
/// * `output_script_lens` - an iterator which returns the length of `script_pubkey` of each output
///   of the to-be-constructed transaction.
///
/// Note that lengths of the scripts must be non-serialized, IOW *without* the preceding compact
/// size. The length of preceding compact size is computed and added inside the function for
/// convenience.
pub fn predict_weight<I, O>(inputs: I, output_script_lens: O) -> Weight
where
    I: IntoIterator<Item = InputWeightPrediction>,
    O: IntoIterator<Item = usize>,
{
    let (input_count, input_script_size) =
        inputs.into_iter().fold((0, 0), |(count, total_script_size), prediction| {
            (count + 1, total_script_size + prediction.script_size)
        });
    let (output_count, output_scripts_size) = output_script_lens.into_iter().fold(
        (0, 0),
        |(output_count, total_scripts_size), script_len| {
            let script_size = script_len + VarInt(script_len as u64).len();
            (output_count + 1, total_scripts_size + script_size)
        },
    );
    predict_weight_internal(input_count, input_script_size, output_count, output_scripts_size)
}

const fn predict_weight_internal(
    input_count: usize,
    input_script_size: usize,
    output_count: usize,
    output_scripts_size: usize,
) -> Weight {
    // Input size: outpoint (32+4) + nSequence (4) + script_size
    let input_size = input_count * (32 + 4 + 4) + input_script_size;
    let output_size = 8 * output_count + output_scripts_size;
    let size =
        // version (2) + tx_type (2):
        4 +
            // count varints:
            VarInt(input_count as u64).len() +
            VarInt(output_count as u64).len() +
            input_size +
            output_size +
            // lock_time
            4;
    Weight::from_wu((size * 4) as u64)
}

#[cfg(test)]
mod tests {
    use hashes::hex::FromHex;

    use super::*;
    use crate::consensus::encode::{deserialize, serialize};
    use crate::internal_macros::hex;
    use crate::network::message::{NetworkMessage, RawNetworkMessage};

    #[test]
    fn test_is_coinbase() {
        use crate::blockdata::constants;
        use dash_network::Network;

        let genesis = constants::genesis_block(Network::Dash);
        assert!(genesis.txdata[0].is_coin_base());
        let tx_bytes = Vec::from_hex("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();
        assert!(!tx.is_coin_base());
    }

    #[test]
    fn test_transaction_deserialization() {
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

        // Dash txid includes 2-byte version and 2-byte tx_type, but for classic
        // transactions (tx_type=0) the serialized form is identical to Bitcoin's 4-byte version
        assert_eq!(
            format!("{:x}", realtx.txid()),
            "a6eab3c14ab5272a58a5ba91505ba1a4b6d7a3a9fcbd187b6cd99a7b6d548cb7".to_string()
        );
        // ntxid is computed with empty script_sig, so it differs from txid
        assert_eq!(
            format!("{:x}", realtx.ntxid()),
            "c3573dbea28ce24425c59a189391937e00d255150fa973d59d61caf3a06b601d".to_string()
        );
        assert_eq!(realtx.check_weight().to_wu() as usize, tx_bytes.len() * 4);
        assert_eq!(realtx.size(), tx_bytes.len());
        assert_eq!(realtx.vsize(), tx_bytes.len());
        assert_eq!(realtx.strippedsize(), tx_bytes.len());
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
        assert_ne!(old_ntxid, tx.ntxid());
    }

    #[test]
    fn test_txid() {
        // A standard Dash transaction
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
            assert_eq!(deserialized, diff.coinbase_tx);
        }
    }
}
