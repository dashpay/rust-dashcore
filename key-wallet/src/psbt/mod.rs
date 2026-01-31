// SPDX-License-Identifier: CC0-1.0

//! Partially Signed Bitcoin Transactions.
//!
//! Implementation of BIP174 Partially Signed Bitcoin Transaction Format as
//! defined at <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
//! except we define PSBTs containing non-standard sighash types as invalid.
//!

use core::{cmp, fmt};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

use crate::bip32::KeySource;
use crate::bip32::{self, ExtendedPrivKey, ExtendedPubKey};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::borrow::Borrow;
use dashcore::blockdata::transaction::txout::TxOut;
use dashcore::blockdata::transaction::Transaction;
use dashcore::crypto::ecdsa;
use dashcore::crypto::key::{PrivateKey, PublicKey};
use dashcore::sighash::{self, EcdsaSighashType, SighashCache};
use dashcore::Amount;
use dashcore_hashes::Hash;
use internals::write_err;
use secp256k1::{Message, Secp256k1, Signing};
use std::collections::{btree_map, BTreeSet};

#[macro_use]
mod macros;
pub mod raw;
pub mod serialize;

mod error;
pub use self::error::Error;

mod map;
pub use self::map::{Input, Output, PsbtSighashType};

/// Partially signed transaction, commonly referred to as a PSBT.
pub type Psbt = PartiallySignedTransaction;

/// A Partially Signed Transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "serde"))]
pub struct PartiallySignedTransaction {
    /// The unsigned transaction, scriptSigs for each input must be empty.
    pub unsigned_tx: Transaction,
    /// The version number of this PSBT. If omitted, the version number is 0.
    pub version: u32,
    /// A global map from extended public keys to the used key fingerprint and
    /// derivation path as defined by BIP 32.
    pub xpub: BTreeMap<ExtendedPubKey, KeySource>,
    /// Global proprietary key-value pairs.
    #[cfg_attr(
        feature = "serde",
        serde(with = "dashcore::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown global key-value pairs.
    #[cfg_attr(
        feature = "serde",
        serde(with = "dashcore::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,

    /// The corresponding key-value map for each input in the unsigned transaction.
    pub inputs: Vec<Input>,
    /// The corresponding key-value map for each output in the unsigned transaction.
    pub outputs: Vec<Output>,
}

impl PartiallySignedTransaction {
    /// Returns an iterator for the funding UTXOs of the psbt
    ///
    /// For each PSBT input that contains UTXO information `Ok` is returned containing that information.
    /// The order of returned items is same as the order of inputs.
    ///
    /// ## Errors
    ///
    /// The function returns error when UTXO information is not present or is invalid.
    ///
    /// ## Panics
    ///
    /// The function panics if the length of transaction inputs is not equal to the length of PSBT inputs.
    pub fn iter_funding_utxos(&self) -> impl Iterator<Item = Result<&TxOut, Error>> {
        assert_eq!(self.inputs.len(), self.unsigned_tx.input.len());
        self.unsigned_tx.input.iter().zip(&self.inputs).map(|(tx_input, psbt_input)| {
            match &psbt_input.utxo {
                Some(utxo) => {
                    let vout = tx_input.previous_output.vout as usize;
                    utxo.output.get(vout).ok_or(Error::PsbtUtxoOutOfBounds)
                }
                None => Err(Error::MissingUtxo),
            }
        })
    }

    /// Checks that unsigned transaction does not have scriptSig's.
    fn unsigned_tx_checks(&self) -> Result<(), Error> {
        for txin in &self.unsigned_tx.input {
            if !txin.script_sig.is_empty() {
                return Err(Error::UnsignedTxHasScriptSigs);
            }
        }

        Ok(())
    }

    /// Creates a PSBT from an unsigned transaction.
    ///
    /// # Errors
    ///
    /// If transactions is not unsigned.
    pub fn from_unsigned_tx(tx: Transaction) -> Result<Self, Error> {
        let psbt = PartiallySignedTransaction {
            inputs: vec![Default::default(); tx.input.len()],
            outputs: vec![Default::default(); tx.output.len()],

            unsigned_tx: tx,
            xpub: Default::default(),
            version: 0,
            proprietary: Default::default(),
            unknown: Default::default(),
        };
        psbt.unsigned_tx_checks()?;
        Ok(psbt)
    }

    /// Extracts the `Transaction` from a PSBT by filling in the available signature information.
    pub fn extract_tx(self) -> Transaction {
        let mut tx: Transaction = self.unsigned_tx;

        for (vin, psbtin) in tx.input.iter_mut().zip(self.inputs.into_iter()) {
            vin.script_sig = psbtin.final_script_sig.unwrap_or_default();
        }

        tx
    }

    /// Combines this [`PartiallySignedTransaction`] with `other` PSBT as described by BIP 174.
    ///
    /// In accordance with BIP 174 this function is commutative i.e., `A.combine(B) == B.combine(A)`
    pub fn combine(&mut self, other: Self) -> Result<(), Error> {
        if self.unsigned_tx != other.unsigned_tx {
            return Err(Error::UnexpectedUnsignedTx {
                expected: Box::new(self.unsigned_tx.clone()),
                actual: Box::new(other.unsigned_tx),
            });
        }

        // BIP 174: The Combiner must remove any duplicate key-value pairs, in accordance with
        //          the specification. It can pick arbitrarily when conflicts occur.

        // Keeping the highest version
        self.version = cmp::max(self.version, other.version);

        // Merging xpubs
        for (xpub, (fingerprint1, derivation1)) in other.xpub {
            match self.xpub.entry(xpub) {
                btree_map::Entry::Vacant(entry) => {
                    entry.insert((fingerprint1, derivation1));
                }
                btree_map::Entry::Occupied(mut entry) => {
                    // Here in case of the conflict we select the version with algorithm:
                    // 1) if everything is equal we do nothing
                    // 2) report an error if
                    //    - derivation paths are equal and fingerprints are not
                    //    - derivation paths are of the same length, but not equal
                    //    - derivation paths has different length, but the shorter one
                    //      is not the strict suffix of the longer one
                    // 3) choose the longest derivation otherwise

                    let (fingerprint2, derivation2) = entry.get().clone();

                    if (derivation1 == derivation2 && fingerprint1 == fingerprint2)
                        || (derivation1.len() < derivation2.len()
                            && derivation1[..]
                                == derivation2[derivation2.len() - derivation1.len()..])
                    {
                        continue;
                    } else if derivation2[..]
                        == derivation1[derivation1.len() - derivation2.len()..]
                    {
                        entry.insert((fingerprint1, derivation1));
                        continue;
                    }
                    return Err(Error::CombineInconsistentKeySources(Box::new(xpub)));
                }
            }
        }

        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);

        for (self_input, other_input) in self.inputs.iter_mut().zip(other.inputs.into_iter()) {
            self_input.combine(other_input);
        }

        for (self_output, other_output) in self.outputs.iter_mut().zip(other.outputs.into_iter()) {
            self_output.combine(other_output);
        }

        Ok(())
    }

    /// Attempts to create _all_ the required signatures for this PSBT using `k`.
    ///
    /// **NOTE**: This function only supports ECDSA inputs (P2PKH and P2SH).
    ///
    /// If you just want to sign an input with one specific key consider using `sighash_ecdsa`. This
    /// function does not support scripts that contain `OP_CODESEPARATOR`.
    ///
    /// # Returns
    ///
    /// Either Ok(SigningKeys) or Err((SigningKeys, SigningErrors)), where
    /// - SigningKeys: A map of input index -> pubkey associated with secret key used to sign.
    /// - SigningKeys: A map of input index -> the error encountered while attempting to sign.
    ///
    /// If an error is returned some signatures may already have been added to the PSBT. Since
    /// `partial_sigs` is a [`BTreeMap`] it is safe to retry, previous sigs will be overwritten.
    pub fn sign<C, K>(
        &mut self,
        k: &K,
        secp: &Secp256k1<C>,
    ) -> Result<SigningKeys, (SigningKeys, SigningErrors)>
    where
        C: Signing,
        K: GetKey,
    {
        let tx = self.unsigned_tx.clone(); // clone because we need to mutably borrow when signing.
        let mut cache = SighashCache::new(&tx);

        let mut used = BTreeMap::new();
        let mut errors = BTreeMap::new();

        for i in 0..self.inputs.len() {
            if let Ok(SigningAlgorithm::Ecdsa) = self.signing_algorithm(i) {
                match self.bip32_sign_ecdsa(k, i, &mut cache, secp) {
                    Ok(v) => {
                        used.insert(i, v);
                    }
                    Err(e) => {
                        errors.insert(i, e);
                    }
                }
            };
        }
        if errors.is_empty() {
            Ok(used)
        } else {
            Err((used, errors))
        }
    }

    /// Attempts to create all signatures required by this PSBT's `bip32_derivation` field, adding
    /// them to `partial_sigs`.
    ///
    /// # Returns
    ///
    /// - Ok: A list of the public keys used in signing.
    /// - Err: Error encountered trying to calculate the sighash AND we had the signing key.
    fn bip32_sign_ecdsa<C, K, T>(
        &mut self,
        k: &K,
        input_index: usize,
        cache: &mut SighashCache<T>,
        secp: &Secp256k1<C>,
    ) -> Result<Vec<PublicKey>, SignError>
    where
        C: Signing,
        T: Borrow<Transaction>,
        K: GetKey,
    {
        let msg_sighash_ty_res = self.sighash_ecdsa(input_index, cache);

        let input = &mut self.inputs[input_index]; // Index checked in call to `sighash_ecdsa`.

        let mut used = Vec::new(); // List of pubkeys used to sign the input.

        for (pk, key_source) in input.bip32_derivation.iter() {
            let sk = if let Ok(Some(sk)) = k.get_key(KeyRequest::Bip32(key_source.clone()), secp) {
                sk
            } else if let Ok(Some(sk)) = k.get_key(KeyRequest::Pubkey(PublicKey::new(*pk)), secp) {
                sk
            } else {
                continue;
            };

            // Only return the error if we have a secret key to sign this input.
            let (msg, sighash_ty) = match msg_sighash_ty_res {
                Err(e) => return Err(e),
                Ok((msg, sighash_ty)) => (msg, sighash_ty),
            };

            let sig = ecdsa::Signature {
                sig: secp.sign_ecdsa(&msg, &sk.inner),
                hash_ty: sighash_ty,
            };

            let pk = sk.public_key(secp);

            input.partial_sigs.insert(pk, sig);
            used.push(pk);
        }

        Ok(used)
    }

    /// Returns the sighash message to sign an ECDSA input along with the sighash type.
    ///
    /// Uses the [`EcdsaSighashType`] from this input if one is specified. If no sighash type is
    /// specified uses [`EcdsaSighashType::All`]. This function does not support scripts that
    /// contain `OP_CODESEPARATOR`.
    pub fn sighash_ecdsa<T: Borrow<Transaction>>(
        &self,
        input_index: usize,
        cache: &mut SighashCache<T>,
    ) -> Result<(Message, EcdsaSighashType), SignError> {
        use OutputType::*;

        let input = self.checked_input(input_index)?;
        let utxo = self.spend_utxo(input_index)?;
        let spk = &utxo.script_pubkey; // scriptPubkey for input spend utxo.

        let hash_ty = input.ecdsa_hash_ty().map_err(|_| SignError::InvalidSighashType)?; // Only support standard sighash types.

        match self.output_type(input_index)? {
            Bare => {
                let sighash = cache.legacy_signature_hash(input_index, spk, hash_ty.to_u32())?;
                Ok((Message::from_digest(sighash.to_byte_array()), hash_ty))
            }
            Sh => {
                let script_code =
                    input.redeem_script.as_ref().ok_or(SignError::MissingRedeemScript)?;
                let sighash =
                    cache.legacy_signature_hash(input_index, script_code, hash_ty.to_u32())?;
                Ok((Message::from_digest(sighash.to_byte_array()), hash_ty))
            }
        }
    }

    /// Returns the spending utxo for this PSBT's input at `input_index`.
    pub fn spend_utxo(&self, input_index: usize) -> Result<&TxOut, SignError> {
        let input = self.checked_input(input_index)?;
        let utxo = if let Some(utxo) = &input.utxo {
            let vout = self.unsigned_tx.input[input_index].previous_output.vout;
            &utxo.output[vout as usize]
        } else {
            return Err(SignError::MissingSpendUtxo);
        };
        Ok(utxo)
    }

    /// Gets the input at `input_index` after checking that it is a valid index.
    fn checked_input(&self, input_index: usize) -> Result<&Input, SignError> {
        self.check_index_is_within_bounds(input_index)?;
        Ok(&self.inputs[input_index])
    }

    /// Checks `input_index` is within bounds for the PSBT `inputs` array and
    /// for the PSBT `unsigned_tx` `input` array.
    fn check_index_is_within_bounds(&self, input_index: usize) -> Result<(), SignError> {
        if input_index >= self.inputs.len() {
            return Err(SignError::IndexOutOfBounds(input_index, self.inputs.len()));
        }

        if input_index >= self.unsigned_tx.input.len() {
            return Err(SignError::IndexOutOfBounds(input_index, self.unsigned_tx.input.len()));
        }

        Ok(())
    }

    /// Returns the algorithm used to sign this PSBT's input at `input_index`.
    fn signing_algorithm(&self, input_index: usize) -> Result<SigningAlgorithm, SignError> {
        // Dash only supports ECDSA signing
        self.check_index_is_within_bounds(input_index)?;
        Ok(SigningAlgorithm::Ecdsa)
    }

    /// Returns the [`OutputType`] of the spend utxo for this PBST's input at `input_index`.
    fn output_type(&self, input_index: usize) -> Result<OutputType, SignError> {
        let utxo = self.spend_utxo(input_index)?;
        let spk = utxo.script_pubkey.clone();

        // Check for P2SH first
        if spk.is_p2sh() {
            return Ok(OutputType::Sh);
        }

        // Everything else (P2PK, P2PKH) is Bare
        Ok(OutputType::Bare)
    }

    /// Calculates transaction fee.
    ///
    /// 'Fee' being the amount that will be paid for mining a transaction with the current inputs
    /// and outputs i.e., the difference in value of the total inputs and the total outputs.
    ///
    /// ## Errors
    ///
    /// - [`Error::MissingUtxo`] when UTXO information for any input is not present or is invalid.
    /// - [`Error::NegativeFee`] if calculated value is negative.
    /// - [`Error::FeeOverflow`] if an integer overflow occurs.
    pub fn fee(&self) -> Result<Amount, Error> {
        let mut inputs: u64 = 0;
        for utxo in self.iter_funding_utxos() {
            inputs = inputs.checked_add(utxo?.value).ok_or(Error::FeeOverflow)?;
        }
        let mut outputs: u64 = 0;
        for out in &self.unsigned_tx.output {
            outputs = outputs.checked_add(out.value).ok_or(Error::FeeOverflow)?;
        }
        inputs.checked_sub(outputs).map(Amount::from_sat).ok_or(Error::NegativeFee)
    }
}

/// Data required to call [`GetKey`] to get the private key to sign an input.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyRequest {
    /// Request a private key using the associated public key.
    Pubkey(PublicKey),
    /// Request a private key using BIP-32 fingerprint and derivation path.
    Bip32(KeySource),
}

/// Trait to get a private key from a key request, key is then used to sign an input.
pub trait GetKey {
    /// An error occurred while getting the key.
    type Error: fmt::Debug;

    /// Attempts to get the private key for `key_request`.
    ///
    /// # Returns
    /// - `Some(key)` if the key is found.
    /// - `None` if the key was not found but no error was encountered.
    /// - `Err` if an error was encountered while looking for the key.
    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error>;
}

impl GetKey for ExtendedPrivKey {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(_) => Err(GetKeyError::NotSupported),
            KeyRequest::Bip32((fingerprint, path)) => {
                let key = if self.fingerprint(secp) == fingerprint {
                    let k = self.derive_priv(secp, &path)?;
                    Some(PrivateKey {
                        compressed: true,
                        network: k.network,
                        inner: k.private_key,
                    })
                } else {
                    None
                };
                Ok(key)
            }
        }
    }
}

/// Map of input index -> pubkey associated with secret key used to create signature for that input.
pub type SigningKeys = BTreeMap<usize, Vec<PublicKey>>;

/// Map of input index -> the error encountered while attempting to sign that input.
pub type SigningErrors = BTreeMap<usize, SignError>;

#[rustfmt::skip]
macro_rules! impl_get_key_for_set {
    ($set:ident) => {

impl GetKey for $set<ExtendedPrivKey> {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        secp: &Secp256k1<C>
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(_) => Err(GetKeyError::NotSupported),
            KeyRequest::Bip32((fingerprint, path)) => {
                for xpriv in self.iter() {
                    if xpriv.parent_fingerprint == fingerprint {
                        let k = xpriv.derive_priv(secp, &path)?;
                        return Ok(Some(PrivateKey {
                            compressed: true,
                            network: k.network.into(),
                            inner: k.private_key,
                        }));
                    }
                }
                Ok(None)
            }
        }
    }
}}}
impl_get_key_for_set!(BTreeSet);
#[cfg(feature = "std")]
impl_get_key_for_set!(HashSet);

#[rustfmt::skip]
macro_rules! impl_get_key_for_map {
    ($map:ident) => {

impl GetKey for $map<PublicKey, PrivateKey> {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        _: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(pk) => Ok(self.get(&pk).cloned()),
            KeyRequest::Bip32(_) => Err(GetKeyError::NotSupported),
        }
    }
}}}
impl_get_key_for_map!(BTreeMap);
#[cfg(feature = "std")]
impl_get_key_for_map!(HashMap);

/// Errors when getting a key.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum GetKeyError {
    /// A bip32 error.
    Bip32(bip32::Error),
    /// The GetKey operation is not supported for this key request.
    NotSupported,
}

impl fmt::Display for GetKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use GetKeyError::*;

        match *self {
            Bip32(ref e) => write_err!(f, "a bip23 error"; e),
            NotSupported => {
                f.write_str("the GetKey operation is not supported for this key request")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GetKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use GetKeyError::*;

        match *self {
            NotSupported => None,
            Bip32(ref e) => Some(e),
        }
    }
}

impl From<bip32::Error> for GetKeyError {
    fn from(e: bip32::Error) -> Self {
        GetKeyError::Bip32(e)
    }
}

/// The various output types supported by the Dash network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum OutputType {
    /// An output of type: pay-to-pubkey or pay-to-pubkey-hash.
    Bare,
    /// A pay-to-script-hash output (P2SH).
    Sh,
}

impl OutputType {
    /// The signing algorithm used to sign this output type.
    pub fn signing_algorithm(&self) -> SigningAlgorithm {
        // Dash only supports ECDSA
        SigningAlgorithm::Ecdsa
    }
}

/// Signing algorithms supported by the Dash network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigningAlgorithm {
    /// The Elliptic Curve Digital Signature Algorithm (see [wikipedia]).
    ///
    /// [wikipedia]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    Ecdsa,
}

/// Errors encountered while calculating the sighash message.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub enum SignError {
    /// Input index out of bounds (actual index, maximum index allowed).
    IndexOutOfBounds(usize, usize),
    /// Invalid Sighash type.
    InvalidSighashType,
    /// Missing input utxo.
    MissingInputUtxo,
    /// Missing Redeem script.
    MissingRedeemScript,
    /// Missing spending utxo.
    MissingSpendUtxo,
    /// Signing algorithm and key type does not match.
    MismatchedAlgoKey,
    /// Attempted to ECDSA sign an non-ECDSA input.
    NotEcdsa,
    /// Sighash computation error.
    SighashComputation(sighash::Error),
    /// Unable to determine the output type.
    UnknownOutputType,
    /// Unable to find key.
    KeyNotFound,
    /// Attempt to sign an input with the wrong signing algorithm.
    WrongSigningAlgorithm,
    /// Signing request currently unsupported.
    Unsupported,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::SignError::*;

        match *self {
            IndexOutOfBounds(ind, len) => {
                write!(f, "index {}, psbt input len: {}", ind, len)
            }
            InvalidSighashType => write!(f, "invalid sighash type"),
            MissingInputUtxo => write!(f, "missing input utxo in PBST"),
            MissingRedeemScript => write!(f, "missing redeem script"),
            MissingSpendUtxo => write!(f, "missing spend utxo in PSBT"),
            MismatchedAlgoKey => write!(f, "signing algorithm and key type does not match"),
            NotEcdsa => write!(f, "attempted to ECDSA sign an non-ECDSA input"),
            SighashComputation(e) => write!(f, "sighash: {}", e),
            UnknownOutputType => write!(f, "unable to determine the output type"),
            KeyNotFound => write!(f, "unable to find key"),
            WrongSigningAlgorithm => {
                write!(f, "attempt to sign an input with the wrong signing algorithm")
            }
            Unsupported => write!(f, "signing request currently unsupported"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::SignError::*;

        match *self {
            IndexOutOfBounds(_, _)
            | InvalidSighashType
            | MissingInputUtxo
            | MissingRedeemScript
            | MissingSpendUtxo
            | MismatchedAlgoKey
            | NotEcdsa
            | UnknownOutputType
            | KeyNotFound
            | WrongSigningAlgorithm
            | Unsupported => None,
            SighashComputation(ref e) => Some(e),
        }
    }
}

impl From<sighash::Error> for SignError {
    fn from(e: sighash::Error) -> Self {
        SignError::SighashComputation(e)
    }
}

#[cfg(feature = "base64")]
mod display_from_str {
    use core::fmt::{self, Display, Formatter};
    use core::str::FromStr;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use internals::write_err;

    use super::{Error, PartiallySignedTransaction};

    /// Error encountered during PSBT decoding from Base64 string.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum PsbtParseError {
        /// Error in internal PSBT data structure.
        PsbtEncoding(Error),
        /// Error in PSBT Base64 encoding.
        Base64Encoding(base64::DecodeError),
    }

    impl Display for PsbtParseError {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            use self::PsbtParseError::*;

            match *self {
                PsbtEncoding(ref e) => write_err!(f, "error in internal PSBT data structure"; e),
                Base64Encoding(ref e) => write_err!(f, "error in PSBT base64 encoding"; e),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for PsbtParseError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            use self::PsbtParseError::*;

            match self {
                PsbtEncoding(e) => Some(e),
                Base64Encoding(e) => Some(e),
            }
        }
    }

    impl Display for PartiallySignedTransaction {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{}", STANDARD.encode(self.serialize()))
        }
    }

    impl FromStr for PartiallySignedTransaction {
        type Err = PsbtParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let data = STANDARD.decode(s).map_err(PsbtParseError::Base64Encoding)?;
            PartiallySignedTransaction::deserialize(&data).map_err(PsbtParseError::PsbtEncoding)
        }
    }
}

#[cfg(feature = "base64")]
pub use self::display_from_str::PsbtParseError;

#[cfg(test)]
mod tests {
    macro_rules! hex (($hex:expr) => (<Vec<u8> as dashcore_hashes::hex::FromHex>::from_hex($hex).unwrap()));

    use std::collections::BTreeMap;

    use dashcore_hashes::{hash160, ripemd160, sha256, Hash};
    use secp256k1::{self, Secp256k1};
    #[cfg(feature = "rand")]
    use secp256k1::{All, SecretKey};

    use super::*;
    use crate::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey, KeySource};
    use crate::psbt::map::{Input, Output};
    use crate::psbt::raw;
    use crate::psbt::serialize::{Deserialize, Serialize};
    use dashcore::blockdata::script::ScriptBuf;
    use dashcore::blockdata::transaction::outpoint::OutPoint;
    use dashcore::blockdata::transaction::txin::TxIn;
    use dashcore::blockdata::transaction::txout::TxOut;
    use dashcore::blockdata::transaction::Transaction;

    #[test]
    fn trivial_psbt() {
        let psbt = PartiallySignedTransaction {
            unsigned_tx: Transaction {
                version: 2,
                lock_time: 0,
                input: Vec::new(),
                output: Vec::new(),
                special_transaction_payload: None,
            },
            xpub: Default::default(),
            version: 0,
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),

            inputs: Vec::new(),
            outputs: Vec::new(),
        };
        assert_eq!(psbt.serialize_hex(), "70736274ff01000a0200000000000000000000");
    }

    #[test]
    fn psbt_uncompressed_key() {
        let psbt: PartiallySignedTransaction = hex_psbt!("70736274ff01003302000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff000000000000420204bb0d5d0cca36e7b9c80f63bc04c1240babb83bcd2803ef7ac8b6e2af594291daec281e856c98d210c5ab14dfd5828761f8ee7d5f45ca21ad3e4c4b41b747a3a047304402204f67e2afb76142d44fae58a2495d33a3419daa26cd0db8d04f3452b63289ac0f022010762a9fb67e94cc5cad9026f6dc99ff7f070f4278d30fbc7d0c869dd38c7fe70100").unwrap();

        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
        let pk = psbt.inputs[0].partial_sigs.iter().next().unwrap().0;
        assert!(!pk.compressed);
    }

    #[test]
    fn serialize_then_deserialize_output() {
        let secp = &Secp256k1::new();
        let seed = hex!("000102030405060708090a0b0c0d0e0f");

        let mut hd_keypaths: BTreeMap<secp256k1::PublicKey, KeySource> = Default::default();

        let mut sk: ExtendedPrivKey =
            ExtendedPrivKey::new_master(key_wallet::Network::Dash, &seed).unwrap();

        let fprint = sk.fingerprint(secp);

        let dpath: Vec<ChildNumber> = vec![
            ChildNumber::from_normal_idx(0).unwrap(),
            ChildNumber::from_normal_idx(1).unwrap(),
            ChildNumber::from_normal_idx(2).unwrap(),
            ChildNumber::from_normal_idx(4).unwrap(),
            ChildNumber::from_normal_idx(42).unwrap(),
            ChildNumber::from_hardened_idx(69).unwrap(),
            ChildNumber::from_normal_idx(420).unwrap(),
            ChildNumber::from_normal_idx(31337).unwrap(),
        ];

        sk = sk.derive_priv(secp, &dpath).unwrap();

        let pk = ExtendedPubKey::from_priv(secp, &sk);

        hd_keypaths.insert(pk.public_key, (fprint, dpath.into()));

        let expected: Output = Output {
            redeem_script: Some(
                ScriptBuf::from_hex("76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac").unwrap(),
            ),
            bip32_derivation: hd_keypaths,
            ..Default::default()
        };

        let actual = Output::deserialize(&expected.serialize()).unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn serialize_then_deserialize_global() {
        let expected = PartiallySignedTransaction {
            unsigned_tx: Transaction {
                version: 2,
                lock_time: 1257139,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126"
                            .parse()
                            .unwrap(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: u32::MAX,
                }],
                output: vec![
                    TxOut {
                        value: 99999699,
                        script_pubkey: ScriptBuf::from_hex(
                            "76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac",
                        )
                        .unwrap(),
                    },
                    TxOut {
                        value: 100000000,
                        script_pubkey: ScriptBuf::from_hex(
                            "a9143545e6e33b832c47050f24d3eeb93c9c03948bc787",
                        )
                        .unwrap(),
                    },
                ],
                special_transaction_payload: None,
            },
            xpub: Default::default(),
            version: 0,
            proprietary: Default::default(),
            unknown: Default::default(),
            inputs: vec![Input::default()],
            outputs: vec![Output::default(), Output::default()],
        };

        let actual: Psbt = Psbt::deserialize(&expected.serialize()).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn serialize_then_deserialize_psbtkvpair() {
        let expected = raw::Pair {
            key: raw::Key {
                type_value: 0u8,
                key: vec![42u8, 69u8],
            },
            value: vec![69u8, 42u8, 4u8],
        };

        let actual = raw::Pair::deserialize(&expected.serialize()).unwrap();

        assert_eq!(expected, actual);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_psbt() {
        //! Create a full PSBT value with various fields filled and make sure it can be JSONized.
        use dashcore_hashes::sha256d;

        use crate::psbt::map::Input;

        // create some values to use in the PSBT
        let tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389"
                        .parse()
                        .unwrap(),
                    vout: 1,
                },
                script_sig: ScriptBuf::from_hex("160014be18d152a9b012039daf3da7de4f53349eecb985")
                    .unwrap(),
                sequence: u32::MAX,
            }],
            output: vec![TxOut {
                value: 190303501938,
                script_pubkey: ScriptBuf::from_hex(
                    "a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587",
                )
                .unwrap(),
            }],
            special_transaction_payload: None,
        };
        let unknown: BTreeMap<raw::Key, Vec<u8>> = vec![(
            raw::Key {
                type_value: 1,
                key: vec![0, 1],
            },
            vec![3, 4, 5],
        )]
        .into_iter()
        .collect();
        let key_source = ("deadbeef".parse().unwrap(), "m/0'/1".parse().unwrap());
        let keypaths: BTreeMap<secp256k1::PublicKey, KeySource> = vec![(
            "0339880dc92394b7355e3d0439fa283c31de7590812ea011c4245c0674a685e883".parse().unwrap(),
            key_source.clone(),
        )]
        .into_iter()
        .collect();

        let proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>> = vec![(
            raw::ProprietaryKey {
                prefix: "prefx".as_bytes().to_vec(),
                subtype: 42,
                key: "test_key".as_bytes().to_vec(),
            },
            vec![5, 6, 7],
        )]
        .into_iter()
        .collect();

        let psbt = PartiallySignedTransaction {
            version: 0,
            xpub: {
                let xpub: ExtendedPubKey =
                    "xpub661MyMwAqRbcGoRVtwfvzZsq2VBJR1LAHfQstHUoxqDorV89vRoMxUZ27kLrraAj6MPi\
                    QfrDb27gigC1VS1dBXi5jGpxmMeBXEkKkcXUTg4".parse().unwrap();
                vec![(xpub, key_source)].into_iter().collect()
            },
            unsigned_tx: {
                let mut unsigned = tx.clone();
                unsigned.input[0].script_sig = ScriptBuf::new();
                unsigned
            },
            proprietary: proprietary.clone(),
            unknown: unknown.clone(),

            inputs: vec![
                Input {
                    utxo: Some(tx),
                    sighash_type: Some("SIGHASH_SINGLE|SIGHASH_ANYONECANPAY".parse::<PsbtSighashType>().unwrap()),
                    redeem_script: Some(vec![0x51].into()),
                    partial_sigs: vec![(
                        "0339880dc92394b7355e3d0439fa283c31de7590812ea011c4245c0674a685e883".parse().unwrap(),
                        "304402204f67e2afb76142d44fae58a2495d33a3419daa26cd0db8d04f3452b63289ac0f022010762a9fb67e94cc5cad9026f6dc99ff7f070f4278d30fbc7d0c869dd38c7fe701".parse().unwrap(),
                    )].into_iter().collect(),
                    bip32_derivation: keypaths.clone(),
                    ripemd160_preimages: vec![(ripemd160::Hash::hash(&[]), vec![1, 2])].into_iter().collect(),
                    sha256_preimages: vec![(sha256::Hash::hash(&[]), vec![1, 2])].into_iter().collect(),
                    hash160_preimages: vec![(hash160::Hash::hash(&[]), vec![1, 2])].into_iter().collect(),
                    hash256_preimages: vec![(sha256d::Hash::hash(&[]), vec![1, 2])].into_iter().collect(),
                    proprietary: proprietary.clone(),
                    unknown: unknown.clone(),
                    ..Default::default()
                }
            ],
            outputs: vec![
                Output {
                    bip32_derivation: keypaths,
                    proprietary,
                    unknown,
                    ..Default::default()
                }
            ],
        };
        let encoded = serde_json::to_string(&psbt).unwrap();
        let decoded: PartiallySignedTransaction = serde_json::from_str(&encoded).unwrap();
        assert_eq!(psbt, decoded);
    }

    mod bip_vectors {
        use std::collections::BTreeMap;
        #[cfg(feature = "base64")]
        use std::str::FromStr;

        use super::*;
        use crate::psbt::map::Map;
        use crate::psbt::{raw, PartiallySignedTransaction};
        use dashcore::blockdata::script::ScriptBuf;

        #[test]
        #[should_panic(expected = "InvalidMagic")]
        fn invalid_vector_1() {
            hex_psbt!("0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300").unwrap();
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "InvalidMagic")]
        fn invalid_vector_1_base64() {
            PartiallySignedTransaction::from_str("AgAAAAEmgXE3Ht/yhek3re6ks3t4AAwFZsuzrWRkFxPKQhcb9gAAAABqRzBEAiBwsiRRI+a/R01gxbUMBD1MaRpdJDXwmjSnZiqdwlF5CgIgATKcqdrPKAvfMHQOwDkEIkIsgctFg5RXrrdvwS7dlbMBIQJlfRGNM1e44PTCzUbbezn22cONmnCry5st5dyNv+TOMf7///8C09/1BQAAAAAZdqkU0MWZA8W6woaHYOkP1SGkZlqnZSCIrADh9QUAAAAAF6kUNUXm4zuDLEcFDyTT7rk8nAOUi8eHsy4TAA==").unwrap();
        }

        #[test]
        #[should_panic(expected = "ConsensusEncoding")]
        fn invalid_vector_2() {
            hex_psbt!("70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000")
                .unwrap();
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "ConsensusEncoding")]
        fn invalid_vector_2_base64() {
            use crate::psbt::PsbtParseError;
            PartiallySignedTransaction::from_str("cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAA==")
                // This weird thing is necessary since rustc 0.29 prints out I/O error in a different format than later versions
                .map_err(|err| match err {
                    PsbtParseError::PsbtEncoding(err) => err,
                    PsbtParseError::Base64Encoding(_) => panic!("PSBT Base64 decoding failed")
                })
                .unwrap();
        }

        #[test]
        #[should_panic(expected = "UnsignedTxHasScriptSigs")]
        fn invalid_vector_3() {
            hex_psbt!("70736274ff0100fd0a010200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be4000000006a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa88292feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000").unwrap();
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "UnsignedTxHasScriptSigs")]
        fn invalid_vector_3_base64() {
            PartiallySignedTransaction::from_str("cHNidP8BAP0KAQIAAAACqwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QAAAAAakcwRAIgR1lmF5fAGwNrJZKJSGhiGDR9iYZLcZ4ff89X0eURZYcCIFMJ6r9Wqk2Ikf/REf3xM286KdqGbX+EhtdVRs7tr5MZASEDXNxh/HupccC1AaZGoqg7ECy0OIEhfKaC3Ibi1z+ogpL+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAABASAA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHhwEEFgAUhdE1N/LiZUBaNNuvqePdoB+4IwgAAAA=").unwrap();
        }

        #[test]
        #[should_panic(expected = "MustHaveUnsignedTx")]
        fn invalid_vector_4() {
            hex_psbt!("70736274ff000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000").unwrap();
        }

        #[cfg(feature = "base64")]
        #[test]
        #[should_panic(expected = "MustHaveUnsignedTx")]
        fn invalid_vector_4_base64() {
            PartiallySignedTransaction::from_str("cHNidP8AAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAA==").unwrap();
        }

        #[test]
        fn valid_vector_2() {
            let psbt: PartiallySignedTransaction = hex_psbt!("70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000").unwrap();

            assert_eq!(psbt.inputs.len(), 2);
            assert_eq!(psbt.outputs.len(), 2);

            assert!(&psbt.inputs[0].final_script_sig.is_some());

            let redeem_script = psbt.inputs[1].redeem_script.as_ref().unwrap();
            let expected_out =
                ScriptBuf::from_hex("a9143545e6e33b832c47050f24d3eeb93c9c03948bc787").unwrap();

            assert_eq!(redeem_script.to_p2sh(), expected_out);

            for output in psbt.outputs {
                assert_eq!(output.get_pairs().len(), 0)
            }
        }

        #[test]
        fn valid_vector_4() {
            let psbt: PartiallySignedTransaction = hex_psbt!("70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac00000000000100df0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e13000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb8230800220202ead596687ca806043edc3de116cdf29d5e9257c196cd055cf698c8d02bf24e9910b4a6ba670000008000000080020000800022020394f62be9df19952c5587768aeb7698061ad2c4a25c894f47d8c162b4d7213d0510b4a6ba6700000080010000800200008000").unwrap();

            assert_eq!(psbt.inputs.len(), 2);
            assert_eq!(psbt.outputs.len(), 2);

            assert!(&psbt.inputs[0].final_script_sig.is_none());
            assert!(&psbt.inputs[1].final_script_sig.is_none());

            let redeem_script = psbt.inputs[1].redeem_script.as_ref().unwrap();
            let expected_out =
                ScriptBuf::from_hex("a9143545e6e33b832c47050f24d3eeb93c9c03948bc787").unwrap();

            assert_eq!(redeem_script.to_p2sh(), expected_out);

            for output in psbt.outputs {
                assert!(!output.get_pairs().is_empty())
            }
        }

        #[test]
        fn valid_vector_5() {
            let psbt: PartiallySignedTransaction = hex_psbt!("70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000000010120955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a010104220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681010547522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220603b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220603de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba670000008000000080050000800000").unwrap();

            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 1);

            assert!(&psbt.inputs[0].final_script_sig.is_none());

            let redeem_script = psbt.inputs[0].redeem_script.as_ref().unwrap();
            let expected_out =
                ScriptBuf::from_hex("a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87").unwrap();

            assert_eq!(redeem_script.to_p2sh(), expected_out);
        }

        #[test]
        fn valid_vector_6() {
            let psbt: PartiallySignedTransaction = hex_psbt!("70736274ff01003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a010000000000000a0f0102030405060708090f0102030405060708090a0b0c0d0e0f0000").unwrap();

            assert_eq!(psbt.inputs.len(), 1);
            assert_eq!(psbt.outputs.len(), 1);

            let tx = &psbt.unsigned_tx;
            assert_eq!(
                tx.txid(),
                "75c5c9665a570569ad77dd1279e6fd4628a093c4dcbf8d41532614044c14c115".parse().unwrap(),
            );

            let mut unknown: BTreeMap<raw::Key, Vec<u8>> = BTreeMap::new();
            let key: raw::Key = raw::Key {
                type_value: 0x0fu8,
                key: hex!("010203040506070809"),
            };
            let value: Vec<u8> = hex!("0102030405060708090a0b0c0d0e0f");

            unknown.insert(key, value);

            assert_eq!(psbt.inputs[0].unknown, unknown)
        }
    }

    #[test]
    fn serialize_and_deserialize_preimage_psbt() {
        // create a sha preimage map
        let mut sha256_preimages = BTreeMap::new();
        sha256_preimages.insert(sha256::Hash::hash(&[1u8, 2u8]), vec![1u8, 2u8]);
        sha256_preimages.insert(sha256::Hash::hash(&[1u8]), vec![1u8]);

        // same for hash160
        let mut hash160_preimages = BTreeMap::new();
        hash160_preimages.insert(hash160::Hash::hash(&[1u8, 2u8]), vec![1u8, 2u8]);
        hash160_preimages.insert(hash160::Hash::hash(&[1u8]), vec![1u8]);

        // same vector as valid_vector_1 from BIPs with added
        let mut unserialized = PartiallySignedTransaction {
            unsigned_tx: Transaction {
                version: 2,
                lock_time: 1257139,
                input: vec![
                    TxIn {
                        previous_output: OutPoint {
                            txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126".parse().unwrap(),
                            vout: 0,
                        },
                        script_sig: ScriptBuf::new(),
                        sequence: 0,
                    }
                ],
                output: vec![
                    TxOut {
                        value: 99999699,
                        script_pubkey: ScriptBuf::from_hex("76a914d0c59903c5bac2868760e90fd521a4665aa7652088ac").unwrap(),
                    },
                    TxOut {
                        value: 100000000,
                        script_pubkey: ScriptBuf::from_hex("a9143545e6e33b832c47050f24d3eeb93c9c03948bc787").unwrap(),
                    },
                ],
                special_transaction_payload: None,
            },
            version: 0,
            xpub: Default::default(),
            proprietary: Default::default(),
            unknown: BTreeMap::new(),

            inputs: vec![
                Input {
                    utxo: Some(Transaction {
                        version: 1,
                        lock_time: 0,
                        input: vec![
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389".parse().unwrap(),
                                    vout: 1,
                                },
                                script_sig: ScriptBuf::from_hex("160014be18d152a9b012039daf3da7de4f53349eecb985").unwrap(),
                                sequence: u32::MAX,
                            },
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "b490486aec3ae671012dddb2bb08466bef37720a533a894814ff1da743aaf886".parse().unwrap(),
                                    vout: 1,
                                },
                                script_sig: ScriptBuf::from_hex("160014fe3e9ef1a745e974d902c4355943abcb34bd5353").unwrap(),
                                sequence: u32::MAX,
                            },
                        ],
                        output: vec![
                            TxOut {
                                value: 200000000,
                                script_pubkey: ScriptBuf::from_hex("76a91485cff1097fd9e008bb34af709c62197b38978a4888ac").unwrap(),
                            },
                            TxOut {
                                value: 190303501938,
                                script_pubkey: ScriptBuf::from_hex("a914339725ba21efd62ac753a9bcd067d6c7a6a39d0587").unwrap(),
                            },
                        ],
                        special_transaction_payload: None,
                    }),
                    ..Default::default()
                },
            ],
            outputs: vec![
                Output {
                    ..Default::default()
                },
                Output {
                    ..Default::default()
                },
            ],
        };
        unserialized.inputs[0].hash160_preimages = hash160_preimages;
        unserialized.inputs[0].sha256_preimages = sha256_preimages;

        let rtt: PartiallySignedTransaction = hex_psbt!(&unserialized.serialize_hex()).unwrap();
        assert_eq!(rtt, unserialized);

        // Now add an ripemd160 with incorrect preimage
        let mut ripemd160_preimages = BTreeMap::new();
        ripemd160_preimages.insert(ripemd160::Hash::hash(&[17u8]), vec![18u8]);
        unserialized.inputs[0].ripemd160_preimages = ripemd160_preimages;

        // Now the roundtrip should fail as the preimage is incorrect.
        let rtt: Result<PartiallySignedTransaction, _> = hex_psbt!(&unserialized.serialize_hex());
        assert!(rtt.is_err());
    }

    #[test]
    fn serialize_and_deserialize_proprietary() {
        let mut psbt: PartiallySignedTransaction = hex_psbt!("70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac000000000001076a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa882920001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787010416001485d13537f2e265405a34dbafa9e3dda01fb82308000000").unwrap();
        psbt.proprietary.insert(
            raw::ProprietaryKey {
                prefix: b"test".to_vec(),
                subtype: 0u8,
                key: b"test".to_vec(),
            },
            b"test".to_vec(),
        );
        assert!(!psbt.proprietary.is_empty());
        let rtt: PartiallySignedTransaction = hex_psbt!(&psbt.serialize_hex()).unwrap();
        assert!(!rtt.proprietary.is_empty());
    }

    // PSBTs taken from BIP 174 test vectors.
    #[test]
    fn combine_psbts() {
        let mut psbt1 = hex_psbt!(include_str!("../../tests/data/psbt1.hex")).unwrap();
        let psbt2 = hex_psbt!(include_str!("../../tests/data/psbt2.hex")).unwrap();
        let psbt_combined = hex_psbt!(include_str!("../../tests/data/psbt2.hex")).unwrap();

        psbt1.combine(psbt2).expect("psbt combine to succeed");
        assert_eq!(psbt1, psbt_combined);
    }

    #[test]
    fn combine_psbts_commutative() {
        let mut psbt1 = hex_psbt!(include_str!("../../tests/data/psbt1.hex")).unwrap();
        let mut psbt2 = hex_psbt!(include_str!("../../tests/data/psbt2.hex")).unwrap();

        let psbt1_clone = psbt1.clone();
        let psbt2_clone = psbt2.clone();

        psbt1.combine(psbt2_clone).expect("psbt1 combine to succeed");
        psbt2.combine(psbt1_clone).expect("psbt2 combine to succeed");

        assert_eq!(psbt1, psbt2);
    }

    #[cfg(feature = "rand")]
    fn gen_keys() -> (PrivateKey, PublicKey, Secp256k1<All>) {
        use rand::{thread_rng, RngCore};

        let secp = Secp256k1::new();

        let mut rng = thread_rng();
        let mut secret_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_key_bytes);
        let sk =
            SecretKey::from_byte_array(&secret_key_bytes).expect("32 bytes, within curve order");
        let priv_key = PrivateKey::new(sk, crate::Network::Regtest);
        let pk = PublicKey::from_private_key(&secp, &priv_key);

        (priv_key, pk, secp)
    }

    #[test]
    #[cfg(feature = "rand")]
    fn get_key_btree_map() {
        let (priv_key, pk, secp) = gen_keys();

        let mut key_map = BTreeMap::new();
        key_map.insert(pk, priv_key);

        let got = key_map.get_key(KeyRequest::Pubkey(pk), &secp).expect("failed to get key");
        assert_eq!(got.unwrap(), priv_key)
    }

    #[test]
    fn test_fee() {
        let output_0_val = 99999699;
        let output_1_val = 100000000;
        let prev_output_val = 200000000;

        let mut t = PartiallySignedTransaction {
            unsigned_tx: Transaction {
                version: 2,
                lock_time: 1257139,
                input: vec![
                    TxIn {
                        previous_output: OutPoint {
                            txid: "f61b1742ca13176464adb3cb66050c00787bb3a4eead37e985f2df1e37718126".parse().unwrap(),
                            vout: 0,
                        },
                        sequence: 0,
                        ..Default::default()
                    }
                ],
                output: vec![
                    TxOut {
                        value: output_0_val,
                        ..Default::default()
                    },
                    TxOut {
                        value: output_1_val,
                        ..Default::default()
                    },
                ],
                special_transaction_payload: None,
            },
            xpub: Default::default(),
            version: 0,
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),

            inputs: vec![
                Input {
                    utxo: Some(Transaction {
                        version: 1,
                        lock_time: 0,
                        input: vec![
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389".parse().unwrap(),
                                    vout: 1,
                                },
                                sequence: u32::MAX,
                                ..Default::default()
                            },
                            TxIn {
                                previous_output: OutPoint {
                                    txid: "b490486aec3ae671012dddb2bb08466bef37720a533a894814ff1da743aaf886".parse().unwrap(),
                                    vout: 1,
                                },
                                sequence: u32::MAX,
                                ..Default::default()
                            },
                        ],
                        output: vec![
                            TxOut {
                                value: prev_output_val,
                                ..Default::default()
                            },
                            TxOut {
                                value: 190303501938,
                                ..Default::default()
                            },
                        ],
                        special_transaction_payload: None,
                    }),
                    ..Default::default()
                },
            ],
            outputs: vec![
                Output {
                    ..Default::default()
                },
                Output {
                    ..Default::default()
                },
            ],
        };
        assert_eq!(
            t.fee().expect("fee calculation"),
            Amount::from_sat(prev_output_val - (output_0_val + output_1_val))
        );
        // no previous output
        let mut t2 = t.clone();
        t2.inputs[0].utxo = None;
        match t2.fee().unwrap_err() {
            Error::MissingUtxo => {}
            e => panic!("unexpected error: {:?}", e),
        }
        //  negative fee
        let mut t3 = t.clone();
        t3.unsigned_tx.output[0].value = prev_output_val;
        match t3.fee().unwrap_err() {
            Error::NegativeFee => {}
            e => panic!("unexpected error: {:?}", e),
        }
        // overflow
        t.unsigned_tx.output[0].value = u64::MAX;
        t.unsigned_tx.output[1].value = u64::MAX;
        match t.fee().unwrap_err() {
            Error::FeeOverflow => {}
            e => panic!("unexpected error: {:?}", e),
        }
    }
}
