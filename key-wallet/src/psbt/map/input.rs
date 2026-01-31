// SPDX-License-Identifier: CC0-1.0

use core::convert::TryFrom;
use core::fmt;
use core::str::FromStr;

use dashcore_hashes::{self as hashes, hash160, ripemd160, sha256, sha256d};

use crate::psbt::map::Map;
use crate::psbt::serialize::Deserialize;
use crate::psbt::{error, raw, Error};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::Transaction;
use dashcore::crypto::ecdsa;
use dashcore::crypto::key::PublicKey;
use dashcore::sighash::{EcdsaSighashType, NonStandardSighashType, SighashTypeParseError};
use std::collections::btree_map;

use crate::bip32::KeySource;
#[cfg(feature = "serde")]
use serde::{Deserialize as SerdeDeserialize, Serialize};

/// Type: Non-Witness UTXO PSBT_IN_NON_WITNESS_UTXO = 0x00
const PSBT_IN_NON_WITNESS_UTXO: u8 = 0x00;
/// Type: Partial Signature PSBT_IN_PARTIAL_SIG = 0x02
const PSBT_IN_PARTIAL_SIG: u8 = 0x02;
/// Type: Sighash Type PSBT_IN_SIGHASH_TYPE = 0x03
const PSBT_IN_SIGHASH_TYPE: u8 = 0x03;
/// Type: Redeem Script PSBT_IN_REDEEM_SCRIPT = 0x04
const PSBT_IN_REDEEM_SCRIPT: u8 = 0x04;
/// Type: BIP 32 Derivation Path PSBT_IN_BIP32_DERIVATION = 0x06
const PSBT_IN_BIP32_DERIVATION: u8 = 0x06;
/// Type: Finalized scriptSig PSBT_IN_FINAL_SCRIPTSIG = 0x07
const PSBT_IN_FINAL_SCRIPTSIG: u8 = 0x07;
/// Type: RIPEMD160 preimage PSBT_IN_RIPEMD160 = 0x0a
const PSBT_IN_RIPEMD160: u8 = 0x0a;
/// Type: SHA256 preimage PSBT_IN_SHA256 = 0x0b
const PSBT_IN_SHA256: u8 = 0x0b;
/// Type: HASH160 preimage PSBT_IN_HASH160 = 0x0c
const PSBT_IN_HASH160: u8 = 0x0c;
/// Type: HASH256 preimage PSBT_IN_HASH256 = 0x0d
const PSBT_IN_HASH256: u8 = 0x0d;
/// Type: Proprietary Use Type PSBT_IN_PROPRIETARY = 0xFC
const PSBT_IN_PROPRIETARY: u8 = 0xFC;

/// A key-value map for an input of the corresponding index in the unsigned
/// transaction.
#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, SerdeDeserialize))]
pub struct Input {
    /// The transaction this input spends from.
    pub utxo: Option<Transaction>,
    /// A map from public keys to their corresponding signature as would be
    /// pushed to the stack from a scriptSig.
    pub partial_sigs: BTreeMap<PublicKey, ecdsa::Signature>,
    /// The sighash type to be used for this input. Signatures for this input
    /// must use the sighash type.
    pub sighash_type: Option<PsbtSighashType>,
    /// The redeem script for this input.
    pub redeem_script: Option<ScriptBuf>,
    /// A map from public keys needed to sign this input to their corresponding
    /// master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "dashcore::serde_utils::btreemap_as_seq"))]
    pub bip32_derivation: BTreeMap<secp256k1::PublicKey, KeySource>,
    /// The finalized, fully-constructed scriptSig with signatures and any other
    /// scripts necessary for this input to pass validation.
    pub final_script_sig: Option<ScriptBuf>,
    /// RIPEMD160 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "dashcore::serde_utils::btreemap_byte_values"))]
    pub ripemd160_preimages: BTreeMap<ripemd160::Hash, Vec<u8>>,
    /// SHA256 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "dashcore::serde_utils::btreemap_byte_values"))]
    pub sha256_preimages: BTreeMap<sha256::Hash, Vec<u8>>,
    /// HASH160 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "dashcore::serde_utils::btreemap_byte_values"))]
    pub hash160_preimages: BTreeMap<hash160::Hash, Vec<u8>>,
    /// HASH256 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "dashcore::serde_utils::btreemap_byte_values"))]
    pub hash256_preimages: BTreeMap<sha256d::Hash, Vec<u8>>,
    /// Proprietary key-value pairs for this input.
    #[cfg_attr(
        feature = "serde",
        serde(with = "dashcore::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub proprietary: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs for this input.
    #[cfg_attr(
        feature = "serde",
        serde(with = "dashcore::serde_utils::btreemap_as_seq_byte_values")
    )]
    pub unknown: BTreeMap<raw::Key, Vec<u8>>,
}

/// A Signature hash type for the corresponding input.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, SerdeDeserialize))]
pub struct PsbtSighashType {
    pub(in crate::psbt) inner: u32,
}

impl fmt::Display for PsbtSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ecdsa_hash_ty() {
            Err(_) => write!(f, "{:#x}", self.inner),
            Ok(ecdsa_hash_ty) => fmt::Display::fmt(&ecdsa_hash_ty, f),
        }
    }
}

impl FromStr for PsbtSighashType {
    type Err = SighashTypeParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // We accept strings of form: "SIGHASH_ALL" etc.
        if let Ok(ty) = EcdsaSighashType::from_str(s) {
            return Ok(ty.into());
        }

        // We accept non-standard sighash values in hex format.
        if let Ok(inner) = u32::from_str_radix(s.trim_start_matches("0x"), 16) {
            return Ok(PsbtSighashType {
                inner,
            });
        }

        Err(SighashTypeParseError {
            unrecognized: s.to_owned(),
        })
    }
}

impl From<EcdsaSighashType> for PsbtSighashType {
    fn from(ecdsa_hash_ty: EcdsaSighashType) -> Self {
        PsbtSighashType {
            inner: ecdsa_hash_ty as u32,
        }
    }
}

impl PsbtSighashType {
    /// Returns the [`EcdsaSighashType`] if the [`PsbtSighashType`] can be
    /// converted to one.
    pub fn ecdsa_hash_ty(self) -> Result<EcdsaSighashType, NonStandardSighashType> {
        EcdsaSighashType::from_standard(self.inner)
    }

    /// Creates a [`PsbtSighashType`] from a raw `u32`.
    ///
    /// Allows construction of a non-standard or non-valid sighash flag.
    pub fn from_u32(n: u32) -> PsbtSighashType {
        PsbtSighashType {
            inner: n,
        }
    }

    /// Converts [`PsbtSighashType`] to a raw `u32` sighash flag.
    ///
    /// No guarantees are made as to the standardness or validity of the returned value.
    pub fn to_u32(self) -> u32 {
        self.inner
    }
}

impl Input {
    /// Obtains the [`EcdsaSighashType`] for this input if one is specified. If no sighash type is
    /// specified, returns [`EcdsaSighashType::All`].
    ///
    /// # Errors
    ///
    /// If the `sighash_type` field is set to a non-standard ECDSA sighash value.
    pub fn ecdsa_hash_ty(&self) -> Result<EcdsaSighashType, NonStandardSighashType> {
        self.sighash_type
            .map(|sighash_type| sighash_type.ecdsa_hash_ty())
            .unwrap_or(Ok(EcdsaSighashType::All))
    }

    pub(super) fn insert_pair(&mut self, pair: raw::Pair) -> Result<(), Error> {
        let raw::Pair {
            key: raw_key,
            value: raw_value,
        } = pair;

        match raw_key.type_value {
            PSBT_IN_NON_WITNESS_UTXO => {
                impl_psbt_insert_pair! {
                    self.utxo <= <raw_key: _>|<raw_value: Transaction>
                }
            }
            PSBT_IN_PARTIAL_SIG => {
                impl_psbt_insert_pair! {
                    self.partial_sigs <= <raw_key: PublicKey>|<raw_value: ecdsa::Signature>
                }
            }
            PSBT_IN_SIGHASH_TYPE => {
                impl_psbt_insert_pair! {
                    self.sighash_type <= <raw_key: _>|<raw_value: PsbtSighashType>
                }
            }
            PSBT_IN_REDEEM_SCRIPT => {
                impl_psbt_insert_pair! {
                    self.redeem_script <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            PSBT_IN_BIP32_DERIVATION => {
                impl_psbt_insert_pair! {
                    self.bip32_derivation <= <raw_key: secp256k1::PublicKey>|<raw_value: KeySource>
                }
            }
            PSBT_IN_FINAL_SCRIPTSIG => {
                impl_psbt_insert_pair! {
                    self.final_script_sig <= <raw_key: _>|<raw_value: ScriptBuf>
                }
            }
            PSBT_IN_RIPEMD160 => {
                psbt_insert_hash_pair(
                    &mut self.ripemd160_preimages,
                    raw_key,
                    raw_value,
                    error::PsbtHash::Ripemd,
                )?;
            }
            PSBT_IN_SHA256 => {
                psbt_insert_hash_pair(
                    &mut self.sha256_preimages,
                    raw_key,
                    raw_value,
                    error::PsbtHash::Sha256,
                )?;
            }
            PSBT_IN_HASH160 => {
                psbt_insert_hash_pair(
                    &mut self.hash160_preimages,
                    raw_key,
                    raw_value,
                    error::PsbtHash::Hash160,
                )?;
            }
            PSBT_IN_HASH256 => {
                psbt_insert_hash_pair(
                    &mut self.hash256_preimages,
                    raw_key,
                    raw_value,
                    error::PsbtHash::Hash256,
                )?;
            }
            PSBT_IN_PROPRIETARY => {
                let key = raw::ProprietaryKey::try_from(raw_key.clone())?;
                match self.proprietary.entry(key) {
                    btree_map::Entry::Vacant(empty_key) => {
                        empty_key.insert(raw_value);
                    }
                    btree_map::Entry::Occupied(_) => return Err(Error::DuplicateKey(raw_key)),
                }
            }
            _ => match self.unknown.entry(raw_key) {
                btree_map::Entry::Vacant(empty_key) => {
                    empty_key.insert(raw_value);
                }
                btree_map::Entry::Occupied(k) => return Err(Error::DuplicateKey(k.key().clone())),
            },
        }

        Ok(())
    }

    /// Combines this [`Input`] with `other` `Input` (as described by BIP 174).
    pub fn combine(&mut self, other: Self) {
        combine!(utxo, self, other);

        self.partial_sigs.extend(other.partial_sigs);
        self.bip32_derivation.extend(other.bip32_derivation);
        self.ripemd160_preimages.extend(other.ripemd160_preimages);
        self.sha256_preimages.extend(other.sha256_preimages);
        self.hash160_preimages.extend(other.hash160_preimages);
        self.hash256_preimages.extend(other.hash256_preimages);
        self.proprietary.extend(other.proprietary);
        self.unknown.extend(other.unknown);

        combine!(redeem_script, self, other);
        combine!(final_script_sig, self, other);
    }
}

impl Map for Input {
    fn get_pairs(&self) -> Vec<raw::Pair> {
        let mut rv: Vec<raw::Pair> = Default::default();

        impl_psbt_get_pair! {
            rv.push(self.utxo, PSBT_IN_NON_WITNESS_UTXO)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.partial_sigs, PSBT_IN_PARTIAL_SIG)
        }

        impl_psbt_get_pair! {
            rv.push(self.sighash_type, PSBT_IN_SIGHASH_TYPE)
        }

        impl_psbt_get_pair! {
            rv.push(self.redeem_script, PSBT_IN_REDEEM_SCRIPT)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.bip32_derivation, PSBT_IN_BIP32_DERIVATION)
        }

        impl_psbt_get_pair! {
            rv.push(self.final_script_sig, PSBT_IN_FINAL_SCRIPTSIG)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.ripemd160_preimages, PSBT_IN_RIPEMD160)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.sha256_preimages, PSBT_IN_SHA256)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.hash160_preimages, PSBT_IN_HASH160)
        }

        impl_psbt_get_pair! {
            rv.push_map(self.hash256_preimages, PSBT_IN_HASH256)
        }

        for (key, value) in self.proprietary.iter() {
            rv.push(raw::Pair {
                key: key.to_key(),
                value: value.clone(),
            });
        }

        for (key, value) in self.unknown.iter() {
            rv.push(raw::Pair {
                key: key.clone(),
                value: value.clone(),
            });
        }

        rv
    }
}

impl_psbtmap_ser_de_serialize!(Input);

fn psbt_insert_hash_pair<H>(
    map: &mut BTreeMap<H, Vec<u8>>,
    raw_key: raw::Key,
    raw_value: Vec<u8>,
    hash_type: error::PsbtHash,
) -> Result<(), Error>
where
    H: hashes::Hash + Deserialize,
{
    if raw_key.key.is_empty() {
        return Err(Error::InvalidKey(raw_key));
    }
    let key_val: H = Deserialize::deserialize(&raw_key.key)?;
    match map.entry(key_val) {
        btree_map::Entry::Vacant(empty_key) => {
            let val: Vec<u8> = Deserialize::deserialize(&raw_value)?;
            if <H as hashes::Hash>::hash(&val) != key_val {
                return Err(Error::InvalidPreimageHashPair {
                    preimage: val.into_boxed_slice(),
                    hash: Box::from(key_val.borrow()),
                    hash_type,
                });
            }
            empty_key.insert(val);
            Ok(())
        }
        btree_map::Entry::Occupied(_) => Err(Error::DuplicateKey(raw_key)),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn psbt_sighash_type_ecdsa() {
        for ecdsa in &[
            EcdsaSighashType::All,
            EcdsaSighashType::None,
            EcdsaSighashType::Single,
            EcdsaSighashType::AllPlusAnyoneCanPay,
            EcdsaSighashType::NonePlusAnyoneCanPay,
            EcdsaSighashType::SinglePlusAnyoneCanPay,
        ] {
            let sighash = PsbtSighashType::from(*ecdsa);
            let s = format!("{}", sighash);
            let back = PsbtSighashType::from_str(&s).unwrap();
            assert_eq!(back, sighash);
            assert_eq!(back.ecdsa_hash_ty().unwrap(), *ecdsa);
        }
    }

    #[test]
    fn psbt_sighash_type_not_std() {
        let nonstd = 0xdddddddd;
        let sighash = PsbtSighashType {
            inner: nonstd,
        };
        let s = format!("{}", sighash);
        let back = PsbtSighashType::from_str(&s).unwrap();

        assert_eq!(back, sighash);
        assert_eq!(back.ecdsa_hash_ty(), Err(NonStandardSighashType(nonstd)));
    }
}
