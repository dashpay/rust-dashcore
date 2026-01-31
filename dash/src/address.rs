// Rust Dash Library
// Originally written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//     For Dash
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

//! Dash addresses.
//!
//! Support for ordinary base58 Dash addresses and private keys.
//!
//! # Example: creating a new address from a randomly-generated key pair
//!
//! ```rust
//! # #[cfg(feature = "rand-std")] {
//! use dashcore::{Address, PublicKey, Network};
//! use dashcore::secp256k1::{rand, Secp256k1};
//!
//! // Generate random key pair.
//! let s = Secp256k1::new();
//! let public_key = PublicKey::new(s.generate_keypair(&mut rand::thread_rng()).1);
//!
//! // Generate pay-to-pubkey-hash address.
//! let address = Address::p2pkh(&public_key, Network::Dash);
//! # }
//! ```
//!
//! # Note: creating a new address requires the rand-std feature flag
//!
//! ```toml
//! dashcore = { version = "...", features = ["rand-std"] }
//! ```

use core::convert::TryInto;
use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;

use crate::base58;
use crate::blockdata::constants::{
    MAX_SCRIPT_ELEMENT_SIZE, PUBKEY_ADDRESS_PREFIX_MAIN, PUBKEY_ADDRESS_PREFIX_TEST,
    SCRIPT_ADDRESS_PREFIX_MAIN, SCRIPT_ADDRESS_PREFIX_TEST,
};
use crate::blockdata::script::{Script, ScriptBuf};
use crate::crypto::key::PublicKey;
use crate::hash_types::{PubkeyHash, ScriptHash};
use crate::prelude::*;
use bech32;
use dash_network::Network;
use hashes::Hash;
use internals::write_err;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Address error.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Error {
    /// Base58 encoding error.
    Base58(base58::Error),
    /// Bech32 encoding error.
    Bech32(bech32::Error),
    /// The bech32 payload was empty.
    EmptyBech32Payload,
    /// The wrong checksum algorithm was used.
    InvalidBech32Variant {
        /// Expected Bech32 variant.
        expected: bech32::Variant,
        /// The actual Bech32 variant encoded in the address representation.
        found: bech32::Variant,
    },
    /// An uncompressed pubkey was used where it is not allowed.
    UncompressedPubkey,
    /// Address size more than 520 bytes is not allowed.
    ExcessiveScriptSize,
    /// Script is not a p2pkh or p2sh.
    UnrecognizedScript,
    /// Address type is either invalid or not supported in rust-dashcore.
    UnknownAddressType(String),
    /// Address's network differs from required one.
    NetworkValidation {
        /// Network that was required.
        required: Network,
        /// Network on which the address was found to be valid.
        found: Network,
        /// The address itself
        address: Address<NetworkUnchecked>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Base58(ref e) => write_err!(f, "base58 address encoding error"; e),
            Error::Bech32(ref e) => write_err!(f, "bech32 address encoding error"; e),
            Error::EmptyBech32Payload => write!(f, "the bech32 payload was empty"),
            Error::InvalidBech32Variant {
                expected,
                found,
            } => write!(
                f,
                "invalid bech32 checksum variant found {:?} when {:?} was expected",
                found, expected
            ),
            Error::UncompressedPubkey => {
                write!(f, "an uncompressed pubkey was used where it is not allowed")
            }
            Error::ExcessiveScriptSize => write!(f, "script size exceed 520 bytes"),
            Error::UnrecognizedScript => write!(f, "script is not a p2pkh or p2sh"),
            Error::UnknownAddressType(ref s) => write!(
                f,
                "unknown address type: '{}' is either invalid or not supported in rust-dash",
                s
            ),
            Error::NetworkValidation {
                required,
                found,
                ref address,
            } => {
                write!(f, "address ")?;
                address.fmt_internal(f)?; // Using fmt_internal in order to remove the "Address<NetworkUnchecked>(..)" wrapper
                write!(
                    f,
                    " belongs to network {} which is different from required {}",
                    found, required
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            Base58(e) => Some(e),
            Bech32(e) => Some(e),
            EmptyBech32Payload
            | InvalidBech32Variant {
                ..
            }
            | UncompressedPubkey
            | ExcessiveScriptSize
            | UnrecognizedScript
            | UnknownAddressType(_)
            | NetworkValidation {
                ..
            } => None,
        }
    }
}

#[doc(hidden)]
impl From<base58::Error> for Error {
    fn from(e: base58::Error) -> Error {
        Error::Base58(e)
    }
}

#[doc(hidden)]
impl From<bech32::Error> for Error {
    fn from(e: bech32::Error) -> Error {
        Error::Bech32(e)
    }
}

/// The different types of addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum AddressType {
    /// Pay to pubkey hash.
    P2pkh,
    /// Pay to script hash.
    P2sh,
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            AddressType::P2pkh => "p2pkh",
            AddressType::P2sh => "p2sh",
        })
    }
}

impl FromStr for AddressType {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "p2pkh" => Ok(AddressType::P2pkh),
            "p2sh" => Ok(AddressType::P2sh),
            _ => Err(Error::UnknownAddressType(s.to_owned())),
        }
    }
}

/// The method used to produce an address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Payload {
    /// P2PKH address.
    PubkeyHash(PubkeyHash),
    /// P2SH address.
    ScriptHash(ScriptHash),
}

impl Payload {
    pub fn as_pubkey_hash(&self) -> Option<&PubkeyHash> {
        match self {
            Payload::PubkeyHash(pubkey_hash) => Some(pubkey_hash),
            _ => None,
        }
    }
}
impl Payload {
    /// Constructs a [Payload] from an output script (`scriptPubkey`).
    pub fn from_script(script: &Script) -> Result<Payload, Error> {
        Ok(if script.is_p2pkh() {
            let bytes = script.as_bytes()[3..23].try_into().expect("statically 20B long");
            Payload::PubkeyHash(PubkeyHash::from_byte_array(bytes))
        } else if script.is_p2sh() {
            let bytes = script.as_bytes()[2..22].try_into().expect("statically 20B long");
            Payload::ScriptHash(ScriptHash::from_byte_array(bytes))
        } else {
            return Err(Error::UnrecognizedScript);
        })
    }

    /// Generates a script pubkey spending to this [Payload].
    pub fn script_pubkey(&self) -> ScriptBuf {
        match *self {
            Payload::PubkeyHash(ref hash) => ScriptBuf::new_p2pkh(hash),
            Payload::ScriptHash(ref hash) => ScriptBuf::new_p2sh(hash),
        }
    }

    /// Returns true if the address creates a particular script
    /// This function doesn't make any allocations.
    pub fn matches_script_pubkey(&self, script: &Script) -> bool {
        match *self {
            Payload::PubkeyHash(ref hash) if script.is_p2pkh() => {
                &script.as_bytes()[3..23] == <PubkeyHash as AsRef<[u8; 20]>>::as_ref(hash)
            }
            Payload::ScriptHash(ref hash) if script.is_p2sh() => {
                &script.as_bytes()[2..22] == <ScriptHash as AsRef<[u8; 20]>>::as_ref(hash)
            }
            Payload::PubkeyHash(_) | Payload::ScriptHash(_) => false,
        }
    }

    /// Creates a pay to (compressed) public key hash payload from a public key
    #[inline]
    pub fn p2pkh(pk: &PublicKey) -> Payload {
        Payload::PubkeyHash(pk.pubkey_hash())
    }

    /// Creates a pay to script hash P2SH payload from a script
    #[inline]
    pub fn p2sh(script: &Script) -> Result<Payload, Error> {
        if script.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(Error::ExcessiveScriptSize);
        }
        Ok(Payload::ScriptHash(script.script_hash()))
    }

    /// Returns a byte slice of the inner program of the payload. If the payload
    /// is a script hash or pubkey hash, a reference to the hash is returned.
    fn inner_prog_as_bytes(&self) -> &[u8] {
        match self {
            Payload::ScriptHash(hash) => hash.as_ref(),
            Payload::PubkeyHash(hash) => hash.as_ref(),
        }
    }
}

/// A utility struct to encode an address payload with the given parameters.
/// This is a low-level utility struct. Consider using `Address` instead.
pub struct AddressEncoding<'a> {
    /// The address payload to encode.
    pub payload: &'a Payload,
    /// base58 version byte for p2pkh payloads (e.g. 0x00 for "1..." addresses).
    pub p2pkh_prefix: u8,
    /// base58 version byte for p2sh payloads (e.g. 0x05 for "3..." addresses).
    pub p2sh_prefix: u8,
    /// hrp used in bech32 address (e.g. "bc" for "bc1..." addresses).
    pub bech32_hrp: &'a str,
}

/// Formats bech32 as upper case if alternate formatting is chosen (`{:#}`).
impl<'a> fmt::Display for AddressEncoding<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self.payload {
            Payload::PubkeyHash(hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = self.p2pkh_prefix;
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            Payload::ScriptHash(hash) => {
                let mut prefixed = [0; 21];
                prefixed[0] = self.p2sh_prefix;
                prefixed[1..].copy_from_slice(&hash[..]);
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
        }
    }
}

mod sealed {
    pub trait NetworkValidation {}
    impl NetworkValidation for super::NetworkChecked {}
    impl NetworkValidation for super::NetworkUnchecked {}
}

/// Marker of status of address's network validation. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
pub trait NetworkValidation: sealed::NetworkValidation {
    /// Indicates whether this `NetworkValidation` is `NetworkChecked` or not.
    const IS_CHECKED: bool;
}

/// Marker that address's network has been successfully validated. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkChecked {}

/// Marker that address's network has not yet been validated. See section [*Parsing addresses*](Address#parsing-addresses)
/// on [`Address`] for details.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkUnchecked {}

impl NetworkValidation for NetworkChecked {
    const IS_CHECKED: bool = true;
}
impl NetworkValidation for NetworkUnchecked {
    const IS_CHECKED: bool = false;
}

/// The inner representation of an address, without the network validation tag.
///
/// An `Address` is composed of a payload and a network. This struct represents the inner
/// representation of an address without the network validation tag, which is used to ensure that
/// addresses are used only on the appropriate network.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct AddressInner {
    payload: Payload,
    network: Network,
}

/// A Dash address.
///
/// ### Parsing addresses
///
/// When parsing string as an address, one has to pay attention to the network, on which the parsed
/// address is supposed to be valid. For the purpose of this validation, `Address` has
/// [`is_valid_for_network`](Address<NetworkUnchecked>::is_valid_for_network) method. In order to provide more safety,
/// enforced by compiler, `Address` also contains a special marker type, which indicates whether network of the parsed
/// address has been checked. This marker type will prevent from calling certain functions unless the network
/// verification has been successfully completed.
///
/// The result of parsing an address is `Address<NetworkUnchecked>` suggesting that network of the parsed address
/// has not yet been verified. To perform this verification, method [`require_network`](Address<NetworkUnchecked>::require_network)
/// can be called, providing network on which the address is supposed to be valid. If the verification succeeds,
/// `Address<NetworkChecked>` is returned.
///
/// The types `Address` and `Address<NetworkChecked>` are synonymous, i. e. they can be used interchangeably.
///
/// ```rust
/// use std::str::FromStr;
/// use dashcore::{Address, Network};
/// use dashcore::address::{NetworkUnchecked, NetworkChecked};
///
/// // variant 1
/// let address: Address<NetworkUnchecked> = "XxMZ412shTuxDKUBdNfxMeLr4KhtfJjRv5".parse().unwrap();
/// let address: Address<NetworkChecked> = address.require_network(Network::Dash).unwrap();
///
/// // variant 2
/// let address: Address = Address::from_str("XxMZ412shTuxDKUBdNfxMeLr4KhtfJjRv5").unwrap()
///                .require_network(Network::Dash).unwrap();
///
/// // variant 3
/// let address: Address<NetworkChecked> = "XxMZ412shTuxDKUBdNfxMeLr4KhtfJjRv5".parse::<Address<_>>()
///                .unwrap().require_network(Network::Dash).unwrap();
/// ```
///
/// ### Formatting addresses
///
/// To format address into its textual representation, both `Debug` (for usage in programmer-facing,
/// debugging context) and `Display` (for user-facing output) can be used, with the following caveats:
///
/// 1. `Display` is implemented only for `Address<NetworkChecked>`:
///
/// ```
/// # use std::str::FromStr;
/// # use dashcore::address::{Address, NetworkChecked};
/// let address: Address<NetworkChecked> = Address::from_str("XbPsX3CJbEaeNUXMpn29CNbQhTy6q6hf4A")
///                .unwrap().assume_checked();
/// assert_eq!(address.to_string(), "XbPsX3CJbEaeNUXMpn29CNbQhTy6q6hf4A");
/// ```
///
/// ```ignore
/// # use std::str::FromStr;
/// # use dashcore::address::{Address, NetworkChecked};
/// use dashcore::Address;
/// use dashcore::address::NetworkUnchecked;
/// let address: Address<NetworkUnchecked> = Address::from_str("XbPsX3CJbEaeNUXMpn29CNbQhTy6q6hf4A")
///                .unwrap();
/// let s = address.to_string(); // does not compile
/// ```
///
/// 2. `Debug` on `Address<NetworkUnchecked>` does not produce clean address but address wrapped by
///    an indicator that its network has not been checked. This is to encourage programmer to properly
///    check the network and use `Display` in user-facing context.
///
/// ```
/// # use std::str::FromStr;
/// # use dashcore::address::{Address, NetworkUnchecked};
/// let address: Address<NetworkUnchecked> = Address::from_str("XbPsX3CJbEaeNUXMpn29CNbQhTy6q6hf4A")
///                .unwrap();
/// assert_eq!(format!("{:?}", address), "Address<NetworkUnchecked>(XbPsX3CJbEaeNUXMpn29CNbQhTy6q6hf4A)");
/// ```
///
/// ```
/// # use std::str::FromStr;
/// # use dashcore::address::{Address, NetworkChecked};
/// let address: Address<NetworkChecked> = Address::from_str("XbPsX3CJbEaeNUXMpn29CNbQhTy6q6hf4A")
///                .unwrap().assume_checked();
/// assert_eq!(format!("{:?}", address), "XbPsX3CJbEaeNUXMpn29CNbQhTy6q6hf4A");
/// ```
///
/// ### Relevant BIPs
///
/// * [BIP13 - Address Format for pay-to-script-hash](https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki)
/// * [BIP16 - Pay to Script Hash](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki)
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
///
/// The `#[repr(transparent)]` attribute is used to guarantee that the layout of the
/// `Address` struct is the same as the layout of the `AddressInner` struct. This attribute is
/// an implementation detail and users should not rely on it in their code.
///
#[repr(transparent)]
pub struct Address<V = NetworkChecked>(AddressInner, PhantomData<V>)
where
    V: NetworkValidation;

#[cfg(feature = "serde")]
struct DisplayUnchecked<'a>(&'a Address<NetworkUnchecked>);

#[cfg(feature = "serde")]
impl fmt::Display for DisplayUnchecked<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt_internal(fmt)
    }
}

#[cfg(feature = "serde")]
crate::serde_utils::serde_string_serialize_impl!(Address, "a Dash address");

#[cfg(feature = "serde")]
crate::serde_utils::serde_string_deserialize_impl!(Address<NetworkUnchecked>, "a Dash address");

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Address<NetworkChecked> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::str::FromStr;
        use serde::de::Error;

        let s = String::deserialize(deserializer)?;
        let addr_unchecked = Address::<NetworkUnchecked>::from_str(&s).map_err(D::Error::custom)?;

        // For NetworkChecked, we need to assume a network. This is a limitation
        // of deserializing without network context. Users should use Address<NetworkUnchecked>
        // for serde when the network is not known at compile time.
        addr_unchecked.require_network(Network::Dash).map_err(D::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Address<NetworkUnchecked> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&DisplayUnchecked(self))
    }
}

#[cfg(feature = "bincode")]
impl bincode::Encode for Address {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.to_string().encode(encoder)
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for Address {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        use core::str::FromStr;
        let s = String::decode(decoder)?;
        Address::from_str(&s)
            .map_err(|e| bincode::error::DecodeError::OtherString(e.to_string()))
            .map(|a| a.assume_checked())
    }
}

#[cfg(feature = "bincode")]
impl<'de, C> bincode::BorrowDecode<'de, C> for Address {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        use core::str::FromStr;
        let s = String::borrow_decode(decoder)?;
        Address::from_str(&s)
            .map_err(|e| bincode::error::DecodeError::OtherString(e.to_string()))
            .map(|a| a.assume_checked())
    }
}

#[cfg(feature = "bincode")]
impl bincode::Encode for AddressType {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        (*self as u8).encode(encoder)
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for AddressType {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let val = u8::decode(decoder)?;
        match val {
            0 => Ok(AddressType::P2pkh),
            1 => Ok(AddressType::P2sh),
            _ => Err(bincode::error::DecodeError::OtherString("invalid address type".to_string())),
        }
    }
}

#[cfg(feature = "bincode")]
impl<'de, C> bincode::BorrowDecode<'de, C> for AddressType {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let val = u8::borrow_decode(decoder)?;
        match val {
            0 => Ok(AddressType::P2pkh),
            1 => Ok(AddressType::P2sh),
            _ => Err(bincode::error::DecodeError::OtherString("invalid address type".to_string())),
        }
    }
}

/// Methods on [`Address`] that can be called on both `Address<NetworkChecked>` and
/// `Address<NetworkUnchecked>`.
impl<V: NetworkValidation> Address<V> {
    /// Returns a reference to the payload of this address.
    pub fn payload(&self) -> &Payload {
        &self.0.payload
    }

    /// Returns a reference to the network of this address.
    pub fn network(&self) -> &Network {
        &self.0.network
    }

    /// Returns a reference to the unchecked address, which is dangerous to use if the address
    /// is invalid in the context of `NetworkUnchecked`.
    pub fn as_unchecked(&self) -> &Address<NetworkUnchecked> {
        unsafe { &*(self as *const Address<V> as *const Address<NetworkUnchecked>) }
    }

    /// Extracts and returns the network and payload components of the `Address`.
    pub fn into_parts(self) -> (Network, Payload) {
        let AddressInner {
            payload,
            network,
        } = self.0;
        (network, payload)
    }

    /// Gets the address type of the address.
    ///
    /// This method is publicly available as [`address_type`](Address<NetworkChecked>::address_type)
    /// on `Address<NetworkChecked>` but internally can be called on `Address<NetworkUnchecked>` as
    /// `address_type_internal`.
    ///
    /// # Returns
    /// None if unknown or non-standard.
    fn address_type_internal(&self) -> Option<AddressType> {
        match self.payload() {
            Payload::PubkeyHash(_) => Some(AddressType::P2pkh),
            Payload::ScriptHash(_) => Some(AddressType::P2sh),
        }
    }

    /// Format the address for the usage by `Debug` and `Display` implementations.
    fn fmt_internal(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let p2pkh_prefix = match self.network() {
            Network::Dash => PUBKEY_ADDRESS_PREFIX_MAIN,
            Network::Testnet | Network::Devnet | Network::Regtest => PUBKEY_ADDRESS_PREFIX_TEST,
            other => unreachable!("Unknown network {other:?} – add explicit prefix"),
        };
        let p2sh_prefix = match self.network() {
            Network::Dash => SCRIPT_ADDRESS_PREFIX_MAIN,
            Network::Testnet | Network::Devnet | Network::Regtest => SCRIPT_ADDRESS_PREFIX_TEST,
            other => unreachable!("Unknown network {other:?} – add explicit prefix"),
        };
        let bech32_hrp = match self.network() {
            Network::Dash => "ds",
            Network::Testnet | Network::Devnet => "tb",
            Network::Regtest => "dsrt",
            other => unreachable!("Unknown network {other:?} – add explicit prefix"),
        };
        let encoding = AddressEncoding {
            payload: self.payload(),
            p2pkh_prefix,
            p2sh_prefix,
            bech32_hrp,
        };

        use fmt::Display;

        encoding.fmt(fmt)
    }

    /// Create new address from given components, inferring the network validation
    /// marker type of the address.
    #[inline]
    pub fn new(network: Network, payload: Payload) -> Self {
        Self(
            AddressInner {
                network,
                payload,
            },
            PhantomData,
        )
    }
}

/// Methods and functions that can be called only on `Address<NetworkChecked>`.
impl Address {
    /// Creates a pay to (compressed) public key hash address from a public key.
    ///
    /// This is the standard address type for Dash.
    #[inline]
    pub fn p2pkh(pk: &PublicKey, network: Network) -> Address {
        Address::new(network, Payload::p2pkh(pk))
    }

    /// Creates a pay to script hash P2SH address from a script.
    ///
    /// This address type was introduced with BIP16 and is the popular type to implement multi-sig
    /// these days.
    #[inline]
    pub fn p2sh(script: &Script, network: Network) -> Result<Address, Error> {
        Ok(Address::new(network, Payload::p2sh(script)?))
    }

    /// Gets the address type of the address.
    ///
    /// # Returns
    /// None if unknown or non-standard.
    #[inline]
    pub fn address_type(&self) -> Option<AddressType> {
        self.address_type_internal()
    }

    /// Checks whether or not the address is following Dash standardness rules when
    /// *spending* from this address.
    ///
    /// <details>
    /// <summary>Spending Standardness</summary>
    ///
    /// For forward compatibility, the senders must send to any [`Address`]. Receivers
    /// can use this method to check whether or not they can spend from this address.
    /// </details>
    ///
    pub fn is_spend_standard(&self) -> bool {
        self.address_type().is_some()
    }

    /// Checks whether or not the address is following Dash standardness rules.
    #[deprecated(since = "0.30.0", note = "Use Address::is_spend_standard instead")]
    pub fn is_standard(&self) -> bool {
        self.address_type().is_some()
    }

    /// Constructs an [`Address`] from an output script (`scriptPubkey`).
    pub fn from_script(script: &ScriptBuf, network: Network) -> Result<Address, Error> {
        Ok(Address::new(network, Payload::from_script(script)?))
    }

    /// Generates a script pubkey spending to this address.
    pub fn script_pubkey(&self) -> ScriptBuf {
        self.payload().script_pubkey()
    }

    /// Creates a URI string *dashcore:address* optimized to be encoded in QR codes.
    ///
    /// If the address is bech32, both the schema and the address become uppercase.
    /// If the address is base58, the schema is lowercase and the address is left mixed case.
    ///
    /// Quoting BIP 173 "inside QR codes uppercase SHOULD be used, as those permit the use of
    /// alphanumeric mode, which is 45% more compact than the normal byte mode."
    ///
    /// Note however that despite BIP21 explicitly stating that the `dashcore:` prefix should be
    /// parsed as case-insensitive many wallets got this wrong and don't parse correctly.
    /// [See compatibility table.](https://github.com/btcpayserver/btcpayserver/issues/2110)
    ///
    /// If you want to avoid allocation you can use alternate display instead:
    /// ```
    /// # use core::fmt::Write;
    /// # const ADDRESS: &str = "Xxb77sLZJZMUeYdf3TpWNoRFgEvjQkoi2q";
    /// # let address = ADDRESS.parse::<dashcore::Address<_>>().unwrap().assume_checked();
    /// # let mut writer = String::new();
    /// # // magic trick to make error handling look better
    /// # (|| -> Result<(), core::fmt::Error> {
    ///
    /// write!(writer, "{:#}", address)?;
    ///
    /// # Ok(())
    /// # })().unwrap();
    /// # assert_eq!(writer, ADDRESS);
    /// ```
    pub fn to_qr_uri(&self) -> String {
        format!("dash:{:#}", self)
    }

    /// Returns true if the given pubkey is directly related to the address payload.
    ///
    /// This is determined by directly comparing the address payload with the
    /// hash of the given public key.
    pub fn is_related_to_pubkey(&self, pubkey: &PublicKey) -> bool {
        let pubkey_hash = pubkey.pubkey_hash();
        let payload = self.payload().inner_prog_as_bytes();
        *pubkey_hash.as_byte_array() == *payload
    }

    /// Returns true if the address creates a particular script
    /// This function doesn't make any allocations.
    pub fn matches_script_pubkey(&self, script_pubkey: &Script) -> bool {
        self.payload().matches_script_pubkey(script_pubkey)
    }
}

/// Methods that can be called only on `Address<NetworkUnchecked>`.
impl Address<NetworkUnchecked> {
    /// Returns a reference to the checked address.
    /// This function is dangerous in case the address is not a valid checked address.
    pub fn assume_checked_ref(&self) -> &Address {
        unsafe { &*(self as *const Address<NetworkUnchecked> as *const Address) }
    }
    /// Parsed addresses do not always have *one* network. The problem is that legacy testnet,
    /// regtest and devnet addresses use the same prefix instead of multiple different ones. When
    /// parsing, such addresses are always assumed to be testnet addresses (the same is true for
    /// bech32 devnet addresses). So if one wants to check if an address belongs to a certain
    /// network a simple comparison is not enough anymore. Instead this function can be used.
    ///
    /// ```rust
    /// use dashcore::{Address, Network};
    /// use dashcore::address::NetworkUnchecked;
    ///
    /// let address: Address<NetworkUnchecked> = "yiLAa2hfeevAiiDn2wf4rXCPC9Frf3TQcE".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Testnet));
    /// assert!(address.is_valid_for_network(Network::Regtest));
    /// assert!(address.is_valid_for_network(Network::Devnet));
    ///
    /// assert_eq!(address.is_valid_for_network(Network::Dash), false);
    ///
    /// let address: Address<NetworkUnchecked> = "Xs6U2uPMzn4zyfTtEkDgXMFGm39RP1F7mv".parse().unwrap();
    /// assert!(address.is_valid_for_network(Network::Dash));
    /// assert_eq!(address.is_valid_for_network(Network::Testnet), false);
    /// ```
    pub fn is_valid_for_network(&self, network: Network) -> bool {
        let is_legacy = matches!(
            self.address_type_internal(),
            Some(AddressType::P2pkh) | Some(AddressType::P2sh)
        );

        match (self.network(), network) {
            (a, b) if *a == b => true,
            (Network::Dash, _) | (_, Network::Dash) => false,
            (Network::Regtest, _) | (_, Network::Regtest) if !is_legacy => false,
            (Network::Testnet, _) | (Network::Regtest, _) | (Network::Devnet, _) => true,
            _ => false,
        }
    }

    /// Checks whether network of this address is as required.
    ///
    /// For details about this mechanism, see section [*Parsing addresses*](Address#parsing-addresses)
    /// on [`Address`].
    #[inline]
    pub fn require_network(self, required: Network) -> Result<Address, Error> {
        if self.is_valid_for_network(required) {
            Ok(self.assume_checked())
        } else {
            Err(Error::NetworkValidation {
                found: *self.network(),
                required,
                address: self,
            })
        }
    }

    /// Marks, without any additional checks, network of this address as checked.
    ///
    /// Improper use of this method may lead to loss of funds. Reader will most likely prefer
    /// [`require_network`](Address<NetworkUnchecked>::require_network) as a safe variant.
    /// For details about this mechanism, see section [*Parsing addresses*](Address#parsing-addresses)
    /// on [`Address`].
    #[inline]
    pub fn assume_checked(self) -> Address {
        let (network, payload) = self.into_parts();
        Address::new(network, payload)
    }

    /// Returns the payload as a vector.
    pub fn payload_to_vec(&self) -> Vec<u8> {
        self.0.payload.inner_prog_as_bytes().to_vec()
    }
}

// For NetworkUnchecked , it compare Addresses and if network and payload matches then return true.
impl PartialEq<Address<NetworkUnchecked>> for Address {
    fn eq(&self, other: &Address<NetworkUnchecked>) -> bool {
        self.network() == other.network() && self.payload() == other.payload()
    }
}

impl PartialEq<Address> for Address<NetworkUnchecked> {
    fn eq(&self, other: &Address) -> bool {
        other == self
    }
}

impl From<Address> for ScriptBuf {
    fn from(a: Address) -> Self {
        a.script_pubkey()
    }
}

// Alternate formatting `{:#}` is used to return uppercase version of bech32 addresses which should
// be used in QR codes, see [`Address::to_qr_uri`].
impl fmt::Display for Address {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_internal(fmt)
    }
}

impl<V: NetworkValidation> fmt::Debug for Address<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if V::IS_CHECKED {
            self.fmt_internal(f)
        } else {
            write!(f, "Address<NetworkUnchecked>(")?;
            self.fmt_internal(f)?;
            write!(f, ")")
        }
    }
}

/// Address can be parsed only with `NetworkUnchecked`.
impl FromStr for Address<NetworkUnchecked> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Address<NetworkUnchecked>, Error> {
        // Dash only supports base58 addresses (P2PKH and P2SH)
        if s.len() > 50 {
            return Err(Error::Base58(base58::Error::InvalidLength(s.len() * 11 / 15)));
        }
        let data = base58::decode_check(s)?;
        if data.len() != 21 {
            return Err(Error::Base58(base58::Error::InvalidLength(data.len())));
        }

        let (network, payload) = match data[0] {
            PUBKEY_ADDRESS_PREFIX_MAIN => {
                (Network::Dash, Payload::PubkeyHash(PubkeyHash::from_slice(&data[1..]).unwrap()))
            }
            SCRIPT_ADDRESS_PREFIX_MAIN => {
                (Network::Dash, Payload::ScriptHash(ScriptHash::from_slice(&data[1..]).unwrap()))
            }
            PUBKEY_ADDRESS_PREFIX_TEST => {
                (Network::Testnet, Payload::PubkeyHash(PubkeyHash::from_slice(&data[1..]).unwrap()))
            }
            SCRIPT_ADDRESS_PREFIX_TEST => {
                (Network::Testnet, Payload::ScriptHash(ScriptHash::from_slice(&data[1..]).unwrap()))
            }
            x => return Err(Error::Base58(base58::Error::InvalidAddressVersion(x))),
        };

        Ok(Address::new(network, payload))
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;
    use crate::crypto::key::PublicKey;
    use dash_network::Network::{Dash, Testnet};

    fn roundtrips(addr: &Address) {
        assert_eq!(
            Address::from_str(&addr.to_string()).unwrap().assume_checked(),
            *addr,
            "string round-trip failed for {}",
            addr,
        );
        assert_eq!(
            Address::from_script(&addr.script_pubkey(), *addr.network()).as_ref(),
            Ok(addr),
            "script round-trip failed for {}",
            addr,
        );

        #[cfg(feature = "serde")]
        {
            let ser = serde_json::to_string(addr).expect("failed to serialize address");
            let back: Address<NetworkUnchecked> =
                serde_json::from_str(&ser).expect("failed to deserialize address");
            assert_eq!(back.assume_checked(), *addr, "serde round-trip failed for {}", addr)
        }
    }

    #[test]
    fn test_p2pkh_address_58() {
        let addr = Address::new(
            Dash,
            Payload::PubkeyHash("162c5ea71c0b23f5b9022ef047c4a86470a5b070".parse().unwrap()),
        );

        assert_eq!(
            addr.script_pubkey(),
            ScriptBuf::from_hex("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac").unwrap()
        );
        assert_eq!(&addr.to_string(), "Xci5rLWMqdQDy5uaCDVWEcTi6sfnkmqdUz");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2pkh_from_key() {
        let key = "048d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b6042a0431ded2478b5c9cf2d81c124a5e57347a3c63ef0e7716cf54d613ba183".parse::<PublicKey>().unwrap();
        let addr = Address::p2pkh(&key, Dash);
        assert_eq!(&addr.to_string(), "XyzL4FHjYiiQk9uhm6yCM4ewbkboBggYyo");

        let key = "03df154ebfcf29d29cc10d5c2565018bce2d9edbab267c31d2caf44a63056cf99f"
            .parse::<PublicKey>()
            .unwrap();
        let addr = Address::p2pkh(&key, Testnet);
        assert_eq!(&addr.to_string(), "yWZBnVvSxS5xSq27dHVAJpuqbt7vvwGFL1");
        assert_eq!(addr.address_type(), Some(AddressType::P2pkh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2sh_address_58() {
        let addr = Address::new(
            Dash,
            Payload::ScriptHash("162c5ea71c0b23f5b9022ef047c4a86470a5b070".parse().unwrap()),
        );

        assert_eq!(
            addr.script_pubkey(),
            ScriptBuf::from_hex("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087").unwrap(),
        );
        assert_eq!(&addr.to_string(), "7URtmpd5Eobeu5YNj3WP968WLcDC86Kko6");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2sh_parse() {
        let script = ScriptBuf::from_hex("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae").unwrap();
        let addr = Address::p2sh(&script, Testnet).unwrap();
        assert_eq!(&addr.to_string(), "8qAmTPBdngNnZ1HoYDMjRWL4JYoF4Kdah4");
        assert_eq!(addr.address_type(), Some(AddressType::P2sh));
        roundtrips(&addr);
    }

    #[test]
    fn test_p2sh_parse_for_large_script() {
        let script = ScriptBuf::from_hex("552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123552103a765fc35b3f210b95223846b36ef62a4e53e34e2925270c2c7906b92c9f718eb2103c327511374246759ec8d0b89fa6c6b23b33e11f92c5bc155409d86de0c79180121038cae7406af1f12f4786d820a1466eec7bc5785a1b5e4a387eca6d797753ef6db2103252bfb9dcaab0cd00353f2ac328954d791270203d66c2be8b430f115f451b8a12103e79412d42372c55dd336f2eb6eb639ef9d74a22041ba79382c74da2338fe58ad21035049459a4ebc00e876a9eef02e72a3e70202d3d1f591fc0dd542f93f642021f82102016f682920d9723c61b27f562eb530c926c00106004798b6471e8c52c60ee02057ae12123122313123123ac1231231231231313123131231231231313212313213123123").unwrap();
        assert_eq!(Address::p2sh(&script, Testnet), Err(Error::ExcessiveScriptSize));
    }

    #[test]
    fn test_address_debug() {
        // This is not really testing output of Debug but the ability and proper functioning
        // of Debug derivation on structs generic in NetworkValidation.
        #[derive(Debug)]
        #[allow(unused)]
        struct Test<V: NetworkValidation> {
            address: Address<V>,
        }

        let addr_str = "7onv7GQcmoxJHdeDzTq2FGD9Q8Do9bxuFD";
        let unchecked = Address::from_str(addr_str).unwrap();

        assert_eq!(
            format!(
                "{:?}",
                Test {
                    address: unchecked.clone()
                }
            ),
            format!("Test {{ address: Address<NetworkUnchecked>({}) }}", addr_str)
        );

        assert_eq!(
            format!(
                "{:?}",
                Test {
                    address: unchecked.assume_checked()
                }
            ),
            format!("Test {{ address: {} }}", addr_str)
        );
    }

    #[test]
    fn test_address_type() {
        let addresses = [
            ("XmzfivrzYQ7B7oBMZKwPRdhjB1iNvX71XZ", Some(AddressType::P2pkh)),
            ("7onv7GQcmoxJHdeDzTq2FGD9Q8Do9bxuFD", Some(AddressType::P2sh)),
        ];
        for (address, expected_type) in &addresses {
            let addr = Address::from_str(address)
                .unwrap()
                .require_network(Network::Dash)
                .expect("mainnet");
            assert_eq!(&addr.address_type(), expected_type);
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    #[ignore = "TODO: adjust tests for dash addr"]
    fn test_json_serialize() {
        use serde_json;

        let addr =
            Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM").unwrap().assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".to_owned())
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac").unwrap()
        );

        let addr =
            Address::from_str("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k").unwrap().assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k".to_owned())
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087").unwrap()
        );

        let addr: Address<NetworkUnchecked> =
            Address::from_str("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
                .unwrap();
        let json = serde_json::to_value(addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String(
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7".to_owned()
            )
        );

        let addr =
            Address::from_str("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
                .unwrap()
                .assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String(
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7".to_owned()
            )
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex(
                "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
            )
            .unwrap()
        );

        let addr = Address::from_str("bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl")
            .unwrap()
            .assume_checked();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl".to_owned())
        );
        let into: Address = serde_json::from_value::<Address<_>>(json).unwrap().assume_checked();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            ScriptBuf::from_hex("001454d26dddb59c7073c6a197946ea1841951fa7a74").unwrap()
        );
    }

    #[test]
    fn test_qr_string() {
        for el in
            ["Xxb77sLZJZMUeYdf3TpWNoRFgEvjQkoi2q", "XanpivH7JqvtWsCkjB5vXqoGBhv4XGBRJn"].iter()
        {
            let addr = Address::from_str(el).unwrap().require_network(Dash).expect("mainnet");
            assert_eq!(addr.to_qr_uri(), format!("dash:{}", el));
        }

        // for el in ["dsrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl", "ds1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"].iter() {
        //     let addr = Address::from_str(el).unwrap().assume_checked();
        //     assert_eq!(addr.to_qr_uri(), format!("DASH:{}", el.to_ascii_uppercase()));
        // }
    }

    #[test]
    fn test_valid_networks() {
        let legacy_payload = &[
            Payload::PubkeyHash(PubkeyHash::all_zeros()),
            Payload::ScriptHash(ScriptHash::all_zeros()),
        ];

        const LEGACY_EQUIVALENCE_CLASSES: &[&[Network]] =
            &[&[Network::Dash], &[Network::Testnet, Network::Regtest, Network::Devnet]];

        fn test_addr_type(payloads: &[Payload], equivalence_classes: &[&[Network]]) {
            for pl in payloads {
                for addr_net in equivalence_classes.iter().flat_map(|ec| ec.iter()) {
                    for valid_net in equivalence_classes
                        .iter()
                        .filter(|ec| ec.contains(addr_net))
                        .flat_map(|ec| ec.iter())
                    {
                        let addr = Address::new(*addr_net, pl.clone());
                        assert!(addr.is_valid_for_network(*valid_net));
                    }

                    for invalid_net in equivalence_classes
                        .iter()
                        .filter(|ec| !ec.contains(addr_net))
                        .flat_map(|ec| ec.iter())
                    {
                        let addr = Address::new(*addr_net, pl.clone());
                        assert!(!addr.is_valid_for_network(*invalid_net));
                    }
                }
            }
        }

        test_addr_type(legacy_payload, LEGACY_EQUIVALENCE_CLASSES);
    }

    #[test]
    fn test_is_related_to_pubkey_p2pkh() {
        let address_string = "XgjvsEewx8SHii5SFYM856eU2qGrJuZ3AN";
        let address = Address::from_str(address_string)
            .expect("address")
            .require_network(Network::Dash)
            .expect("mainnet");

        let pubkey_string = "0370be7922711cf8e19923d40126d1fb1a7300d873019abd58c7984aeff44f8ce4";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_is_related_to_pubkey_p2pkh_uncompressed_key() {
        let address_string = "Xo6KeXZcaKyZCEMGioNYnsrPskpUZAZFhr";
        let address = Address::from_str(address_string)
            .expect("address")
            .require_network(Network::Dash)
            .expect("testnet");

        let pubkey_string = "04e96e22004e3db93530de27ccddfdf1463975d2138ac018fc3e7ba1a2e5e0aad8e424d0b55e2436eb1d0dcd5cb2b8bcc6d53412c22f358de57803a6a655fbbd04";
        let pubkey = PublicKey::from_str(pubkey_string).expect("pubkey");

        let result = address.is_related_to_pubkey(&pubkey);
        assert!(result);

        let unused_pubkey = PublicKey::from_str(
            "02ba604e6ad9d3864eda8dc41c62668514ef7d5417d3b6db46e45cc4533bff001c",
        )
        .expect("pubkey");
        assert!(!address.is_related_to_pubkey(&unused_pubkey))
    }

    #[test]
    fn test_fail_address_from_script() {
        // Test that unrecognized scripts fail
        let unrecognized_script =
            ScriptBuf::from_hex("001161458e330389cd0437ee9fe3641d70cc18").unwrap();
        let expected = Err(Error::UnrecognizedScript);

        assert_eq!(Address::from_script(&unrecognized_script, Network::Dash), expected);
    }

    #[test]
    fn valid_address_parses_correctly() {
        let addr = AddressType::from_str("p2pkh").expect("false negative while parsing address");
        assert_eq!(addr, AddressType::P2pkh);
    }

    #[test]
    fn invalid_address_parses_error() {
        let got = AddressType::from_str("invalid");
        let want = Err(Error::UnknownAddressType("invalid".to_string()));
        assert_eq!(got, want);
    }

    #[test]
    fn test_matches_script_pubkey() {
        let addresses = [
            "XgjvsEewx8SHii5SFYM856eU2qGrJuZ3AN", // P2PKH
            "7fH3aFXJ5TWv5eNScx7m4FCf3XD27mXYHq", // P2SH
        ];
        for addr in &addresses {
            let addr = Address::from_str(addr).unwrap().require_network(Network::Dash).unwrap();
            for another in &addresses {
                let another =
                    Address::from_str(another).unwrap().require_network(Network::Dash).unwrap();
                assert_eq!(addr.matches_script_pubkey(&another.script_pubkey()), addr == another);
            }
        }
    }
}
