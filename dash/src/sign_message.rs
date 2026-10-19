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

//! Signature
//!
//! This module provides the Dash signed message format over
//! [`EcdsaRecSignature`], including public key recovery.
//!

#[cfg(feature = "base64")]
use base64::Engine as _;
#[cfg(feature = "base64")]
use base64::engine::general_purpose::STANDARD as BASE64;
use hashes::{Hash, HashEngine, sha256d};

use crate::address::{Address, AddressType, Payload};
use crate::consensus::{Encodable, encode};
use crate::crypto::ecdsa::{EcdsaError, EcdsaPublicKey, EcdsaRecSignature};
use crate::crypto::key::PublicKey;
#[cfg(feature = "base64")]
use crate::prelude::*;

/// The prefix for signed messages using Dash's message signing protocol.
pub const DASH_SIGNED_MSG_PREFIX: &[u8] = b"\x19DarkCoin Signed Message:\n";

/// An error used for dealing with Bitcoin Signed Messages.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MessageSignatureError {
    /// Signature is expected to be 65 bytes.
    #[error("length not 65 bytes")]
    InvalidLength,
    /// The signature is invalidly constructed.
    #[error("invalid encoding")]
    InvalidEncoding(#[from] EcdsaError),
    /// Invalid base64 encoding.
    #[error("invalid base64")]
    InvalidBase64,
    /// Unsupported Address Type
    #[error("unsupported address type: {0}")]
    UnsupportedAddressType(AddressType),
}

/// Parses a signature from its 65-byte compact encoding.
pub fn from_slice(bytes: &[u8]) -> Result<EcdsaRecSignature, MessageSignatureError> {
    EcdsaRecSignature::try_from(bytes).map_err(|_| MessageSignatureError::InvalidLength)
}

/// Parses a signature from the base64 of its compact encoding.
#[cfg(feature = "base64")]
pub fn from_base64(s: &str) -> Result<EcdsaRecSignature, MessageSignatureError> {
    from_slice(&BASE64.decode(s).map_err(|_| MessageSignatureError::InvalidBase64)?)
}

/// Encodes a signature as the base64 of its compact encoding.
#[cfg(feature = "base64")]
pub fn to_base64(signature: EcdsaRecSignature) -> String {
    BASE64.encode(signature.as_bytes())
}

/// Recovers the signing key from a signature over `msg_hash`.
///
/// To get the message hash from a message, use [signed_msg_hash].
pub fn recover_pubkey(
    signature: &EcdsaRecSignature,
    msg_hash: sha256d::Hash,
) -> Result<PublicKey, MessageSignatureError> {
    Ok(PublicKey {
        inner: EcdsaPublicKey::recover(msg_hash.as_byte_array(), signature)?,
        compressed: signature.is_compressed()?,
    })
}

/// Checks that a signature over `msg_hash` was made by `address`.
///
/// To get the message hash from a message, use [signed_msg_hash].
pub fn is_signed_by_address(
    signature: &EcdsaRecSignature,
    address: &Address,
    msg_hash: sha256d::Hash,
) -> Result<bool, MessageSignatureError> {
    match address.address_type() {
        Some(AddressType::P2pkh) => {
            let pubkey = recover_pubkey(signature, msg_hash)?;
            Ok(*address.payload() == Payload::p2pkh(&pubkey))
        }
        Some(address_type) => Err(MessageSignatureError::UnsupportedAddressType(address_type)),
        None => Ok(false),
    }
}

/// Hash message for signature using Bitcoin's message signing format.
pub fn signed_msg_hash(msg: &str) -> sha256d::Hash {
    let mut engine = sha256d::Hash::engine();
    engine.input(DASH_SIGNED_MSG_PREFIX);
    let msg_len = encode::VarInt(msg.len() as u64);
    msg_len.consensus_encode(&mut engine).expect("engines don't error");
    engine.input(msg.as_bytes());
    sha256d::Hash::from_engine(engine)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_msg_hash() {
        let hash = signed_msg_hash("test");
        assert_eq!(
            hash.to_string(),
            "9534c129a0eec7aaec6b6145d5014c2867d573f23a9827089ff09d5c357597dc"
        );
    }

    #[test]
    #[cfg(all(feature = "base64", feature = "rand-std"))]
    fn test_message_signature() {
        use crate::crypto::ecdsa::EcdsaSecretKey;
        use crate::{Address, AddressType, Network};

        let message = "rust-dash MessageSignature test";
        let msg_hash = signed_msg_hash(message);

        let privkey = EcdsaSecretKey::generate();
        let signature = privkey.sign_recoverable(msg_hash.as_byte_array());
        assert_eq!(signature.is_compressed(), Ok(true));

        let signature2 = from_base64(&to_base64(signature)).unwrap();
        assert_eq!(signature2, signature);
        let pubkey = recover_pubkey(&signature2, msg_hash).unwrap();
        assert!(pubkey.compressed);
        assert_eq!(pubkey.inner, privkey.public_key());

        let p2pkh = Address::p2pkh(&pubkey, Network::Mainnet);
        assert_eq!(is_signed_by_address(&signature2, &p2pkh, msg_hash), Ok(true));
        let p2wpkh = Address::p2wpkh(&pubkey, Network::Mainnet).unwrap();
        assert_eq!(
            is_signed_by_address(&signature2, &p2wpkh, msg_hash),
            Err(MessageSignatureError::UnsupportedAddressType(AddressType::P2wpkh))
        );
        let p2shwpkh = Address::p2shwpkh(&pubkey, Network::Mainnet).unwrap();
        assert_eq!(
            is_signed_by_address(&signature2, &p2shwpkh, msg_hash),
            Err(MessageSignatureError::UnsupportedAddressType(AddressType::P2sh))
        );
    }

    #[test_case::test_matrix([26, 35])]
    fn test_message_signature_header_out_of_range(header: u8) {
        use crate::crypto::ecdsa::EcdsaError;

        let mut bytes = [0u8; 65];
        bytes[0] = header;
        let signature = from_slice(&bytes).expect("65 bytes");
        assert_eq!(
            recover_pubkey(&signature, signed_msg_hash("test")),
            Err(MessageSignatureError::InvalidEncoding(EcdsaError::InvalidRecoveryId))
        );
    }

    #[test]
    #[cfg(feature = "base64")]
    fn test_incorrect_message_signature() {
        use crate::crypto::key::PublicKey;
        use crate::{Address, Network};

        let message = "a different message from what was signed";
        let msg_hash = super::signed_msg_hash(message);

        // Signature of msg = "rust-dashcore MessageSignature test"
        // Signed with pk "UuOGDsfLPr4HIMKQX0ipjJeRaj1geCq3yPUF2COP5ME="
        let signature_base64 = "IAM2qX24tYx/bdBTIgVLhD8QEAjrPlJpmjB4nZHdRYGIBa4DmVulAcwjPnWe6Q5iEwXH6F0pUCJP/ZeHPWS1h1o=";
        let pubkey_base64 = "A1FTfMEntPpAty3qkEo0q2Dc1FEycI10a3jmwEFy+Qr6";
        let signature = from_base64(signature_base64).expect("message signature");

        let pubkey = PublicKey::from_slice(&BASE64.decode(pubkey_base64).expect("base64 string"))
            .expect("pubkey slice");

        let p2pkh = Address::p2pkh(&pubkey, Network::Mainnet);
        assert_eq!(is_signed_by_address(&signature, &p2pkh, msg_hash), Ok(false));
    }
}
