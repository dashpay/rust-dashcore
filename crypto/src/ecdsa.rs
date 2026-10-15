//
// This file is a part of rust-dashcore.
// Portions written by Andrew Poelstra <apoelstra@wpsoftware.net> for rust-bitcoin.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! ECDSA Bitcoin signatures.
//!
//! This module provides ECDSA signatures used Bitcoin that can be roundtrip (de)serialized.

#[cfg(feature = "rand")]
use bitcoin_crypto::key::rand;
#[cfg(feature = "rand")]
use bitcoin_crypto::secp256k1::SecretKey;

pub use bitcoin_crypto::ecdsa::{DecodeError, ParseSignatureError, SerializedSignature, Signature};

/// Draws a random secret key from the thread RNG.
#[cfg(feature = "rand")]
pub fn generate() -> SecretKey {
    SecretKey::new(&mut rand::rng())
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;

    // A DER signature with `SIGHASH_ALL` appended.
    const SIG_HEX: &str = "3045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c01";

    /// Formatting flags apply to the whole encoding, as for a string.
    #[test]
    fn display_applies_format_flags() {
        let sig = Signature::from_str(SIG_HEX).unwrap();
        assert_eq!(format!("{}", sig), SIG_HEX);
        assert_eq!(format!("{:#}", sig), format!("0x{}", SIG_HEX));
        assert_eq!(format!("{:>200}", sig), format!("{:>200}", SIG_HEX));
        assert_eq!(format!("{:.4}", sig), SIG_HEX[..4]);

        let serialized = sig.serialize();
        assert_eq!(format!("{:x}", serialized), SIG_HEX);
        assert_eq!(format!("{:#x}", serialized), format!("0x{}", SIG_HEX));
        assert_eq!(format!("{:X}", serialized), SIG_HEX.to_uppercase());
    }
}
