//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! Cryptographic primitives shared by rust-dashcore crates

#![doc(html_logo_url = "https://media.dash.org/wp-content/uploads/dash-d-logo.svg")]
#![doc(html_favicon_url = "https://media.dash.org/wp-content/uploads/dash-d-logo.svg")]

extern crate alloc;

pub use bitcoin_crypto::base58;
pub extern crate dash_pkc;
pub extern crate dashcore_hashes as hashes;
#[cfg(feature = "serde")]
pub extern crate serde;

pub mod bls;
pub mod ecdsa;
pub mod eddsa;
pub mod key;
pub mod sighash;

/// Taproot signatures.
pub mod taproot {
    pub use bitcoin_crypto::taproot::{
        ParseSignatureError, SerializedSignature, SigFromSliceError, Signature,
    };

    pub type Error = SigFromSliceError;
}
