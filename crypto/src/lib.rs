//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! Cryptographic primitives shared by rust-dashcore crates

#![doc(html_logo_url = "https://media.dash.org/wp-content/uploads/dash-d-logo.svg")]
#![doc(html_favicon_url = "https://media.dash.org/wp-content/uploads/dash-d-logo.svg")]

extern crate alloc;

pub extern crate base58ck as base58;
#[cfg(feature = "bls")]
pub extern crate dash_pkc;
pub extern crate dashcore_hashes as hashes;
pub extern crate secp256k1;
#[cfg(feature = "serde")]
pub extern crate serde;

#[cfg(feature = "serde")]
#[macro_use]
pub(crate) mod serde_utils;

pub mod bls;
pub mod ecdsa;
pub mod eddsa;
pub mod key;
pub mod sighash;
pub mod taproot;

/// Implements `std::error::Error` for a type whose `Display` carries the message.
macro_rules! impl_std_error {
    ($type:ty) => {
        impl std::error::Error for $type {}
    };
    ($type:ty, $field:ident) => {
        impl std::error::Error for $type {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.$field)
            }
        }
    };
}
pub(crate) use impl_std_error;
