//! Key Wallet Library
//!
//! This library provides key derivation and wallet functionality for Dash,
//! including BIP32 hierarchical deterministic wallets, BIP39 mnemonic support,
//! and Dash-specific derivation paths (DIP9).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(test)]
#[macro_use]
mod test_macros;

pub mod address;
pub mod bip32;
pub mod derivation;
pub mod dip9;
pub mod error;
pub mod mnemonic;
pub(crate) mod utils;

pub use address::{Address, AddressType, NetworkExt};
pub use bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
pub use dash_network::Network;
pub use derivation::KeyDerivation;
pub use dip9::{DerivationPathReference, DerivationPathType};
pub use error::{Error, Result};
pub use mnemonic::Mnemonic;

/// Re-export commonly used types
pub mod prelude {
    pub use super::{
        Address, AddressType, ChildNumber, DerivationPath, Error, ExtendedPrivKey, ExtendedPubKey,
        KeyDerivation, Mnemonic, Result,
    };
}
