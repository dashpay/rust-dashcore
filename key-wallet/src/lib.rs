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

pub use address::{Address, AddressType, Network};
pub use bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
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

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn test_basic_functionality() {
        // Basic test to ensure the library compiles
        assert!(true);
    }
}
