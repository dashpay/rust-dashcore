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

#[cfg(test)]
mod wallet_comprehensive_tests;
#[cfg(test)]
mod mnemonic_tests;
#[cfg(test)]
mod address_metadata_tests;

pub mod account;
pub mod address;
pub mod address_pool;
pub mod bip32;
#[cfg(feature = "bip38")]
pub mod bip38;
pub mod derivation;
pub mod dip9;
pub mod error;
pub mod gap_limit;
pub mod mnemonic;
pub(crate) mod utils;
pub mod wallet;
pub mod watch_only;

pub use account::{Account, AccountBalance, AccountType, SpecialPurposeType};
pub use address::{Address, AddressType, NetworkExt};
pub use address_pool::{AddressInfo, AddressPool, KeySource, PoolStats};
pub use bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
#[cfg(feature = "bip38")]
pub use bip38::{Bip38EncryptedKey, Bip38Mode, encrypt_private_key, generate_intermediate_code};
pub use dash_network::Network;
pub use derivation::{KeyDerivation, DerivationPathBuilder, DerivationStrategy};
pub use dip9::{DerivationPathReference, DerivationPathType};
pub use error::{Error, Result};
pub use gap_limit::{GapLimit, GapLimitManager, GapLimitStage};
pub use mnemonic::Mnemonic;
pub use wallet::{Wallet, WalletBalance, WalletConfig};
pub use watch_only::{WatchOnlyWallet, WatchOnlyWalletBuilder, ScanResult};

/// Re-export commonly used types
pub mod prelude {
    pub use super::{
        Address, AddressType, ChildNumber, DerivationPath, Error, ExtendedPrivKey, ExtendedPubKey,
        KeyDerivation, Mnemonic, Result,
    };
}
