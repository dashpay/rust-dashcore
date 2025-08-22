//! Key Wallet Library
//!
//! This library provides key derivation and wallet functionality for Dash,
//! including BIP32 hierarchical deterministic wallets, BIP39 mnemonic support,
//! and Dash-specific derivation paths (DIP9).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

extern crate core;
#[cfg(feature = "std")]
extern crate std;

#[cfg(test)]
#[macro_use]
mod test_macros;

#[cfg(test)]
mod address_metadata_tests;
#[cfg(all(test, feature = "bip38"))]
mod bip38_tests;
#[cfg(test)]
mod mnemonic_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod wallet_comprehensive_tests;

pub mod account;
pub mod bip32;
#[cfg(feature = "bip38")]
pub mod bip38;
pub mod derivation;
#[cfg(feature = "bls")]
pub mod derivation_bls_bip32;
#[cfg(feature = "eddsa")]
pub mod derivation_slip10;
pub mod dip9;
pub mod error;
pub mod gap_limit;
pub mod mnemonic;
pub mod psbt;
pub mod seed;
pub mod transaction_checking;
pub(crate) mod utils;
pub mod utxo;
pub mod wallet;
pub mod watch_only;

pub use dashcore;

pub use account::address_pool::{AddressInfo, AddressPool, KeySource, PoolStats};
pub use account::{Account, AccountCollection, AccountType, ManagedAccountType};
pub use bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
#[cfg(feature = "bip38")]
pub use bip38::{encrypt_private_key, generate_intermediate_code, Bip38EncryptedKey, Bip38Mode};
pub use dash_network::Network;
pub use dashcore::{Address, AddressType};
pub use derivation::{DerivationPathBuilder, DerivationStrategy, KeyDerivation};
pub use dip9::{DerivationPathReference, DerivationPathType};
pub use error::{Error, Result};
pub use gap_limit::{GapLimit, GapLimitManager, GapLimitStage};
pub use mnemonic::Mnemonic;
pub use seed::Seed;
pub use utxo::{Utxo, UtxoSet};
pub use wallet::{
    balance::{BalanceError, WalletBalance},
    config::WalletConfig,
    Wallet,
};
pub use watch_only::{ScanResult, WatchOnlyWallet, WatchOnlyWalletBuilder};

/// Re-export commonly used types
pub mod prelude {
    pub use super::{
        Address, AddressType, ChildNumber, DerivationPath, Error, ExtendedPrivKey, ExtendedPubKey,
        KeyDerivation, Mnemonic, Result,
    };
    pub use dashcore::prelude::*;
}
