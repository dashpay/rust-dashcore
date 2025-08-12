//! High-level wallet management for Dash
//!
//! This crate provides high-level wallet functionality that builds on top of
//! the low-level primitives in `key-wallet` and uses transaction types from
//! `dashcore`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod coin_selection;
pub mod fee;
pub mod transaction_builder;
pub mod utxo;
pub mod wallet_manager;

// Re-export key-wallet types
pub use key_wallet::{
    Account, AccountBalance, AccountType, Address, AddressType, ChildNumber, DerivationPath,
    ExtendedPrivKey, ExtendedPubKey, Mnemonic, Network, Wallet, WalletConfig,
};

// Re-export dashcore transaction types
pub use dashcore::blockdata::transaction::txin::TxIn;
pub use dashcore::blockdata::transaction::txout::TxOut;
pub use dashcore::blockdata::transaction::OutPoint;
pub use dashcore::blockdata::transaction::Transaction;

// Export our high-level types
pub use coin_selection::{CoinSelector, SelectionResult, SelectionStrategy};
pub use fee::{FeeEstimator, FeeRate};
pub use transaction_builder::TransactionBuilder;
pub use utxo::{Utxo, UtxoSet};
pub use wallet_manager::WalletManager;
