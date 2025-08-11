//! High-level wallet management for Dash
//!
//! This crate provides high-level wallet functionality that builds on top of
//! the low-level primitives in `key-wallet` and uses transaction types from
//! `dashcore`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod transaction_builder;
pub mod utxo;
pub mod wallet_manager;
pub mod fee;
pub mod coin_selection;

// Re-export key-wallet types
pub use key_wallet::{
    Account, AccountBalance, AccountType, Address, AddressType, 
    ExtendedPrivKey, ExtendedPubKey, Mnemonic, Network, Wallet, WalletConfig,
    DerivationPath, ChildNumber,
};

// Re-export dashcore transaction types  
pub use dashcore::blockdata::transaction::Transaction;
pub use dashcore::blockdata::transaction::txin::TxIn;
pub use dashcore::blockdata::transaction::txout::TxOut;
pub use dashcore::blockdata::transaction::OutPoint;

// Export our high-level types
pub use transaction_builder::TransactionBuilder;
pub use utxo::{Utxo, UtxoSet};
pub use wallet_manager::WalletManager;
pub use fee::{FeeRate, FeeEstimator};
pub use coin_selection::{CoinSelector, SelectionStrategy, SelectionResult};