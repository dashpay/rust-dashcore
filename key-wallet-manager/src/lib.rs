//! High-level wallet management for Dash
//!
//! This crate provides high-level wallet functionality that builds on top of
//! the low-level primitives in `key-wallet` and uses transaction types from
//! `dashcore`.
//!
//! ## Features
//!
//! - Multiple wallet management
//! - BIP 157/158 compact block filter support
//! - Transaction processing and matching
//! - UTXO tracking and management
//! - Address generation and gap limit handling
//! - Blockchain synchronization
//! - Transaction building and signing

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod wallet_interface;
pub mod wallet_manager;

// Re-export key-wallet types
pub use key_wallet::{
    Account, AccountType, Address, AddressType, ChildNumber, DerivationPath, ExtendedPrivKey,
    ExtendedPubKey, Mnemonic, Network, Utxo, UtxoSet, Wallet,
};

// Re-export dashcore transaction types
pub use dashcore::blockdata::transaction::Transaction;
pub use dashcore::{OutPoint, TxIn, TxOut};

// Export our high-level types
pub use key_wallet::wallet::managed_wallet_info::coin_selection::{
    CoinSelector, SelectionResult, SelectionStrategy,
};
pub use key_wallet::wallet::managed_wallet_info::fee::{FeeEstimator, FeeRate};
pub use key_wallet::wallet::managed_wallet_info::transaction_builder::TransactionBuilder;
pub use wallet_interface::BlockProcessingResult;
pub use wallet_manager::{WalletError, WalletManager};
