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

pub mod coin_selection;
pub mod compact_filter;
pub mod fee;
pub mod filter_client;
pub mod sync;
pub mod transaction_builder;
pub mod transaction_handler;
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
pub use compact_filter::{CompactFilter, FilterHeader, FilterType, GolombCodedSet};
pub use fee::{FeeEstimator, FeeRate};
pub use filter_client::{
    BlockFetcher, BlockProcessResult as FilterBlockResult, FetchError, FilterClient,
    FilterFetcher, FilterMatchResult, FilterSPVClient, SyncResult as FilterSyncResult,
    SyncStatus,
};
pub use sync::{BlockProcessResult, ReorgHandler, SyncManager, SyncState, WalletSynchronizer};
pub use transaction_builder::TransactionBuilder;
pub use transaction_handler::{
    AddressTracker, TransactionHandler, TransactionMatch, TransactionProcessResult,
};
pub use utxo::{Utxo, UtxoSet};
pub use wallet_manager::{WalletManager, WalletError};
