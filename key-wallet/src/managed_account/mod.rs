//! Managed account state and helpers
//!
//! This module groups the mutable account state used during wallet operation,
//! kept separate from the immutable [`Account`](crate::Account) structure.
//!
//! Two managed-account variants are exposed:
//!
//! - [`ManagedCoreFundsAccount`]: full state including balance, UTXO set and
//!   spent-outpoint tracking. Used for accounts that hold and spend funds
//!   (Standard, CoinJoin, DashPay).
//! - [`ManagedCoreKeysAccount`]: lightweight state without balance/UTXO/spent-outpoint
//!   tracking. Intended for accounts that primarily derive keys for special-purpose
//!   flows (identity registration, asset locks, masternode provider keys).

pub mod address_pool;
pub mod managed_account_collection;
pub mod managed_account_trait;
pub mod managed_account_type;
pub mod managed_core_funds_account;
pub mod managed_core_keys_account;
pub mod managed_platform_account;
pub mod platform_address;
pub mod transaction_record;

pub use managed_core_funds_account::ManagedCoreFundsAccount;
pub use managed_core_keys_account::ManagedCoreKeysAccount;
