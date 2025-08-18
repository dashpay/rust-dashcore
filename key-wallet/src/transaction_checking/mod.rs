//! Transaction checking module
//!
//! This module provides functionality for checking if transactions belong to
//! wallet accounts, routing checks to appropriate account types based on
//! transaction types.

pub mod account_checker;
pub mod transaction_router;
pub mod wallet_checker;

pub use account_checker::AccountTransactionChecker;
pub use transaction_router::{TransactionRouter, TransactionType};
pub use wallet_checker::{TransactionContext, WalletTransactionChecker};
