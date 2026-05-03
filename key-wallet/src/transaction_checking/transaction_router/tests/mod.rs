//! Tests for the transaction router module
//!
//! This module contains comprehensive tests for transaction classification,
//! routing logic, and account type checking functionality.

#[cfg(test)]
mod helpers;

#[cfg(test)]
mod asset_unlock;
#[cfg(test)]
mod classification;
// `coinbase` exercises in-memory transaction storage; only built when the
// `keep_txs_in_memory` Cargo feature is enabled.
#[cfg(all(test, feature = "keep_txs_in_memory"))]
mod coinbase;
#[cfg(test)]
mod coinjoin;
#[cfg(test)]
mod conversions;
#[cfg(test)]
mod identity_transactions;
#[cfg(test)]
mod provider;
#[cfg(test)]
mod routing;
#[cfg(test)]
mod standard_transactions;
