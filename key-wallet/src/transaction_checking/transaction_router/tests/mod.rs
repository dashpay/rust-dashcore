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
#[cfg(test)]
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
