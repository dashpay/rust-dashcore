//! Atomic changeset types for wallet state mutations.
//!
//! Every wallet mutation produces a [`WalletChangeSet`] capturing what changed.
//! Changesets are composable via the [`Merge`] trait — multiple deltas can be
//! batched before being applied or persisted.
//!
//! This module is about **atomicity and consistency**, not persistence.
//! Persistence is a separate layer that consumes changesets.
//!
//! Changesets carry the wallet's **native types** (`Utxo`, `TransactionRecord`,
//! etc.) directly rather than flattened persistence-friendly representations.
//! Persistence backends translate from native types to their own schema.

#[allow(clippy::module_inception)]
mod changeset;
mod merge;

pub use changeset::{
    AccountChangeSet, AccountKeyChangeSet, BalanceChangeSet, ChainChangeSet, WalletChangeSet,
};
pub use merge::Merge;
