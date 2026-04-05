//! Atomic changeset types for wallet state mutations.
//!
//! Every wallet mutation produces a [`WalletChangeSet`] capturing what changed.
//! ChangeSets are composable via the [`Merge`] trait — multiple deltas can be
//! batched before being applied or persisted.
//!
//! This module is about **atomicity and consistency**, not persistence.
//! Persistence is a separate layer that consumes changesets.

mod changeset;
mod merge;

pub use changeset::{
    AccountChangeSet, BalanceChangeSet, ChainChangeSet, TransactionChangeSet, TransactionEntry,
    UtxoChangeSet, UtxoEntry, WalletChangeSet,
};
pub use merge::Merge;
