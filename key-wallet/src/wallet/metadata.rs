//! Wallet metadata types and functionality
//!
//! This module contains the metadata structures for wallets.

use std::collections::BTreeMap;

use dashcore::ephemerealdata::chain_lock::ChainLock;
use dashcore::prelude::CoreBlockHeight;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Wallet metadata
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WalletMetadata {
    /// Birth height (when wallet was created/restored) - 0 (genesis) if unknown
    pub birth_height: CoreBlockHeight,
    /// Last processed block height
    pub last_processed_height: CoreBlockHeight,
    /// Sync checkpoint height
    pub synced_height: CoreBlockHeight,
    /// Highest chainlock that has been applied to this wallet,
    /// establishing the finality boundary: every block at or below
    /// `chain_lock.block_height` is final for this wallet. `None` until
    /// the first chainlock arrives. Persisted so consumers (e.g.
    /// Platform) with external transaction persistence can reason about
    /// which transactions have already been finalized, and retain the
    /// signing proof.
    pub last_applied_chain_lock: Option<ChainLock>,
    /// Last sync timestamp
    pub last_synced: Option<u64>,
    /// Wallet version
    pub version: u32,
    /// Custom metadata fields
    pub custom: BTreeMap<String, String>,
}
