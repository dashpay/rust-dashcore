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
    /// The chain height the spend scan is working toward — the tip of the
    /// filter-header chain the scanner has committed to covering.
    ///
    /// `synced_height` is where the scan has reached; this is where it is
    /// going. While `synced_height < scan_target_height` the wallet is
    /// catching up and cannot know whether a freshly discovered output has
    /// already been spent in a block it has not scanned yet, so receives
    /// applied in that window are held back from coin selection. See
    /// [`crate::utxo::Utxo::spend_scanned`].
    ///
    /// `0` means "unknown": no scanner has reported a target, and the
    /// spend-scan gate stays open. A scanner must set this for the gate to
    /// have any effect.
    #[cfg_attr(feature = "serde", serde(default))]
    pub scan_target_height: CoreBlockHeight,
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
