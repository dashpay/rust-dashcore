use crate::sync::ManagerIdentifier;
use dashcore::{Address, BlockHash, Txid};
use key_wallet_manager::wallet_manager::FilterMatchKey;
use std::collections::BTreeSet;

/// Events that managers can emit and subscribe to.
///
/// Each event represents a meaningful state change that other managers
/// may need to react to.
#[derive(Debug, Clone)]
pub enum SyncEvent {
    /// New block headers have been stored.
    ///
    /// Emitted by: `BlockHeadersManager`
    /// Consumed by: `MasternodesManager`, `FilterHeadersManager`
    SyncStart {
        /// Identifier of the manager that started to sync.
        identifier: ManagerIdentifier,
    },
    /// New block headers have been stored.
    ///
    /// Emitted by: `BlockHeadersManager`
    /// Consumed by: `MasternodesManager`, `FilterHeadersManager`
    BlockHeadersStored {
        /// New tip height after storage
        tip_height: u32,
    },

    /// Headers have reached the chain tip (initial sync complete).
    ///
    /// Emitted by: `BlockHeadersManager`
    /// Consumed by: `MasternodesManager` (to start masternode sync)
    BlockHeaderSyncComplete {
        /// Tip height when sync completed
        tip_height: u32,
    },

    /// New filter headers have been stored.
    ///
    /// Emitted by: `FilterHeadersManager`
    /// Consumed by: `FiltersManager`
    FilterHeadersStored {
        /// Lowest height stored in this batch
        start_height: u32,
        /// Highest height stored in this batch
        end_height: u32,
        /// New tip height after storage
        tip_height: u32,
    },

    /// Filter headers have reached the chain tip (initial sync complete).
    ///
    /// Emitted by: `FilterHeadersManager`
    /// Consumed by: `FiltersManager`
    FilterHeadersSyncComplete {
        /// Tip height when sync completed
        tip_height: u32,
    },

    /// Filters have been stored and are ready for matching.
    ///
    /// Emitted by: `FiltersManager`
    /// Consumed by: (informational, used for progress tracking)
    FiltersStored {
        /// Lowest height stored
        start_height: u32,
        /// Highest height stored
        end_height: u32,
    },

    /// Filter sync has reached the chain tip (all filters processed).
    ///
    /// Emitted by: `FiltersManager`
    /// Consumed by: `BlocksManager` (to transition to Synced)
    FiltersSyncComplete {
        /// Tip height when sync completed
        tip_height: u32,
    },

    /// Filters matched the wallet, blocks need downloading.
    ///
    /// Emitted by: `FiltersManager`
    /// Consumed by: `BlocksManager`
    BlocksNeeded {
        /// Blocks to download (sorted by height)
        blocks: BTreeSet<FilterMatchKey>,
    },

    /// Block downloaded and processed through wallet.
    ///
    /// Emitted by: `BlocksManager`
    /// Consumed by: `FiltersManager` (for gap limit rescanning)
    BlockProcessed {
        /// Hash of the processed block
        block_hash: BlockHash,
        /// Height of the processed block
        height: u32,
        /// New addresses discovered from wallet gap limit maintenance
        new_addresses: Vec<Address>,
    },

    /// Masternode state updated to a new height.
    ///
    /// Emitted by: `MasternodesManager`
    /// Consumed by: (informational, may be used for ChainLock validation)
    MasternodeStateUpdated {
        /// New masternode state height
        height: u32,
    },

    /// A manager encountered a recoverable error.
    ///
    /// Emitted by: Any manager
    /// Consumed by: Coordinator (for logging/monitoring)
    ManagerError {
        /// Which manager encountered the error
        manager: ManagerIdentifier,
        /// Error description
        error: String,
    },

    /// ChainLock received and processed.
    ///
    /// Emitted by: `ChainLockManager`
    /// Consumed by: External listeners, wallet state updates
    ChainLockReceived {
        /// Block height that was chainlocked
        height: u32,
        /// Block hash that was chainlocked
        block_hash: BlockHash,
        /// Whether the signature was validated
        validated: bool,
    },

    /// InstantSend lock received and processed.
    ///
    /// Emitted by: `InstantSendManager`
    /// Consumed by: External listeners, mempool state updates
    InstantLockReceived {
        /// Transaction ID that was locked
        txid: Txid,
        /// Whether the signature was validated
        validated: bool,
    },

    /// Sync has reached the chain tip (all managers idle).
    ///
    /// Emitted by: Coordinator
    /// Consumed by: External listeners
    SyncComplete {
        /// Final header tip height
        header_tip: u32,
    },
}

impl SyncEvent {
    /// Get a short description of this event for logging.
    pub fn description(&self) -> String {
        match self {
            SyncEvent::SyncStart {
                identifier,
            } => {
                format!("SyncStart(identifier={})", identifier)
            }
            SyncEvent::BlockHeadersStored {
                tip_height,
            } => {
                format!("BlockHeadersStored(tip={})", tip_height)
            }
            SyncEvent::BlockHeaderSyncComplete {
                tip_height,
            } => {
                format!("BlockHeaderSyncComplete(tip={})", tip_height)
            }
            SyncEvent::FilterHeadersStored {
                start_height,
                end_height,
                tip_height,
            } => {
                format!("FilterHeadersStored({}-{}, tip={})", start_height, end_height, tip_height)
            }
            SyncEvent::FilterHeadersSyncComplete {
                tip_height,
            } => {
                format!("FilterHeadersSyncComplete(tip={})", tip_height)
            }
            SyncEvent::FiltersStored {
                start_height,
                end_height,
            } => {
                format!("FiltersStored({}-{})", start_height, end_height)
            }
            SyncEvent::FiltersSyncComplete {
                tip_height,
            } => {
                format!("FiltersSyncComplete(tip={})", tip_height)
            }
            SyncEvent::BlocksNeeded {
                blocks,
            } => {
                format!("BlocksNeeded(count={})", blocks.len())
            }
            SyncEvent::BlockProcessed {
                height,
                new_addresses,
                ..
            } => {
                format!("BlockProcessed(height={}, new_addrs={})", height, new_addresses.len())
            }
            SyncEvent::MasternodeStateUpdated {
                height,
            } => {
                format!("MasternodeStateUpdated(height={})", height)
            }
            SyncEvent::ManagerError {
                manager,
                error,
                ..
            } => {
                format!("ManagerError({}, {})", manager, error)
            }
            SyncEvent::ChainLockReceived {
                height,
                validated,
                ..
            } => {
                format!("ChainLockReceived(height={}, validated={})", height, validated)
            }
            SyncEvent::InstantLockReceived {
                txid,
                validated,
            } => {
                format!("InstantLockReceived(txid={}, validated={})", txid, validated)
            }
            SyncEvent::SyncComplete {
                header_tip,
            } => {
                format!("SyncComplete(tip={})", header_tip)
            }
        }
    }
}
