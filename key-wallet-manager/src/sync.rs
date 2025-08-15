//! Wallet synchronization with the blockchain
//!
//! This module provides functionality for synchronizing wallet state
//! with the blockchain using compact filters and block scanning.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp;

use dashcore::blockdata::block::{Block, Header};
use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::Transaction;
use dashcore::{BlockHash, Txid};
use dashcore_hashes::Hash;
use key_wallet::{Address, Network};

use crate::compact_filter::{CompactFilter, FilterHeader, FilterType};
use crate::transaction_handler::{AddressTracker, TransactionHandler, TransactionProcessResult};
use crate::utxo::UtxoSet;
use crate::wallet_manager::{WalletId, WalletManager};

/// Sync state for a wallet
#[derive(Debug, Clone)]
pub struct SyncState {
    /// Last synced block height
    pub last_height: u32,
    /// Last synced block hash
    pub last_block_hash: BlockHash,
    /// Last filter header
    pub last_filter_header: Option<[u8; 32]>,
    /// Sync progress (0.0 to 1.0)
    pub progress: f32,
    /// Whether sync is in progress
    pub is_syncing: bool,
    /// Number of blocks scanned
    pub blocks_scanned: u64,
    /// Number of relevant blocks found
    pub relevant_blocks: u64,
}

impl Default for SyncState {
    fn default() -> Self {
        Self {
            last_height: 0,
            last_block_hash: BlockHash::all_zeros(),
            last_filter_header: None,
            progress: 0.0,
            is_syncing: false,
            blocks_scanned: 0,
            relevant_blocks: 0,
        }
    }
}

/// Wallet synchronizer using compact filters
pub struct WalletSynchronizer {
    /// Network we're operating on
    network: Network,
    /// Transaction handler
    tx_handler: TransactionHandler,
    /// Address tracker
    address_tracker: AddressTracker,
    /// Sync state for each wallet
    sync_states: BTreeMap<WalletId, SyncState>,
    /// Scripts we're monitoring across all wallets
    monitored_scripts: BTreeSet<ScriptBuf>,
    /// Birth height of each wallet (when it was created)
    wallet_birth_heights: BTreeMap<WalletId, u32>,
}

impl WalletSynchronizer {
    /// Create a new wallet synchronizer
    pub fn new(network: Network, gap_limit: u32) -> Self {
        Self {
            network,
            tx_handler: TransactionHandler::new(network),
            address_tracker: AddressTracker::new(gap_limit),
            sync_states: BTreeMap::new(),
            monitored_scripts: BTreeSet::new(),
            wallet_birth_heights: BTreeMap::new(),
        }
    }

    /// Register a wallet for synchronization
    pub fn register_wallet(
        &mut self,
        wallet_id: WalletId,
        addresses: Vec<Address>,
        birth_height: u32,
    ) {
        // Register addresses with transaction handler
        self.tx_handler.register_wallet_addresses(wallet_id.clone(), addresses.clone());

        // Add scripts to monitored set
        for address in addresses {
            let script = ScriptBuf::from(address.script_pubkey());
            self.monitored_scripts.insert(script);
        }

        // Initialize sync state
        self.sync_states.insert(wallet_id.clone(), SyncState::default());
        self.wallet_birth_heights.insert(wallet_id, birth_height);
    }

    /// Process a compact filter to check if a block is relevant
    pub fn check_block_relevance(&self, filter: &CompactFilter) -> bool {
        // Convert our scripts to the format needed by the filter
        let scripts: Vec<ScriptBuf> = self.monitored_scripts.iter().cloned().collect();
        filter.match_any_script(&scripts)
    }

    /// Process a block that matched our filters
    pub fn process_block(&mut self, block: &Block, height: u32) -> BlockProcessResult {
        let mut result = BlockProcessResult {
            wallet_updates: BTreeMap::new(),
            new_utxos: Vec::new(),
            spent_utxos: Vec::new(),
            new_addresses_needed: BTreeMap::new(),
        };

        let timestamp = block.header.time as u64;

        // Process each transaction in the block
        for tx in &block.txdata {
            let tx_result = self.tx_handler.process_transaction(tx, Some(height), timestamp);

            if tx_result.is_relevant {
                // Update affected wallets
                for wallet_id in &tx_result.affected_wallets {
                    let update = result
                        .wallet_updates
                        .entry(wallet_id.clone())
                        .or_insert_with(WalletUpdate::default);

                    update.new_transactions.push(tx.clone());
                    update.balance_change +=
                        tx_result.balance_changes.get(wallet_id).copied().unwrap_or(0);
                }

                // Track UTXOs
                result.new_utxos.extend(tx_result.new_utxos);
                result.spent_utxos.extend(tx_result.spent_utxos);

                // Check if we need to generate new addresses
                // This would require parsing the transaction to determine
                // which addresses were used and updating the address tracker
            }
        }

        // Update sync states
        let block_hash = block.header.block_hash();
        for (wallet_id, _) in &result.wallet_updates {
            if let Some(state) = self.sync_states.get_mut(wallet_id) {
                state.last_height = height;
                state.last_block_hash = block_hash;
                state.blocks_scanned += 1;
                if !result.wallet_updates[wallet_id].new_transactions.is_empty() {
                    state.relevant_blocks += 1;
                }
            }
        }

        result
    }

    /// Start synchronization for a wallet
    pub fn start_sync(&mut self, wallet_id: &WalletId, target_height: u32) {
        if let Some(state) = self.sync_states.get_mut(wallet_id) {
            state.is_syncing = true;
            state.progress = 0.0;

            // Calculate starting height
            let birth_height = self.wallet_birth_heights.get(wallet_id).copied().unwrap_or(0);
            let start_height = cmp::max(state.last_height, birth_height);

            // Update progress
            if target_height > start_height {
                state.progress = 0.0;
            }
        }
    }

    /// Update sync progress
    pub fn update_sync_progress(
        &mut self,
        wallet_id: &WalletId,
        current_height: u32,
        target_height: u32,
    ) {
        if let Some(state) = self.sync_states.get_mut(wallet_id) {
            let birth_height = self.wallet_birth_heights.get(wallet_id).copied().unwrap_or(0);

            let total_blocks = target_height.saturating_sub(birth_height);
            let synced_blocks = current_height.saturating_sub(birth_height);

            if total_blocks > 0 {
                state.progress = (synced_blocks as f32) / (total_blocks as f32);
            } else {
                state.progress = 1.0;
            }

            state.last_height = current_height;
        }
    }

    /// Complete synchronization for a wallet
    pub fn complete_sync(&mut self, wallet_id: &WalletId) {
        if let Some(state) = self.sync_states.get_mut(wallet_id) {
            state.is_syncing = false;
            state.progress = 1.0;
        }
    }

    /// Get sync state for a wallet
    pub fn get_sync_state(&self, wallet_id: &WalletId) -> Option<&SyncState> {
        self.sync_states.get(wallet_id)
    }

    /// Check if any wallet needs synchronization
    pub fn needs_sync(&self, current_height: u32) -> Vec<WalletId> {
        self.sync_states
            .iter()
            .filter(|(_, state)| state.last_height < current_height && !state.is_syncing)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

/// Result of processing a block
#[derive(Debug, Clone)]
pub struct BlockProcessResult {
    /// Updates for each affected wallet
    pub wallet_updates: BTreeMap<WalletId, WalletUpdate>,
    /// New UTXOs created
    pub new_utxos: Vec<crate::utxo::Utxo>,
    /// UTXOs that were spent
    pub spent_utxos: Vec<dashcore::OutPoint>,
    /// New addresses needed per wallet/account
    pub new_addresses_needed: BTreeMap<(WalletId, u32), u32>,
}

/// Update for a single wallet
#[derive(Debug, Clone, Default)]
pub struct WalletUpdate {
    /// New transactions for this wallet
    pub new_transactions: Vec<Transaction>,
    /// Net balance change
    pub balance_change: i64,
    /// Addresses that were used
    pub used_addresses: Vec<Address>,
}

/// Chain reorganization handler
pub struct ReorgHandler {
    /// Transactions by height for rollback
    transactions_by_height: BTreeMap<u32, Vec<Transaction>>,
    /// Maximum reorg depth to handle
    max_reorg_depth: u32,
}

impl ReorgHandler {
    /// Create a new reorg handler
    pub fn new(max_reorg_depth: u32) -> Self {
        Self {
            transactions_by_height: BTreeMap::new(),
            max_reorg_depth,
        }
    }

    /// Record transactions at a height
    pub fn record_block(&mut self, height: u32, transactions: Vec<Transaction>) {
        self.transactions_by_height.insert(height, transactions);

        // Clean up old heights
        let min_height = height.saturating_sub(self.max_reorg_depth);
        self.transactions_by_height.retain(|&h, _| h >= min_height);
    }

    /// Handle a reorganization
    pub fn handle_reorg(&mut self, from_height: u32, to_height: u32) -> ReorgResult {
        let mut result = ReorgResult {
            removed_transactions: Vec::new(),
            restored_utxos: Vec::new(),
            removed_utxos: Vec::new(),
        };

        // Remove transactions from reorganized blocks
        for height in (to_height + 1)..=from_height {
            if let Some(txs) = self.transactions_by_height.remove(&height) {
                result.removed_transactions.extend(txs);
            }
        }

        // In a real implementation, we would:
        // 1. Restore UTXOs that were spent in removed transactions
        // 2. Remove UTXOs that were created in removed transactions
        // 3. Update wallet balances accordingly

        result
    }
}

/// Result of handling a reorganization
#[derive(Debug, Clone)]
pub struct ReorgResult {
    /// Transactions that were removed
    pub removed_transactions: Vec<Transaction>,
    /// UTXOs that should be restored
    pub restored_utxos: Vec<dashcore::OutPoint>,
    /// UTXOs that should be removed
    pub removed_utxos: Vec<dashcore::OutPoint>,
}

/// Sync manager coordinates synchronization across multiple wallets
pub struct SyncManager {
    /// Wallet synchronizer
    synchronizer: WalletSynchronizer,
    /// Reorg handler
    reorg_handler: ReorgHandler,
    /// Current chain tip
    chain_tip: u32,
    /// Whether we're currently syncing
    is_syncing: bool,
}

impl SyncManager {
    /// Create a new sync manager
    pub fn new(network: Network, gap_limit: u32, max_reorg_depth: u32) -> Self {
        Self {
            synchronizer: WalletSynchronizer::new(network, gap_limit),
            reorg_handler: ReorgHandler::new(max_reorg_depth),
            chain_tip: 0,
            is_syncing: false,
        }
    }

    /// Update the chain tip
    pub fn update_chain_tip(&mut self, height: u32) {
        self.chain_tip = height;
    }

    /// Start synchronization for all wallets that need it
    pub fn start_sync_all(&mut self) {
        let wallets_to_sync = self.synchronizer.needs_sync(self.chain_tip);
        let has_wallets = !wallets_to_sync.is_empty();
        for wallet_id in wallets_to_sync {
            self.synchronizer.start_sync(&wallet_id, self.chain_tip);
        }
        self.is_syncing = has_wallets;
    }

    /// Process a filter and fetch block if relevant
    pub fn process_filter(&mut self, filter: &CompactFilter, height: u32) -> bool {
        let is_relevant = self.synchronizer.check_block_relevance(filter);

        if is_relevant {
            // In a real implementation, we would fetch the full block here
            // For now, just return that it's relevant
            true
        } else {
            // Update sync progress even for irrelevant blocks
            let wallet_ids: Vec<_> = self.synchronizer.sync_states.keys().cloned().collect();
            for wallet_id in wallet_ids {
                self.synchronizer.update_sync_progress(&wallet_id, height, self.chain_tip);
            }
            false
        }
    }

    /// Process a full block
    pub fn process_block(&mut self, block: &Block, height: u32) -> BlockProcessResult {
        let result = self.synchronizer.process_block(block, height);

        // Record block for potential reorg handling
        self.reorg_handler.record_block(height, block.txdata.clone());

        result
    }

    /// Handle a chain reorganization
    pub fn handle_reorg(&mut self, from_height: u32, to_height: u32) -> ReorgResult {
        self.reorg_handler.handle_reorg(from_height, to_height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_state() {
        let mut sync = WalletSynchronizer::new(Network::Testnet, 20);
        let wallet_id = "wallet1".to_string();

        sync.register_wallet(wallet_id.clone(), Vec::new(), 0);
        sync.start_sync(&wallet_id, 1000);

        let state = sync.get_sync_state(&wallet_id).unwrap();
        assert!(state.is_syncing);
        assert_eq!(state.progress, 0.0);

        sync.update_sync_progress(&wallet_id, 500, 1000);
        let state = sync.get_sync_state(&wallet_id).unwrap();
        assert_eq!(state.progress, 0.5);

        sync.complete_sync(&wallet_id);
        let state = sync.get_sync_state(&wallet_id).unwrap();
        assert!(!state.is_syncing);
        assert_eq!(state.progress, 1.0);
    }
}
