//! Compact filter client for SPV wallets
//!
//! This module implements a client that uses BIP 157/158 compact filters
//! to efficiently sync wallets without downloading full blocks.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use dashcore::blockdata::block::Block;
use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::{BlockHash, Network, Txid};
use dashcore_hashes::{sha256, Hash};
use key_wallet::Address;

use crate::compact_filter::{CompactFilter, FilterHeader, FilterType};
use crate::enhanced_wallet_manager::EnhancedWalletManager;
use crate::transaction_handler::TransactionProcessResult;

/// Filter client for managing compact filters and syncing
pub struct FilterClient {
    /// Network we're operating on
    network: Network,
    /// Current filter chain
    filter_chain: FilterChain,
    /// Scripts we're watching (from all wallets)
    pub(crate) watched_scripts: BTreeSet<ScriptBuf>,
    /// Outpoints we're watching (our UTXOs that might be spent)
    pub(crate) watched_outpoints: BTreeSet<OutPoint>,
    /// Block fetcher callback
    block_fetcher: Option<Box<dyn BlockFetcher>>,
    /// Filter fetcher callback
    filter_fetcher: Option<Box<dyn FilterFetcher>>,
    /// Current sync height
    sync_height: u32,
    /// Target sync height
    target_height: u32,
}

/// Trait for fetching blocks
pub trait BlockFetcher: Send + Sync {
    /// Fetch a block by hash
    fn fetch_block(&mut self, block_hash: &BlockHash) -> Result<Block, FetchError>;

    /// Fetch multiple blocks
    fn fetch_blocks(&mut self, block_hashes: &[BlockHash]) -> Result<Vec<Block>, FetchError> {
        let mut blocks = Vec::new();
        for hash in block_hashes {
            blocks.push(self.fetch_block(hash)?);
        }
        Ok(blocks)
    }
}

/// Trait for fetching filters
pub trait FilterFetcher: Send + Sync {
    /// Fetch a filter by block hash
    fn fetch_filter(&mut self, block_hash: &BlockHash) -> Result<CompactFilter, FetchError>;

    /// Fetch a filter header by block hash
    fn fetch_filter_header(&mut self, block_hash: &BlockHash) -> Result<FilterHeader, FetchError>;

    /// Fetch multiple filters
    fn fetch_filters(
        &mut self,
        block_hashes: &[BlockHash],
    ) -> Result<Vec<CompactFilter>, FetchError> {
        let mut filters = Vec::new();
        for hash in block_hashes {
            filters.push(self.fetch_filter(hash)?);
        }
        Ok(filters)
    }
}

/// Errors that can occur during fetching
#[derive(Debug, Clone)]
pub enum FetchError {
    /// Network error
    Network(String),
    /// Block not found
    NotFound,
    /// Invalid data
    InvalidData(String),
    /// Timeout
    Timeout,
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FetchError::Network(msg) => write!(f, "Network error: {}", msg),
            FetchError::NotFound => write!(f, "Not found"),
            FetchError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            FetchError::Timeout => write!(f, "Timeout"),
        }
    }
}

/// Filter chain for tracking and validating filters
pub struct FilterChain {
    /// Filter headers by height
    headers: BTreeMap<u32, FilterHeader>,
    /// Cached filters
    filters: BTreeMap<BlockHash, CompactFilter>,
    /// Maximum number of filters to cache
    max_cache_size: usize,
    /// Filter type we're using
    filter_type: FilterType,
}

impl FilterChain {
    /// Create a new filter chain
    pub fn new(filter_type: FilterType, max_cache_size: usize) -> Self {
        Self {
            headers: BTreeMap::new(),
            filters: BTreeMap::new(),
            max_cache_size,
            filter_type,
        }
    }

    /// Add a filter header to the chain
    pub fn add_header(&mut self, height: u32, header: FilterHeader) -> Result<(), ChainError> {
        // Validate the header connects to the previous one
        if height > 0 {
            if let Some(prev_header) = self.headers.get(&(height - 1)) {
                let expected_prev = prev_header.calculate();
                if header.prev_header != expected_prev {
                    return Err(ChainError::InvalidPrevHeader);
                }
            }
        }

        self.headers.insert(height, header);
        Ok(())
    }

    /// Add a filter to the cache
    pub fn cache_filter(&mut self, filter: CompactFilter) {
        // Evict old filters if cache is full
        if self.filters.len() >= self.max_cache_size {
            // Remove the oldest filter (simple FIFO for now)
            if let Some(first_key) = self.filters.keys().next().cloned() {
                self.filters.remove(&first_key);
            }
        }

        let block_hash = BlockHash::from_slice(&filter.block_hash).unwrap();
        self.filters.insert(block_hash, filter);
    }

    /// Get a cached filter
    pub fn get_filter(&self, block_hash: &BlockHash) -> Option<&CompactFilter> {
        self.filters.get(block_hash)
    }

    /// Validate a filter against its header
    pub fn validate_filter(&self, height: u32, filter: &CompactFilter) -> bool {
        if let Some(header) = self.headers.get(&height) {
            // Calculate filter hash and compare
            let filter_hash = sha256::Hash::hash(filter.filter.data());
            filter_hash.to_byte_array() == header.filter_hash
        } else {
            false
        }
    }
}

/// Chain validation error
#[derive(Debug, Clone)]
pub enum ChainError {
    /// Invalid previous header
    InvalidPrevHeader,
    /// Invalid filter hash
    InvalidFilterHash,
    /// Missing header
    MissingHeader,
}

impl FilterClient {
    /// Create a new filter client
    pub fn new(network: Network) -> Self {
        Self {
            network,
            filter_chain: FilterChain::new(FilterType::Basic, 1000),
            watched_scripts: BTreeSet::new(),
            watched_outpoints: BTreeSet::new(),
            block_fetcher: None,
            filter_fetcher: None,
            sync_height: 0,
            target_height: 0,
        }
    }

    /// Set the block fetcher
    pub fn set_block_fetcher(&mut self, fetcher: Box<dyn BlockFetcher>) {
        self.block_fetcher = Some(fetcher);
    }

    /// Set the filter fetcher
    pub fn set_filter_fetcher(&mut self, fetcher: Box<dyn FilterFetcher>) {
        self.filter_fetcher = Some(fetcher);
    }

    /// Add scripts to watch
    pub fn watch_scripts(&mut self, scripts: Vec<ScriptBuf>) {
        for script in scripts {
            self.watched_scripts.insert(script);
        }
    }

    /// Add outpoints to watch
    pub fn watch_outpoints(&mut self, outpoints: Vec<OutPoint>) {
        for outpoint in outpoints {
            self.watched_outpoints.insert(outpoint);
        }
    }

    /// Remove scripts from watch list
    pub fn unwatch_scripts(&mut self, scripts: &[ScriptBuf]) {
        for script in scripts {
            self.watched_scripts.remove(script);
        }
    }

    /// Update watched elements from wallet manager
    pub fn update_from_wallet_manager(&mut self, manager: &EnhancedWalletManager) {
        // Clear existing watches
        self.watched_scripts.clear();
        self.watched_outpoints.clear();

        // Use the manager's watched scripts and outpoints
        self.watched_scripts = manager.get_watched_scripts().clone();
        self.watched_outpoints = manager.get_watched_outpoints().clone();
    }

    /// Process a compact filter to check if we need the block
    pub fn process_filter(
        &mut self,
        filter: &CompactFilter,
        height: u32,
        block_hash: &BlockHash,
    ) -> FilterMatchResult {
        // Cache the filter
        // Don't cache here - the filter chain doesn't have a cache_filter method
        // We could add caching later if needed

        // Check if this filter matches any of our watched items
        let matches_scripts = self.check_filter_matches_scripts(filter);
        let matches_outpoints = self.check_filter_matches_outpoints(filter);

        if matches_scripts || matches_outpoints {
            FilterMatchResult::Match {
                height,
                block_hash: *block_hash,
                matches_scripts,
                matches_outpoints,
            }
        } else {
            FilterMatchResult::NoMatch
        }
    }

    /// Check if a filter matches any of our watched scripts
    fn check_filter_matches_scripts(&self, filter: &CompactFilter) -> bool {
        if self.watched_scripts.is_empty() {
            return false;
        }

        let scripts: Vec<ScriptBuf> = self.watched_scripts.iter().cloned().collect();
        filter.match_any_script(&scripts)
    }

    /// Check if a filter matches any of our watched outpoints
    fn check_filter_matches_outpoints(&self, filter: &CompactFilter) -> bool {
        if self.watched_outpoints.is_empty() {
            return false;
        }

        // Check each outpoint
        for outpoint in &self.watched_outpoints {
            if filter.contains_outpoint(outpoint) {
                return true;
            }
        }

        false
    }

    /// Fetch and process a block that matched our filter
    pub fn fetch_and_process_block(
        &mut self,
        block_hash: &BlockHash,
        height: u32,
    ) -> Result<BlockProcessResult, FetchError> {
        let fetcher = self
            .block_fetcher
            .as_mut()
            .ok_or_else(|| FetchError::Network("No block fetcher configured".into()))?;

        let block = fetcher.fetch_block(block_hash)?;

        Ok(self.process_block(&block, height))
    }

    /// Process a fetched block
    pub fn process_block(&mut self, block: &Block, height: u32) -> BlockProcessResult {
        let mut result = BlockProcessResult {
            height,
            block_hash: block.header.block_hash(),
            relevant_txs: Vec::new(),
            new_outpoints: Vec::new(),
            spent_outpoints: Vec::new(),
            new_scripts: Vec::new(),
        };

        // Check each transaction
        for tx in &block.txdata {
            let mut is_relevant = false;

            // Check if any outputs are for us
            for (vout, output) in tx.output.iter().enumerate() {
                if self.watched_scripts.contains(&output.script_pubkey) {
                    is_relevant = true;
                    result.new_scripts.push(output.script_pubkey.clone());

                    let outpoint = OutPoint {
                        txid: tx.txid(),
                        vout: vout as u32,
                    };
                    result.new_outpoints.push(outpoint);

                    // Add to watched outpoints for future spending detection
                    self.watched_outpoints.insert(outpoint);
                }
            }

            // Check if any inputs spend our outpoints
            for input in &tx.input {
                if self.watched_outpoints.contains(&input.previous_output) {
                    is_relevant = true;
                    result.spent_outpoints.push(input.previous_output);

                    // Remove from watched outpoints
                    self.watched_outpoints.remove(&input.previous_output);
                }
            }

            if is_relevant {
                result.relevant_txs.push(tx.clone());
            }
        }

        // Update sync height
        self.sync_height = height;

        result
    }

    /// Sync filters from start_height to end_height
    pub async fn sync_filters(
        &mut self,
        start_height: u32,
        end_height: u32,
        block_hashes: Vec<(u32, BlockHash)>,
    ) -> Result<SyncResult, SyncError> {
        let mut sync_result = SyncResult {
            blocks_scanned: 0,
            blocks_matched: 0,
            blocks_fetched: Vec::new(),
            transactions_found: 0,
        };

        for (height, block_hash) in block_hashes {
            if height < start_height || height > end_height {
                continue;
            }

            // Fetch the filter
            let filter = if let Some(fetcher) = self.filter_fetcher.as_mut() {
                fetcher.fetch_filter(&block_hash).map_err(|e| SyncError::FetchError(e))?
            } else {
                return Err(SyncError::NoFilterFetcher);
            };

            sync_result.blocks_scanned += 1;

            // Check if the filter matches
            let match_result = self.process_filter(&filter, height, &block_hash);

            if let FilterMatchResult::Match {
                ..
            } = match_result
            {
                sync_result.blocks_matched += 1;

                // Fetch and process the full block
                let block_result = self
                    .fetch_and_process_block(&block_hash, height)
                    .map_err(|e| SyncError::FetchError(e))?;

                sync_result.transactions_found += block_result.relevant_txs.len();
                sync_result.blocks_fetched.push((height, block_hash, block_result));
            }

            // Update progress
            self.sync_height = height;
        }

        Ok(sync_result)
    }

    /// Get sync progress
    pub fn sync_progress(&self) -> f32 {
        if self.target_height == 0 {
            return 0.0;
        }

        (self.sync_height as f32) / (self.target_height as f32)
    }

    /// Get the number of watched scripts
    pub fn watched_scripts_count(&self) -> usize {
        self.watched_scripts.len()
    }

    /// Get the number of watched outpoints
    pub fn watched_outpoints_count(&self) -> usize {
        self.watched_outpoints.len()
    }
}

/// Result of checking a filter
#[derive(Debug, Clone)]
pub enum FilterMatchResult {
    /// Filter matches our criteria
    Match {
        height: u32,
        block_hash: BlockHash,
        matches_scripts: bool,
        matches_outpoints: bool,
    },
    /// Filter doesn't match
    NoMatch,
}

/// Result of processing a block
#[derive(Debug, Clone)]
pub struct BlockProcessResult {
    /// Block height
    pub height: u32,
    /// Block hash
    pub block_hash: BlockHash,
    /// Relevant transactions found
    pub relevant_txs: Vec<Transaction>,
    /// New outpoints created for us
    pub new_outpoints: Vec<OutPoint>,
    /// Our outpoints that were spent
    pub spent_outpoints: Vec<OutPoint>,
    /// New scripts found
    pub new_scripts: Vec<ScriptBuf>,
}

/// Result of a sync operation
#[derive(Debug, Clone)]
pub struct SyncResult {
    /// Number of blocks scanned
    pub blocks_scanned: usize,
    /// Number of blocks that matched filters
    pub blocks_matched: usize,
    /// Blocks that were fetched and processed
    pub blocks_fetched: Vec<(u32, BlockHash, BlockProcessResult)>,
    /// Total transactions found
    pub transactions_found: usize,
}

/// Sync error
#[derive(Debug, Clone)]
pub enum SyncError {
    /// No filter fetcher configured
    NoFilterFetcher,
    /// No block fetcher configured
    NoBlockFetcher,
    /// Fetch error
    FetchError(FetchError),
    /// Chain validation error
    ChainError(ChainError),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SyncError::NoFilterFetcher => write!(f, "No filter fetcher configured"),
            SyncError::NoBlockFetcher => write!(f, "No block fetcher configured"),
            SyncError::FetchError(e) => write!(f, "Fetch error: {}", e),
            SyncError::ChainError(_) => write!(f, "Chain validation error"),
        }
    }
}

/// Complete filter-based SPV client
pub struct FilterSPVClient {
    /// Filter client
    pub(crate) filter_client: FilterClient,
    /// Wallet manager
    pub(crate) wallet_manager: EnhancedWalletManager,
    /// Block header chain (height -> block hash)
    header_chain: BTreeMap<u32, BlockHash>,
    /// Current chain tip
    chain_tip: u32,
    /// Sync status
    sync_status: SyncStatus,
}

/// Sync status
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SyncStatus {
    /// Not syncing
    Idle,
    /// Syncing headers
    SyncingHeaders,
    /// Syncing filters
    SyncingFilters,
    /// Syncing blocks
    SyncingBlocks,
    /// Synced
    Synced,
}

impl FilterSPVClient {
    /// Create a new SPV client
    pub fn new(network: Network) -> Self {
        Self {
            filter_client: FilterClient::new(network),
            wallet_manager: EnhancedWalletManager::new(network),
            header_chain: BTreeMap::new(),
            chain_tip: 0,
            sync_status: SyncStatus::Idle,
        }
    }

    /// Add a wallet to manage
    pub fn add_wallet(
        &mut self,
        wallet_id: String,
        name: String,
        mnemonic: &str,
        passphrase: &str,
        birth_height: Option<u32>,
    ) -> Result<(), String> {
        let network = self.wallet_manager.network();
        self.wallet_manager
            .base_mut()
            .create_wallet_from_mnemonic(
                wallet_id,
                name,
                mnemonic,
                passphrase,
                Some(network.into()),
                birth_height,
            )
            .map_err(|e| format!("{}", e))?;

        // Update filter client with new wallet addresses
        self.filter_client.update_from_wallet_manager(&self.wallet_manager);

        Ok(())
    }

    /// Process a new filter
    pub fn process_new_filter(
        &mut self,
        height: u32,
        block_hash: BlockHash,
        filter: CompactFilter,
    ) -> Result<Option<BlockProcessResult>, String> {
        // Update header chain
        self.header_chain.insert(height, block_hash);

        // Check if filter matches
        let match_result = self.filter_client.process_filter(&filter, height, &block_hash);

        match match_result {
            FilterMatchResult::Match {
                ..
            } => {
                // Fetch and process the block
                let block_result = self
                    .filter_client
                    .fetch_and_process_block(&block_hash, height)
                    .map_err(|e| format!("Failed to fetch block: {}", e))?;

                // Process transactions in wallet manager
                for tx in &block_result.relevant_txs {
                    let timestamp = 0; // Would need proper timestamp from block
                    self.wallet_manager.process_transaction(
                        tx,
                        Some(height),
                        Some(block_hash),
                        timestamp,
                    );
                }

                Ok(Some(block_result))
            }
            FilterMatchResult::NoMatch => Ok(None),
        }
    }

    /// Start sync from a given height
    pub async fn start_sync(&mut self, from_height: u32) -> Result<SyncResult, String> {
        self.sync_status = SyncStatus::SyncingFilters;

        // Get block hashes to sync (would come from header chain)
        let block_hashes: Vec<(u32, BlockHash)> = self
            .header_chain
            .iter()
            .filter(|(&h, _)| h >= from_height)
            .map(|(&h, &hash)| (h, hash))
            .collect();

        let result = self
            .filter_client
            .sync_filters(from_height, self.chain_tip, block_hashes)
            .await
            .map_err(|e| format!("Sync failed: {}", e))?;

        // Process all fetched blocks
        for (height, block_hash, block_result) in &result.blocks_fetched {
            for tx in &block_result.relevant_txs {
                let timestamp = 0; // Would need proper timestamp from block
                self.wallet_manager.process_transaction(
                    tx,
                    Some(*height),
                    Some(*block_hash),
                    timestamp,
                );
            }
        }

        self.sync_status = SyncStatus::Synced;
        Ok(result)
    }

    /// Get wallet balance
    pub fn get_balance(&self, wallet_id: &str) -> Result<(u64, u64), String> {
        let wallet_id_string = wallet_id.to_string();
        let balance = self
            .wallet_manager
            .base()
            .get_wallet_balance(&wallet_id_string)
            .map_err(|e| format!("{}", e))?;

        Ok((balance.confirmed, balance.unconfirmed))
    }

    /// Get sync status
    pub fn sync_status(&self) -> SyncStatus {
        self.sync_status
    }

    /// Get sync progress
    pub fn sync_progress(&self) -> f32 {
        self.filter_client.sync_progress()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBlockFetcher {
        blocks: BTreeMap<BlockHash, Block>,
    }

    impl BlockFetcher for MockBlockFetcher {
        fn fetch_block(&mut self, block_hash: &BlockHash) -> Result<Block, FetchError> {
            self.blocks.get(block_hash).cloned().ok_or(FetchError::NotFound)
        }
    }

    #[test]
    fn test_filter_client_creation() {
        let mut client = FilterClient::new(Network::Testnet);

        // Add some scripts to watch
        let script = ScriptBuf::new();
        client.watch_scripts(vec![script.clone()]);

        assert!(client.watched_scripts.contains(&script));
    }

    #[test]
    fn test_filter_chain() {
        let mut chain = FilterChain::new(FilterType::Basic, 10);

        let header = FilterHeader {
            filter_type: FilterType::Basic,
            block_hash: [0u8; 32],
            prev_header: [0u8; 32],
            filter_hash: [1u8; 32],
        };

        assert!(chain.add_header(0, header).is_ok());
        assert_eq!(chain.headers.len(), 1);
    }
}
