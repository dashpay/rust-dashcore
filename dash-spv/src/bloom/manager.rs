//! Bloom filter lifecycle management for SPV clients

use std::sync::Arc;
use tokio::sync::RwLock;
use dashcore::bloom::{BloomFilter, BloomFlags, BloomError};
use dashcore::network::message_bloom::{FilterLoad, FilterAdd};
use dashcore::address::Address;
use dashcore::transaction::Transaction;
use dashcore::script::Script;
use dashcore::OutPoint;
use crate::error::SpvError;

/// Configuration for bloom filter behavior
#[derive(Debug, Clone)]
pub struct BloomFilterConfig {
    /// Expected number of elements
    pub elements: u32,
    /// Desired false positive rate (0.0 to 1.0)
    pub false_positive_rate: f64,
    /// Random value added to hash seeds
    pub tweak: u32,
    /// Update behavior flags
    pub flags: BloomFlags,
    /// Auto-recreate filter when false positive rate exceeds this threshold
    pub max_false_positive_rate: f64,
    /// Track performance statistics
    pub enable_stats: bool,
}

impl Default for BloomFilterConfig {
    fn default() -> Self {
        Self {
            elements: 100,
            false_positive_rate: 0.001,
            tweak: rand::random::<u32>(),
            flags: BloomFlags::All,
            max_false_positive_rate: 0.05,
            enable_stats: true,
        }
    }
}

/// Statistics for bloom filter performance
#[derive(Debug, Clone, Default)]
pub struct BloomFilterStats {
    /// Number of items added to the filter
    pub items_added: u64,
    /// Number of positive matches
    pub matches: u64,
    /// Number of queries performed
    pub queries: u64,
    /// Number of times filter was recreated
    pub recreations: u64,
    /// Current estimated false positive rate
    pub current_false_positive_rate: f64,
}

/// Manages bloom filter lifecycle for SPV client
pub struct BloomFilterManager {
    /// Current bloom filter
    filter: Arc<RwLock<Option<BloomFilter>>>,
    /// Configuration
    config: BloomFilterConfig,
    /// Performance statistics
    stats: Arc<RwLock<BloomFilterStats>>,
    /// Addresses being watched
    addresses: Arc<RwLock<Vec<Address>>>,
    /// Outpoints being watched
    outpoints: Arc<RwLock<Vec<OutPoint>>>,
    /// Data elements being watched
    data_elements: Arc<RwLock<Vec<Vec<u8>>>>,
}

impl BloomFilterManager {
    /// Create a new bloom filter manager
    pub fn new(config: BloomFilterConfig) -> Self {
        Self {
            filter: Arc::new(RwLock::new(None)),
            config,
            stats: Arc::new(RwLock::new(BloomFilterStats::default())),
            addresses: Arc::new(RwLock::new(Vec::new())),
            outpoints: Arc::new(RwLock::new(Vec::new())),
            data_elements: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Initialize or recreate the bloom filter
    pub async fn create_filter(&self) -> Result<FilterLoad, SpvError> {
        let addresses = self.addresses.read().await;
        let outpoints = self.outpoints.read().await;
        let data_elements = self.data_elements.read().await;

        // Calculate total elements
        let total_elements = addresses.len() as u32 
            + outpoints.len() as u32 
            + data_elements.len() as u32;
        
        let elements = std::cmp::max(self.config.elements, total_elements);

        // Create new filter
        let mut new_filter = BloomFilter::new(
            elements,
            self.config.false_positive_rate,
            self.config.tweak,
            self.config.flags,
        ).map_err(|e| SpvError::General(format!("Failed to create bloom filter: {:?}", e)))?;

        // Add all watched elements
        for address in addresses.iter() {
            self.add_address_to_filter(&mut new_filter, address)?;
        }

        for outpoint in outpoints.iter() {
            new_filter.insert(&outpoint_to_bytes(outpoint));
        }

        for data in data_elements.iter() {
            new_filter.insert(data);
        }

        // Update stats
        if self.config.enable_stats {
            let mut stats = self.stats.write().await;
            stats.recreations += 1;
            stats.items_added = total_elements as u64;
            stats.current_false_positive_rate = new_filter.estimate_false_positive_rate(total_elements);
        }

        // Store the new filter
        let filter_load = FilterLoad::from_bloom_filter(&new_filter);
        *self.filter.write().await = Some(new_filter);

        Ok(filter_load)
    }

    /// Add an address to the filter
    pub async fn add_address(&self, address: &Address) -> Result<Option<FilterAdd>, SpvError> {
        // Add to tracked addresses
        self.addresses.write().await.push(address.clone());

        // Update filter if it exists
        if let Some(ref mut filter) = *self.filter.write().await {
            let mut data = Vec::new();
            self.add_address_to_filter(filter, address)?;
            
            // Get the script pubkey bytes
            let script = address.script_pubkey();
            data.extend_from_slice(script.as_bytes());

            if self.config.enable_stats {
                let mut stats = self.stats.write().await;
                stats.items_added += 1;
            }

            return Ok(Some(FilterAdd { data }));
        }

        Ok(None)
    }

    /// Add an outpoint to the filter
    pub async fn add_outpoint(&self, outpoint: &OutPoint) -> Result<Option<FilterAdd>, SpvError> {
        // Add to tracked outpoints
        self.outpoints.write().await.push(*outpoint);

        // Update filter if it exists
        if let Some(ref mut filter) = *self.filter.write().await {
            let data = outpoint_to_bytes(outpoint);
            filter.insert(&data);

            if self.config.enable_stats {
                let mut stats = self.stats.write().await;
                stats.items_added += 1;
            }

            return Ok(Some(FilterAdd { data }));
        }

        Ok(None)
    }

    /// Add arbitrary data to the filter
    pub async fn add_data(&self, data: Vec<u8>) -> Result<Option<FilterAdd>, SpvError> {
        // Add to tracked data
        self.data_elements.write().await.push(data.clone());

        // Update filter if it exists
        if let Some(ref mut filter) = *self.filter.write().await {
            filter.insert(&data);

            if self.config.enable_stats {
                let mut stats = self.stats.write().await;
                stats.items_added += 1;
            }

            return Ok(Some(FilterAdd { data }));
        }

        Ok(None)
    }

    /// Check if data matches the filter
    pub async fn contains(&self, data: &[u8]) -> bool {
        if let Some(ref filter) = *self.filter.read().await {
            let result = filter.contains(data);

            if self.config.enable_stats {
                let mut stats = self.stats.write().await;
                stats.queries += 1;
                if result {
                    stats.matches += 1;
                }
            }

            result
        } else {
            // No filter means match everything
            true
        }
    }

    /// Process a transaction to check for matches
    pub async fn process_transaction(&self, tx: &Transaction) -> bool {
        if self.filter.read().await.is_none() {
            return true; // No filter means match everything
        }

        // Check if any output matches our addresses
        for output in &tx.output {
            if self.contains(output.script_pubkey.as_bytes()).await {
                return true;
            }
        }

        // Check if any input matches our outpoints
        for input in &tx.input {
            if self.contains(&outpoint_to_bytes(&input.previous_output)).await {
                return true;
            }
        }

        false
    }

    /// Check if filter needs recreation based on false positive rate
    pub async fn needs_recreation(&self) -> bool {
        if self.config.enable_stats {
            let stats = self.stats.read().await;
            stats.current_false_positive_rate > self.config.max_false_positive_rate
        } else {
            false
        }
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> BloomFilterStats {
        self.stats.read().await.clone()
    }

    /// Clear the filter
    pub async fn clear(&self) {
        *self.filter.write().await = None;
        self.addresses.write().await.clear();
        self.outpoints.write().await.clear();
        self.data_elements.write().await.clear();
        *self.stats.write().await = BloomFilterStats::default();
    }

    /// Helper to add address to filter
    fn add_address_to_filter(&self, filter: &mut BloomFilter, address: &Address) -> Result<(), SpvError> {
        // Add the script pubkey
        let script = address.script_pubkey();
        filter.insert(script.as_bytes());

        // For P2PKH addresses, also add the public key hash
        if let Some(pubkey_hash) = self.extract_pubkey_hash(&script) {
            filter.insert(&pubkey_hash);
        }

        Ok(())
    }

    /// Extract public key hash from script if it's P2PKH
    fn extract_pubkey_hash(&self, script: &Script) -> Option<Vec<u8>> {
        let bytes = script.as_bytes();
        // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        if bytes.len() == 25 
            && bytes[0] == 0x76  // OP_DUP
            && bytes[1] == 0xa9  // OP_HASH160
            && bytes[2] == 0x14  // Push 20 bytes
            && bytes[23] == 0x88 // OP_EQUALVERIFY
            && bytes[24] == 0xac // OP_CHECKSIG
        {
            Some(bytes[3..23].to_vec())
        } else {
            None
        }
    }
}

/// Convert outpoint to bytes for bloom filter
fn outpoint_to_bytes(outpoint: &OutPoint) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(36);
    bytes.extend_from_slice(&outpoint.txid[..]);
    bytes.extend_from_slice(&outpoint.vout.to_le_bytes());
    bytes
}