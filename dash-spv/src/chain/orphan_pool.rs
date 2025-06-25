use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use dashcore::{BlockHash, Header as BlockHeader};
use tracing::{debug, trace};

/// Maximum number of orphan blocks to keep in memory
const MAX_ORPHAN_BLOCKS: usize = 100;

/// Maximum time to keep an orphan block before eviction
const ORPHAN_TIMEOUT: Duration = Duration::from_secs(900); // 15 minutes

/// Represents an orphan block with metadata
#[derive(Debug, Clone)]
pub struct OrphanBlock {
    /// The block header
    pub header: BlockHeader,
    /// When this orphan was received
    pub received_at: Instant,
    /// Number of times we've tried to process this orphan
    pub process_attempts: u32,
}

/// Manages orphan blocks that arrive before their parents
pub struct OrphanPool {
    /// Orphan blocks indexed by their previous block hash
    orphans_by_prev: HashMap<BlockHash, Vec<OrphanBlock>>,
    /// All orphan blocks indexed by their own hash
    orphans_by_hash: HashMap<BlockHash, OrphanBlock>,
    /// Queue for eviction order (oldest first)
    eviction_queue: VecDeque<BlockHash>,
    /// Maximum orphans to store
    max_orphans: usize,
    /// Timeout for orphan blocks
    orphan_timeout: Duration,
}

impl OrphanPool {
    /// Creates a new orphan pool with default settings
    pub fn new() -> Self {
        Self::with_config(MAX_ORPHAN_BLOCKS, ORPHAN_TIMEOUT)
    }

    /// Creates a new orphan pool with custom configuration
    pub fn with_config(max_orphans: usize, orphan_timeout: Duration) -> Self {
        Self {
            orphans_by_prev: HashMap::new(),
            orphans_by_hash: HashMap::new(),
            eviction_queue: VecDeque::new(),
            max_orphans,
            orphan_timeout,
        }
    }

    /// Adds an orphan block to the pool
    pub fn add_orphan(&mut self, header: BlockHeader) -> bool {
        let block_hash = header.block_hash();
        
        // Check if we already have this orphan
        if self.orphans_by_hash.contains_key(&block_hash) {
            trace!("Orphan block {} already in pool", block_hash);
            return false;
        }

        // Enforce size limit
        while self.orphans_by_hash.len() >= self.max_orphans {
            if let Some(oldest_hash) = self.eviction_queue.pop_front() {
                self.remove_orphan(&oldest_hash);
                debug!("Evicted oldest orphan {} due to size limit", oldest_hash);
            }
        }

        // Create orphan entry
        let orphan = OrphanBlock {
            header: header.clone(),
            received_at: Instant::now(),
            process_attempts: 0,
        };

        // Index by previous block
        self.orphans_by_prev
            .entry(header.prev_blockhash)
            .or_default()
            .push(orphan.clone());

        // Index by hash
        self.orphans_by_hash.insert(block_hash, orphan);
        self.eviction_queue.push_back(block_hash);

        debug!(
            "Added orphan block {} (prev: {})",
            block_hash,
            header.prev_blockhash
        );

        true
    }

    /// Gets all orphan blocks that reference the given block as their parent
    pub fn get_orphans_by_prev(&mut self, prev_hash: &BlockHash) -> Vec<BlockHeader> {
        self.orphans_by_prev
            .get(prev_hash)
            .map(|orphans| {
                orphans
                    .iter()
                    .map(|o| {
                        // Increment process attempts
                        if let Some(orphan) = self.orphans_by_hash.get_mut(&o.header.block_hash()) {
                            orphan.process_attempts += 1;
                        }
                        o.header.clone()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Removes an orphan block from the pool
    pub fn remove_orphan(&mut self, hash: &BlockHash) -> Option<OrphanBlock> {
        if let Some(orphan) = self.orphans_by_hash.remove(hash) {
            // Remove from prev index
            if let Some(orphans) = self.orphans_by_prev.get_mut(&orphan.header.prev_blockhash) {
                orphans.retain(|o| o.header.block_hash() != *hash);
                if orphans.is_empty() {
                    self.orphans_by_prev.remove(&orphan.header.prev_blockhash);
                }
            }

            // Remove from eviction queue
            self.eviction_queue.retain(|h| h != hash);

            trace!("Removed orphan block {}", hash);
            Some(orphan)
        } else {
            None
        }
    }

    /// Checks if a block is an orphan
    pub fn contains(&self, hash: &BlockHash) -> bool {
        self.orphans_by_hash.contains_key(hash)
    }

    /// Gets the number of orphans in the pool
    pub fn len(&self) -> usize {
        self.orphans_by_hash.len()
    }

    /// Checks if the pool is empty
    pub fn is_empty(&self) -> bool {
        self.orphans_by_hash.is_empty()
    }

    /// Removes expired orphans
    pub fn remove_expired(&mut self) -> Vec<BlockHash> {
        let now = Instant::now();
        let mut removed = Vec::new();

        // Find expired orphans
        let expired: Vec<BlockHash> = self
            .orphans_by_hash
            .iter()
            .filter(|(_, orphan)| now.duration_since(orphan.received_at) > self.orphan_timeout)
            .map(|(hash, _)| *hash)
            .collect();

        // Remove them
        for hash in expired {
            if self.remove_orphan(&hash).is_some() {
                removed.push(hash);
                debug!("Removed expired orphan {}", hash);
            }
        }

        removed
    }

    /// Gets statistics about the orphan pool
    pub fn stats(&self) -> OrphanPoolStats {
        let now = Instant::now();
        let oldest_age = self
            .orphans_by_hash
            .values()
            .map(|o| now.duration_since(o.received_at))
            .max()
            .unwrap_or(Duration::ZERO);

        let max_attempts = self
            .orphans_by_hash
            .values()
            .map(|o| o.process_attempts)
            .max()
            .unwrap_or(0);

        OrphanPoolStats {
            total_orphans: self.orphans_by_hash.len(),
            unique_parents: self.orphans_by_prev.len(),
            oldest_age,
            max_process_attempts: max_attempts,
        }
    }

    /// Clears all orphans from the pool
    pub fn clear(&mut self) {
        self.orphans_by_prev.clear();
        self.orphans_by_hash.clear();
        self.eviction_queue.clear();
        debug!("Cleared orphan pool");
    }

    /// Process orphans when a new block is accepted
    /// Returns headers that are now connectable
    pub fn process_new_block(&mut self, block_hash: &BlockHash) -> Vec<BlockHeader> {
        let orphans = self.get_orphans_by_prev(block_hash);
        
        // Remove these from the pool since we're processing them
        for header in &orphans {
            let _block_hash = header.block_hash();
            self.remove_orphan(&header.block_hash());
        }
        
        orphans
    }
}

/// Statistics about the orphan pool
#[derive(Debug, Clone)]
pub struct OrphanPoolStats {
    /// Total number of orphan blocks
    pub total_orphans: usize,
    /// Number of unique parent blocks referenced
    pub unique_parents: usize,
    /// Age of the oldest orphan
    pub oldest_age: Duration,
    /// Maximum number of process attempts for any orphan
    pub max_process_attempts: u32,
}

impl Default for OrphanPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::hashes::Hash;

    fn create_test_header(prev: BlockHash, nonce: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_blockhash: prev,
            merkle_root: BlockHash::all_zeros(),
            time: 0,
            bits: 0,
            nonce,
        }
    }

    #[test]
    fn test_add_and_retrieve_orphan() {
        let mut pool = OrphanPool::new();
        let genesis = BlockHash::all_zeros();
        let header = create_test_header(genesis, 1);
        let block_hash = header.block_hash();

        assert!(pool.add_orphan(header.clone()));
        assert!(pool.contains(&block_hash));
        assert_eq!(pool.len(), 1);

        let orphans = pool.get_orphans_by_prev(&genesis);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0], header);
    }

    #[test]
    fn test_remove_orphan() {
        let mut pool = OrphanPool::new();
        let header = create_test_header(BlockHash::all_zeros(), 1);
        let block_hash = header.block_hash();

        pool.add_orphan(header.clone());
        assert!(pool.contains(&block_hash));

        let removed = pool.remove_orphan(&block_hash);
        assert!(removed.is_some());
        assert!(!pool.contains(&block_hash));
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_max_orphans_limit() {
        let mut pool = OrphanPool::with_config(3, Duration::from_secs(60));

        // Add 4 orphans, should evict the oldest
        for i in 0..4 {
            let header = create_test_header(BlockHash::all_zeros(), i);
            pool.add_orphan(header);
        }

        assert_eq!(pool.len(), 3);
        
        // First orphan should have been evicted
        let first_hash = create_test_header(BlockHash::all_zeros(), 0).block_hash();
        assert!(!pool.contains(&first_hash));
    }

    #[test]
    fn test_duplicate_orphan() {
        let mut pool = OrphanPool::new();
        let header = create_test_header(BlockHash::all_zeros(), 1);

        assert!(pool.add_orphan(header.clone()));
        assert!(!pool.add_orphan(header)); // Should not add duplicate
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_orphan_chain() {
        let mut pool = OrphanPool::new();
        
        // Create a chain of orphans
        let genesis = BlockHash::all_zeros();
        let header1 = create_test_header(genesis, 1);
        let hash1 = header1.block_hash();
        let header2 = create_test_header(hash1, 2);
        let hash2 = header2.block_hash();
        let header3 = create_test_header(hash2, 3);

        pool.add_orphan(header1.clone());
        pool.add_orphan(header2.clone());
        pool.add_orphan(header3);

        assert_eq!(pool.len(), 3);

        // Get orphans by parent
        let orphans = pool.get_orphans_by_prev(&genesis);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0], header1);

        let orphans = pool.get_orphans_by_prev(&hash1);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0], header2);
    }

    #[test]
    fn test_process_attempts() {
        let mut pool = OrphanPool::new();
        let header = create_test_header(BlockHash::all_zeros(), 1);
        let block_hash = header.block_hash();

        pool.add_orphan(header);

        // Get orphans multiple times
        for _ in 0..3 {
            pool.get_orphans_by_prev(&BlockHash::all_zeros());
        }

        // Check process attempts
        let stats = pool.stats();
        assert_eq!(stats.max_process_attempts, 3);
    }

    #[test]
    fn test_clear_pool() {
        let mut pool = OrphanPool::new();
        
        for i in 0..5 {
            let header = create_test_header(BlockHash::all_zeros(), i);
            pool.add_orphan(header);
        }

        assert_eq!(pool.len(), 5);
        
        pool.clear();
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());
    }
}