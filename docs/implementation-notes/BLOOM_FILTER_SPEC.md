# Bloom Filter Implementation Specification for rust-dashcore

## Executive Summary

This specification defines the implementation of full BIP37 bloom filter support in rust-dashcore and dash-spv. While the codebase currently includes bloom filter message types, there is no actual bloom filter implementation. This spec outlines a complete implementation that will enable SPV clients to use bloom filters for transaction filtering, providing an alternative to BIP157/158 compact filters.

## Background

### Current State
- **Message Types**: BIP37 bloom filter messages (filterload, filteradd, filterclear) are defined in `dash/src/network/message_bloom.rs`
- **Configuration**: `MempoolStrategy::BloomFilter` exists but is not implemented
- **Alternative**: The SPV client currently uses BIP157/158 compact filters exclusively
- **Gap**: No actual bloom filter data structure or filtering logic exists

### Motivation
1. **Compatibility**: Many Dash nodes support BIP37 bloom filters
2. **Real-time Filtering**: Unlike compact filters, bloom filters allow dynamic updates
3. **Resource Efficiency**: Lower bandwidth for wallets monitoring few addresses
4. **User Choice**: Provide flexibility between privacy (BIP158) and efficiency (BIP37)

## Architecture Overview

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                        dash crate                           │
├─────────────────────────────────────────────────────────────┤
│  bloom/                                                     │
│  ├── filter.rs         - Core BloomFilter implementation   │
│  ├── hash.rs           - Murmur3 hash implementation       │
│  ├── error.rs          - Bloom filter specific errors      │
│  └── mod.rs            - Module exports                    │
├─────────────────────────────────────────────────────────────┤
│  network/                                                   │
│  └── message_bloom.rs  - [EXISTING] BIP37 messages         │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                       dash-spv crate                        │
├─────────────────────────────────────────────────────────────┤
│  bloom/                                                     │
│  ├── manager.rs        - Bloom filter lifecycle manager     │
│  ├── builder.rs        - Filter construction utilities     │
│  └── mod.rs            - Module exports                    │
├─────────────────────────────────────────────────────────────┤
│  mempool_filter.rs     - [MODIFY] Integrate bloom filtering│
│  network/                                                   │
│  └── peer.rs           - [MODIFY] Handle bloom messages    │
└─────────────────────────────────────────────────────────────┘
```

## Detailed Implementation

### 1. Core Bloom Filter (`dash/src/bloom/filter.rs`)

```rust
use crate::consensus::encode::{Decodable, Encodable};
use crate::bloom::hash::murmur3;

/// A BIP37 bloom filter
#[derive(Clone, Debug, PartialEq)]
pub struct BloomFilter {
    /// Filter bit field
    data: Vec<u8>,
    /// Number of hash functions to use
    n_hash_funcs: u32,
    /// Seed value for hash functions
    n_tweak: u32,
    /// Bloom filter update flags
    flags: BloomFlags,
}

impl BloomFilter {
    /// Create a new bloom filter
    /// 
    /// # Parameters
    /// - `elements`: Expected number of elements
    /// - `fp_rate`: Desired false positive rate (0.0 - 1.0)
    /// - `tweak`: Random seed for hash functions
    /// - `flags`: Filter update behavior
    pub fn new(elements: usize, fp_rate: f64, tweak: u32, flags: BloomFlags) -> Result<Self, BloomError> {
        // Validate parameters
        if fp_rate <= 0.0 || fp_rate >= 1.0 {
            return Err(BloomError::InvalidFalsePositiveRate);
        }
        
        // Calculate optimal filter size (BIP37 formula)
        let filter_size = (-1.0 * elements as f64 * fp_rate.ln() / (2.0_f64.ln().powi(2))).ceil() as usize;
        let filter_size = filter_size.max(1).min(MAX_BLOOM_FILTER_SIZE);
        
        // Calculate optimal number of hash functions
        let n_hash_funcs = ((filter_size * 8) as f64 / elements as f64 * 2.0_f64.ln()).round() as u32;
        let n_hash_funcs = n_hash_funcs.max(1).min(MAX_HASH_FUNCS);
        
        Ok(BloomFilter {
            data: vec![0u8; (filter_size + 7) / 8],
            n_hash_funcs,
            n_tweak: tweak,
            flags,
        })
    }
    
    /// Insert data into the filter
    pub fn insert(&mut self, data: &[u8]) {
        for i in 0..self.n_hash_funcs {
            let hash = self.hash(i, data);
            let index = (hash as usize) % (self.data.len() * 8);
            self.data[index / 8] |= 1 << (index & 7);
        }
    }
    
    /// Check if data might be in the filter
    pub fn contains(&self, data: &[u8]) -> bool {
        if self.is_full() {
            return true;
        }
        
        for i in 0..self.n_hash_funcs {
            let hash = self.hash(i, data);
            let index = (hash as usize) % (self.data.len() * 8);
            if self.data[index / 8] & (1 << (index & 7)) == 0 {
                return false;
            }
        }
        true
    }
    
    /// Calculate hash for given data and function index
    fn hash(&self, n_hash_num: u32, data: &[u8]) -> u32 {
        murmur3(data, n_hash_num.wrapping_mul(0xFBA4C795).wrapping_add(self.n_tweak))
    }
    
    /// Check if filter matches everything (all bits set)
    pub fn is_full(&self) -> bool {
        self.data.iter().all(|&byte| byte == 0xFF)
    }
    
    /// Clear the filter
    pub fn clear(&mut self) {
        self.data.fill(0);
    }
    
    /// Update filter based on flags when transaction is matched
    pub fn update_from_tx(&mut self, tx: &Transaction) {
        match self.flags {
            BloomFlags::None => {},
            BloomFlags::All => {
                // Add all outputs
                for (index, output) in tx.output.iter().enumerate() {
                    let outpoint = OutPoint::new(tx.compute_txid(), index as u32);
                    self.insert(&consensus::encode::serialize(&outpoint));
                }
            },
            BloomFlags::PubkeyOnly => {
                // Add only outputs that are pay-to-pubkey or pay-to-multisig
                for (index, output) in tx.output.iter().enumerate() {
                    if output.script_pubkey.is_p2pk() || output.script_pubkey.is_multisig() {
                        let outpoint = OutPoint::new(tx.compute_txid(), index as u32);
                        self.insert(&consensus::encode::serialize(&outpoint));
                    }
                }
            },
        }
    }
}

/// Constants from BIP37
const MAX_BLOOM_FILTER_SIZE: usize = 36_000; // 36KB
const MAX_HASH_FUNCS: u32 = 50;
```

### 2. Murmur3 Hash Implementation (`dash/src/bloom/hash.rs`)

```rust
/// MurmurHash3 as specified in BIP37
pub fn murmur3(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e2d51;
    const C2: u32 = 0x1b873593;
    const R1: u32 = 15;
    const R2: u32 = 13;
    const M: u32 = 5;
    const N: u32 = 0xe6546b64;
    
    let mut hash = seed;
    let mut chunks = data.chunks_exact(4);
    
    // Process 4-byte chunks
    for chunk in &mut chunks {
        let mut k = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        k = k.wrapping_mul(C1);
        k = k.rotate_left(R1);
        k = k.wrapping_mul(C2);
        
        hash ^= k;
        hash = hash.rotate_left(R2);
        hash = hash.wrapping_mul(M).wrapping_add(N);
    }
    
    // Process remaining bytes
    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        let mut k = 0u32;
        for (i, &byte) in remainder.iter().enumerate() {
            k |= (byte as u32) << (i * 8);
        }
        k = k.wrapping_mul(C1);
        k = k.rotate_left(R1);
        k = k.wrapping_mul(C2);
        hash ^= k;
    }
    
    // Finalization
    hash ^= data.len() as u32;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85ebca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2ae35);
    hash ^= hash >> 16;
    
    hash
}
```

### 3. SPV Bloom Filter Manager (`dash-spv/src/bloom/manager.rs`)

```rust
use dash::bloom::{BloomFilter, BloomFlags};
use dash::network::message_bloom::{FilterLoad, FilterAdd};
use crate::wallet::Wallet;

/// Manages bloom filter lifecycle for SPV client
pub struct BloomFilterManager {
    /// Current bloom filter
    filter: Option<BloomFilter>,
    /// False positive rate
    fp_rate: f64,
    /// Filter update flags
    flags: BloomFlags,
    /// Elements added since last filter load
    elements_added: usize,
    /// Maximum elements before filter reload
    max_elements: usize,
}

impl BloomFilterManager {
    pub fn new(fp_rate: f64, flags: BloomFlags) -> Self {
        Self {
            filter: None,
            fp_rate,
            flags,
            elements_added: 0,
            max_elements: 1000, // Reload filter after 1000 additions
        }
    }
    
    /// Build initial bloom filter from wallet
    pub fn build_from_wallet(&mut self, wallet: &Wallet) -> Result<FilterLoad, BloomError> {
        let addresses = wallet.get_all_addresses();
        let utxos = wallet.get_unspent_outputs();
        
        // Calculate total elements
        let total_elements = addresses.len() + utxos.len() + 100; // Extra capacity
        
        // Generate random tweak
        let tweak = rand::thread_rng().gen::<u32>();
        
        // Create filter
        let mut filter = BloomFilter::new(total_elements, self.fp_rate, tweak, self.flags)?;
        
        // Add addresses
        for address in &addresses {
            filter.insert(&address.to_script_pubkey().as_bytes());
        }
        
        // Add UTXOs
        for utxo in &utxos {
            filter.insert(&consensus::encode::serialize(&utxo.outpoint));
        }
        
        // Create FilterLoad message
        let filter_load = FilterLoad {
            filter: filter.clone(),
        };
        
        self.filter = Some(filter);
        self.elements_added = 0;
        
        Ok(filter_load)
    }
    
    /// Add element to filter
    pub fn add_element(&mut self, data: &[u8]) -> Option<FilterAdd> {
        if let Some(ref mut filter) = self.filter {
            filter.insert(data);
            self.elements_added += 1;
            
            // Return FilterAdd message
            Some(FilterAdd {
                data: data.to_vec(),
            })
        } else {
            None
        }
    }
    
    /// Check if filter needs reload
    pub fn needs_reload(&self) -> bool {
        self.elements_added >= self.max_elements || 
        self.filter.as_ref().map_or(false, |f| f.is_full())
    }
    
    /// Test if transaction matches filter
    pub fn matches_transaction(&self, tx: &Transaction) -> bool {
        if let Some(ref filter) = self.filter {
            // Check each output
            for output in &tx.output {
                if filter.contains(&output.script_pubkey.as_bytes()) {
                    return true;
                }
            }
            
            // Check each input's previous output
            for input in &tx.input {
                if filter.contains(&consensus::encode::serialize(&input.previous_output)) {
                    return true;
                }
            }
            
            false
        } else {
            // No filter means accept everything
            true
        }
    }
    
    /// Update filter after matching transaction
    pub fn update_from_transaction(&mut self, tx: &Transaction) {
        if let Some(ref mut filter) = self.filter {
            filter.update_from_tx(tx);
        }
    }
}
```

### 4. Integration with Mempool Filter (`dash-spv/src/mempool_filter.rs` modifications)

```rust
// Add to existing MempoolFilter implementation
impl MempoolFilter {
    pub fn should_fetch_transaction(
        &self, 
        txid: &Txid, 
        bloom_manager: Option<&BloomFilterManager>
    ) -> bool {
        match self.strategy {
            MempoolStrategy::FetchAll => true,
            MempoolStrategy::BloomFilter => {
                // Use bloom filter if available
                bloom_manager.map_or(false, |manager| {
                    // We can't check txid directly, need the full transaction
                    // Return true to fetch, then filter after receiving
                    true
                })
            },
            MempoolStrategy::Selective => {
                self.is_recently_sent(txid) || self.watching_addresses_involved(txid)
            },
        }
    }
    
    pub fn process_received_transaction(
        &mut self,
        tx: &Transaction,
        bloom_manager: Option<&mut BloomFilterManager>
    ) -> bool {
        match self.strategy {
            MempoolStrategy::BloomFilter => {
                if let Some(manager) = bloom_manager {
                    if manager.matches_transaction(tx) {
                        manager.update_from_transaction(tx);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            },
            _ => {
                // Existing logic for other strategies
                true
            }
        }
    }
}
```

### 5. Network Integration (`dash-spv/src/network/manager.rs` modifications)

```rust
// Add to Peer struct
pub struct Peer {
    // ... existing fields ...
    /// Bloom filter manager for this peer
    bloom_manager: Option<BloomFilterManager>,
}

// Add bloom filter message handling
impl Peer {
    /// Initialize bloom filter for this peer
    pub async fn setup_bloom_filter(&mut self, wallet: &Wallet) -> Result<(), Error> {
        if let MempoolStrategy::BloomFilter = self.config.mempool_strategy {
            let mut manager = BloomFilterManager::new(0.001, BloomFlags::All);
            let filter_load = manager.build_from_wallet(wallet)?;
            
            // Send filterload message
            self.send_message(NetworkMessage::FilterLoad(filter_load)).await?;
            
            self.bloom_manager = Some(manager);
        }
        Ok(())
    }
    
    /// Update bloom filter with new element
    pub async fn add_to_bloom_filter(&mut self, data: &[u8]) -> Result<(), Error> {
        if let Some(ref mut manager) = self.bloom_manager {
            if let Some(filter_add) = manager.add_element(data) {
                self.send_message(NetworkMessage::FilterAdd(filter_add)).await?;
            }
            
            // Check if filter needs reload
            if manager.needs_reload() {
                self.reload_bloom_filter().await?;
            }
        }
        Ok(())
    }
    
    /// Reload bloom filter
    async fn reload_bloom_filter(&mut self) -> Result<(), Error> {
        if let Some(ref mut manager) = self.bloom_manager {
            // Clear current filter
            self.send_message(NetworkMessage::FilterClear).await?;
            
            // Build and send new filter
            let filter_load = manager.build_from_wallet(&self.wallet)?;
            self.send_message(NetworkMessage::FilterLoad(filter_load)).await?;
        }
        Ok(())
    }
}
```

## Testing Strategy

### 1. Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bloom_filter_basic() {
        let mut filter = BloomFilter::new(10, 0.001, 0, BloomFlags::None).unwrap();
        
        // Insert and check
        let data = b"hello world";
        assert!(!filter.contains(data));
        filter.insert(data);
        assert!(filter.contains(data));
        
        // False positive rate
        let mut false_positives = 0;
        for i in 0..10000 {
            let test_data = format!("test{}", i);
            if filter.contains(test_data.as_bytes()) {
                false_positives += 1;
            }
        }
        assert!(false_positives < 20); // Should be ~0.1%
    }
    
    #[test]
    fn test_murmur3_vectors() {
        // Test vectors from BIP37
        assert_eq!(murmur3(b"", 0), 0);
        assert_eq!(murmur3(b"", 0xFBA4C795), 0x6a396f08);
        assert_eq!(murmur3(b"\x00", 0x00000000), 0x514e28b7);
        assert_eq!(murmur3(b"\x00\x00\x00\x00", 0x00000000), 0x2362f9de);
    }
    
    #[test]
    fn test_filter_update_flags() {
        let tx = create_test_transaction();
        
        // Test None flag
        let mut filter = BloomFilter::new(10, 0.01, 0, BloomFlags::None).unwrap();
        let initial = filter.clone();
        filter.update_from_tx(&tx);
        assert_eq!(filter, initial); // No change
        
        // Test All flag
        let mut filter = BloomFilter::new(100, 0.01, 0, BloomFlags::All).unwrap();
        filter.update_from_tx(&tx);
        // Should contain all outputs
        for (i, _) in tx.output.iter().enumerate() {
            let outpoint = OutPoint::new(tx.compute_txid(), i as u32);
            assert!(filter.contains(&consensus::encode::serialize(&outpoint)));
        }
    }
}
```

### 2. Integration Tests

```rust
#[tokio::test]
async fn test_bloom_filter_with_peer() {
    let mut peer = create_test_peer();
    let wallet = create_test_wallet();
    
    // Setup bloom filter
    peer.setup_bloom_filter(&wallet).await.unwrap();
    
    // Verify filter contains wallet addresses
    let manager = peer.bloom_manager.as_ref().unwrap();
    for addr in wallet.get_all_addresses() {
        assert!(manager.filter.as_ref().unwrap()
            .contains(&addr.to_script_pubkey().as_bytes()));
    }
    
    // Test adding new address
    let new_addr = wallet.get_new_address();
    peer.add_to_bloom_filter(&new_addr.to_script_pubkey().as_bytes())
        .await.unwrap();
}

#[tokio::test]
async fn test_bloom_filter_transaction_matching() {
    let manager = BloomFilterManager::new(0.001, BloomFlags::All);
    let wallet = create_test_wallet();
    
    // Build filter from wallet
    manager.build_from_wallet(&wallet).unwrap();
    
    // Create transaction to wallet address
    let tx = create_transaction_to_address(wallet.get_address());
    assert!(manager.matches_transaction(&tx));
    
    // Create transaction to unknown address
    let tx = create_transaction_to_address(random_address());
    assert!(!manager.matches_transaction(&tx));
}
```

### 3. Performance Tests

```rust
#[bench]
fn bench_bloom_filter_insert(b: &mut Bencher) {
    let mut filter = BloomFilter::new(10000, 0.001, 0, BloomFlags::None).unwrap();
    let data: Vec<Vec<u8>> = (0..1000)
        .map(|i| format!("test{}", i).into_bytes())
        .collect();
    
    b.iter(|| {
        for d in &data {
            filter.insert(d);
        }
    });
}

#[bench]
fn bench_bloom_filter_contains(b: &mut Bencher) {
    let mut filter = BloomFilter::new(10000, 0.001, 0, BloomFlags::None).unwrap();
    for i in 0..1000 {
        filter.insert(&format!("test{}", i).into_bytes());
    }
    
    b.iter(|| {
        for i in 0..1000 {
            filter.contains(&format!("test{}", i).into_bytes());
        }
    });
}
```

## Security Considerations

### 1. Privacy Implications
- Bloom filters reveal approximate wallet contents to peers
- False positive rate should be tuned to balance privacy vs bandwidth
- Consider warning users about privacy trade-offs

### 2. DoS Protection
- Limit filter size to MAX_BLOOM_FILTER_SIZE (36KB)
- Limit hash functions to MAX_HASH_FUNCS (50)
- Implement rate limiting for filter updates
- Monitor for peers sending excessive filteradd messages

### 3. Validation
- Validate all parameters before creating filters
- Check for malformed filter data in network messages
- Ensure filters don't consume excessive memory

## Migration Plan

### Phase 1: Core Implementation
1. Implement BloomFilter in dash crate
2. Add comprehensive unit tests
3. Ensure compatibility with existing message types

### Phase 2: SPV Integration
1. Implement BloomFilterManager
2. Integrate with MempoolFilter
3. Update Peer to handle bloom filters
4. Add integration tests

### Phase 3: FFI Updates
1. Expose bloom filter configuration in FFI
2. Add callbacks for filter events
3. Update Swift SDK bindings

### Phase 4: Documentation
1. Update API documentation
2. Add usage examples
3. Document privacy implications

## Configuration

### SPV Client Configuration
```rust
pub struct BloomFilterConfig {
    /// False positive rate (0.0001 - 0.01 recommended)
    pub false_positive_rate: f64,
    /// Filter update behavior
    pub flags: BloomFlags,
    /// Maximum elements before filter reload
    pub max_elements_before_reload: usize,
    /// Enable automatic filter updates
    pub auto_update: bool,
}

impl Default for BloomFilterConfig {
    fn default() -> Self {
        Self {
            false_positive_rate: 0.001,
            flags: BloomFlags::All,
            max_elements_before_reload: 1000,
            auto_update: true,
        }
    }
}
```

## API Examples

### Basic Usage
```rust
// Create SPV client with bloom filter
let config = SPVClientConfig {
    mempool_strategy: MempoolStrategy::BloomFilter,
    bloom_config: Some(BloomFilterConfig {
        false_positive_rate: 0.001,
        flags: BloomFlags::All,
        ..Default::default()
    }),
    ..Default::default()
};

let client = SPVClient::new(config);
client.connect().await?;

// Filter will be automatically managed
// Transactions matching wallet addresses will be received
```

### Manual Filter Management
```rust
// Create bloom filter manually
let mut filter = BloomFilter::new(100, 0.001, rand::random(), BloomFlags::PubkeyOnly)?;

// Add addresses
for addr in wallet.get_addresses() {
    filter.insert(&addr.to_script_pubkey().as_bytes());
}

// Send to peer
peer.send_filter_load(filter).await?;

// Add new element
peer.send_filter_add(new_address.to_script_pubkey().as_bytes()).await?;
```

## Performance Metrics

### Expected Performance
- Filter creation: < 1ms for 1000 elements
- Insert operation: O(k) where k = number of hash functions
- Contains check: O(k) 
- Memory usage: ~4.5KB for 0.1% FPR with 1000 elements

### Bandwidth Savings
- Full blocks: ~1-2MB per block
- With bloom filters: ~10-100KB per block (depending on wallet activity)
- Vs compact filters: More efficient for active wallets, less private

## Future Enhancements

1. **Adaptive Filter Sizing**: Automatically adjust filter size based on false positive rate
2. **Multi-peer Filters**: Different filters for different peers to improve privacy
3. **Filter Compression**: Compress filter data for network transmission
4. **Hybrid Mode**: Use bloom filters for recent blocks, compact filters for historical data
5. **Metrics**: Track filter performance and false positive rates

## Conclusion

This specification provides a complete blueprint for implementing BIP37 bloom filters in rust-dashcore. The implementation prioritizes:
- Compatibility with existing Dash network nodes
- Performance for resource-constrained devices
- Flexibility in privacy/efficiency trade-offs
- Robust error handling and security

The modular design allows gradual rollout and easy testing of each component independently.