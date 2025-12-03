# SPV Wallet with Compact Filters (BIP 157/158)

This guide explains how the filter-based SPV wallet implementation works and how to use it.

## Overview

The system implements a lightweight SPV (Simplified Payment Verification) wallet using compact block filters as specified in BIP 157 and BIP 158. This approach provides:

- **95% bandwidth savings** compared to downloading full blocks
- **Privacy**: Servers don't learn which addresses belong to the wallet
- **Efficiency**: Only download blocks containing relevant transactions
- **Security**: Full SPV validation with merkle proofs

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   FilterSPVClient                    │
│                                                      │
│  ┌─────────────────┐       ┌──────────────────┐    │
│  │  FilterClient   │◄──────►│  WalletManager   │    │
│  │                 │       │                   │    │
│  │ - Check filters │       │ - Manage wallets  │    │
│  │ - Fetch blocks  │       │ - Track UTXOs     │    │
│  │ - Process txs   │       │ - Update balances │    │
│  └────────┬────────┘       └──────────────────┘    │
│           │                                         │
│           ▼                                         │
│  ┌─────────────────┐                               │
│  │ Network Layer   │                               │
│  │                 │                               │
│  │ - P2P Protocol  │                               │
│  │ - Fetch filters │                               │
│  │ - Fetch blocks  │                               │
│  └─────────────────┘                               │
└─────────────────────────────────────────────────────┘
```

## Workflow

### 1. Initial Setup

```rust
use key_wallet_manager::{FilterSPVClient, Network};

// Create SPV client
let mut spv_client = FilterSPVClient::new(Network::Testnet);

// Add wallet from mnemonic
spv_client.add_wallet(
    "main_wallet".to_string(),
    "My Wallet".to_string(),
    mnemonic,
    passphrase,
    Some(birth_height), // Start scanning from this height
)?;
```

### 2. Filter Processing Flow

```
For each new block:
    1. Receive compact filter from network
    2. Check if filter matches any of:
       - Our addresses (watched scripts)
       - Our UTXOs (watched outpoints)
    3. If match found:
       - Fetch full block
       - Process transactions
       - Update wallet state
    4. If no match:
       - Skip block (save bandwidth)
```

### 3. Filter Matching

The system watches two types of data:

#### Watched Scripts (Addresses)
- All addresses generated for the wallet
- Automatically updated when new addresses are created
- Matched against transaction outputs

#### Watched Outpoints (UTXOs)
- All unspent transaction outputs owned by the wallet
- Automatically updated when receiving/spending
- Matched against transaction inputs (spending detection)

### 4. Processing Matched Blocks

When a filter matches, the system:

1. **Fetches the full block** from the network
2. **Processes each transaction**:
   - Check outputs for payments to our addresses
   - Check inputs for spending of our UTXOs
3. **Updates wallet state**:
   - Add new UTXOs
   - Remove spent UTXOs
   - Update balances
   - Record transaction history

## Implementation Details

### Compact Filters (BIP 158)

Compact filters use Golomb-Rice coding to create a probabilistic data structure:

- **Size**: ~1/20th of the full block
- **False positive rate**: 1 in 784,931
- **No false negatives**: If your transaction is in the block, the filter will match

### Filter Chain Validation

The system maintains a chain of filter headers for validation:

```rust
FilterHeader {
    filter_type: FilterType::Basic,
    block_hash: [u8; 32],
    prev_header: [u8; 32],  // Hash of previous filter header
    filter_hash: [u8; 32],   // Hash of this block's filter
}
```

### Address Gap Limit

The wallet implements BIP 44 gap limit handling:

- Default gap limit: 20 addresses
- Automatically generates new addresses when used
- Tracks both receive and change addresses separately

## Usage Example

```rust
// Process incoming filter
let filter = receive_filter_from_network();
let block_hash = BlockHash::from_slice(&filter.block_hash)?;

// Check if we need this block
match spv_client.process_new_filter(height, block_hash, filter)? {
    Some(result) => {
        println!("Found {} relevant transactions", result.relevant_txs.len());
        println!("New UTXOs: {}", result.new_outpoints.len());
        println!("Spent UTXOs: {}", result.spent_outpoints.len());
    }
    None => {
        println!("Block not relevant, skipping");
    }
}

// Check balance
let (confirmed, unconfirmed) = spv_client.get_balance("main_wallet")?;
println!("Balance: {} confirmed, {} unconfirmed", confirmed, unconfirmed);
```

## Network Integration

To integrate with a P2P network, implement the trait interfaces:

```rust
impl BlockFetcher for YourNetworkClient {
    fn fetch_block(&mut self, block_hash: &BlockHash) -> Result<Block, FetchError> {
        // Send getdata message
        // Wait for block response
        // Return parsed block
    }
}

impl FilterFetcher for YourNetworkClient {
    fn fetch_filter(&mut self, block_hash: &BlockHash) -> Result<CompactFilter, FetchError> {
        // Send getcfilters message
        // Wait for cfilter response
        // Return parsed filter
    }
}
```

## Performance Characteristics

### Bandwidth Usage

| Method | Data Downloaded | Privacy | Speed |
|--------|----------------|---------|-------|
| Full Node | 100% of blocks | Full | Slow |
| Traditional SPV | 100% of blocks with txs | Low | Medium |
| **Compact Filters** | ~5% of blocks | High | Fast |

### Storage Requirements

- **Headers**: ~4 MB per year
- **Filters**: ~50 MB per year
- **Relevant blocks**: Only blocks with your transactions
- **Total**: <100 MB for typical wallet

## Security Considerations

1. **SPV Security**: Validates proof-of-work and merkle proofs
2. **Privacy**: Server doesn't know which addresses are yours
3. **Filter Validation**: Validates filter chain to prevent omission attacks
4. **Multiple Peers**: Should connect to multiple peers for security

## Testing

Run the example:

```bash
cargo run --example spv_wallet
```

Run tests:

```bash
cargo test -p key-wallet-manager
```

## Future Enhancements

- [ ] Batch filter requests for efficiency
- [ ] Filter caching and persistence
- [ ] Peer rotation for privacy
- [ ] Tor/proxy support
- [ ] Lightning Network integration
- [ ] Hardware wallet support

## References

- [BIP 157: Client Side Block Filtering](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki)
- [BIP 158: Compact Block Filters](https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki)
- [Neutrino Protocol](https://github.com/lightninglabs/neutrino)
