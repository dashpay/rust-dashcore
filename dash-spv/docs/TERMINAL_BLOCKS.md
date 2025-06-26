# Terminal Blocks System

## Overview

Terminal blocks are predefined blockchain heights where masternode list states are known to be accurate. They serve as optimization checkpoints for masternode synchronization, allowing nodes to start syncing from a known-good state instead of from genesis.

## Benefits

1. **Reduced Network Traffic**: Instead of requesting a diff from genesis (0 → current), nodes request a smaller diff (terminal block → current)
2. **Faster Sync Times**: Skip processing hundreds of thousands of blocks worth of masternode changes
3. **Lower Memory Usage**: Don't need to process the entire masternode history
4. **Proven Security**: Terminal blocks are validated checkpoints in the blockchain

## How It Works

### Sync Flow

1. Node starts masternode sync
2. Checks for pre-calculated masternode data at terminal blocks
3. Validates terminal block exists in the blockchain
4. Uses terminal block as base for requesting masternode diff
5. Requests diff from terminal block to current tip
6. Falls back to genesis if terminal block validation fails

### Example

Without terminal blocks:
```
Request: Genesis (0) → Current (1,276,272)
Diff size: ~500MB, covering 1.2M blocks
```

With terminal blocks:
```
Request: Terminal Block (900,000) → Current (1,276,272)
Diff size: ~100MB, covering 376K blocks
```

## Terminal Block Heights

### Testnet
- 900,000 - Latest terminal block

### Mainnet
- 2,000,000 - Latest terminal block

## Data Structure

Each terminal block contains:
```json
{
  "height": 900000,
  "block_hash": "0000011764a05571e0b3963b1422a8f3771e4c0d5b72e9b8e0799aabf07d28ef",
  "merkle_root_mn_list": "bb98f57eb724d5447b979cf2107f15b872a7289d95fb66ba2a92774e1f4b7748",
  "masternode_count": 514,
  "masternode_list": [
    {
      "pro_tx_hash": "...",
      "service": "IP:port",
      "pub_key_operator": "...",
      "voting_address": "...",
      "is_valid": true,
      "n_type": 0
    }
  ],
  "fetched_at": 1234567890
}
```

## Updating Terminal Block Data

### Prerequisites

1. Running Dash Core node (mainnet and/or testnet)
2. Python 3.x
3. Access to `dash-cli`

### Fetching Data

```bash
# Fetch testnet data
python3 scripts/fetch_terminal_blocks.py /path/to/dash-cli testnet

# Fetch mainnet data
python3 scripts/fetch_terminal_blocks.py /path/to/dash-cli mainnet
```

This will:
1. Query each terminal block height
2. Fetch masternode list state at that height
3. Save to `data/[network]/terminal_block_[height].json`
4. Generate Rust module to include the data

### Data Sizes

- Testnet: ~190KB (1 terminal block)
- Mainnet: ~1.4MB (1 terminal block)

## Implementation Details

### Validation

All terminal block data is validated when loaded:
- Block hash format (64 hex chars)
- Merkle root format (64 hex chars)
- ProTxHash format (64 hex chars)
- BLS public key format (96 hex chars)
- Service address format (IP:port)
- Masternode count matches list length

Invalid data is rejected with warnings logged.

### Security Considerations

1. **Block Hash Verification**: Terminal block hash must match the actual block in the chain
2. **Merkle Root Validation**: Future enhancement to validate masternode list merkle root
3. **Fallback Mechanism**: Always falls back to genesis if terminal block fails
4. **No Trust Required**: Terminal blocks are just optimization hints

### Current Limitations

1. **Static Data**: Terminal block data is compiled into the binary
2. **Manual Updates**: Requires recompilation to update terminal blocks
3. **No Merkle Proof**: Currently doesn't verify masternode list merkle root

## Future Enhancements

1. **Dynamic Loading**: Load terminal block data at runtime
2. **Merkle Verification**: Validate masternode list against merkle root
3. **Compression**: Use binary format to reduce data size
4. **Automatic Updates**: Fetch new terminal blocks as chain grows

## Testing

Run terminal block tests:
```bash
cargo test --test terminal_block_test
```

Example usage:
```rust
let manager = TerminalBlockManager::new(Network::Testnet);
if let Some(data) = manager.find_best_terminal_block_with_data(current_height) {
    println!("Using terminal block {} with {} masternodes", 
             data.height, data.masternode_count);
}
```