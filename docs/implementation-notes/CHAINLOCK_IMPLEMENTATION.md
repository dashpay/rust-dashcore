# ChainLock (DIP8) Implementation for dash-spv

This document describes the implementation of ChainLock validation (DIP8) for the dash-spv Rust client, providing protection against 51% attacks and securing InstantSend transactions.

## Overview

ChainLocks use Long Living Masternode Quorums (LLMQs) to sign and lock blocks, preventing chain reorganizations past locked blocks. When a quorum of masternodes (240 out of 400) agrees on a block as the first seen at a specific height, they create a ChainLock signature that all nodes must respect.

## Key Components

### 1. ChainLockManager (`src/chain/chainlock_manager.rs`)
- Manages ChainLock validation and storage
- Maintains in-memory cache of chain locks by height and hash
- Integrates with storage layer for persistence
- Provides methods to check if blocks are chain-locked
- Enforces chain lock rules during validation

### 2. ChainLockValidator (`src/validation/chainlock.rs`)
- Performs structural validation of ChainLock messages
- Validates timing constraints (not too far in future/past)
- Constructs signing messages according to DIP8 spec
- Handles quorum signature validation (when masternode list available)

### 3. QuorumManager (`src/validation/quorum.rs`)
- Manages LLMQ quorum information for validation
- Tracks active quorums by type (ChainLock vs InstantSend)
- Validates BLS threshold signatures
- Ensures quorum age requirements are met

### 4. ReorgManager Integration (`src/chain/reorg.rs`)
- Enhanced to respect chain locks during reorganization
- Prevents reorganizations past chain-locked blocks
- Can be configured to enable/disable chain lock enforcement

### 5. Storage Layer
- Added chain lock storage methods to StorageManager trait
- Implemented in both MemoryStorageManager and DiskStorageManager
- Persistent storage of chain locks by height

### 6. ChainState Updates (`src/types.rs`)
- Added chain lock tracking to ChainState
- Methods to update and query chain lock status
- Track last chain-locked height and hash

## Security Features

1. **51% Attack Prevention**: Once a block is chain-locked, it cannot be reorganized even with majority hashpower
2. **InstantSend Security**: Chain locks provide finality for InstantSend transactions
3. **Quorum Validation**: Requires 60% threshold (240/400) signatures from masternode quorum
4. **Timing Validation**: Prevents acceptance of far-future chain locks

## Usage Example

```rust
use dash_spv::chain::ChainLockManager;
use dash_spv::validation::QuorumManager;

// Create managers
let chain_lock_mgr = Arc::new(ChainLockManager::new(true));
let quorum_mgr = QuorumManager::new();

// Process incoming chain lock
let chain_lock = ChainLock {
    block_height: 1000,
    block_hash: block_hash,
    signature: bls_signature,
};

chain_lock_mgr.process_chain_lock(
    chain_lock,
    &chain_state,
    &mut storage
).await?;

// Check if block is chain-locked
if chain_lock_mgr.is_block_chain_locked(&block_hash, height) {
    println!("Block is chain-locked and cannot be reorganized");
}
```

## Testing

Comprehensive tests are provided in `tests/chainlock_test.rs` covering:
- Basic chain lock validation
- Storage and retrieval
- Reorg prevention
- Timing constraints
- Quorum management

## Future Enhancements

1. **BLS Signature Verification**: Currently stubbed out, needs full BLS library integration
2. **Masternode List Integration**: Automatic quorum extraction from masternode list
3. **Network Message Handling**: Full CLSig message processing from P2P network
4. **Performance Optimization**: Batch validation of multiple chain locks

## Configuration

Chain lock enforcement can be configured when creating the ChainLockManager:
- `ChainLockManager::new(true)` - Enforce chain locks (production)
- `ChainLockManager::new(false)` - Disable enforcement (testing only)

## References

- [DIP8: ChainLocks](https://github.com/dashpay/dips/blob/master/dip-0008.md)
- [Dash Core Implementation](https://github.com/dashpay/dash/pull/2643)
- [Long Living Masternode Quorums](https://www.dash.org/blog/long-living-masternode-quorums/)