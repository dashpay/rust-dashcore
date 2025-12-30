# UTXO Rollback Mechanism

## Overview

The UTXO rollback mechanism provides robust handling of blockchain reorganizations in dash-spv. It tracks UTXO state changes and transaction confirmations, allowing the wallet to properly restore its state when the blockchain reorganizes.

## Key Components

### 1. UTXORollbackManager

The core component that manages UTXO state tracking and rollback functionality.

**Features:**
- Tracks UTXO creation and spending
- Maintains transaction confirmation status
- Creates snapshots at each block height
- Handles rollback to previous states
- Supports persistence for recovery

**Usage:**
```rust
use dash_spv::wallet::{UTXORollbackManager, WalletState};

// Create wallet state with rollback support
let mut wallet_state = WalletState::with_rollback(Network::Testnet, true);

// Or initialize from storage
wallet_state.init_rollback_from_storage(&storage, true).await?;
```

### 2. UTXOSnapshot

Represents the UTXO state at a specific block height.

**Contains:**
- Block height and hash
- UTXO changes (created/spent/status changed)
- Transaction status changes
- Total UTXO count
- Timestamp

### 3. TransactionStatus

Tracks the confirmation status of transactions:
- `Unconfirmed` - Transaction in mempool
- `Confirmed(height)` - Transaction confirmed at specific height
- `Conflicted` - Transaction conflicted by another transaction
- `Abandoned` - Transaction removed from mempool

### 4. UTXOChange

Represents changes to UTXO state:
- `Created(Utxo)` - New UTXO created
- `Spent(OutPoint)` - UTXO was spent
- `StatusChanged` - UTXO confirmation status changed

## Integration with ReorgManager

The UTXO rollback mechanism is fully integrated with the `ReorgManager`:

```rust
// During reorganization
let reorg_event = reorg_manager.reorganize(
    &mut chain_state,
    &mut wallet_state,
    &fork,
    &chain_storage,
    &mut storage_manager,
).await?;
```

The reorganization process:
1. Finds common ancestor between chains
2. Rolls back wallet state to common ancestor
3. Disconnects blocks from old chain
4. Connects blocks from new chain
5. Reprocesses transactions in new chain

## Usage Examples

### Basic Block Processing

```rust
// Process a new block
wallet_state.process_block_with_rollback(
    height,
    block_hash,
    &transactions,
    &mut storage,
).await?;
```

### Manual Rollback

```rust
// Rollback to specific height
wallet_state.rollback_to_height(target_height, &mut storage).await?;
```

### Transaction Status Tracking

```rust
// Check transaction status
let status = wallet_state.get_transaction_status(&txid);

// Mark transaction as conflicted
wallet_state.mark_transaction_conflicted(&txid);
```

### Accessing Rollback Information

```rust
// Get rollback manager
if let Some(rollback_mgr) = wallet_state.rollback_manager() {
    // Get latest snapshot
    let snapshot = rollback_mgr.get_latest_snapshot();
    
    // Get UTXO count
    let count = rollback_mgr.get_utxo_count();
    
    // Get snapshots in range
    let snapshots = rollback_mgr.get_snapshots_in_range(start, end);
}
```

## Configuration

### Snapshot Limits

By default, the system maintains up to 100 snapshots. This can be configured:

```rust
let rollback_mgr = UTXORollbackManager::with_max_snapshots(200, true);
```

### Persistence

Snapshots can be persisted to storage for recovery:

```rust
// Enable persistence
let wallet_state = WalletState::with_rollback(network, true);

// Snapshots are automatically saved to storage
// and loaded on initialization
```

## Testing

Comprehensive tests are provided in `tests/utxo_rollback_test.rs`:

```bash
cargo test utxo_rollback
```

Test scenarios include:
- Basic rollback functionality
- Transaction status tracking
- Complex reorganization scenarios
- Snapshot persistence
- Conflicting transactions
- Consistency validation

## Error Handling

The rollback mechanism provides detailed error information:

```rust
match wallet_state.rollback_to_height(height, &mut storage).await {
    Ok(snapshots) => {
        // Process rolled back snapshots
    }
    Err(e) => {
        // Handle error
        eprintln!("Rollback failed: {:?}", e);
    }
}
```

## Performance Considerations

1. **Memory Usage**: Each snapshot stores UTXO changes, not full state
2. **Snapshot Limits**: Automatic pruning of old snapshots
3. **Persistence**: Optional to reduce I/O overhead
4. **Validation**: Consistency checks can be run periodically

## Future Enhancements

1. **Compression**: Compress snapshot data for storage efficiency
2. **Checkpointing**: Create full state checkpoints at intervals
3. **Parallel Processing**: Process multiple blocks in parallel
4. **Recovery Tools**: CLI tools for manual state recovery
5. **Metrics**: Performance metrics and monitoring

## Security Considerations

1. **State Validation**: Regular consistency checks prevent corruption
2. **Atomic Operations**: All state changes are atomic
3. **Rollback Limits**: Maximum reorg depth prevents deep rollbacks
4. **Chain Locks**: Integration with Dash chain locks for finality
