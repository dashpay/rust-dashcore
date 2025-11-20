# QuorumLookup Component Guide

## Overview

The `QuorumLookup` component provides thread-safe, shareable access to masternode lists and quorum data without requiring exclusive access to the `DashSpvClient`.

## Problem Solved

Previously, applications needed to wrap `DashSpvClient` in `Arc<AsyncRwLock<_>>` to perform quorum queries from multiple threads. This was problematic because:

1. **DashSpvClient is designed as single-owner** - The `sync_manager` field uses a "Single Owner Pattern" and cannot be shared
2. **Double-locking overhead** - Adding `RwLock` on top of client's internal locks created performance issues
3. **No Clone implementation** - The client cannot be cheaply cloned and shared

## Solution: QuorumLookup

The `QuorumLookup` component is a **shared, thread-safe interface** that wraps the masternode engine and provides quorum query methods.

### Architecture

```
DashSpvClient
    ├── sync_manager (NOT shareable - single owner)
    ├── chainlock_manager: Arc<ChainLockManager> (shareable)
    └── quorum_lookup: Arc<QuorumLookup> (shareable) ✨ NEW
```

## Usage

### Basic Usage

```rust
use dash_spv::client::DashSpvClient;

// Create your SPV client (single instance)
let client = DashSpvClient::new(config, network, storage, wallet).await?;

// Get the QuorumLookup component
let quorum_lookup = client.quorum_lookup();

// Clone it for use in different parts of your app
let lookup_for_manager = quorum_lookup.clone();
let lookup_for_handler = quorum_lookup.clone();

// Use in async tasks
tokio::spawn(async move {
    if let Some(quorum) = lookup_for_manager
        .get_quorum_at_height(height, quorum_type, &quorum_hash)
        .await
    {
        // Use the quorum data
        let public_key = &quorum.quorum_entry.quorum_public_key;
        println!("Found quorum with public key: {:?}", public_key);
    }
});
```

### Integration Example

For your app's architecture where you have a manager that needs quorum lookups:

```rust
struct MyAppManager {
    // Store the QuorumLookup, not the whole client
    quorum_lookup: Arc<QuorumLookup>,
}

impl MyAppManager {
    pub fn new(client: &DashSpvClient<W, N, S>) -> Self {
        Self {
            quorum_lookup: client.quorum_lookup().clone(),
        }
    }

    pub async fn handle_quorum_query(
        &self,
        height: u32,
        quorum_type: u8,
        quorum_hash: &[u8; 32],
    ) -> Result<(), String> {
        match self.quorum_lookup.get_quorum_at_height(height, quorum_type, quorum_hash).await {
            Some(quorum) => {
                // Process the quorum
                println!("Found quorum!");
                Ok(())
            }
            None => Err("Quorum not found".to_string()),
        }
    }
}
```

## Available Methods

### Query Methods

#### `get_quorum_at_height(height, quorum_type, quorum_hash) -> Option<QualifiedQuorumEntry>`

Query a specific quorum by height, type, and hash.

**Parameters:**
- `height: u32` - Block height
- `quorum_type: u8` - LLMQ type (e.g., 1 for LLMQ_TYPE_50_60, 4 for LLMQ_TYPE_400_60)
- `quorum_hash: &[u8; 32]` - 32-byte quorum hash

**Returns:**
- `Some(quorum)` if found
- `None` if masternode sync incomplete or quorum not found

**Example:**
```rust
let quorum_hash = [0u8; 32]; // Your quorum hash
if let Some(quorum) = quorum_lookup
    .get_quorum_at_height(100000, 1, &quorum_hash)
    .await
{
    let public_key = &quorum.quorum_entry.quorum_public_key;
    // Use the public key for validation
}
```

#### `get_masternode_list_at_height(height) -> Option<MasternodeList>`

Get the complete masternode list at a specific height.

**Example:**
```rust
if let Some(ml) = quorum_lookup.get_masternode_list_at_height(100000).await {
    println!("Masternode list has {} masternodes", ml.masternodes.len());
}
```

### Status Methods

#### `is_available() -> bool`

Check if the masternode engine is available (i.e., masternode sync has completed).

**Example:**
```rust
if quorum_lookup.is_available() {
    // Can perform queries
} else {
    // Still syncing masternode data
}
```

#### `masternode_list_count() -> usize`

Get the number of masternode lists currently stored.

**Example:**
```rust
let count = quorum_lookup.masternode_list_count();
println!("Have {} masternode lists", count);
```

#### `masternode_list_height_range() -> Option<(u32, u32)>`

Get the height range of available masternode lists.

**Returns:**
- `Some((min_height, max_height))` if lists are available
- `None` if no lists available yet

**Example:**
```rust
if let Some((min, max)) = quorum_lookup.masternode_list_height_range() {
    println!("Can query quorums from height {} to {}", min, max);
}
```

## When Does QuorumLookup Become Available?

The `QuorumLookup` component is populated with the masternode engine when:

1. **Masternode sync completes** - The SPV client syncs masternode lists from the network
2. **`update_chainlock_validation()` is called** - This happens automatically during sync

You can check availability:

```rust
// Poll until available
while !quorum_lookup.is_available() {
    tokio::time::sleep(Duration::from_secs(1)).await;
}
println!("QuorumLookup is now ready!");
```

## Migration Guide

### Before (Problematic Pattern)

```rust
// ❌ OLD WAY - Don't do this
use tokio::sync::RwLock as AsyncRwLock;

struct App {
    client: Arc<AsyncRwLock<Option<DashSpvClient<W, N, S>>>>,
}

impl App {
    async fn query_quorum(&self) -> Result<()> {
        let client = self.client.read().await;
        if let Some(ref client) = *client {
            // Had to use get_quorum_at_height which blocks
            if let Some(quorum) = client.get_quorum_at_height(height, type, hash) {
                // Use quorum
            }
        }
        Ok(())
    }
}
```

### After (Recommended Pattern)

```rust
// ✅ NEW WAY - Use QuorumLookup
use dash_spv::client::QuorumLookup;

struct App {
    client: DashSpvClient<W, N, S>,  // Direct ownership
    quorum_lookup: Arc<QuorumLookup>, // Shared component
}

impl App {
    fn new(client: DashSpvClient<W, N, S>) -> Self {
        let quorum_lookup = client.quorum_lookup().clone();
        Self { client, quorum_lookup }
    }

    async fn query_quorum(&self) -> Result<()> {
        // Direct async call, no locking
        if let Some(quorum) = self.quorum_lookup
            .get_quorum_at_height(height, type, hash)
            .await
        {
            // Use quorum
        }
        Ok(())
    }
}
```

## Performance Benefits

1. **No double-locking** - Only one `RwLock` inside `QuorumLookup`, not wrapped around the client
2. **Concurrent reads** - Multiple threads can query simultaneously
3. **Cheap cloning** - `Arc::clone()` is just a pointer increment
4. **Non-blocking** - Async methods don't block the executor

## Thread Safety

The `QuorumLookup` uses:
- **Outer `Arc`** - Allows cheap cloning and sharing across threads
- **Inner `RwLock`** - Provides multiple concurrent readers, exclusive writer
- **Inner `Arc<MasternodeListEngine>`** - Avoids deep copying on queries

This means:
- ✅ Multiple threads can query concurrently
- ✅ Updates are exclusive (only during sync)
- ✅ No risk of deadlocks
- ✅ No panics from poisoned locks (uses `expect` which should never fail in normal operation)

## Complete Example

See `examples/quorum_lookup_example.rs` for a runnable example:

```bash
cargo run --example quorum_lookup_example
```

## Testing

The implementation includes comprehensive tests:

```bash
# Run QuorumLookup tests
cargo test --lib quorum_lookup

# Run all dash-spv tests
cargo test --lib -p dash-spv
```

## Summary

| Feature | Before | After |
|---------|--------|-------|
| Client wrapping | `Arc<AsyncRwLock<Option<Client>>>` | Direct ownership |
| Quorum queries | Blocking sync method | Async method |
| Thread sharing | Difficult (client not clonable) | Easy (`Arc::clone()`) |
| Performance | Double-locking overhead | Single lock |
| Concurrency | One query at a time | Multiple concurrent queries |
| Complexity | High | Low |

The `QuorumLookup` component solves the architectural challenge of performing quorum queries from multiple threads without compromising the SPV client's single-owner design pattern.
