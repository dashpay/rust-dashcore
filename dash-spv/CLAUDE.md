# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**dash-spv** is a Rust implementation of a Dash SPV (Simplified Payment Verification) client library built on top of the `dashcore` library. It provides a modular, async/await-based architecture for connecting to the Dash network, synchronizing blockchain data, and monitoring transactions.

## Architecture

The project follows a layered, trait-based architecture with clear separation of concerns:

### Core Modules
- **`client/`**: High-level client API (`DashSpvClient`) and configuration (`ClientConfig`)
- **`network/`**: TCP connections, handshake management, message routing, and peer management
- **`storage/`**: Storage abstraction with memory and disk backends via `StorageManager` trait
- **`sync/`**: Synchronization coordinators for headers, filters, and masternode data
- **`sync/sequential/`**: Sequential sync manager that handles all synchronization phases
- **`validation/`**: Header validation, ChainLock, and InstantLock verification
- **`wallet/`**: UTXO tracking, balance calculation, and transaction processing
- **`types.rs`**: Common data structures (`SyncProgress`, `ValidationMode`, `WatchItem`, etc.)
- **`error.rs`**: Unified error handling with domain-specific error types

### Key Design Patterns
- **Trait-based abstractions**: `NetworkManager`, `StorageManager` for swappable implementations
- **Async/await throughout**: Built on tokio runtime
- **Sequential sync**: Uses `SequentialSyncManager` for organized phase-based synchronization
- **State management**: Each sync phase tracked independently with clear state transitions
- **Modular validation**: Configurable validation modes (None/Basic/Full)

## Development Commands

### Building and Running
```bash
# Build the library
cargo build

# Run the SPV client binary
cargo run --bin dash-spv -- --network mainnet --data-dir ./spv-data

# Run with custom peer
cargo run --bin dash-spv -- --peer 192.168.1.100:9999

# Run examples
cargo run --example simple_sync
cargo run --example filter_sync
```

### Testing

**Unit and Integration Tests:**
```bash
# Run all tests
cargo test

# Run specific test files
cargo test --test handshake_test
cargo test --test header_sync_test
cargo test --test storage_test
cargo test --test integration_real_node_test

# Run individual test functions
cargo test --test handshake_test test_handshake_with_mainnet_peer

# Run tests with output
cargo test -- --nocapture

# Run single test with debug output
cargo test --test handshake_test test_handshake_with_mainnet_peer -- --nocapture
```

**Integration Tests with Real Node:**
The integration tests in `tests/integration_real_node_test.rs` connect to a live Dash Core node at `127.0.0.1:9999`. These tests gracefully skip if no node is available.

```bash
# Run real node integration tests
cargo test --test integration_real_node_test -- --nocapture

# Test specific real node functionality
cargo test --test integration_real_node_test test_real_header_sync_genesis_to_1000 -- --nocapture
```

See `run_integration_tests.md` for detailed setup instructions.

### Code Quality
```bash
# Check formatting
cargo fmt --check

# Run linter
cargo clippy --all-targets --all-features -- -D warnings

# Check all features compile
cargo check --all-features
```

## Key Concepts

### Sync Coordination
The `SequentialSyncManager` coordinates all synchronization through a phase-based approach:
- **Phase 1: Headers** - Synchronize blockchain headers
- **Phase 2: Masternode List** - Download masternode state
- **Phase 3: Filter Headers** - Synchronize compact filter headers
- **Phase 4: Filters** - Download specific filters on demand
- **Phase 5: Blocks** - Download blocks that match filters

Each phase must complete before the next begins, ensuring consistency and simplifying error recovery.

### Storage Backends
Two storage implementations via the `StorageManager` trait:
- `MemoryStorageManager`: In-memory storage for testing
- `DiskStorageManager`: Persistent disk storage for production

### Network Layer
TCP-based networking with proper Dash protocol implementation:
- **DNS-first peer discovery**: Automatically uses DNS seeds (`dnsseed.dash.org`, `testnet-seed.dashdot.io`) when no explicit peers are configured
- **Immediate startup**: No delay for initial peer discovery (10-second delay only for subsequent searches)
- **Exclusive mode**: When explicit peers are provided, uses only those peers (no DNS discovery)
- Connection management via `TcpConnection`
- Handshake handling via `HandshakeManager`
- Message routing via `MessageHandler`
- Peer support via `PeerNetworkManager`

### Validation Modes
- `ValidationMode::None`: No validation (fast)
- `ValidationMode::Basic`: Basic structure and timestamp validation
- `ValidationMode::Full`: Complete PoW and chain validation

### Wallet Integration
Basic wallet functionality for address monitoring:
- UTXO tracking via `Utxo` struct
- Balance calculation with confirmation states
- Transaction processing via `TransactionProcessor`

## Testing Strategy

### Test Organization
- **Unit tests**: In-module tests for individual components
- **Integration tests**: `tests/` directory with comprehensive test suites
- **Real network tests**: Integration with live Dash Core nodes
- **Performance tests**: Sync rate and memory usage benchmarks

### Test Categories (from `tests/test_plan.md`)
1. **Network layer**: Handshake, connection management (3/4 passing)
2. **Storage layer**: Memory/disk operations (9/9 passing) 
3. **Header sync**: Genesis to tip synchronization (11/11 passing)
4. **Integration**: Real node connectivity and performance (6/6 passing)

### Test Data Requirements
- Dash Core node at `127.0.0.1:9999` for integration tests
- Tests gracefully handle node unavailability
- Performance benchmarks expect 50-200+ headers/second sync rates

## Development Workflow

### Working with Sync
The sync system uses a sequential phase-based pattern:
1. Create `DashSpvClient` with desired configuration
2. Call `start()` to begin synchronization
3. The client internally uses `SequentialSyncManager` to progress through sync phases
4. Monitor progress via `get_sync_progress()` or progress receiver
5. Each phase completes before the next begins

### Adding New Features
1. Define traits for abstractions (e.g., new storage backend)
2. Implement concrete types following existing patterns
3. Add comprehensive unit tests
4. Add integration tests if network interaction is involved
5. Update error types in `error.rs` for new failure modes

### Error Handling
Use domain-specific error types:
- `NetworkError`: Connection and protocol issues
- `StorageError`: Data persistence problems  
- `SyncError`: Synchronization failures
- `ValidationError`: Header and transaction validation issues
- `SpvError`: Top-level errors wrapping specific domains

## MSRV and Dependencies

- **Minimum Rust Version**: 1.89
- **Core dependencies**: `dashcore`, `tokio`, `async-trait`, `thiserror`
- **Built on**: `dashcore` library with Dash-specific features enabled
- **Async runtime**: Tokio with full feature set

## Key Implementation Details

### Storage Architecture
- **Segmented storage**: Headers stored in 10,000-header segments with index files
- **Filter storage**: Separate storage for filter headers and compact block filters
- **State persistence**: Chain state, masternode data, and sync progress persisted between runs
- **Storage paths**: Headers in `headers/`, filters in `filters/`, state in `state/`

### Async Architecture Patterns
- **Trait objects**: `Arc<dyn StorageManager>`, `Arc<dyn NetworkManager>` for runtime polymorphism
- **Message passing**: Tokio channels for inter-component communication
- **Timeout handling**: Configurable timeouts with recovery mechanisms
- **State machines**: `SyncState` enum drives synchronization flow

### Debugging and Troubleshooting

**Common Debug Commands:**
```bash
# Run with tracing output
RUST_LOG=debug cargo test --test integration_real_node_test -- --nocapture

# Run specific test with verbose output  
cargo test --test handshake_test test_handshake_with_mainnet_peer -- --nocapture --test-threads=1

# Check storage state
ls -la data*/headers/
ls -la data*/state/
```

**Debug Data Locations:**
- `test-debug/`: Debug data from test runs
- `data*/`: Runtime data directories (numbered by run)
- Storage index files show header counts and segment info

**Network Debugging:**
- Connection issues: Check if Dash Core node is running at `127.0.0.1:9999`
- Handshake failures: Verify network (mainnet/testnet/devnet) matches node
- Timeout issues: Node may be syncing or under load

## Current Status

This is a refactored SPV client extracted from a monolithic example:
- ✅ Core architecture implemented and modular
- ✅ Compilation successful with comprehensive trait abstractions
- ✅ Extensive test coverage (29/29 implemented tests passing)
- ⚠️ Some wallet functionality still in development (see `PLAN.md`)
- ⚠️ ChainLock/InstantLock signature validation has TODO items

The project transforms a 1,143-line monolithic example into a production-ready, testable library suitable for integration into wallets and other Dash applications.