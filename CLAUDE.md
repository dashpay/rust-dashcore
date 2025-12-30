# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

rust-dashcore is a Rust implementation of the Dash cryptocurrency protocol library. It provides:
- Block and transaction serialization/deserialization
- Script evaluation and address generation
- Network protocol implementation
- SPV (Simplified Payment Verification) client
- HD wallet functionality (BIP32/BIP39/DIP9)
- FFI bindings for C and Swift integration
- JSON-RPC client for Dash Core nodes

**IMPORTANT**: This library should NOT be used for consensus code. The exact behavior of the consensus-critical parts of Dash Core cannot be replicated without an exact copy of the C++ code.

## Repository Structure

### Core Libraries
- `dash/` - Core Dash protocol implementation (blocks, transactions, scripts, addresses)
- `hashes/` - Cryptographic hash implementations (SHA256, X11, Blake3)
- `internals/` - Internal utilities and macros

### Network & SPV
- `dash-network/` - Network protocol abstractions
- `dash-network-ffi/` - C-compatible FFI bindings for network types
- `dash-spv/` - SPV client implementation
- `dash-spv-ffi/` - C-compatible FFI bindings for SPV client

### Wallet & Keys
- `key-wallet/` - Comprehensive HD wallet implementation with multi-account support, address pools, and transaction management (see key-wallet/CLAUDE.md for detailed architecture)
- `key-wallet-ffi/` - C-compatible FFI bindings for wallet functionality

### RPC & Integration
- `rpc-client/` - JSON-RPC client for Dash Core nodes
- `rpc-json/` - JSON types for RPC communication
- `rpc-integration-test/` - Integration tests for RPC

### Testing
- `fuzz/` - Fuzzing tests for security testing

## Build Commands

### Basic Rust Build
```bash
# Build all workspace members
cargo build

# Build release version
cargo build --release

# Build specific crate
cargo build -p dash-spv
```

### FFI Library Build
```bash
# Build iOS libraries for key-wallet-ffi
cd key-wallet-ffi && ./build-ios.sh
```

### iOS/macOS Targets
```bash
# Add iOS targets
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

# Build for specific target
cargo build --release --target aarch64-apple-ios
```

## Test Commands

### Running Tests
```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run tests for specific crate
cargo test -p dash-spv

# Run comprehensive test suite
./contrib/test.sh
```

### Environment Variables for Testing
```bash
# Enable coverage
DO_COV=true ./contrib/test.sh

# Enable linting
DO_LINT=true ./contrib/test.sh

# Enable formatting check
DO_FMT=true ./contrib/test.sh
```

### Integration Tests
```bash
# Run with real Dash node (requires DASH_SPV_IP environment variable)
cd dash-spv
cargo test --test integration_real_node_test -- --nocapture
```

## Development Commands

### Linting and Formatting
```bash
# Format code
cargo fmt

# Check formatting
cargo fmt --check

# Run clippy
cargo clippy --all-features --all-targets -- -D warnings
```

### Documentation
```bash
# Build documentation
cargo doc --all-features

# Build and open documentation
cargo doc --open
```

## Key Features

### Dash-Specific Features
- **InstantSend (IX)**: Instant transaction confirmation
- **ChainLocks**: Additional blockchain security via LLMQ
- **Masternodes**: Support for masternode operations
- **Quorums**: Long-Living Masternode Quorums (LLMQ)
- **Special Transactions**: DIP2/DIP3 special transaction types
- **Deterministic Masternode Lists**: DIP3 masternode system
- **X11 Mining Algorithm**: Dash's proof-of-work algorithm

### Architecture Highlights
- **Workspace-based**: Multiple crates with clear separation of concerns
- **Async/Await**: Modern async Rust throughout
- **FFI Support**: C and Swift bindings for cross-platform usage
- **Comprehensive Testing**: Unit, integration, and fuzz testing
- **MSRV**: Rust 1.89 minimum supported version

## Code Style Guidelines

### Important Constraints
- **No Hardcoded Values**: Never hardcode network parameters, addresses, or keys
- **Error Handling**: Use proper error types (thiserror) and propagate errors appropriately
- **Async Code**: Use tokio runtime for async operations
- **Memory Safety**: Careful handling in FFI boundaries
- **Feature Flags**: Use conditional compilation for optional features

### Testing Requirements
- Write unit tests for new functionality
- Integration tests for network operations
- Test both mainnet and testnet configurations
- Use proptest for property-based testing where appropriate

### Git Workflow
- Current development branch: `v0.42-dev`
- Main branch: `master`

## Current Status

The project is actively developing:
- FFI bindings improvements
- Support for Dash Core versions 0.18.0 - 0.23.x

## Security Considerations

- This library is NOT suitable for consensus-critical code
- Always validate inputs from untrusted sources
- Use secure random number generation for keys
- Never log or expose private keys
- Be careful with FFI memory management

## API Stability

The API is currently unstable (version 0.x.x). Breaking changes may occur in minor version updates. Production use requires careful version pinning.

## Known Limitations

- Cannot replicate exact consensus behavior of Dash Core
- Not suitable for mining or consensus validation
- FFI bindings have limited error propagation
- Some Dash Core RPC methods not yet implemented
