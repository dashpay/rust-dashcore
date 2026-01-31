# dash-network

A Rust library providing network type definitions for the Dash cryptocurrency.

## Overview

This crate defines the `Network` enum used across Dash-related Rust projects to identify which network (mainnet, testnet, devnet, or regtest) is being used. It provides a centralized definition to avoid duplication and circular dependencies between crates.

## Features

- **Network Identification**: Enum representing Dash networks (Dash mainnet, Testnet, Devnet, Regtest)
- **Magic Bytes**: Network-specific magic bytes for message headers
- **Protocol Information**: Core version activation heights and network-specific parameters
- **Serialization Support**: Optional serde and bincode support via feature flags

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
dash-network = "0.42.0"
```

### Basic Example

```rust
use dash_network::Network;

fn main() {
    let network = Network::Dash;
    
    // Get network magic bytes
    let magic = network.magic();
    println!("Network magic: 0x{:08X}", magic);
    
    // Check core v20 activation
    let block_height = 2_000_000;
    if network.core_v20_is_active_at(block_height) {
        println!("Core v20 is active at height {}", block_height);
    }
}
```

### Network Types

- `Network::Dash` - Dash mainnet
- `Network::Testnet` - Dash testnet  
- `Network::Devnet` - Dash devnet
- `Network::Regtest` - Regression test network

### Features

- `default`: Enables `std`
- `std`: Standard library support (enabled by default)
- `no-std`: Enables no_std compatibility
- `serde`: Enables serde serialization/deserialization
- `bincode`: Enables bincode encoding/decoding

## Network Magic Bytes

Each network has unique magic bytes used in message headers:

- Dash mainnet: `0xBD6B0CBF`
- Testnet: `0xFFCAE2CE`
- Devnet: `0xCEFFCAE2`
- Regtest: `0xDAB5BFFA`

## License

This project is licensed under the CC0 1.0 Universal license.
