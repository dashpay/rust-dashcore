# dash-network-ffi

FFI bindings for the dash-network crate, providing C-compatible language bindings.

## Overview

This crate provides Foreign Function Interface (FFI) bindings for the `dash-network` types, allowing them to be used from other programming languages like Swift, Python, Kotlin, and Ruby.

## Features

- C-compatible FFI bindings for the Network enum
- Network information and utilities exposed through FFI
- Support for magic bytes operations
- Core version activation queries

## Usage

### Building

```bash
cargo build --release
```

### Example Usage (Swift)

```swift
// Initialize the library
dashNetworkFfiInitialize()

// Create a network info object
let networkInfo = NetworkInfo(network: .dash)

// Get magic bytes
let magic = networkInfo.magic()
print("Dash network magic: \(String(format: "0x%08X", magic))")

// Check if core v20 is active
if networkInfo.isCoreV20Active(blockHeight: 2000000) {
    print("Core v20 is active!")
}

// Create from magic bytes
do {
    let network = try NetworkInfo.fromMagic(magic: 0xBD6B0CBF)
    print("Network: \(network.toString())")
} catch {
    print("Invalid magic bytes")
}
```

### Example Usage (Python)

```python
import dash_network_ffi

# Initialize the library
dash_network_ffi.initialize()

# Create a network info object
network_info = dash_network_ffi.NetworkInfo(dash_network_ffi.Network.DASH)

# Get magic bytes
magic = network_info.magic()
print(f"Dash network magic: 0x{magic:08X}")

# Check if core v20 is active
if network_info.is_core_v20_active(2000000):
    print("Core v20 is active!")

# Create from magic bytes
try:
    network = dash_network_ffi.NetworkInfo.from_magic(0xBD6B0CBF)
    print(f"Network: {network.to_string()}")
except dash_network_ffi.NetworkError.InvalidMagic:
    print("Invalid magic bytes")
```

## API

### Network Enum

- `Dash` - Dash mainnet
- `Testnet` - Dash testnet
- `Devnet` - Dash devnet  
- `Regtest` - Regression test network

### NetworkInfo Class

#### Constructors
- `new(network: Network)` - Create from a Network enum value
- `from_magic(magic: u32)` - Create from magic bytes (throws NetworkError)

#### Methods
- `magic() -> u32` - Get the network's magic bytes
- `to_string() -> String` - Get the network name as a string
- `is_core_v20_active(block_height: u32) -> bool` - Check if core v20 is active at height
- `core_v20_activation_height() -> u32` - Get the activation height for core v20

### NetworkError Enum

- `InvalidMagic` - Invalid magic bytes provided
- `InvalidNetwork` - Invalid network specified

## License

This project is licensed under the CC0 1.0 Universal license.