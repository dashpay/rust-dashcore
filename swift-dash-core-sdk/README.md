# Swift Dash Core SDK

A pure Swift SDK for integrating Dash SPV (Simplified Payment Verification) functionality into iOS, macOS, tvOS, and watchOS applications. Built on top of the rust-dashcore `dash-spv-ffi` library with SwiftData persistence.

> **Note**: This SDK is compatible with the Unified SDK architecture. When used in projects with DashUnifiedSDK.xcframework, it automatically uses the unified binary which includes both Core and Platform functionality.

## Features

- 🚀 **Modern Swift**: Built with async/await, actors, and structured concurrency
- 💾 **SwiftData Persistence**: Automatic data persistence using SwiftData
- 🔒 **Type Safety**: Strong typing with Swift enums and structs
- 📱 **Multi-Platform**: Supports iOS 17+, macOS 14+, tvOS 17+, watchOS 10+
- ⚡ **InstantSend**: Full support for Dash InstantSend transactions
- 🔗 **ChainLock**: Validation of ChainLocked blocks
- 📊 **Real-time Updates**: Observable properties and Combine publishers

## Requirements

- Swift 5.9+
- iOS 17.0+ / macOS 14.0+ / tvOS 17.0+ / watchOS 10.0+
- Xcode 15.0+
- rust-dashcore with dash-spv-ffi built

## Installation

### Option 1: Using Unified SDK (Recommended)

When using the Unified SDK, the Core functionality is already included:

```swift
dependencies: [
    .package(path: "../swift-dash-core-sdk")
]
```

The SDK will automatically use symbols from DashUnifiedSDK.xcframework when available.

### Option 2: Standalone Usage

For standalone usage, build the required Rust library:

```bash
cd ../dash-spv-ffi
cargo build --release
```

### Swift Package Manager

Add the package to your `Package.swift`:

```swift
dependencies: [
    .package(path: "../swift-dash-core-sdk")
]
```

Or in Xcode: File → Add Package Dependencies → Add Local → Select the `swift-dash-core-sdk` folder.

## Quick Start

### Basic Usage

```swift
import SwiftDashCoreSDK

// Create SDK instance
let sdk = try DashSDK(configuration: .testnet())

// Connect to network
try await sdk.connect()

// Watch an address
try await sdk.watchAddress("yXkgEH5zVfyr12K2tRcPsJNgMPLCb3HiLR")

// Get balance
let balance = try await sdk.getBalance()
print("Balance: \(balance.formattedTotal)")

// Get transactions
let transactions = try await sdk.getTransactions()
for tx in transactions {
    print("TX: \(tx.txid) - \(tx.status)")
}

// Send transaction
let txid = try await sdk.sendTransaction(
    to: "yZKdLYCvDXa2kyQr8Tg3N6c3xeZoK7XDcj",
    amount: 100_000_000 // 1 DASH in satoshis
)
```

### Configuration

```swift
let config = SPVClientConfiguration()
config.network = .mainnet
config.validationMode = .full
config.maxPeers = 16
config.dataDirectory = URL(fileURLWithPath: "/path/to/data")

let sdk = try DashSDK(configuration: config)
```

### Event Handling

```swift
sdk.eventPublisher
    .sink { event in
        switch event {
        case .blockReceived(let height, let hash):
            print("New block: \(height)")
        case .transactionReceived(let txid, let confirmed):
            print("Transaction: \(txid)")
        case .balanceUpdated(let balance):
            print("Balance updated: \(balance.formattedTotal)")
        default:
            break
        }
    }
    .store(in: &cancellables)
```

## Architecture

### Module Structure

- **Models**: Swift data models with SwiftData persistence
- **Core**: SPV client wrapper and FFI bridge
- **Storage**: SwiftData persistence layer
- **Wallet**: Wallet operations and balance management
- **Network**: Network configuration (future)
- **Utils**: Utilities and extensions

### Key Components

#### SPVClient
Core wrapper around the FFI client handling:
- Connection lifecycle
- Synchronization
- Network operations
- Event callbacks

#### WalletManager
Manages wallet operations:
- Address watching
- Balance queries
- UTXO management
- Transaction history

#### StorageManager
Handles data persistence:
- SwiftData integration
- CRUD operations
- Batch updates
- Data export/import

## Data Models

### Balance
```swift
@Model class Balance {
    var confirmed: UInt64
    var pending: UInt64
    var instantLocked: UInt64
    var total: UInt64
    var lastUpdated: Date
}
```

### Transaction
```swift
@Model class Transaction {
    @Attribute(.unique) var txid: String
    var height: UInt32?
    var timestamp: Date
    var amount: Int64
    var confirmations: UInt32
    var isInstantLocked: Bool
}
```

### UTXO
```swift
@Model class UTXO {
    @Attribute(.unique) var outpoint: String
    var address: String
    var value: UInt64
    var isSpent: Bool
}
```

## Advanced Usage

### Custom Event Stream

```swift
for await event in sdk.events {
    switch event {
    case .syncProgressUpdated(let progress):
        updateUI(progress: progress)
    default:
        break
    }
}
```

### Batch Operations

```swift
try await storage.performBatchUpdate {
    // Multiple operations in a single transaction
    for utxo in utxos {
        storage.saveUTXO(utxo)
    }
}
```

### Data Export/Import

```swift
// Export wallet data
let exportData = try sdk.exportWalletData()
let jsonData = try JSONEncoder().encode(exportData)

// Import wallet data
let importData = try JSONDecoder().decode(WalletExportData.self, from: jsonData)
try await sdk.importWalletData(importData)
```

## Example App

See the `Examples/DashWalletExample` directory for a complete SwiftUI example application demonstrating:
- Connection management
- Address watching
- Balance display
- Transaction history
- Sending transactions

## Testing

Run the test suite:

```bash
swift test
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built on top of [rust-dashcore](https://github.com/dashpay/rust-dashcore)
- Uses dash-spv-ffi for Rust-Swift interoperability
- SwiftData for persistence