# Integration Notes for Swift Dash Core SDK

This document outlines the integration points between the Swift SDK and the rust-dashcore FFI libraries.

## Current Architecture

The Swift SDK is designed to work with two FFI libraries:

1. **dash-spv-ffi**: Core SPV functionality (blockchain sync, transaction management)
2. **key-wallet-ffi**: HD wallet functionality (key derivation, address generation)

## Integration Points

### 1. SPV Client Integration (Implemented)

The SDK currently integrates with dash-spv-ffi for:
- Network connection and peer management
- Blockchain synchronization
- Address watching and balance queries
- Transaction broadcasting
- UTXO management

**Status**: ✅ Basic integration complete

### 2. HD Wallet Integration (Needs Implementation)

The HD wallet example app requires integration with key-wallet-ffi for:
- BIP39 mnemonic generation/validation
- BIP32 HD key derivation
- BIP44 account management
- Address generation from extended keys

**Status**: ⚠️ Using mock implementations

## Required FFI Extensions

### For dash-spv-ffi

To fully support HD wallets, dash-spv-ffi needs these additional functions:

```c
// HD Wallet Support
FFIErrorCode dash_spv_ffi_client_watch_xpub(
    FFIClient* client,
    const char* xpub,
    uint32_t account_index,
    bool is_internal,
    uint32_t start_index,
    uint32_t count
);

FFIErrorCode dash_spv_ffi_client_get_xpub_balance(
    FFIClient* client,
    const char* xpub,
    FFIBalance** out_balance
);

FFIErrorCode dash_spv_ffi_client_discover_addresses(
    FFIClient* client,
    const char* xpub,
    uint32_t gap_limit,
    ProgressCallback progress,
    CompletionCallback completion,
    void* user_data
);
```

### For key-wallet-ffi

The key-wallet-ffi already has most needed functionality via UniFFI, but could benefit from:

```swift
// Additional convenience methods
extension HDWallet {
    func deriveAddresses(
        account: UInt32,
        change: Bool,
        startIndex: UInt32,
        count: UInt32
    ) -> [String]
    
    func getAccountXpub(index: UInt32) -> String
}
```

## Implementation Approach

### Option 1: Direct Integration (Recommended)

1. Add key-wallet-ffi as a dependency to the Swift package
2. Use UniFFI-generated Swift bindings directly
3. Remove mock implementations in HDWalletService

```swift
// Package.swift
.target(
    name: "KeyWalletFFI",
    dependencies: [],
    path: "Sources/KeyWalletFFI"
),
.target(
    name: "SwiftDashCoreSDK",
    dependencies: ["DashSPVFFI", "KeyWalletFFI"]
)
```

### Option 2: Extend dash-spv-ffi

1. Add HD wallet functions to dash-spv-ffi that internally use key-wallet
2. Expose a unified C API for both SPV and HD wallet functionality
3. Maintain single FFI dependency in Swift

```rust
// In dash-spv-ffi
use key_wallet::{HDWallet, Mnemonic};

#[no_mangle]
pub extern "C" fn dash_spv_ffi_create_hd_wallet(
    mnemonic: *const c_char,
    network: FFINetwork,
    wallet: *mut *mut FFIHDWallet,
) -> FFIErrorCode {
    // Implementation
}
```

### Option 3: Hybrid Approach

1. Use key-wallet-ffi for wallet creation and key derivation
2. Pass derived addresses/xpubs to dash-spv-ffi for monitoring
3. Coordinate between both libraries in Swift

## Example Integration Code

### Using key-wallet-ffi with UniFFI

```swift
import KeyWalletFFI

class RealHDWalletService {
    func createWallet(mnemonic: [String], network: DashNetwork) throws -> HDWallet {
        // Use real key-wallet-ffi
        let phrase = mnemonic.joined(separator: " ")
        let wallet = try KeyWalletFFI.HDWallet(
            phrase: phrase,
            passphrase: "",
            network: network.toKeyWalletNetwork()
        )
        return wallet
    }
    
    func deriveAddress(
        wallet: HDWallet,
        account: UInt32,
        change: Bool,
        index: UInt32
    ) throws -> String {
        let path = BIP44Path(
            account: account,
            change: change ? 1 : 0,
            addressIndex: index
        )
        return try wallet.deriveAddress(path: path)
    }
}
```

### Bridging Networks

```swift
extension DashNetwork {
    func toKeyWalletNetwork() -> KeyWalletFFI.Network {
        switch self {
        case .mainnet:
            return .dash
        case .testnet:
            return .dashTestnet
        case .regtest:
            return .dashRegtest
        case .devnet:
            return .dashDevnet
        }
    }
}
```

## Build Configuration

### Including Both FFI Libraries

```bash
# Build key-wallet-ffi
cd ../key-wallet-ffi
cargo build --release

# Build dash-spv-ffi
cd ../dash-spv-ffi
cargo build --release

# Copy libraries
cp ../key-wallet-ffi/target/release/libkey_wallet_ffi.a swift-dash-core-sdk/Libraries/
cp ../dash-spv-ffi/target/release/libdash_spv_ffi.a swift-dash-core-sdk/Libraries/
```

### Swift Package Configuration

```swift
// Package.swift
.binaryTarget(
    name: "DashSPVFFI",
    path: "Libraries/libdash_spv_ffi.xcframework"
),
.binaryTarget(
    name: "KeyWalletFFI", 
    path: "Libraries/libkey_wallet_ffi.xcframework"
)
```

## Testing Integration

1. **Unit Tests**: Test key derivation and address generation
2. **Integration Tests**: Test address discovery with real blockchain data
3. **UI Tests**: Test wallet creation and transaction flows

## Security Considerations

1. **Key Management**: Never expose private keys to Swift layer
2. **Memory Safety**: Clear sensitive data after use
3. **Encryption**: Use platform keychain for seed storage
4. **Validation**: Validate all addresses before use

## Performance Considerations

1. **Address Generation**: Batch generate addresses for better performance
2. **Discovery**: Use parallel discovery for multiple accounts
3. **Caching**: Cache derived addresses to avoid recomputation
4. **Threading**: Use background queues for key derivation

## Future Enhancements

1. **Hardware Wallet Support**: Add interface for external signers
2. **Multi-Sig**: Support for multi-signature accounts
3. **Custom Derivation**: Support for non-BIP44 paths
4. **Key Rotation**: Support for key rotation and migration