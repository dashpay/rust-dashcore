# Key Wallet FFI

FFI bindings for the key-wallet library, providing a C-compatible interface for use in other languages like Swift, Kotlin, Python, etc.

> **Note**: This library can be used standalone or as part of the [Unified SDK](../../platform-ios/packages/rs-sdk-ffi/UNIFIED_SDK_ARCHITECTURE.md) which combines both Core (including this wallet functionality) and Platform features into a single optimized binary. The Unified SDK is recommended for iOS applications as it eliminates duplicate symbols and reduces binary size by 79.4%.

## Features

- **C-compatible FFI**: Direct C-style FFI bindings without code generation
- **Memory-safe**: Rust's ownership model ensures memory safety across FFI boundary
- **Thread-safe**: All exposed types are thread-safe
- **Error handling**: Proper error propagation across language boundaries

## Supported Languages

This library provides C-compatible FFI that can be used by:
- Swift (iOS/macOS)
- Kotlin (Android) via JNI
- Python via ctypes/cffi
- Any language that can interface with C libraries

## Building

### Prerequisites

- Rust 1.70+
- For iOS: Xcode and cargo-lipo
- For Android: Android NDK

### Build libraries

#### Standalone Build

```bash
# Build for current platform
cargo build --release

# Build for iOS (requires cargo-lipo)
cargo lipo --release

# Build for Android (requires cargo-ndk)
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 -o ./jniLibs build --release
```

#### Unified SDK Build (Recommended for iOS)

For iOS applications, use the Unified SDK which includes this library:

```bash
cd ../../platform-ios/packages/rs-sdk-ffi
./build_ios.sh
```

This creates `DashUnifiedSDK.xcframework` containing both Core (including wallet functionality) and Platform symbols in a single optimized binary.

## Usage Examples

### Swift

```swift
import KeyWalletFFI

// Create mnemonic
let mnemonic = try Mnemonic(wordCount: 12, language: .english)

// Create wallet
let wallet = try HDWallet.fromMnemonic(
    mnemonic: mnemonic,
    passphrase: "",
    network: .dash
)

// Derive address
let account = try wallet.getBip44Account(account: 0)
let firstAddress = try wallet.derivePub(path: "m/44'/5'/0'/0/0")
```

### Kotlin

```kotlin
import com.dash.keywallet.*

// Create mnemonic
val mnemonic = Mnemonic.fromPhrase(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    Language.ENGLISH
)

// Create wallet
val wallet = HDWallet.fromMnemonic(mnemonic, "", Network.DASH)

// Generate addresses
val generator = AddressGenerator(Network.DASH)
val addresses = generator.generateRange(accountXpub, true, 0u, 10u)
```

### Python

```python
from key_wallet_ffi import *

# Create mnemonic
mnemonic = Mnemonic.from_phrase(
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    Language.ENGLISH
)

# Create wallet
wallet = HDWallet.from_mnemonic(mnemonic, "", Network.DASH)

# Get first address
first_addr = wallet.derive_pub("m/44'/5'/0'/0/0")
```

## API Reference

### Core Types

- `Mnemonic`: BIP39 mnemonic phrase handling
- `HDWallet`: Hierarchical deterministic wallet
- `ExtendedKey`: Extended public/private keys
- `Address`: Dash address encoding/decoding
- `AddressGenerator`: Bulk address generation

### Enums

- `Network`: Dash, Testnet, Regtest, Devnet
- `Language`: Supported mnemonic languages
- `AddressType`: P2PKH, P2SH

### Error Handling

All methods that can fail return a `Result` type with specific error variants:
- `InvalidMnemonic`
- `InvalidDerivationPath`
- `InvalidAddress`
- `Bip32Error`
- `KeyError`

## Thread Safety

All exposed types are `Send + Sync` and wrapped in `Arc` for thread-safe reference counting.

## License

This project is licensed under the CC0 1.0 Universal license.
