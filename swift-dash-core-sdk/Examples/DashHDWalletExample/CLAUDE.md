# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DashHDWalletExample is an iOS/macOS SwiftUI application demonstrating HD (Hierarchical Deterministic) wallet functionality using SwiftDashCoreSDK. It showcases SPV (Simplified Payment Verification) blockchain synchronization, address management, and transaction handling for the Dash cryptocurrency.

## Build Commands

### Xcode Build (Recommended)
```bash
# Command line build for iOS Simulator
xcodebuild -project DashHDWalletExample.xcodeproj -scheme DashHDWalletExample -sdk iphonesimulator18.5 -configuration Debug build

# Build for specific simulator architectures
xcodebuild -project DashHDWalletExample.xcodeproj -scheme DashHDWalletExample -sdk iphonesimulator18.5 -arch arm64 build  # Apple Silicon
xcodebuild -project DashHDWalletExample.xcodeproj -scheme DashHDWalletExample -sdk iphonesimulator18.5 -arch x86_64 build # Intel

# Build for physical iOS device
xcodebuild -project DashHDWalletExample.xcodeproj -scheme DashHDWalletExample -sdk iphoneos18.5 -configuration Release build

# Build for macOS
xcodebuild -project DashHDWalletExample.xcodeproj -scheme DashHDWalletExample -sdk macosx15.5 -configuration Debug build
```

### Swift Package Manager Build
```bash
# Build with library linking
./build-spm.sh

# Run the app
./run-spm.sh

# Manual build with linker flags
swift build -Xlinker -L$(pwd) -Xlinker -ldash_spv_ffi
```

### FFI Library Build
```bash
# From swift-dash-core-sdk directory (parent)
cd ../..
./build-ios.sh

# This creates:
# - libdash_spv_ffi_ios.a (iOS device)
# - libdash_spv_ffi_sim.a (iOS simulator)
# - Copies to Examples/DashHDWalletExample/
```

## Architecture

### Key Components

**Services**
- `WalletService`: Main service managing SDK interaction, wallet lifecycle, and blockchain sync
  - Handles connection/disconnection to SPV network
  - Manages enhanced sync progress tracking with streaming API
  - Coordinates wallet persistence and account management
  - Enables mempool tracking for unconfirmed transactions

**Models**
- `HDWalletModels.swift`: SwiftData models for persistent storage
  - `HDWallet`: Root wallet with encrypted seed (mock implementation)
  - `HDAccount`: BIP44 accounts with derivation paths
  - `WatchedAddress`: Individual addresses with balance tracking
  - `SyncState`: Blockchain synchronization progress

**Views**
- Platform-adaptive UI using SwiftUI's cross-platform capabilities
- `ContentView`: Main navigation with wallet list
- `WalletDetailView`: Account management and sync controls
- `EnhancedSyncProgressView`: Real-time sync visualization with:
  - Stage-based progress (Connecting, Downloading, Validating)
  - Headers/second download rate
  - ETA calculations
  - Streaming vs callback sync method toggle

### FFI Integration

The app depends on prebuilt Rust FFI libraries:
- `libdash_spv_ffi.a`: SPV client functionality from dash-spv-ffi
- `libkey_wallet_ffi.a`: HD wallet operations (currently mocked)

**Library Architecture Selection**:
- iOS Simulator: Universal binary supporting arm64 + x86_64
- iOS Device: arm64 only
- Selected via `select-library.sh` based on build target

### Sync Methods

Two approaches for blockchain synchronization:

1. **Streaming API** (`syncProgressStream()`):
   - Returns `AsyncThrowingStream<DetailedSyncProgress>`
   - Continuous updates via Swift async/await
   - Automatic cancellation on task termination

2. **Callback API** (`syncToTipWithProgress()`):
   - Traditional callback-based approach
   - Progress and completion callbacks
   - Manual memory management for callback holders

## Common Issues and Solutions

### Duplicate Type Definitions
If you encounter "filename used twice" errors:
- Check for duplicate files in `Models/` and `Types/` directories
- SPVClient.swift should not contain type definitions (they belong in separate files)

### Private Access Errors
When accessing SPV functionality:
- Use DashSDK's public methods, not direct client access
- Add public wrapper methods to DashSDK if needed

### Library Linking Issues
For "undefined symbols" errors:
1. Verify library exists: `ls -la libdash_spv_ffi.a`
2. Check architecture: `lipo -info libdash_spv_ffi.a`
3. Ensure library is added to Build Phases → Link Binary With Libraries
4. Verify Library Search Paths includes `$(PROJECT_DIR)`

### Mempool Tracking
The app enables mempool tracking on connection:
```swift
try await sdk?.enableMempoolTracking(strategy: .fetchAll)
```
Available strategies: `.fetchAll`, `.bloomFilter`, `.selective`

## Development Workflow

### Making SDK Changes
1. Edit Swift SDK code in `../../Sources/SwiftDashCoreSDK/`
2. Changes are automatically picked up (local Swift package)
3. Clean build folder if needed: Product → Clean Build Folder

### Adding New FFI Functions
1. Implement in Rust: `../../../dash-spv-ffi/src/`
2. Run `cargo build --release` in dash-spv-ffi
3. Run `./sync-headers.sh` to update headers
4. Rebuild iOS libraries: `cd ../.. && ./build-ios.sh`
5. Add Swift wrapper in appropriate SDK file

### Testing Sync Progress
The enhanced sync view provides detailed progress tracking:
- Connection establishment
- Peer discovery
- Header batch downloading
- Validation progress
- Storage operations

Monitor console output for detailed logs during development.

## Platform Considerations

### iOS vs macOS
- Shared codebase with conditional compilation
- iOS: Navigation stack with modal sheets
- macOS: Split view with sidebar navigation
- Platform-specific views in `#if os(iOS)` blocks

### SwiftData Requirements
- Requires Xcode for full SwiftData support
- Command line builds have limited SwiftData functionality
- Models use `@Model` macro requiring iOS 17.0+

## Network Configuration

Default networks configured in `SPVClientConfiguration`:
- Mainnet: Primary Dash network
- Testnet: For development (default)
- Devnet/Regtest: Local testing

Peers are hardcoded in configuration - no DNS seeds in example app.