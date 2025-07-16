# Unified SDK Integration

## Overview

The rust-dashcore libraries (`dash-spv-ffi` and `key-wallet-ffi`) can be integrated into iOS applications in two ways:

1. **Standalone Libraries** - Traditional approach with separate binaries
2. **Unified SDK** - Recommended approach combining all functionality into a single optimized binary

## Unified SDK Architecture

The Unified SDK combines:
- **dash-spv-ffi** - SPV client functionality
- **key-wallet-ffi** - HD wallet operations  
- **dash-sdk-ffi** - Platform SDK functionality

Into a single `DashUnifiedSDK.xcframework` that:
- Eliminates duplicate symbols
- Reduces total binary size by 79.4% (from 143MB to 29.5MB)
- Simplifies integration
- Maintains full API compatibility

## Building the Unified SDK

The Unified SDK is built from the platform-ios repository:

```bash
cd ../platform-ios/packages/rs-sdk-ffi
./build_ios.sh
```

This produces `DashUnifiedSDK.xcframework` containing:
- All Core SDK symbols (`dash_spv_ffi_*`, `key_wallet_ffi_*`)
- All Platform SDK symbols (`dash_sdk_*`)
- Unified header with resolved type conflicts
- Support for both device and simulator architectures

## Integration in iOS Projects

### Using SwiftDashCoreSDK

The SwiftDashCoreSDK automatically detects and uses the Unified SDK when available:

```swift
// No code changes needed - same API
import SwiftDashCoreSDK

let sdk = try DashSDK(configuration: .testnet())
try await sdk.connect()
```

### Direct FFI Usage

If using FFI directly:

```swift
// Import from unified framework
import DashSPVFFI  // Core functionality
import DashSDKFFI  // Platform functionality

// Initialize once for both
dash_sdk_init()
```

## Benefits

1. **Size Reduction**: 79.4% smaller than separate libraries
2. **No Symbol Conflicts**: Shared dependencies included only once
3. **Simplified Distribution**: Single XCFramework to manage
4. **Better Performance**: Reduced memory footprint and faster load times
5. **Easier Maintenance**: One build process for all functionality

## Compatibility

- The Unified SDK maintains full API compatibility
- No code changes required when switching from standalone libraries
- Can still use libraries standalone if needed for specific use cases

## Documentation

For detailed technical information about the Unified SDK architecture:
- [UNIFIED_SDK_ARCHITECTURE.md](../platform-ios/packages/rs-sdk-ffi/UNIFIED_SDK_ARCHITECTURE.md)
- [MIGRATION_GUIDE.md](../platform-ios/packages/rs-sdk-ffi/MIGRATION_GUIDE.md)

## Version Requirements

- iOS 17.0+ deployment target
- Rust 1.70+
- Swift 5.9+
- Xcode 15.0+