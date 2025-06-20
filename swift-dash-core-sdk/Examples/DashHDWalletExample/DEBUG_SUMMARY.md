# Debug Summary: Undefined Symbols Issue

## Problem Analysis

The build fails with undefined symbols for `dash_spv_ffi_*` functions despite:
1. The library (`libdash_spv_ffi.a`) being present in the project directory
2. The library containing the correct symbols (verified with `nm`)
3. The library having the correct architectures (x86_64 and arm64)

## Root Cause

The issue occurs because:
1. The example project uses Swift Package Manager to include `SwiftDashCoreSDK`
2. The `Package.swift` defines several library search paths using relative paths
3. When Xcode resolves the package, these relative paths don't resolve correctly from the package location
4. The linker can't find `libdash_spv_ffi.a` in any of the search paths

## Why It Happens

The `Package.swift` includes these linker settings for the `DashSPVFFI` target:
```swift
.unsafeFlags([
    "-L../target/aarch64-apple-ios-sim/release",
    "-L../target/x86_64-apple-ios/release", 
    "-L../target/ios-simulator-universal/release",
    "-L../target/release",
    "-LExamples/DashHDWalletExample",
    "-L."
])
```

These paths are relative to the package root (`swift-dash-core-sdk`), but the libraries weren't in those locations.

## Solution Applied

Created symlinks from the actual library location to the expected locations:
- `/Users/quantum/src/rust-dashcore/swift-dash-core-sdk/target/release/libdash_spv_ffi.a`
- And other architecture-specific locations

This was done using the `fix-linking.sh` script.

## Alternative Solutions

1. **Direct Linking**: Add the library directly to the Xcode project's "Link Binary With Libraries" build phase
2. **Absolute Paths**: Update Package.swift to use absolute paths (not recommended for portability)
3. **Build Script**: Add a build phase script that copies libraries to expected locations
4. **Local xcconfig**: Configure the project to use the Local.xcconfig file that defines proper search paths

## Files Created

1. `LINKING_FIX.md` - Detailed instructions for fixing the issue
2. `fix-linking.sh` - Script to create necessary symlinks
3. `DEBUG_SUMMARY.md` - This summary of the debugging process

## Verification

After running `fix-linking.sh`:
1. Clean Build Folder in Xcode (⇧⌘K)
2. Build the project (⌘B)
3. The undefined symbol errors should be resolved