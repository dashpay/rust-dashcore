# Building Swift Dash Core SDK

This guide explains how to build and integrate the Swift Dash Core SDK into your project.

## Prerequisites

1. **Rust toolchain** (for building dash-spv-ffi)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Xcode 15.0+** with Swift 5.9+

3. **rust-dashcore** repository cloned

## Build Steps

### 1. Build the FFI Library

First, build the dash-spv-ffi library that the Swift SDK depends on:

```bash
# Navigate to dash-spv-ffi directory
cd ../dash-spv-ffi

# Build for release
cargo build --release

# The library will be at: target/release/libdash_spv_ffi.a
```

### 2. Generate C Headers

The C headers are automatically generated when building dash-spv-ffi:

```bash
cd ../dash-spv-ffi
cargo build --release
# Headers are generated in dash-spv-ffi/include/dash_spv_ffi.h
```

### 3. Copy Headers to Swift Package

```bash
# From swift-dash-core-sdk directory
./sync-headers.sh

# Or manually:
cp ../dash-spv-ffi/include/dash_spv_ffi.h Sources/DashSPVFFI/include/
```

Note: The `build-ios.sh` script automatically copies headers when building for iOS.

### 4. Build for iOS/macOS

For iOS devices and simulators, you need to build universal binaries:

```bash
# Install cargo-lipo for iOS builds
cargo install cargo-lipo

# Add iOS targets
rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim

# Build for iOS
cargo lipo --release

# Build for macOS
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin

# Create universal binary for macOS
lipo -create \
  target/x86_64-apple-darwin/release/libdash_spv_ffi.a \
  target/aarch64-apple-darwin/release/libdash_spv_ffi.a \
  -output target/release/libdash_spv_ffi_macos.a
```

## Integration

### Swift Package Manager

1. The Package.swift is already configured to link with the FFI library
2. Make sure the library path in Package.swift points to your built library:
   ```swift
   .unsafeFlags(["-L../target/release"])
   ```

### Xcode Project

If integrating directly into an Xcode project:

1. Add `swift-dash-core-sdk` as a local package dependency
2. In Build Settings → Other Linker Flags, add:
   ```
   -L/path/to/rust-dashcore/target/release
   -ldash_spv_ffi
   ```
3. In Build Settings → Header Search Paths, add:
   ```
   /path/to/swift-dash-core-sdk/Sources/DashSPVFFI/include
   ```

## Platform-Specific Builds

### iOS

```bash
# Build for iOS device
cargo build --release --target aarch64-apple-ios

# Build for iOS simulator (Apple Silicon)
cargo build --release --target aarch64-apple-ios-sim

# Build for iOS simulator (Intel)
cargo build --release --target x86_64-apple-ios
```

### macOS

```bash
# Intel Mac
cargo build --release --target x86_64-apple-darwin

# Apple Silicon Mac
cargo build --release --target aarch64-apple-darwin
```

### tvOS

```bash
# Add tvOS targets
rustup target add aarch64-apple-tvos x86_64-apple-tvos

# Build
cargo build --release --target aarch64-apple-tvos
```

### watchOS

```bash
# Add watchOS targets
rustup target add aarch64-apple-watchos x86_64-apple-watchos-sim

# Build
cargo build --release --target aarch64-apple-watchos
```

## Creating XCFramework

For distribution, create an XCFramework:

```bash
# Create XCFramework directory structure
mkdir -p DashSPVFFI.xcframework

# Use xcodebuild to create XCFramework
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libdash_spv_ffi.a \
  -headers Sources/DashSPVFFI/include \
  -library target/x86_64-apple-ios/release/libdash_spv_ffi.a \
  -headers Sources/DashSPVFFI/include \
  -library target/release/libdash_spv_ffi_macos.a \
  -headers Sources/DashSPVFFI/include \
  -output DashSPVFFI.xcframework
```

## Troubleshooting

### SwiftData Build Issues

When building from the command line, you may encounter errors related to SwiftData macros:
```
error: external macro implementation type 'SwiftDataMacros.PersistentModelMacro' could not be found
```

This is a known limitation when building SwiftData-enabled packages from the command line. Solutions:

1. **Use Xcode for builds**: Open Package.swift in Xcode and build from there
2. **Use the build script**: `./build.sh xcode`
3. **For CI/CD**: Consider using `xcodebuild` instead of `swift build`

### Linking Errors

If you get linking errors:
1. Verify the library path is correct
2. Check that the library was built for the correct architecture
3. Use `nm` to verify symbols: `nm -g libdash_spv_ffi.a | grep dash_spv_ffi`

### Missing Headers

If headers are not found:
1. Verify the header file exists in the include directory
2. Check the module.modulemap file
3. Clean and rebuild the Swift package

### Architecture Mismatch

Use `lipo -info` to check library architectures:
```bash
lipo -info target/release/libdash_spv_ffi.a
```

## Development Workflow

1. Make changes to dash-spv-ffi
2. Rebuild the Rust library
3. Run Swift tests: `swift test`
4. Test in example app

## CI/CD Integration

For automated builds:

```yaml
# Example GitHub Actions workflow
- name: Build Rust FFI
  run: |
    cd dash-spv-ffi
    cargo build --release
    
- name: Build Swift Package
  run: |
    cd swift-dash-core-sdk
    swift build
    swift test
```
