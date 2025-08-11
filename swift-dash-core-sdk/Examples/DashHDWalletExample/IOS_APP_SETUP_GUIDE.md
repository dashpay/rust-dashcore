# iOS App Setup Guide for DashHDWalletExample

This guide provides step-by-step instructions for setting up and building the DashHDWalletExample iOS app in Xcode.

## Prerequisites

1. **Xcode 15.0+** installed
2. **Rust toolchain** installed with iOS targets
3. **Built FFI libraries** (see Building FFI Libraries section)

## Building FFI Libraries

Before opening the Xcode project, you need to build the Rust FFI libraries:

```bash
# From the rust-dashcore root directory
cd swift-dash-core-sdk

# Build the iOS libraries
./build-ios.sh

# This creates the necessary .a files in:
# - Examples/DashHDWalletExample/DashSPVFFI.xcframework/
```

## Xcode Project Setup

### 1. Open the Project

```bash
cd Examples/DashHDWalletExample
open DashHDWalletExample.xcodeproj
```

### 2. Configure Library Linking

**IMPORTANT**: The FFI libraries must be explicitly added to the Build Phases to avoid "undefined symbols" errors.

1. **Select the DashHDWalletExample target**
   - In the project navigator, click on "DashHDWalletExample" (top level)
   - In the editor, select the "DashHDWalletExample" target

2. **Go to the Build Phases tab**

3. **Configure "Link Binary With Libraries"**
   - Expand the "Link Binary With Libraries" section
   - Click the "+" button
   - Click "Add Other..." 
   - Navigate to: `/Users/quantum/src/rust-dashcore/swift-dash-core-sdk/Examples/DashHDWalletExample`
   - Select `libdash_spv_ffi.a`
   - Click "Add"
   - Repeat for `libkey_wallet_ffi.a` if needed

4. **Verify Library Search Paths** (Build Settings tab)
   - Search for "Library Search Paths"
   - Ensure these paths are present:
     - `$(PROJECT_DIR)`
     - `$(PROJECT_DIR)/DashHDWalletExample`

### 3. Select Target Device

- For iOS Simulator: Choose any iOS Simulator device (e.g., iPhone 15)
- For physical device: Connect your device and select it

### 4. (Optional) Add Automatic Library Build Phase

Due to Xcode sandbox restrictions, automatic library building has limitations. Choose one approach:

#### Option A: Build Libraries Only (Recommended for CI/CD)

This builds the libraries but doesn't copy them (due to sandbox restrictions):

1. **Select the DashHDWalletExample target**
2. **Go to Build Phases tab**
3. **Click "+" → "New Run Script Phase"**
4. **Drag it to run BEFORE "Compile Sources"**
5. **Paste this script directly**:
   ```bash
   #!/bin/bash
   set -e
   
   # Source cargo environment
   if [ -f "$HOME/.cargo/env" ]; then
       source "$HOME/.cargo/env"
   fi
   export PATH="$HOME/.cargo/bin:$PATH"
   
   # Navigate to swift-dash-core-sdk directory
   cd "$SRCROOT/../.."
   
   # Run the no-copy build script
   ./build-ios-no-copy.sh
   ```

#### Option B: Manual Build Process (Recommended for Development)

1. **Build libraries manually** before opening Xcode:
   ```bash
   cd /Users/quantum/src/rust-dashcore/swift-dash-core-sdk
   ./build-ios.sh
   ```

2. **Open Xcode and build normally**

This approach avoids all sandbox issues and ensures libraries are properly copied.

#### Option C: Check Library Freshness Only

Add a build phase that warns if libraries are outdated:

1. **Add a Run Script Phase**
2. **Paste this script**:
   ```bash
   #!/bin/bash
   # Check if Rust source is newer than built library
   RUST_SRC="$SRCROOT/../../dash-spv-ffi/src"
   LIB_FILE="$SRCROOT/libdash_spv_ffi.a"
   
   if [ -d "$RUST_SRC" ] && [ -f "$LIB_FILE" ]; then
       if [ "$RUST_SRC" -nt "$LIB_FILE" ]; then
           echo "warning: Rust source files are newer than libdash_spv_ffi.a"
           echo "warning: Run './build-ios.sh' to update the library"
       fi
   fi
   ```

**Note**: Due to Xcode's sandbox, the build phase cannot modify files in the project directory.

### 5. Build and Run

1. **Clean Build Folder** (recommended first time)
   - Product → Clean Build Folder (⇧⌘K)

2. **Build**
   - Product → Build (⌘B)

3. **Run**
   - Product → Run (⌘R)

## Troubleshooting

### "Undefined symbols" Linker Errors

If you see errors like:
```
Undefined symbols for architecture arm64:
  "_dash_spv_ffi_client_sync_to_tip_with_progress", referenced from:
```

**Solution**: The FFI library is not properly linked. Follow these steps:

1. Verify the library exists and has correct architecture:
   ```bash
   # Check if library exists
   ls -la Examples/DashHDWalletExample/libdash_spv_ffi.a
   
   # Check architecture (should show arm64 for simulator)
   lipo -info Examples/DashHDWalletExample/libdash_spv_ffi.a
   
   # Check symbols
   nm -g Examples/DashHDWalletExample/libdash_spv_ffi.a | grep dash_spv_ffi_client
   ```

2. If the library is missing or wrong architecture:
   ```bash
   # Copy the correct library for iOS Simulator
   cp DashSPVFFI.xcframework/ios-arm64_x86_64-simulator/libdash_spv_ffi_sim.a libdash_spv_ffi.a
   
   # For physical iOS device
   cp DashSPVFFI.xcframework/ios-arm64/libdash_spv_ffi_ios.a libdash_spv_ffi.a
   ```

3. Re-add the library to Build Phases (see step 2.3 above)

4. Clean and rebuild

### "Module 'DashSPVFFI' not found"

This means the Swift Package Manager can't find the FFI module.

**Solution**:
1. File → Packages → Reset Package Caches
2. File → Packages → Update to Latest Package Versions
3. Clean and rebuild

### "Could not find module 'SwiftDashCoreSDK'"

**Solution**:
1. Ensure the SwiftDashCoreSDK package is properly added to the project
2. Check that the package is listed in the project's Package Dependencies
3. Try removing and re-adding the package reference

### "Operation not permitted" or "Sandbox: deny" Errors

If you get sandbox errors when trying to run build scripts:

**Solution**:
1. Don't use external script files in Build Phases
2. Paste the script content directly into the Xcode build phase editor
3. Ensure the script doesn't try to access files outside the project directory
4. If using external scripts is necessary, add them to the project and mark them as part of the target

### Build Fails with "Library not loaded"

This happens when the dynamic library path is incorrect.

**Solution**:
1. Ensure you're using static libraries (.a files) not dynamic (.dylib)
2. Check "Embed & Sign" settings in General → Frameworks, Libraries, and Embedded Content

## Architecture-Specific Builds

### iOS Simulator (Apple Silicon Macs)
- Requires `arm64` architecture for simulator
- Use libraries from `ios-arm64_x86_64-simulator/`

### iOS Simulator (Intel Macs)
- Requires `x86_64` architecture
- Use libraries from `ios-arm64_x86_64-simulator/` (universal binary)

### Physical iOS Device
- Requires `arm64` architecture
- Use libraries from `ios-arm64/`

## Updating FFI Libraries

The `libdash_spv_ffi.a` library is built from the Rust code in `dash-spv-ffi/`. Last modified: **June 19, 2025** (built from commit on June 18, 2025).

### When to Update

Update the libraries when:
- Changes are made to `dash-spv-ffi/` Rust code
- New FFI functions are added
- Bug fixes in the SPV implementation
- Performance improvements are made

### How to Update

1. **Check what changed**
   ```bash
   # See recent changes to dash-spv-ffi
   git log --oneline -- dash-spv-ffi/
   ```

2. **Rebuild the FFI libraries**
   ```bash
   # From swift-dash-core-sdk directory
   cd /Users/quantum/src/rust-dashcore/swift-dash-core-sdk
   ./build-ios.sh
   ```
   
   This script will:
   - Build for iOS device (arm64)
   - Build for iOS simulator (arm64 + x86_64)
   - Create universal binaries
   - Copy libraries to `Examples/DashHDWalletExample/`

3. **Update the XCFramework (if needed)**
   
   The build script creates:
   - `libdash_spv_ffi_sim.a` - Universal simulator library
   - `libdash_spv_ffi_ios.a` - Device library
   
   To create/update the XCFramework:
   ```bash
   cd Examples/DashHDWalletExample
   
   # Create XCFramework
   xcodebuild -create-xcframework \
     -library libdash_spv_ffi_ios.a \
     -library libdash_spv_ffi_sim.a \
     -output DashSPVFFI.xcframework
   ```

4. **Update the symlink**
   ```bash
   # For simulator builds
   ln -sf libdash_spv_ffi_sim.a libdash_spv_ffi.a
   
   # For device builds
   ln -sf libdash_spv_ffi_ios.a libdash_spv_ffi.a
   ```

5. **Clean and rebuild in Xcode**
   - Product → Clean Build Folder (⇧⌘K)
   - Product → Build (⌘B)

### Verifying the Update

After updating, verify the library:

```bash
# Check file dates
ls -la libdash_spv_ffi*.a

# Verify symbols are present
nm -g libdash_spv_ffi.a | grep dash_spv_ffi_client

# Check architectures
lipo -info libdash_spv_ffi.a
```

## Common Build Settings

These build settings should be configured correctly by default, but verify if you have issues:

- **Enable Bitcode**: No
- **Build Active Architecture Only**: Yes (Debug), No (Release)
- **Valid Architectures**: arm64 (add x86_64 for Intel Mac simulator support)
- **Deployment Target**: iOS 17.0

## Using the Example App

Once built successfully:

1. **Create a Wallet**: Tap "Create Wallet" to generate a new HD wallet
2. **Sync**: The app will automatically start syncing with the Dash network
3. **View Balance**: See your balance update in real-time during sync
4. **Receive**: Generate receive addresses
5. **Send**: Send Dash transactions (testnet by default)

## Development Tips

- Use the Xcode console to see detailed sync progress logs
- The app uses testnet by default for safe testing
- Wallet data persists between app launches using SwiftData
- Pull to refresh triggers a blockchain rescan

## Getting Help

If you encounter issues not covered here:

1. Check the build logs in Xcode's Report Navigator
2. Verify all prerequisites are installed correctly
3. Ensure FFI libraries are built for the correct target
4. Check the main project's CLAUDE.md for additional context