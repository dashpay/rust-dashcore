# Swift Package Manager Linking Solution

## Problem
Swift Package Manager cannot find the prebuilt `libdash_spv_ffi.a` library even though it exists in the directory. The linker fails with undefined symbols.

## Root Cause
SPM has limitations when linking prebuilt static libraries:
1. Library search paths specified in Package.swift are not always respected
2. SPM prefers to build everything from source
3. Binary targets require XCFramework format

## Solutions

### Solution 1: Command Line Build (Recommended)
Use swift build with explicit linker flags:

```bash
# From the example directory
swift build -Xlinker -L$(pwd) -Xlinker -ldash_spv_ffi
```

### Solution 2: Xcode Configuration
When using Xcode:
1. Open the project in Xcode
2. Select your target
3. Go to Build Settings > Other Linker Flags
4. Add: `-L$(PROJECT_DIR) -ldash_spv_ffi`

### Solution 3: Environment Variables
Set library paths before building:

```bash
source ./setup-env.sh
swift build $SWIFT_BUILD_FLAGS
```

### Solution 4: System Library Installation
Install the library to a system location:

```bash
sudo cp libdash_spv_ffi.a /usr/local/lib/
```

### Solution 5: XCFramework (Future)
Convert the static library to XCFramework format:

```bash
# This would allow using binaryTarget in Package.swift
xcodebuild -create-xcframework \
  -library libdash_spv_ffi.a \
  -headers ../../../Sources/DashSPVFFI/include \
  -output libdash_spv_ffi.xcframework
```

## Current Workaround
The Package.swift includes the library path in linkerSettings:

```swift
linkerSettings: [
    .linkedLibrary("dash_spv_ffi"),
    .unsafeFlags([
        "-L/Users/quantum/src/rust-dashcore/swift-dash-core-sdk/Examples/DashHDWalletExample"
    ])
]
```

However, this may not work reliably across different environments.

## Testing
To verify the library is correctly built:

```bash
# Check library architecture
lipo -info libdash_spv_ffi.a

# Check for symbols
nm -gU libdash_spv_ffi.a | grep dash_spv_ffi_client_new
```

## Best Practice
For production use, consider:
1. Creating an XCFramework
2. Publishing the library to a package registry
3. Using a build script to ensure the library is in the correct location