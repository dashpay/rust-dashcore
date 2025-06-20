# Fixing Undefined Symbols for dash_spv_ffi

The linking error occurs because the Swift Package Manager can't find the `libdash_spv_ffi.a` library even though it's present in the project directory. Here are several solutions:

## Solution 1: Add Library to Xcode Project Build Phases (Recommended)

1. **Open DashHDWalletExample.xcodeproj in Xcode**

2. **Select the DashHDWalletExample target**
   - Click on the project in the navigator
   - Select the "DashHDWalletExample" target

3. **Go to Build Phases tab**

4. **Expand "Link Binary With Libraries"**

5. **Click the "+" button and "Add Other..."**
   - Navigate to: `/Users/quantum/src/rust-dashcore/swift-dash-core-sdk/Examples/DashHDWalletExample`
   - Select `libdash_spv_ffi.a`
   - Click "Add"

6. **Go to Build Settings tab**

7. **Search for "Library Search Paths"**
   - Add: `$(PROJECT_DIR)` if not already present

8. **Clean and Build**
   - Product → Clean Build Folder (⇧⌘K)
   - Product → Build (⌘B)

## Solution 2: Use the Local.xcconfig File

The project includes a `Local.xcconfig` file that sets up the proper paths. To use it:

1. **In Xcode, select the project (top level)**

2. **In the main editor, select the PROJECT (not target)**

3. **Go to the Info tab**

4. **Under Configurations, for both Debug and Release:**
   - Click the disclosure triangle to expand
   - For "DashHDWalletExample", set "Based on Configuration File" to "Local"

5. **Clean and rebuild**

## Solution 3: Update Package.swift to Use Absolute Path

If the above don't work, we can temporarily update the Package.swift to use an absolute path:

1. **Edit `/Users/quantum/src/rust-dashcore/swift-dash-core-sdk/Package.swift`**

2. **In the DashSPVFFI target, update the linkerSettings:**

```swift
linkerSettings: [
    .linkedLibrary("dash_spv_ffi"),
    .unsafeFlags([
        "-L/Users/quantum/src/rust-dashcore/swift-dash-core-sdk/Examples/DashHDWalletExample",
        // ... other paths
    ])
]
```

3. **In Xcode, update the package:**
   - File → Packages → Update to Latest Package Versions

## Solution 4: Create a Symlink in Standard Location

Create a symlink in a location that SPM will definitely search:

```bash
# Create the directory if it doesn't exist
mkdir -p /Users/quantum/src/rust-dashcore/swift-dash-core-sdk/target/release

# Create symlink
ln -sf /Users/quantum/src/rust-dashcore/swift-dash-core-sdk/Examples/DashHDWalletExample/libdash_spv_ffi.a \
       /Users/quantum/src/rust-dashcore/swift-dash-core-sdk/target/release/libdash_spv_ffi.a
```

Then clean and rebuild in Xcode.

## Debugging Steps

To verify the library has the correct symbols:

```bash
# Check symbols
nm -gU /Users/quantum/src/rust-dashcore/swift-dash-core-sdk/Examples/DashHDWalletExample/libdash_spv_ffi.a | grep dash_spv_

# Check architecture
lipo -info /Users/quantum/src/rust-dashcore/swift-dash-core-sdk/Examples/DashHDWalletExample/libdash_spv_ffi.a
```

To see what Xcode is actually doing:

```bash
# Build with verbose output
xcodebuild -project DashHDWalletExample.xcodeproj -scheme DashHDWalletExample -configuration Debug -showBuildSettings | grep -E "(LIBRARY_SEARCH_PATHS|OTHER_LDFLAGS)"
```

## Expected Result

After applying one of these solutions, the build should succeed and the app should run without undefined symbol errors.