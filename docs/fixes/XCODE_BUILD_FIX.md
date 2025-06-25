# Fixing Xcode Build Issues

## Errors Fixed

### 1. "Cannot find type 'FFISyncProgress' in scope"
### 2. "Cannot find type 'FFISpvStats' in scope"  
### 3. "Cannot find type 'FFIDetailedSyncProgress' in scope"

These errors occur when Swift files are missing the `import DashSPVFFI` statement. The following files have been updated:

- **SyncProgress.swift**: Added `import DashSPVFFI` and fixed FFISyncProgress field mappings
- **SPVStats.swift**: Added `import DashSPVFFI` and fixed FFISpvStats field mappings
- **DetailedSyncProgress.swift**: Added `import DashSPVFFI`

### Additional Errors Fixed

4. **FFIBridge.swift errors**:
   - Fixed `FFIString` field access (changed from `data` to `ptr`)
   - Fixed `FFIWatchItemType` enum usage
   - Fixed `FFIWatchItem` initialization
   - Removed incorrect destroy calls on FFI types

### Code Fixes Applied

1. **SyncProgress.swift**: Updated initializer to use correct FFISyncProgress fields:
   ```swift
   internal init(ffiProgress: FFISyncProgress) {
       self.currentHeight = ffiProgress.header_height
       self.totalHeight = 0 // FFISyncProgress doesn't provide total height
       self.progress = ffiProgress.headers_synced ? 1.0 : 0.0
       self.status = ffiProgress.headers_synced ? .synced : .downloadingHeaders
       self.estimatedTimeRemaining = nil
       self.message = nil
   }
   ```

2. **SPVStats.swift**: Updated initializer to use correct FFISpvStats fields:
   ```swift
   internal init(ffiStats: FFISpvStats) {
       self.connectedPeers = 0 // Not provided by FFISpvStats
       self.totalPeers = 0 // Not provided by FFISpvStats
       self.headerHeight = 0 // Not provided by FFISpvStats
       self.filterHeight = 0 // Not provided by FFISpvStats
       self.scannedHeight = 0 // Not provided by FFISpvStats
       self.totalHeaders = ffiStats.headers_downloaded
       self.totalFilters = ffiStats.filters_downloaded
       self.totalTransactions = ffiStats.blocks_processed
       self.startTime = Date.now.addingTimeInterval(-TimeInterval(ffiStats.uptime))
       self.bytesReceived = ffiStats.bytes_received
       self.bytesSent = ffiStats.bytes_sent
   }
   ```

### Solution Steps

1. **Ensure Libraries Are Built**
   ```bash
   cd swift-dash-core-sdk
   ./build-ios.sh
   ```
   
   This should have created:
   - `Examples/DashHDWalletExample/libdash_spv_ffi_sim.a` (for Simulator)
   - `Examples/DashHDWalletExample/libdash_spv_ffi_ios.a` (for Device)

2. **Clean Xcode Build**
   - In Xcode: Product → Clean Build Folder (⇧⌘K)
   - Delete DerivedData: `rm -rf ~/Library/Developer/Xcode/DerivedData`

3. **Configure Build Settings**
   In your Xcode project, ensure these settings are correct:

   **For the App Target:**
   - Build Settings → Search Paths → Library Search Paths:
     ```
     $(PROJECT_DIR)
     $(inherited)
     ```
   
   - Build Settings → Linking → Other Linker Flags:
     ```
     -ldash_spv_ffi_sim (for Simulator)
     -ldash_spv_ffi_ios (for Device)
     ```

4. **Add Build Phase Script** (if not already present)
   - Select your app target
   - Build Phases → New Run Script Phase
   - Add this script:
   ```bash
   # Select the correct library based on the SDK
   if [ "$PLATFORM_NAME" = "iphonesimulator" ]; then
       cp "${PROJECT_DIR}/libdash_spv_ffi_sim.a" "${PROJECT_DIR}/libdash_spv_ffi.a"
   else
       cp "${PROJECT_DIR}/libdash_spv_ffi_ios.a" "${PROJECT_DIR}/libdash_spv_ffi.a"
   fi
   ```

5. **Using Swift Package Manager in Xcode**
   If you're using the Swift Package:
   - File → Add Package Dependencies
   - Add Local Package → Select the `swift-dash-core-sdk` folder
   - The DashSPVFFI module should be automatically available

6. **Manual Module Import**
   If the module still isn't found, check that `SyncProgress.swift` has:
   ```swift
   import Foundation
   import DashSPVFFI
   ```

### Updated Code

The `SyncProgress.swift` file has been updated to properly use the FFISyncProgress struct:

```swift
internal init(ffiProgress: FFISyncProgress) {
    self.currentHeight = ffiProgress.header_height
    self.totalHeight = 0 // FFISyncProgress doesn't provide total height
    self.progress = ffiProgress.headers_synced ? 1.0 : 0.0
    self.status = ffiProgress.headers_synced ? .synced : .downloadingHeaders
    self.estimatedTimeRemaining = nil
    self.message = nil
}
```

### Alternative: Direct Integration

If you're still having issues with the Swift Package, you can directly add the files:

1. Add the `SwiftDashCoreSDK` folder to your Xcode project
2. Add the header file: `Sources/DashSPVFFI/include/dash_spv_ffi.h`
3. Create a bridging header if needed:
   ```objc
   #import "dash_spv_ffi.h"
   ```

### Verification

After following these steps:
1. Clean and rebuild the project
2. The FFISyncProgress type should be recognized
3. The app should compile successfully

### Common Issues

- **Architecture Mismatch**: Ensure you're using the correct library for your target (simulator vs device)
- **Missing Libraries**: Run `./build-ios.sh` to rebuild if libraries are missing
- **Module Cache**: Sometimes Xcode's module cache gets corrupted. Delete DerivedData to fix.