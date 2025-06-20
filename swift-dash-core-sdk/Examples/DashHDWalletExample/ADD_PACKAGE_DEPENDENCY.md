# Adding SwiftDashCoreSDK Package Dependency

The project needs to add the SwiftDashCoreSDK package dependency. Follow these steps in Xcode:

## Steps to Add Package Dependency

1. **Open the project in Xcode:**
   ```bash
   open DashHDWalletExample.xcodeproj
   ```

2. **Add the package dependency:**
   - Select the DashHDWalletExample project in the navigator (top-level blue icon)
   - Select the DashHDWalletExample target
   - Click on the "General" tab
   - Scroll down to "Frameworks, Libraries, and Embedded Content"
   - Click the "+" button
   - Click "Add Package Dependency..."
   - Click "Add Local..."
   - Navigate to: `/Users/quantum/src/rust-dashcore/swift-dash-core-sdk`
   - Click "Add Package"

3. **Select the products to add:**
   - Check "SwiftDashCoreSDK"
   - Check "KeyWalletFFISwift"
   - Click "Add"

4. **Clean and build:**
   - Product → Clean Build Folder (Shift+Cmd+K)
   - Build the project (Cmd+B)

## Alternative Method (via File Menu)

1. **File → Add Package Dependencies...**
2. Click "Add Local..."
3. Navigate to the `swift-dash-core-sdk` directory
4. Add Package
5. Select both "SwiftDashCoreSDK" and "KeyWalletFFISwift"

## Verify the Integration

After adding the package, you should see:
- A "Package Dependencies" section in the project navigator with SwiftDashCoreSDK
- The build errors about "No such module 'SwiftDashCoreSDK'" should be resolved

## Library Linking

The project already has library search paths configured in `Local.xcconfig` for the FFI libraries:
- `libdash_spv_ffi.a`
- `libkey_wallet_ffi.a`

These will be automatically linked based on the target architecture (simulator vs device).