# Fix "No such module 'SwiftDashCoreSDK'" Error

This error occurs because the SwiftDashCoreSDK package isn't linked to your Xcode project. Here's how to fix it:

## Quick Fix Steps

1. **In Xcode, with DashHDWalletExample.xcodeproj open:**

2. **Click on the project name** (blue icon at the top of the file navigator)
   - You should see "DashHDWalletExample" with a blue app icon

3. **In the main editor, ensure you have:**
   - PROJECT: DashHDWalletExample (selected)
   - TARGETS: DashHDWalletExample (selected)

4. **Add the package dependency - Method 1 (Recommended):**
   - Click "File" menu → "Add Package Dependencies..."
   - In the dialog, click "Add Local..." button (bottom left)
   - Navigate to: `/Users/quantum/src/rust-dashcore/swift-dash-core-sdk`
   - Click "Add Package"
   - In the next dialog, check both:
     ✓ SwiftDashCoreSDK
     ✓ KeyWalletFFISwift
   - Click "Add"

5. **Alternative - Method 2:**
   - Select the DashHDWalletExample target
   - Go to "General" tab
   - Scroll to "Frameworks, Libraries, and Embedded Content"
   - Click the "+" button
   - Choose "Add Package Dependency..."
   - Follow steps from Method 1

6. **After adding the dependency:**
   - You should see "Package Dependencies" in the file navigator
   - Under it, you'll see "swift-dash-core-sdk"
   - Clean Build Folder: Product → Clean Build Folder (⇧⌘K)
   - Build: Product → Build (⌘B)

## Verify the Fix

After adding the package:
1. The "No such module" errors should disappear
2. You should see "Package Dependencies" in your project navigator
3. The SwiftDashCoreSDK module should be importable

## If It Still Doesn't Work

1. **Reset Package Cache:**
   - File → Packages → Reset Package Caches
   - Wait for resolution to complete
   - Clean and build again

2. **Check Package Resolution:**
   - Look for "Package Dependencies" in the navigator
   - If you see a red icon or error, right-click → "Resolve Package Dependencies"

3. **Manual Resolution:**
   - Close Xcode
   - Delete the `.swiftpm` folder in the project directory
   - Delete DerivedData: `rm -rf ~/Library/Developer/Xcode/DerivedData`
   - Reopen Xcode and try again

## Command Line Alternative

If you prefer command line:
```bash
cd /Users/quantum/src/rust-dashcore/swift-dash-core-sdk/Examples/DashHDWalletExample
xcodebuild -resolvePackageDependencies
```

Then reopen in Xcode.