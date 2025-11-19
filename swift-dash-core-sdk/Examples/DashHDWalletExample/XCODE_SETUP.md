# Xcode Setup for DashHDWalletExample

## Opening the Project

1. Navigate to the example directory:
   ```bash
   cd swift-dash-core-sdk/Examples/DashHDWalletExample
   open DashHDWalletExample.xcodeproj
   ```

## Package Dependencies

The project is already configured to use the local SwiftDashCoreSDK package. The dependency is set up to reference the SDK at `../../../..` (the root of swift-dash-core-sdk).

## Build Settings

The project requires the following libraries to be linked:
- `libdash_spv_ffi.a` (for Dash SPV functionality)
- `libkey_wallet_ffi.a` (for HD wallet functionality)

These libraries are included in the project directory with separate versions for:
- iOS device: `libdash_spv_ffi_ios.a`, `libkey_wallet_ffi.a`
- iOS simulator: `libdash_spv_ffi_sim.a`, `libkey_wallet_ffi_sim.a`

## Running the App

1. Select the DashHDWalletExample scheme in Xcode (should be selected by default)
2. Choose your target device or simulator
3. Click the Run button (▶️) or press Cmd+R

## Troubleshooting

If you encounter build errors:

1. **Clean Build Folder**: Product → Clean Build Folder (Shift+Cmd+K)
2. **Reset Package Caches**: File → Packages → Reset Package Caches
3. **Delete Derived Data**: Xcode → Settings → Locations → Derived Data → Delete

If the Run button is still greyed out:
- Ensure a scheme is selected in the toolbar
- Check that a valid simulator or device is selected
- Verify that the minimum iOS deployment target (iOS 17.0) is supported by your selected device

## Project Structure

```
DashHDWalletExample/
├── DashHDWalletExample.xcodeproj   # Xcode project file
├── DashHDWalletExample/            # Source files
│   ├── DashHDWalletApp.swift       # App entry point
│   ├── Models/                     # Data models
│   ├── Services/                   # Business logic
│   ├── Views/                      # SwiftUI views
│   ├── Utils/                      # Utility functions
│   └── Assets.xcassets/            # App resources
├── DashHDWalletExampleTests/       # Unit tests
└── DashHDWalletExampleUITests/     # UI tests
```
