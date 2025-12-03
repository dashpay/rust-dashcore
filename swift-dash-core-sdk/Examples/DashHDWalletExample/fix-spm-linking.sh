#!/bin/bash

# This script fixes SPM linking issues by ensuring libraries are in all search paths

echo "Fixing SPM linking issues..."

# Source library
SOURCE_LIB="/Users/quantum/src/rust-dashcore/swift-dash-core-sdk/Examples/DashHDWalletExample/libdash_spv_ffi_sim.a"
SOURCE_KEY_LIB="/Users/quantum/src/rust-dashcore/swift-dash-core-sdk/Examples/DashHDWalletExample/libkey_wallet_ffi_sim.a"

# Ensure libraries exist
if [ ! -f "$SOURCE_LIB" ]; then
    echo "Error: $SOURCE_LIB not found!"
    exit 1
fi

if [ ! -f "$SOURCE_KEY_LIB" ]; then
    echo "Error: $SOURCE_KEY_LIB not found!"
    exit 1
fi

# Create all target directories if they don't exist
mkdir -p /Users/quantum/src/rust-dashcore/target/aarch64-apple-ios-sim/release
mkdir -p /Users/quantum/src/rust-dashcore/target/x86_64-apple-ios/release
mkdir -p /Users/quantum/src/rust-dashcore/target/ios-simulator-universal/release
mkdir -p /Users/quantum/src/rust-dashcore/target/release

# Copy to all possible locations that SPM might look
echo "Copying libraries to all search paths..."

# dash_spv_ffi
cp "$SOURCE_LIB" /Users/quantum/src/rust-dashcore/swift-dash-core-sdk/Examples/DashHDWalletExample/libdash_spv_ffi.a
cp "$SOURCE_LIB" /Users/quantum/src/rust-dashcore/swift-dash-core-sdk/libdash_spv_ffi.a
cp "$SOURCE_LIB" /Users/quantum/src/rust-dashcore/target/aarch64-apple-ios-sim/release/libdash_spv_ffi.a
cp "$SOURCE_LIB" /Users/quantum/src/rust-dashcore/target/x86_64-apple-ios/release/libdash_spv_ffi.a
cp "$SOURCE_LIB" /Users/quantum/src/rust-dashcore/target/ios-simulator-universal/release/libdash_spv_ffi.a
cp "$SOURCE_LIB" /Users/quantum/src/rust-dashcore/target/release/libdash_spv_ffi.a

# key_wallet_ffi
cp "$SOURCE_KEY_LIB" /Users/quantum/src/rust-dashcore/swift-dash-core-sdk/Examples/DashHDWalletExample/libkey_wallet_ffi.a
cp "$SOURCE_KEY_LIB" /Users/quantum/src/rust-dashcore/swift-dash-core-sdk/libkey_wallet_ffi.a
cp "$SOURCE_KEY_LIB" /Users/quantum/src/rust-dashcore/target/aarch64-apple-ios-sim/release/libkey_wallet_ffi.a
cp "$SOURCE_KEY_LIB" /Users/quantum/src/rust-dashcore/target/x86_64-apple-ios/release/libkey_wallet_ffi.a
cp "$SOURCE_KEY_LIB" /Users/quantum/src/rust-dashcore/target/ios-simulator-universal/release/libkey_wallet_ffi.a
cp "$SOURCE_KEY_LIB" /Users/quantum/src/rust-dashcore/target/release/libkey_wallet_ffi.a

echo "Clearing all Xcode caches..."
rm -rf ~/Library/Developer/Xcode/DerivedData/DashHDWalletExample*
rm -rf ~/Library/Caches/com.apple.dt.Xcode*
rm -rf ~/Library/Caches/org.swift.swiftpm

echo "Done! Now clean and rebuild in Xcode."
