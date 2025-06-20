#!/bin/bash

# Build script for iOS targets
set -e

echo "Building Rust libraries for iOS..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Navigate to rust project root
cd ../

# Install iOS targets if not already installed
echo -e "${YELLOW}Installing iOS rust targets...${NC}"
rustup target add aarch64-apple-ios-sim
rustup target add aarch64-apple-ios
rustup target add x86_64-apple-ios

# Build for iOS Simulator (arm64)
echo -e "${GREEN}Building for iOS Simulator (arm64)...${NC}"
cargo build --release --target aarch64-apple-ios-sim -p dash-spv-ffi
cargo build --release --target aarch64-apple-ios-sim -p key-wallet-ffi

# Build for iOS Device (arm64)
echo -e "${GREEN}Building for iOS Device (arm64)...${NC}"
cargo build --release --target aarch64-apple-ios -p dash-spv-ffi
cargo build --release --target aarch64-apple-ios -p key-wallet-ffi

# Build for iOS Simulator (x86_64) - for Intel Macs
echo -e "${GREEN}Building for iOS Simulator (x86_64)...${NC}"
cargo build --release --target x86_64-apple-ios -p dash-spv-ffi
cargo build --release --target x86_64-apple-ios -p key-wallet-ffi

# Create universal binary for simulator
echo -e "${GREEN}Creating universal binary for iOS Simulator...${NC}"
mkdir -p target/ios-simulator-universal/release

lipo -create \
    target/aarch64-apple-ios-sim/release/libdash_spv_ffi.a \
    target/x86_64-apple-ios/release/libdash_spv_ffi.a \
    -output target/ios-simulator-universal/release/libdash_spv_ffi.a

lipo -create \
    target/aarch64-apple-ios-sim/release/libkey_wallet_ffi.a \
    target/x86_64-apple-ios/release/libkey_wallet_ffi.a \
    -output target/ios-simulator-universal/release/libkey_wallet_ffi.a

# Copy the iOS device library
echo -e "${GREEN}Copying iOS device library...${NC}"
mkdir -p target/ios/release
cp target/aarch64-apple-ios/release/libdash_spv_ffi.a target/ios/release/
cp target/aarch64-apple-ios/release/libkey_wallet_ffi.a target/ios/release/

# Navigate back to swift directory
cd swift-dash-core-sdk

# Copy libraries to example directory
echo -e "${GREEN}Copying libraries to example directory...${NC}"
cp ../target/ios-simulator-universal/release/libdash_spv_ffi.a Examples/DashHDWalletExample/libdash_spv_ffi_sim.a
cp ../target/ios/release/libdash_spv_ffi.a Examples/DashHDWalletExample/libdash_spv_ffi_ios.a
cp ../target/ios-simulator-universal/release/libkey_wallet_ffi.a Examples/DashHDWalletExample/libkey_wallet_ffi_sim.a
cp ../target/ios/release/libkey_wallet_ffi.a Examples/DashHDWalletExample/libkey_wallet_ffi_ios.a

# Create symlinks for Xcode (defaults to simulator for development)
echo -e "${GREEN}Creating symlinks for Xcode...${NC}"
cd Examples/DashHDWalletExample
ln -sf libdash_spv_ffi_sim.a libdash_spv_ffi.a
ln -sf libkey_wallet_ffi_sim.a libkey_wallet_ffi.a
cd ../..

echo -e "${GREEN}iOS build complete!${NC}"
echo ""
echo "Libraries built and copied to Examples/DashHDWalletExample/:"
echo "  - dash_spv_ffi (simulator): libdash_spv_ffi_sim.a"
echo "  - dash_spv_ffi (device): libdash_spv_ffi_ios.a"
echo "  - key_wallet_ffi (simulator): libkey_wallet_ffi_sim.a"
echo "  - key_wallet_ffi (device): libkey_wallet_ffi_ios.a"
echo ""
echo "Symlinks created for Xcode:"
echo "  - libdash_spv_ffi.a -> libdash_spv_ffi_sim.a"
echo "  - libkey_wallet_ffi.a -> libkey_wallet_ffi_sim.a"
echo ""
echo "You can now open DashHDWalletExample.xcodeproj in Xcode and build!"