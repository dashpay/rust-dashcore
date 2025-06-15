#!/bin/bash

# Build script for key-wallet-ffi iOS targets

set -e

echo "Building key-wallet-ffi for iOS..."

# Ensure we have the required iOS targets
rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim

# Build for iOS devices (arm64)
echo "Building for iOS devices (arm64)..."
cargo build --release --target aarch64-apple-ios

# Build for iOS simulator (x86_64)
echo "Building for iOS simulator (x86_64)..."
cargo build --release --target x86_64-apple-ios

# Build for iOS simulator (arm64 - M1 Macs)
echo "Building for iOS simulator (arm64)..."
cargo build --release --target aarch64-apple-ios-sim

# Create universal library
echo "Creating universal library..."
mkdir -p target/universal/release

# Create fat library for simulators
lipo -create \
    target/x86_64-apple-ios/release/libkey_wallet_ffi.a \
    target/aarch64-apple-ios-sim/release/libkey_wallet_ffi.a \
    -output target/universal/release/libkey_wallet_ffi_sim.a

# Copy device library
cp target/aarch64-apple-ios/release/libkey_wallet_ffi.a target/universal/release/libkey_wallet_ffi_device.a

# Generate Swift bindings
echo "Generating Swift bindings..."
cargo run --features uniffi/cli --bin uniffi-bindgen generate \
    src/key_wallet.udl \
    --language swift \
    --out-dir target/swift-bindings

echo "Build complete!"
echo "Libraries available at:"
echo "  - Device: target/universal/release/libkey_wallet_ffi_device.a"
echo "  - Simulator: target/universal/release/libkey_wallet_ffi_sim.a"
echo "  - Swift bindings: target/swift-bindings/"