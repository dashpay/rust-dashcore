#!/bin/bash

# Fix linking issues by creating symlinks in expected locations

echo "Creating symlinks for dash_spv_ffi library..."

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$SCRIPT_DIR/../.."

# Create target directories if they don't exist
mkdir -p "$PROJECT_ROOT/target/release"
mkdir -p "$PROJECT_ROOT/target/aarch64-apple-ios-sim/release"
mkdir -p "$PROJECT_ROOT/target/x86_64-apple-ios/release"
mkdir -p "$PROJECT_ROOT/target/ios-simulator-universal/release"

# Create symlinks for the universal library
if [ -f "$SCRIPT_DIR/libdash_spv_ffi.a" ]; then
    echo "Creating symlink in target/release..."
    ln -sf "$SCRIPT_DIR/libdash_spv_ffi.a" "$PROJECT_ROOT/target/release/libdash_spv_ffi.a"
    
    echo "Creating symlink in ios-simulator-universal..."
    ln -sf "$SCRIPT_DIR/libdash_spv_ffi.a" "$PROJECT_ROOT/target/ios-simulator-universal/release/libdash_spv_ffi.a"
fi

# Create symlinks for simulator-specific library
if [ -f "$SCRIPT_DIR/libdash_spv_ffi_sim.a" ]; then
    echo "Creating symlink in aarch64-apple-ios-sim..."
    ln -sf "$SCRIPT_DIR/libdash_spv_ffi_sim.a" "$PROJECT_ROOT/target/aarch64-apple-ios-sim/release/libdash_spv_ffi.a"
    
    echo "Creating symlink in x86_64-apple-ios..."
    ln -sf "$SCRIPT_DIR/libdash_spv_ffi_sim.a" "$PROJECT_ROOT/target/x86_64-apple-ios/release/libdash_spv_ffi.a"
fi

# Create symlinks for iOS device library
if [ -f "$SCRIPT_DIR/libdash_spv_ffi_ios.a" ]; then
    echo "Creating symlink in aarch64-apple-ios..."
    mkdir -p "$PROJECT_ROOT/target/aarch64-apple-ios/release"
    ln -sf "$SCRIPT_DIR/libdash_spv_ffi_ios.a" "$PROJECT_ROOT/target/aarch64-apple-ios/release/libdash_spv_ffi.a"
fi

echo "Symlinks created successfully!"
echo ""
echo "Next steps:"
echo "1. In Xcode: Product → Clean Build Folder (⇧⌘K)"
echo "2. In Xcode: Product → Build (⌘B)"
echo ""
echo "If you still have issues, try:"
echo "- File → Packages → Reset Package Caches"
echo "- Delete DerivedData: rm -rf ~/Library/Developer/Xcode/DerivedData"