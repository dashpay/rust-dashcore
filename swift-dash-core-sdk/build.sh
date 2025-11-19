#!/bin/bash

# Build script for swift-dash-core-sdk

echo "Building swift-dash-core-sdk..."

# Check if we're building for Xcode or command line
if [ "$1" == "xcode" ]; then
    echo "Building with Xcode..."
    xcodebuild -scheme SwiftDashCoreSDK -destination 'platform=iOS' build
else
    echo "Building with Swift command line..."
    echo "Note: SwiftData models require Xcode for full functionality."
    echo "Command line builds will have limited SwiftData support."

    # First build the Rust FFI library if needed
    if [ ! -f "../target/release/libdash_spv_ffi.a" ]; then
        echo "Building Rust FFI library first..."
        cd ..
        cargo build --release -p dash-spv-ffi
        cd swift-dash-core-sdk
    fi

    # Build the Swift package
    swift build
fi

echo "Build complete!"
