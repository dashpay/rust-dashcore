#!/bin/bash
# Build phase script for Xcode that ensures proper PATH setup

set -e

echo "Setting up environment for Rust build..."

# Source cargo environment (handles both common installation paths)
if [ -f "$HOME/.cargo/env" ]; then
    source "$HOME/.cargo/env"
elif [ -f "$HOME/.profile" ]; then
    source "$HOME/.profile"
elif [ -f "$HOME/.bash_profile" ]; then
    source "$HOME/.bash_profile"
elif [ -f "$HOME/.zprofile" ]; then
    source "$HOME/.zprofile"
fi

# Alternative: Add cargo bin directly to PATH if above doesn't work
export PATH="$HOME/.cargo/bin:$PATH"

# Verify rustup is available
if ! command -v rustup &> /dev/null; then
    echo "Error: rustup not found in PATH"
    echo "PATH is: $PATH"
    echo "Please ensure Rust is installed via https://rustup.rs"
    exit 1
fi

# Verify cargo is available
if ! command -v cargo &> /dev/null; then
    echo "Error: cargo not found in PATH"
    exit 1
fi

echo "Rust environment configured successfully"
echo "rustup location: $(which rustup)"
echo "cargo location: $(which cargo)"

# Navigate to the swift-dash-core-sdk directory
cd "$SRCROOT/../.."

# Check if we need to rebuild (optional optimization)
# You can add logic here to check if source files have changed

# Run the build script
echo "Running build-ios.sh..."
./build-ios.sh

echo "Build phase completed successfully"
