#!/bin/bash
# Script to sync FFI headers from Rust crates to Swift SDK

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Syncing FFI headers to Swift SDK...${NC}"

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

# Source header locations
DASH_SPV_FFI_HEADER="$ROOT_DIR/dash-spv-ffi/include/dash_spv_ffi.h"
KEY_WALLET_FFI_HEADER="$ROOT_DIR/key-wallet-ffi/include/key_wallet_ffi.h"

# Destination locations
SWIFT_DASH_SPV_HEADER="$SCRIPT_DIR/Sources/DashSPVFFI/include/dash_spv_ffi.h"
SWIFT_KEY_WALLET_HEADER="$SCRIPT_DIR/Sources/KeyWalletFFI/include/key_wallet_ffi.h"

# Check if source headers exist
if [ ! -f "$DASH_SPV_FFI_HEADER" ]; then
    echo "Error: dash_spv_ffi.h not found at $DASH_SPV_FFI_HEADER"
    echo "Please run 'cargo build --release' in dash-spv-ffi first"
    exit 1
fi

# Copy dash_spv_ffi.h
echo "Copying dash_spv_ffi.h..."
cp "$DASH_SPV_FFI_HEADER" "$SWIFT_DASH_SPV_HEADER"
echo -e "${GREEN}✓ dash_spv_ffi.h copied${NC}"

# Copy key_wallet_ffi.h if it exists
if [ -f "$KEY_WALLET_FFI_HEADER" ]; then
    echo "Copying key_wallet_ffi.h..."
    mkdir -p "$(dirname "$SWIFT_KEY_WALLET_HEADER")"
    cp "$KEY_WALLET_FFI_HEADER" "$SWIFT_KEY_WALLET_HEADER"
    echo -e "${GREEN}✓ key_wallet_ffi.h copied${NC}"
else
    echo -e "${YELLOW}⚠ key_wallet_ffi.h not found, skipping${NC}"
fi

echo -e "${GREEN}Header sync complete!${NC}"