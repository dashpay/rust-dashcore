#!/bin/bash

# Environment setup for Swift Package Manager builds

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Set library search paths
export LIBRARY_SEARCH_PATHS="${SCRIPT_DIR}:${LIBRARY_SEARCH_PATHS}"
export LD_LIBRARY_PATH="${SCRIPT_DIR}:${LD_LIBRARY_PATH}"
export DYLD_LIBRARY_PATH="${SCRIPT_DIR}:${DYLD_LIBRARY_PATH}"

# Set pkg-config path
export PKG_CONFIG_PATH="${SCRIPT_DIR}:${PKG_CONFIG_PATH}"

# Set Swift PM flags
export SWIFT_BUILD_FLAGS="-Xlinker -L${SCRIPT_DIR}"

echo "Environment configured for dash_spv_ffi library"
echo "Library path: ${SCRIPT_DIR}"
echo ""
echo "To build with Swift PM, use:"
echo "  swift build \$SWIFT_BUILD_FLAGS"
echo "Or in Xcode, add to 'Other Linker Flags':"
echo "  -L${SCRIPT_DIR}"