#!/bin/bash

# Build script for Swift Package Manager with proper library linking

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Building with Swift Package Manager..."
echo "Library path: ${SCRIPT_DIR}"

# Build with explicit linker flags
swift build \
    -Xlinker -L${SCRIPT_DIR} \
    -Xlinker -ldash_spv_ffi \
    "$@"

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
else
    echo "❌ Build failed!"
    exit 1
fi
