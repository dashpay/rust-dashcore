#!/bin/bash

# Run script for Swift Package Manager with proper library linking

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Running with Swift Package Manager..."
echo "Library path: ${SCRIPT_DIR}"

# Run with explicit linker flags
swift run \
    -Xlinker -L${SCRIPT_DIR} \
    -Xlinker -ldash_spv_ffi \
    "$@"