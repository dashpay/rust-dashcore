#!/bin/bash

# Script to set up library search paths for Swift Package Manager

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Create symlink to library in a standard location
sudo mkdir -p /usr/local/lib
sudo ln -sf "${SCRIPT_DIR}/libdash_spv_ffi.a" /usr/local/lib/libdash_spv_ffi.a

echo "Library symlink created at /usr/local/lib/libdash_spv_ffi.a"
echo "You may need to run 'swift package clean' and rebuild"